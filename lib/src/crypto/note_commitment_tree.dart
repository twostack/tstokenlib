/*
  Copyright 2024 - Stephan M. February

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import '../script_gen/pool_spend_air.dart' show PoolHash, PoolSpendAir;

/// A Merkle path from a leaf to the root, in the shape [PoolHash.root] and
/// [SpendNote] consume: siblings leaf level first, and the leaf's position,
/// whose bit i says whether the node at level i is the right child.
class MerklePath {
  final List<List<int>> siblings;
  final int position;
  const MerklePath(this.siblings, this.position);

  List<int> rootFor(List<int> leaf) => PoolHash.root(leaf, siblings, position);
}

/// A fixed-depth Poseidon2 Merkle tree kept as a map of computed nodes, so
/// any leaf can be set and any path produced. Nodes that were never written
/// read as the empty subtree of their level.
class MerkleStore {
  final int depth;
  final List<Map<int, List<int>>> _nodes;
  MerkleStore(this.depth) : _nodes = List.generate(depth + 1, (_) => <int, List<int>>{});

  List<int> nodeAt(int level, int index) => _nodes[level][index] ?? MerkleFrontier.emptyRoots[level];

  List<int> get root => nodeAt(depth, 0);

  /// Write [leaf] at [index] and recompute the path to the root.
  void set(int index, List<int> leaf) {
    if (leaf.length != PoolHash.digestLanes) throw ArgumentError('leaf must be ${PoolHash.digestLanes} lanes');
    _nodes[0][index] = List.unmodifiable(leaf);
    var idx = index;
    for (int l = 0; l < depth; l++) {
      final left = idx & ~1;
      _nodes[l + 1][idx >> 1] = PoolHash.node(nodeAt(l, left), nodeAt(l, left | 1));
      idx >>= 1;
    }
  }

  MerklePath path(int index) =>
      MerklePath([for (int l = 0; l < depth; l++) nodeAt(l, (index >> l) ^ 1)], index);
}

/// The append-only frontier of a depth-32 Poseidon2 Merkle tree whose empty
/// leaves are [emptyLeaf]. Holds one node per level (the roots of the
/// complete left subtrees on the path to the next free leaf), so the root can
/// be recomputed and a leaf appended with 32 hashes and no other storage.
/// This is the state a covenant would carry to append commitments on chain.
class MerkleFrontier {
  static const depth = PoolSpendAir.depth;
  static const capacity = 1 << depth;
  static final List<int> emptyLeaf = List.filled(PoolHash.digestLanes, 0);

  /// emptyRoots[l] is the root of an empty subtree of height l.
  static final List<List<int>> emptyRoots = (() {
    final out = <List<int>>[emptyLeaf];
    for (int l = 0; l < depth; l++) {
      out.add(PoolHash.node(out[l], out[l]));
    }
    return out;
  })();

  int _size = 0;
  final List<List<int>?> _peaks = List.filled(depth, null);

  int get size => _size;

  /// peaks[l] is present exactly when bit l of [size] is set.
  List<List<int>?> get peaks => List.unmodifiable(_peaks);

  List<int> get root {
    var cur = emptyRoots[0];
    for (int l = 0; l < depth; l++) {
      cur = (_size >> l) & 1 == 1 ? PoolHash.node(_peaks[l]!, cur) : PoolHash.node(cur, emptyRoots[l]);
    }
    return cur;
  }

  /// Append [leaf] at position [size]; returns that position.
  int append(List<int> leaf) {
    if (leaf.length != PoolHash.digestLanes) throw ArgumentError('leaf must be ${PoolHash.digestLanes} lanes');
    if (_size >= capacity) throw StateError('tree is full');
    var cur = leaf;
    var l = 0;
    while ((_size >> l) & 1 == 1) {
      cur = PoolHash.node(_peaks[l]!, cur);
      _peaks[l] = null;
      l++;
    }
    _peaks[l] = cur;
    return _size++;
  }
}

/// The wallet's view of the note commitment tree: every node that has been
/// computed, so a [MerklePath] can be produced for any leaf against the
/// current root. Appends keep a [MerkleFrontier] in step, and the two roots
/// are checked against each other.
class NoteCommitmentTree {
  static const depth = MerkleFrontier.depth;

  final MerkleFrontier frontier = MerkleFrontier();
  final MerkleStore _store = MerkleStore(depth);

  int get size => frontier.size;

  List<int> nodeAt(int level, int index) => _store.nodeAt(level, index);

  List<int> get root => _store.root;

  int append(List<int> leaf) {
    final pos = frontier.append(leaf);
    _store.set(pos, leaf);
    return pos;
  }

  /// The path of the leaf at [position] against the current [root].
  MerklePath path(int position) {
    if (position < 0 || position >= size) throw RangeError.range(position, 0, size - 1);
    return _store.path(position);
  }

  /// The path of the *next free* slot against the current root: what an
  /// append proof walks first, with the empty leaf, to show the slot is
  /// empty under the root it then updates.
  MerklePath appendPath() => _store.path(size);

  // ---- subtree batching (PP1_SP): the tree as depth 28 over depth-4 subtrees ----
  static const subtreeDepth = 5;
  static const subtreeLeaves = 1 << subtreeDepth;
  static const mainDepth = depth - subtreeDepth;

  /// The next free subtree index; the size must be subtree-aligned.
  int get nextSubtree {
    if (size % subtreeLeaves != 0) throw StateError('tree size $size is not subtree-aligned');
    return size ~/ subtreeLeaves;
  }

  /// Siblings of subtree [j] at the main levels (tree levels subtreeDepth..31).
  List<List<int>> subtreePath(int j) => [for (int l = 0; l < mainDepth; l++) nodeAt(subtreeDepth + l, (j >> l) ^ 1)];

  /// The root of the subtree over [leaves] (padded with empty leaves).
  static List<int> subtreeRoot(List<List<int>> leaves) {
    if (leaves.length > subtreeLeaves) throw ArgumentError('at most $subtreeLeaves leaves');
    var level = [...leaves, for (int i = leaves.length; i < subtreeLeaves; i++) MerkleFrontier.emptyLeaf];
    while (level.length > 1) {
      level = [for (int i = 0; i < level.length; i += 2) PoolHash.node(level[i], level[i + 1])];
    }
    return level[0];
  }

  /// Walk a subtree root up the main tree along [siblings] from index [j].
  static List<int> mainRoot(List<int> subtree, List<List<int>> siblings, int j) => PoolHash.root(subtree, siblings, j);

  /// Append a whole subtree of [leaves] (padded with empty leaves), returning
  /// its index. The padding leaves count towards [size].
  int appendSubtree(List<List<int>> leaves) {
    final j = nextSubtree;
    for (int i = 0; i < subtreeLeaves; i++) {
      append(i < leaves.length ? leaves[i] : MerkleFrontier.emptyLeaf);
    }
    return j;
  }
}
