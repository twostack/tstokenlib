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

import 'dart:typed_data';

import '../script_gen/pool_spend_air.dart' show PoolHash, PoolSpendAir;
import 'poseidon2_batch.dart';

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

  /// The tree level this store's level 0 is. Zero for the commitment tree
  /// itself; a store over block roots sits at the block level, and an
  /// unwritten node there is the empty subtree of *that* height, not of
  /// height zero.
  final int baseLevel;
  final List<Map<int, List<int>>> _nodes;
  MerkleStore(this.depth, {this.baseLevel = 0}) : _nodes = List.generate(depth + 1, (_) => <int, List<int>>{});
  MerkleStore._(this.depth, this.baseLevel, this._nodes);

  /// An independent copy. A node is replaced, never changed in place, so
  /// the copy shares them.
  MerkleStore copy() => MerkleStore._(depth, baseLevel, [for (final m in _nodes) Map<int, List<int>>.of(m)]);

  List<int> nodeAt(int level, int index) => _nodes[level][index] ?? MerkleFrontier.emptyRoots[baseLevel + level];

  /// Forgets every node at each level left of [keepFrom] at that level: a
  /// store that only ever has leaves appended never reads them again,
  /// because a [set] reads only the aligned pair holding the index it
  /// writes. What a follower still needs out of them it has already copied
  /// into the paths it keeps.
  void pruneLeft(int Function(int level) keepFrom) {
    for (int l = 0; l <= depth; l++) {
      final keep = keepFrom(l);
      _nodes[l].removeWhere((i, _) => i < keep);
    }
  }

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

  MerkleFrontier();
  MerkleFrontier._(this._size, List<List<int>?> peaks) {
    _peaks.setAll(0, peaks);
  }

  MerkleFrontier copy() => MerkleFrontier._(_size, _peaks);

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

  final MerkleFrontier frontier;
  final MerkleStore _store;

  NoteCommitmentTree()
      : frontier = MerkleFrontier(),
        _store = MerkleStore(depth);
  NoteCommitmentTree._(this.frontier, this._store);

  /// An independent copy: a reader applies a round to a copy and keeps it
  /// only if the round checks out, so a refused round needs no undo.
  NoteCommitmentTree copy() => NoteCommitmentTree._(frontier.copy(), _store.copy());

  /// The tree holding [leaves] in order, built a level at a time from the
  /// leaves up, so each node is hashed once (about as many hashes as
  /// leaves) where appending them one by one rewrites a 32-node path for
  /// each. The nodes are the ones [append] would have written, and the
  /// frontier is read off them. Restoring a snapshot goes through here.
  static NoteCommitmentTree fromLeaves(List<List<int>> leaves) {
    final n = leaves.length;
    if (n > MerkleFrontier.capacity) throw ArgumentError('at most ${MerkleFrontier.capacity} leaves');
    final t = NoteCommitmentTree();
    if (n == 0) return t;
    var cur = Uint32List(8 * n);
    for (int i = 0; i < n; i++) {
      final l = leaves[i];
      if (l.length != PoolHash.digestLanes) throw ArgumentError('leaf must be ${PoolHash.digestLanes} lanes');
      cur.setRange(8 * i, 8 * i + 8, l);
      t._store._nodes[0][i] = List.unmodifiable(l);
    }
    var count = n;
    for (int l = 0; l < depth; l++) {
      final parents = (count + 1) >> 1;
      final pairs = Uint32List(16 * parents);
      pairs.setRange(0, 16 * (count >> 1), cur);
      if (count.isOdd) {
        pairs.setRange(16 * (parents - 1), 16 * (parents - 1) + 8, cur, 8 * (count - 1));
        pairs.setRange(16 * (parents - 1) + 8, 16 * parents, MerkleFrontier.emptyRoots[l]);
      }
      final next = Poseidon2Batch.compress(pairs);
      final level = t._store._nodes[l + 1];
      for (int p = 0; p < parents; p++) {
        level[p] = Uint32List.sublistView(next, 8 * p, 8 * p + 8);
      }
      cur = next;
      count = parents;
    }
    t.frontier._size = n;
    for (int l = 0; l < depth; l++) {
      if ((n >> l) & 1 == 1) t.frontier._peaks[l] = t._store.nodeAt(l, (n >> l) - 1);
    }
    return t;
  }

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

/// Why a block root was not folded: the round it was offered for, and what
/// was wrong with it. A refused fold leaves the follower exactly as it was.
class FoldRefusal implements Exception {
  final int round;
  final String reason;
  const FoldRefusal(this.round, this.reason);
  @override
  String toString() => 'round $round refused: $reason';
}

/// A leaf's Merkle path kept current from block roots alone.
///
/// A round appends a fixed power-of-two block of leaves, so the leaf at
/// [position] sits in block `position >> blockLevel` and its siblings split
/// in two. The [blockLevel] below it are inside its own block and are fixed
/// the moment that round is mined. The ones above it follow from the blocks
/// that come after, one 32-byte root at a time: [BlockFold.fold] rewrites
/// exactly those that the new block falls under, which is at most one a
/// round.
class FoldedPath {
  final int position;
  final int blockLevel;
  final List<List<int>> _siblings;

  FoldedPath(MerklePath path, {required this.blockLevel})
      : position = path.position,
        _siblings = [for (final s in path.siblings) List<int>.of(s)] {
    if (_siblings.length != NoteCommitmentTree.depth) {
      throw ArgumentError('a path of ${NoteCommitmentTree.depth} siblings');
    }
  }

  /// The block (the round, less one) whose leaves this one is among.
  int get block => position >> blockLevel;

  /// The path as it stands, against the root of the last block folded.
  MerklePath get path => MerklePath([for (final s in _siblings) List<int>.unmodifiable(s)], position);
}

/// A party following a pool by its block roots: 32 bytes a round.
///
/// Round N appends the plan's fixed block of `1 << blockLevel` leaves at
/// block index N - 1, so the tree above the block level is a tree of block
/// roots and nothing else. Folding a round's block root into it gives the
/// pool's whole commitment root, which is the `cmRoot` of that round's
/// header: so a block root can be taken from anyone, checked against a
/// header proved off the chain, and it names nobody, which is why
/// following a pool costs a wallet no privacy.
///
/// What it holds is bounded: the aligned pair of nodes at each level above
/// the block level, and the paths it was asked to keep. Nothing grows with
/// the number of rounds.
class BlockFold {
  /// log2 of the leaves a round appends.
  final int blockLevel;
  final int leavesPerRound;

  int _rounds;
  MerkleStore _upper;
  final List<FoldedPath> _tracked = [];

  BlockFold._(this.blockLevel, this.leavesPerRound, this._rounds, this._upper);

  /// A follower at the pool's genesis, for a plan that appends
  /// [leavesPerRound] leaves a round.
  factory BlockFold(int leavesPerRound) {
    if (leavesPerRound <= 0 || leavesPerRound & (leavesPerRound - 1) != 0) {
      throw ArgumentError('a round appends a power of two leaves, not $leavesPerRound');
    }
    final level = leavesPerRound.bitLength - 1;
    return BlockFold._(level, leavesPerRound, 0, MerkleStore(NoteCommitmentTree.depth - level, baseLevel: level));
  }

  /// Rounds folded; the next block root expected is round `rounds + 1`'s.
  int get rounds => _rounds;

  /// Levels of tree above the block level.
  int get upperDepth => NoteCommitmentTree.depth - blockLevel;

  /// Leaves the pool holds after the rounds folded.
  int get size => _rounds * leavesPerRound;

  /// The pool's commitment root after the last block folded, in the 32
  /// bytes a header carries it in. Block roots, commitment roots and
  /// headers all meet on the wire as bytes; the paths this keeps are lanes,
  /// because a spend proof consumes them.
  List<int> get cmRoot => lanesToBytes(_upper.root);

  /// The same, in lanes.
  List<int> get rootLanes => _upper.root;

  /// The block root of the round the follower stands at, in 32 bytes.
  List<int> get lastBlockRoot {
    if (_rounds == 0) throw StateError('nothing has been folded');
    return lanesToBytes(_upper.nodeAt(0, _rounds - 1));
  }

  /// The complete left subtrees above the block level, in level order:
  /// with [lastBlockRoot] and the round, this is everything a new follower
  /// needs to fold from here on, and nothing else.
  ///
  /// One node per level where the block index has a bit set, so at most
  /// [upperDepth] of them: 23 nodes at production parameters, 736 bytes,
  /// whatever the pool's age.
  List<List<int>> get leftNodes {
    if (_rounds == 0) return const [];
    final m = _rounds - 1;
    return [
      for (int l = 0; l < upperDepth; l++)
        if ((m >> l) & 1 == 1) lanesToBytes(_upper.nodeAt(l, (m >> l) ^ 1))
    ];
  }

  /// A follower joining at [round], from that round's [blockRoot] and the
  /// left subtrees above the block level ([leftNodes]). It folds from
  /// round + 1 on exactly as one that had folded every round since the
  /// genesis; what it cannot do is bring an older leaf's path up to date,
  /// which is why a wallet holding notes folds every round from its note's
  /// own and only a wallet holding none joins this way.
  ///
  /// Nothing here is trusted: [cmRoot] after this must be the commitment
  /// root of a round the caller has proved off the chain, and a frontier
  /// that does not reproduce it is a frontier of some other tree.
  factory BlockFold.at(
      {required int leavesPerRound, required int round, required List<int> blockRoot, required List<List<int>> left}) {
    final empty = BlockFold(leavesPerRound);
    if (round < 1) throw ArgumentError('a frontier stands at round 1 or more, not $round');
    final m = round - 1;
    final upper = empty._upper;
    var k = 0;
    for (int l = 0; l < empty.upperDepth; l++) {
      if ((m >> l) & 1 == 1) {
        if (k >= left.length) {
          throw ArgumentError('round $round needs ${_leftCount(m, empty.upperDepth)} nodes above the block level, ${left.length} given');
        }
        upper._nodes[l][(m >> l) ^ 1] = bytesToLanes(left[k++]);
      }
    }
    if (k != left.length) {
      throw ArgumentError('round $round needs $k nodes above the block level, ${left.length} given');
    }
    upper.set(m, bytesToLanes(blockRoot));
    upper.pruneLeft((l) => (m >> l) & ~1);
    return BlockFold._(empty.blockLevel, leavesPerRound, round, upper);
  }

  static int _leftCount(int m, int upperDepth) {
    var n = 0;
    for (int l = 0; l < upperDepth; l++) {
      if ((m >> l) & 1 == 1) n++;
    }
    return n;
  }

  /// The nodes the follower is holding, level by level above the block
  /// level. For the state a new follower is given, see [leftNodes].
  List<(int, int, List<int>)> get frontier => [
        for (int l = 0; l <= upperDepth; l++)
          for (final e in _upper._nodes[l].entries) (l, e.key, e.value)
      ];

  /// Keeps [path] current on every later fold.
  FoldedPath track(FoldedPath path) {
    if (path.blockLevel != blockLevel) throw ArgumentError('a path of another pool\'s block size');
    _tracked.add(path);
    return path;
  }

  /// Keeps the path of the leaf at [position], as the pool gave it when
  /// that leaf's round was mined, current from here on.
  FoldedPath follow(MerklePath path) => track(FoldedPath(path, blockLevel: blockLevel));

  void forget(FoldedPath path) => _tracked.remove(path);

  /// Folds round [round]'s [blockRoot] and returns the commitment root it
  /// gives, having brought every tracked path to it.
  ///
  /// With [cmRoot] the fold is checked: the root computed must be the one
  /// that round's header carries, and a fold that does not match is
  /// refused naming the round and changes nothing. That check is what
  /// makes a block root safe to take from a coordinator, a peer or a
  /// stranger; without it a follower is only as right as whoever sent the
  /// bytes.
  List<int> fold(int round, List<int> blockRoot, {List<int>? cmRoot}) {
    if (blockRoot.length != 32) {
      throw FoldRefusal(round, 'a block root is 32 bytes, not ${blockRoot.length}');
    }
    if (cmRoot != null && cmRoot.length != 32) {
      throw FoldRefusal(round, 'a commitment root is 32 bytes, not ${cmRoot.length}');
    }
    final List<int> lanes;
    try {
      lanes = bytesToLanes(blockRoot);
    } on ArgumentError {
      throw FoldRefusal(round, 'the block root holds a lane outside the field');
    }
    if (round != _rounds + 1) {
      throw FoldRefusal(round, 'the follower stands at round $_rounds, so the next block root is round ${_rounds + 1}\'s; '
          'a round cannot be skipped, because the rounds between it and here hold the leaves this one sits on');
    }
    final block = round - 1;
    // worked out on a copy, so a fold that does not check out leaves
    // nothing behind
    final trial = _upper.copy();
    trial.set(block, lanes);
    final root = lanesToBytes(trial.root);
    if (cmRoot != null && !_eqLanes(root, cmRoot)) {
      throw FoldRefusal(round, 'the block root given does not fold to the commitment root round $round\'s header carries');
    }
    _upper = trial;
    _rounds = round;
    for (final p in _tracked) {
      final j = p.block;
      for (int l = 0; l < upperDepth; l++) {
        // the new block sits under this path's sibling at level l, so that
        // sibling has changed and no other has
        if ((block >> l) == ((j >> l) ^ 1)) p._siblings[blockLevel + l] = _upper.nodeAt(l, block >> l);
      }
    }
    // everything left of the aligned pair at each level is a complete
    // subtree no later block reads, and every tracked path that wanted one
    // has taken its copy
    _upper.pruneLeft((l) => (block >> l) & ~1);
    return root;
  }

  /// 8 lanes as the 32 little-endian bytes a header and the wire carry.
  static List<int> lanesToBytes(List<int> lanes) => [
        for (final l in lanes) ...[l & 0xff, (l >> 8) & 0xff, (l >> 16) & 0xff, (l >> 24) & 0xff]
      ];

  /// The reverse, refusing a lane outside the field.
  static List<int> bytesToLanes(List<int> bytes) {
    if (bytes.length != 32) throw ArgumentError('32 bytes');
    final out = [for (int i = 0; i < 32; i += 4) bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)];
    if (out.any((l) => l < 0 || l >= 0x7fffffff)) throw ArgumentError('a lane outside the field');
    return out;
  }

  static bool _eqLanes(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
