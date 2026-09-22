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

import '../script_gen/pool_spend_air.dart' show PoolHash;
import 'poseidon2_batch.dart';
import 'm31.dart';

/// The pool's set of spent nullifiers as a sparse Poseidon2 Merkle tree,
/// updated inside the aggregation circuit (level 2) rather than in script.
///
/// A nullifier's slot is its first two lanes read as one 62-bit key (lane 0
/// the low 31 bits), so absence is shown by one path to an empty slot and
/// insertion by the same path to a filled one. A sorted tree with
/// adjacency proofs would need ordering comparisons of eight 31-bit lanes
/// in circuit; a keyed slot needs none, only the key's bits, which the
/// walk already takes. Two different nullifiers sharing 62 bits would
/// block the later spend. That takes about 2^31 nullifiers by chance, and
/// a nullifier is a hash of a key the spender alone holds, so nobody can
/// aim one at another's slot.
///
/// The key's bits must be the canonical ones. A lane is below p = 2^31 - 1,
/// but 31 bits can also spell p itself, which is 0 again, so a lane of 0
/// has two decompositions. The circuit forbids the all-ones pattern; without
/// that a nullifier ground to have a zero lane would have two slots and
/// could be spent twice.
///
/// Leaves are hashed as `H(0 ‖ nf)` and an empty slot is `H(0 ‖ 0)`, which
/// is the commitment tree's empty node of height 1, so an empty subtree of
/// height h here is that tree's empty node of height h + 1.
class NullifierTree {
  static const laneBits = 31;
  static const depth = 2 * laneBits;
  static const _zeros = [0, 0, 0, 0, 0, 0, 0, 0];

  /// empty[h]: the root of an empty subtree h levels above the leaf nodes.
  static final List<List<int>> empty = (() {
    final out = <List<int>>[PoolHash.node(_zeros, _zeros)];
    for (int h = 0; h < depth; h++) {
      out.add(PoolHash.node(out[h], out[h]));
    }
    return List<List<int>>.unmodifiable(out);
  })();

  static List<int> leafNode(List<int> nf) => PoolHash.node(_zeros, nf);

  /// The slot of [nf]: lane 0 then lane 1, 31 bits each.
  static int key(List<int> nf) {
    if (nf.length != PoolHash.digestLanes) throw ArgumentError('a nullifier is ${PoolHash.digestLanes} lanes');
    if (nf[0] < 0 || nf[0] >= M31.p || nf[1] < 0 || nf[1] >= M31.p) throw ArgumentError('lane out of range');
    return nf[0] | (nf[1] << laneBits);
  }

  final List<Map<int, List<int>>> _nodes;
  NullifierTree() : _nodes = List.generate(depth + 1, (_) => <int, List<int>>{});
  NullifierTree._(this._nodes);

  /// An independent copy: a round's insertions are proved before the round
  /// is mined, so a coordinator inserts into a copy and keeps it only once
  /// the round is.
  NullifierTree copy() => NullifierTree._([for (final m in _nodes) Map<int, List<int>>.of(m)]);

  /// The tree holding [nullifiers], built a level at a time from the leaves
  /// up. Inserting them one by one hashes a 62-node path each; here a node
  /// is hashed once, and below about level log2(n) nearly every node has
  /// one key under it, so that is still about 62 - log2(n) hashes a key,
  /// but in batches the native kernel runs. Throws when two share a slot,
  /// as [insert] would. Restoring a snapshot goes through here.
  static NullifierTree fromNullifiers(List<List<int>> nullifiers) {
    final t = NullifierTree();
    final n = nullifiers.length;
    if (n == 0) return t;
    final keys = [for (final nf in nullifiers) key(nf)];
    final order = List<int>.generate(n, (i) => i)..sort((a, b) => keys[a].compareTo(keys[b]));
    // the leaf nodes H(0 || nf), in key order
    final pairs = Uint32List(16 * n);
    var ks = List<int>.filled(n, 0);
    for (int j = 0; j < n; j++) {
      final i = order[j];
      if (j > 0 && keys[i] == ks[j - 1]) throw StateError('nullifier already spent');
      ks[j] = keys[i];
      pairs.setRange(16 * j + 8, 16 * j + 16, nullifiers[i]);
    }
    var cur = Poseidon2Batch.compress(pairs);
    for (int j = 0; j < n; j++) {
      t._nodes[0][ks[j]] = Uint32List.sublistView(cur, 8 * j, 8 * j + 8);
    }
    for (int h = 0; h < depth; h++) {
      // siblings are adjacent in key order; a lone child pairs with the
      // empty subtree of its height
      final parentKeys = <int>[];
      final pp = Uint32List(16 * ks.length);
      var j = 0, m = 0;
      while (j < ks.length) {
        final parent = ks[j] >> 1;
        final right = ks[j] & 1 == 1;
        if (!right && j + 1 < ks.length && ks[j + 1] == ks[j] + 1) {
          pp.setRange(16 * m, 16 * m + 16, cur, 8 * j);
          j += 2;
        } else if (right) {
          pp.setRange(16 * m, 16 * m + 8, empty[h]);
          pp.setRange(16 * m + 8, 16 * m + 16, cur, 8 * j);
          j += 1;
        } else {
          pp.setRange(16 * m, 16 * m + 8, cur, 8 * j);
          pp.setRange(16 * m + 8, 16 * m + 16, empty[h]);
          j += 1;
        }
        parentKeys.add(parent);
        m++;
      }
      cur = Poseidon2Batch.compress(Uint32List.sublistView(pp, 0, 16 * m));
      final level = t._nodes[h + 1];
      for (int p = 0; p < m; p++) {
        level[parentKeys[p]] = Uint32List.sublistView(cur, 8 * p, 8 * p + 8);
      }
      ks = parentKeys;
    }
    return t;
  }

  /// Spent nullifiers recorded.
  int get size => _nodes[0].length;

  List<int> _at(int h, int i) => _nodes[h][i] ?? empty[h];
  List<int> get root => _at(depth, 0);

  bool occupied(List<int> nf) => _nodes[0].containsKey(key(nf));

  /// The siblings of [nf]'s slot, leaf level first. They are the same
  /// before and after the slot is written, which is what lets one path
  /// show the slot empty and then filled.
  List<List<int>> path(List<int> nf) {
    final k = key(nf);
    return [for (int h = 0; h < depth; h++) _at(h, (k >> h) ^ 1)];
  }

  /// Record [nf] as spent; returns the path the circuit walks. Throws when
  /// its slot is taken, which is a double spend (or the 2^-62 collision).
  List<List<int>> insert(List<int> nf) {
    final k = key(nf);
    if (_nodes[0].containsKey(k)) throw StateError('nullifier already spent');
    final p = path(nf);
    var node = leafNode(nf);
    _nodes[0][k] = node;
    for (int h = 0; h < depth; h++) {
      final i = k >> h;
      node = i & 1 == 1 ? PoolHash.node(_at(h, i ^ 1), node) : PoolHash.node(node, _at(h, i ^ 1));
      _nodes[h + 1][i >> 1] = node;
    }
    return p;
  }

  /// The root reached from [leaf] (a leaf node) at slot [k] over [siblings].
  static List<int> rootFrom(List<int> leaf, int k, List<List<int>> siblings) {
    var node = leaf;
    for (int h = 0; h < siblings.length; h++) {
      node = (k >> h) & 1 == 1 ? PoolHash.node(siblings[h], node) : PoolHash.node(node, siblings[h]);
    }
    return node;
  }
}
