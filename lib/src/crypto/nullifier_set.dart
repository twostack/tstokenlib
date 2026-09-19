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
import 'package:crypto/crypto.dart' show sha256;

/// A path in a SHA256 Merkle tree: siblings from the leaf up, and the leaf
/// index whose bits (LSB first) say on which side each sibling sits.
class ShaMerklePath {
  final List<Uint8List> siblings;
  final int index;
  const ShaMerklePath(this.siblings, this.index);

  Uint8List rootFor(List<int> leaf) {
    var node = Uint8List.fromList(leaf);
    for (int l = 0; l < siblings.length; l++) {
      final s = siblings[l];
      node = ((index >> l) & 1) == 1 ? NullifierSet.node(s, node) : NullifierSet.node(node, s);
    }
    return node;
  }
}

/// A sparse SHA256 Merkle tree of fixed depth whose unwritten leaves are
/// [NullifierSet.emptyLeaf]; only written nodes are stored.
class ShaMerkleStore {
  final int depth;
  final List<Map<int, Uint8List>> _nodes;
  ShaMerkleStore(this.depth) : _nodes = List.generate(depth + 1, (_) => <int, Uint8List>{});

  Uint8List nodeAt(int level, int index) => _nodes[level][index] ?? NullifierSet.emptyRoots[level];
  Uint8List get root => nodeAt(depth, 0);

  void set(int index, List<int> leaf) {
    if (leaf.length != 32) throw ArgumentError('leaf must be 32 bytes');
    _nodes[0][index] = Uint8List.fromList(leaf);
    var idx = index;
    for (int l = 0; l < depth; l++) {
      final left = idx & ~1;
      _nodes[l + 1][idx >> 1] = NullifierSet.node(nodeAt(l, left), nodeAt(l, left | 1));
      idx >>= 1;
    }
  }

  ShaMerklePath path(int index) => ShaMerklePath([for (int l = 0; l < depth; l++) nodeAt(l, (index >> l) ^ 1)], index);
}

/// One leaf of the [NullifierSet]: a spent nullifier and the next larger one
/// in the set, hashed as `SHA256(value || next)` over two 32-byte strings.
///
/// The linked list carries no index. A spender only ever needs `value` and
/// `next` to show that nothing lies between them, and insertion preserves
/// that invariant without knowing where the next leaf sits.
class NullifierLeaf {
  final Uint8List value, next;
  NullifierLeaf(List<int> value, List<int> next)
      : value = Uint8List.fromList(value),
        next = Uint8List.fromList(next);
  Uint8List get digest => NullifierSet.hashLeaf(value, next);
}

/// A witness that one nullifier was absent and has been inserted. The
/// covenant consumes exactly this: it re-derives [rootBefore] from the low
/// leaf and its path, checks the two orderings, then re-derives [rootMid]
/// and [rootAfter] from the same two paths with updated leaves. The indices
/// only matter as direction bits; any leaf whose interval brackets the
/// nullifier, and any empty slot, will do.
class NullifierInsertion {
  final Uint8List nullifier;

  /// The leaf whose interval contains the nullifier, and its path.
  final int lowIndex;
  final NullifierLeaf low;
  final ShaMerklePath lowPath;

  /// The slot the new leaf goes into, and its path in the intermediate tree.
  final int newIndex;
  final NullifierLeaf created;
  final ShaMerklePath newPath;

  final Uint8List rootBefore, rootMid, rootAfter;

  const NullifierInsertion({
    required this.nullifier,
    required this.lowIndex,
    required this.low,
    required this.lowPath,
    required this.newIndex,
    required this.created,
    required this.newPath,
    required this.rootBefore,
    required this.rootMid,
    required this.rootAfter,
  });

  /// The leaf the low slot holds after the insertion.
  NullifierLeaf get lowAfter => NullifierLeaf(low.value, nullifier);

  /// Re-run the checks the covenant will run. Returns true when the witness
  /// is internally consistent; the caller still has to believe [rootBefore].
  bool verify() {
    if (NullifierSet.compare(low.value, nullifier) >= 0) return false;
    if (NullifierSet.compare(nullifier, low.next) >= 0) return false;
    if (!_eq(lowPath.rootFor(low.digest), rootBefore)) return false;
    if (!_eq(lowPath.rootFor(lowAfter.digest), rootMid)) return false;
    if (!_eq(newPath.rootFor(NullifierSet.emptyLeaf), rootMid)) return false;
    if (!_eq(newPath.rootFor(created.digest), rootAfter)) return false;
    return _eq(created.value, nullifier) && _eq(created.next, low.next);
  }

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// The pool's set of spent nullifiers, as an indexed Merkle tree over SHA256,
/// maintained by wallets and checked by the pool covenant in script.
///
/// Membership is not what a spend proves; *absence* is. Every leaf covers the
/// open interval between its own value and the next value in the set, so a
/// nullifier is absent exactly when some leaf's interval contains it. Proving
/// that costs one Merkle path instead of the tree's full key depth.
///
/// Values are 32-byte strings ordered as unsigned little-endian integers
/// (byte 31 most significant): the order OP_BIN2NUM / OP_LESSTHAN give on
/// chain. A nullifier from the circuit is its 8 M31 lanes serialised as
/// 4-byte LE words ([fromLanes]), so it is below 2^255 and never equals the
/// upper sentinel.
class NullifierSet {
  static const depth = 32;
  static final Uint8List minValue = Uint8List(32);
  static final Uint8List maxValue = Uint8List.fromList(List.filled(32, 0xff));
  static final Uint8List emptyLeaf = Uint8List(32);

  /// emptyRoots[l] is the root of an empty subtree of height l.
  static final List<Uint8List> emptyRoots = (() {
    final out = <Uint8List>[emptyLeaf];
    for (int l = 0; l < depth; l++) {
      out.add(node(out[l], out[l]));
    }
    return out;
  })();

  static Uint8List node(List<int> left, List<int> right) => Uint8List.fromList(sha256.convert([...left, ...right]).bytes);
  static Uint8List hashLeaf(List<int> value, List<int> next) => node(value, next);

  /// The transcript's serialisation of 8 M31 lanes: 4-byte LE words.
  static Uint8List fromLanes(List<int> lanes) {
    final out = Uint8List(4 * lanes.length);
    final bd = ByteData.view(out.buffer);
    for (int i = 0; i < lanes.length; i++) {
      bd.setUint32(4 * i, lanes[i], Endian.little);
    }
    return out;
  }

  /// The inverse of [fromLanes].
  static List<int> toLanes(List<int> bytes) {
    final bd = ByteData.view(Uint8List.fromList(bytes).buffer);
    return [for (int i = 0; i < bytes.length ~/ 4; i++) bd.getUint32(4 * i, Endian.little)];
  }

  static int compare(List<int> a, List<int> b) {
    if (a.length != b.length) throw ArgumentError('values differ in length');
    for (int i = a.length - 1; i >= 0; i--) {
      if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
  }

  final ShaMerkleStore _store = ShaMerkleStore(depth);
  final List<NullifierLeaf> _leaves = [];

  NullifierSet() {
    _write(0, NullifierLeaf(minValue, maxValue));
  }

  int get size => _leaves.length;
  Uint8List get root => _store.root;
  NullifierLeaf leafAt(int i) => _leaves[i];

  void _write(int index, NullifierLeaf leaf) {
    if (index == _leaves.length) {
      _leaves.add(leaf);
    } else {
      _leaves[index] = leaf;
    }
    _store.set(index, leaf.digest);
  }

  bool contains(List<int> nullifier) => _leaves.any((l) => compare(l.value, nullifier) == 0);

  /// The index of the leaf whose interval contains [nullifier], or -1 when
  /// the nullifier is already in the set.
  int lowIndexFor(List<int> nullifier) {
    for (int i = 0; i < _leaves.length; i++) {
      final l = _leaves[i];
      if (compare(l.value, nullifier) < 0 && compare(nullifier, l.next) < 0) return i;
      if (compare(l.value, nullifier) == 0) return -1;
    }
    return -1;
  }

  /// Insert [nullifier], returning the witness a spend will carry.
  NullifierInsertion insert(List<int> nullifier) {
    if (nullifier.length != 32) throw ArgumentError('nullifier must be 32 bytes');
    if (compare(nullifier, minValue) <= 0 || compare(nullifier, maxValue) >= 0) {
      throw ArgumentError('nullifier outside the sentinels');
    }
    final li = lowIndexFor(nullifier);
    if (li < 0) throw StateError('nullifier already spent');
    if (_leaves.length >= 1 << depth) throw StateError('nullifier set is full');

    final low = _leaves[li];
    final rootBefore = root;
    final lowPath = _store.path(li);
    final newIndex = _leaves.length;

    _write(li, NullifierLeaf(low.value, nullifier));
    final rootMid = root;
    final newPath = _store.path(newIndex);

    final created = NullifierLeaf(nullifier, low.next);
    _write(newIndex, created);

    return NullifierInsertion(
      nullifier: Uint8List.fromList(nullifier),
      lowIndex: li,
      low: low,
      lowPath: lowPath,
      newIndex: newIndex,
      created: created,
      newPath: newPath,
      rootBefore: rootBefore,
      rootMid: rootMid,
      rootAfter: root,
    );
  }
}
