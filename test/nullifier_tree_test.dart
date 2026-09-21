import 'dart:math';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';

void main() {
  final rng = Random(11);
  List<int> nf() => List.generate(8, (_) => rng.nextInt(M31.p));

  test('an empty slot of height h is the commitment tree\'s empty node of height h + 1', () {
    for (int h = 0; h < MerkleFrontier.emptyRoots.length - 1; h++) {
      expect(NullifierTree.empty[h], MerkleFrontier.emptyRoots[h + 1]);
    }
  });

  test('one path shows the slot empty before and filled after', () {
    final t = NullifierTree();
    for (int i = 0; i < 20; i++) {
      final n = nf(), before = t.root, k = NullifierTree.key(n);
      final p = t.insert(n);
      expect(NullifierTree.rootFrom(NullifierTree.empty[0], k, p), before);
      expect(NullifierTree.rootFrom(NullifierTree.leafNode(n), k, p), t.root);
      expect(t.occupied(n), isTrue);
    }
  });

  test('a nullifier is spent once', () {
    final t = NullifierTree(), n = nf();
    t.insert(n);
    expect(() => t.insert(n), throwsStateError);
    // same slot, different tail: blocked as well (the 2^-62 case)
    expect(() => t.insert([n[0], n[1], ...nf().sublist(2)]), throwsStateError);
  });

  test('the key is lane 0 low, lane 1 high', () {
    expect(NullifierTree.key([5, 3, 0, 0, 0, 0, 0, 0]), 5 | (3 << 31));
    expect(() => NullifierTree.key([M31.p, 0, 0, 0, 0, 0, 0, 0]), throwsArgumentError);
  });
}
