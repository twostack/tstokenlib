import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/nullifier_set.dart';

void main() {
  final rng = Random(99);
  Uint8List nf() => NullifierSet.fromLanes(List.generate(8, (_) => rng.nextInt(M31.p)));

  test('an empty set is one sentinel leaf, ordered as little-endian integers', () {
    final s = NullifierSet();
    expect(s.size, 1);
    expect(s.leafAt(0).value, NullifierSet.minValue);
    expect(s.leafAt(0).next, NullifierSet.maxValue);
    expect(s.root, isNot(equals(NullifierSet.emptyRoots[32])));
    // byte 31 is the most significant, as OP_BIN2NUM reads a 32-byte string
    final lo = Uint8List(32)..[0] = 9;
    final hi = Uint8List(32)..[31] = 1;
    expect(NullifierSet.compare(lo, hi), -1);
    expect(NullifierSet.compare(hi, lo), 1);
    expect(NullifierSet.compare(lo, lo), 0);
    // a lane image is below 2^255
    final v = nf();
    expect(v[31] < 0x80, isTrue);
    expect(NullifierSet.compare(v, NullifierSet.maxValue), -1);
  });

  test('every insertion yields a witness that verifies, and the roots chain', () {
    final s = NullifierSet();
    final seen = <Uint8List>[];
    var previous = s.root;
    for (int i = 0; i < 40; i++) {
      final v = nf();
      expect(s.contains(v), isFalse);
      final w = s.insert(v);
      expect(w.rootBefore, previous, reason: 'insertion $i starts where the last ended');
      expect(w.verify(), isTrue, reason: 'witness $i');
      expect(w.rootAfter, s.root);
      expect(w.newIndex, i + 1);
      expect(s.contains(v), isTrue);
      seen.add(v);
      previous = s.root;
      for (int j = 0; j < s.size; j++) {
        expect(NullifierSet.compare(s.leafAt(j).value, s.leafAt(j).next), -1, reason: 'leaf $j ordered');
        for (final u in seen) {
          final inside = NullifierSet.compare(s.leafAt(j).value, u) < 0 && NullifierSet.compare(u, s.leafAt(j).next) < 0;
          expect(inside, isFalse, reason: 'a spent nullifier sits inside an interval');
        }
      }
    }
    expect(() => s.insert(seen[7]), throwsA(isA<StateError>()));
    expect(s.lowIndexFor(seen[7]), -1);
  });

  test('a witness does not verify once any of its parts is altered', () {
    final s = NullifierSet();
    for (int i = 0; i < 5; i++) {
      s.insert(nf());
    }
    final v = nf();
    final w = s.insert(v);
    expect(w.verify(), isTrue);

    NullifierInsertion tweak({
      Uint8List? nullifier, NullifierLeaf? low, ShaMerklePath? lowPath,
      NullifierLeaf? created, Uint8List? rootMid, Uint8List? rootAfter,
    }) => NullifierInsertion(
          nullifier: nullifier ?? w.nullifier, lowIndex: w.lowIndex, low: low ?? w.low,
          lowPath: lowPath ?? w.lowPath, newIndex: w.newIndex, created: created ?? w.created,
          newPath: w.newPath, rootBefore: w.rootBefore, rootMid: rootMid ?? w.rootMid,
          rootAfter: rootAfter ?? w.rootAfter);

    expect(tweak(nullifier: nf()).verify(), isFalse);
    expect(tweak(low: NullifierLeaf(w.nullifier, w.low.next)).verify(), isFalse);
    expect(tweak(low: NullifierLeaf(NullifierSet.minValue, NullifierSet.maxValue)).verify(), isFalse);
    final badPath = ShaMerklePath([...w.lowPath.siblings]..[4] = nf(), w.lowPath.index);
    expect(tweak(lowPath: badPath).verify(), isFalse);
    expect(tweak(created: NullifierLeaf(w.nullifier, NullifierSet.maxValue)).verify(), isFalse);
    expect(tweak(rootMid: nf()).verify(), isFalse);
    expect(tweak(rootAfter: nf()).verify(), isFalse);
  });

  test('two nullifiers of one spend chain through the set', () {
    final s = NullifierSet();
    final a = nf(), b = nf();
    final wa = s.insert(a);
    final wb = s.insert(b);
    expect(wa.rootAfter, wb.rootBefore);
    expect(wa.verify(), isTrue);
    expect(wb.verify(), isTrue);
    expect(wb.newIndex, wa.newIndex + 1);
    expect(s.root, wb.rootAfter);
  });
}
