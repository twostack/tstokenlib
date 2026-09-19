import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/circle_fft.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';

void main() {
  final rng = Random(42);
  QM31 randQ() => QM31.fromLimbs(rng.nextInt(M31.p), rng.nextInt(M31.p), rng.nextInt(M31.p), rng.nextInt(M31.p));

  test('twin index maps circleDomain(k) onto HalfCoset(k-1) and its conjugate', () {
    for (final k in [1, 2, 3, 5]) {
      final d = circleDomain(k);
      final h = HalfCoset(k - 1);
      for (int cyc = 0; cyc < d.length; cyc++) {
        final tw = CircleFft.twinIndex(k, cyc);
        expect(CircleFft.cyclicIndex(k, tw), cyc);
        final i = tw < h.size ? tw : tw - h.size;
        final p = h.at(i);
        expect(d[cyc], tw < h.size ? p : CirclePoint(p.x, M31.neg(p.y)));
      }
    }
  });

  test('line twiddles at level l are the x-coordinates of the doubled coset', () {
    for (final m in [2, 5, 8]) {
      final xs = CosetTables.of(m).x;
      var cur = Uint32List.fromList(xs);
      for (int l = 1; l <= m - 1; l++) {
        cur = Uint32List.fromList([for (int i = 0; i < cur.length ~/ 2; i++) M31.sub(M31.mul(2, M31.mul(cur[i], cur[i])), 1)]);
        expect(cur, CosetTables.of(m - l).x.sublist(0, cur.length));
      }
    }
  });

  test('interpolate/evaluate round trip and agreement with the reference interpolant', () {
    for (final m in [0, 1, 2, 4, 6]) {
      final n = 2 << m;
      final vals = Uint32List.fromList([for (int i = 0; i < n; i++) rng.nextInt(M31.p)]);
      final coefs = CircleFft.interpolate(vals, m);
      expect(CircleFft.evaluate(coefs, m), vals);
      // reference interpolation on the same points, given in cyclic order
      final d = circleDomain(m + 1);
      final ref = CirclePolyRef.interpolate(d, [for (int cyc = 0; cyc < n; cyc++) embed(vals[CircleFft.twinIndex(m + 1, cyc)])]);
      for (int k = 0; k < 3; k++) {
        final x = randQ(), y = randQ();
        expect(CircleFft.evalAt(coefs, x, y), ref.eval(x, y), reason: 'm=$m');
      }
    }
  });

  test('zero-padded coefficients give the low-degree extension', () {
    const m = 3, big = 6;
    final n = 2 << m;
    final vals = Uint32List.fromList([for (int i = 0; i < n; i++) rng.nextInt(M31.p)]);
    final coefs = CircleFft.interpolate(vals, m);
    final ext = CircleFft.evaluate(coefs, big);
    final h = HalfCoset(big);
    for (final i in [0, 1, 7, 33, h.size - 1]) {
      final p = h.at(i);
      expect(embed(ext[i]), CircleFft.evalAt(coefs, embed(p.x), embed(p.y)));
      expect(embed(ext[h.size + i]), CircleFft.evalAt(coefs, embed(p.x), embed(M31.neg(p.y))));
    }
    // and it agrees with the small domain on the small domain
    final small = HalfCoset(m);
    final ref = CirclePolyRef.interpolate(circleDomain(m + 1), [for (int cyc = 0; cyc < n; cyc++) embed(vals[CircleFft.twinIndex(m + 1, cyc)])]);
    expect(ref.evalP(small.at(5)), embed(vals[5]));
    expect(CircleFft.evalAt(coefs, embed(small.at(5).x), embed(small.at(5).y)), embed(vals[5]));
  });

  test('x-index shift by 2^k multiplies by pi^k(x)', () {
    const m = 4, k = 2;
    final n = 2 << m;
    final coefs = Uint32List(n);
    for (int i = 0; i < (2 << k); i++) {
      coefs[i] = rng.nextInt(M31.p);
    }
    final shifted = Uint32List(n);
    for (int i = 0; i < (2 << k); i++) {
      shifted[i + (2 << k)] = coefs[i]; // x-index j -> j + 2^k  <=> combined index i -> i + 2^(k+1)
    }
    final x = randQ(), y = randQ();
    var pik = x;
    for (int i = 0; i < k; i++) {
      pik = pik * pik + pik * pik - QM31.one;
    }
    expect(CircleFft.evalAt(shifted, x, y), CircleFft.evalAt(coefs, x, y) * pik);
  });

  test('batch inversion', () {
    final xs = Uint32List.fromList([for (int i = 0; i < 37; i++) rng.nextInt(M31.p - 1) + 1]);
    final inv = CircleFft.batchInv(xs);
    for (int i = 0; i < xs.length; i++) {
      expect(M31.mul(xs[i], inv[i]), 1);
    }
  });

  test('mersenne reduction matches modular arithmetic', () {
    for (int i = 0; i < 1000; i++) {
      final a = rng.nextInt(M31.p), b = rng.nextInt(M31.p);
      expect(CircleFft.mul(a, b), M31.mul(a, b));
      expect(CircleFft.add(a, b), M31.add(a, b));
      expect(CircleFft.sub(a, b), M31.sub(a, b));
    }
    expect(CircleFft.mul(M31.p - 1, M31.p - 1), 1);
    expect(CircleFft.mul(0, 5), 0);
  });
}
