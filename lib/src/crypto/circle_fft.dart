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
import 'm31.dart';

/// Circle FFT over M31 (Haböck–Levit–Papini), specialised to the domain
/// conventions used by `StarkVerifierGen` / `StarkProverRef`.
///
/// Domain layout ("twin layout"): a circle domain of size 2^(m+1) is
/// HalfCoset(m) ∪ conj(HalfCoset(m)). Values are stored in one array of
/// size 2^(m+1): position i < M holds f(H.at(i)), position M + i holds
/// f(conj H.at(i)) with conj (x, y) = (x, -y). This is exactly the order in
/// which the verifier's Merkle leaves are laid out.
///
/// The standard circle domain D_k of `circleDomain(k)` (points h·g^j in cyclic
/// order) is the twin layout of HalfCoset(k-1): cyclic index 2i is H.at(i) and
/// cyclic index 2^k-1-2i is conj H.at(i); see [twinIndex].
///
/// Coefficient basis (natural order, index bits low to high):
///   bit 0 -> y, bit 1 -> x, bit 2 -> π(x), bit 3 -> π²(x), ...   π(x) = 2x²-1
/// i.e. coefficient i multiplies y^{b0} · x^{b1} · π(x)^{b2} · ... The x-part
/// with index j = i >> 1 has degree exactly j, so the coefficients with index
/// < 2^n span the same space as the reference basis {x^i, y x^i : i < 2^(n-1)}
/// and zero-padding a coefficient vector extends the polynomial to a larger
/// domain unchanged. Multiplying by π^k(x) is a shift of the x-index by 2^k.
class CircleFft {
  static const int _p = M31.p;

  @pragma('vm:prefer-inline')
  static int mul(int a, int b) {
    final x = a * b;
    var r = (x & _p) + (x >> 31);
    r = (r & _p) + (r >> 31);
    return r >= _p ? r - _p : r;
  }

  @pragma('vm:prefer-inline')
  static int add(int a, int b) {
    final r = a + b;
    return r >= _p ? r - _p : r;
  }

  @pragma('vm:prefer-inline')
  static int sub(int a, int b) {
    final r = a - b;
    return r < 0 ? r + _p : r;
  }

  static int bitrev(int x, int bits) {
    var r = 0;
    for (int i = 0; i < bits; i++) {
      r = (r << 1) | ((x >> i) & 1);
    }
    return r;
  }

  static int log2(int n) {
    if (n <= 0 || (n & (n - 1)) != 0) throw ArgumentError('not a power of two: $n');
    return n.bitLength - 1;
  }

  /// Position in the twin layout of the size-2^logDomain circle domain of the
  /// point with cyclic index [cyc] (h·g^cyc, h = gen(logDomain+1), g = gen(logDomain)).
  static int twinIndex(int logDomain, int cyc) {
    final m = 1 << (logDomain - 1);
    return cyc.isEven ? cyc >> 1 : m + ((2 * m - 1 - cyc) >> 1);
  }

  /// Inverse of [twinIndex].
  static int cyclicIndex(int logDomain, int twin) {
    final m = 1 << (logDomain - 1);
    return twin < m ? 2 * twin : 2 * m - 1 - 2 * (twin - m);
  }

  /// Batch inversion (Montgomery trick). Zero entries are not allowed.
  static Uint32List batchInv(Uint32List xs) {
    final n = xs.length;
    final prefix = Uint32List(n);
    var acc = 1;
    for (int i = 0; i < n; i++) {
      prefix[i] = acc;
      acc = mul(acc, xs[i]);
    }
    var inv = M31.inv(acc);
    final out = Uint32List(n);
    for (int i = n - 1; i >= 0; i--) {
      out[i] = mul(inv, prefix[i]);
      inv = mul(inv, xs[i]);
    }
    return out;
  }

  /// Evaluations (twin layout on HalfCoset(m), size 2^(m+1)) -> coefficients
  /// (natural order, size 2^(m+1)).
  static Uint32List interpolate(Uint32List vals, int m) {
    final M = 1 << m, N = 2 * M;
    if (vals.length != N) throw ArgumentError('expected ${N} values, got ${vals.length}');
    final v = Uint32List.fromList(vals);
    // circle level: f = f0(x) + y f1(x)
    final yInv = CosetTables.of(m).yInv;
    for (int i = 0; i < M; i++) {
      final a = v[i], b = v[M + i];
      v[i] = add(a, b);
      v[M + i] = mul(sub(a, b), yInv[i]);
    }
    // line levels: f(x) = g0(π x) + x g1(π x), blocks of size L = M >> l
    for (int l = 0; (M >> l) >= 2; l++) {
      final L = M >> l, h = L >> 1;
      final xInv = CosetTables.of(m - l).xInv;
      for (int s = 0; s < N; s += L) {
        for (int i = 0; i < h; i++) {
          final a = v[s + i], b = v[s + i + h];
          v[s + i] = add(a, b);
          v[s + i + h] = mul(sub(a, b), xInv[i]);
        }
      }
    }
    final nInv = M31.inv(N);
    final n = m + 1;
    final out = Uint32List(N);
    for (int pos = 0; pos < N; pos++) {
      out[bitrev(pos, n)] = mul(v[pos], nInv);
    }
    return out;
  }

  /// Coefficients (natural order, length a power of two ≤ 2^(m+1)) ->
  /// evaluations in twin layout on HalfCoset(m). Shorter coefficient vectors
  /// are zero-padded, which is the low-degree extension.
  static Uint32List evaluate(Uint32List coefs, int m) {
    final M = 1 << m, N = 2 * M, n = m + 1;
    if (coefs.length > N) throw ArgumentError('too many coefficients for domain');
    log2(coefs.length);
    final v = Uint32List(N);
    for (int i = 0; i < coefs.length; i++) {
      v[bitrev(i, n)] = coefs[i];
    }
    for (int l = m - 1; l >= 0; l--) {
      final L = M >> l, h = L >> 1;
      final xs = CosetTables.of(m - l).x;
      for (int s = 0; s < N; s += L) {
        for (int i = 0; i < h; i++) {
          final a = v[s + i], b = mul(xs[i], v[s + i + h]);
          v[s + i] = add(a, b);
          v[s + i + h] = sub(a, b);
        }
      }
    }
    final ys = CosetTables.of(m).y;
    for (int i = 0; i < M; i++) {
      final a = v[i], b = mul(ys[i], v[M + i]);
      v[i] = add(a, b);
      v[M + i] = sub(a, b);
    }
    return v;
  }

  /// Evaluate a coefficient vector at an arbitrary (extension-field) point.
  static QM31 evalAt(Uint32List coefs, QM31 x, QM31 y) {
    final n = log2(coefs.length);
    if (n == 0) return QM31.fromLimbs(coefs[0], 0, 0, 0);
    // level 0: pair (2j, 2j+1) with y; all coefficients still base-field
    var v = List<QM31>.generate(coefs.length >> 1, (j) => QM31.fromLimbs(coefs[2 * j], 0, 0, 0) + y.scale(coefs[2 * j + 1]));
    var tw = x;
    for (int k = 1; k < n; k++) {
      v = List<QM31>.generate(v.length >> 1, (j) => v[2 * j] + tw * v[2 * j + 1]);
      tw = tw * tw + tw * tw - QM31.one;
    }
    return v[0];
  }
}

/// Cached x/y coordinates (natural order) of HalfCoset(logSize), plus their
/// batch inverses.
class CosetTables {
  final int logSize;
  final Uint32List x, y;
  Uint32List? _xInv, _yInv;

  static final Map<int, CosetTables> _cache = {};
  static CosetTables of(int logSize) => _cache.putIfAbsent(logSize, () => CosetTables._(logSize));

  CosetTables._(this.logSize)
      : x = Uint32List(1 << logSize),
        y = Uint32List(1 << logSize) {
    final h = HalfCoset(logSize);
    var p = h.initial;
    for (int i = 0; i < x.length; i++) {
      x[i] = p.x;
      y[i] = p.y;
      p = p * h.step;
    }
  }

  int get size => x.length;
  Uint32List get xInv => _xInv ??= CircleFft.batchInv(x);
  Uint32List get yInv => _yInv ??= CircleFft.batchInv(y);
}
