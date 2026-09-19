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

import '../crypto/m31.dart';
import 'm31_script_gen.dart';

List<String> limbNames(String base) => List.generate(4, (k) => '${base}_$k');

/// Circle-STARK DEEP quotient (Stwo's complex-conjugate-line construction).
///
/// For a sample point z = (zx, zy) in QM31 and a column value v = f(z), with
/// conj the automorphism u -> -u of QM31 (so f(conj z) = conj f(z) for
/// base-field f), the line through (z, v) and (conj z, conj v), scaled by
/// c = conj(zy) - zy, is
///   c * l(p) = a * p.y + b,   a = conj(v) - v,   b = c * v - a * zy.
/// The numerator c * f(p) - a * p.y - b vanishes at z and conj z, and the
/// denominator is the line through z and conj z:
///   D(p) = dA * p.x + dB * p.y + dC
///   dA = zy - conj(zy),  dB = conj(zx) - zx,  dC = zx * conj(zy) - zy * conj(zx)
/// With per-column weights w_j = alpha^j the batched quotient at p is
///   q(p) = ( c * Σ_j w_j f_j(p)  -  p.y * Σ_j w_j a_j  -  Σ_j w_j b_j ) / D(p)
/// Everything except Σ_j w_j f_j(p) is independent of p and precomputed once.
class DeepConstants {
  final QM31 c, A, B, dA, dB, dC;
  final List<QM31> weights;
  DeepConstants(this.c, this.A, this.B, this.dA, this.dB, this.dC, this.weights);
}

class DeepQuotientRef {
  /// With [base] the weights are base * alpha^j: a group whose weights are
  /// a scalar multiple of another's shares that group's weighted sum of
  /// the openings (one sum per query point for both).
  static DeepConstants precompute(QM31 zx, QM31 zy, List<QM31> values, QM31 alpha, {QM31? base}) {
    final c = zy.conj - zy;
    final dA = zy - zy.conj;
    final dB = zx.conj - zx;
    final dC = zx * zy.conj - zy * zx.conj;
    var w = base ?? QM31.one;
    var A = QM31.zero, B = QM31.zero;
    final weights = <QM31>[];
    for (final v in values) {
      weights.add(w);
      final a = v.conj - v;
      final b = c * v - a * zy;
      A = A + w * a;
      B = B + w * b;
      w = w * alpha;
    }
    return DeepConstants(c, A, B, dA, dB, dC, weights);
  }

  static QM31 denominator(DeepConstants k, int px, int py) =>
      k.dA.scale(px) + k.dB.scale(py) + k.dC;

  static QM31 quotient(DeepConstants k, int px, int py, List<int> openings) {
    var s = QM31.zero;
    for (int j = 0; j < openings.length; j++) {
      s = s + k.weights[j].scale(openings[j]);
    }
    final n = k.c * s - k.A.scale(py) - k.B;
    return n * denominator(k, px, py).inv;
  }
}

class DeepQuotientScriptGen {
  static void _copy(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.pick(src[k], as: dst[k]);
    }
  }

  /// Push conj(v) = (v0, v1, -v2, -v3) as new limbs, lazily (negatives unreduced).
  static void _pushConj(StackEmitter e, List<String> v, List<String> out) {
    e.pick(v[0], as: out[0]);
    e.pick(v[1], as: out[1]);
    e.pushConst(0);
    e.pick(v[2]);
    e.sub();
    e.nameTop(out[2]);
    e.pushConst(0);
    e.pick(v[3]);
    e.sub();
    e.nameTop(out[3]);
  }

  /// out = x - y limbwise (lazy), consuming both.
  static void _subInto(StackEmitter e, List<String> x, List<String> y, List<String> out) {
    for (int k = 0; k < 4; k++) {
      e.roll(x[k]);
      e.roll(y[k]);
      e.sub();
      e.nameTop(out[k]);
    }
  }

  /// acc += t limbwise (lazy), consuming t.
  static void _addInto(StackEmitter e, List<String> acc, List<String> t) {
    for (int k = 0; k < 4; k++) {
      e.roll(acc[k]);
      e.roll(t[k]);
      e.add();
      e.nameTop(acc[k]);
    }
  }

  static void _reduceAll(StackEmitter e, List<String> x) {
    for (int k = 0; k < 4; k++) {
      e.roll(x[k]);
      e.reduce();
    }
  }

  /// One-time precompute for one sample point.
  ///
  /// Expects named limbs for zx, zy, alpha and each value v_j (all canonical).
  /// Consumes the values; keeps zx, zy, alpha. Leaves, all canonical:
  ///   c_*, A_*, B_*, dA_*, dB_*, dC_*, and w{j}_* for j in 0..C-1.
  /// With [weightsTag] the weights of that earlier group are reused (picked)
  /// and no weights are pushed for this one; with [base] the accumulators
  /// are scaled by it afterwards (this group's weights = base * theirs).
  static void emitPrecompute(StackEmitter e, List<String> zx, List<String> zy,
      List<String> alpha, List<List<String>> values, {String tag = '', String? weightsTag, List<String>? base}) {
    final C = values.length;
    List<String> T(String b) => limbNames('$b$tag');
    final wTag = weightsTag ?? tag;
    // c = conj(zy) - zy ; dA = zy - conj(zy) ; dB = conj(zx) - zx
    _pushConj(e, zy, limbNames('_czy'));
    _copy(e, zy, limbNames('_zy1'));
    _subInto(e, limbNames('_czy'), limbNames('_zy1'), T('c'));
    _reduceAll(e, T('c'));
    _copy(e, zy, limbNames('_zy2'));
    _pushConj(e, zy, limbNames('_czy2'));
    _subInto(e, limbNames('_zy2'), limbNames('_czy2'), T('dA'));
    _reduceAll(e, T('dA'));
    _pushConj(e, zx, limbNames('_czx'));
    _copy(e, zx, limbNames('_zx1'));
    _subInto(e, limbNames('_czx'), limbNames('_zx1'), T('dB'));
    _reduceAll(e, T('dB'));
    // dC = zx * conj(zy) - zy * conj(zx)
    _copy(e, zx, limbNames('_zx2'));
    _pushConj(e, zy, limbNames('_czy3'));
    M31Ops.qm31Mul(e, limbNames('_zx2'), limbNames('_czy3'), limbNames('_t1'), reduceOut: false);
    _copy(e, zy, limbNames('_zy3'));
    _pushConj(e, zx, limbNames('_czx2'));
    M31Ops.qm31Mul(e, limbNames('_zy3'), limbNames('_czx2'), limbNames('_t2'), reduceOut: false);
    _subInto(e, limbNames('_t1'), limbNames('_t2'), T('dC'));
    _reduceAll(e, T('dC'));

    // Accumulators: V = Σ w_j v_j, A = Σ w_j a_j. Then B = c·V - zy·A, since
    // b_j = c v_j - a_j zy is linear in v_j and a_j.
    for (int k = 0; k < 4; k++) {
      e.pushConst(0, as: 'V${tag}_$k');
    }
    for (int k = 0; k < 4; k++) {
      e.pushConst(0, as: 'A${tag}_$k');
    }
    if (weightsTag == null) {
      e.pushConst(1, as: 'w${tag}0_0');
      e.pushConst(0, as: 'w${tag}0_1');
      e.pushConst(0, as: 'w${tag}0_2');
      e.pushConst(0, as: 'w${tag}0_3');
    }

    for (int j = 0; j < C; j++) {
      final v = values[j];
      final w = limbNames('w$wTag$j');
      // a_j = conj(v) - v = (0, 0, -2 v2, -2 v3)   (lazy)
      e.pushConst(0);
      e.pick(v[2]);
      e.dup();
      e.add();
      e.sub();
      e.nameTop('_a_2');
      e.pushConst(0);
      e.pick(v[3]);
      e.dup();
      e.add();
      e.sub();
      e.nameTop('_a_3');
      // V += w * v   (v consumed, w picked)
      M31Ops.qm31Mul(e, w, v, limbNames('_wv'), reduceOut: false, consumeA: false);
      _addInto(e, T('V'), limbNames('_wv'));
      // A += w * a   (a has two zero limbs)
      M31Ops.qm31MulHi(e, w, '_a_2', '_a_3', limbNames('_wa'), reduceOut: false, consumeA: false);
      _addInto(e, T('A'), limbNames('_wa'));
      // w_{j+1} = w_j * alpha
      if (weightsTag == null && j < C - 1) {
        M31Ops.qm31Mul(e, w, alpha, limbNames('w$tag${j + 1}'), consumeA: false, consumeB: false);
      }
    }
    _reduceAll(e, T('V'));
    _reduceAll(e, T('A'));
    if (base != null) {
      for (final acc in ['V', 'A']) {
        _copy(e, base, limbNames('_bs'));
        M31Ops.qm31Mul(e, T(acc), limbNames('_bs'), limbNames('_bsr'));
        for (int k = 0; k < 4; k++) {
          e.rename('_bsr_$k', T(acc)[k]);
        }
      }
    }
    // B = c * V - zy * A
    _copy(e, T('c'), limbNames('_c1'));
    M31Ops.qm31Mul(e, limbNames('_c1'), T('V'), limbNames('_cV'), reduceOut: false);
    _copy(e, zy, limbNames('_zy4'));
    _copy(e, T('A'), limbNames('_A1'));
    M31Ops.qm31Mul(e, limbNames('_zy4'), limbNames('_A1'), limbNames('_zyA'), reduceOut: false);
    _subInto(e, limbNames('_cV'), limbNames('_zyA'), T('B'));
    _reduceAll(e, T('B'));
  }

  /// Per query point. Expects px, py (canonical M31), openings o_j (M31),
  /// a prover hint h = D(p)^-1 (4 limbs), and the precomputed constants.
  /// Consumes the openings and the hint; leaves q(p) canonical as [out].
  /// With [negY] the point is (px, -py), sharing px with the partner point.
  static void emitQuotient(StackEmitter e, String px, String py,
      List<String> openings, List<String> hint, List<String> out,
      {bool negY = false, String tag = ''}) {
    emitSum(e, openings, tag, limbNames('_S'));
    emitQuotientFromSum(e, px, py, limbNames('_S'), hint, out, negY: negY, tag: tag);
  }

  /// S_k = Σ_j w_{j,k} o_j over group [weightsTag]'s weights (lazy, unreduced).
  /// Consumes the openings.
  static void emitSum(StackEmitter e, List<String> openings, String weightsTag, List<String> out, {int weightOffset = 0}) {
    final C = openings.length;
    for (int k = 0; k < 4; k++) {
      for (int j = 0; j < C; j++) {
        e.pick('w$weightsTag${weightOffset + j}_$k');
        if (k == 3) {
          e.roll(openings[j]);
        } else {
          e.pick(openings[j]);
        }
        e.mul();
        if (j > 0) e.add();
      }
      e.nameTop(out[k]);
    }
  }

  /// The quotient from the weighted sum [S] of the openings (consumed).
  static void emitQuotientFromSum(StackEmitter e, String px, String py, List<String> S, List<String> hint,
      List<String> out, {bool negY = false, String tag = ''}) {
    // N = c * S
    _copy(e, limbNames('c$tag'), limbNames('_c2'));
    M31Ops.qm31Mul(e, limbNames('_c2'), S, limbNames('_N'), reduceOut: false);
    // N -= A * py ; N -= B          (or += A * py for the conjugate point)
    for (int k = 0; k < 4; k++) {
      e.roll('_N_$k');
      e.pick('A${tag}_$k');
      e.pick(py);
      e.mul();
      if (negY) {
        e.add();
      } else {
        e.sub();
      }
      e.pick('B${tag}_$k');
      e.sub();
      e.nameTop('_N_$k');
    }
    // D = dA * px ± dB * py + dC
    for (int k = 0; k < 4; k++) {
      e.pick('dA${tag}_$k');
      e.pick(px);
      e.mul();
      e.pick('dB${tag}_$k');
      e.pick(py);
      e.mul();
      if (negY) {
        e.sub();
      } else {
        e.add();
      }
      e.pick('dC${tag}_$k');
      e.add();
      e.reduce();
      e.nameTop('_D_$k');
    }
    // verify hint: D * h == 1
    _copy(e, hint, limbNames('_h1'));
    M31Ops.qm31Mul(e, limbNames('_D'), limbNames('_h1'), limbNames('_one'));
    e.roll('_one_0');
    e.numEqualVerifyConst(1);
    for (int k = 1; k < 4; k++) {
      e.roll('_one_$k');
      e.numEqualVerifyConst(0);
    }
    // q = N * h
    M31Ops.qm31Mul(e, limbNames('_N'), hint, out);
  }
}
