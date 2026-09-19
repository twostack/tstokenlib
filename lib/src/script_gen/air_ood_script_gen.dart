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
import 'deep_quotient_script_gen.dart' show limbNames;

/// Out-of-domain (OODS) constraint check for a Poseidon2-style narrow AIR:
/// width-16 state, one external round per row.
///
/// Constraint j (0..15):  next_j - Σ_k ME[j][k] * (cur_k + rc_k)^5 = 0
/// where ME = circ(2·M4, M4, M4, M4) is the Poseidon2 external matrix.
///
/// The verifier checks, at the OODS point z:
///   comp(z) * v_n(z) == Σ_j beta^j * C_j(z)
/// with v_n(z) = π^(t-1)(z.x), π(x) = 2x² - 1, the vanishing polynomial of
/// the size-2^t trace domain, and comp(z) reconstructed from the four
/// base-field composition columns as c0 + c1·i + c2·u + c3·i·u.
class Poseidon2AirRef {
  static const width = 16;
  static const m4 = [
    [5, 7, 1, 3],
    [4, 6, 1, 1],
    [1, 3, 5, 7],
    [1, 1, 4, 6],
  ];
  final List<int> rc; // 16 round constants
  final int logTrace;
  Poseidon2AirRef(this.rc, this.logTrace);

  static QM31 pow5(QM31 x) {
    final x2 = x * x;
    return x2 * x2 * x;
  }

  /// Poseidon2 external linear layer on 16 QM31 values.
  static List<QM31> externalLayer(List<QM31> s) {
    final y = List<QM31>.filled(16, QM31.zero);
    for (int b = 0; b < 4; b++) {
      for (int r = 0; r < 4; r++) {
        var acc = QM31.zero;
        for (int c = 0; c < 4; c++) {
          acc = acc + s[4 * b + c].scale(m4[r][c]);
        }
        y[4 * b + r] = acc;
      }
    }
    final sums = List<QM31>.generate(4, (r) => y[r] + y[4 + r] + y[8 + r] + y[12 + r]);
    return List.generate(16, (i) => y[i] + sums[i % 4]);
  }

  List<QM31> constraints(List<QM31> cur, List<QM31> next) {
    final sb = List.generate(16, (k) => pow5(cur[k] + QM31.fromLimbs(rc[k], 0, 0, 0)));
    final lin = externalLayer(sb);
    return List.generate(16, (j) => next[j] - lin[j]);
  }

  /// Σ_j beta^j C_j, optionally times a selector value.
  QM31 combined(List<QM31> cur, List<QM31> next, QM31 beta, {QM31? sel}) {
    final cs = constraints(cur, next);
    var acc = QM31.zero;
    for (int j = 15; j >= 0; j--) {
      acc = acc * beta + cs[j];
    }
    return sel == null ? acc : acc * sel;
  }

  QM31 vanishing(QM31 zx) {
    var x = zx;
    for (int i = 0; i < logTrace - 1; i++) {
      x = x * x + x * x - QM31.one;
    }
    return x;
  }

  static QM31 composeColumns(List<QM31> c) =>
      c[0] + c[1] * QM31.i + c[2] * QM31.u + c[3] * QM31.i * QM31.u;
}

class AirOodScriptGen {
  static void _copy(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.pick(src[k], as: dst[k]);
    }
  }

  static void _reduceAll(StackEmitter e, List<String> x) {
    for (int k = 0; k < 4; k++) {
      e.roll(x[k]);
      e.reduce();
    }
  }

  /// out = Σ coef_i * term_i limbwise (lazy). Terms are picked (not consumed).
  static void _combine(StackEmitter e, List<(List<String>, int)> terms, List<String> out) {
    for (int k = 0; k < 4; k++) {
      for (int i = 0; i < terms.length; i++) {
        final (t, c) = terms[i];
        e.pick(t[k]);
        if (c != 1) e.mulConst(c);
        if (i > 0) e.add();
      }
      e.nameTop(out[k]);
    }
  }

  /// x^5 with x = cur + rc (rc on limb 0). Picks cur; leaves canonical [out].
  static void emitSbox(StackEmitter e, List<String> cur, int rc, List<String> out) {
    final x = limbNames('_x');
    e.pick(cur[0]);
    e.pushConst(rc);
    e.add();
    e.reduce();
    e.nameTop(x[0]);
    for (int k = 1; k < 4; k++) {
      e.pick(cur[k], as: x[k]);
    }
    _copy(e, x, limbNames('_xa'));
    _copy(e, x, limbNames('_xb'));
    M31Ops.qm31Mul(e, limbNames('_xa'), limbNames('_xb'), limbNames('_x2'));
    _copy(e, limbNames('_x2'), limbNames('_x2b'));
    M31Ops.qm31Mul(e, limbNames('_x2'), limbNames('_x2b'), limbNames('_x4'));
    M31Ops.qm31Mul(e, limbNames('_x4'), x, out);
  }

  /// Poseidon2 external linear layer on 16 named QM31 elements (consumed).
  /// Leaves 16 canonical elements named [outPrefix]0..15.
  static void emitExternalLayer(StackEmitter e, List<List<String>> s, String outPrefix) {
    for (int b = 0; b < 4; b++) {
      for (int r = 0; r < 4; r++) {
        _combine(
            e,
            List.generate(4, (c) => (s[4 * b + c], Poseidon2AirRef.m4[r][c])),
            limbNames('_y${4 * b + r}'));
      }
    }
    for (final blk in s) {
      for (final l in blk) {
        e.dropNamed(l);
      }
    }
    for (int r = 0; r < 4; r++) {
      _combine(
          e,
          [(limbNames('_y$r'), 1), (limbNames('_y${4 + r}'), 1), (limbNames('_y${8 + r}'), 1), (limbNames('_y${12 + r}'), 1)],
          limbNames('_sum$r'));
    }
    for (int i = 0; i < 16; i++) {
      _combine(e, [(limbNames('_y$i'), 1), (limbNames('_sum${i % 4}'), 1)], limbNames('$outPrefix$i'));
      _reduceAll(e, limbNames('$outPrefix$i'));
    }
    for (int i = 0; i < 16; i++) {
      for (final l in limbNames('_y$i')) {
        e.dropNamed(l);
      }
    }
    for (int r = 0; r < 4; r++) {
      for (final l in limbNames('_sum$r')) {
        e.dropNamed(l);
      }
    }
  }

  /// acc = Σ_j beta^j (next_j - lin_j) by Horner from j = 15 down. Consumes
  /// next and lin; picks beta. Leaves canonical [out].
  static void emitCombine(StackEmitter e, List<List<String>> next, List<List<String>> lin,
      List<String> beta, List<String> out) {
    final acc = limbNames('_acc');
    for (int j = 15; j >= 0; j--) {
      if (j == 15) {
        for (int k = 0; k < 4; k++) {
          e.roll(next[j][k]);
          e.roll(lin[j][k]);
          e.sub();
          e.nameTop(acc[k]);
        }
      } else {
        _copy(e, beta, limbNames('_beta'));
        M31Ops.qm31Mul(e, acc, limbNames('_beta'), limbNames('_accb'), reduceOut: false);
        for (int k = 0; k < 4; k++) {
          e.roll('_accb_$k');
          e.roll(next[j][k]);
          e.add();
          e.roll(lin[j][k]);
          e.sub();
          e.reduce();
          e.nameTop(acc[k]);
        }
      }
    }
    _reduceAll(e, acc);
    for (int k = 0; k < 4; k++) {
      e.rename(acc[k], out[k]);
    }
  }

  /// v = π^(logTrace-1)(zx), π(x) = 2x² - 1. Picks zx; leaves canonical [out].
  static void emitVanishing(StackEmitter e, List<String> zx, int logTrace, List<String> out) {
    final x = limbNames('_vx');
    _copy(e, zx, x);
    for (int i = 0; i < logTrace - 1; i++) {
      _copy(e, x, limbNames('_vxa'));
      M31Ops.qm31Mul(e, limbNames('_vxa'), x, limbNames('_vx2'), reduceOut: false);
      for (int k = 0; k < 4; k++) {
        e.roll('_vx2_$k');
        e.dup();
        e.add();
        if (k == 0) {
          e.pushConst(1);
          e.sub();
        }
        e.reduce();
        e.nameTop(x[k]);
      }
    }
    for (int k = 0; k < 4; k++) {
      e.rename(x[k], out[k]);
    }
  }

  /// comp = c0 + c1·i + c2·u + c3·i·u from four QM31 column values (consumed).
  /// Limb formulas (l = [a, b, c, d]):
  ///   x·i  = (-b,  a, -d,  c)
  ///   x·u  = (2c - d, c + 2d, a, b)
  ///   x·iu = (-2d - c, 2c - d, -b, a)
  static void emitComposeColumns(StackEmitter e, List<List<String>> c, List<String> out) {
    final c0 = c[0], c1 = c[1], c2 = c[2], c3 = c[3];
    // limb 0: c0.a - c1.b + 2 c2.c - c2.d - 2 c3.d - c3.c
    e.pick(c0[0]);
    e.pick(c1[1]);
    e.sub();
    e.pick(c2[2]);
    e.mulConst(2);
    e.add();
    e.pick(c2[3]);
    e.sub();
    e.pick(c3[3]);
    e.mulConst(2);
    e.sub();
    e.pick(c3[2]);
    e.sub();
    e.reduce();
    e.nameTop(out[0]);
    // limb 1: c0.b + c1.a + c2.c + 2 c2.d + 2 c3.c - c3.d
    e.pick(c0[1]);
    e.pick(c1[0]);
    e.add();
    e.pick(c2[2]);
    e.add();
    e.pick(c2[3]);
    e.mulConst(2);
    e.add();
    e.pick(c3[2]);
    e.mulConst(2);
    e.add();
    e.pick(c3[3]);
    e.sub();
    e.reduce();
    e.nameTop(out[1]);
    // limb 2: c0.c - c1.d + c2.a - c3.b
    e.pick(c0[2]);
    e.pick(c1[3]);
    e.sub();
    e.pick(c2[0]);
    e.add();
    e.pick(c3[1]);
    e.sub();
    e.reduce();
    e.nameTop(out[2]);
    // limb 3: c0.d + c1.c + c2.b + c3.a
    e.pick(c0[3]);
    e.pick(c1[2]);
    e.add();
    e.pick(c2[1]);
    e.add();
    e.pick(c3[0]);
    e.add();
    e.reduce();
    e.nameTop(out[3]);
    for (final col in c) {
      for (final l in col) {
        e.dropNamed(l);
      }
    }
  }

  /// Full OODS check. Expects named limbs: cur{j}_*, next{j}_* (j < 16),
  /// comp{k}_* (k < 4), beta_*, zx_* and, with [withSelector], sel_*.
  /// Consumes everything.
  static void emitOodsCheck(StackEmitter e, Poseidon2AirRef air, {bool withSelector = false}) {
    final cur = List.generate(16, (j) => limbNames('cur$j'));
    final next = List.generate(16, (j) => limbNames('next$j'));
    final comp = List.generate(4, (k) => limbNames('comp$k'));

    final sb = List.generate(16, (j) => limbNames('_sb$j'));
    for (int j = 0; j < 16; j++) {
      emitSbox(e, cur[j], air.rc[j], sb[j]);
    }
    for (final c in cur) {
      for (final l in c) {
        e.dropNamed(l);
      }
    }
    emitExternalLayer(e, sb, '_lin');
    final lin = List.generate(16, (j) => limbNames('_lin$j'));
    emitCombine(e, next, lin, limbNames('beta'), withSelector ? limbNames('_rhs0') : limbNames('_rhs'));
    for (final l in limbNames('beta')) {
      e.dropNamed(l);
    }
    if (withSelector) {
      M31Ops.qm31Mul(e, limbNames('_rhs0'), limbNames('sel'), limbNames('_rhs'));
    }
    emitVanishing(e, limbNames('zx'), air.logTrace, limbNames('_v'));
    for (final l in limbNames('zx')) {
      e.dropNamed(l);
    }
    emitComposeColumns(e, comp, limbNames('_comp'));
    M31Ops.qm31Mul(e, limbNames('_comp'), limbNames('_v'), limbNames('_lhs'));
    for (int k = 0; k < 4; k++) {
      e.roll('_lhs_$k');
      e.roll('_rhs_$k');
      e.numEqualVerify();
    }
  }
}
