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
import '../crypto/circle_fft.dart';
import '../crypto/poseidon2_m31.dart';
import 'air.dart';
import 'air_ring.dart';
import 'm31_script_gen.dart';
import 'deep_quotient_script_gen.dart' show limbNames;
import 'air_ood_script_gen.dart' show AirOodScriptGen;

/// The full Poseidon2 permutation as an AIR: one round per row, 16 state
/// columns, a period of 32 rows per permutation.
///
/// Row schedule within a period:
///   row 0        L: next = M_E · cur                 (initial linear layer)
///   rows 1..4    E: next = M_E · (cur + rc)^5        (external rounds 0..3)
///   rows 5..18   P: next = M_I · sbox0(cur + rc·e0)  (internal rounds 0..13)
///   rows 19..22  E: external rounds 4..7
///   rows 23..31  free: row 23 holds the output; transitions unconstrained
///
/// Periodic columns (19): rc_0..rc_15 (round constant per lane; on P rows
/// only rc_0 is nonzero), sE, sP, sL. Constraint per lane j, with
/// t_k = (cur_k + rc_k)^5 and b = (t_0, cur_1, ..., cur_15):
///   C_j = (sE + sP + sL)·next_j − M_E(sE·t + sL·cur)_j − M_I(sP·b)_j
/// of degree 6, so the composition domain is 8× the trace (logExpand 3).
class Poseidon2Air extends Air {
  @override
  final int logTrace;
  Poseidon2Air(this.logTrace) {
    if (logTrace < logPeriod) throw ArgumentError('trace must hold at least one period');
  }

  @override
  int get numCols => 16;
  @override
  int get numConstraints => 16;
  @override
  int get logPeriod => 5;
  static const rowsPerPerm = 23; // L + 8 E + 14 P; output at row 23
  int get permsPerTrace => 1 << (logTrace - logPeriod);

  static const _colSE = 16, _colSP = 17, _colSL = 18;

  /// Row type within the period: 'L', 'E', 'P' or '-' (free), and the round
  /// index for E/P rows.
  static (String, int) rowType(int r) {
    if (r == 0) return ('L', -1);
    if (r <= 4) return ('E', r - 1);
    if (r <= 18) return ('P', r - 5);
    if (r <= 22) return ('E', r - 19 + 4);
    return ('-', -1);
  }

  List<List<int>>? _periodic;
  @override
  List<List<int>> get periodic => _periodic ??= _buildPeriodic();

  List<List<int>> _buildPeriodic() {
    final cols = List.generate(19, (_) => List<int>.filled(32, 0));
    for (int r = 0; r < 32; r++) {
      final (ty, round) = rowType(r);
      switch (ty) {
        case 'L':
          cols[_colSL][r] = 1;
        case 'E':
          cols[_colSE][r] = 1;
          for (int k = 0; k < 16; k++) {
            cols[k][r] = Poseidon2M31.externalRc[round][k];
          }
        case 'P':
          cols[_colSP][r] = 1;
          cols[0][r] = Poseidon2M31.internalRc[round];
      }
    }
    return cols;
  }

  /// One row transition (the honest prover's step), M31.
  static List<int> step(List<int> cur, int r) {
    final (ty, round) = rowType(r & 31);
    switch (ty) {
      case 'L':
        return Poseidon2M31.externalLayer(cur);
      case 'E':
        return Poseidon2M31.externalRound(cur, round);
      case 'P':
        return Poseidon2M31.internalRound(cur, round);
      default:
        return cur;
    }
  }

  /// Trace of 2^logTrace rows: each period runs one permutation on
  /// [inputs][i] if given, else on the previous permutation's output
  /// (or [initial] for the first). Free rows carry the output forward.
  List<List<int>> generateTrace(List<int> initial, {List<List<int>?>? inputs}) {
    final rows = <List<int>>[];
    var s = initial;
    for (int perm = 0; perm < permsPerTrace; perm++) {
      final given = inputs != null && perm < inputs.length ? inputs[perm] : null;
      if (given != null) s = given;
      for (int r = 0; r < 32; r++) {
        rows.add(s);
        s = step(s, r);
      }
    }
    return rows;
  }

  // ---------------------------------------------------------------- QM31 spec

  @override
  List<T> constraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin) {
    final sE = per[_colSE], sP = per[_colSP], sL = per[_colSL];
    final t = List.generate(16, (k) => pow5G(f, f.add(cur[k], per[k])));
    final a = List.generate(16, (k) => f.add(f.mul(sE, t[k]), f.mul(sL, cur[k])));
    final b = List.generate(16, (k) => f.mul(sP, k == 0 ? t[0] : cur[k]));
    final mea = externalLayerG(f, a);
    var sum = b[0];
    for (int k = 1; k < 16; k++) {
      sum = f.add(sum, b[k]);
    }
    final s = f.add(f.add(sE, sP), sL);
    return List.generate(
        16, (j) => f.sub(f.sub(f.mul(s, next[j]), mea[j]), f.add(sum, f.scale(b[j], Poseidon2M31.internalDiag[j]))));
  }

  static T pow5G<T>(Ring<T> f, T x) {
    final x2 = f.mul(x, x);
    return f.mul(f.mul(x2, x2), x);
  }

  /// The external linear layer circ(2·M4, M4, M4, M4) over a ring.
  static List<T> externalLayerG<T>(Ring<T> f, List<T> s) {
    final y = <T>[];
    for (int b = 0; b < 4; b++) {
      for (int r = 0; r < 4; r++) {
        y.add(f.linear([for (int c = 0; c < 4; c++) s[4 * b + c]], Poseidon2M31.m4[r]));
      }
    }
    final sums = List<T>.generate(4, (r) => f.add(f.add(y[r], y[4 + r]), f.add(y[8 + r], y[12 + r])));
    return List.generate(16, (i) => f.add(y[i], sums[i % 4]));
  }

  // ---------------------------------------------------------------- M31 fast path

  final Uint32List _t = Uint32List(16), _a = Uint32List(16), _b = Uint32List(16);

  @override
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out) {
    final sE = per[_colSE], sP = per[_colSP], sL = per[_colSL];
    for (int k = 0; k < 16; k++) {
      _t[k] = Poseidon2M31.pow5(CircleFft.add(cur[k], per[k]));
      _a[k] = CircleFft.add(CircleFft.mul(sE, _t[k]), CircleFft.mul(sL, cur[k]));
      _b[k] = CircleFft.mul(sP, k == 0 ? _t[0] : cur[k]);
    }
    final mea = Poseidon2M31.externalLayer(_a);
    final mib = Poseidon2M31.internalLayer(_b);
    final s = CircleFft.add(CircleFft.add(sE, sP), sL);
    for (int j = 0; j < 16; j++) {
      out[j] = CircleFft.sub(CircleFft.sub(CircleFft.mul(s, next[j]), mea[j]), mib[j]);
    }
  }

  // ---------------------------------------------------------------- script

  static void _copy(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.pick(src[k], as: dst[k]);
    }
  }

  static void _dropQ(StackEmitter e, List<String> q) {
    for (final l in q) {
      e.dropNamed(l);
    }
  }

  /// out = x^5 for canonical named x (consumed).
  static void _emitPow5(StackEmitter e, List<String> x, List<String> out) {
    _copy(e, x, limbNames('_p5a'));
    _copy(e, x, limbNames('_p5b'));
    M31Ops.qm31Mul(e, limbNames('_p5a'), limbNames('_p5b'), limbNames('_p5x2'));
    _copy(e, limbNames('_p5x2'), limbNames('_p5x2b'));
    M31Ops.qm31Mul(e, limbNames('_p5x2'), limbNames('_p5x2b'), limbNames('_p5x4'));
    M31Ops.qm31Mul(e, limbNames('_p5x4'), x, out);
  }

  @override
  void emitConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next,
      List<List<String>> per, List<List<String>> lin, List<List<String>> out) {
    final sE = per[_colSE], sP = per[_colSP], sL = per[_colSL];
    // S = sE + sP + sL
    for (int k = 0; k < 4; k++) {
      e.pick(sE[k]);
      e.pick(sP[k]);
      e.add();
      e.pick(sL[k]);
      e.add();
      e.reduce();
      e.nameTop('_S_$k');
    }
    final a = List.generate(16, (k) => limbNames('_a$k'));
    final b = List.generate(16, (k) => limbNames('_b$k'));
    for (int k = 0; k < 16; k++) {
      // t_k = (cur_k + rc_k)^5
      for (int l = 0; l < 4; l++) {
        e.pick(cur[k][l]);
        e.roll(per[k][l]);
        e.add();
        e.reduce();
        e.nameTop('_x_$l');
      }
      _emitPow5(e, limbNames('_x'), limbNames('_t'));
      // b_k = sP * (k == 0 ? t_0 : cur_k)
      _copy(e, sP, limbNames('_sp'));
      if (k == 0) {
        _copy(e, limbNames('_t'), limbNames('_tb'));
        M31Ops.qm31Mul(e, limbNames('_sp'), limbNames('_tb'), b[k]);
      } else {
        _copy(e, cur[k], limbNames('_cb'));
        M31Ops.qm31Mul(e, limbNames('_sp'), limbNames('_cb'), b[k]);
      }
      // a_k = sE * t_k + sL * cur_k
      _copy(e, sE, limbNames('_se'));
      M31Ops.qm31Mul(e, limbNames('_se'), limbNames('_t'), limbNames('_ae'), reduceOut: false);
      _copy(e, sL, limbNames('_sl'));
      M31Ops.qm31Mul(e, limbNames('_sl'), cur[k], limbNames('_al'), reduceOut: false);
      for (int l = 0; l < 4; l++) {
        e.roll('_ae_$l');
        e.roll('_al_$l');
        e.add();
        e.reduce();
        e.nameTop(a[k][l]);
      }
    }
    _dropQ(e, sE);
    _dropQ(e, sP);
    _dropQ(e, sL);
    // M_E(a) -> _mea{j}
    AirOodScriptGen.emitExternalLayer(e, a, '_mea');
    // M_I(b): sum + d_j b_j
    for (int l = 0; l < 4; l++) {
      for (int k = 0; k < 16; k++) {
        e.pick(b[k][l]);
        if (k > 0) e.add();
      }
      e.reduce();
      e.nameTop('_bsum_$l');
    }
    for (int j = 0; j < 16; j++) {
      // c_j = S * next_j - mea_j - (bsum + d_j b_j)
      _copy(e, limbNames('_S'), limbNames('_sn'));
      M31Ops.qm31Mul(e, limbNames('_sn'), next[j], limbNames('_snx'), reduceOut: false);
      for (int l = 0; l < 4; l++) {
        e.roll('_snx_$l');
        e.roll('_mea${j}_$l');
        e.sub();
        e.pick('_bsum_$l');
        e.sub();
        e.roll(b[j][l]);
        e.mulConst(Poseidon2M31.internalDiag[j]);
        e.sub();
        e.reduce();
        e.nameTop(out[j][l]);
      }
    }
    _dropQ(e, limbNames('_bsum'));
    _dropQ(e, limbNames('_S'));
  }
}
