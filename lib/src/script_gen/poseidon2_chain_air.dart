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
import '../crypto/m31.dart';
import 'air.dart';
import 'm31_script_gen.dart';
import 'deep_quotient_script_gen.dart' show limbNames;
import 'air_ood_script_gen.dart' show AirOodScriptGen;
import 'poseidon2_air.dart';

/// One period of the chain: either a fresh start (the chain is broken here and
/// all 16 input lanes are witness) or a link that absorbs 8 witness lanes
/// alongside the previous permutation's 8-lane digest.
class ChainStep {
  /// All 16 input lanes; non-null marks a break period.
  final List<int>? freshInput;

  /// The 8 witness lanes absorbed by a chained step.
  final List<int> witness;

  /// Place the incoming digest in lanes 8..15 instead of 0..7. For a fresh
  /// step it only documents the layout (witness half = lanes 0..7 when set),
  /// which is what a [SiblingBinding] reads.
  final bool swap;

  const ChainStep.fresh(List<int> input, {this.swap = false})
      : freshInput = input,
        witness = const [];
  const ChainStep.chained(this.witness, {this.swap = false}) : freshInput = null;
}

/// Two Merkle walks of [steps] periods each, starting at periods [walk1] and
/// [walk2] (in the first half; the second half binds its own pair), whose
/// witness halves and swap bits must agree step by step: the first walk
/// proves the old root over some siblings, the second computes the new root
/// over the same siblings. No local constraint can reach across a period, so
/// the binding is a random linear combination: after the trace is committed
/// the transcript yields gamma, and an accumulator column (an aux-round QM31
/// column, four base columns) absorbs S = sum_j gamma^j w_j + gamma^8 b at
/// every glue row, shifting by gamma^9 per period, weighted +1 during walk 1
/// and -gamma^(9 D) during walk 2 (D = walk2 - walk1). It starts and ends at
/// zero, which forces the two sibling sequences to agree except with
/// probability about 2^-120. The weight comes from a *mode* register
/// (0 outside the walks, 1 in walk 1, 2 in walk 2) with break rows at the
/// four walk boundaries and constant pins in each region.
class SiblingBinding {
  final int walk1, walk2, steps;

  /// Optionally also bind the walks' *position* (their direction bits) to
  /// public inputs, which an append needs: without it the prover picks the
  /// slot. A 32-bit position does not fit M31 (2^31 = 1), so a base column
  /// accumulates the first steps-2 direction bits of walk 1 as
  /// `pos' = 2 pos + b` (most significant first; the public value is the
  /// bit-reversed low position) and the last two bits are pinned directly.
  /// Walk 2's bits follow from the sibling binding. Indices are into the
  /// public inputs, (first half, second half).
  final PositionPins? position;
  const SiblingBinding({required this.walk1, required this.walk2, required this.steps, this.position});
  int get offset => walk2 - walk1;
  int get accLevels => steps - 2;
}

/// Public-input indices for [SiblingBinding.position]: the accumulated low
/// bits, then the two top direction bits, each as (half A, half B).
class PositionPins {
  final int accA, accB, hiA, hiB, topA, topB;
  const PositionPins(
      {required this.accA, required this.accB, required this.hiA, required this.hiB, required this.topA, required this.topB});

  /// The three public values for a [depth]-level walk at [position].
  static (int, int, int) valuesFor(int position, int depth) {
    var acc = 0;
    for (int i = 0; i < depth - 2; i++) {
      acc = (acc << 1) | ((position >> i) & 1);
    }
    return (acc, (position >> (depth - 2)) & 1, (position >> (depth - 1)) & 1);
  }
}

/// One term of a [BoundaryExpr]: coef * col (of the current or next row),
/// optionally also multiplied by the group's selector s (+1 at the group's
/// row, -1 at its half-turn partner), which lets a term apply on one side of
/// the pair only via (1 +/- s)/2.
class BoundaryTerm {
  final int col;
  final bool next;
  final int coef;
  final bool timesS;
  const BoundaryTerm(this.col, {this.next = false, this.coef = 1, this.timesS = false});
}

/// An affine constraint enforced at a half-turn pair of rows:
///   sum(terms) + L(constA, constB) = 0
/// where L is constA at the group's row and constB at its partner.
class BoundaryExpr {
  final List<BoundaryTerm> terms;
  final int constA, constB;

  /// Optional gate: the whole expression is multiplied by cur[gateCol]
  /// (or by 1 - cur[gateCol] when [gateNeg]). One extra QM31 multiplication
  /// in script; lets a pin be switched off by a boolean column.
  final int gateCol;
  final bool gateNeg;

  /// Optional runtime constants: pubCoef * L(pub[pubA], pub[pubB]) is added,
  /// where an index of -1 stands for zero. These are the AIR's public inputs,
  /// picked from the unlocking script rather than baked into the script.
  final int pubA, pubB, pubCoef;
  const BoundaryExpr(this.terms,
      {this.constA = 0,
      this.constB = 0,
      this.gateCol = -1,
      this.gateNeg = false,
      this.pubA = -1,
      this.pubB = -1,
      this.pubCoef = M31.p - 1});

  /// cur[col] == valueA at the row, valueB at the partner.
  factory BoundaryExpr.public(int col, int valueA, int valueB, {int gateCol = -1, bool gateNeg = false}) =>
      BoundaryExpr([BoundaryTerm(col)],
          constA: M31.neg(valueA), constB: M31.neg(valueB), gateCol: gateCol, gateNeg: gateNeg);

  /// cur[col] == pub[idxA] at the row, pub[idxB] at the partner.
  factory BoundaryExpr.publicAt(int col, int idxA, int idxB, {int gateCol = -1, bool gateNeg = false}) =>
      BoundaryExpr([BoundaryTerm(col)], pubA: idxA, pubB: idxB, gateCol: gateCol, gateNeg: gateNeg);

  /// cur[col] * (cur[col] - 1) == 0.
  factory BoundaryExpr.boolean(int col) =>
      BoundaryExpr([BoundaryTerm(col)], constA: M31.p - 1, constB: M31.p - 1, gateCol: col);

  /// (1 - cur[gateCol]) * cur[col] == 0: the column is forced to zero
  /// whenever the (boolean) gate is off.
  factory BoundaryExpr.zeroUnless(int col, int gateCol) =>
      BoundaryExpr([BoundaryTerm(col)], gateCol: gateCol, gateNeg: true);

  /// cur[col] == cur[otherCol] (both secret).
  factory BoundaryExpr.equal(int col, int otherCol) =>
      BoundaryExpr([BoundaryTerm(col), BoundaryTerm(otherCol, coef: M31.p - 1)]);

  bool get needsSelector => constA != constB || pubA != pubB || terms.any((t) => t.timesS);

  /// The (m, h) of the runtime part: pubCoef * L(pub[pubA], pub[pubB]).
  (int, int) pubLagrange(List<int> pub) {
    if (pubA < 0 && pubB < 0) return (0, 0);
    final (m, h) = Poseidon2ChainAir.lagrange(pubA < 0 ? 0 : pub[pubA], pubB < 0 ? 0 : pub[pubB]);
    return (M31.mul(pubCoef, m), M31.mul(pubCoef, h));
  }
}

/// Constraints enforced only at cyclic rows [row] and row + 2^(logTrace-1).
class BoundaryGroup {
  final int row;
  final List<BoundaryExpr> exprs;
  const BoundaryGroup(this.row, this.exprs);
  bool get needsSelector => exprs.any((e) => e.needsSelector);
}

/// A column that accumulates the free bit lanes with a per-period schedule:
///   acc(next) = mult[r] * acc(cur) + gate[r] * sum_k 2^k * cur[9 + k]
/// for r the row within the period. mult 1 / gate 0 holds; mult 0 resets.
class AccumulatorSpec {
  final List<int> mult, gate;
  const AccumulatorSpec(this.mult, this.gate);
}

/// A chain of Poseidon2 permutations, one per 32-row period, with registers,
/// bit lanes and accumulators.
///
/// Layout. Period p occupies rows 32p..32p+31: row 0 is the permutation input,
/// row 23 its output, rows 24..31 carry the 8-lane digest forward in lanes
/// 0..7. Lane 8 of row 31 holds the *swap bit* b of the next period, and the
/// glue constraint writes the digest into the next input's low half (b = 0)
/// or high half (b = 1), leaving the other half free for witness. Lanes 9..15
/// of rows 24..31 are the *bit lanes*, constrained boolean in every period,
/// and lane 8 of rows 24..30 is free scratch. The chain is cyclic and is cut
/// at the [breakPeriods] by multiplying the glue by the linear forms that
/// vanish at the transition into them; at a break all 16 input lanes are
/// witness.
///
/// Because a linear form vanishes at a *half-turn pair* of rows, every break
/// and every boundary group applies at row r and at row r + 2^(logTrace-1)
/// simultaneously, so the trace has two structurally identical halves.
///
/// Columns after the 16 state lanes: the [registers], each constant except
/// at its own break rows, then the [accumulators].
///
/// Constraints, in order:
///   0..15          Poseidon2 round transitions (degree 6)
///   16..23         carry and glue on lanes 0..7
///   24             swap-bit booleanity
///   25..           register persistence, one per register
///   then           accumulator schedules, one per accumulator
///   then           bit-lane booleanity, 7
///   then one group per [boundaries], divided by that group's linear form.
class Poseidon2ChainAir extends Poseidon2Air {
  /// Periods where the chain restarts. Only the representative in the first
  /// half is listed; its partner p + periods/2 breaks with it.
  final List<int> breakPeriods;

  /// Break rows per register column (each row also breaks at its partner).
  final List<List<int>> registers;
  final List<AccumulatorSpec> accumulators;
  final List<BoundaryGroup> boundaries;

  /// Concrete public inputs (see [Air.numPublics]); boundary expressions
  /// refer to them by index. The script depends only on their number.
  final List<int> publics;
  @override
  int get numPublics => publics.length;
  @override
  List<int> get publicValues => publics;

  /// Optional sibling binding between two Merkle walks. Adds the mode
  /// register (the last register column), its pins, the accumulator's zero
  /// pins, and the aux round.
  final SiblingBinding? binding;

  Poseidon2ChainAir(
    super.logTrace, {
    this.breakPeriods = const [],
    List<List<int>> registers = const [],
    this.accumulators = const [],
    List<BoundaryGroup> boundaries = const [],
    this.publics = const [],
    this.binding,
  })  : registers = _withModeRegister(registers, binding, logTrace),
        boundaries = _withBindingPins(boundaries, registers.length, accumulators.length, binding, logTrace) {
    final half = periods >> 1;
    if (binding != null) {
      final b = binding!;
      if (b.walk1 < 0 || b.walk1 + b.steps > b.walk2 || b.walk2 + b.steps > half) {
        throw ArgumentError('sibling binding walks must be ordered and lie in the first half');
      }
    }
    for (final g in boundaries) {
      for (final ex in g.exprs) {
        for (final k in [ex.pubA, ex.pubB]) {
          if (k >= publics.length) throw ArgumentError('public input $k out of range (${publics.length})');
        }
      }
    }
    for (final p in breakPeriods) {
      if (p < 0 || p >= half) {
        throw ArgumentError('break period $p must lie in the first half (0..${half - 1})');
      }
    }
    for (final a in accumulators) {
      if (a.mult.length != 32 || a.gate.length != 32) throw ArgumentError('accumulator schedule needs 32 rows');
    }
    _buildForms();
  }

  int get periods => 1 << (logTrace - logPeriod);
  static const colSwapBit = 8;
  static const bitLane0 = 9, bitLanes = 7;
  static const _colSC = 19, _colSG = 20, _colSFree = 21, _colAcc0 = 22;

  int get regCol0 => 16;
  int get accCol0 => 16 + registers.length;
  @override
  int get numCols => 16 + registers.length + accumulators.length + (hasPosition ? 1 : 0);

  int get _mainCount => 25 + registers.length + accumulators.length + bitLanes + (hasPosition ? 1 : 0);

  @override
  int get numConstraints => _mainCount + boundaries.fold(0, (a, g) => a + g.exprs.length);

  // ---------------------------------------------------------------- sibling binding

  static int _glue(int p, int logTrace) => ((p << 5) - 1) & ((1 << logTrace) - 1);

  /// Rows normalised to the first half (a break or a symmetric pin at row r
  /// is the same at r + n/2, and the form cache is keyed by row).
  static int _norm(int row, int logTrace) => row & ((1 << (logTrace - 1)) - 1);

  static List<List<int>> _withModeRegister(List<List<int>> regs, SiblingBinding? b, int logTrace) {
    if (b == null) return regs;
    final rows = <int>{
      _norm(_glue(b.walk1, logTrace), logTrace),
      _norm(_glue(b.walk1 + b.steps, logTrace), logTrace),
      _norm(_glue(b.walk2, logTrace), logTrace),
      _norm(_glue(b.walk2 + b.steps, logTrace), logTrace),
    };
    return [...regs, rows.toList()..sort()];
  }

  static List<BoundaryGroup> _withBindingPins(
      List<BoundaryGroup> groups, int numRegs, int numAccs, SiblingBinding? b, int logTrace) {
    if (b == null) return groups;
    // columns: 16 state, user registers, the mode register, accumulators,
    // the position column (if any), then the aux columns
    final mode = 16 + numRegs;
    final pos = 16 + numRegs + 1 + numAccs;
    final aux0 = pos + (b.position == null ? 0 : 1);
    int row(int p) => _norm(p << 5, logTrace);
    int glue(int p) => _norm(_glue(p, logTrace), logTrace);
    final pins = <int, List<BoundaryExpr>>{};
    void pin(int r, BoundaryExpr ex) => (pins[r] ??= []).add(ex);
    // mode = 1 in walk 1, read through `next` from the glue row so it shares
    // that row's group with the accumulator pins (one divisor fewer)
    pin(glue(b.walk1), BoundaryExpr([BoundaryTerm(mode, next: true)], constA: M31.p - 1, constB: M31.p - 1));
    if (b.walk1 + b.steps < b.walk2) pin(row(b.walk1 + b.steps), BoundaryExpr.public(mode, 0, 0));
    pin(row(b.walk2), BoundaryExpr.public(mode, 2, 2));
    pin(row(b.walk2 + b.steps), BoundaryExpr.public(mode, 0, 0));
    // the accumulator absorbs a period's sibling at the glue row before it,
    // so it is zero at the glue row into walk 1 and at walk 2's end row
    for (int k = 0; k < 4; k++) {
      pin(glue(b.walk1), BoundaryExpr.public(aux0 + k, 0, 0));
      pin(row(b.walk2 + b.steps), BoundaryExpr.public(aux0 + k, 0, 0));
    }
    final pp = b.position;
    if (pp != null) {
      if (b.steps < 3) throw ArgumentError('position binding needs at least 3 steps');
      // pos = 0 before walk 1; after accLevels absorbs it is read through
      // `next` from the glue row of the next-to-last step, whose own swap
      // bit (cur lane 8) is the second-highest direction bit; the last
      // step's swap bit is the highest.
      pin(glue(b.walk1), BoundaryExpr.public(pos, 0, 0));
      pin(glue(b.walk1 + b.accLevels), BoundaryExpr([BoundaryTerm(pos)], pubA: pp.accA, pubB: pp.accB));
      pin(glue(b.walk1 + b.accLevels), BoundaryExpr.publicAt(colSwapBit, pp.hiA, pp.hiB));
      pin(glue(b.walk1 + b.accLevels + 1), BoundaryExpr.publicAt(colSwapBit, pp.topA, pp.topB));
    }
    return [...groups, for (final r in pins.keys.toList()..sort()) BoundaryGroup(r, pins[r]!)];
  }

  /// The mode register column (binding only): the register appended last.
  int get modeCol => regCol0 + registers.length - 1;
  bool get hasPosition => binding?.position != null;
  /// The position accumulator column (binding with position only).
  int get posCol => 16 + registers.length + accumulators.length;
  int get auxCol0 => numCols;

  @override
  int get numChallenges => binding == null ? 0 : 1;
  @override
  int get numAuxCols => binding == null ? 0 : 4;
  @override
  int get numAuxConstraints => binding == null ? 0 : 1;

  static final int _halfM31 = M31.inv(2);
  static QM31 _powQ(QM31 g, int e) {
    var r = QM31.one, b = g;
    for (; e > 0; e >>= 1) {
      if (e & 1 == 1) r = r * b;
      b = b * b;
    }
    return r;
  }

  /// gamma-derived constants, memoised on the challenge value.
  QM31? _cachedGamma;
  late List<QM31> _gpow; // gamma^0 .. gamma^9
  late QM31 _wa, _wb; // weight g(m) = m (wa + wb m): g(1) = 1, g(2) = -gamma^(9 D)
  void _prepare(QM31 gamma) {
    if (_cachedGamma == gamma) return;
    _cachedGamma = gamma;
    _gpow = [QM31.one];
    for (int j = 1; j <= 9; j++) {
      _gpow.add(_gpow[j - 1] * gamma);
    }
    final c = _powQ(_gpow[9], binding!.offset);
    _wa = (c + QM31.fromLimbs(4, 0, 0, 0)).scale(_halfM31);
    _wb = (QM31.zero - c - QM31.fromLimbs(2, 0, 0, 0)).scale(_halfM31);
  }

  /// S = sum_j gamma^j w_j + gamma^8 b, with w the witness half of [next]
  /// selected by the swap bit [b].
  QM31 _absorbed(List<QM31> next, QM31 b) {
    var p = QM31.zero, q = QM31.zero;
    for (int j = 7; j >= 0; j--) {
      p = p * _gpow[1] + next[8 + j];
      q = q * _gpow[1] + (next[j] - next[8 + j]);
    }
    return p + b * (q + _gpow[8]);
  }

  /// At a glue row the absorbed sibling is the next period's, so its weight
  /// is the next row's mode (the mode register breaks exactly at glue rows).
  QM31 _auxValue(List<QM31> cur, List<QM31> next, QM31 sG) {
    final acc = Air.composeLimbs(cur.sublist(auxCol0, auxCol0 + 4));
    final accN = Air.composeLimbs(next.sublist(auxCol0, auxCol0 + 4));
    final m = next[modeCol];
    final g = m * (_wa + _wb * m);
    final s = _absorbed(next, cur[colSwapBit]);
    return accN - acc - sG * ((_gpow[9] - QM31.one) * acc + g * s);
  }

  @override
  List<QM31> auxConstraints(List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin, List<QM31> chal) {
    if (binding == null) return const [];
    _prepare(chal[0]);
    return [_auxValue(cur, next, per[_colSG])];
  }

  @override
  void auxConstraintsM31(
      Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, List<QM31> chal, List<QM31> out) {
    if (binding == null) return;
    _prepare(chal[0]);
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    out[0] = _auxValue([for (final v in cur) emb(v)], [for (final v in next) emb(v)], emb(per[_colSG]));
  }

  /// The accumulator: zero at walk 1's input row, then the recurrence around
  /// the cycle. [rows] are the base columns.
  @override
  List<Uint32List> auxColumns(List<List<int>> rows, List<QM31> chal) {
    if (binding == null) return const [];
    _prepare(chal[0]);
    final n = rows.length;
    final cols = List.generate(4, (_) => Uint32List(n));
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    final start = _glue(binding!.walk1, logTrace);
    var acc = QM31.zero;
    for (int i = 0; i < n; i++) {
      final r = (start + i) % n;
      final limbs = acc.limbs;
      for (int k = 0; k < 4; k++) {
        cols[k][r] = limbs[k];
      }
      if (r & 31 == 31) {
        final nxt = [for (final v in rows[(r + 1) % n]) emb(v)];
        final m = nxt[modeCol];
        final g = m * (_wa + _wb * m);
        acc = _gpow[9] * acc + g * _absorbed(nxt, emb(rows[r][colSwapBit]));
      }
    }
    return cols;
  }

  @override
  void emitAuxConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next, List<List<String>> per,
      List<List<String>> lin, List<List<String>> chal, List<List<String>> out) {
    if (binding == null) return;
    final gam = chal[0];
    // gamma^2, ^4, ^8, ^9
    _copy(e, gam, limbNames('_ga'));
    _copy(e, gam, limbNames('_gb'));
    M31Ops.qm31Mul(e, limbNames('_ga'), limbNames('_gb'), limbNames('_g2'));
    _copy(e, limbNames('_g2'), limbNames('_ga'));
    M31Ops.qm31Mul(e, limbNames('_g2'), limbNames('_ga'), limbNames('_g4'));
    _copy(e, limbNames('_g4'), limbNames('_ga'));
    M31Ops.qm31Mul(e, limbNames('_g4'), limbNames('_ga'), limbNames('_g8'));
    _copy(e, limbNames('_g8'), limbNames('_ga'));
    _copy(e, gam, limbNames('_gb'));
    M31Ops.qm31Mul(e, limbNames('_ga'), limbNames('_gb'), limbNames('_g9'));
    // c = (gamma^9)^D by square-and-multiply, most significant bit first
    final d = binding!.offset;
    _copy(e, limbNames('_g9'), limbNames('_c'));
    for (int k = d.bitLength - 2; k >= 0; k--) {
      _copy(e, limbNames('_c'), limbNames('_ca'));
      M31Ops.qm31Mul(e, limbNames('_c'), limbNames('_ca'), limbNames('_cc'));
      _rename(e, limbNames('_cc'), limbNames('_c'));
      if ((d >> k) & 1 == 1) {
        _copy(e, limbNames('_g9'), limbNames('_ca'));
        M31Ops.qm31Mul(e, limbNames('_c'), limbNames('_ca'), limbNames('_cc'));
        _rename(e, limbNames('_cc'), limbNames('_c'));
      }
    }
    // wa = (c + 4) / 2, wb = -(c + 2) / 2
    for (int l = 0; l < 4; l++) {
      e.pick('_c_$l');
      if (l == 0) {
        e.pushConst(4);
        e.add();
      }
      e.mulConst(_halfM31);
      e.reduce();
      e.nameTop('_wa_$l');
    }
    for (int l = 0; l < 4; l++) {
      e.roll('_c_$l');
      if (l == 0) {
        e.pushConst(2);
        e.add();
      }
      e.mulConst(M31.p - _halfM31);
      e.reduce();
      e.nameTop('_wb_$l');
    }
    // P = Horner_gamma(next[8..15]), Q = Horner_gamma(next[j] - next[8+j])
    final ps = <List<String>>[], qs = <List<String>>[];
    for (int j = 0; j < 8; j++) {
      _copy(e, next[8 + j], limbNames('_p$j'));
      ps.add(limbNames('_p$j'));
      _affine(e, [(next[j], 1), (next[8 + j], M31.p - 1)], 0, limbNames('_q$j'));
      qs.add(limbNames('_q$j'));
    }
    AirScriptGen.emitHorner(e, ps, gam, limbNames('_P'));
    AirScriptGen.emitHorner(e, qs, gam, limbNames('_Q'));
    // S = P + b (Q + gamma^8)
    for (int l = 0; l < 4; l++) {
      e.roll('_Q_$l');
      e.roll('_g8_$l');
      e.add();
      e.reduce();
      e.nameTop('_Q_$l');
    }
    _copy(e, cur[colSwapBit], limbNames('_bb'));
    M31Ops.qm31Mul(e, limbNames('_Q'), limbNames('_bb'), limbNames('_bQ'), reduceOut: false);
    for (int l = 0; l < 4; l++) {
      e.roll('_P_$l');
      e.roll('_bQ_$l');
      e.add();
      e.reduce();
      e.nameTop('_S_$l');
    }
    // g = m (wa + wb m), m the next row's mode
    _copy(e, next[modeCol], limbNames('_m'));
    M31Ops.qm31Mul(e, limbNames('_wb'), limbNames('_m'), limbNames('_wbm'), reduceOut: false);
    for (int l = 0; l < 4; l++) {
      e.roll('_wbm_$l');
      e.roll('_wa_$l');
      e.add();
      e.reduce();
      e.nameTop('_t_$l');
    }
    _copy(e, next[modeCol], limbNames('_m'));
    M31Ops.qm31Mul(e, limbNames('_t'), limbNames('_m'), limbNames('_gm'));
    // acc, accN from the four base columns (composed from copies: the
    // composer drops its inputs, and the base emitter still needs them)
    final accCols = List.generate(4, (k) => limbNames('_ak$k'));
    final accNCols = List.generate(4, (k) => limbNames('_an$k'));
    for (int k = 0; k < 4; k++) {
      _copy(e, cur[auxCol0 + k], accCols[k]);
      _copy(e, next[auxCol0 + k], accNCols[k]);
    }
    AirOodScriptGen.emitComposeColumns(e, accCols, limbNames('_acc'));
    AirOodScriptGen.emitComposeColumns(e, accNCols, limbNames('_accN'));
    // inner = (gamma^9 - 1) acc + g S ; v = sG inner ; out = accN - acc - v
    for (int l = 0; l < 4; l++) {
      e.roll('_g9_$l');
      if (l == 0) {
        e.pushConst(1);
        e.sub();
        e.reduce();
      }
      e.nameTop('_g91_$l');
    }
    _copy(e, limbNames('_acc'), limbNames('_acca'));
    M31Ops.qm31Mul(e, limbNames('_g91'), limbNames('_acca'), limbNames('_u1'), reduceOut: false);
    M31Ops.qm31Mul(e, limbNames('_gm'), limbNames('_S'), limbNames('_u2'), reduceOut: false);
    for (int l = 0; l < 4; l++) {
      e.roll('_u1_$l');
      e.roll('_u2_$l');
      e.add();
      e.reduce();
      e.nameTop('_in_$l');
    }
    _copy(e, per[_colSG], limbNames('_sgb'));
    M31Ops.qm31Mul(e, limbNames('_sgb'), limbNames('_in'), limbNames('_v'), reduceOut: false);
    for (int l = 0; l < 4; l++) {
      e.roll('_accN_$l');
      e.roll('_acc_$l');
      e.sub();
      e.roll('_v_$l');
      e.sub();
      e.reduce();
      e.nameTop(out[0][l]);
    }
  }

  // ---------------------------------------------------------------- forms

  late final List<LinearForm> _forms;
  late final List<int> _breakForms; // glue break forms
  late final List<List<int>> _regForms; // per register
  late final List<int> _groupVan, _groupSel; // per boundary group (sel -1 if unused)
  late final int _posForm; // position accumulator reset form (-1 without)

  void _buildForms() {
    final forms = <LinearForm>[];
    final van = <int, int>{};
    int vanFor(int row) => van.putIfAbsent(row, () {
          forms.add(LinearForm.vanishingAt(rowPoint(row)));
          return forms.length - 1;
        });
    _breakForms = [for (final p in breakPeriods) vanFor(glueRow(p))];
    _regForms = [
      for (final r in registers) [for (final row in r) vanFor(row)]
    ];
    // the position accumulator is reset (pinned to zero) at the glue row
    // into walk 1, so the transition into that row is excepted
    _posForm = hasPosition ? vanFor((_glue(binding!.walk1, logTrace) - 1) & ((1 << logTrace) - 1)) : -1;
    _groupVan = [for (final g in boundaries) vanFor(g.row)];
    _groupSel = [
      for (final g in boundaries)
        if (g.needsSelector) (() {
          forms.add(LinearForm.selectorAt(rowPoint(g.row)));
          return forms.length - 1;
        })() else -1
    ];
    _forms = forms;
  }

  @override
  List<LinearForm> get linearForms => _forms;

  @override
  List<ConstraintGroup> get groups => [
        ConstraintGroup(_mainCount),
        for (int i = 0; i < boundaries.length; i++)
          ConstraintGroup(boundaries[i].exprs.length, divisor: _groupVan[i]),
      ];

  List<List<int>>? _per;
  @override
  List<List<int>> get periodic => _per ??= [
        ...super.periodic,
        [for (int r = 0; r < 32; r++) r >= 23 && r <= 30 ? 1 : 0],
        [for (int r = 0; r < 32; r++) r == 31 ? 1 : 0],
        [for (int r = 0; r < 32; r++) r >= 24 ? 1 : 0],
        for (final a in accumulators) ...[a.mult, a.gate],
      ];

  static final int _half = M31.inv(2);

  /// The degree-1 interpolant that is [a] at a group's row and [b] at its
  /// half-turn partner: (a+b)/2 + ((a-b)/2)*s.
  static (int, int) lagrange(int a, int b) =>
      (M31.mul(M31.add(a, b), _half), M31.mul(M31.sub(a, b), _half));

  // ---------------------------------------------------------------- QM31 spec

  @override
  List<QM31> constraints(List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin) {
    final out = <QM31>[
      ...super.constraints(cur.sublist(0, 16), next.sublist(0, 16), per.sublist(0, 19), const [])
    ];
    final sC = per[_colSC], sG = per[_colSG], sF = per[_colSFree];
    var v = QM31.one;
    for (final f in _breakForms) {
      v = v * lin[f];
    }
    final t = sG * v;
    final b = cur[colSwapBit];
    final u = sC + t, w = t * b;
    for (int j = 0; j < 8; j++) {
      out.add(u * (next[j] - cur[j]) + w * (next[j + 8] - next[j]));
    }
    out.add(sG * (b * b - b));
    for (int k = 0; k < registers.length; k++) {
      var vr = QM31.one;
      for (final f in _regForms[k]) {
        vr = vr * lin[f];
      }
      out.add(vr * (next[regCol0 + k] - cur[regCol0 + k]));
    }
    var bits = QM31.zero;
    for (int k = bitLanes - 1; k >= 0; k--) {
      bits = bits + bits + cur[bitLane0 + k];
    }
    for (int a = 0; a < accumulators.length; a++) {
      final c = accCol0 + a;
      out.add(next[c] - per[_colAcc0 + 2 * a] * cur[c] - per[_colAcc0 + 2 * a + 1] * bits);
    }
    for (int k = 0; k < bitLanes; k++) {
      final x = cur[bitLane0 + k];
      out.add(sF * (x * x - x));
    }
    if (hasPosition) {
      // V * (pos' - pos - sG * m(2 - m) * (pos + b)), m the next row's mode,
      // V the form excepting the reset transition
      final m = next[modeCol], p = cur[posCol];
      out.add(lin[_posForm] * (next[posCol] - p - sG * (m * (QM31.fromLimbs(2, 0, 0, 0) - m)) * (p + b)));
    }
    for (int i = 0; i < boundaries.length; i++) {
      final s = _groupSel[i] < 0 ? QM31.zero : lin[_groupSel[i]];
      for (final e in boundaries[i].exprs) {
        var plain = QM31.zero, withS = QM31.zero;
        for (final tm in e.terms) {
          final x = (tm.next ? next : cur)[tm.col].scale(tm.coef);
          if (tm.timesS) {
            withS = withS + x;
          } else {
            plain = plain + x;
          }
        }
        final (m0, h0) = lagrange(e.constA, e.constB);
        final (pm, ph) = e.pubLagrange(publics);
        final m = M31.add(m0, pm), h = M31.add(h0, ph);
        var v = plain + QM31.fromLimbs(m, 0, 0, 0) + (withS + QM31.fromLimbs(h, 0, 0, 0)) * s;
        if (e.gateCol >= 0) {
          final g = cur[e.gateCol];
          v = v * (e.gateNeg ? QM31.one - g : g);
        }
        out.add(v);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- M31 fast path

  final Uint32List _sub16 = Uint32List(16), _subN16 = Uint32List(16), _subP = Uint32List(19);
  final Uint32List _base = Uint32List(16);

  @override
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out) {
    for (int j = 0; j < 16; j++) {
      _sub16[j] = cur[j];
      _subN16[j] = next[j];
    }
    for (int k = 0; k < 19; k++) {
      _subP[k] = per[k];
    }
    super.constraintsM31(_sub16, _subN16, _subP, lin, _base);
    for (int j = 0; j < 16; j++) {
      out[j] = _base[j];
    }
    final sC = per[_colSC], sG = per[_colSG], sF = per[_colSFree];
    var v = 1;
    for (final f in _breakForms) {
      v = M31.mul(v, lin[f]);
    }
    final t = M31.mul(sG, v);
    final b = cur[colSwapBit];
    final u = M31.add(sC, t), w = M31.mul(t, b);
    for (int j = 0; j < 8; j++) {
      out[16 + j] = M31.add(M31.mul(u, M31.sub(next[j], cur[j])), M31.mul(w, M31.sub(next[j + 8], next[j])));
    }
    out[24] = M31.mul(sG, M31.sub(M31.mul(b, b), b));
    var o = 25;
    for (int k = 0; k < registers.length; k++) {
      var vr = 1;
      for (final f in _regForms[k]) {
        vr = M31.mul(vr, lin[f]);
      }
      out[o++] = M31.mul(vr, M31.sub(next[regCol0 + k], cur[regCol0 + k]));
    }
    var bits = 0;
    for (int k = bitLanes - 1; k >= 0; k--) {
      bits = M31.add(M31.add(bits, bits), cur[bitLane0 + k]);
    }
    for (int a = 0; a < accumulators.length; a++) {
      final c = accCol0 + a;
      out[o++] = M31.sub(M31.sub(next[c], M31.mul(per[_colAcc0 + 2 * a], cur[c])), M31.mul(per[_colAcc0 + 2 * a + 1], bits));
    }
    for (int k = 0; k < bitLanes; k++) {
      final x = cur[bitLane0 + k];
      out[o++] = M31.mul(sF, M31.sub(M31.mul(x, x), x));
    }
    if (hasPosition) {
      final m = next[modeCol], p = cur[posCol];
      final w = M31.mul(m, M31.sub(2, m));
      out[o++] = M31.mul(lin[_posForm], M31.sub(M31.sub(next[posCol], p), M31.mul(M31.mul(sG, w), M31.add(p, b))));
    }
    for (int i = 0; i < boundaries.length; i++) {
      final s = _groupSel[i] < 0 ? 0 : lin[_groupSel[i]];
      for (final e in boundaries[i].exprs) {
        var plain = 0, withS = 0;
        for (final tm in e.terms) {
          final x = M31.mul((tm.next ? next : cur)[tm.col], tm.coef);
          if (tm.timesS) {
            withS = M31.add(withS, x);
          } else {
            plain = M31.add(plain, x);
          }
        }
        final (m0, h0) = lagrange(e.constA, e.constB);
        final (pm, ph) = e.pubLagrange(publics);
        final m = M31.add(m0, pm), h = M31.add(h0, ph);
        var v = M31.add(M31.add(plain, m), M31.mul(M31.add(withS, h), s));
        if (e.gateCol >= 0) {
          final g = cur[e.gateCol];
          v = M31.mul(v, e.gateNeg ? M31.sub(1, g) : g);
        }
        out[o++] = v;
      }
    }
  }

  // ---------------------------------------------------------------- script

  static void _copy(StackEmitter e, List<String> s, List<String> d) {
    for (int k = 0; k < 4; k++) {
      e.pick(s[k], as: d[k]);
    }
  }

  static void _rename(StackEmitter e, List<String> s, List<String> d) {
    for (int k = 0; k < 4; k++) {
      e.rename(s[k], d[k]);
    }
  }

  static void _drop(StackEmitter e, List<String> q) {
    for (final l in q) {
      e.dropNamed(l);
    }
  }

  /// out = a - b limbwise from picks of canonical a, b.
  static void _diff(StackEmitter e, List<String> a, List<String> b, List<String> out) {
    for (int l = 0; l < 4; l++) {
      e.pick(a[l]);
      e.pick(b[l]);
      e.sub();
      e.reduce();
      e.nameTop(out[l]);
    }
  }

  /// out = product of copies of the named forms, or 1 if none.
  static void _product(StackEmitter e, List<List<String>> fs, List<String> out) {
    if (fs.isEmpty) {
      e.pushConst(1, as: out[0]);
      for (int k = 1; k < 4; k++) {
        e.pushConst(0, as: out[k]);
      }
      return;
    }
    _copy(e, fs[0], out);
    for (int i = 1; i < fs.length; i++) {
      _copy(e, fs[i], limbNames('_pfb'));
      M31Ops.qm31Mul(e, out, limbNames('_pfb'), limbNames('_pfc'));
      _rename(e, limbNames('_pfc'), out);
    }
  }

  /// Affine combination: out = sum coef_i * X_i (+ constant in limb 0).
  /// out = sum coef * x (QM31) + constant + sum coef * scalar, the scalars
  /// being single-limb stack items (public inputs) that enter limb 0.
  static void _affine(StackEmitter e, List<(List<String>, int)> terms, int constant, List<String> out,
      {List<(String, int)> scalars = const []}) {
    for (int l = 0; l < 4; l++) {
      var n = 0;
      for (final (x, c) in terms) {
        if (c == 0) continue;
        e.pick(x[l]);
        if (c != 1) e.mulConst(c);
        if (n > 0) e.add();
        n++;
      }
      if (l == 0) {
        for (final (name, c) in scalars) {
          if (c == 0) continue;
          e.pick(name);
          if (c != 1) e.mulConst(c);
          if (n > 0) e.add();
          n++;
        }
      }
      if (l == 0 && constant != 0) {
        e.pushConst(constant);
        if (n > 0) e.add();
        n++;
      }
      if (n == 0) {
        e.pushConst(0);
      } else {
        e.reduce();
      }
      e.nameTop(out[l]);
    }
  }

  /// The runtime part of a boundary expression, pubCoef * L(pub[A], pub[B]),
  /// as (scalars for m, scalars for h) over the public-input stack names.
  static (List<(String, int)>, List<(String, int)>) _pubScalars(BoundaryExpr ex) {
    final a = ex.pubA, b = ex.pubB, c = ex.pubCoef;
    if (a < 0 && b < 0) return (const [], const []);
    if (a == b) return ([(Air.publicName(a), c)], const []);
    final ch = M31.mul(c, _half);
    final ms = <(String, int)>[], hs = <(String, int)>[];
    if (a >= 0) {
      ms.add((Air.publicName(a), ch));
      hs.add((Air.publicName(a), ch));
    }
    if (b >= 0) {
      ms.add((Air.publicName(b), ch));
      hs.add((Air.publicName(b), M31.neg(ch)));
    }
    return (ms, hs);
  }

  @override
  void emitConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next,
      List<List<String>> per, List<List<String>> lin, List<List<String>> out) {
    final sC = per[_colSC], sG = per[_colSG], sF = per[_colSFree];
    final b = cur[colSwapBit];

    // V = product of the break forms; T = sG * V; U = sC + T; W = T * b
    _product(e, [for (final f in _breakForms) lin[f]], limbNames('_V'));
    _copy(e, sG, limbNames('_sg1'));
    M31Ops.qm31Mul(e, limbNames('_sg1'), limbNames('_V'), limbNames('_T'));
    for (int l = 0; l < 4; l++) {
      e.pick(sC[l]);
      e.pick('_T_$l');
      e.add();
      e.reduce();
      e.nameTop('_U_$l');
    }
    _copy(e, b, limbNames('_b1'));
    M31Ops.qm31Mul(e, limbNames('_T'), limbNames('_b1'), limbNames('_W'));

    // carry and glue on lanes 0..7
    for (int j = 0; j < 8; j++) {
      _diff(e, next[j], cur[j], limbNames('_D'));
      _diff(e, next[j + 8], next[j], limbNames('_E'));
      _copy(e, limbNames('_U'), limbNames('_Ua'));
      M31Ops.qm31Mul(e, limbNames('_Ua'), limbNames('_D'), limbNames('_g1'), reduceOut: false);
      _copy(e, limbNames('_W'), limbNames('_Wa'));
      M31Ops.qm31Mul(e, limbNames('_Wa'), limbNames('_E'), limbNames('_g2'), reduceOut: false);
      for (int l = 0; l < 4; l++) {
        e.roll('_g1_$l');
        e.roll('_g2_$l');
        e.add();
        e.reduce();
        e.nameTop(out[16 + j][l]);
      }
    }
    _drop(e, limbNames('_U'));
    _drop(e, limbNames('_W'));

    // swap-bit booleanity: sG * (b^2 - b)
    _copy(e, b, limbNames('_ba'));
    _copy(e, b, limbNames('_bb'));
    M31Ops.qm31Mul(e, limbNames('_ba'), limbNames('_bb'), limbNames('_b2'));
    for (int l = 0; l < 4; l++) {
      e.roll('_b2_$l');
      e.pick(b[l]);
      e.sub();
      e.reduce();
      e.nameTop('_bd_$l');
    }
    _copy(e, sG, limbNames('_sg2'));
    M31Ops.qm31Mul(e, limbNames('_sg2'), limbNames('_bd'), out[24]);

    var o = 25;
    // register persistence
    for (int k = 0; k < registers.length; k++) {
      _diff(e, next[regCol0 + k], cur[regCol0 + k], limbNames('_rd'));
      if (_regForms[k].isEmpty) {
        _rename(e, limbNames('_rd'), out[o]);
      } else {
        _product(e, [for (final f in _regForms[k]) lin[f]], limbNames('_vr'));
        M31Ops.qm31Mul(e, limbNames('_vr'), limbNames('_rd'), out[o]);
      }
      o++;
    }
    // bits = sum 2^k cur[9+k]
    if (accumulators.isNotEmpty) {
      _affine(e, [for (int k = 0; k < bitLanes; k++) (cur[bitLane0 + k], 1 << k)], 0, limbNames('_bits'));
    }
    for (int a = 0; a < accumulators.length; a++) {
      final c = accCol0 + a;
      _copy(e, per[_colAcc0 + 2 * a], limbNames('_am'));
      _copy(e, cur[c], limbNames('_ac'));
      M31Ops.qm31Mul(e, limbNames('_am'), limbNames('_ac'), limbNames('_amc'), reduceOut: false);
      _copy(e, per[_colAcc0 + 2 * a + 1], limbNames('_ag'));
      _copy(e, limbNames('_bits'), limbNames('_ab'));
      M31Ops.qm31Mul(e, limbNames('_ag'), limbNames('_ab'), limbNames('_agb'), reduceOut: false);
      for (int l = 0; l < 4; l++) {
        e.pick(next[c][l]);
        e.roll('_amc_$l');
        e.sub();
        e.roll('_agb_$l');
        e.sub();
        e.reduce();
        e.nameTop(out[o][l]);
      }
      o++;
    }
    if (accumulators.isNotEmpty) _drop(e, limbNames('_bits'));
    // bit-lane booleanity: sF * (x^2 - x)
    for (int k = 0; k < bitLanes; k++) {
      final x = cur[bitLane0 + k];
      _copy(e, x, limbNames('_xa'));
      _copy(e, x, limbNames('_xb'));
      M31Ops.qm31Mul(e, limbNames('_xa'), limbNames('_xb'), limbNames('_x2'));
      for (int l = 0; l < 4; l++) {
        e.roll('_x2_$l');
        e.pick(x[l]);
        e.sub();
        e.reduce();
        e.nameTop('_xd_$l');
      }
      _copy(e, sF, limbNames('_sf'));
      M31Ops.qm31Mul(e, limbNames('_sf'), limbNames('_xd'), out[o++]);
    }
    if (hasPosition) {
      // w = m (2 - m); out = next[pos] - pos - sG * w * (pos + b)
      _affine(e, [(next[modeCol], M31.p - 1)], 2, limbNames('_pw2'));
      _copy(e, next[modeCol], limbNames('_pm'));
      M31Ops.qm31Mul(e, limbNames('_pm'), limbNames('_pw2'), limbNames('_pw'), reduceOut: false);
      _copy(e, sG, limbNames('_psg'));
      M31Ops.qm31Mul(e, limbNames('_psg'), limbNames('_pw'), limbNames('_pws'));
      _affine(e, [(cur[posCol], 1), (b, 1)], 0, limbNames('_ppb'));
      M31Ops.qm31Mul(e, limbNames('_pws'), limbNames('_ppb'), limbNames('_pv'), reduceOut: false);
      for (int l = 0; l < 4; l++) {
        e.pick(next[posCol][l]);
        e.pick(cur[posCol][l]);
        e.sub();
        e.roll('_pv_$l');
        e.sub();
        e.reduce();
        e.nameTop('_pd_$l');
      }
      _copy(e, lin[_posForm], limbNames('_pf'));
      M31Ops.qm31Mul(e, limbNames('_pf'), limbNames('_pd'), out[o++]);
    }

    // boundary expressions
    for (int i = 0; i < boundaries.length; i++) {
      for (final ex in boundaries[i].exprs) {
        final (m, h) = lagrange(ex.constA, ex.constB);
        final plain = <(List<String>, int)>[], withS = <(List<String>, int)>[];
        for (final tm in ex.terms) {
          final x = (tm.next ? next : cur)[tm.col];
          (tm.timesS ? withS : plain).add((x, tm.coef));
        }
        final gated = ex.gateCol >= 0;
        final target = gated ? limbNames('_bg') : out[o];
        final (mScalars, hScalars) = _pubScalars(ex);
        if (withS.isEmpty && h == 0 && hScalars.isEmpty) {
          _affine(e, plain, m, target, scalars: mScalars);
        } else {
          _affine(e, plain, m, limbNames('_bp'), scalars: mScalars);
          _affine(e, withS, h, limbNames('_bs'), scalars: hScalars);
          _copy(e, lin[_groupSel[i]], limbNames('_bsel'));
          M31Ops.qm31Mul(e, limbNames('_bs'), limbNames('_bsel'), limbNames('_bss'), reduceOut: false);
          for (int l = 0; l < 4; l++) {
            e.roll('_bp_$l');
            e.roll('_bss_$l');
            e.add();
            e.reduce();
            e.nameTop(target[l]);
          }
        }
        if (gated) {
          // gate g (or 1 - g) as a QM31 with the column in limb 0
          final g = cur[ex.gateCol];
          if (ex.gateNeg) {
            _affine(e, [(g, M31.p - 1)], 1, limbNames('_bgc'));
          } else {
            _copy(e, g, limbNames('_bgc'));
          }
          M31Ops.qm31Mul(e, limbNames('_bg'), limbNames('_bgc'), out[o]);
        }
        o++;
      }
    }

    // everything this class only picked
    for (int k = 16; k < numCols; k++) {
      _drop(e, cur[k]);
      _drop(e, next[k]);
    }
    for (final f in lin) {
      _drop(e, f);
    }
    for (int k = 19; k < per.length; k++) {
      _drop(e, per[k]);
    }
    super.emitConstraints(
        e, cur.sublist(0, 16), next.sublist(0, 16), per.sublist(0, 19), const [], out.sublist(0, 16));
  }

  // ---------------------------------------------------------------- trace

  /// Build the 16 state lanes for a program of [steps] (one per period);
  /// bit lanes and scratch are zero. Registers and accumulators are appended
  /// as zero columns for the caller to fill; see [fillAccumulators].
  List<List<int>> generateChain(List<ChainStep> steps) {
    if (steps.length != periods) {
      throw ArgumentError('expected $periods steps, got ${steps.length}');
    }
    final rows = <List<int>>[];
    var carry = List<int>.filled(8, 0);
    final extra = numCols - 16;
    for (int p = 0; p < periods; p++) {
      final st = steps[p];
      List<int> input;
      if (st.freshInput != null) {
        input = [...st.freshInput!];
      } else {
        input = List<int>.filled(16, 0);
        final lo = st.swap ? 8 : 0, hi = st.swap ? 0 : 8;
        for (int j = 0; j < 8; j++) {
          input[lo + j] = carry[j];
          input[hi + j] = st.witness[j];
        }
      }
      var s = input;
      for (int r = 0; r < 24; r++) {
        rows.add([...s, ...List.filled(extra, 0)]);
        s = Poseidon2Air.step(s, r);
      }
      carry = s.sublist(0, 8);
      final nxt = steps[(p + 1) % periods];
      for (int r = 24; r < 32; r++) {
        final row = List<int>.filled(numCols, 0, growable: true);
        for (int j = 0; j < 8; j++) {
          row[j] = carry[j];
        }
        if (r == 31 && nxt.swap) row[colSwapBit] = 1;
        rows.add(row);
      }
    }
    if (binding != null) {
      final b = binding!, half = periods >> 1;
      for (int p = 0; p < periods; p++) {
        final q = p % half;
        final m = q >= b.walk1 && q < b.walk1 + b.steps ? 1 : (q >= b.walk2 && q < b.walk2 + b.steps ? 2 : 0);
        for (int r = p << 5; r < (p + 1) << 5; r++) {
          rows[r][modeCol] = m;
        }
      }
      if (hasPosition) {
        final n = rows.length;
        final start = _glue(b.walk1, logTrace);
        var pos = 0;
        for (int i = 0; i < n; i++) {
          final r = (start + i) % n;
          if (r == start || r == (start + (n >> 1)) % n) pos = 0; // reset for each half's walk
          rows[r][posCol] = pos;
          if (r & 31 == 31 && rows[(r + 1) % n][modeCol] == 1) {
            pos = M31.add(M31.add(pos, pos), rows[r][colSwapBit]);
          }
        }
      }
    }
    return rows;
  }

  /// Compute the accumulator columns from the bit lanes, following each
  /// schedule cyclically (a schedule that resets every period is
  /// well-defined; one that never resets must be consistent around the cycle).
  void fillAccumulators(List<List<int>> rows) {
    final n = rows.length;
    for (int a = 0; a < accumulators.length; a++) {
      final spec = accumulators[a];
      final c = accCol0 + a;
      // start after a reset row so the value at the top of the trace is right
      int start = 0;
      for (int r = 0; r < 32; r++) {
        if (spec.mult[r] == 0) {
          start = r + 1;
          break;
        }
      }
      var acc = 0;
      for (int i = 0; i < n + start; i++) {
        final r = (start + i) % n;
        rows[r][c] = acc;
        final bits = _bits(rows[r]);
        acc = M31.add(M31.mul(spec.mult[r & 31], acc), M31.mul(spec.gate[r & 31], bits));
      }
    }
  }

  static int _bits(List<int> row) {
    var v = 0;
    for (int k = bitLanes - 1; k >= 0; k--) {
      v = M31.add(M31.add(v, v), row[bitLane0 + k]);
    }
    return v;
  }

  /// The permutation output of period [p], i.e. trace row 32p + 23.
  static int outputRow(int p) => (p << 5) + 23;

  /// The permutation input of period [p].
  static int inputRow(int p) => p << 5;

  /// The row whose transition feeds period [p]'s input, i.e. the last row of
  /// the preceding period. Breaking the chain before [p] means excepting the
  /// glue constraint here, not at [p]'s own first row.
  int glueRow(int p) => ((p << logPeriod) - 1) & ((1 << logTrace) - 1);
}
