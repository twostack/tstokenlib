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
import '../script_gen/air.dart';
import '../script_gen/air_ring.dart';
import '../script_gen/deep_quotient_script_gen.dart' show limbNames;
import '../script_gen/m31_script_gen.dart';
import '../script_gen/poseidon2_air.dart';
import '../script_gen/program_script_gen.dart';

/// The machine that verifies a Poseidon2-flavour STARK proof inside a STARK.
///
/// One circuit for every inner proof shape: the structure below is fixed and
/// a *program* (the preprocessed columns, see [VerifierProgramColumns])
/// says what each row does. The trace is a Poseidon2 chain (32-row periods,
/// as `Poseidon2ChainAir`) for the transcript and the Merkle walks, a small
/// straight-line VM for the field arithmetic, and a *bus* (a LogUp lookup
/// with tags, in the aux round) that wires values between rows.
///
/// Main columns (committed first):
///   0..15  Poseidon2 state. Row 0 of a period is the permutation input,
///          row 23 its output, rows 24..31 carry the digest in lanes 0..7.
///          Lane 8 of row 31 is the *swap bit* b of the next period (the
///          digest lands in the next input's low half when b = 0, high half
///          when b = 1).
///   16..19 A, 20..23 B: the two bus operands (4 limbs each), also the
///          hint columns and the cells the hash input/digest pins refer to.
///          Merkle direction bits are the (boolean) swap bits, produced on
///          the bus and bound to the query index by the VM.
/// Aux columns (committed after the challenges gamma, delta, eta):
///   ACC (4), H1 (4), H2 (4), HA (4), HB (4): the bus accumulator and the
///   LogUp helper inverses of the producer ports P1, P2 and consumer ports
///   A, B.
/// Preprocessed columns: the program, [VerifierProgramColumns.names].
/// Public inputs, two modes:
///   * digest ([wide] false): 8 lanes, the digest the program computes over
///     the inner proofs' *statement digests* (see `VerifierProgram`), pinned
///     by `pinPub` to lanes 0..7 of a period's digest row.
///   * wide ([wide] true, the root of an aggregation): 8 lanes per pinned
///     period, the raw public inputs of every transfer; `pinPub` pins lanes
///     8..15 of the hash-input row of each such period to *public columns*
///     (see `Air.pubColumns`), which the verifier evaluates out of domain
///     with the trace domain's Lagrange kernel.
class VerifierAir extends Poseidon2Air {
  static const colA = 16, colB = 20;
  static const numMainCols = 24;
  static const numPublicLanes = 8;
  static const tagP2Offset = 1 << 20;

  /// Aux column offsets (relative to [auxCol0]).
  static const auxAcc = 0, auxH1 = 4, auxH2 = 8, auxHA = 12, auxHB = 16;

  final VerifierProgramColumns prog;
  final List<int> publics;
  final bool wide;

  /// Program-recorded constraints take the publics as ring inputs when set.
  List<Object>? publicsOverride;

  VerifierAir(super.logTrace, this.prog, this.publics, {this.wide = false}) {
    if (prog.rows != 1 << logTrace) throw ArgumentError('program has ${prog.rows} rows, trace ${1 << logTrace}');
    if (!wide && publics.length != numPublicLanes) throw ArgumentError('$numPublicLanes public lanes');
    if (wide && publics.length != 8 * pinnedRows.length) {
      throw ArgumentError('wide statement: ${8 * pinnedRows.length} public lanes for ${pinnedRows.length} pinned periods');
    }
  }

  int get periods => 1 << (logTrace - logPeriod);

  /// The rows the program pins (ascending): digest rows in digest mode,
  /// hash-input rows in wide mode, one public chunk each.
  List<int>? _pinned;
  List<int> get pinnedRows => _pinned ??= [
        for (int r = 0; r < prog.rows; r++)
          if (prog.columns[VerifierProgramColumns.pinPub][r] == 1) r
      ];

  @override
  int get numCols => numMainCols;
  @override
  int get numPublics => publics.length;
  @override
  List<int> get publicValues => publics;
  @override
  int get numChallenges => 3;
  @override
  int get numAuxCols => 20;
  @override
  int get numAuxConstraints => 5;
  @override
  int get numPreCols => VerifierProgramColumns.count;
  @override
  List<Uint32List> preColumns() => prog.columns;
  @override
  Object get preColumnsIdentity => prog;
  int get auxCol0 => numMainCols;

  static const _mainCount = 77;
  @override
  int get numConstraints => _mainCount + numPublicLanes;

  // periodic columns after the 19 of Poseidon2Air
  static const _colSC = 19, _colSG = 20;
  List<List<int>>? _per;
  @override
  List<List<int>> get periodic => _per ??= [
        ...super.periodic,
        [for (int r = 0; r < 32; r++) r >= 23 && r <= 30 ? 1 : 0],
        [for (int r = 0; r < 32; r++) r == 31 ? 1 : 0],
      ];

  @override
  List<ConstraintGroup> get groups => [ConstraintGroup(numConstraints)];

  // ---------------------------------------------------------------- QM31 limb arithmetic over a ring

  /// (a0 + a1 i)(b0 + b1 i)
  static (T, T) _cmul<T>(Ring<T> f, T a0, T a1, T b0, T b1) =>
      (f.sub(f.mul(a0, b0), f.mul(a1, b1)), f.add(f.mul(a0, b1), f.mul(a1, b0)));

  /// QM31 product of two 4-limb values, limbwise (see `QM31.operator *`).
  static List<T> qmulLimbs<T>(Ring<T> f, List<T> a, List<T> b) {
    final (p0, p1) = _cmul(f, a[0], a[1], b[0], b[1]);
    final (q0, q1) = _cmul(f, a[2], a[3], b[2], b[3]);
    // (q0 + q1 i)(2 + i) = (2q0 - q1) + (q0 + 2q1) i
    final t0 = f.sub(f.add(q0, q0), q1), t1 = f.add(q0, f.add(q1, q1));
    final (r0, r1) = _cmul(f, a[0], a[1], b[2], b[3]);
    final (s0, s1) = _cmul(f, a[2], a[3], b[0], b[1]);
    return [f.add(p0, t0), f.add(p1, t1), f.add(r0, s0), f.add(r1, s1)];
  }

  /// The VM result f(A, B) as 4 limbs, selected by the op columns.
  List<T> vmResultG<T>(Ring<T> f, List<T> cur, List<T> pre) {
    final a = cur.sublist(colA, colA + 4), b = cur.sublist(colB, colB + 4);
    final imm = [for (int k = 0; k < 4; k++) pre[VerifierProgramColumns.imm0 + k]];
    final opAdd = pre[VerifierProgramColumns.opAdd], opSub = pre[VerifierProgramColumns.opSub];
    final opMul = pre[VerifierProgramColumns.opMul], opMulImm = pre[VerifierProgramColumns.opMulImm];
    final opConst = pre[VerifierProgramColumns.opConst], opLimb = pre[VerifierProgramColumns.opLimb];
    final ab = qmulLimbs(f, a, b), ai = qmulLimbs(f, a, imm);
    final limb = f.add(f.add(f.mul(imm[0], a[0]), f.mul(imm[1], a[1])), f.add(f.mul(imm[2], a[2]), f.mul(imm[3], a[3])));
    return [
      for (int k = 0; k < 4; k++)
        f.add(
            f.add(f.add(f.mul(opAdd, f.add(a[k], b[k])), f.mul(opSub, f.sub(a[k], b[k]))),
                f.add(f.mul(opMul, ab[k]), f.mul(opMulImm, ai[k]))),
            f.add(f.mul(opConst, imm[k]), k == 0 ? f.mul(opLimb, limb) : f.zero)),
    ];
  }

  // ---------------------------------------------------------------- main constraints

  @override
  List<T> constraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin) {
    final out = <T>[...super.constraintsG(f, cur.sublist(0, 16), next.sublist(0, 16), per.sublist(0, 19), const [])];
    final pre = cur.sublist(preCol0, preCol0 + VerifierProgramColumns.count);
    T P(int c) => pre[c];
    final sC = per[_colSC], sG = per[_colSG];
    final b = cur[8];
    // carry and glue on lanes 0..7: chained periods take the digest in the half the swap bit selects
    final t = f.mul(sG, P(VerifierProgramColumns.chain));
    final u = f.add(sC, t), w = f.mul(t, b);
    for (int j = 0; j < 8; j++) {
      out.add(f.add(f.mul(u, f.sub(next[j], cur[j])), f.mul(w, f.sub(next[j + 8], next[j]))));
    }
    out.add(f.mul(sG, f.sub(f.mul(b, b), b))); // 24
    // zero pins on the permutation input
    for (int j = 0; j < 8; j++) {
      out.add(f.mul(P(VerifierProgramColumns.zeroLo), cur[j])); // 25..32
    }
    out.add(f.mul(P(VerifierProgramColumns.z8), cur[8])); // 33
    for (int j = 9; j < 16; j++) {
      out.add(f.mul(P(VerifierProgramColumns.zTail), cur[j])); // 34..40
    }
    // lanes pinned to the operand columns
    final ab = [...cur.sublist(colA, colA + 4), ...cur.sublist(colB, colB + 4)];
    for (int j = 0; j < 8; j++) {
      out.add(f.mul(P(VerifierProgramColumns.inHiAB), f.sub(cur[8 + j], ab[j]))); // 41..48
    }
    for (int j = 0; j < 8; j++) {
      out.add(f.mul(P(VerifierProgramColumns.inLoAB), f.sub(cur[j], ab[j]))); // 49..56
    }
    for (int j = 0; j < 8; j++) {
      out.add(f.mul(P(VerifierProgramColumns.digAB), f.sub(cur[j], ab[j]))); // 57..64
    }
    // lanes 8..15 pinned to the NEXT row's operand columns (a second bus
    // value into one hash input: Merkle nodes of two wires)
    final nextAb = [...next.sublist(colA, colA + 4), ...next.sublist(colB, colB + 4)];
    for (int j = 0; j < 8; j++) {
      out.add(f.mul(P(VerifierProgramColumns.inHiNext), f.sub(cur[8 + j], nextAb[j]))); // 65..72
    }
    // the VM result asserted zero
    final res = vmResultG(f, cur, pre);
    for (int k = 0; k < 4; k++) {
      out.add(f.mul(P(VerifierProgramColumns.assertZero), res[k])); // 73..76
    }
    if (out.length != _mainCount) throw StateError('main constraint count ${out.length}');
    // the statement: the program pins a period's digest lanes to the public
    // inputs (digest mode) or its hash-input lanes to the public columns (wide)
    final pubs = publicsOverride?.cast<T>();
    for (int j = 0; j < 8; j++) {
      final T pv = wide ? per[numPeriodic + j] : (pubs == null ? f.constM31(publics[j]) : pubs[j]);
      out.add(f.mul(P(VerifierProgramColumns.pinPub), f.sub(cur[(wide ? 8 : 0) + j], pv))); // 77..84
    }
    return out;
  }

  // ---------------------------------------------------------------- the wide statement's public columns
  //
  // Column j holds publics[8c + j] at the c-th pinned row and 0 elsewhere.
  // Its interpolant at an out-of-domain point z on the circle is
  //   v(z) * sum_c publics[8c + j] * s_c * (1 + <z, h_c>) / (z x h_c),
  // with h_c the row's point, <,> the dot and x the cross product, v the
  // trace vanishing polynomial and s_c = (-1)^{r_c} / 2^logTrace (the
  // circle Lagrange kernel; checked against the FFT interpolant).

  @override
  int get numPubCols => wide ? 8 : 0;

  @override
  List<Uint32List> pubColumns() {
    if (!wide) return const [];
    final cols = List.generate(8, (_) => Uint32List(prog.rows));
    final rows = pinnedRows;
    for (int c = 0; c < rows.length; c++) {
      for (int j = 0; j < 8; j++) {
        cols[j][rows[c]] = publics[8 * c + j];
      }
    }
    return cols;
  }

  /// s_c, s_c h_x, s_c h_y for the c-th pinned row.
  (int, int, int) _kernelConsts(int c) {
    final r = pinnedRows[c];
    final h = rowPoint(r);
    final nInv = M31.inv(1 << logTrace);
    final s = r.isEven ? nInv : M31.p - nInv;
    return (s, M31.mul(s, h.x), M31.mul(s, h.y));
  }

  /// The per-chunk kernel factors s_c (1 + <z,h_c>) / (z x h_c).
  List<QM31> _kernels(QM31 zx, QM31 zy) {
    final out = <QM31>[];
    for (int c = 0; c < pinnedRows.length; c++) {
      final h = rowPoint(pinnedRows[c]);
      final (s, shx, shy) = _kernelConsts(c);
      final num = QM31.fromLimbs(s, 0, 0, 0) + zx.scale(shx) + zy.scale(shy);
      final den = zy.scale(h.x) - zx.scale(h.y);
      out.add(num * den.inv);
    }
    return out;
  }

  @override
  List<QM31> pubColumnsAt(QM31 zx, QM31 zy) {
    if (!wide) return const [];
    final ks = _kernels(zx, zy);
    final v = vanishing(zx);
    return [
      for (int j = 0; j < 8; j++)
        () {
          var acc = QM31.zero;
          for (int c = 0; c < ks.length; c++) {
            acc = acc + ks[c].scale(publics[8 * c + j]);
          }
          return acc * v;
        }()
    ];
  }

  @override
  List<T> pubColumnsAtG<T>(Ring<T> f, T zx, T zy) {
    if (!wide) return const [];
    if (f is QM31Ring) return pubColumnsAt(zx as QM31, zy as QM31).cast<T>();
    throw UnsupportedError('a wide statement is verified by the reference verifier and in script only');
  }

  @override
  int get numPubHints => wide ? pinnedRows.length : 0;

  @override
  List<QM31> pubHints(QM31 zx, QM31 zy) => wide ? _kernels(zx, zy) : const [];

  /// Script: per chunk c, check hint_c * (zy h_x - zx h_y) == s_c + s_c h_x zx + s_c h_y zy,
  /// accumulate publics[8c + j] * hint_c per lane j (lazily), then scale by v.
  @override
  void emitPubColumns(StackEmitter e, List<String> zx, List<String> zy, List<String> v, List<List<String>> hints,
      List<List<String>> out) {
    if (!wide) return;
    final n = pinnedRows.length;
    for (int c = 0; c < n; c++) {
      final h = rowPoint(pinnedRows[c]);
      final (s, shx, shy) = _kernelConsts(c);
      // den = zy h_x - zx h_y (lazy)
      for (int k = 0; k < 4; k++) {
        e.pick(zy[k]);
        e.mulConst(h.x);
        e.pick(zx[k]);
        e.mulConst(h.y);
        e.sub();
        e.nameTop('_pd_$k');
      }
      // num = s + s h_x zx + s h_y zy (canonical)
      for (int k = 0; k < 4; k++) {
        e.pick(zx[k]);
        e.mulConst(shx);
        e.pick(zy[k]);
        e.mulConst(shy);
        e.add();
        if (k == 0) {
          e.pushConst(s);
          e.add();
        }
        e.reduce();
        e.nameTop('_pn_$k');
      }
      for (int k = 0; k < 4; k++) {
        e.pick(hints[c][k], as: '_ph_$k');
      }
      M31Ops.qm31Mul(e, limbNames('_pd'), limbNames('_ph'), limbNames('_pp'));
      for (int k = 0; k < 4; k++) {
        e.roll('_pp_$k');
        e.roll('_pn_$k');
        e.numEqualVerify();
      }
    }
    // acc_{j,k} = Σ_c pub_{8c+j} * hint_{c,k}: the sum stays on top (lazy)
    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 4; k++) {
        for (int c = 0; c < n; c++) {
          e.pick(Air.publicName(8 * c + j));
          if (j == 7 && k == 3) {
            e.roll(hints[c][k]);
          } else {
            e.pick(hints[c][k]);
          }
          e.mul();
          if (c > 0) e.add();
        }
        e.reduce();
        e.nameTop('_pa${j}_$k');
      }
    }
    for (int c = 0; c < n; c++) {
      for (final l in hints[c]) {
        if (e.has(l)) e.dropNamed(l);
      }
    }
    for (int j = 0; j < 8; j++) {
      for (int k = 0; k < 4; k++) {
        e.pick(v[k], as: '_pv_$k');
      }
      M31Ops.qm31Mul(e, limbNames('_pa$j'), limbNames('_pv'), out[j]);
    }
  }

  final M31Ring _m31 = const M31Ring();
  List<int>? _curL, _nextL, _perL, _linL;

  @override
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out) {
    _curL ??= List<int>.filled(cur.length, 0);
    _nextL ??= List<int>.filled(next.length, 0);
    _perL ??= List<int>.filled(per.length, 0);
    _linL ??= List<int>.filled(lin.length, 0);
    _curL!.setAll(0, cur);
    _nextL!.setAll(0, next);
    _perL!.setAll(0, per);
    _linL!.setAll(0, lin);
    final r = constraintsG(_m31, _curL!, _nextL!, _perL!, _linL!);
    out.setAll(0, r);
  }

  // ---------------------------------------------------------------- the bus (aux round)

  /// The producer port P1's value, the consumer port A's value and the
  /// enables, over a ring whose values are QM31 (embedded base cells).
  ({T v1, T en1, T vB, T vA, T enA}) _busValues<T>(Ring<T> f, List<T> cur, List<T> pre, T eta) {
    T P(int c) => pre[c];
    final a = cur.sublist(colA, colA + 4), b = cur.sublist(colB, colB + 4);
    final ca = f.composeLimbs(a), cb = f.composeLimbs(b);
    final k8 = f.add(ca, f.mul(eta, cb));
    final res = f.composeLimbs(vmResultG(f, cur, pre));
    final p1vm = P(VerifierProgramColumns.p1vm), p1a4 = P(VerifierProgramColumns.p1a4);
    final p1ab8 = P(VerifierProgramColumns.p1ab8), p1a1 = P(VerifierProgramColumns.p1a1);
    final p1swap = P(VerifierProgramColumns.p1swap);
    final v1 = f.add(f.add(f.mul(p1vm, res), f.mul(p1a4, ca)),
        f.add(f.add(f.mul(p1ab8, k8), f.mul(p1a1, a[0])), f.mul(p1swap, cur[8])));
    final en1 = f.add(f.add(p1vm, p1a4), f.add(f.add(p1ab8, p1a1), p1swap));
    final ak4 = P(VerifierProgramColumns.ak4), ak8 = P(VerifierProgramColumns.ak8), ak1 = P(VerifierProgramColumns.ak1);
    final vA = f.add(f.add(f.mul(ak4, ca), f.mul(ak8, k8)), f.mul(ak1, a[0]));
    final enA = f.add(f.add(ak4, ak8), ak1);
    return (v1: v1, en1: en1, vB: cb, vA: vA, enA: enA);
  }

  @override
  List<T> auxConstraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin, List<T> chal) {
    final gamma = chal[0], delta = chal[1], eta = chal[2];
    final pre = cur.sublist(preCol0, preCol0 + VerifierProgramColumns.count);
    T P(int c) => pre[c];
    final bv = _busValues(f, cur, pre, eta);
    final rowid = P(VerifierProgramColumns.rowid);
    final acc = f.composeLimbs(cur.sublist(auxCol0 + auxAcc, auxCol0 + auxAcc + 4));
    final accN = f.composeLimbs(next.sublist(auxCol0 + auxAcc, auxCol0 + auxAcc + 4));
    final h1 = f.composeLimbs(cur.sublist(auxCol0 + auxH1, auxCol0 + auxH1 + 4));
    final h2 = f.composeLimbs(cur.sublist(auxCol0 + auxH2, auxCol0 + auxH2 + 4));
    final hA = f.composeLimbs(cur.sublist(auxCol0 + auxHA, auxCol0 + auxHA + 4));
    final hB = f.composeLimbs(cur.sublist(auxCol0 + auxHB, auxCol0 + auxHB + 4));
    final d1 = f.add(f.add(gamma, bv.v1), f.mul(delta, rowid));
    final d2 = f.add(f.add(gamma, bv.vB), f.mul(delta, f.addConst(rowid, tagP2Offset)));
    final dA = f.add(f.add(gamma, bv.vA), f.mul(delta, P(VerifierProgramColumns.tagA)));
    final dB = f.add(f.add(gamma, bv.vB), f.mul(delta, P(VerifierProgramColumns.tagB)));
    final flow = f.sub(f.sub(f.add(f.mul(P(VerifierProgramColumns.mult1), h1), f.mul(P(VerifierProgramColumns.mult2), h2)), hA), hB);
    return [
      f.sub(f.mul(h1, d1), bv.en1),
      f.sub(f.mul(h2, d2), P(VerifierProgramColumns.p2en)),
      f.sub(f.mul(hA, dA), bv.enA),
      f.sub(f.mul(hB, dB), P(VerifierProgramColumns.ben)),
      f.sub(f.sub(accN, acc), flow),
    ];
  }

  @override
  void auxConstraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, List<QM31> chal, List<QM31> out) {
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    final r = auxConstraintsG(QM31Ring.instance, [for (final v in cur) emb(v)], [for (final v in next) emb(v)],
        [for (final v in per) emb(v)], [for (final v in lin) emb(v)], chal);
    out.setAll(0, r);
  }

  /// The helper inverses and the accumulator from the main rows and the
  /// program. A valid witness has the bus terms summing to zero over the
  /// trace, so the cyclic accumulator closes.
  @override
  List<Uint32List> auxColumns(List<List<int>> rows, List<QM31> chal) {
    final n = rows.length;
    final gamma = chal[0], delta = chal[1], eta = chal[2];
    const f = QM31Ring.instance;
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    final cols = List.generate(20, (_) => Uint32List(n));
    final terms = List<QM31>.filled(n, QM31.zero);
    final preLists = prog.columns;
    for (int r = 0; r < n; r++) {
      final cur = [for (final v in rows[r]) emb(v)];
      final pre = [for (int c = 0; c < VerifierProgramColumns.count; c++) emb(preLists[c][r])];
      final bv = _busValues(f, cur, pre, eta);
      final rowid = pre[VerifierProgramColumns.rowid];
      QM31 helper(QM31 en, QM31 v, QM31 tag) => en == QM31.zero ? QM31.zero : (gamma + v + delta * tag).inv * en;
      final h1 = helper(bv.en1, bv.v1, rowid);
      final h2 = helper(pre[VerifierProgramColumns.p2en], bv.vB, rowid + emb(tagP2Offset));
      final hA = helper(bv.enA, bv.vA, pre[VerifierProgramColumns.tagA]);
      final hB = helper(pre[VerifierProgramColumns.ben], bv.vB, pre[VerifierProgramColumns.tagB]);
      terms[r] = pre[VerifierProgramColumns.mult1] * h1 + pre[VerifierProgramColumns.mult2] * h2 - hA - hB;
      void put(int off, QM31 v) {
        final l = v.limbs;
        for (int k = 0; k < 4; k++) {
          cols[off + k][r] = l[k];
        }
      }
      put(auxH1, h1);
      put(auxH2, h2);
      put(auxHA, hA);
      put(auxHB, hB);
    }
    var acc = QM31.zero;
    for (int r = 0; r < n; r++) {
      final l = acc.limbs;
      for (int k = 0; k < 4; k++) {
        cols[auxAcc + k][r] = l[k];
      }
      acc = acc + terms[r];
    }
    if (acc != QM31.zero) throw StateError('bus does not balance: ${acc}');
    return cols;
  }

  /// The bus as a [LogUpSpec]: the four helpers' (enable, value, tag,
  /// multiplicity) from the main row, the program row and the challenges
  /// (gamma, delta, eta), exactly as [auxColumns] computes them.
  @override
  LogUpSpec logUpSpec() {
    final r = ExprRing();
    final cur = r.inputs('cur', numCols), pre = r.inputs('pre', VerifierProgramColumns.count), chal = r.inputs('chal', numChallenges);
    final bv = _busValues(r, cur, pre, chal[2]);
    final rowid = pre[VerifierProgramColumns.rowid];
    final minusOne = r.neg(r.one);
    final prog = r.program([
      bv.en1, bv.v1, rowid, pre[VerifierProgramColumns.mult1],
      pre[VerifierProgramColumns.p2en], bv.vB, r.addConst(rowid, tagP2Offset), pre[VerifierProgramColumns.mult2],
      bv.enA, bv.vA, pre[VerifierProgramColumns.tagA], minusOne,
      pre[VerifierProgramColumns.ben], bv.vB, pre[VerifierProgramColumns.tagB], minusOne,
    ]);
    return LogUpSpec(prog, helperOffsets: const [auxH1, auxH2, auxHA, auxHB], accOffset: auxAcc);
  }

  // ---------------------------------------------------------------- script

  /// The main constraints recorded as a [Program] over the inputs cur{j},
  /// next{j} (totalCols each), per{k}, lin{k} and pub{j} (the 8 public
  /// lanes, base-field values).
  Program mainProgram() {
    final r = ExprRing();
    final cur = r.inputs('cur', totalCols), next = r.inputs('next', totalCols);
    final per = r.inputs('per', numPointCols), lin = r.inputs('lin', numLinear);
    publicsOverride = wide ? null : r.inputs('pub', numPublicLanes);
    try {
      return r.program(constraintsG(r, cur, next, per, lin));
    } finally {
      publicsOverride = null;
    }
  }

  /// The aux constraints as a [Program] over cur, next, per, lin and
  /// chal{k} (three QM31 challenges).
  Program auxProgram() {
    final r = ExprRing();
    final cur = r.inputs('cur', totalCols), next = r.inputs('next', totalCols);
    final per = r.inputs('per', numPointCols), lin = r.inputs('lin', numLinear);
    final chal = r.inputs('chal', numChallenges);
    return r.program(auxConstraintsG(r, cur, next, per, lin, chal));
  }

  static Map<String, List<String>> _inputMap(
      List<List<String>> cur, List<List<String>> next, List<List<String>> per, List<List<String>> lin) {
    final m = <String, List<String>>{};
    for (int j = 0; j < cur.length; j++) {
      m['cur$j'] = cur[j];
      m['next$j'] = next[j];
    }
    for (int k = 0; k < per.length; k++) {
      m['per$k'] = per[k];
    }
    for (int k = 0; k < lin.length; k++) {
      m['lin$k'] = lin[k];
    }
    return m;
  }

  /// Script side of the main constraints: the compiled [mainProgram], which
  /// consumes cur, next, per and lin and picks the publics `pub0..7`.
  @override
  void emitConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next, List<List<String>> per,
      List<List<String>> lin, List<List<String>> out) {
    final prog = mainProgram();
    final m = _inputMap(cur, next, per, lin);
    if (!wide) {
      for (int j = 0; j < numPublicLanes; j++) {
        m['pub$j'] = [Air.publicName(j)];
      }
    }
    ProgramScriptGen.emit(e, prog, m, out, consume: {...m.keys.where((k) => !k.startsWith('pub'))});
  }

  /// Script side of the aux constraints: the compiled [auxProgram], which
  /// picks cur, next, per and lin and consumes the challenges.
  @override
  void emitAuxConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next, List<List<String>> per,
      List<List<String>> lin, List<List<String>> chal, List<List<String>> out) {
    final prog = auxProgram();
    final m = _inputMap(cur, next, per, lin);
    for (int k = 0; k < numChallenges; k++) {
      m['chal$k'] = chal[k];
    }
    ProgramScriptGen.emit(e, prog, m, out, consume: {for (int k = 0; k < numChallenges; k++) 'chal$k'});
  }
}

/// M31 scalar arithmetic as a [Ring], for the prover's fast path of
/// limbwise constraints (QM31 constants are not representable here).
class M31Ring extends Ring<int> {
  const M31Ring();
  @override
  int get zero => 0;
  @override
  int get one => 1;
  @override
  int constM31(int m) => m;
  @override
  int constQ(QM31 c) {
    if (c.c0.b != 0 || c.c1 != CM31.zero) throw ArgumentError('not a base-field constant');
    return c.c0.a;
  }
  @override
  int add(int a, int b) => M31.add(a, b);
  @override
  int sub(int a, int b) => M31.sub(a, b);
  @override
  int mul(int a, int b) => M31.mul(a, b);
  @override
  int scale(int a, int m) => M31.mul(a, m);
}

/// The program: one value per row for each preprocessed column. Selector
/// columns are 0/1; tags, multiplicities and immediates are M31 values.
class VerifierProgramColumns {
  static const names = [
    'rowid',
    // bus: producer P1 (kinds), P2 (B as K4), consumers A (kinds) and B
    'p1vm', 'p1a4', 'p1ab8', 'p1a1', 'p1swap', 'mult1', 'p2en', 'mult2', 'ak4', 'ak8', 'ak1', 'tagA', 'ben', 'tagB',
    // hash side
    'chain', 'zeroLo', 'z8', 'zTail', 'inHiAB', 'inLoAB', 'inHiNext', 'digAB', 'assertZero', 'pinPub',
    // VM
    'opAdd', 'opSub', 'opMul', 'opMulImm', 'opConst', 'opLimb', 'imm0', 'imm1', 'imm2', 'imm3',
  ];
  static final int count = names.length;
  static int _i(String n) => names.indexOf(n);
  static final int rowid = _i('rowid');
  static final int p1vm = _i('p1vm'), p1a4 = _i('p1a4'), p1ab8 = _i('p1ab8'), p1a1 = _i('p1a1'), p1swap = _i('p1swap');
  static final int mult1 = _i('mult1'), p2en = _i('p2en'), mult2 = _i('mult2');
  static final int ak4 = _i('ak4'), ak8 = _i('ak8'), ak1 = _i('ak1'), tagA = _i('tagA'), ben = _i('ben'), tagB = _i('tagB');
  static final int chain = _i('chain'), zeroLo = _i('zeroLo'), z8 = _i('z8'), zTail = _i('zTail');
  static final int inHiAB = _i('inHiAB'), inLoAB = _i('inLoAB'), inHiNext = _i('inHiNext'), digAB = _i('digAB');
  static final int assertZero = _i('assertZero'), pinPub = _i('pinPub');
  static final int opAdd = _i('opAdd'), opSub = _i('opSub'), opMul = _i('opMul'), opMulImm = _i('opMulImm');
  static final int opConst = _i('opConst'), opLimb = _i('opLimb'), imm0 = _i('imm0');

  final int rows;
  final List<Uint32List> columns;
  VerifierProgramColumns(this.rows) : columns = List.generate(count, (_) => Uint32List(rows)) {
    for (int r = 0; r < rows; r++) {
      columns[rowid][r] = r;
    }
  }

  void set(int col, int row, int value) {
    if (value < 0 || value >= M31.p) throw ArgumentError('program value out of range');
    columns[col][row] = value;
  }

  int get(int col, int row) => columns[col][row];
}
