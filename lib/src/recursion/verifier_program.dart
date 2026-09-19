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
import '../crypto/poseidon2_m31.dart';
import '../crypto/proof_hash.dart';
import '../crypto/stark_prover_ref.dart';
import '../script_gen/air.dart';
import '../script_gen/air_ring.dart';
import '../script_gen/poseidon2_air.dart';
import '../script_gen/poseidon2_chain_air.dart';
import 'verifier_air.dart';

/// The shape of the inner proof a [VerifierProgram] verifies: its parameters
/// and its AIR (whose constraints the program evaluates out of domain).
class InnerShape {
  final StarkParams P;
  final Air air;
  InnerShape(this.P, this.air);
  int get C => air.numCols;
  int get A => air.numAuxCols;
  int get R => air.numPreCols;
  int get CT => air.totalCols;
}

/// A value on the bus: produced once at [row] (tag = row + [tagOffset]),
/// consumed [uses] times. [kind] is 1 (one lane, port A only), 4 (a QM31)
/// or 8 (eight lanes, port A with both operand columns). In witness mode
/// [lanes] is its value.
class Wire {
  final int kind;
  final String label;
  int uses = 0;
  int row = -1;
  int tagOffset = 0;
  List<int> Function()? lanesFn;
  List<int>? _lanes;
  Wire(this.kind, this.label, [this.lanesFn]);
  List<int> get lanes => _lanes ??= lanesFn!();
  QM31 get q {
    final l = lanes;
    return QM31.fromLimbs(l[0], l.length > 1 ? l[1] : 0, l.length > 2 ? l[2] : 0, l.length > 3 ? l[3] : 0);
  }

  int get tag {
    if (row < 0) throw StateError('wire $label has no producer row');
    return row + tagOffset;
  }

  @override
  String toString() => 'Wire($label, k$kind, row $row, uses $uses)';
}

enum _Op { add, sub, mul, mulImm, constant, limb }

/// A row of the VM: f(A, B) produced as a wire, or asserted zero.
class _VmItem {
  final _Op op;
  final Wire? a, b;
  final QM31 imm;
  final Wire? out;
  final bool assertZero;
  int row = -1;
  _VmItem(this.op, this.a, this.b, this.imm, this.out, this.assertZero);
}

/// A hint row: the prover writes the wire's lanes into A (and B).
class _HintItem {
  final Wire wire;
  int row = -1;
  _HintItem(this.wire);
}

/// One 32-row period of the hash chain.
class _Period {
  final int index;
  bool fresh = false;
  bool loZero = false;
  Wire? loWire8; // fresh: lanes 0..7 pinned to a K8 wire (consumed)
  Wire? hiA, hiB; // lanes 8..11 / 12..15 pinned to K4 wires (consumed)
  Wire? hiWire8; // lanes 8..15 pinned to a K8 wire (consumed)
  bool hiZero = false;
  bool hiNonce = false; // lanes 9..15 zero, lane 8 free
  List<int> Function()? loFree, hiFree; // free witness halves
  Wire? prodHiA, prodHiB; // lanes 8..11 / 12..15 produced as K4 wires (from hiFree)
  // row 31
  int Function()? swapBitFn; // the next period's swap bit (witness)
  Wire? swapWire; // lane 8 of row 31 produced as K1
  Wire? digProd8, digProd4, digProd1, digCons8;
  bool pinPub = false;
  List<int>? _input, _digest;
  int? _swapBitValue;
  _Period(this.index);
  bool get row0Claimed => loWire8 != null || hiA != null || hiWire8 != null || prodHiA != null;
  bool get row31Claimed => digProd8 != null || digProd4 != null || digProd1 != null || digCons8 != null;
}

/// Field arithmetic that emits VM rows; values are [Wire]s.
class _WireRing extends Ring<Wire> {
  final VerifierProgramBuilder b;
  final Map<QM31, Wire> _consts = {};
  _WireRing(this.b);
  @override
  Wire get zero => constQ(QM31.zero);
  @override
  Wire get one => constQ(QM31.one);
  @override
  Wire constM31(int m) => constQ(QM31.fromLimbs(m, 0, 0, 0));
  @override
  Wire constQ(QM31 c) => _consts.putIfAbsent(c, () => b._vm(_Op.constant, null, null, c, 'const'));
  @override
  Wire add(Wire x, Wire y) => b._vm(_Op.add, x, y, QM31.zero, 'add');
  @override
  Wire sub(Wire x, Wire y) => b._vm(_Op.sub, x, y, QM31.zero, 'sub');
  @override
  Wire mul(Wire x, Wire y) => x.kind == 4 && y.kind == 1 ? b._vm(_Op.mul, y, x, QM31.zero, 'mul') : b._vm(_Op.mul, x, y, QM31.zero, 'mul');
  @override
  Wire scale(Wire x, int m) => m == 1 ? x : b._vm(_Op.mulImm, x, null, QM31.fromLimbs(m, 0, 0, 0), 'scale');
  Wire mulQ(Wire x, QM31 c) => b._vm(_Op.mulImm, x, null, c, 'mulq');
  Wire limb(Wire x, int k) =>
      b._vm(_Op.limb, x, null, QM31.fromLimbs(k == 0 ? 1 : 0, k == 1 ? 1 : 0, k == 2 ? 1 : 0, k == 3 ? 1 : 0), 'limb$k');
}

/// The compiled program for one inner shape: the preprocessed columns of
/// [VerifierAir] and, given an inner proof, the witness trace.
class VerifierProgram {
  final InnerShape shape;
  final int logTrace;
  final VerifierProgramColumns columns;
  final int periodsUsed, vmRows, hintRows;
  VerifierProgram(this.shape, this.logTrace, this.columns, this.periodsUsed, this.vmRows, this.hintRows);

  /// Compile for [shape] on a 2^[logTrace]-row trace.
  static VerifierProgram compile(InnerShape shape, int logTrace) {
    final b = VerifierProgramBuilder(shape, logTrace, null);
    b.build();
    return VerifierProgram(shape, logTrace, b.columns, b.periods.length, b.vmItems.length, b.hintItems.length);
  }

  /// The verifier AIR for this program, verifying a proof whose statement
  /// digest is [publics].
  VerifierAir air(List<int> publics) => VerifierAir(logTrace, columns, publics);

  /// The trace rows (main columns) proving that [proof] verifies. The
  /// program columns are recomputed and must match [columns].
  List<List<int>> witness(StarkProof proof) {
    final b = VerifierProgramBuilder(shape, logTrace, proof);
    b.build();
    for (int c = 0; c < VerifierProgramColumns.count; c++) {
      for (int r = 0; r < columns.rows; r++) {
        if (b.columns.columns[c][r] != columns.columns[c][r]) {
          throw StateError('witness program differs at column ${VerifierProgramColumns.names[c]} row $r');
        }
      }
    }
    return b.rows();
  }

  /// The statement digest of an inner proof: the inner transcript state
  /// after the statement absorption.
  static List<int> statementDigest(Air air, List<int> preRoot) {
    final ts = Poseidon2Transcript();
    ts.absorbStatement(air.publicValues, preRoot);
    return ts.state;
  }
}

/// Lays out the verification of one inner proof as periods, VM rows and
/// hint rows, assigns rows, and fills the program columns; with a proof it
/// also computes every cell. The verification follows `StarkVerifierRef`
/// check for check.
class VerifierProgramBuilder {
  final InnerShape shape;
  final int logTrace;
  final StarkProof? proof;
  final VerifierProgramColumns columns;
  final periods = <_Period>[];
  final vmItems = <_VmItem>[];
  final hintItems = <_HintItem>[];
  late final _WireRing f = _WireRing(this);
  _Period? _cur; // the transcript's current period (its digest is the state)

  VerifierProgramBuilder(this.shape, this.logTrace, this.proof) : columns = VerifierProgramColumns(1 << logTrace);

  bool get witnessMode => proof != null;
  StarkProof get pf => proof!;
  int get numPeriods => 1 << (logTrace - 5);

  // ---------------------------------------------------------------- wires and VM

  Wire _vm(_Op op, Wire? a, Wire? b, QM31 imm, String label) {
    if (b != null && b.kind != 4) throw StateError('port B takes K4 wires only ($label, ${b.label})');
    if (a != null && a.kind == 8) throw StateError('the VM takes K1 or K4 operands ($label)');
    final out = Wire(4, label);
    a?.uses++;
    b?.uses++;
    vmItems.add(_VmItem(op, a, b, imm, out, false));
    if (witnessMode) {
      out.lanesFn = () {
        final r = switch (op) {
          _Op.add => a!.q + b!.q,
          _Op.sub => a!.q - b!.q,
          _Op.mul => a!.q * b!.q,
          _Op.mulImm => a!.q * imm,
          _Op.constant => imm,
          _Op.limb => QM31.fromLimbs(a!.lanes[imm.c0.a == 1 ? 0 : imm.c0.b == 1 ? 1 : imm.c1.a == 1 ? 2 : 3], 0, 0, 0),
        };
        return r.limbs;
      };
    }
    return out;
  }

  void assertZero(Wire w) => assertEq(w, f.zero);

  void assertEq(Wire a, Wire b) {
    if (b.kind != 4) throw StateError('assertEq needs a K4 right-hand side');
    a.uses++;
    b.uses++;
    vmItems.add(_VmItem(_Op.sub, a, b, QM31.zero, null, true));
  }

  Wire hint4(String label, QM31 Function() v) => _hint(Wire(4, label, () => v().limbs));
  Wire hint8(String label, List<int> Function() v) => _hint(Wire(8, label, v));
  Wire hint1(String label, int Function() v) => _hint(Wire(1, label, () => [v()]));
  Wire _hint(Wire w) {
    hintItems.add(_HintItem(w));
    return w;
  }

  /// A boolean hint (as a K4 wire) with its booleanity asserted.
  Wire bitHint(String label, int Function() v) {
    final w = hint4(label, () => QM31.fromLimbs(v(), 0, 0, 0));
    assertZero(f.sub(f.mul(w, w), w));
    return w;
  }

  /// Σ 2^k b_k from bit wires (K1 or K4).
  Wire _fromBits(List<Wire> bits, {int shift = 0}) {
    Wire? acc;
    for (int k = 0; k < bits.length; k++) {
      final term = f.scale(bits[k], 1 << (k + shift));
      acc = acc == null ? term : f.add(acc, term);
    }
    return acc ?? f.zero;
  }

  // ---------------------------------------------------------------- periods

  _Period _period() {
    final p = _Period(periods.length);
    periods.add(p);
    return p;
  }

  /// A transcript step: chained from the current state, with the given
  /// high half; the new period becomes the state.
  _Period _absorb({Wire? a, Wire? b, Wire? w8, bool zero = false, bool nonce = false, List<int> Function()? free}) {
    final p = _period();
    final cur = _cur;
    if (cur == null) throw StateError('no transcript state');
    if (cur.index != p.index - 1) {
      // the state is not the previous period: restart from its digest
      final s = cur.digProd8 ??= Wire(8, 'state${cur.index}', () => cur._digest!);
      p.fresh = true;
      p.loWire8 = s;
      s.uses++;
    }
    if (a != null) {
      p.hiA = a;
      p.hiB = b;
      a.uses++;
      b!.uses++;
    } else if (w8 != null) {
      p.hiWire8 = w8;
      w8.uses++;
    } else if (zero) {
      p.hiZero = true;
    } else if (nonce) {
      p.hiNonce = true;
      p.hiFree = free;
    } else {
      p.hiFree = free;
    }
    return p;
  }

  Wire squeeze4(String label) {
    final p = _absorb(zero: true);
    _cur = p;
    final w = Wire(4, label, () => p._digest!.sublist(0, 4));
    p.digProd4 = w;
    return w;
  }

  Wire squeeze1(String label) {
    final p = _absorb(zero: true);
    _cur = p;
    final w = Wire(1, label, () => [p._digest![0]]);
    p.digProd1 = w;
    return w;
  }

  /// A leaf chain: chunks of 8 lanes hashed from h = 0. Returns the last period.
  _Period _leaf(List<Wire> chunks4) {
    _Period? p;
    for (int c = 0; c < chunks4.length; c += 2) {
      final a = chunks4[c], b = chunks4[c + 1];
      final n = _period();
      if (p == null) {
        n.fresh = true;
        n.loZero = true;
      } else {
        p.swapBitFn = () => 0;
      }
      n.hiA = a;
      n.hiB = b;
      a.uses++;
      b.uses++;
      p = n;
    }
    return p!;
  }

  /// A Merkle walk of [depth] chained periods from the leaf period; the
  /// swap bits are the low bits of the index lane (bound in the VM with a
  /// range-checked remainder), the root is checked at the end. Returns the
  /// bit wires.
  List<Wire> _walk(_Period leaf, Wire idx, int depth, Wire root, List<List<int>> Function() siblings) {
    var p = leaf;
    final bits = <Wire>[];
    for (int k = 0; k < depth; k++) {
      final sib = k;
      p.swapBitFn = () => (idx.lanes[0] >> sib) & 1;
      final w = Wire(1, 'bit$k', () => [(idx.lanes[0] >> sib) & 1]);
      p.swapWire = w;
      bits.add(w);
      final n = _period();
      n.loFree = () => siblings()[sib];
      n.hiFree = () => siblings()[sib];
      p = n;
    }
    p.digCons8 = root;
    root.uses++;
    // idx = Σ 2^k b_k + 2^depth rem, rem < 2^(31 - depth) by bit decomposition
    final remBits = [for (int j = 0; j < 31 - depth; j++) bitHint('rem$j', () => (idx.lanes[0] >> (depth + j)) & 1)];
    assertEq(idx, f.add(_fromBits(bits), _fromBits(remBits, shift: depth)));
    return bits;
  }

  // ---------------------------------------------------------------- the verification

  void build() {
    final P = shape.P, air = shape.air;
    final A = shape.A, R = shape.R, CT = shape.CT;
    final a = P.logCompHalf;
    final gT = CirclePoint.subgroupGen(P.logTrace);

    // ---- statement: publics padded to 64 lanes, then the preprocessed root (or zeros) ----
    final pubWires = <Wire>[];
    final pubs = air.publicValues;
    for (int c = 0; c < Poseidon2Transcript.statementPeriods; c++) {
      final p = _period();
      if (c == 0) {
        p.fresh = true;
        p.loZero = true;
      } else {
        periods[c - 1].swapBitFn = () => 0;
      }
      if (c < 8) {
        p.hiFree = () => [for (int j = 0; j < 8; j++) 8 * c + j < pubs.length ? pubs[8 * c + j] : 0];
        final wa = Wire(4, 'pub${2 * c}', () => p._input!.sublist(8, 12));
        final wb = Wire(4, 'pub${2 * c + 1}', () => p._input!.sublist(12, 16));
        wb.tagOffset = VerifierAir.tagP2Offset;
        p.prodHiA = wa;
        p.prodHiB = wb;
        pubWires.addAll([wa, wb]);
      } else {
        p.hiFree = () => R > 0 ? pf.preRoot : Poseidon2Transcript.zeros;
        p.pinPub = true;
      }
      _cur = p;
    }
    final pubLane = [for (int k = 0; k < pubs.length; k++) f.limb(pubWires[k ~/ 4], k % 4)];

    // ---- transcript: roots and challenges ----
    final traceRoot = hint8('traceRoot', () => pf.traceRoot);
    _cur = _absorb(w8: traceRoot);
    final chal = [for (int k = 0; k < air.numChallenges; k++) squeeze4('chal$k')];
    Wire? auxRoot;
    if (A > 0) {
      auxRoot = hint8('auxRoot', () => pf.auxRoot);
      _cur = _absorb(w8: auxRoot);
    }
    final beta = squeeze4('beta');
    final compRoot = hint8('compRoot', () => pf.compRoot);
    _cur = _absorb(w8: compRoot);
    final tch = squeeze4('tch');
    final zHint = hint4('zHint', () => pf.zHint);
    final t2 = f.mul(tch, tch);
    assertEq(f.mul(f.add(f.one, t2), zHint), f.one);
    final zx = f.mul(f.sub(f.one, t2), zHint), zy = f.mul(f.add(tch, tch), zHint);
    final traceAtZ = [for (int j = 0; j < CT; j++) hint4('tz$j', () => pf.traceAtZ[j])];
    final traceAtZg = [for (int j = 0; j < CT; j++) hint4('tzg$j', () => pf.traceAtZg[j])];
    final compAtZ = [for (int k = 0; k < 4; k++) hint4('cz$k', () => pf.compAtZ[k])];
    final oods = [...traceAtZ, ...traceAtZg, ...compAtZ];
    for (int i = 0; i < oods.length; i += 2) {
      _cur = _absorb(a: oods[i], b: i + 1 < oods.length ? oods[i + 1] : f.zero);
    }
    final lamA = squeeze4('lamA'), lamB = squeeze4('lamB'), lamC = squeeze4('lamC'), alC = squeeze4('alC');

    // ---- out-of-domain check of the inner AIR ----
    _withPublics(air, pubLane, () {
      assertZero(air.oodCheckG(f, traceAtZ, traceAtZg, compAtZ, beta, zx, zy, chal: chal));
    });

    // ---- z*g and the DEEP constants ----
    final zgx = f.sub(f.scale(zx, gT.x), f.scale(zy, gT.y));
    final zgy = f.add(f.scale(zx, gT.y), f.scale(zy, gT.x));
    final kA = _deepPrecompute(zx, zy, compAtZ, lamA);
    final kB = _deepPrecompute(zx, zy, traceAtZ, lamB);
    final kC = _deepPrecompute(zgx, zgy, traceAtZg, lamC);

    // ---- FRI roots and alphas, final coefficients, grinding, indices ----
    final friRoots = <Wire>[], alphas = <Wire>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      final w = hint8('fr$l', () => pf.friRoots[l]);
      friRoots.add(w);
      _cur = _absorb(w8: w);
      alphas.add(squeeze4('al$l'));
    }
    final finalCoefs = [for (int i = 0; i < P.finalDegree; i++) hint4('fc$i', () => pf.finalCoefs[i])];
    for (int i = 0; i < finalCoefs.length; i += 2) {
      _cur = _absorb(a: finalCoefs[i], b: i + 1 < finalCoefs.length ? finalCoefs[i + 1] : f.zero);
    }
    final stateBeforeGrind = _cur!;
    final grind = _absorb(nonce: true, free: () => [pf.nonce[0], 0, 0, 0, 0, 0, 0, 0]);
    final grindLane = Wire(1, 'grind', () => [grind._digest![0]]);
    grind.digProd1 = grindLane;
    {
      // lane 0 = Σ_{k >= G} 2^k g_k with boolean g_k: the low G bits are zero
      final G = Poseidon2Transcript.grindBits(P.grindBytes);
      final gBits = [for (int k = G; k < 31; k++) bitHint('g$k', () => (grindLane.lanes[0] >> k) & 1)];
      assertEq(grindLane, _fromBits(gBits, shift: G));
    }
    _cur = stateBeforeGrind;
    final indices = [for (int q = 0; q < P.numQueries; q++) squeeze1('idx$q')];

    // ---- queries ----
    final hA = HalfCoset(a);
    final stepPow = <CirclePoint>[];
    {
      var g = hA.step;
      for (int k = 0; k < a; k++) {
        stepPow.add(g);
        g = g.double_();
      }
    }
    for (int q = 0; q < P.numQueries; q++) {
      final idx = indices[q];
      QueryProof qp() => pf.queries[q];
      // composition opening and walk
      final cl0 = hint4('cl${q}a', () => _q4(qp().compLeaf, 0)), cl1 = hint4('cl${q}b', () => _q4(qp().compLeaf, 4));
      final leaf = _leaf([cl0, cl1]);
      final bits = _walk(leaf, idx, a, compRoot, () => qp().compPath);
      // the query point from its bits: acc = initial * Π step^(2^k b_k)
      var px = f.constM31(hA.initial.x), py = f.constM31(hA.initial.y);
      for (int k = 0; k < a; k++) {
        final g = stepPow[k];
        final nx = f.sub(f.scale(px, g.x), f.scale(py, g.y));
        final ny = f.add(f.scale(px, g.y), f.scale(py, g.x));
        px = f.add(px, f.mul(bits[k], f.sub(nx, px)));
        py = f.add(py, f.mul(bits[k], f.sub(ny, py)));
      }
      var xB = px, yB = py;
      for (int k = 0; k < a - P.logTraceHalf; k++) {
        final x2 = f.mul(xB, xB);
        final nx = f.sub(f.add(x2, x2), f.one);
        final xy = f.mul(xB, yB);
        yB = f.add(xy, xy);
        xB = nx;
      }
      // DEEP group A at p and conj p, then the circle fold
      final dAp = hint4('dap$q', () => qp().dAInvP), dAc = hint4('dac$q', () => qp().dAInvC);
      final qAp = _quotient(kA, px, py, [for (int k = 0; k < 4; k++) f.limb(cl0, k)], dAp);
      final qAc = _quotient(kA, px, f.neg(py), [for (int k = 0; k < 4; k++) f.limb(cl1, k)], dAc);
      final yAi = hint1('yai$q', () => qp().yAInv);
      assertEq(f.mul(yAi, py), f.one);
      var out = _fold(qAp, qAc, yAi, alC);
      var top = bits[a - 1];
      var xA = f.add(px, f.mul(top, f.neg(f.add(px, px)))); // -x when the top bit is set
      // FRI layers
      for (int l = 0; l < P.numLineFolds; l++) {
        final d = a - 1 - l;
        final lf = hint4('lf${q}_$l', () => qp().lineF0[l]), lg = hint4('lg${q}_$l', () => qp().lineF1[l]);
        // the previous output is the component of this layer's pair the top bit selects
        assertEq(out, f.add(lf, f.mul(top, f.sub(lg, lf))));
        Wire? outT;
        if (l == P.foldInIndex) outT = _foldIn(q, idx, traceRoot, auxRoot, kB, kC, xB, yB, alphas[l]);
        final lLeaf = _leaf([lf, lg]);
        final lbits = _walk(lLeaf, idx, d, friRoots[l], () => qp().linePaths[l]);
        final xi = hint1('lxi${q}_$l', () => qp().lineXInv[l]);
        assertEq(f.mul(xi, xA), f.one);
        var next = _fold(lf, lg, xi, alphas[l]);
        if (outT != null) next = f.add(next, outT);
        final x2 = f.mul(xA, xA);
        final dbl = f.sub(f.add(x2, x2), f.one);
        if (l < P.numLineFolds - 1) {
          top = lbits[d - 1];
          xA = f.add(dbl, f.mul(top, f.neg(f.add(dbl, dbl))));
          out = next;
        } else {
          assertEq(f.horner(finalCoefs, dbl), next);
        }
      }
    }
    _finish();
  }

  static QM31 _q4(List<int> l, int from) => QM31.fromLimbs(l[from], l[from + 1], l[from + 2], l[from + 3]);

  void _withPublics(Air air, List<Wire> pubLane, void Function() body) {
    if (air is Poseidon2ChainAir) air.publicsOverride = pubLane;
    if (air is VerifierAir) air.publicsOverride = pubLane;
    try {
      body();
    } finally {
      if (air is Poseidon2ChainAir) air.publicsOverride = null;
      if (air is VerifierAir) air.publicsOverride = null;
    }
  }

  Wire _foldIn(int q, Wire idx, Wire traceRoot, Wire? auxRoot, DeepWires kB, DeepWires kC, Wire xB, Wire yB, Wire alpha) {
    final C = shape.C, A = shape.A, R = shape.R;
    QueryProof qp() => pf.queries[q];
    List<Wire> chunks(String tag, int lanes, List<int> Function() src) {
      final n = (lanes + 3) ~/ 4;
      final out = <Wire>[];
      for (int c = 0; c < n; c++) {
        final k = c;
        out.add(hint4('$tag${q}_$c', () {
          final s = src();
          int at(int i) => i < s.length ? s[i] : 0;
          return QM31.fromLimbs(at(4 * k), at(4 * k + 1), at(4 * k + 2), at(4 * k + 3));
        }));
      }
      if (out.length.isOdd) out.add(f.zero);
      return out;
    }

    final tl = chunks('tl', 2 * C, () => qp().traceLeaf);
    _walk(_leaf(tl), idx, shape.P.logTraceHalf, traceRoot, () => qp().tracePath);
    List<Wire> al = const [], pl = const [];
    if (A > 0) {
      al = chunks('axl', 2 * A, () => qp().auxLeaf);
      _walk(_leaf(al), idx, shape.P.logTraceHalf, auxRoot!, () => qp().auxPath);
    }
    if (R > 0) {
      final preRoot = hint8('preRoot', () => pf.preRoot);
      pl = chunks('prl', 2 * R, () => qp().preLeaf);
      _walk(_leaf(pl), idx, shape.P.logTraceHalf, preRoot, () => qp().prePath);
    }
    List<Wire> lanesOf(List<Wire> ch, int from, int count) =>
        [for (int j = 0; j < count; j++) f.limb(ch[(from + j) ~/ 4], (from + j) % 4)];
    final atP = [...lanesOf(tl, 0, C), ...lanesOf(al, 0, A), ...lanesOf(pl, 0, R)];
    final atC = [...lanesOf(tl, C, C), ...lanesOf(al, A, A), ...lanesOf(pl, R, R)];
    final dBp = hint4('dbp$q', () => qp().dBInvP), dBc = hint4('dbc$q', () => qp().dBInvC);
    final dCp = hint4('dcp$q', () => qp().dCInvP), dCc = hint4('dcc$q', () => qp().dCInvC);
    final qTp = f.add(_quotient(kB, xB, yB, atP, dBp), _quotient(kC, xB, yB, atP, dCp));
    final nyB = f.neg(yB);
    final qTc = f.add(_quotient(kB, xB, nyB, atC, dBc), _quotient(kC, xB, nyB, atC, dCc));
    final yBi = hint1('ybi$q', () => qp().yBInv);
    assertEq(f.mul(yBi, yB), f.one);
    return _fold(qTp, qTc, yBi, alpha);
  }

  Wire _fold(Wire f0, Wire f1, Wire twInv, Wire alpha) => f.add(f.add(f0, f1), f.mul(alpha, f.mul(twInv, f.sub(f0, f1))));

  Wire _conj(Wire v) {
    // conj(v) = v - 2 (l2 u + l3 iu)
    final l2 = f.limb(v, 2), l3 = f.limb(v, 3);
    final t = f.add(f.mulQ(l2, QM31.u), f.mulQ(l3, QM31.i * QM31.u));
    return f.sub(v, f.add(t, t));
  }

  DeepWires _deepPrecompute(Wire zx, Wire zy, List<Wire> values, Wire alpha) {
    final zyc = _conj(zy), zxc = _conj(zx);
    final c = f.sub(zyc, zy);
    final dA = f.sub(zy, zyc);
    final dB = f.sub(zxc, zx);
    final dC = f.sub(f.mul(zx, zyc), f.mul(zy, zxc));
    var w = f.one;
    Wire? aAcc, bAcc;
    final weights = <Wire>[];
    for (final v in values) {
      weights.add(w);
      final av = f.sub(_conj(v), v);
      final bv = f.sub(f.mul(c, v), f.mul(av, zy));
      final wa = f.mul(w, av), wb = f.mul(w, bv);
      aAcc = aAcc == null ? wa : f.add(aAcc, wa);
      bAcc = bAcc == null ? wb : f.add(bAcc, wb);
      w = f.mul(w, alpha);
    }
    return DeepWires(c, aAcc!, bAcc!, dA, dB, dC, weights);
  }

  /// q = (c Σ w_j f_j - y A - B) dInv with dInv checked against dA x + dB y + dC.
  Wire _quotient(DeepWires k, Wire px, Wire py, List<Wire> openings, Wire dInv) {
    final den = f.add(f.add(f.mul(k.dA, px), f.mul(k.dB, py)), k.dC);
    assertEq(f.mul(den, dInv), f.one);
    Wire? s;
    for (int j = 0; j < openings.length; j++) {
      final term = f.mul(k.weights[j], openings[j]);
      s = s == null ? term : f.add(s, term);
    }
    final num = f.sub(f.sub(f.mul(k.c, s!), f.mul(k.A, py)), k.B);
    return f.mul(num, dInv);
  }

  // ---------------------------------------------------------------- finishing: rows, program, witness

  final Map<int, bool> _claimed = {};
  final List<(int, Wire, bool)> _consumers = [];
  final List<(int, Wire, int)> _producers = [];
  List<List<int>>? _rowsOut;

  void _finish() {
    if (periods.length > numPeriods) {
      throw StateError('program needs ${periods.length} periods, trace holds $numPeriods (raise logTrace)');
    }
    final n = 1 << logTrace;
    for (final p in periods) {
      final r0 = p.index << 5;
      if (p.row0Claimed) _claimed[r0] = true;
      if (p.row31Claimed || p.swapWire != null) _claimed[r0 + 31] = true;
    }
    for (final p in periods) {
      final r0 = p.index << 5, r31 = r0 + 31;
      if (p.fresh) {
        if (p.loZero) columns.set(VerifierProgramColumns.zeroLo, r0, 1);
        if (p.loWire8 != null) {
          columns.set(VerifierProgramColumns.inLoAB, r0, 1);
          _consumeAt(r0, p.loWire8!);
        }
      } else {
        columns.set(VerifierProgramColumns.chain, r0 - 1, 1);
      }
      if (p.hiZero) {
        columns.set(VerifierProgramColumns.z8, r0, 1);
        columns.set(VerifierProgramColumns.zTail, r0, 1);
      }
      if (p.hiNonce) columns.set(VerifierProgramColumns.zTail, r0, 1);
      if (p.hiA != null) {
        columns.set(VerifierProgramColumns.inHiAB, r0, 1);
        _consumeAt(r0, p.hiA!, portB: p.hiB!);
      }
      if (p.hiWire8 != null) {
        columns.set(VerifierProgramColumns.inHiAB, r0, 1);
        _consumeAt(r0, p.hiWire8!);
      }
      if (p.prodHiA != null) {
        columns.set(VerifierProgramColumns.inHiAB, r0, 1);
        if (p.prodHiA!.uses > 0) _produceAt(r0, p.prodHiA!, VerifierProgramColumns.p1a4);
        if (p.prodHiB!.uses > 0) _produceAt(r0, p.prodHiB!, VerifierProgramColumns.p2en);
        _pinned.add((r0, p.prodHiA!, p.prodHiB!));
      }
      if (p.swapWire != null && p.swapWire!.uses > 0) _produceAt(r31, p.swapWire!, VerifierProgramColumns.p1swap);
      if (p.row31Claimed) columns.set(VerifierProgramColumns.digAB, r31, 1);
      var prods = 0;
      if (p.digProd8 != null) {
        _produceAt(r31, p.digProd8!, VerifierProgramColumns.p1ab8);
        prods++;
      }
      if (p.digProd4 != null) {
        _produceAt(r31, p.digProd4!, VerifierProgramColumns.p1a4);
        prods++;
      }
      if (p.digProd1 != null) {
        _produceAt(r31, p.digProd1!, VerifierProgramColumns.p1a1);
        prods++;
      }
      if (prods + (p.swapWire != null && p.swapWire!.uses > 0 ? 1 : 0) > 1) throw StateError('two producers at row $r31');
      if (p.digCons8 != null) _consumeAt(r31, p.digCons8!);
      if (p.pinPub) columns.set(VerifierProgramColumns.pinPub, r31, 1);
    }
    // VM and hint rows into the free rows
    var free = 0;
    int nextFree() {
      while (free < n && (_claimed[free] == true || (free & 31) == 0 || (free & 31) == 31)) {
        free++;
      }
      if (free >= n) throw StateError('out of rows for VM and hints (raise logTrace)');
      return free++;
    }

    for (final h in hintItems) {
      if (h.wire.uses == 0) continue;
      h.row = nextFree();
      _produceAt(h.row, h.wire,
          switch (h.wire.kind) { 1 => VerifierProgramColumns.p1a1, 4 => VerifierProgramColumns.p1a4, _ => VerifierProgramColumns.p1ab8 });
    }
    for (final v in vmItems) {
      if (!v.assertZero && v.out!.uses == 0) {
        v.a?.uses--;
        v.b?.uses--;
        continue;
      }
      v.row = nextFree();
      columns.set(
          switch (v.op) {
            _Op.add => VerifierProgramColumns.opAdd,
            _Op.sub => VerifierProgramColumns.opSub,
            _Op.mul => VerifierProgramColumns.opMul,
            _Op.mulImm => VerifierProgramColumns.opMulImm,
            _Op.constant => VerifierProgramColumns.opConst,
            _Op.limb => VerifierProgramColumns.opLimb,
          },
          v.row,
          1);
      final l = v.imm.limbs;
      for (int k = 0; k < 4; k++) {
        columns.set(VerifierProgramColumns.imm0 + k, v.row, l[k]);
      }
      if (v.a != null) _consumeAt(v.row, v.a!, portB: v.b);
      if (v.assertZero) {
        columns.set(VerifierProgramColumns.assertZero, v.row, 1);
      } else {
        _produceAt(v.row, v.out!, VerifierProgramColumns.p1vm);
      }
    }
    for (final (row, w, isB) in _consumers) {
      columns.set(isB ? VerifierProgramColumns.tagB : VerifierProgramColumns.tagA, row, w.tag);
    }
    for (final (row, w, col) in _producers) {
      columns.set(col == VerifierProgramColumns.p2en ? VerifierProgramColumns.mult2 : VerifierProgramColumns.mult1, row, w.uses);
    }
    if (witnessMode) _fillRows();
  }

  final List<(int, Wire, Wire)> _pinned = [];

  void _consumeAt(int row, Wire w, {Wire? portB}) {
    columns.set(switch (w.kind) { 1 => VerifierProgramColumns.ak1, 4 => VerifierProgramColumns.ak4, _ => VerifierProgramColumns.ak8 }, row, 1);
    _consumers.add((row, w, false));
    if (portB != null) {
      columns.set(VerifierProgramColumns.ben, row, 1);
      _consumers.add((row, portB, true));
    }
  }

  void _produceAt(int row, Wire w, int kindCol) {
    if (w.row >= 0) throw StateError('wire ${w.label} produced twice');
    w.row = row;
    columns.set(kindCol, row, 1);
    _producers.add((row, w, kindCol));
  }

  // ---------------------------------------------------------------- witness

  List<List<int>> rows() => _rowsOut!;

  List<int> _simulate(_Period p) {
    if (p._digest != null) return p._digest!;
    final input = List<int>.filled(16, 0);
    if (p.fresh) {
      if (p.loWire8 != null) input.setRange(0, 8, p.loWire8!.lanes);
      if (p.loFree != null) input.setRange(0, 8, p.loFree!());
      if (p.hiFree != null) input.setRange(8, 16, p.hiFree!());
    } else {
      final prev = periods[p.index - 1];
      final dig = _simulate(prev);
      final b = prev._swapBitValue ??= prev.swapBitFn?.call() ?? 0;
      if (b == 1) {
        input.setRange(8, 16, dig);
        if (p.loFree != null) input.setRange(0, 8, p.loFree!());
      } else {
        input.setRange(0, 8, dig);
        if (p.hiFree != null) input.setRange(8, 16, p.hiFree!());
      }
    }
    if (p.hiA != null) {
      input.setRange(8, 12, p.hiA!.lanes);
      input.setRange(12, 16, p.hiB!.lanes);
    }
    if (p.hiWire8 != null) input.setRange(8, 16, p.hiWire8!.lanes);
    p._input = input;
    p._digest = Poseidon2M31.permute(input).sublist(0, 8);
    return p._digest!;
  }

  void _fillRows() {
    final n = 1 << logTrace;
    final rows = List<List<int>>.generate(n, (_) => List<int>.filled(VerifierAir.numMainCols, 0));
    for (final p in periods) {
      _simulate(p);
      final r0 = p.index << 5;
      var s = p._input!;
      for (int r = 0; r < 24; r++) {
        rows[r0 + r].setRange(0, 16, s);
        s = Poseidon2Air.step(s, r);
      }
      for (int r = 24; r < 32; r++) {
        rows[r0 + r].setRange(0, 8, p._digest!);
      }
      if (p.index + 1 < periods.length && !periods[p.index + 1].fresh) {
        rows[r0 + 31][8] = p._swapBitValue ??= p.swapBitFn?.call() ?? 0;
      }
    }
    // padding periods: honest permutations of the zero state (no program rows)
    for (int pi = periods.length; pi < numPeriods; pi++) {
      final r0 = pi << 5;
      var s = List<int>.filled(16, 0);
      for (int r = 0; r < 24; r++) {
        rows[r0 + r].setRange(0, 16, s);
        s = Poseidon2Air.step(s, r);
      }
      for (int r = 24; r < 32; r++) {
        rows[r0 + r].setRange(0, 8, s.sublist(0, 8));
      }
    }
    void putA(int r, List<int> l) => rows[r].setRange(VerifierAir.colA, VerifierAir.colA + 4, _pad4(l));
    void putB(int r, List<int> l) => rows[r].setRange(VerifierAir.colB, VerifierAir.colB + 4, _pad4(l));
    for (final (r, w, isB) in _consumers) {
      final l = w.lanes;
      if (isB) {
        putB(r, l);
      } else if (w.kind == 8) {
        putA(r, l.sublist(0, 4));
        putB(r, l.sublist(4, 8));
      } else {
        putA(r, l);
      }
    }
    for (final (r, w, col) in _producers) {
      if (col == VerifierProgramColumns.p1vm || col == VerifierProgramColumns.p1swap) continue;
      final l = w.lanes;
      if (col == VerifierProgramColumns.p2en) {
        putB(r, l);
      } else if (w.kind == 8) {
        putA(r, l.sublist(0, 4));
        putB(r, l.sublist(4, 8));
      } else {
        putA(r, l);
      }
    }
    // publics rows pin the lanes to A, B whether or not the wires are used
    for (final (r, wa, wb) in _pinned) {
      putA(r, wa.lanes);
      putB(r, wb.lanes);
    }
    // digest rows that produce a wire pin all eight lanes to A, B
    for (final p in periods) {
      if (p.row31Claimed && p.digCons8 == null) {
        final r31 = (p.index << 5) + 31;
        putA(r31, p._digest!.sublist(0, 4));
        putB(r31, p._digest!.sublist(4, 8));
      }
    }
    _rowsOut = rows;
  }

  static List<int> _pad4(List<int> l) => [for (int k = 0; k < 4; k++) k < l.length ? l[k] : 0];
}

/// The DEEP constants as wires.
class DeepWires {
  final Wire c, A, B, dA, dB, dC;
  final List<Wire> weights;
  DeepWires(this.c, this.A, this.B, this.dA, this.dB, this.dC, this.weights);
}
