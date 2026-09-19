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
import '../crypto/note_commitment_tree.dart';
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
  Wire? hiWire8Next; // lanes 8..15 pinned to a K8 wire consumed at row 1
  bool loSameAsHi = false; // lanes 0..7 pinned to the same operands as 8..15 (an empty node)
  bool hiZero = false;
  bool hiNonce = false; // lanes 9..15 zero, lane 8 free
  List<int> Function()? loFree, hiFree; // free witness halves
  Wire? prodHiA, prodHiB; // lanes 8..11 / 12..15 produced as K4 wires (from hiFree)
  Wire? prodHi8; // lanes 8..15 produced as one K8 wire (from pinned K4 operands)
  bool pinWide = false; // row 0: lanes 8..15 pinned to the public columns
  // row 31
  int Function()? swapBitFn; // the next period's swap bit (witness)
  Wire? swapWire; // lane 8 of row 31 produced as K1
  Wire? digProd8, digProd4, digProd1, digCons8;
  bool pinPub = false;
  List<int>? _input, _digest;
  int? _swapBitValue;
  _Period(this.index);
  bool get row0Claimed =>
      loWire8 != null || hiA != null || hiWire8 != null || hiWire8Next != null || prodHiA != null || prodHi8 != null;
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

/// The aggregation tree a wide root program re-derives the digests of.
/// Level 0 is the spends ([spendPublics] public lanes each, preprocessed
/// root [spendPreRoot], empty for the pool's spend AIR); level l + 1 holds
/// the verifier proofs of shape [levels][l] (with that circuit's
/// preprocessed root), each verifying `arities[l]` proofs of the level below.
/// The root verifies one proof of the last level and takes every spend's
/// publics as its own (wide) statement.
class AggregationTree {
  final int spendPublics;
  final List<int> spendPreRoot;
  final List<(InnerShape, List<int>)> levels;

  /// Proofs verified per node, level by level (level 1 folds spends).
  final List<int> arities;

  /// The chunks of each spend's publics that are commitment-tree leaves,
  /// in leaf order (the pool's cm1, cm2).
  final List<int> leafChunks;
  AggregationTree(this.spendPublics, this.spendPreRoot, this.levels, this.arities, {this.leafChunks = const [3, 4]}) {
    if (levels.isEmpty) throw ArgumentError('at least one aggregation level');
    if (arities.length != levels.length || arities.any((a) => a < 1)) throw ArgumentError('one arity per level');
  }

  /// The same [arity] at every level.
  AggregationTree.uniform(int spendPublics, List<int> spendPreRoot, List<(InnerShape, List<int>)> levels, int arity,
      {List<int> leafChunks = const [3, 4]})
      : this(spendPublics, spendPreRoot, levels, List.filled(levels.length, arity), leafChunks: leafChunks);

  int get depth => levels.length;
  int get transfers => arities.fold(1, (n, a) => n * a);

  /// Pinned chunks per spend: its publics padded to whole chunks.
  int get spendChunks => (spendPublics + 7) ~/ 8;

  // ---- the commitment-tree update the root proves ----
  static const subtreeLeaves = NoteCommitmentTree.subtreeLeaves;
  static const mainDepth = NoteCommitmentTree.mainDepth;
  int get leaves => transfers * leafChunks.length;

  /// Whole subtrees appended per round (the last padded with empty leaves).
  int get subtrees => (leaves + subtreeLeaves - 1) ~/ subtreeLeaves;

  /// Rows appended to the pool's tree per round.
  int get leavesAppended => subtrees * subtreeLeaves;

  /// The round chunks after the transfers': rootBefore, rootAfter,
  /// [index, 0 x 7] with index the first subtree's position.
  static const roundChunks = 3;
  int get roundOffset => 8 * spendChunks * transfers;

  /// The root's wide public inputs: every transfer's publics (padded to
  /// chunks), then the round chunks.
  List<int> widePublics(List<List<int>> spends,
      {required List<int> rootBefore, required List<int> rootAfter, required int index}) {
    if (spends.length != transfers) throw ArgumentError('$transfers transfers expected');
    if (rootBefore.length != 8 || rootAfter.length != 8) throw ArgumentError('8-lane roots');
    if (index < 0 || index + subtrees > 1 << mainDepth) throw ArgumentError('subtree index');
    return [
      for (final p in spends) ...[...p, ...List.filled(8 * spendChunks - p.length, 0)],
      ...rootBefore,
      ...rootAfter,
      index,
      ...List.filled(7, 0),
    ];
  }

  /// The leaves of subtree [s] from the transfers' publics, null = empty.
  List<List<int>?> subtreeLeavesOf(List<List<int>> spends, int s) => [
        for (int i = 0; i < subtreeLeaves; i++)
          () {
            final k = s * subtreeLeaves + i;
            if (k >= leaves) return null;
            final n = k ~/ leafChunks.length, c = leafChunks[k % leafChunks.length];
            return spends[n].sublist(8 * c, 8 * c + 8);
          }()
      ];
}

/// The compiled program for a list of inner shapes: the preprocessed
/// columns of [VerifierAir] and, given the inner proofs, the witness trace.
///
/// Digest mode ([tree] null): the program verifies one proof per shape and
/// its 8-lane public input is the digest of their statement digests
/// ([nodeDigest]). Wide mode: the root of an [AggregationTree].
class VerifierProgram {
  final List<InnerShape> shapes;
  final AggregationTree? tree;
  final int logTrace;
  final VerifierProgramColumns columns;
  final int periodsUsed, vmRows, hintRows;
  VerifierProgram(this.shapes, this.tree, this.logTrace, this.columns, this.periodsUsed, this.vmRows, this.hintRows);

  InnerShape get shape => shapes.single;
  bool get wide => tree != null;

  /// Compile for one [shape] on a 2^[logTrace]-row trace.
  static VerifierProgram compile(InnerShape shape, int logTrace) => compileAll([shape], logTrace);

  /// Compile a digest-mode program verifying one proof of each shape.
  static VerifierProgram compileAll(List<InnerShape> shapes, int logTrace) {
    final b = VerifierProgramBuilder(shapes, null, logTrace, null, null, null);
    b.build();
    return VerifierProgram(shapes, null, logTrace, b.columns, b.periods.length, b.vmItems.length, b.hintItems.length);
  }

  /// Compile the wide root program of [tree].
  static VerifierProgram compileWide(AggregationTree tree, int logTrace) {
    final b = VerifierProgramBuilder([tree.levels.last.$1], tree, logTrace, null, null, null);
    b.build();
    return VerifierProgram([tree.levels.last.$1], tree, logTrace, b.columns, b.periods.length, b.vmItems.length, b.hintItems.length);
  }

  /// The verifier AIR for this program with its public inputs: the node
  /// digest (digest mode) or the wide publics ([AggregationTree.widePublics]).
  VerifierAir air(List<int> publics) => VerifierAir(logTrace, columns, publics, wide: wide);

  /// The trace rows (main columns) proving that [proof] verifies.
  List<List<int>> witness(StarkProof proof) => witnessAll([proof]);

  /// The trace rows for the inner [proofs] (one per shape); a wide program
  /// also needs the transfers' [widePublics]. The inner AIR instances
  /// ([shapes], defaulting to the compiled ones) supply the proofs' public
  /// inputs. The program columns are recomputed and must match [columns].
  List<List<int>> witnessAll(List<StarkProof> proofs,
      {List<InnerShape>? shapes, List<int>? widePublics, List<List<List<int>>>? subtreePaths}) {
    shapes ??= this.shapes;
    if (proofs.length != shapes.length) throw ArgumentError('${shapes.length} inner proofs expected');
    if (wide && (widePublics == null || subtreePaths == null)) {
      throw ArgumentError('a wide program needs the transfers\' publics and the subtree paths');
    }
    final b = VerifierProgramBuilder(shapes, tree, logTrace, proofs, widePublics, subtreePaths);
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

  /// The public input of a digest-mode program verifying one proof.
  static List<int> nodeDigestOf(Air air, List<int> preRoot) => nodeDigest([statementDigest(air, preRoot)]);

  /// A digest-mode program's public input: the chain digest of its inner
  /// proofs' statement digests.
  static List<int> nodeDigest(List<List<int>> digests) {
    final ts = Poseidon2Transcript();
    for (final d in digests) {
      ts.absorb(d);
    }
    return ts.state;
  }
}

/// Lays out the verification of one inner proof as periods, VM rows and
/// hint rows, assigns rows, and fills the program columns; with a proof it
/// also computes every cell. The verification follows `StarkVerifierRef`
/// check for check.
class VerifierProgramBuilder {
  final List<InnerShape> shapes;
  final AggregationTree? tree;
  final int logTrace;
  final List<StarkProof>? proofs;
  final List<int>? widePublics;
  final List<List<List<int>>>? subtreePaths;
  final VerifierProgramColumns columns;
  final periods = <_Period>[];
  final vmItems = <_VmItem>[];
  final hintItems = <_HintItem>[];
  late final _WireRing f = _WireRing(this);
  _Period? _cur; // the transcript's current period (its digest is the state)

  VerifierProgramBuilder(this.shapes, this.tree, this.logTrace, this.proofs, this.widePublics, this.subtreePaths)
      : columns = VerifierProgramColumns(1 << logTrace);

  bool get witnessMode => proofs != null;
  StarkProof pfAt(int i) => proofs![i];
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
    final (end, bits) = _walkTo(leaf, idx, depth, siblings);
    end.digCons8 = root;
    root.uses++;
    return bits;
  }

  /// [_walk] without the root check: returns the final period (whose digest
  /// is the root reached) and the bit wires.
  (_Period, List<Wire>) _walkTo(_Period leaf, Wire idx, int depth, List<List<int>> Function() siblings) {
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
    // idx = Σ 2^k b_k + 2^depth rem, rem < 2^(31 - depth) by bit decomposition
    final remBits = [for (int j = 0; j < 31 - depth; j++) bitHint('rem$j', () => (idx.lanes[0] >> (depth + j)) & 1)];
    assertEq(idx, f.add(_fromBits(bits), _fromBits(remBits, shift: depth)));
    return (p, bits);
  }

  // ---------------------------------------------------------------- the statements

  Wire _digestWire(_Period p) => p.digProd8 ??= Wire(8, 'S${p.index}', () => _simulate(p));

  /// A fresh chain period with the given high half (see [_absorb]).
  _Period _fresh({Wire? w8, List<int> Function()? free}) {
    final p = _period();
    p.fresh = true;
    p.loZero = true;
    if (w8 != null) {
      p.hiWire8 = w8;
      w8.uses++;
    } else {
      p.hiFree = free;
    }
    _cur = p;
    return p;
  }

  /// The two K4 wires of a period's high half (lanes 8..11, 12..15).
  (Wire, Wire) _hiWires(_Period p, String label) {
    final wa = Wire(4, '${label}a', () => p._input!.sublist(8, 12));
    final wb = Wire(4, '${label}b', () => p._input!.sublist(12, 16));
    wb.tagOffset = VerifierAir.tagP2Offset;
    p.prodHiA = wa;
    p.prodHiB = wb;
    return (wa, wb);
  }

  /// The inner AIR's publics as single-lane wires from the statement's
  /// chunk wires (each K4).
  List<Wire> _pubLanes(Air air, List<Wire> chunks) =>
      [for (int k = 0; k < air.numPublics; k++) f.limb(chunks[k ~/ 4], k % 4)];

  /// The statement of inner [i] with free publics (the inner proof binds
  /// them): its chunks produced as K4 wires for the inner's constraints,
  /// then the preprocessed root chunk bound to [preRoot] (a K8 wire, the
  /// same one the query walks check against) or zero. Returns the last
  /// period and the public lanes.
  (_Period, List<Wire>) _statementFree(int i, Wire? preRoot) {
    final air = shapes[i].air;
    final pubs = air.publicValues;
    final chunkWires = <Wire>[];
    _Period? p;
    for (int c = 0; c < Poseidon2Transcript.statementPeriods - 1; c++) {
      List<int> lanes() => [for (int j = 0; j < 8; j++) 8 * c + j < pubs.length ? pubs[8 * c + j] : 0];
      p = c == 0 ? _fresh(free: lanes) : (_cur = _absorb(free: lanes));
      final (wa, wb) = _hiWires(p, 'pub${i}_$c');
      chunkWires.addAll([wa, wb]);
    }
    _cur = preRoot == null ? _absorb(zero: true) : _absorb(w8: preRoot);
    return (_cur!, _pubLanes(air, chunkWires));
  }

  /// The statement of a verifier proof whose 8-lane public input is the
  /// wire [d8] (bound), with its preprocessed root the constant [preRoot].
  /// Returns the last period, the public lanes, and the root as a K8 wire
  /// for the query walks.
  (_Period, List<Wire>, Wire) _statementBound(Air air, Wire d8, List<int> preRoot) {
    final p0 = _fresh(w8: d8);
    final (wa, wb) = _hiWires(p0, 'bound');
    for (int c = 1; c < Poseidon2Transcript.statementPeriods - 1; c++) {
      _cur = _absorb(zero: true);
    }
    if (preRoot.length != 8) throw ArgumentError('an 8-lane preprocessed root');
    final ca = f.constQ(QM31.fromLimbs(preRoot[0], preRoot[1], preRoot[2], preRoot[3]));
    final cb = f.constQ(QM31.fromLimbs(preRoot[4], preRoot[5], preRoot[6], preRoot[7]));
    final pr = _absorb(a: ca, b: cb);
    final root8 = Wire(8, 'preRootConst', () => preRoot);
    pr.prodHi8 = root8;
    _cur = pr;
    return (pr, _pubLanes(air, [wa, wb]), root8);
  }

  /// A fresh period whose high half is pinned to public chunk [c] (lanes
  /// widePublics[8c..8c+8]); [chained] continues the current chain instead.
  _Period _pinnedChunk(int c, {bool chained = false}) {
    List<int> lanes() => widePublics!.sublist(8 * c, 8 * c + 8);
    final p = chained ? (_cur = _absorb(free: lanes)) : _fresh(free: lanes);
    p.pinWide = true;
    return p;
  }

  /// The statement of spend [n] of a wide root: its chunks pinned to the
  /// public columns, padding and root chunks zero. Returns the pinned
  /// chunk periods and the last period.
  (List<_Period>, _Period) _statementPinned(int n) {
    final t = tree!;
    final c0 = t.spendChunks * n;
    final chunks = <_Period>[];
    for (int c = 0; c < Poseidon2Transcript.statementPeriods - 1; c++) {
      if (c < t.spendChunks) {
        chunks.add(_pinnedChunk(c0 + c, chained: c > 0));
      } else {
        _cur = _absorb(zero: true);
      }
    }
    if (t.spendPreRoot.isEmpty) {
      _cur = _absorb(zero: true);
    } else {
      final r = t.spendPreRoot;
      _cur = _absorb(a: f.constQ(QM31.fromLimbs(r[0], r[1], r[2], r[3])), b: f.constQ(QM31.fromLimbs(r[4], r[5], r[6], r[7])));
    }
    return (chunks, _cur!);
  }

  /// A period's high half as a K8 wire (its operand cells pin the lanes).
  Wire _hi8(_Period p, String label) => p.prodHi8 ??= Wire(8, label, () {
        _simulate(p);
        return p._input!.sublist(8, 16);
      });

  // ---------------------------------------------------------------- the commitment tree

  /// The empty node of height [h] >= 1 as a K8 wire: P(E_{h-1} ‖ E_{h-1}),
  /// both halves pinned to the same constant operands; one period per
  /// height, shared.
  final Map<int, Wire> _emptyNodes = {};
  Wire _emptyNode(int h) => _emptyNodes.putIfAbsent(h, () => _digestWire(_emptyPeriod(h)));

  _Period _emptyPeriod(int h) {
    final e = MerkleFrontier.emptyRoots[h - 1];
    final p = _period();
    p.fresh = true;
    p.hiA = f.constQ(QM31.fromLimbs(e[0], e[1], e[2], e[3]));
    p.hiB = f.constQ(QM31.fromLimbs(e[4], e[5], e[6], e[7]));
    p.hiA!.uses++;
    p.hiB!.uses++;
    p.loSameAsHi = true;
    return p;
  }

  /// P(left ‖ right) of two K8 wires at height [h] (null = the empty node
  /// of height h - 1; leaves are zero).
  _Period _node(Wire? left, Wire? right, int h) {
    // children first: a consumed period must precede its consumer
    final lw = left ?? (h == 1 ? null : _emptyNode(h - 1));
    final rw = right ?? (h == 1 ? null : _emptyNode(h - 1));
    final p = _period();
    p.fresh = true;
    if (lw == null) {
      p.loZero = true;
    } else {
      p.loWire8 = lw;
      lw.uses++;
    }
    if (rw == null) {
      p.hiZero = true;
    } else {
      p.hiWire8Next = rw;
      rw.uses++;
    }
    return p;
  }

  /// The subtree over [leaves] (K8 wires, null = empty): returns its root
  /// period (the last one allocated, so a walk can chain from it).
  _Period _subtree(List<Wire?> leaves) {
    var level = leaves;
    var h = 1;
    while (level.length > 1) {
      final periods = <_Period?>[];
      for (int i = 0; i < level.length; i += 2) {
        final l = level[i], r = level[i + 1];
        periods.add(l == null && r == null ? null : _node(l, r, h));
      }
      if (periods.length == 1) return periods[0]!;
      level = [for (final p in periods) p == null ? null : _digestWire(p)];
      h++;
    }
    throw StateError('a subtree of one leaf');
  }

  /// Prove the round's subtrees appended: from [rootBefore] (each slot
  /// shown empty first) to [rootAfter], the subtrees at [index]..
  void _treeUpdate(List<Wire> leaves, Wire rootBefore, Wire rootAfter, Wire index) {
    final t = tree!;
    var before = rootBefore;
    for (int s = 0; s < t.subtrees; s++) {
      final subLeaves = <Wire?>[
        for (int i = 0; i < AggregationTree.subtreeLeaves; i++)
          s * AggregationTree.subtreeLeaves + i < leaves.length ? leaves[s * AggregationTree.subtreeLeaves + i] : null
      ];
      final idx = s == 0 ? index : f.addConst(index, s);
      List<List<int>> siblings() => subtreePaths![s];
      // the slot is empty under the root so far
      _walk(_emptyPeriod(NoteCommitmentTree.subtreeDepth), idx, AggregationTree.mainDepth, before, siblings);
      // the subtree in place
      final (end, _) = _walkTo(_subtree(subLeaves), idx, AggregationTree.mainDepth, siblings);
      if (s == t.subtrees - 1) {
        end.digCons8 = rootAfter;
        rootAfter.uses++;
      } else {
        before = _digestWire(end);
      }
    }
  }

  /// The chain digest of the K8 wires [s]: a fresh zero-state period
  /// absorbing s[0], then one chained period per further wire.
  _Period _chain(List<Wire> s) {
    _Period? p;
    for (final w in s) {
      p = p == null ? _fresh(w8: w) : (_cur = _absorb(w8: w));
    }
    return p!;
  }

  // ---------------------------------------------------------------- the verification

  void build() {
    if (tree == null) {
      final digests = <Wire>[];
      for (int i = 0; i < shapes.length; i++) {
        final preRoot = shapes[i].R > 0 ? hint8('preRoot$i', () => pfAt(i).preRoot) : null;
        final (st, pubLane) = _statementFree(i, preRoot);
        digests.add(_digestWire(st));
        _verifyInner(i, pubLane, preRoot);
      }
      _chain(digests).pinPub = true;
    } else {
      _buildWide();
    }
    _finish();
  }

  void _buildWide() {
    final t = tree!;
    final digests0 = <Wire>[], leaves = <Wire>[];
    for (int n = 0; n < t.transfers; n++) {
      final (chunks, last) = _statementPinned(n);
      digests0.add(_digestWire(last));
      for (final c in t.leafChunks) {
        leaves.add(_hi8(chunks[c], 'leaf${n}_$c'));
      }
    }
    // the round chunks and the commitment-tree update
    final r0 = _pinnedChunk(t.roundOffset ~/ 8), r1 = _pinnedChunk(t.roundOffset ~/ 8 + 1), r2 = _pinnedChunk(t.roundOffset ~/ 8 + 2);
    final (ia, _) = _hiWires(r2, 'round');
    _treeUpdate(leaves, _hi8(r0, 'rootBefore'), _hi8(r1, 'rootAfter'), f.limb(ia, 0));
    var digests = digests0;
    for (int l = 0; l < t.depth; l++) {
      final (shape, preRoot) = t.levels[l];
      final next = <Wire>[];
      final arity = t.arities[l];
      for (int m = 0; m < digests.length ~/ arity; m++) {
        final d = _digestWire(_chain(digests.sublist(arity * m, arity * (m + 1))));
        final (st, pubLane, root8) = _statementBound(shape.air, d, preRoot);
        if (l == t.depth - 1) {
          _verifyInner(0, pubLane, root8);
        } else {
          next.add(_digestWire(st));
        }
      }
      digests = next;
    }
  }

  /// Verify inner proof [i] from the current transcript state (its
  /// statement period), replaying `StarkVerifierRef` check for check.
  void _verifyInner(int i, List<Wire> pubLane, Wire? preRoot) {
    final shape = shapes[i];
    final P = shape.P, air = shape.air;
    final A = shape.A, CT = shape.CT, C = shape.C, R = shape.R, K = P.compCols;
    final a = P.logTraceHalf;
    final gT = CirclePoint.subgroupGen(P.logTrace);
    StarkProof pf() => pfAt(i);

    // ---- transcript: roots and challenges ----
    final traceRoot = hint8('traceRoot', () => pf().traceRoot);
    _cur = _absorb(w8: traceRoot);
    final chal = [for (int k = 0; k < air.numChallenges; k++) squeeze4('chal$k')];
    Wire? auxRoot;
    if (A > 0) {
      auxRoot = hint8('auxRoot', () => pf().auxRoot);
      _cur = _absorb(w8: auxRoot);
    }
    final beta = squeeze4('beta');
    final compRoot = hint8('compRoot', () => pf().compRoot);
    _cur = _absorb(w8: compRoot);
    final tch = squeeze4('tch');
    final zHint = hint4('zHint', () => pf().zHint);
    final t2 = f.mul(tch, tch);
    assertEq(f.mul(f.add(f.one, t2), zHint), f.one);
    final zx = f.mul(f.sub(f.one, t2), zHint), zy = f.mul(f.add(tch, tch), zHint);
    final traceAtZ = [for (int j = 0; j < CT; j++) hint4('tz$j', () => pf().traceAtZ[j])];
    final traceAtZg = [for (int j = 0; j < CT; j++) hint4('tzg$j', () => pf().traceAtZg[j])];
    final compAtZ = [for (int k = 0; k < K; k++) hint4('cz$k', () => pf().compAtZ[k])];
    final oods = [...traceAtZ, ...traceAtZg, ...compAtZ];
    for (int k = 0; k < oods.length; k += 2) {
      _cur = _absorb(a: oods[k], b: k + 1 < oods.length ? oods[k + 1] : f.zero);
    }
    final lamB = squeeze4('lamB'), lamC = squeeze4('lamC'), alC = squeeze4('alC');

    // ---- out-of-domain check of the inner AIR: the composition's limb
    // values at z are its blocks' recombined with M_k(zx) (StarkParams.chunkMultipliers)
    final compLimbsAtZ = <Wire>[];
    {
      Wire dbl(Wire w) {
        final w2 = f.mul(w, w);
        return f.sub(f.add(w2, w2), f.one);
      }
      var w = zx;
      for (int j = 0; j < P.logTraceBound - 1; j++) {
        w = dbl(w);
      }
      final factors = <Wire>[];
      for (int j = 0; j < P.logComp - P.logTraceBound; j++) {
        factors.add(w);
        w = dbl(w);
      }
      final mk = <Wire?>[null];
      for (int k = 1; k < P.compChunks; k++) {
        int low = 0;
        while ((k >> low) & 1 == 0) {
          low++;
        }
        final rest = mk[k & (k - 1)];
        mk.add(rest == null ? factors[low] : f.mul(rest, factors[low]));
      }
      for (int l = 0; l < 4; l++) {
        var acc = compAtZ[l];
        for (int k = 1; k < P.compChunks; k++) {
          acc = f.add(acc, f.mul(mk[k]!, compAtZ[4 * k + l]));
        }
        compLimbsAtZ.add(acc);
      }
    }
    _withPublics(air, pubLane, () {
      assertZero(air.oodCheckG(f, traceAtZ, traceAtZg, compLimbsAtZ, beta, zx, zy, chal: chal));
    });

    // ---- z*g and the DEEP constants: group B is every column at z (trace,
    // aux, pre, then the composition blocks), group C the trace columns at z*g
    final zgx = f.sub(f.scale(zx, gT.x), f.scale(zy, gT.y));
    final zgy = f.add(f.scale(zx, gT.y), f.scale(zy, gT.x));
    final kB = _deepPrecompute(zx, zy, [...traceAtZ, ...compAtZ], lamB);
    final kC = _deepPrecompute(zgx, zgy, traceAtZg, lamB, base: lamC);

    // ---- FRI roots and alphas, final coefficients, grinding, indices ----
    final friRoots = <Wire>[], alphas = <Wire>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      final w = hint8('fr$l', () => pf().friRoots[l]);
      friRoots.add(w);
      _cur = _absorb(w8: w);
      alphas.add(squeeze4('al$l'));
    }
    final finalCoefs = [for (int k = 0; k < P.finalDegree; k++) hint4('fc$k', () => pf().finalCoefs[k])];
    for (int k = 0; k < finalCoefs.length; k += 2) {
      _cur = _absorb(a: finalCoefs[k], b: k + 1 < finalCoefs.length ? finalCoefs[k + 1] : f.zero);
    }
    final stateBeforeGrind = _cur!;
    final grind = _absorb(nonce: true, free: () => [pf().nonce[0], 0, 0, 0, 0, 0, 0, 0]);
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
    final hB = HalfCoset(a);
    final stepPow = <CirclePoint>[];
    {
      var g = hB.step;
      for (int k = 0; k < a; k++) {
        stepPow.add(g);
        g = g.double_();
      }
    }
    for (int q = 0; q < P.numQueries; q++) {
      final idx = indices[q];
      QueryProof qp() => pf().queries[q];
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
      List<Wire> lanesOf(List<Wire> ch, int from, int count) =>
          [for (int j = 0; j < count; j++) f.limb(ch[(from + j) ~/ 4], (from + j) % 4)];

      // every commitment is opened at leaf idx of the trace domain
      final cl = chunks('cl', 2 * K, () => qp().compLeaf);
      final bits = _walk(_leaf(cl), idx, a, compRoot, () => qp().compPath);
      final tl = chunks('tl', 2 * C, () => qp().traceLeaf);
      _walk(_leaf(tl), idx, a, traceRoot, () => qp().tracePath);
      List<Wire> al = const [], pl = const [];
      if (A > 0) {
        al = chunks('axl', 2 * A, () => qp().auxLeaf);
        _walk(_leaf(al), idx, a, auxRoot!, () => qp().auxPath);
      }
      if (R > 0) {
        // the root the statement absorbed: one wire for the statement and every query
        pl = chunks('prl', 2 * R, () => qp().preLeaf);
        _walk(_leaf(pl), idx, a, preRoot!, () => qp().prePath);
      }
      // the query point from its bits: acc = initial * Π step^(2^k b_k)
      var px = f.constM31(hB.initial.x), py = f.constM31(hB.initial.y);
      for (int k = 0; k < a; k++) {
        final g = stepPow[k];
        final nx = f.sub(f.scale(px, g.x), f.scale(py, g.y));
        final ny = f.add(f.scale(px, g.y), f.scale(py, g.x));
        px = f.add(px, f.mul(bits[k], f.sub(nx, px)));
        py = f.add(py, f.mul(bits[k], f.sub(ny, py)));
      }
      // DEEP groups B and C at p and conj p from one weighted sum of the
      // trace openings (group C's weights are kC.base times group B's; group
      // B adds the composition blocks with the weights after the trace's)
      final atP = [...lanesOf(tl, 0, C), ...lanesOf(al, 0, A), ...lanesOf(pl, 0, R)];
      final atC = [...lanesOf(tl, C, C), ...lanesOf(al, A, A), ...lanesOf(pl, R, R)];
      final compP = lanesOf(cl, 0, K), compC = lanesOf(cl, K, K);
      final dBp = hint4('dbp$q', () => qp().dBInvP), dBc = hint4('dbc$q', () => qp().dBInvC);
      final dCp = hint4('dcp$q', () => qp().dCInvP), dCc = hint4('dcc$q', () => qp().dCInvC);
      final sTp = _weightedSum(kB, atP), sTc = _weightedSum(kB, atC);
      final sBp = f.add(sTp, _weightedSumFrom(kB, compP, CT)), sBc = f.add(sTc, _weightedSumFrom(kB, compC, CT));
      final qTp = f.add(_quotientOfSum(kB, px, py, sBp, dBp), _quotientOfSum(kC, px, py, f.mul(kC.base!, sTp), dCp));
      final npy = f.neg(py);
      final qTc = f.add(_quotientOfSum(kB, px, npy, sBc, dBc), _quotientOfSum(kC, px, npy, f.mul(kC.base!, sTc), dCc));
      final yBi = hint1('ybi$q', () => qp().yBInv);
      assertEq(f.mul(yBi, py), f.one);
      var out = _fold(qTp, qTc, yBi, alC);
      var top = bits[a - 1];
      var xA = f.add(px, f.mul(top, f.neg(f.add(px, px)))); // -x when the top bit is set
      // FRI layers
      for (int l = 0; l < P.numLineFolds; l++) {
        final d = a - 1 - l;
        final lf = hint4('lf${q}_$l', () => qp().lineF0[l]), lg = hint4('lg${q}_$l', () => qp().lineF1[l]);
        // the previous output is the component of this layer's pair the top bit selects
        assertEq(out, f.add(lf, f.mul(top, f.sub(lg, lf))));
        final lLeaf = _leaf([lf, lg]);
        final lbits = _walk(lLeaf, idx, d, friRoots[l], () => qp().linePaths[l]);
        final xi = hint1('lxi${q}_$l', () => qp().lineXInv[l]);
        assertEq(f.mul(xi, xA), f.one);
        final next = _fold(lf, lg, xi, alphas[l]);
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
  }

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

  Wire _fold(Wire f0, Wire f1, Wire twInv, Wire alpha) => f.add(f.add(f0, f1), f.mul(alpha, f.mul(twInv, f.sub(f0, f1))));

  Wire _conj(Wire v) {
    // conj(v) = v - 2 (l2 u + l3 iu)
    final l2 = f.limb(v, 2), l3 = f.limb(v, 3);
    final t = f.add(f.mulQ(l2, QM31.u), f.mulQ(l3, QM31.i * QM31.u));
    return f.sub(v, f.add(t, t));
  }

  /// With [base] the weights are base * alpha^j (see DeepQuotientRef.precompute).
  DeepWires _deepPrecompute(Wire zx, Wire zy, List<Wire> values, Wire alpha, {Wire? base}) {
    final zyc = _conj(zy), zxc = _conj(zx);
    final c = f.sub(zyc, zy);
    final dA = f.sub(zy, zyc);
    final dB = f.sub(zxc, zx);
    final dC = f.sub(f.mul(zx, zyc), f.mul(zy, zxc));
    var w = base ?? f.one;
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
    return DeepWires(c, aAcc!, bAcc!, dA, dB, dC, weights, base: base);
  }

  Wire _weightedSum(DeepWires k, List<Wire> openings) => _weightedSumFrom(k, openings, 0);

  /// The weighted sum with the weights from index [offset] on.
  Wire _weightedSumFrom(DeepWires k, List<Wire> openings, int offset) {
    Wire? s;
    for (int j = 0; j < openings.length; j++) {
      final term = f.mul(k.weights[offset + j], openings[j]);
      s = s == null ? term : f.add(s, term);
    }
    return s!;
  }

  Wire _quotientOfSum(DeepWires k, Wire px, Wire py, Wire s, Wire dInv) {
    final den = f.add(f.add(f.mul(k.dA, px), f.mul(k.dB, py)), k.dC);
    assertEq(f.mul(den, dInv), f.one);
    final num = f.sub(f.sub(f.mul(k.c, s), f.mul(k.A, py)), k.B);
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
      if (p.hiWire8Next != null) _claimed[r0 + 1] = true;
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
      if (p.hiWire8Next != null) {
        columns.set(VerifierProgramColumns.inHiNext, r0, 1);
        _consumeAt(r0 + 1, p.hiWire8Next!);
      }
      if (p.loSameAsHi) columns.set(VerifierProgramColumns.inLoAB, r0, 1);
      if (p.prodHiA != null) {
        columns.set(VerifierProgramColumns.inHiAB, r0, 1);
        if (p.prodHiA!.uses > 0) _produceAt(r0, p.prodHiA!, VerifierProgramColumns.p1a4);
        if (p.prodHiB!.uses > 0) _produceAt(r0, p.prodHiB!, VerifierProgramColumns.p2en);
        _pinned.add((r0, p.prodHiA!, p.prodHiB!));
      }
      if (p.prodHi8 != null && p.prodHi8!.uses > 0) {
        if (p.prodHiA != null && p.prodHiA!.uses > 0) throw StateError('two P1 producers at row $r0');
        columns.set(VerifierProgramColumns.inHiAB, r0, 1);
        _produceAt(r0, p.prodHi8!, VerifierProgramColumns.p1ab8);
      }
      if (p.pinWide) columns.set(VerifierProgramColumns.pinPub, r0, 1);
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
    if (p.hiWire8Next != null) input.setRange(8, 16, p.hiWire8Next!.lanes);
    if (p.loSameAsHi) input.setRange(0, 8, input.sublist(8, 16));
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
  /// The scalar this group's weights carry over alpha^j (null: one).
  final Wire? base;
  DeepWires(this.c, this.A, this.B, this.dA, this.dB, this.dC, this.weights, {this.base});
}
