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
import '../crypto/nullifier_tree.dart';
import '../crypto/poseidon2_m31.dart';
import '../crypto/proof_hash.dart';
import '../crypto/stark_prover_ref.dart';
import '../script_gen/air.dart';
import '../script_gen/air_ring.dart';
import '../script_gen/poseidon2_air.dart';
import '../script_gen/poseidon2_chain_air.dart';
import '../script_gen/pool_spend_air.dart';
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
  Wire? prodLoA, prodLoB; // row 0 lanes 0..3 / 4..7 produced as K4 wires (whatever fills them)
  Wire? prodNextA, prodNextB; // lanes 8..11 / 12..15 produced as K4 wires at row 1
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
      loWire8 != null ||
      hiA != null ||
      hiWire8 != null ||
      hiWire8Next != null ||
      prodHiA != null ||
      prodHi8 != null ||
      prodLoA != null;
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

/// The anchor check a level-1 node makes on every spend it verifies: the
/// spend's anchor (statement chunk [anchorChunk]) must be one of the [size]
/// roots the node absorbs after its spends' digests, unless the spend has
/// no real input (lanes [real1] and [real2] both zero), when the anchor
/// protects nothing. The ring is part of the node's public input, so the
/// root, which knows the round's ring, can re-derive the node's digest and
/// the anchor's eight lanes need not be public at all.
class AnchorRing {
  final int anchorChunk, real1, real2, size;
  const AnchorRing({required this.anchorChunk, required this.real1, required this.real2, this.size = 4});

  /// The pool's: the anchor is the first chunk, the real flags lanes 50 and
  /// 51, and the state header keeps four roots.
  static const pool = AnchorRing(
      anchorChunk: PoolPublicInputs.idxAnchor ~/ 8, real1: PoolPublicInputs.idxReal1, real2: PoolPublicInputs.idxReal2, size: 4);
}

/// The aggregation tree a wide root program re-derives the digests of.
/// Level 0 is the spends ([spendPublics] public lanes each, preprocessed
/// root [spendPreRoot], empty for the pool's spend AIR); level l + 1 holds
/// the verifier proofs of shape [levels][l] (with that circuit's
/// preprocessed root), each verifying `arities[l]` proofs of the level below.
/// The root verifies one proof of the last level and takes every spend's
/// publics, less the [freeChunks], as its own (wide) statement.
class AggregationTree {
  final int spendPublics;
  final List<int> spendPreRoot;
  final List<(InnerShape, List<int>)> levels;

  /// Proofs verified per node, level by level (level 1 folds spends).
  final List<int> arities;

  /// The chunks of each spend's publics that are commitment-tree leaves,
  /// in leaf order (the pool's cm1, cm2).
  final List<int> leafChunks;

  /// The ring check level 1 makes, whose ring the root takes as round
  /// chunks; null for a tree whose level 1 has none.
  final AnchorRing? ring;

  /// The chunks of each spend's publics the root takes as witness rather
  /// than public input: the leaves, whose only reader is the tree update
  /// the root proves, and the anchor, which level 1 checked against the
  /// ring. The spend's digest still covers them, so the root cannot use
  /// other values than the ones the spend proof was made for.
  final List<int> freeChunks;

  /// The level whose nodes insert the round's nullifiers (null: the tree
  /// proves none, and the nullifier set is someone else's job). The root
  /// then pins the set's root before and after the round, and rebuilds that
  /// level's digests from the chunks it already pins (see [NullifierSegment]).
  final int? nullifierLevel;

  /// Deposit receipts the round can carry (0: none). Each slot is two
  /// pinned chunks, `[cm]` and `[lo, hi, used, 0 x 5]`, and the root proves
  /// every used slot is exactly one transfer's: its first output
  /// commitment, its signed amount, the BSV asset and two dummy inputs, no
  /// transfer backing two slots. The dummies are a privacy rule: a deposit
  /// is public, and real inputs beside it would put the depositor's name on
  /// their earlier notes. Slots rather than a public commitment per
  /// transfer because the root script pays per pinned chunk: all 256
  /// cmOut1 chunks measured +203 KB of script, 8 slots are 16 chunks.
  final int receiptSlots;
  AggregationTree(this.spendPublics, this.spendPreRoot, this.levels, this.arities,
      {this.leafChunks = const [3, 4], this.ring, List<int>? freeChunks, this.nullifierLevel, this.receiptSlots = 0})
      : freeChunks = freeChunks ?? ([if (ring != null) ring.anchorChunk, ...leafChunks]..sort()) {
    if (levels.isEmpty) throw ArgumentError('at least one aggregation level');
    if (arities.length != levels.length || arities.any((a) => a < 1)) throw ArgumentError('one arity per level');
    if (this.freeChunks.any((c) => c < 0 || c >= spendChunks) || this.freeChunks.toSet().length != this.freeChunks.length) {
      throw ArgumentError('free chunks');
    }
    if (leafChunks.any((c) => !this.freeChunks.contains(c))) throw ArgumentError('the leaf chunks are witness chunks');
    final nl = nullifierLevel;
    if (nl != null) {
      if (nl < 0 || nl >= levels.length) throw ArgumentError('no level $nl');
      if (NullifierSegment.chunks.any(this.freeChunks.contains)) throw ArgumentError('the nullifier chunks must be public');
    }
    if (receiptSlots < 0) throw ArgumentError('receipt slots');
    if (receiptSlots > 0 && ReceiptSlot.pinnedSources.any(this.freeChunks.contains)) {
      throw ArgumentError('a receipt reads the amount and flag chunks, which must be public');
    }
    final appended = leavesAppended;
    if (appended <= 0 || appended & (appended - 1) != 0) {
      throw ArgumentError('a round must append a power of two leaves, not $appended '
          '($transfers transfers x ${leafChunks.length} = $leaves leaves, '
          '$subtrees subtrees of $subtreeLeaves); round N owns the aligned subtree at '
          'level log2(leaves a round) only while that count is a power of two, and a '
          'note keeps its path current from one block root a round only because it does');
    }
  }

  /// The same [arity] at every level.
  AggregationTree.uniform(int spendPublics, List<int> spendPreRoot, List<(InnerShape, List<int>)> levels, int arity,
      {List<int> leafChunks = const [3, 4], AnchorRing? ring, List<int>? freeChunks, int? nullifierLevel, int receiptSlots = 0})
      : this(spendPublics, spendPreRoot, levels, List.filled(levels.length, arity),
            leafChunks: leafChunks, ring: ring, freeChunks: freeChunks, nullifierLevel: nullifierLevel, receiptSlots: receiptSlots);

  /// Transfers under one node of level [l].
  int transfersPerNode(int l) => arities.sublist(0, l + 1).fold(1, (n, a) => n * a);

  /// Nodes at level [l].
  int nodesAt(int l) => transfers ~/ transfersPerNode(l);

  int get depth => levels.length;
  int get transfers => arities.fold(1, (n, a) => n * a);

  /// Chunks per spend statement: its publics padded to whole chunks.
  int get spendChunks => (spendPublics + 7) ~/ 8;

  /// Pinned chunks per spend: the statement chunks that are public lanes.
  int get pinnedChunks => spendChunks - freeChunks.length;

  /// A spend's public lanes as the root pins them: its statement chunks
  /// in order, less the free ones.
  List<int> reducedLanes(List<int> spend) {
    if (spend.length != spendPublics) throw ArgumentError('$spendPublics lanes per spend');
    return [
      for (int c = 0; c < spendChunks; c++)
        if (!freeChunks.contains(c))
          for (int j = 0; j < 8; j++) 8 * c + j < spend.length ? spend[8 * c + j] : 0
    ];
  }

  // ---- the commitment-tree update the root proves ----
  static const subtreeLeaves = NoteCommitmentTree.subtreeLeaves;
  static const mainDepth = NoteCommitmentTree.mainDepth;
  int get leaves => transfers * leafChunks.length;

  /// Whole subtrees appended per round (the last padded with empty leaves).
  int get subtrees => (leaves + subtreeLeaves - 1) ~/ subtreeLeaves;

  /// Rows appended to the pool's tree per round.
  int get leavesAppended => subtrees * subtreeLeaves;

  /// The round chunks after the transfers': rootBefore, rootAfter,
  /// [index, 0 x 7] with index the first subtree's position, then the
  /// ring's roots when level 1 checks anchors, then the nullifier set's
  /// root before and after the round when a level inserts them.
  int get roundChunks => 3 + (ring?.size ?? 0) + (nullifierLevel == null ? 0 : 2) + 2 * receiptSlots;
  int get roundOffset => 8 * pinnedChunks * transfers;

  /// Where the ring's lanes start in the wide publics.
  int get ringOffset => roundOffset + 24;

  /// Where nfBefore's lanes start (nfAfter's follow).
  int get nullifierOffset => ringOffset + 8 * (ring?.size ?? 0);

  /// Where the receipt slots start: slot r is 16 lanes from here + 16 r.
  int get receiptOffset => nullifierOffset + (nullifierLevel == null ? 0 : 16);

  /// The root's wide public inputs: every transfer's reduced lanes
  /// ([reducedLanes]), then the round chunks.
  List<int> widePublics(List<List<int>> spends,
      {required List<int> rootBefore,
      required List<int> rootAfter,
      required int index,
      List<List<int>>? ring,
      List<int>? nfBefore,
      List<int>? nfAfter,
      List<int> receiptTransfers = const []}) {
    if (spends.length != transfers) throw ArgumentError('$transfers transfers expected');
    if (rootBefore.length != 8 || rootAfter.length != 8) throw ArgumentError('8-lane roots');
    if (index < 0 || index + subtrees > 1 << mainDepth) throw ArgumentError('subtree index');
    final r = this.ring;
    if (r == null ? ring != null : (ring == null || ring.length != r.size || ring.any((x) => x.length != 8))) {
      throw ArgumentError(r == null ? 'this tree has no ring' : 'a ring of ${r.size} 8-lane roots');
    }
    if ((nullifierLevel != null) != (nfBefore != null && nfAfter != null) || nfBefore?.length != nfAfter?.length) {
      throw ArgumentError(nullifierLevel == null ? 'this tree inserts no nullifiers' : 'the nullifier roots before and after');
    }
    return [
      for (final p in spends) ...reducedLanes(p),
      ...rootBefore,
      ...rootAfter,
      index,
      ...List.filled(7, 0),
      if (ring != null)
        for (final x in ring) ...x,
      ...?nfBefore,
      ...?nfAfter,
      for (final c in ReceiptSlot.chunks(spends, receiptTransfers, receiptSlots)) ...c,
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

/// A deposit receipt as the root states it (see [AggregationTree.receiptSlots]).
class ReceiptSlot {
  static const cmChunk = PoolPublicInputs.idxCm1 ~/ 8;
  static const amountChunk = PoolPublicInputs.idxPubLo ~/ 8;
  static const flagChunk = PoolPublicInputs.idxReal1 ~/ 8;
  static const loLimb = PoolPublicInputs.idxPubLo % 8, hiLimb = PoolPublicInputs.idxPubHi % 8;
  static const real1Limb = PoolPublicInputs.idxReal1 % 8, real2Limb = PoolPublicInputs.idxReal2 % 8;

  /// The pinned statement chunks a receipt reads (cmOut1 is a witness chunk
  /// the spend's digest already binds).
  static const pinnedSources = [amountChunk, flagChunk];

  /// The slot's second chunk: `[lo, hi, used]`.
  static const loLane = 0, hiLane = 1, usedLane = 2;

  static void _check() {
    assert(loLimb < 4 && hiLimb < 4 && real1Limb < 4 && real2Limb < 4, 'the limbs sit in the chunks\' first halves');
    assert(PoolPublicInputs.idxAsset % 8 == 4 && PoolPublicInputs.idxAsset ~/ 8 == flagChunk, 'the asset is the flag chunk\'s second half');
  }

  /// Whether transfer lanes [l] may back a receipt: money in, BSV, no real input.
  static String? refusal(List<int> l) {
    final p = PoolPublicInputs.fromLanes(l);
    if (p.publicOut >= 0) return 'takes no money in';
    if (p.real1 || p.real2) return 'spends a real note beside a deposit, which would name the depositor as its owner';
    for (int i = 0; i < PoolHash.assetLanes; i++) {
      if (p.asset[i] != PoolHash.bsvAsset[i]) return 'is not in BSV';
    }
    return null;
  }

  /// The slots' chunks for deposits [transfers] (indices into [spends], in
  /// receipt order), unused slots zero.
  static List<List<int>> chunks(List<List<int>> spends, List<int> transfers, int slots) {
    _check();
    if (transfers.length > slots) throw ArgumentError('${transfers.length} receipts, $slots slots');
    if (transfers.toSet().length != transfers.length) throw ArgumentError('a transfer backs one receipt');
    final out = <List<int>>[];
    for (int r = 0; r < slots; r++) {
      if (r >= transfers.length) {
        out.addAll([List.filled(8, 0), List.filled(8, 0)]);
        continue;
      }
      final l = spends[transfers[r]];
      final why = refusal(l);
      if (why != null) throw ArgumentError('transfer ${transfers[r]} $why');
      out.add(l.sublist(PoolPublicInputs.idxCm1, PoolPublicInputs.idxCm1 + 8));
      out.add([l[PoolPublicInputs.idxPubLo], l[PoolPublicInputs.idxPubHi], 1, 0, 0, 0, 0, 0]);
    }
    return out;
  }
}

/// The nullifiers a digest-mode node inserts into the pool's
/// [NullifierTree]: every real input of the transfers under it, in order.
///
/// The node absorbs, after its inner digests, the tree's root before and
/// after its insertions and three statement chunks per transfer ([chunks]:
/// nf1, nf2, and the chunk holding the real flags). That makes them part
/// of its public digest, and the root, which pins those same chunks for
/// every transfer, rebuilds the digest from its own copies. So the lanes a
/// node inserts are the lanes the spend proofs were verified against, and
/// the roots chain from node to node up to the two the round states.
class NullifierSegment {
  /// Statement chunks absorbed per transfer, and where in the last one the
  /// real flags sit.
  static const chunks = [PoolPublicInputs.idxNf1 ~/ 8, PoolPublicInputs.idxNf2 ~/ 8, PoolPublicInputs.idxReal1 ~/ 8];
  static const real1Limb = PoolPublicInputs.idxReal1 % 8, real2Limb = PoolPublicInputs.idxReal2 % 8;

  final List<int> before, after;

  /// Per transfer, its three chunks (8 lanes each).
  final List<List<List<int>>> transferChunks;

  /// Per nullifier (two per transfer), the siblings its slot has.
  final List<List<List<int>>> paths;

  NullifierSegment(this.before, this.after, this.transferChunks, this.paths) {
    if (before.length != 8 || after.length != 8) throw ArgumentError('8-lane roots');
    if (paths.length != 2 * transferChunks.length) throw ArgumentError('two paths per transfer');
  }

  /// The chunks of a transfer's full statement lanes that a node absorbs.
  static List<List<int>> chunksOf(List<int> spendLanes) => [for (final c in chunks) spendLanes.sublist(8 * c, 8 * c + 8)];

  /// Insert the real nullifiers of transfers with statement lanes [spends]
  /// into [tree], returning the segment a node proves. A dummy input's
  /// nullifier is not inserted, but its slot must be empty all the same:
  /// the node walks it and writes the empty leaf back.
  static NullifierSegment insert(NullifierTree tree, List<List<int>> spends) {
    final before = tree.root;
    final paths = <List<List<int>>>[];
    for (final l in spends) {
      for (final (nfAt, realAt) in [(PoolPublicInputs.idxNf1, PoolPublicInputs.idxReal1), (PoolPublicInputs.idxNf2, PoolPublicInputs.idxReal2)]) {
        final nf = l.sublist(nfAt, nfAt + 8);
        if (l[realAt] == 1) {
          paths.add(tree.insert(nf));
        } else {
          if (tree.occupied(nf)) throw StateError('a dummy nullifier lands on a spent slot');
          paths.add(tree.path(nf));
        }
      }
    }
    return NullifierSegment(before, tree.root, [for (final l in spends) chunksOf(l)], paths);
  }

  /// What the node absorbs after its inner digests (see [VerifierProgram.nodeDigest]).
  List<List<int>> get tail => [before, after, for (final t in transferChunks) ...t];
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

  /// Digest mode only: the anchor check this program makes, whose ring it
  /// absorbs after its inner digests (see [nodeDigest]).
  final AnchorRing? ring;

  /// Digest mode only: the transfers whose nullifiers this node inserts (0:
  /// none), see [NullifierSegment].
  final int nullifierTransfers;
  VerifierProgram(this.shapes, this.tree, this.logTrace, this.columns, this.periodsUsed, this.vmRows, this.hintRows,
      {this.ring, this.nullifierTransfers = 0});

  InnerShape get shape => shapes.single;
  bool get wide => tree != null;

  /// Compile for one [shape] on a 2^[logTrace]-row trace.
  static VerifierProgram compile(InnerShape shape, int logTrace, {AnchorRing? ring}) => compileAll([shape], logTrace, ring: ring);

  /// Compile a digest-mode program verifying one proof of each shape; with
  /// [ring] it also checks each inner statement's anchor against a ring it
  /// takes as public input (a level-1 node); with [nullifierTransfers] it
  /// also inserts the nullifiers of that many transfers ([NullifierSegment]).
  static VerifierProgram compileAll(List<InnerShape> shapes, int logTrace, {AnchorRing? ring, int nullifierTransfers = 0}) {
    final b = VerifierProgramBuilder(shapes, null, logTrace, null, null, null, ring: ring, nullifierTransfers: nullifierTransfers);
    b.build();
    return VerifierProgram(shapes, null, logTrace, b.columns, b.periods.length, b.vmItems.length, b.hintItems.length,
        ring: ring, nullifierTransfers: nullifierTransfers);
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

  /// The trace rows for the inner [proofs] (one per shape); a program with
  /// a ring check needs the [ring] (its roots, 8 lanes each); a wide program
  /// also needs the [widePublics], every transfer's full lanes
  /// ([spendLanes], for the witness chunks) and the [subtreePaths]. The
  /// inner AIR instances ([shapes], defaulting to the compiled ones) supply
  /// the proofs' public inputs. The program columns are recomputed and must
  /// match [columns].
  ///
  /// [forgedAfterPaths] is for tests only: the siblings a dishonest prover
  /// would climb with the subtree in place, instead of the ones that showed
  /// the slot empty. The AIR must refuse any trace built with them.
  List<List<int>> witnessAll(List<StarkProof> proofs,
      {List<InnerShape>? shapes,
      List<List<int>>? ring,
      List<int>? widePublics,
      List<List<int>>? spendLanes,
      List<List<List<int>>>? subtreePaths,
      NullifierSegment? nullifiers,
      List<List<int>>? nullifierRoots,
      List<int> receiptTransfers = const [],
      List<List<List<int>>>? forgedAfterPaths}) {
    shapes ??= this.shapes;
    if (proofs.length != shapes.length) throw ArgumentError('${shapes.length} inner proofs expected');
    if (wide && (widePublics == null || subtreePaths == null || spendLanes == null)) {
      throw ArgumentError('a wide program needs the wide publics, the transfers\' lanes and the subtree paths');
    }
    if (this.ring != null && (ring == null || ring.length != this.ring!.size || ring.any((r) => r.length != 8))) {
      throw ArgumentError('this program checks anchors against a ring of ${this.ring!.size} roots');
    }
    if (nullifierTransfers > 0 && nullifiers?.transferChunks.length != nullifierTransfers) {
      throw ArgumentError('this program inserts the nullifiers of $nullifierTransfers transfers');
    }
    final b = VerifierProgramBuilder(shapes, tree, logTrace, proofs, widePublics, subtreePaths,
        ring: this.ring,
        ringLanes: ring,
        spendLanes: spendLanes,
        nullifierTransfers: nullifierTransfers,
        nullifiers: nullifiers,
        nullifierRoots: nullifierRoots,
        receiptTransfers: receiptTransfers,
        forgedAfterPaths: forgedAfterPaths);
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
  /// proofs' statement digests, then of the [ring]'s roots when the program
  /// checks anchors against one.
  static List<int> nodeDigest(List<List<int>> digests, {List<List<int>>? ring, NullifierSegment? nullifiers}) {
    final ts = Poseidon2Transcript();
    for (final d in digests) {
      ts.absorb(d);
    }
    for (final r in ring ?? const <List<int>>[]) {
      ts.absorb(r);
    }
    for (final c in nullifiers?.tail ?? const <List<int>>[]) {
      ts.absorb(c);
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

  /// Digest mode: the anchor check and, in witness mode, the ring's roots.
  final AnchorRing? ring;
  final List<List<int>>? ringLanes;

  /// Wide mode, witness: every transfer's full lanes, for the witness chunks.
  final List<List<int>>? spendLanes;

  /// Digest mode: the nullifier insertions, and in witness mode their data.
  final int nullifierTransfers;
  final NullifierSegment? nullifiers;

  /// Wide mode, witness: the nullifier set's root at each boundary between
  /// the inserting level's nodes (nodes + 1 roots, first and last public).
  final List<List<int>>? nullifierRoots;

  /// Wide mode, witness: the transfer behind each used receipt slot.
  final List<int> receiptTransfers;

  /// Tests only, see [VerifierProgram.witnessAll].
  final List<List<List<int>>>? forgedAfterPaths;
  final VerifierProgramColumns columns;
  final periods = <_Period>[];
  final vmItems = <_VmItem>[];
  final hintItems = <_HintItem>[];
  late final _WireRing f = _WireRing(this);
  _Period? _cur; // the transcript's current period (its digest is the state)

  VerifierProgramBuilder(this.shapes, this.tree, this.logTrace, this.proofs, this.widePublics, this.subtreePaths,
      {this.ring,
      this.ringLanes,
      this.spendLanes,
      this.nullifierTransfers = 0,
      this.nullifiers,
      this.nullifierRoots,
      this.receiptTransfers = const [],
      this.forgedAfterPaths})
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
  (_Period, List<Wire>) _walkTo(_Period leaf, Wire idx, int depth, List<List<int>> Function() siblings, {List<_Period>? trail}) {
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
      trail?.add(n);
      p = n;
    }
    // idx = Σ 2^k b_k + 2^depth rem, rem < 2^(31 - depth) by bit decomposition
    final remBits = [for (int j = 0; j < 31 - depth; j++) bitHint('rem$j', () => (idx.lanes[0] >> (depth + j)) & 1)];
    assertEq(idx, f.add(_fromBits(bits), _fromBits(remBits, shift: depth)));
    return (p, bits);
  }

  /// Two Merkle walks over the same siblings and the same direction bits:
  /// the first from [leafA] must reach [rootA]; the second starts at the
  /// period [leafB] allocates (called once the first walk is laid out, so
  /// the second chains from it) and its end is returned. This is an
  /// insertion: the first walk shows what the slot held under the old root,
  /// the second computes the new root with the slot replaced.
  ///
  /// Both walks take their siblings as free witness, so without the binding
  /// the second could climb over siblings of its own choosing and reach any
  /// root at all, a tree with every other leaf replaced. Each chained period
  /// therefore publishes both halves of its input (low half at row 0, high
  /// half at row 1); the sibling is the high half when the level's bit is
  /// 0 and the low half when it is 1, and the VM requires the two walks'
  /// siblings to agree at every level. The second walk's bits are the
  /// first's, asserted equal rather than decomposed again.
  ///
  /// The slot is either the index lane [idx] ([depth] bits, as [_walkTo]) or
  /// the key lanes [keyLanes] (31 bits each, lane 0 lowest), which must be
  /// their canonical decomposition: see [NullifierTree].
  _Period _walkPair(_Period leafA, Wire rootA, _Period Function() leafB, int depth, List<List<int>> Function() siblings,
      {Wire? idx, List<Wire>? keyLanes, List<List<int>> Function()? siblingsB}) {
    final sibsB = siblingsB ?? siblings;
    final trailA = <_Period>[];
    final (endA, bits) =
        idx != null ? _walkTo(leafA, idx, depth, siblings, trail: trailA) : _walkToKey(leafA, keyLanes!, depth, siblings, trailA);
    endA.digCons8 = rootA;
    rootA.uses++;
    // a K1 operand is only bound in limb 0, so the bits are lifted before use
    final lifted = [for (final a in bits) f.limb(a, 0)];
    if (keyLanes != null) {
      const lb = NullifierTree.laneBits;
      for (int j = 0; j < keyLanes.length; j++) {
        final mine = lifted.sublist(lb * j, lb * (j + 1));
        assertEq(keyLanes[j], _fromBits(mine));
        // not all ones: 2^31 - 1 is p, a second spelling of 0
        var all = mine[0];
        for (int k = 1; k < lb; k++) {
          all = f.mul(all, mine[k]);
        }
        assertZero(all);
      }
    }
    var p = leafB();
    for (int k = 0; k < depth; k++) {
      final sib = k, a = bits[k], bit = lifted[k];
      p.swapBitFn = () => a.lanes[0];
      final w = Wire(1, 'bitB$k', () => [a.lanes[0]]);
      p.swapWire = w;
      assertZero(f.sub(f.limb(w, 0), bit));
      final n = _period();
      n.loFree = () => sibsB()[sib];
      n.hiFree = () => sibsB()[sib];
      _bindSibling(trailA[k], n, bit);
      p = n;
    }
    return p;
  }

  /// [_walkTo] keyed by [keyLanes], 31 bits a lane, with no decomposition
  /// check of its own ([_walkPair] makes it on the lifted bits).
  (_Period, List<Wire>) _walkToKey(_Period leaf, List<Wire> keyLanes, int depth, List<List<int>> Function() siblings, List<_Period> trail) {
    const lb = NullifierTree.laneBits;
    if (depth != lb * keyLanes.length) throw ArgumentError('$lb bits per key lane');
    var p = leaf;
    final bits = <Wire>[];
    for (int k = 0; k < depth; k++) {
      final sib = k, lane = keyLanes[k ~/ lb], sh = k % lb;
      p.swapBitFn = () => (lane.lanes[0] >> sh) & 1;
      final w = Wire(1, 'kbit$k', () => [(lane.lanes[0] >> sh) & 1]);
      p.swapWire = w;
      bits.add(w);
      final n = _period();
      n.loFree = () => siblings()[sib];
      n.hiFree = () => siblings()[sib];
      trail.add(n);
      p = n;
    }
    return (p, bits);
  }

  /// The nullifier insertions of a digest-mode node (see [NullifierSegment]):
  /// absorbs the roots and each transfer's chunks, continuing the chain,
  /// then walks every nullifier from the empty leaf to `H(0 ‖ real · nf)`
  /// over one path, so a dummy writes the empty leaf back and leaves the
  /// root as it was. Returns the chain's last period.
  _Period _nullifierSegment(int transfers) {
    NullifierSegment seg() => nullifiers!;
    var p = _cur = _absorb(free: () => seg().before);
    final before8 = _hi8(p, 'nfBefore');
    p = _cur = _absorb(free: () => seg().after);
    final after8 = _hi8(p, 'nfAfter');
    final ins = <(Wire, Wire, Wire)>[];
    for (int t = 0; t < transfers; t++) {
      final hw = <(Wire, Wire)>[];
      for (int c = 0; c < NullifierSegment.chunks.length; c++) {
        final tt = t, cc = c;
        p = _cur = _absorb(free: () => seg().transferChunks[tt][cc]);
        hw.add(_hiWires(p, 'nfc${t}_$c'));
      }
      final flags = hw[2].$1;
      ins.add((hw[0].$1, hw[0].$2, f.limb(flags, NullifierSegment.real1Limb)));
      ins.add((hw[1].$1, hw[1].$2, f.limb(flags, NullifierSegment.real2Limb)));
    }
    final last = p;
    var root = before8;
    for (int i = 0; i < ins.length; i++) {
      final (a, b, real) = ins[i];
      final ii = i;
      final end = _walkPair(_emptyPeriod(1), root, () => _leaf([f.mul(a, real), f.mul(b, real)]), NullifierTree.depth,
          () => seg().paths[ii],
          keyLanes: [f.limb(a, 0), f.limb(a, 1)]);
      if (i == ins.length - 1) {
        end.digCons8 = after8;
        after8.uses++;
      } else {
        root = _digestWire(end);
      }
    }
    return last;
  }

  /// Both halves of chained period [p]'s input as K4 wires: (lo 0..3, lo
  /// 4..7, hi 8..11, hi 12..15).
  (Wire, Wire, Wire, Wire) _inputHalves(_Period p, String label) {
    List<int> lanes(int from) {
      _simulate(p);
      return p._input!.sublist(from, from + 4);
    }

    final la = Wire(4, '${label}la', () => lanes(0)), lb = Wire(4, '${label}lb', () => lanes(4));
    final ha = Wire(4, '${label}ha', () => lanes(8)), hb = Wire(4, '${label}hb', () => lanes(12));
    lb.tagOffset = VerifierAir.tagP2Offset;
    hb.tagOffset = VerifierAir.tagP2Offset;
    p.prodLoA = la;
    p.prodLoB = lb;
    p.prodNextA = ha;
    p.prodNextB = hb;
    return (la, lb, ha, hb);
  }

  /// The sibling of chained periods [pa] and [pb] is the same: with d the
  /// difference of their halves, d_hi + bit (d_lo - d_hi) = 0 per K4 half.
  void _bindSibling(_Period pa, _Period pb, Wire bit) {
    final (aLa, aLb, aHa, aHb) = _inputHalves(pa, 'pwA${pa.index}');
    final (bLa, bLb, bHa, bHb) = _inputHalves(pb, 'pwB${pb.index}');
    for (final (lo1, lo2, hi1, hi2) in [(aLa, bLa, aHa, bHa), (aLb, bLb, aHb, bHb)]) {
      final dHi = f.sub(hi1, hi2), dLo = f.sub(lo1, lo2);
      assertZero(f.add(dHi, f.mul(f.sub(dLo, dHi), bit)));
    }
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
  /// A period's high input half as two K4 wires produced at row 1 (lanes
  /// 8..11, 12..15), leaving row 0's operands free for a K8 wire of the same
  /// half (a leaf, or the nullifier chain).
  (Wire, Wire) _hiHalvesNext(_Period p, String label) {
    if (p.prodNextA != null) return (p.prodNextA!, p.prodNextB!);
    List<int> lanes(int from) {
      _simulate(p);
      return p._input!.sublist(from, from + 4);
    }

    final a = Wire(4, '${label}a', () => lanes(8)), b = Wire(4, '${label}b', () => lanes(12));
    b.tagOffset = VerifierAir.tagP2Offset;
    p.prodNextA = a;
    p.prodNextB = b;
    return (a, b);
  }

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
  /// period, the public lanes and the chunk wires (two K4 per chunk).
  (_Period, List<Wire>, List<Wire>) _statementFree(int i, Wire? preRoot) {
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
    return (_cur!, _pubLanes(air, chunkWires), chunkWires);
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
  /// public columns except the tree's free chunks, which are witness (from
  /// [spendLanes]); padding and root chunks zero. Returns the chunk
  /// periods (by chunk) and the last period.
  (List<_Period>, _Period) _statementPinned(int n) {
    final t = tree!;
    final c0 = t.pinnedChunks * n;
    final chunks = <_Period>[];
    var pinned = 0;
    for (int c = 0; c < Poseidon2Transcript.statementPeriods - 1; c++) {
      if (c >= t.spendChunks) {
        _cur = _absorb(zero: true);
      } else if (t.freeChunks.contains(c)) {
        List<int> lanes() => [for (int j = 0; j < 8; j++) 8 * c + j < t.spendPublics ? spendLanes![n][8 * c + j] : 0];
        chunks.add(c == 0 ? _fresh(free: lanes) : (_cur = _absorb(free: lanes)));
      } else {
        chunks.add(_pinnedChunk(c0 + pinned, chained: c > 0));
        pinned++;
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
      // the slot is empty under the root so far, then the subtree in place
      // over the same siblings
      final end = _walkPair(_emptyPeriod(NoteCommitmentTree.subtreeDepth), before, () => _subtree(subLeaves),
          AggregationTree.mainDepth, siblings,
          idx: idx,
          siblingsB: forgedAfterPaths == null ? null : () => forgedAfterPaths![s]);
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
      final anchors = <(Wire, Wire, Wire, Wire)>[];
      for (int i = 0; i < shapes.length; i++) {
        final preRoot = shapes[i].R > 0 ? hint8('preRoot$i', () => pfAt(i).preRoot) : null;
        final (st, pubLane, chunks) = _statementFree(i, preRoot);
        digests.add(_digestWire(st));
        final r = ring;
        if (r != null) anchors.add((chunks[2 * r.anchorChunk], chunks[2 * r.anchorChunk + 1], pubLane[r.real1], pubLane[r.real2]));
        _verifyInner(i, pubLane, preRoot);
      }
      var last = _chain(digests);
      final r = ring;
      if (r != null) {
        // the ring's roots continue the chain, so they are part of the
        // public input; their halves are wires the anchor checks read
        final ringA = <Wire>[], ringB = <Wire>[];
        for (int k = 0; k < r.size; k++) {
          final kk = k;
          last = _cur = _absorb(free: () => ringLanes![kk]);
          final (a, b) = _hiWires(last, 'ring$k');
          ringA.add(a);
          ringB.add(b);
        }
        for (int i = 0; i < anchors.length; i++) {
          final (a0, b0, real1, real2) = anchors[i];
          _anchorInRing(i, a0, b0, real1, real2, ringA, ringB);
        }
      }
      if (nullifierTransfers > 0) last = _nullifierSegment(nullifierTransfers);
      last.pinPub = true;
    } else {
      _buildWide();
    }
    _finish();
  }

  /// Spend [i]'s anchor (K4 halves [a0], [b0]) is one of the ring's roots
  /// unless neither input is real. A selector bit per root, from a hint,
  /// picks the root: the bits sum to r = real1 OR real2, and the selected
  /// root's halves equal r times the anchor's. So a real spend with a stale
  /// anchor has no selector to set, and no witness; a spend of two dummies
  /// sets none and its anchor is unconstrained, as on chain.
  void _anchorInRing(int i, Wire a0, Wire b0, Wire real1, Wire real2, List<Wire> ringA, List<Wire> ringB) {
    final r = f.sub(f.add(real1, real2), f.mul(real1, real2));
    int chosen() {
      if (r.lanes[0] == 0) return -1;
      final anchor = [...a0.lanes, ...b0.lanes];
      for (int k = 0; k < ringA.length; k++) {
        final root = ringLanes![k];
        var same = true;
        for (int j = 0; j < 8 && same; j++) {
          same = root[j] == anchor[j];
        }
        if (same) return k;
      }
      return -1;
    }

    final sel = [for (int k = 0; k < ringA.length; k++) bitHint('anchor${i}_$k', () => chosen() == k ? 1 : 0)];
    var sum = sel[0], sa = f.mul(sel[0], ringA[0]), sb = f.mul(sel[0], ringB[0]);
    for (int k = 1; k < sel.length; k++) {
      sum = f.add(sum, sel[k]);
      sa = f.add(sa, f.mul(sel[k], ringA[k]));
      sb = f.add(sb, f.mul(sel[k], ringB[k]));
    }
    assertEq(sum, r);
    assertEq(sa, f.mul(r, a0));
    assertEq(sb, f.mul(r, b0));
  }

  /// Every used receipt slot is exactly one transfer's first output
  /// commitment and signed amount, in BSV, with no real input; no transfer
  /// backs two. A selector bit per (slot, transfer) from a hint picks it, as
  /// [_anchorInRing] picks a root: the bits of a slot sum to its used flag,
  /// and each selected quantity summed equals the slot's.
  void _receipts(AggregationTree t, List<List<_Period>> stChunks, int firstChunk) {
    final n = t.transfers;
    final cmA = <Wire>[], cmB = <Wire>[], lo = <Wire>[], hi = <Wire>[], real = <Wire>[], asset = <Wire>[];
    for (int k = 0; k < n; k++) {
      final (ca, cb) = _hiHalvesNext(stChunks[k][ReceiptSlot.cmChunk], 'rc$k');
      final (aa, _) = _hiHalvesNext(stChunks[k][ReceiptSlot.amountChunk], 'ra$k');
      final (fa, fb) = _hiHalvesNext(stChunks[k][ReceiptSlot.flagChunk], 'rf$k');
      cmA.add(ca);
      cmB.add(cb);
      lo.add(f.limb(aa, ReceiptSlot.loLimb));
      hi.add(f.limb(aa, ReceiptSlot.hiLimb));
      real.add(f.add(f.limb(fa, ReceiptSlot.real1Limb), f.limb(fa, ReceiptSlot.real2Limb)));
      asset.add(fb);
    }
    final bsv = f.constQ(QM31.fromLimbs(PoolHash.bsvAsset[0], PoolHash.bsvAsset[1], PoolHash.bsvAsset[2], PoolHash.bsvAsset[3]));
    final perTransfer = List<Wire?>.filled(n, null);
    for (int r = 0; r < t.receiptSlots; r++) {
      final (sA, sB) = _hiHalvesNext(_pinnedChunk(firstChunk + 2 * r), 'slotCm$r');
      final (vA, _) = _hiHalvesNext(_pinnedChunk(firstChunk + 2 * r + 1), 'slotV$r');
      final used = f.limb(vA, ReceiptSlot.usedLane);
      assertZero(f.sub(f.mul(used, used), used));
      final rr = r;
      final sel = [
        for (int k = 0; k < n; k++)
          bitHint('rs${r}_$k', () => rr < receiptTransfers.length && receiptTransfers[rr] == k ? 1 : 0)
      ];
      Wire sum(Wire Function(int) term) {
        var acc = term(0);
        for (int k = 1; k < n; k++) {
          acc = f.add(acc, term(k));
        }
        return acc;
      }

      assertEq(sum((k) => sel[k]), used);
      assertEq(sum((k) => f.mul(sel[k], cmA[k])), sA);
      assertEq(sum((k) => f.mul(sel[k], cmB[k])), sB);
      assertEq(sum((k) => f.mul(sel[k], lo[k])), f.limb(vA, ReceiptSlot.loLane));
      assertEq(sum((k) => f.mul(sel[k], hi[k])), f.limb(vA, ReceiptSlot.hiLane));
      assertZero(sum((k) => f.mul(sel[k], real[k])));
      assertEq(sum((k) => f.mul(sel[k], asset[k])), f.mul(used, bsv));
      for (int k = 0; k < n; k++) {
        perTransfer[k] = perTransfer[k] == null ? sel[k] : f.add(perTransfer[k]!, sel[k]);
      }
    }
    for (final q in perTransfer) {
      if (t.receiptSlots > 1) assertZero(f.sub(f.mul(q!, q), q));
    }
  }

  void _buildWide() {
    final t = tree!;
    final digests0 = <Wire>[], leaves = <Wire>[];
    final stChunks = <List<_Period>>[];
    for (int n = 0; n < t.transfers; n++) {
      final (chunks, last) = _statementPinned(n);
      stChunks.add(chunks);
      digests0.add(_digestWire(last));
      for (final c in t.leafChunks) {
        leaves.add(_hi8(chunks[c], 'leaf${n}_$c'));
      }
    }
    // the round chunks and the commitment-tree update
    final r0 = _pinnedChunk(t.roundOffset ~/ 8), r1 = _pinnedChunk(t.roundOffset ~/ 8 + 1), r2 = _pinnedChunk(t.roundOffset ~/ 8 + 2);
    final (ia, _) = _hiWires(r2, 'round');
    // the ring, once per round: every level-1 digest absorbs it
    final ringWires = <Wire>[
      for (int k = 0; k < (t.ring?.size ?? 0); k++) _hi8(_pinnedChunk(t.roundOffset ~/ 8 + 3 + k), 'ring$k'),
    ];
    // the nullifier set's roots at the boundaries of the inserting level's
    // nodes: the round's two public ones at the ends, witness between, each
    // shared by the node that ends there and the node that starts there
    final nl = t.nullifierLevel;
    final nfWires = <Wire>[];
    if (nl != null) {
      final c0 = t.nullifierOffset ~/ 8; // pinned after the ring, so the public order holds
      final nodes = t.nodesAt(nl);
      nfWires.add(_hi8(_pinnedChunk(c0), 'nfBefore'));
      for (int k = 1; k < nodes; k++) {
        final kk = k;
        nfWires.add(hint8('nfMid$k', () => nullifierRoots![kk]));
      }
      nfWires.add(_hi8(_pinnedChunk(c0 + 1), 'nfAfter'));
    }
    // the receipt slots, pinned after the nullifier roots
    if (t.receiptSlots > 0) _receipts(t, stChunks, t.receiptOffset ~/ 8);

    List<Wire> nullifierTail(int m) {
      final per = t.transfersPerNode(nl!);
      return [
        nfWires[m],
        nfWires[m + 1],
        for (int n = per * m; n < per * (m + 1); n++)
          for (final c in NullifierSegment.chunks) _hi8(stChunks[n][c], 'nfc${n}_$c'),
      ];
    }

    _treeUpdate(leaves, _hi8(r0, 'rootBefore'), _hi8(r1, 'rootAfter'), f.limb(ia, 0));
    var digests = digests0;
    for (int l = 0; l < t.depth; l++) {
      final (shape, preRoot) = t.levels[l];
      final next = <Wire>[];
      final arity = t.arities[l];
      for (int m = 0; m < digests.length ~/ arity; m++) {
        final d = _digestWire(_chain(
            [...digests.sublist(arity * m, arity * (m + 1)), if (l == 0) ...ringWires, if (l == nl) ...nullifierTail(m)]));
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
      if (p.hiWire8Next != null || p.prodNextA != null) _claimed[r0 + 1] = true;
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
      if (p.prodLoA != null) {
        if (p.fresh || p.hiA != null || p.hiWire8 != null || p.prodHiA != null || p.prodHi8 != null) {
          throw StateError('period ${p.index}: row 0 operands already taken');
        }
        columns.set(VerifierProgramColumns.inLoAB, r0, 1);
        if (p.prodLoA!.uses > 0) _produceAt(r0, p.prodLoA!, VerifierProgramColumns.p1a4);
        if (p.prodLoB!.uses > 0) _produceAt(r0, p.prodLoB!, VerifierProgramColumns.p2en);
        _pinned.add((r0, p.prodLoA!, p.prodLoB!));
      }
      if (p.prodNextA != null) {
        if (p.hiWire8Next != null) throw StateError('period ${p.index}: row 1 operands already taken');
        columns.set(VerifierProgramColumns.inHiNext, r0, 1);
        if (p.prodNextA!.uses > 0) _produceAt(r0 + 1, p.prodNextA!, VerifierProgramColumns.p1a4);
        if (p.prodNextB!.uses > 0) _produceAt(r0 + 1, p.prodNextB!, VerifierProgramColumns.p2en);
        _pinned.add((r0 + 1, p.prodNextA!, p.prodNextB!));
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
