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

import 'dart:math';
import '../crypto/proof_hash.dart';
import '../crypto/stark_prover.dart';
import '../crypto/stark_prover_ref.dart';
import '../crypto/stark_verifier_ref.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_legacy_script_gen.dart' show PP1SpLegacyHeader;
import 'prover_pool.dart';
import 'verifier_air.dart';
import 'verifier_program.dart';

/// One level of the aggregation tree: its nodes are verifier proofs on
/// 2^[logTrace] rows proved with [params], each verifying [arity] proofs
/// of the level below (spends at level 1).
class AggregationLevel {
  final StarkParams params;
  final int logTrace;
  final int arity;
  const AggregationLevel({required this.params, required this.logTrace, required this.arity});
}

/// The coordinator's aggregation: spend proofs (Poseidon2 flavour) folded
/// level by level into verifier proofs of the same flavour, each level with
/// its own arity, trace size and parameters, then the top proof re-proved
/// by the wide root program (SHA256 flavour) whose public inputs are every
/// transfer's publics and the round chunks. One compiled program per level;
/// the levels' preprocessed roots are constants of the root program.
///
/// Inner proofs never reach the chain, so their parameters follow prover
/// throughput (see [throughput]): low blowup with more queries costs the
/// prover little and the next circuit more periods, and the trade-off is
/// won by wide, low-blowup nodes. Only the root is verified by a script, so
/// only its parameters answer to the on-chain price per query; the levels
/// below it narrow the trace back toward the root's size while keeping the
/// prover's blowup low.
class PoolAggregation {
  final StarkParams spendP;
  final List<AggregationLevel> levelSpec;
  final StarkParams rootP;
  final int rootLog;
  static const p2 = Poseidon2ProofHash();
  static const sha = Sha256ProofHash();

  late final List<VerifierProgram> levels;
  late final List<InnerShape> levelShapes;
  late final List<List<int>> preRoots;
  late final AggregationTree tree;
  late final VerifierProgram root;

  /// The anchor check level 1 makes: each real spend's anchor is one of the
  /// state header's four roots, which the round takes as public input once.
  static const anchorRing = AnchorRing.pool;

  /// Whether level 1 checks anchors (production: yes; off only to size the
  /// check, see the design record).
  final bool anchorCheck;

  /// Compiles every level's program and the root's. With [dryRun] the
  /// levels' preprocessed roots are zeros instead of real commitments
  /// (gigabytes at production size), which is enough to size the programs
  /// (periods, transfers) but not to prove.
  PoolAggregation(
      {required this.spendP,
      required this.levelSpec,
      required this.rootP,
      required this.rootLog,
      bool dryRun = false,
      this.anchorCheck = true}) {
    if (levelSpec.isEmpty || levelSpec.any((l) => l.arity < 1)) throw ArgumentError('at least one level, arities >= 1');
    assert(anchorRing.size == PP1SpLegacyHeader.ringSize, 'the in-circuit ring is the header\'s');
    var shape = InnerShape(spendP, PoolSpendAir.air(PoolPublicInputs.zero()));
    levels = [];
    levelShapes = [];
    preRoots = [];
    for (int l = 0; l < levelSpec.length; l++) {
      final level = levelSpec[l];
      final prog = VerifierProgram.compileAll(List.filled(level.arity, shape), level.logTrace, ring: l == 0 ? ring : null);
      final air = prog.air(List.filled(VerifierAir.numPublicLanes, 0));
      levels.add(prog);
      shape = InnerShape(level.params, air);
      levelShapes.add(shape);
      preRoots.add(dryRun ? List.filled(8, 0) : PreCommitment.root(air, level.params, p2));
    }
    tree = AggregationTree(PoolPublicInputs.count, const [], [for (int l = 0; l < levelSpec.length; l++) (levelShapes[l], preRoots[l])],
        [for (final l in levelSpec) l.arity],
        ring: ring);
    root = VerifierProgram.compileWide(tree, rootLog);
  }

  /// The ring check as configured, null when off.
  AnchorRing? get ring => anchorCheck ? anchorRing : null;

  /// The same [arity] and one parameter set per level, as the first
  /// aggregated rounds were built.
  PoolAggregation.uniform({
    required StarkParams spendP,
    required List<StarkParams> levelP,
    required List<int> levelLog,
    required StarkParams rootP,
    required int rootLog,
    int arity = 2,
    bool dryRun = false,
  }) : this(spendP: spendP, levelSpec: _uniformSpec(levelP, levelLog, arity), rootP: rootP, rootLog: rootLog, dryRun: dryRun);

  static List<AggregationLevel> _uniformSpec(List<StarkParams> levelP, List<int> levelLog, int arity) {
    if (levelP.length != levelLog.length) throw ArgumentError('one trace size per level');
    return [for (int l = 0; l < levelP.length; l++) AggregationLevel(params: levelP[l], logTrace: levelLog[l], arity: arity)];
  }

  // ---- the production plan, sized for prover throughput ----

  /// Spend proofs for aggregation: blowup 256 with 11 queries (about 104
  /// bits with the 16-bit grind), 5 s to prove in the wallet, 2,453 periods
  /// to verify in-circuit against 3,364 at the on-chain parameters.
  static const spendThroughputParams =
      StarkParams(logTrace: PoolSpendAir.logTrace, logBlowup: 8, logExpand: 3, logFinal: 13, numQueries: 11, grindBytes: 2, zkRandomizers: 128);

  /// Inner verifier proofs: blowup 8 with 30 queries at 2^20 and 2^21.
  static const innerParams20 = StarkParams(logTrace: 20, logBlowup: 3, logExpand: 3, logFinal: 8, numQueries: 30, grindBytes: 2);
  static const innerParams21 = StarkParams(logTrace: 21, logBlowup: 3, logExpand: 3, logFinal: 8, numQueries: 30, grindBytes: 2);

  /// The root's parameters: blowup 32 with 18 queries, because the root is
  /// the proof a script verifies and the on-chain verifier is priced per
  /// query and per FRI fold.
  static const rootParams19 = StarkParams(logTrace: 19, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 18, grindBytes: 2);

  /// The narrowing levels below the root: blowup 16 with 23 queries.
  ///
  /// These levels are never verified by a script, only by the level above,
  /// so nothing here is priced per query; they took the root's blowup 32
  /// by inheritance and paid for it in memory. A 2^20 trace at blowup 32
  /// commits on 2^25 and one node peaks at 22.4 GB; at blowup 16 it commits
  /// on 2^24 and peaks at 11.5 GB, proves in 13.5 s instead of 20.3 s and
  /// is two bits sounder (92 + 16 against 90 + 16). What it costs is paid
  /// by the level above, which verifies 23 queries instead of 18: level 4
  /// needs 15,636 of its 16,384 periods and the root 11,576.
  ///
  /// The final layer is larger than the blowup-32 levels' (2^7 and 2^6
  /// coefficients) because the level above verifies one fewer FRI fold per
  /// query for every step the final layer grows, which is what buys the
  /// room for the extra queries.
  static const narrowParams20 = StarkParams(logTrace: 20, logBlowup: 4, logExpand: 3, logFinal: 11, numQueries: 23, grindBytes: 2);
  static const narrowParams19 = StarkParams(logTrace: 19, logBlowup: 4, logExpand: 3, logFinal: 10, numQueries: 23, grindBytes: 2);

  /// The 256-transfer plan (16 × 4 × 2 × 2): level 1 on 2^20 folds 16
  /// spends (34 s for 13 measured), level 2 on 2^21 folds 4 level-1 proofs,
  /// then two narrowing levels (2^20 verifying two level-2 proofs, 2^19
  /// verifying two of those) so the root on 2^19 can verify the top proof
  /// beside the 256 statements. 24 nodes.
  static const throughputLevels = [
    AggregationLevel(params: innerParams20, logTrace: 20, arity: 16),
    AggregationLevel(params: innerParams21, logTrace: 21, arity: 4),
    AggregationLevel(params: narrowParams20, logTrace: 20, arity: 2),
    AggregationLevel(params: narrowParams19, logTrace: 19, arity: 2),
  ];

  static PoolAggregation throughput({bool dryRun = false}) => PoolAggregation(
      spendP: spendThroughputParams, levelSpec: throughputLevels, rootP: rootParams19, rootLog: 19, dryRun: dryRun);

  int get transfers => tree.transfers;
  int get depth => levelSpec.length;
  int get widePublicsCount => tree.roundOffset + 8 * tree.roundChunks;

  /// Periods used by each level's program and by the root's, of the
  /// periods its trace holds.
  List<(int, int)> get periods => [
        for (int l = 0; l < depth; l++) (levels[l].periodsUsed, 1 << (levelSpec[l].logTrace - 5)),
        (root.periodsUsed, 1 << (rootLog - 5)),
      ];

  /// The root verifier AIR for the wide [publics] (any of the right length
  /// gives the same locking script).
  VerifierAir rootAir(List<int> publics) => root.air(publics);

  /// Aggregate the transfers' [proofs] (over [publics], in order) into the
  /// root proof; [rootBefore], [rootAfter], [index] and the subtree
  /// [paths] describe the round's tree update and [ring] is the state's
  /// ring of roots every real spend's anchor must be in. Returns the root
  /// proof and the wide publics it is bound to.
  ///
  /// Level 1 is the bulk of the round and each of its nodes is independent,
  /// so it can be spread over the coordinator's machines: with [level1] every
  /// level-1 node becomes a [NodeJob] handed to that prover (a [ProverPool],
  /// or a [LocalNodeProver], which is what the inline path amounts to).
  /// Nothing is folded unverified: a prover that does not promise to have
  /// checked its own result ([NodeProver.verifies]) has it checked here
  /// against the digest this coordinator computed, and a proof that fails is
  /// replaced by one proved here.
  Future<(StarkProof, List<int>)> aggregate(List<PoolPublicInputs> publics, List<StarkProof> proofs,
      {required List<int> rootBefore,
      required List<int> rootAfter,
      required int index,
      required List<List<List<int>>> paths,
      required List<List<int>> ring,
      Random? rng,
      NodeProver? level1,
      bool verbose = false}) async {
    if (publics.length != transfers || proofs.length != transfers) throw ArgumentError('$transfers transfers');
    if (ring.length != anchorRing.size || ring.any((r) => r.length != 8)) throw ArgumentError('a ring of ${anchorRing.size} roots');
    final ringOrNull = anchorCheck ? ring : null;
    rng ??= Random();
    final sw = Stopwatch()..start();
    void lap(String what) {
      if (verbose) print('  [aggregate] $what ${sw.elapsedMilliseconds} ms');
      sw.reset();
    }

    var shapes = [for (final p in publics) InnerShape(spendP, PoolSpendAir.air(p))];
    var curProofs = proofs;
    var digests = [for (final s in shapes) VerifierProgram.statementDigest(s.air, const [])];
    for (int l = 0; l < levels.length; l++) {
      final prog = levels[l], level = levelSpec[l];
      final nextShapes = <InnerShape>[], nextProofs = <StarkProof>[], nextDigests = <List<int>>[];
      for (int m = 0; m < curProofs.length ~/ level.arity; m++) {
        final lo = level.arity * m, hi = lo + level.arity;
        final nodeDigest = VerifierProgram.nodeDigest(digests.sublist(lo, hi), ring: l == 0 ? ringOrNull : null);
        final air = prog.air(nodeDigest);
        StarkProof? pf;
        if (l == 0 && level1 != null) {
          final job = NodeJob(
              spendParams: spendP,
              levelParams: level.params,
              levelPreRoot: preRoots[0],
              publics: publics.sublist(lo, hi),
              proofs: curProofs.sublist(lo, hi),
              ring: ring,
              digest: nodeDigest);
          pf = await level1.prove(job);
          if (!level1.verifies && !_accepts(level.params, air, pf)) {
            if (verbose) print('  [aggregate] level 1 node $m did not verify; proving it here');
            pf = null;
          }
        }
        pf ??= StarkProver.prove(
            level.params, air, prog.witnessAll(curProofs.sublist(lo, hi), shapes: shapes.sublist(lo, hi), ring: l == 0 ? ringOrNull : null),
            rng: rng, hash: p2);
        nextProofs.add(pf);
        nextShapes.add(InnerShape(level.params, air));
        nextDigests.add(VerifierProgram.statementDigest(air, preRoots[l]));
      }
      shapes = nextShapes;
      curProofs = nextProofs;
      digests = nextDigests;
      lap('level ${l + 1}: ${curProofs.length} proofs');
    }
    final spendLanes = [for (final p in publics) p.toLanes()];
    final wide = tree.widePublics(spendLanes, rootBefore: rootBefore, rootAfter: rootAfter, index: index, ring: ringOrNull);
    final rows = root.witnessAll(curProofs, shapes: shapes, widePublics: wide, spendLanes: spendLanes, subtreePaths: paths);
    final proof = StarkProver.prove(rootP, root.air(wide), rows, rng: rng, hash: sha);
    lap('root');
    return (proof, wide);
  }

  /// Whether [pf] proves the statement [air] states, with any error counted
  /// as a refusal: a proof from outside is untrusted input.
  static bool _accepts(StarkParams params, VerifierAir air, StarkProof pf) {
    try {
      return StarkVerifierRef(params, air, hash: p2).check(pf) == null;
    } catch (_) {
      return false;
    }
  }
}
