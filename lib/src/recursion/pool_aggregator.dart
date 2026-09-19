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
import '../script_gen/pool_spend_air.dart';
import 'verifier_air.dart';
import 'verifier_program.dart';

/// The coordinator's aggregation: [arity]^depth spend proofs (Poseidon2
/// flavour) folded level by level into verifier proofs of the same
/// flavour, then the top proof re-proved by the wide root program (SHA256
/// flavour) whose public inputs are every transfer's publics and the round
/// chunks. One compiled program per level; the levels' preprocessed roots
/// are constants of the root program.
class PoolAggregation {
  final StarkParams spendP;
  final List<StarkParams> levelP;
  final List<int> levelLog;
  final StarkParams rootP;
  final int rootLog;
  final int arity;
  static const p2 = Poseidon2ProofHash();
  static const sha = Sha256ProofHash();

  late final List<VerifierProgram> levels;
  late final List<InnerShape> levelShapes;
  late final List<List<int>> preRoots;
  late final AggregationTree tree;
  late final VerifierProgram root;

  PoolAggregation({
    required this.spendP,
    required this.levelP,
    required this.levelLog,
    required this.rootP,
    required this.rootLog,
    this.arity = 2,
  }) {
    if (levelP.length != levelLog.length || levelP.isEmpty) throw ArgumentError('one trace size per level');
    var shape = InnerShape(spendP, PoolSpendAir.air(PoolPublicInputs.zero()));
    levels = [];
    levelShapes = [];
    preRoots = [];
    for (int l = 0; l < levelP.length; l++) {
      final prog = VerifierProgram.compileAll(List.filled(arity, shape), levelLog[l]);
      final air = prog.air(List.filled(VerifierAir.numPublicLanes, 0));
      levels.add(prog);
      shape = InnerShape(levelP[l], air);
      levelShapes.add(shape);
      preRoots.add(PreCommitment.root(air, levelP[l], p2));
    }
    tree = AggregationTree(PoolPublicInputs.count, const [], [for (int l = 0; l < levelP.length; l++) (levelShapes[l], preRoots[l])], arity);
    root = VerifierProgram.compileWide(tree, rootLog);
  }

  int get transfers => tree.transfers;
  int get widePublicsCount => tree.roundOffset + 8 * AggregationTree.roundChunks;

  /// The root verifier AIR for the wide [publics] (any of the right length
  /// gives the same locking script).
  VerifierAir rootAir(List<int> publics) => root.air(publics);

  /// Aggregate the transfers' [proofs] (over [publics], in order) into the
  /// root proof; [rootBefore], [rootAfter], [index] and the subtree
  /// [paths] describe the round's tree update. Returns the root proof and
  /// the wide publics it is bound to.
  (StarkProof, List<int>) aggregate(List<PoolPublicInputs> publics, List<StarkProof> proofs,
      {required List<int> rootBefore,
      required List<int> rootAfter,
      required int index,
      required List<List<List<int>>> paths,
      Random? rng,
      bool verbose = false}) {
    if (publics.length != transfers || proofs.length != transfers) throw ArgumentError('$transfers transfers');
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
      final prog = levels[l];
      final nextShapes = <InnerShape>[], nextProofs = <StarkProof>[], nextDigests = <List<int>>[];
      for (int m = 0; m < curProofs.length ~/ arity; m++) {
        final lo = arity * m, hi = lo + arity;
        final rows = prog.witnessAll(curProofs.sublist(lo, hi), shapes: shapes.sublist(lo, hi));
        final air = prog.air(VerifierProgram.nodeDigest(digests.sublist(lo, hi)));
        nextProofs.add(StarkProver.prove(levelP[l], air, rows, rng: rng, hash: p2));
        nextShapes.add(InnerShape(levelP[l], air));
        nextDigests.add(VerifierProgram.statementDigest(air, preRoots[l]));
      }
      shapes = nextShapes;
      curProofs = nextProofs;
      digests = nextDigests;
      lap('level ${l + 1}: ${curProofs.length} proofs');
    }
    final wide = tree.widePublics([for (final p in publics) p.toLanes()], rootBefore: rootBefore, rootAfter: rootAfter, index: index);
    final rows = root.witnessAll(curProofs, shapes: shapes, widePublics: wide, subtreePaths: paths);
    final proof = StarkProver.prove(rootP, root.air(wide), rows, rng: rng, hash: sha);
    lap('root');
    return (proof, wide);
  }
}
