import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// The aggregation with one arity and one parameter set per level: a
/// 3 × 2 tree at small parameters proved end to end, and the production
/// throughput plan compiled (dry run) to check that every level fits.
void main() {
  final rng = Random(23);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const sha = Sha256ProofHash();
  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const l1 = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const l2 = StarkParams(logTrace: 17, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const rootP = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  test('a 3 x 2 tree with its own parameters per level proves and verifies', () {
    final sw = Stopwatch()..start();
    final agg = PoolAggregation(
        spendP: spendP,
        levelSpec: const [
          AggregationLevel(params: l1, logTrace: 16, arity: 3),
          AggregationLevel(params: l2, logTrace: 17, arity: 2),
        ],
        rootP: rootP,
        rootLog: 16);
    expect(agg.transfers, 6);
    expect(agg.tree.arities, [3, 2]);
    print('  compiled in ${sw.elapsedMilliseconds} ms: periods ${agg.periods}');
    sw.reset();
    final publics = <PoolPublicInputs>[], proofs = <StarkProof>[];
    for (int n = 0; n < agg.transfers; n++) {
      final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
      final oa = OutputNote(pkd: lanes(8), value: 1000 + n, rho: lanes(3), rcm: lanes(4));
      final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
      final w = PoolSpendAir.witness(da, db, oa, ob, -(1025 + n), anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
      publics.add(w.publics);
      proofs.add(StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: rng, hash: p2));
    }
    final spendPubs = [for (final p in publics) p.toLanes()];
    final cmTree = NoteCommitmentTree();
    final rootBefore = cmTree.root, j = cmTree.nextSubtree;
    final paths = <List<List<int>>>[];
    for (int s = 0; s < agg.tree.subtrees; s++) {
      paths.add(cmTree.subtreePath(j + s));
      cmTree.appendSubtree([for (final l in agg.tree.subtreeLeavesOf(spendPubs, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final (proof, wide) = agg.aggregate(publics, proofs, rootBefore: rootBefore, rootAfter: cmTree.root, index: j, paths: paths, rng: rng, verbose: true);
    print('  aggregated in ${sw.elapsedMilliseconds} ms');
    expect(wide.length, agg.widePublicsCount);
    expect(StarkVerifierRef(rootP, agg.rootAir(wide), hash: sha).verify(proof), isTrue);
    // the statements are bound: another transfer's publics do not verify
    final bad = [...wide]..[56 + PoolPublicInputs.idxNf1] ^= 1;
    expect(() => StarkVerifierRef(rootP, agg.rootAir(bad), hash: sha).verify(proof), throwsA(isA<VerificationFailure>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('the throughput plan compiles: 256 transfers, every level fits', () {
    final sw = Stopwatch()..start();
    final agg = PoolAggregation.throughput(dryRun: true);
    expect(agg.transfers, 256);
    final periods = agg.periods;
    print('  compiled in ${sw.elapsedMilliseconds} ms: ${agg.transfers} transfers, ${agg.widePublicsCount} public lanes, periods $periods');
    for (final (used, cap) in periods) {
      expect(used, lessThanOrEqualTo(cap));
    }
  }, timeout: const Timeout(Duration(minutes: 20)));
}
