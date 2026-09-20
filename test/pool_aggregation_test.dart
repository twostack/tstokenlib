import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/prover_pool.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// The aggregation with one arity and one parameter set per level: a
/// 3 × 2 tree at small parameters proved end to end, the same round with
/// level 1 handed to a node prover instead of proved inline, and the
/// production throughput plan compiled (dry run) to check that every level
/// fits.
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

  test('a 3 x 2 tree with its own parameters per level proves and verifies', () async {
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
    final ring = [rootBefore, lanes(8), lanes(8), lanes(8)];
    final (proof, wide) = await agg.aggregate(publics, proofs,
        rootBefore: rootBefore, rootAfter: cmTree.root, index: j, paths: paths, ring: ring, rng: rng, verbose: true);
    print('  aggregated in ${sw.elapsedMilliseconds} ms');
    expect(wide.length, agg.widePublicsCount);
    expect(wide.sublist(agg.tree.ringOffset, agg.tree.ringOffset + 8), rootBefore);
    expect(StarkVerifierRef(rootP, agg.rootAir(wide), hash: sha).verify(proof), isTrue);
    // the statements are bound: another transfer's publics do not verify
    final bad = [...wide]..[PoolPublicInputs.reducedCount + PoolPublicInputs.rIdxNf1] ^= 1;
    expect(() => StarkVerifierRef(rootP, agg.rootAir(bad), hash: sha).verify(proof), throwsA(isA<VerificationFailure>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('level 1 through a node prover gives the same round as proving it inline', () async {
    final agg = PoolAggregation(
        spendP: spendP,
        levelSpec: const [
          AggregationLevel(params: l1, logTrace: 16, arity: 2),
          AggregationLevel(params: l2, logTrace: 17, arity: 2),
        ],
        rootP: rootP,
        rootLog: 16);
    expect(agg.transfers, 4);
    final publics = <PoolPublicInputs>[], proofs = <StarkProof>[];
    for (int n = 0; n < agg.transfers; n++) {
      final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
      final oa = OutputNote(pkd: lanes(8), value: 500 + n, rho: lanes(3), rcm: lanes(4));
      final ob = OutputNote(pkd: lanes(8), value: 9, rho: lanes(3), rcm: lanes(4));
      final w = PoolSpendAir.witness(da, db, oa, ob, -(509 + n), anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
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
    final rootAfter = cmTree.root;
    final ring = [rootBefore, lanes(8), lanes(8), lanes(8)];
    Future<(StarkProof, List<int>)> round({NodeProver? level1}) => agg.aggregate(publics, proofs,
        rootBefore: rootBefore, rootAfter: rootAfter, index: j, paths: paths, ring: ring, rng: Random(7), level1: level1);

    final sw = Stopwatch()..start();
    final (inlineProof, inlineWide) = await round();
    print('  inline in ${sw.elapsedMilliseconds} ms');
    expect(StarkVerifierRef(rootP, agg.rootAir(inlineWide), hash: sha).verify(inlineProof), isTrue);

    // the local prover is the same work behind the interface: the levels are
    // not zero-knowledge, so the round is reproduced proof for proof
    sw.reset();
    final (localProof, localWide) = await round(level1: LocalNodeProver(program: agg.levels[0]));
    print('  through a local node prover in ${sw.elapsedMilliseconds} ms');
    expect(localWide, inlineWide);
    expect(localProof.traceRoot, inlineProof.traceRoot);

    // an honest prover that only ever sees the job's bytes
    sw.reset();
    final pool = ProverPool(program: agg.levels[0], provers: [_RemoteProver()]);
    final (pooledProof, pooledWide) = await round(level1: pool);
    print('  through one prover in ${sw.elapsedMilliseconds} ms: ${pool.outcomes}');
    expect(pool.pooledNodes, 2);
    expect(pool.localNodes, 0);
    expect(pooledWide, inlineWide);
    expect(pooledProof.traceRoot, inlineProof.traceRoot);
    expect(StarkVerifierRef(rootP, agg.rootAir(pooledWide), hash: sha).verify(pooledProof), isTrue);

    // a prover that does not vouch for what it returns is checked here, and
    // its rubbish is replaced by the coordinator's own proof
    sw.reset();
    final (badProof, badWide) = await round(level1: _JunkProver());
    print('  with a bad unchecked prover in ${sw.elapsedMilliseconds} ms');
    expect(badWide, inlineWide);
    expect(badProof.traceRoot, inlineProof.traceRoot);
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

/// A prover that sees only the encoded job, as a remote one would: it
/// decodes, compiles the level program itself, proves, and answers over the
/// proof codec.
class _RemoteProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) async {
    final received = NodeJob.decode(job.encode());
    final program = received.compile();
    final codec = received.nodeCodec(program);
    return codec.decode(codec.encode(LocalNodeProver(program: program).proveNow(received)));
  }
}

/// A prover that answers instantly with something that is not a proof and
/// does not claim to have checked it.
class _JunkProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) async => StarkProof(
      traceRoot: List.filled(8, 0),
      compRoot: List.filled(8, 0),
      zHint: QM31.one,
      traceAtZ: const [],
      traceAtZg: const [],
      compAtZ: const [],
      friRoots: const [],
      finalCoefs: const [],
      nonce: const [0],
      queries: const []);
}
