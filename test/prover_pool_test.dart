import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/proof_codec.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/prover_pool.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// Level-1 nodes handed out as jobs: the job's own round trip, and the
/// pool against an honest prover, a prover that answers with another
/// node's proof, and a prover that never answers.
void main() {
  final rng = Random(59);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const levelP = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const arity = 2;

  (PoolPublicInputs, StarkProof) spend(int n) {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 700 + n, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 13, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -(713 + n), anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    return (w.publics, StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: rng, hash: p2));
  }

  /// [arity] spends, the compiled level program, and a job over them. The
  /// program is compiled once and shared: it depends on the shapes, not on
  /// the transfers' values.
  late VerifierProgram program;
  late List<NodeJob> jobs;

  setUpAll(() {
    final publics = <PoolPublicInputs>[], proofs = <StarkProof>[];
    for (int n = 0; n < 2 * arity; n++) {
      final (p, pf) = spend(n);
      publics.add(p);
      proofs.add(pf);
    }
    program = VerifierProgram.compileAll([for (int i = 0; i < arity; i++) InnerShape(spendP, PoolSpendAir.air(publics[i]))], levelP.logTrace,
        ring: AnchorRing.pool);
    final preRoot = PreCommitment.root(program.air(List.filled(8, 0)), levelP, p2);
    jobs = [
      for (int m = 0; m < 2; m++)
        (() {
          final ps = publics.sublist(arity * m, arity * (m + 1));
          final ring = [lanes(8), lanes(8), lanes(8), lanes(8)];
          final digest = VerifierProgram.nodeDigest([for (final p in ps) VerifierProgram.statementDigest(PoolSpendAir.air(p), const [])],
              ring: ring);
          return NodeJob(
              spendParams: spendP,
              levelParams: levelP,
              levelPreRoot: preRoot,
              publics: ps,
              proofs: proofs.sublist(arity * m, arity * (m + 1)),
              ring: ring,
              digest: digest);
        })()
    ];
  });

  test('a job round-trips through its encoding', () {
    final job = jobs[0];
    final bytes = job.encode();
    expect(bytes.length, job.bytes);
    print('  job ${bytes.length} B for ${job.arity} transfers');
    final back = NodeJob.decode(bytes);
    expect(back.arity, job.arity);
    expect(back.digest, job.digest);
    expect(back.ring, job.ring);
    expect(back.levelPreRoot, job.levelPreRoot);
    expect(back.levelParams.logTrace, job.levelParams.logTrace);
    expect(back.spendParams.numQueries, job.spendParams.numQueries);
    expect([for (final p in back.publics) p.toLanes()], [for (final p in job.publics) p.toLanes()]);
    expect(back.encode(), bytes);
    expect(back.derivedDigest(), job.digest);
    // a decoded job proves the same node
    expect(LocalNodeProver(program: program).proveNow(back).traceRoot,
        LocalNodeProver(program: program).proveNow(job).traceRoot);
    expect(() => NodeJob.decode(Uint8List.sublistView(bytes, 0, bytes.length - 4)), throwsA(isA<ProofCodecException>()));
    expect(() => NodeJob.decode(Uint8List.fromList([...bytes, 0, 0, 0, 0])), throwsA(isA<ProofCodecException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('the pool takes an honest prover, refuses a wrong one, and outlasts a silent one', () async {
    final job = jobs[0], other = jobs[1];
    final honestProof = LocalNodeProver(program: program).proveNow(job);
    final otherProof = LocalNodeProver(program: program).proveNow(other);

    final honest = _FixedProver(honestProof);
    var s = ProverPool(program: program, provers: [honest]);
    expect((await s.prove(job)).traceRoot, honestProof.traceRoot);
    expect(s.pooledNodes, 1);
    expect(s.localNodes, 0);

    // a valid proof, but of the other node: the digest it is bound to is not this job's
    s = ProverPool(program: program, provers: [_FixedProver(otherProof)]);
    final fromWrong = await s.prove(job);
    expect(fromWrong.traceRoot, honestProof.traceRoot);
    expect(s.localNodes, 1);
    expect(s.outcomes.single.fallback, 'rejected');
    expect(s.accepts(job, otherProof), isFalse);
    expect(s.accepts(other, otherProof), isTrue);

    // a proof that is not a proof at all
    final broken = StarkProof(
        traceRoot: honestProof.traceRoot,
        compRoot: honestProof.compRoot,
        auxRoot: honestProof.auxRoot,
        preRoot: honestProof.preRoot,
        zHint: honestProof.zHint,
        traceAtZ: honestProof.traceAtZ,
        traceAtZg: honestProof.traceAtZg,
        compAtZ: honestProof.compAtZ,
        friRoots: honestProof.friRoots,
        finalCoefs: honestProof.finalCoefs,
        nonce: honestProof.nonce,
        queries: const []);
    expect(ProverPool(program: program).accepts(job, broken), isFalse);

    // a prover that never answers
    s = ProverPool(program: program, provers: [_SilentProver()], timeout: const Duration(milliseconds: 50));
    expect((await s.prove(job)).traceRoot, honestProof.traceRoot);
    expect(s.outcomes.single.fallback, 'timeout');

    // and with no provers at all
    s = ProverPool(program: program);
    expect((await s.prove(job)).traceRoot, honestProof.traceRoot);
    expect(s.outcomes.single.fallback, 'no provers');
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('a prover proving from the encoded job alone reproduces the node', () async {
    final job = jobs[0];
    final prover = _RemoteProver();
    final s = ProverPool(program: program, provers: [prover]);
    final pf = await s.prove(job);
    expect(s.pooledNodes, 1);
    expect(pf.traceRoot, LocalNodeProver(program: program).proveNow(job).traceRoot);
  }, timeout: const Timeout(Duration(minutes: 20)));
}

/// A prover that always answers with the same proof, whatever it is asked.
class _FixedProver implements NodeProver {
  final StarkProof proof;
  _FixedProver(this.proof);
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) async => proof;
}

/// A prover that accepts the job and is never heard from again.
class _SilentProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) => Completer<StarkProof>().future;
}

/// A prover that only ever sees the job's bytes, as a remote one would: it
/// decodes, compiles the program itself, proves, and answers with the
/// proof's bytes.
class _RemoteProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) async {
    final received = NodeJob.decode(job.encode());
    final program = received.compile();
    final proof = LocalNodeProver(program: program).proveNow(received);
    final codec = received.nodeCodec(program);
    return codec.decode(codec.encode(proof));
  }
}
