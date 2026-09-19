import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

/// Recursion on chain: a SHA256-flavour proof of the verifier AIR (which
/// verifies a Poseidon2-flavour spend proof) is checked by the generated
/// locking script in the interpreter, preprocessed columns included.
void main() {
  final rng = Random(43);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const sha = Sha256ProofHash();

  const inner = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
  final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
  final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
  final w = PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
  final innerAir = PoolSpendAir.air(w.publics);
  const vLog = 14;
  const outer = StarkParams(logTrace: vLog, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  Transaction tx(SVScript sig) {
    final t = Transaction()
      ..version = 1
      ..nLockTime = 0;
    t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
    t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
    return t;
  }

  void run(SVScript sig, SVScript lock) =>
      Interpreter().correctlySpends(sig, lock, tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));

  test('the script verifies a SHA256-flavour proof of the verifier AIR', () {
    final innerProof = StarkProver.prove(inner, innerAir, w.rows, rng: Random(1), hash: p2);
    final program = VerifierProgram.compile(InnerShape(inner, innerAir), vLog);
    final rows = program.witness(innerProof);
    final digest = VerifierProgram.nodeDigestOf(innerAir, innerProof.preRoot);
    final vAir = program.air(digest);

    var sw = Stopwatch()..start();
    final proof = StarkProver.prove(outer, vAir, rows, rng: Random(2), hash: sha);
    print('  outer prover (SHA256 flavour): ${sw.elapsedMilliseconds} ms, proof ${ProofSize.bytes(outer, vAir, sha)} B');
    expect(StarkVerifierRef(outer, vAir, hash: sha).verify(proof), isTrue);

    sw = Stopwatch()..start();
    final gen = StarkVerifierGen(outer, vAir);
    final lock = gen.generate();
    print('  verifier script: ${lock.buffer.length} bytes, ${lock.chunks.length} chunks, generated in ${sw.elapsedMilliseconds} ms');
    final unlock = gen.buildUnlock(proof);
    print('  unlock: ${unlock.buffer.length} bytes');
    sw = Stopwatch()..start();
    run(unlock, lock);
    print('  interpreter: ${sw.elapsedMilliseconds} ms');

    // the same proof under a different statement digest is rejected
    final other = program.air(lanes(8));
    expect(() => run(StarkVerifierGen(outer, other).buildUnlock(proof), lock), throwsA(isA<ScriptException>()));
    // and so is a tampered preprocessed opening
    final q = proof.queries[0];
    final bad = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, auxRoot: proof.auxRoot, preRoot: proof.preRoot,
        zHint: proof.zHint, traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ,
        friRoots: proof.friRoots, finalCoefs: proof.finalCoefs, nonce: proof.nonce,
        queries: [
          QueryProof(
              index: q.index, compLeaf: q.compLeaf, compPath: q.compPath, lineF0: q.lineF0, lineF1: q.lineF1, linePaths: q.linePaths, lineXInv: q.lineXInv,
              traceLeaf: q.traceLeaf, tracePath: q.tracePath, auxLeaf: q.auxLeaf, auxPath: q.auxPath,
              preLeaf: [...q.preLeaf]..[2] ^= 1, prePath: q.prePath, yBInv: q.yBInv, dBInvP: q.dBInvP,
              dBInvC: q.dBInvC, dCInvP: q.dCInvP, dCInvC: q.dCInvC),
          ...proof.queries.sublist(1)
        ]);
    expect(() => run(gen.buildUnlock(bad), lock), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));
}
