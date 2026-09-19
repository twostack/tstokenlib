import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

Transaction _tx(SVScript sig) {
  var tx = Transaction();
  tx.version = 1;
  tx.nLockTime = 0;
  tx.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER,
      scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
  tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return tx;
}

int _run(SVScript sig, SVScript lock) {
  final sw = Stopwatch()..start();
  Interpreter().correctlySpends(sig, lock, _tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  return sw.elapsedMilliseconds;
}

void _expectSameProof(StarkProof a, StarkProof b) {
  expect(a.traceRoot, b.traceRoot);
  expect(a.compRoot, b.compRoot);
  expect(a.zHint, b.zHint);
  expect(a.traceAtZ, b.traceAtZ);
  expect(a.traceAtZg, b.traceAtZg);
  expect(a.compAtZ, b.compAtZ);
  expect(a.friRoots, b.friRoots);
  expect(a.finalCoefs, b.finalCoefs);
  expect(a.nonce, b.nonce);
  expect(a.queries.length, b.queries.length);
  for (int q = 0; q < a.queries.length; q++) {
    final x = a.queries[q], y = b.queries[q];
    expect(x.index, y.index);
    expect(x.compLeaf, y.compLeaf);
    expect(x.compPath, y.compPath);
    expect(x.yAInv, y.yAInv);
    expect(x.dAInvP, y.dAInvP);
    expect(x.dAInvC, y.dAInvC);
    expect(x.lineF0, y.lineF0);
    expect(x.lineF1, y.lineF1);
    expect(x.linePaths, y.linePaths);
    expect(x.lineXInv, y.lineXInv);
    expect(x.traceLeaf, y.traceLeaf);
    expect(x.tracePath, y.tracePath);
    expect(x.yBInv, y.yBInv);
    expect(x.dBInvP, y.dBInvP);
    expect(x.dBInvC, y.dBInvC);
    expect(x.dCInvP, y.dCInvP);
    expect(x.dCInvC, y.dCInvC);
  }
  for (final k in a.debug.keys) {
    expect(a.debug[k], b.debug[k], reason: 'debug key $k');
  }
}

void main() {
  final initial = List.generate(16, (i) => (i * 104729 + 1) % M31.p);

  test('FFT prover is byte-identical to the reference prover (zk off)', () {
    for (final params in const [
      StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1),
      StarkParams(logTrace: 5, logBlowup: 3, logExpand: 3, logFinal: 4, numQueries: 3, grindBytes: 1),
    ]) {
      final air = Poseidon2Air(params.logTrace);
      final rows = air.generateTrace(initial);
      final ref = StarkProverRef.prove(params, air, rows);
      final fft = StarkProver.prove(params, air, rows);
      _expectSameProof(ref, fft);
    }
  });

  test('zk-masked proof (small params) verifies in script; masks agree on the trace', () {
    const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 4);
    final air = Poseidon2Air(params.logTrace);
    final rows = air.generateTrace(initial);
    final p1 = StarkProver.prove(params, air, rows, rng: Random(1));
    final p2 = StarkProver.prove(params, air, rows, rng: Random(2));
    expect(p1.debug['probeOn'], p2.debug['probeOn']);
    expect(p1.debug['probeOn'], QM31.fromLimbs(rows[2][0], 0, 0, 0));
    expect(p1.debug['probeOff'], isNot(equals(p2.debug['probeOff'])));
    final gen = StarkVerifierGen(params, air);
    final lock = gen.generate();
    _run(gen.buildUnlock(p1), lock);
    _run(gen.buildUnlock(p2), lock);
  });

  test('production parameters: prove and verify end to end', () {
    const prod = StarkParams(logTrace: 12, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 16, grindBytes: 3, zkRandomizers: 128);
    final air = Poseidon2Air(prod.logTrace);
    final rows = air.generateTrace(initial);
    final sw = Stopwatch()..start();
    final proof = StarkProver.prove(prod, air, rows, verbose: true);
    final proveMs = sw.elapsedMilliseconds;
    final gen = StarkVerifierGen(prod, air);
    final lock = gen.generate();
    final unlock = gen.buildUnlock(proof);
    final verifyMs = _run(unlock, lock);
    print('--- production proof (t=12, blowup 32, 16 queries, zk R=128) ---');
    print('  prover time      : $proveMs ms');
    print('  locking script   : ${lock.buffer.length} bytes');
    print('  unlocking script : ${unlock.buffer.length} bytes');
    print('  interp time      : $verifyMs ms');
  }, timeout: const Timeout(Duration(minutes: 20)));
}
