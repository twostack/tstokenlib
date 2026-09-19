import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

Transaction _createDummyTx(SVScript scriptSig) {
  var tx = Transaction();
  tx.version = 1;
  tx.nLockTime = 0;
  tx.inputs.add(TransactionInput(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    0,
    TransactionInput.MAX_SEQ_NUMBER,
    scriptBuilder: DefaultUnlockBuilder.fromScript(scriptSig),
  ));
  tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return tx;
}

int _run(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  var sw = Stopwatch()..start();
  interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
      {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  sw.stop();
  return sw.elapsedMicroseconds;
}

void main() {
  // zkRandomizers 4 exercises the masking path; real hiding needs R >= 4Q + 8.
  const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 4);
  final air = Poseidon2Air(params.logTrace);
  final initial = List.generate(16, (i) => (i * 104729 + 1) % M31.p);
  final rows = air.generateTrace(initial);

  group('assembled STARK verifier', () {
    late StarkProof proof;
    late StarkVerifierGen gen;
    late SVScript lock;

    setUpAll(() {
      final sw = Stopwatch()..start();
      proof = StarkProverRef.prove(params, air, rows);
      print('prover time (naive reference): ${sw.elapsedMilliseconds} ms');
      gen = StarkVerifierGen(params, air);
      lock = gen.generate();
    });

    test('honest proof verifies', () {
      final unlock = gen.buildUnlock(proof);
      final us = _run(unlock, lock);
      print('--- assembled verifier, test params (t=5, blowup 4, 2 queries, zk masking on) ---');
      print('  locking script   : ${lock.buffer.length} bytes');
      print('  unlocking script : ${unlock.buffer.length} bytes');
      print('  interp time      : ${(us / 1000).toStringAsFixed(1)} ms');
    });

    test('tampered OODS value fails', () {
      final bad = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, zHint: proof.zHint,
        traceAtZ: [...proof.traceAtZ]..[3] = proof.traceAtZ[3] + QM31.one,
        traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ, friRoots: proof.friRoots,
        finalCoefs: proof.finalCoefs, nonce: proof.nonce, queries: proof.queries,
      );
      expect(() => _run(gen.buildUnlock(bad), lock), throwsA(isA<ScriptException>()));
    });

    test('tampered composition opening fails', () {
      final q0 = proof.queries[0];
      final badQ = QueryProof(
        index: q0.index, compLeaf: [...q0.compLeaf]..[2] = (q0.compLeaf[2] + 1) % M31.p,
        compPath: q0.compPath,
        lineF0: q0.lineF0, lineF1: q0.lineF1, linePaths: q0.linePaths, lineXInv: q0.lineXInv,
        traceLeaf: q0.traceLeaf, tracePath: q0.tracePath, yBInv: q0.yBInv,
        dBInvP: q0.dBInvP, dBInvC: q0.dBInvC, dCInvP: q0.dCInvP, dCInvC: q0.dCInvC,
      );
      final bad = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, zHint: proof.zHint,
        traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ,
        friRoots: proof.friRoots, finalCoefs: proof.finalCoefs, nonce: proof.nonce,
        queries: [badQ, ...proof.queries.sublist(1)],
      );
      expect(() => _run(gen.buildUnlock(bad), lock), throwsA(isA<ScriptException>()));
    });

    test('wrong grinding nonce fails', () {
      final bad = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, zHint: proof.zHint,
        traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ,
        friRoots: proof.friRoots, finalCoefs: proof.finalCoefs, nonce: [9, 9, 9, 9],
        queries: proof.queries,
      );
      expect(() => _run(gen.buildUnlock(bad), lock), throwsA(isA<ScriptException>()));
    });
  });

  group('zero-knowledge masking', () {
    test('two proofs of the same trace agree on trace rows and differ off-domain', () {
      final p1 = StarkProverRef.prove(params, air, rows, rng: Random(1));
      final p2 = StarkProverRef.prove(params, air, rows, rng: Random(2));
      expect(p1.debug['probeOn'], equals(p2.debug['probeOn']));
      expect(p1.debug['probeOn'], equals(QM31.fromLimbs(rows[2][0], 0, 0, 0)));
      expect(p1.debug['probeOff'], isNot(equals(p2.debug['probeOff'])));
      // and the unmasked prover is deterministic off-domain
      const plain = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
      final q1 = StarkProverRef.prove(plain, air, rows, rng: Random(1));
      final q2 = StarkProverRef.prove(plain, air, rows, rng: Random(2));
      expect(q1.debug['probeOff'], equals(q2.debug['probeOff']));
    });
  });

  group('production-parameter script size', () {
    test('trace 2^12, blowup 32, 16 queries, final degree 32', () {
      const prod = StarkParams(logTrace: 12, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 16, grindBytes: 3, zkRandomizers: 128);
      expect(prod.zkSufficient, isTrue, reason: 'R=${prod.zkRandomizers} must cover ${prod.revealedPerColumn} revealed points');
      final prodAir = Poseidon2Air(prod.logTrace);
      final sw = Stopwatch()..start();
      final lock = StarkVerifierGen(prod, prodAir).generate();
      final one = StarkVerifierGen(
          const StarkParams(logTrace: 12, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 1, grindBytes: 3, zkRandomizers: 128),
          prodAir).generate();
      final noZk = StarkVerifierGen(
          const StarkParams(logTrace: 12, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 16, grindBytes: 3),
          prodAir).generate();
      final perQuery = (lock.buffer.length - one.buffer.length) / 15;
      print('--- production parameters ---');
      print('  comp half-coset log size : composition blocks ${prod.compChunks}  (line folds: ${prod.numLineFolds})');
      print('  zk: R=${prod.zkRandomizers} randomizers, ${prod.revealedPerColumn} revealed points/column, trace half-coset log ${prod.logTraceHalf}');
      print('  full locking script      : ${lock.buffer.length} bytes  (${(lock.buffer.length / 1024).toStringAsFixed(0)} KB)');
      print('  without zk masking       : ${noZk.buffer.length} bytes  (zk cost ${lock.buffer.length - noZk.buffer.length} bytes)');
      print('  per query                : ${perQuery.toStringAsFixed(0)} bytes');
      print('  fixed (once per proof)   : ${(one.buffer.length - perQuery).toStringAsFixed(0)} bytes');
      print('  generation time          : ${sw.elapsedMilliseconds} ms');
      expect(lock.buffer.length, lessThan(500 * 1024));
    });
  });
}
