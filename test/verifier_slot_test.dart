import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/verifier_slot_gen.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

Transaction roundTx(String parentTxid, Uint8List resultOutput) {
  final t = Transaction();
  t.version = 1;
  t.nLockTime = 0;
  for (int v = 0; v < 2; v++) {
    t.inputs.add(TransactionInput(parentTxid, v, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript())));
  }
  t.outputs.add(TransactionOutput(BigInt.from(5000), SVScript.fromHex('76a914${'11' * 20}88ac')));
  t.outputs.add(TransactionOutput(BigInt.zero, SVScript.fromByteArray(resultOutput.sublist(9))));
  return t;
}

List<int> prevoutsTail(Transaction t) => [
      for (final i in t.inputs.skip(1)) ...[
        ...hex.decode(i.prevTxnId).reversed,
        ...(ByteData(4)..setUint32(0, i.prevTxnOutputIndex, Endian.little)).buffer.asUint8List(),
      ]
    ];

void main() {
  final rng = Random(2026);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int k) => List.generate(k, (_) => r31());
  const p = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  final gen = VerifierSlotGen(p);
  late SVScript lock;
  late PoolPublicInputs publics;
  late StarkProof proof;

  setUpAll(() {
    lock = gen.lock();
    // a deposit proof: two dummies, an anchor of the caller's choosing
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final na = OutputNote(pkd: lanes(8), value: 700000, rho: lanes(3), rcm: lanes(4));
    final nb = OutputNote(pkd: lanes(8), value: 5, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, na, nb, -(na.value + nb.value), anchor: lanes(8));
    publics = w.publics;
    proof = StarkProver.prove(p, PoolSpendAir.air(publics), w.rows, rng: Random(3));
  });

  void run(SVScript unlock, Transaction tx) => Interpreter().correctlySpends(unlock, lock, tx, 1, verifyFlags, Coin.valueOf(BigInt.one));

  test('the proof path publishes the hash of the publics it verified', () {
    final tx = roundTx('ab' * 32, VerifierSlotGen.resultOutput(publics.toLanes()));
    final pre = Sighash().createSighashPreImage(tx, 0x43, 1, lock, BigInt.one)!;
    final unlock = gen.unlockProof(proof, publics, pre, prevoutsTail(tx));
    final sw = Stopwatch()..start();
    run(unlock, tx);
    print('  verifier slot: lock ${lock.buffer.length} B, proof unlock ${unlock.buffer.length} B, preimage ${pre.length} B, interpreter ${sw.elapsedMilliseconds} ms');
    // other publics under the same result: the proof does not verify
    final other = publics.copyWith(anchor: [...publics.anchor]..[0] ^= 1);
    expect(() => run(gen.unlockProof(proof, other, pre, prevoutsTail(tx)), tx), throwsA(isA<ScriptException>()));
    // a result output for other publics
    final tx2 = roundTx('ab' * 32, VerifierSlotGen.resultOutput(other.toLanes()));
    final pre2 = Sighash().createSighashPreImage(tx2, 0x43, 1, lock, BigInt.one)!;
    expect(() => run(gen.unlockProof(proof, publics, pre2, prevoutsTail(tx2)), tx2), throwsA(isA<ScriptException>()));
    // the state not co-spent
    final loose = roundTx('cd' * 32, VerifierSlotGen.resultOutput(publics.toLanes()));
    loose.inputs[1] = TransactionInput('ab' * 32, 1, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript()));
    final preL = Sighash().createSighashPreImage(loose, 0x43, 1, lock, BigInt.one)!;
    expect(() => run(gen.unlockProof(proof, publics, preL, prevoutsTail(loose)), loose), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('the skip path publishes an empty result, and only that', () {
    final tx = roundTx('ab' * 32, VerifierSlotGen.emptyResultOutput());
    final pre = Sighash().createSighashPreImage(tx, 0x43, 1, lock, BigInt.one)!;
    run(gen.unlockSkip(pre, prevoutsTail(tx)), tx);
    // skipping cannot publish a real-looking result
    final tx2 = roundTx('ab' * 32, VerifierSlotGen.resultOutput(publics.toLanes()));
    final pre2 = Sighash().createSighashPreImage(tx2, 0x43, 1, lock, BigInt.one)!;
    expect(() => run(gen.unlockSkip(pre2, prevoutsTail(tx2)), tx2), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
