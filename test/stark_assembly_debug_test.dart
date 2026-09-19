import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
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

String _run(SVScript sig, SVScript lock) {
  try {
    Interpreter().correctlySpends(sig, lock, _tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    return 'OK';
  } catch (ex) {
    return 'FAIL $ex';
  }
}

void main() {
  test('bisect stages', () {
    const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 4);
    final air = Poseidon2Air(params.logTrace);
    final initial = List.generate(16, (i) => (i * 104729 + 1) % M31.p);
    final proof = StarkProverRef.prove(params, air, air.generateTrace(initial));
    final gen = StarkVerifierGen(params, air);
    gen.expect = proof.debug;
    final unlock = gen.buildUnlock(proof);
    for (final st in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20, 21, 22, 23, 24, 999]) {
      gen.stopStage = st;
      final lock = gen.generate();
      print('stage $st: ${_run(unlock, lock)}');
    }
  });
}
