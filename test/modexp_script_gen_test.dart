import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/script_gen/modexp_script_gen.dart';

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

/// Runs the script and returns wall-clock microseconds for interpretation only.
int _runTimed(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  var sw = Stopwatch()..start();
  interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
      {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  sw.stop();
  return sw.elapsedMicroseconds;
}

final _rng = Random.secure();

BigInt _randomBits(int bits) {
  var v = BigInt.zero;
  for (int i = 0; i < bits; i += 8) {
    v = (v << 8) | BigInt.from(_rng.nextInt(256));
  }
  // Truncate to exactly `bits` and force the top bit so it's full-width.
  v = v & ((BigInt.one << bits) - BigInt.one);
  return v | (BigInt.one << (bits - 1));
}

BigInt _randomOddModulus(int bits) => _randomBits(bits) | BigInt.one;

void _reportCase(String label, int expBits, int modBits, {int runs = 3}) {
  final m = _randomOddModulus(modBits);
  final base = _randomBits(modBits - 1) % m;
  final e = _randomBits(expBits);
  final expected = base.modPow(e, m);

  final lock = ModExpScriptGen.generateVerify(m, expBits, expected);
  final sig = ModExpScriptGen.buildScriptSig(base, e);

  final lockBytes = lock.buffer.length;
  final sigBytes = sig.buffer.length;
  // Fixed overhead: modulus push + expected push + setup/teardown.
  final modPushBytes = (modBits + 7) ~/ 8 + 3;
  final loopBytes = lockBytes - 2 * modPushBytes;

  int best = 1 << 62;
  for (int r = 0; r < runs; r++) {
    best = min(best, _runTimed(sig, lock));
  }

  print(label);
  print('  exponent bits      : $expBits');
  print('  modulus bits       : $modBits');
  print('  locking script     : $lockBytes bytes');
  print('  loop body only     : $loopBytes bytes  (${(loopBytes / expBits).toStringAsFixed(1)} bytes/bit)');
  print('  unlocking script   : $sigBytes bytes');
  print('  interp time (best) : ${(best / 1000).toStringAsFixed(1)} ms');
}

void main() {
  group('ModExpScriptGen correctness', () {
    test('3^5 mod 7 == 5', () {
      final lock = ModExpScriptGen.generateVerify(BigInt.from(7), 8, BigInt.from(5));
      _runTimed(ModExpScriptGen.buildScriptSig(BigInt.from(3), BigInt.from(5)), lock);
    });

    test('exponent 0 gives 1', () {
      final lock = ModExpScriptGen.generateVerify(BigInt.from(97), 8, BigInt.one);
      _runTimed(ModExpScriptGen.buildScriptSig(BigInt.from(42), BigInt.zero), lock);
    });

    test('exponent 1 gives base mod m', () {
      final lock = ModExpScriptGen.generateVerify(BigInt.from(97), 8, BigInt.from(42));
      _runTimed(ModExpScriptGen.buildScriptSig(BigInt.from(42), BigInt.one), lock);
    });

    test('max exponent 2^bits - 1', () {
      final m = BigInt.from(1000003);
      final e = BigInt.from(255);
      final base = BigInt.from(12345);
      final lock = ModExpScriptGen.generateVerify(m, 8, base.modPow(e, m));
      _runTimed(ModExpScriptGen.buildScriptSig(base, e), lock);
    });

    test('wrong expected value fails', () {
      final lock = ModExpScriptGen.generateVerify(BigInt.from(7), 8, BigInt.from(6));
      expect(
        () => _runTimed(ModExpScriptGen.buildScriptSig(BigInt.from(3), BigInt.from(5)), lock),
        throwsA(isA<ScriptException>()),
      );
    });

    test('20 random 64-bit exponents, 512-bit modulus', () {
      for (int i = 0; i < 20; i++) {
        final m = _randomOddModulus(512);
        final base = _randomBits(500) % m;
        final e = _randomBits(64) >> _rng.nextInt(60); // vary actual bit length
        final lock = ModExpScriptGen.generateVerify(m, 64, base.modPow(e, m));
        _runTimed(ModExpScriptGen.buildScriptSig(base, e), lock);
      }
    });
  });

  group('ModExpScriptGen measurements', () {
    test('256-bit exponent, 3072-bit modulus (Schnorr-group sigma protocol)', () {
      _reportCase('Schnorr group', 256, 3072);
    });

    test('256-bit exponent, 2048-bit modulus', () {
      _reportCase('Schnorr group (2048)', 256, 2048);
    });

    test('1500-bit exponent, 3072-bit modulus (RSA accumulator proof)', () {
      _reportCase('RSA accumulator', 1500, 3072);
    });

    test('3072-bit exponent, 3072-bit modulus (full-width, worst case)', () {
      _reportCase('Full width', 3072, 3072);
    });
  });
}
