import 'dart:convert';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/script_gen/rabin_verify_script_gen.dart';

Transaction _createDummyTx(SVScript scriptSig) {
  var tx = Transaction();
  tx.version = 1;
  tx.nLockTime = 0;
  var input = TransactionInput(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    0,
    TransactionInput.MAX_SEQ_NUMBER,
    scriptBuilder: DefaultUnlockBuilder.fromScript(scriptSig),
  );
  tx.inputs.add(input);
  tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return tx;
}

Set<VerifyFlag> get _genesisFlags => {VerifyFlag.UTXO_AFTER_GENESIS};

void _verifyScript(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  interp.correctlySpends(
    scriptSig, scriptPubKey, tx, 0, _genesisFlags, Coin.valueOf(BigInt.from(1000)),
  );
}

void _expectScriptFails(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  expect(
    () => interp.correctlySpends(
      scriptSig, scriptPubKey, tx, 0, _genesisFlags, Coin.valueOf(BigInt.from(1000)),
    ),
    throwsException,
  );
}

void main() {
  // Pre-generate keypairs once (prime generation is slow)
  late RabinKeyPair keyPair1024;
  late RabinKeyPair keyPair2048;

  setUpAll(() {
    print('Generating 1024-bit Rabin keypair...');
    keyPair1024 = Rabin.generateKeyPair(1024);
    print('  n has ${Rabin.bigIntToScriptNum(keyPair1024.n).length} bytes');

    print('Generating 2048-bit Rabin keypair...');
    keyPair2048 = Rabin.generateKeyPair(2048);
    print('  n has ${Rabin.bigIntToScriptNum(keyPair2048.n).length} bytes');
  });

  group('Rabin Dart-level crypto', () {
    test('sign and verify in Dart (1024-bit)', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('hello world'));
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);
      expect(Rabin.verify(messageHash, sig, keyPair1024.n), isTrue);
    });

    test('sign and verify in Dart (2048-bit)', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('identity binding test'));
      var sig = Rabin.sign(messageHash, keyPair2048.p, keyPair2048.q);
      expect(Rabin.verify(messageHash, sig, keyPair2048.n), isTrue);
    });

    test('wrong message fails verification', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('correct message'));
      var wrongHash = Rabin.sha256ToInt(utf8.encode('wrong message'));
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);
      expect(Rabin.verify(wrongHash, sig, keyPair1024.n), isFalse);
    });

    test('wrong key fails verification', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('test'));
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);
      expect(Rabin.verify(messageHash, sig, keyPair2048.n), isFalse);
    });
  });

  group('Rabin verification in Bitcoin Script', () {
    test('1024-bit: valid signature verifies through interpreter', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('test identity binding'));
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      var scriptSig = RabinVerifyScriptGen.buildScriptSig(messageHash, sig);
      var scriptPubKey = RabinVerifyScriptGen.generate(keyPair1024.n);

      print('1024-bit script sizes:');
      print('  scriptPubKey: ${scriptPubKey.buffer?.length ?? 0} bytes');
      print('  scriptSig:    ${scriptSig.buffer?.length ?? 0} bytes');

      _verifyScript(scriptSig, scriptPubKey);
    });

    test('2048-bit: valid signature verifies through interpreter', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('test identity binding'));
      var sig = Rabin.sign(messageHash, keyPair2048.p, keyPair2048.q);

      var scriptSig = RabinVerifyScriptGen.buildScriptSig(messageHash, sig);
      var scriptPubKey = RabinVerifyScriptGen.generate(keyPair2048.n);

      print('2048-bit script sizes:');
      print('  scriptPubKey: ${scriptPubKey.buffer?.length ?? 0} bytes');
      print('  scriptSig:    ${scriptSig.buffer?.length ?? 0} bytes');

      _verifyScript(scriptSig, scriptPubKey);
    });

    test('wrong signature fails in interpreter', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('test'));
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      // Tamper with the signature
      var wrongSig = RabinSignature(sig.s + BigInt.one, sig.padding);
      var scriptSig = RabinVerifyScriptGen.buildScriptSig(messageHash, wrongSig);
      var scriptPubKey = RabinVerifyScriptGen.generate(keyPair1024.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });

    test('wrong message fails in interpreter', () {
      var correctHash = Rabin.sha256ToInt(utf8.encode('correct'));
      var wrongHash = Rabin.sha256ToInt(utf8.encode('wrong'));
      var sig = Rabin.sign(correctHash, keyPair1024.p, keyPair1024.q);

      // Sign with correct hash but push wrong hash
      var scriptSig = RabinVerifyScriptGen.buildScriptSig(wrongHash, sig);
      var scriptPubKey = RabinVerifyScriptGen.generate(keyPair1024.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });

    test('wrong key (different n) fails in interpreter', () {
      var messageHash = Rabin.sha256ToInt(utf8.encode('test'));
      // Sign with 1024-bit key but verify against 2048-bit key
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      var scriptSig = RabinVerifyScriptGen.buildScriptSig(messageHash, sig);
      var scriptPubKey = RabinVerifyScriptGen.generate(keyPair2048.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });

    test('signature with non-zero padding verifies', () {
      // Keep trying messages until we find one that needs padding > 0
      for (int i = 0; i < 100; i++) {
        var messageHash = Rabin.sha256ToInt(utf8.encode('padding test $i'));
        var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

        if (sig.padding > 0) {
          print('Found message needing padding=${sig.padding} at i=$i');

          var scriptSig = RabinVerifyScriptGen.buildScriptSig(messageHash, sig);
          var scriptPubKey = RabinVerifyScriptGen.generate(keyPair1024.n);

          _verifyScript(scriptSig, scriptPubKey);
          return; // test passed
        }
      }
      // If all 100 messages had padding=0, that's fine too (just unlikely)
      print('All 100 messages had padding=0 (statistically unusual but valid)');
    });
  });

  group('Identity binding: sign(identityTxId || ed25519PubKey)', () {
    test('valid binding verifies through interpreter (1024-bit)', () {
      // Simulate a 32-byte identity txid and 32-byte ED25519 pubkey
      var identityTxId = List<int>.generate(32, (i) => i + 1);  // 0x01..0x20
      var ed25519PubKey = List<int>.generate(32, (i) => i + 0x41);  // 0x41..0x60

      // Compute hash the way the script will: sha256(txId || pubKey) as LE unsigned
      var concat = [...identityTxId, ...ed25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);

      // Sign with Rabin
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      // Build scripts
      var scriptSig = RabinVerifyScriptGen.buildBindingScriptSig(
          sig, identityTxId, ed25519PubKey);
      var scriptPubKey = RabinVerifyScriptGen.generateWithBinding(keyPair1024.n);

      print('Identity binding script sizes (1024-bit):');
      print('  scriptPubKey: ${scriptPubKey.buffer?.length ?? 0} bytes');
      print('  scriptSig:    ${scriptSig.buffer?.length ?? 0} bytes');

      _verifyScript(scriptSig, scriptPubKey);
    });

    test('valid binding verifies through interpreter (2048-bit)', () {
      var identityTxId = List<int>.generate(32, (i) => 0xFF - i);
      var ed25519PubKey = List<int>.generate(32, (i) => i * 7 & 0xFF);

      var concat = [...identityTxId, ...ed25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, keyPair2048.p, keyPair2048.q);

      var scriptSig = RabinVerifyScriptGen.buildBindingScriptSig(
          sig, identityTxId, ed25519PubKey);
      var scriptPubKey = RabinVerifyScriptGen.generateWithBinding(keyPair2048.n);

      print('Identity binding script sizes (2048-bit):');
      print('  scriptPubKey: ${scriptPubKey.buffer?.length ?? 0} bytes');
      print('  scriptSig:    ${scriptSig.buffer?.length ?? 0} bytes');

      _verifyScript(scriptSig, scriptPubKey);
    });

    test('wrong identityTxId fails', () {
      var identityTxId = List<int>.generate(32, (i) => i + 1);
      var wrongTxId = List<int>.generate(32, (i) => i + 2);  // different
      var ed25519PubKey = List<int>.generate(32, (i) => i + 0x41);

      var concat = [...identityTxId, ...ed25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      // Sign with correct data but push wrong identityTxId
      var scriptSig = RabinVerifyScriptGen.buildBindingScriptSig(
          sig, wrongTxId, ed25519PubKey);
      var scriptPubKey = RabinVerifyScriptGen.generateWithBinding(keyPair1024.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });

    test('wrong ed25519PubKey fails', () {
      var identityTxId = List<int>.generate(32, (i) => i + 1);
      var ed25519PubKey = List<int>.generate(32, (i) => i + 0x41);
      var wrongPubKey = List<int>.generate(32, (i) => i + 0x42);  // different

      var concat = [...identityTxId, ...ed25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      // Sign with correct data but push wrong pubkey
      var scriptSig = RabinVerifyScriptGen.buildBindingScriptSig(
          sig, identityTxId, wrongPubKey);
      var scriptPubKey = RabinVerifyScriptGen.generateWithBinding(keyPair1024.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });

    test('wrong Rabin key fails', () {
      var identityTxId = List<int>.generate(32, (i) => i + 1);
      var ed25519PubKey = List<int>.generate(32, (i) => i + 0x41);

      var concat = [...identityTxId, ...ed25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      // Sign with 1024-bit key but verify against 2048-bit key
      var sig = Rabin.sign(messageHash, keyPair1024.p, keyPair1024.q);

      var scriptSig = RabinVerifyScriptGen.buildBindingScriptSig(
          sig, identityTxId, ed25519PubKey);
      var scriptPubKey = RabinVerifyScriptGen.generateWithBinding(keyPair2048.n);

      _expectScriptFails(scriptSig, scriptPubKey);
    });
  });

  group('BigInt ↔ script number encoding', () {
    test('round-trip: BigInt → scriptNum → BigInt', () {
      var values = [
        BigInt.one,
        BigInt.from(127),
        BigInt.from(128),
        BigInt.from(255),
        BigInt.from(256),
        BigInt.from(0x7FFF),
        BigInt.from(0x8000),
        BigInt.parse('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', radix: 16),
        keyPair1024.n,
      ];

      for (var v in values) {
        var encoded = Rabin.bigIntToScriptNum(v);
        // Decode back using dartsv's fromSM
        var decoded = fromSM(encoded.reversed.toList(), endian: Endian.big);
        expect(decoded, equals(v), reason: 'Round-trip failed for $v');
      }
    });
  });
}
