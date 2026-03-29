import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

void main() {
  // Test key material (same as SM token tests — testnet WIF)
  final privateKey = SVPrivateKey.fromWIF(
      'cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final publicKey = privateKey.publicKey;
  final sigHashType =
      SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;

  group('SignerAdapter', () {
    test('fromCallback produces same signature as DefaultTransactionSigner', () {
      // Create both signers for the same key
      final directSigner = DefaultTransactionSigner(sigHashType, privateKey);
      final callbackSigner = SignerAdapter.fromCallback(
        (Uint8List sighash) {
          final sig = SVSignature.fromPrivateKey(privateKey);
          sig.nhashtype = sigHashType;
          sig.sign(HEX.encode(sighash));
          return Uint8List.fromList(sig.toDER());
        },
        publicKey,
        sigHashType: sigHashType,
      );

      // Both should have the same sigHashType
      expect(callbackSigner.sigHashType, equals(directSigner.sigHashType));

      // Sign the same preimage with both
      final preimage = Uint8List.fromList(List.generate(100, (i) => i));
      final directSig = directSigner.signPreimage(preimage);
      final callbackSig = callbackSigner.signPreimage(preimage);

      // Signatures should be identical
      expect(callbackSig.toTxFormat(), equals(directSig.toTxFormat()));
    });

    test('fromCallbackWithContext receives script bytes', () {
      Uint8List? receivedScript;
      int? receivedIndex;

      final signer = SignerAdapter.fromCallbackWithContext(
        (Uint8List sighash, int inputIndex, Uint8List scriptPubKey) {
          receivedIndex = inputIndex;
          receivedScript = scriptPubKey;
          final sig = SVSignature.fromPrivateKey(privateKey);
          sig.nhashtype = sigHashType;
          sig.sign(HEX.encode(sighash));
          return Uint8List.fromList(sig.toDER());
        },
        publicKey,
        sigHashType: sigHashType,
      );

      // signPreimage passes inputIndex=-1 and empty script
      signer.signPreimage(Uint8List.fromList(List.generate(32, (i) => i)));
      expect(receivedIndex, equals(-1));
      expect(receivedScript!.isEmpty, isTrue);
    });

    test('default sigHashType is SIGHASH_ALL | SIGHASH_FORKID', () {
      final signer = SignerAdapter.fromCallback(
        (sighash) => Uint8List(0),
        publicKey,
      );
      expect(
        signer.sigHashType,
        equals(SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value),
      );
    });
  });
}
