import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';

import 'signing_callback.dart';

/// Adapts a [SigningCallback] into a dartsv [TransactionSigner].
///
/// Callers who have a raw signing closure (e.g., from a KMS, HSM, or
/// coordinator callback) use [SignerAdapter.fromCallback] to get a
/// [TransactionSigner] they can pass to any tstokenlib tool method.
///
/// ```dart
/// final signer = SignerAdapter.fromCallback(
///   (sighash) {
///     // Sign with your KMS, HSM, or secure enclave
///     return kms.sign(sighash);
///   },
///   myPublicKey,
/// );
/// tokenTool.createTokenIssuanceTxn(fundingTx, signer, myPublicKey, ...);
/// ```
class SignerAdapter extends TransactionSigner {
  @override
  final int sigHashType;
  final SigningCallbackWithContext _onSign;

  SignerAdapter._({
    required this.sigHashType,
    required SigningCallbackWithContext onSign,
  }) : _onSign = onSign;

  /// Wraps a 1-arg [SigningCallback] into a [TransactionSigner].
  ///
  /// The callback receives only the sighash bytes. Use this for simple
  /// single-key signers.
  static SignerAdapter fromCallback(
    SigningCallback callback,
    SVPublicKey publicKey, {
    int? sigHashType,
  }) {
    final sht = sigHashType ??
        (SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value);
    return SignerAdapter._(
      sigHashType: sht,
      onSign: (sighash, inputIndex, scriptPubKey) => callback(sighash),
    );
  }

  /// Wraps a 3-arg [SigningCallbackWithContext] into a [TransactionSigner].
  ///
  /// The callback receives the sighash, input index, and locking script of
  /// the output being spent. Use this for multi-key HD wallets that need
  /// to resolve the correct signing key from the locking script.
  static SignerAdapter fromCallbackWithContext(
    SigningCallbackWithContext callback,
    SVPublicKey publicKey, {
    int? sigHashType,
  }) {
    final sht = sigHashType ??
        (SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value);
    return SignerAdapter._(
      sigHashType: sht,
      onSign: callback,
    );
  }

  @override
  Transaction sign(Transaction unsignedTxn, TransactionOutput utxo, int inputIndex) {
    SVScript subscript = utxo.script;
    var sigHash = Sighash();
    var hash = sigHash.hash(unsignedTxn, sigHashType, inputIndex, subscript, utxo.satoshis);
    var hashBytes = Uint8List.fromList(HEX.decode(hash).reversed.toList());

    // Delegate signing to the callback, passing the locking script
    var scriptBytes = Uint8List.fromList(utxo.script.buffer?.toList() ?? []);
    var derBytes = _onSign(hashBytes, inputIndex, scriptBytes);

    var sig = SVSignature.fromDER(HEX.encode(derBytes));
    sig.nhashtype = sigHashType;

    TransactionInput input = unsignedTxn.inputs[inputIndex];
    if (input != null) {
      UnlockingScriptBuilder scriptBuilder = input.scriptBuilder!;
      scriptBuilder.signatures.add(sig);
    } else {
      throw TransactionException(
          "Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
    }

    return unsignedTxn;
  }

  @override
  SVSignature signPreimage(Uint8List preImage) {
    var sighash = Uint8List.fromList(sha256Twice(preImage.toList()));
    var derBytes = _onSign(sighash, -1, Uint8List(0));
    var sig = SVSignature.fromDER(HEX.encode(derBytes));
    sig.nhashtype = sigHashType;
    return sig;
  }
}
