import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';

import '../builder/identity_anchor_builder.dart';
import '../builder/map_lockbuilder.dart';

/// Utilities for verifying the link between a token issuance and its issuer identity.
class IdentityVerification {

  /// Extracts the identity anchor txid and signature from an issuance transaction's
  /// metadata output (output[4]).
  ///
  /// Returns a record with identityTxId and identitySig, or nulls if not present.
  static ({String? identityTxId, String? identitySig}) extractIdentityFromMetadata(SVScript metadataScript) {
    try {
      var mapLocker = MapLockBuilder.fromScript(metadataScript);
      return (
        identityTxId: mapLocker.map['identityTxId']?.toString(),
        identitySig: mapLocker.map['identitySig']?.toString(),
      );
    } catch (_) {
      return (identityTxId: null, identitySig: null);
    }
  }

  /// Verifies that the issuance transaction's metadata correctly links to the
  /// identity anchor transaction.
  ///
  /// Verification steps:
  /// 1. Extract identityTxId and identitySig from issuance metadata (output[4])
  /// 2. Extract ED25519 public key from identity anchor's AIP output (output[2])
  /// 3. Verify identitySig is a valid signature over identityTxId using that pubkey
  static Future<bool> verifyIssuanceIdentity(Transaction issuanceTx, Transaction identityAnchorTx) async {
    var metadataScript = issuanceTx.outputs[4].script;
    var identity = extractIdentityFromMetadata(metadataScript);

    if (identity.identityTxId == null || identity.identitySig == null) {
      return false;
    }

    var pubkeyHex = IdentityAnchorBuilder.extractPublicKey(identityAnchorTx);
    if (pubkeyHex.isEmpty) return false;

    var algorithm = Ed25519();
    var publicKey = SimplePublicKey(hex.decode(pubkeyHex), type: KeyPairType.ed25519);
    var signatureBytes = base64Decode(identity.identitySig!);
    var messageBytes = hex.decode(identity.identityTxId!);

    var signature = Signature(signatureBytes, publicKey: publicKey);

    try {
      return await algorithm.verify(messageBytes, signature: signature);
    } catch (_) {
      return false;
    }
  }

  /// Verifies the identity anchor transaction's self-signature.
  ///
  /// The AIP output (output[2]) contains an ED25519 signature over a SHA256 hash
  /// of the pre-tx (the transaction built without the AIP output).
  ///
  /// To verify, we rebuild the pre-tx by constructing a transaction with
  /// the same inputs and all outputs except the AIP output (output[2]).
  static Future<bool> verifyIdentityAnchor(Transaction identityAnchorTx) async {
    var pubkeyHex = IdentityAnchorBuilder.extractPublicKey(identityAnchorTx);
    var signatureHex = IdentityAnchorBuilder.extractSignature(identityAnchorTx);

    if (pubkeyHex.isEmpty || signatureHex.isEmpty) return false;

    // Rebuild the pre-tx (without the AIP output at index 2)
    // Output layout: [0]=change, [1]=MAP metadata, [2]=AIP signature
    // Pre-tx had:    [0]=change, [1]=MAP metadata
    var preTxBuilder = TransactionBuilder();

    for (var input in identityAnchorTx.inputs) {
      var unlocker = DefaultUnlockBuilder.fromScript(input.script ?? ScriptBuilder.createEmpty());
      preTxBuilder.spendFromOutput(
          input.prevTxnId, input.prevTxnOutputIndex, BigInt.zero, input.sequenceNumber, unlocker);
    }

    // Add all outputs except the AIP output (index 2)
    for (var i = 0; i < identityAnchorTx.outputs.length; i++) {
      if (i == 2) continue;
      var output = identityAnchorTx.outputs[i];
      var locker = DefaultLockBuilder.fromScript(output.script);
      preTxBuilder.spendToLockBuilder(locker, output.satoshis);
    }

    var preTx = preTxBuilder.build(false);

    var preTxBytes = hex.decode(preTx.serialize());
    var preTxHash = await Sha256().hash(preTxBytes);

    var algorithm = Ed25519();
    var publicKey = SimplePublicKey(hex.decode(pubkeyHex), type: KeyPairType.ed25519);
    var sigBytes = hex.decode(signatureHex);
    var signature = Signature(sigBytes, publicKey: publicKey);

    try {
      return await algorithm.verify(preTxHash.bytes, signature: signature);
    } catch (_) {
      return false;
    }
  }
}
