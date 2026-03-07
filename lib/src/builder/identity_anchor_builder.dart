import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';

import 'aip_lockbuilder.dart';
import 'map_lockbuilder.dart';

/// Builds an identity anchor transaction for token issuers.
///
/// The identity anchor transaction is a standalone on-chain record that
/// establishes an issuer's identity. Output layout:
///   - Output 0: Change (added by TransactionBuilder)
///   - Output 1: OP_RETURN with MAP-formatted identity metadata
///   - Output 2: OP_RETURN with AIP signature + ED25519 pubkey covering
///               a SHA256 hash of the pre-tx (tx without the AIP output)
class IdentityAnchorBuilder {

  /// Key-value pairs of issuer identity metadata to store on-chain.
  final Map<String, String> identityMetadata;

  /// Creates an identity anchor builder with the given [identityMetadata].
  IdentityAnchorBuilder(this.identityMetadata);

  /// Builds the identity anchor transaction.
  ///
  /// [fundingTx] - Transaction with funding UTXO at output[1]
  /// [signer] - TransactionSigner for the funding input
  /// [fundingPubKey] - Public key for the funding UTXO
  /// [changeAddress] - Address to send change to
  /// [wand] - ED25519 SignatureWand for signing the identity anchor
  Future<Transaction> buildTransaction(
      Transaction fundingTx,
      TransactionSigner signer,
      SVPublicKey fundingPubKey,
      Address changeAddress,
      SignatureWand wand,
      ) async {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);

    // Build the MAP metadata output with app and type prefixed
    var mapData = <String, String>{
      'app': 'tsl1',
      'type': 'issuer_identity',
    };
    mapData.addAll(identityMetadata);
    var mapLocker = MapLockBuilder.fromMap(mapData);

    // Step 1: Build the tx WITHOUT the AIP output
    var preTx = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendToLockBuilder(mapLocker, BigInt.zero) // MAP identity metadata
        .sendChangeToPKH(changeAddress)
        .withFeePerKb(1)
        .build(false);

    // Step 2: Hash the pre-tx (everything except the AIP output that we'll add)
    var preTxBytes = hex.decode(preTx.serialize());
    var preTxHash = Sha256().hash(preTxBytes);
    var hashBytes = (await preTxHash).bytes;

    // Step 3: Sign the hash with ED25519
    var signature = await wand.sign(hashBytes);
    SimplePublicKey pubkey = (await wand.extractPublicKeyUsedForSignatures() as SimplePublicKey);

    var b64Sig = base64Encode(signature.bytes);
    var pubkeyHex = hex.encode(pubkey.bytes);

    // Step 4: Build AIP output with signature + pubkey
    var aipLocker = AIPLockBuilder(pubkeyHex, b64Sig);

    // Step 5: Rebuild the full tx with the AIP output
    var fullTx = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendToLockBuilder(mapLocker, BigInt.zero) // MAP identity metadata
        .spendToLockBuilder(aipLocker, BigInt.zero) // AIP signature
        .sendChangeToPKH(changeAddress)
        .withFeePerKb(1)
        .build(false);

    return fullTx;
  }

  /// Extracts identity metadata from an identity anchor transaction's MAP output (output[1]).
  static Map<String, String> extractMetadata(Transaction identityAnchorTx) {
    var mapScript = identityAnchorTx.outputs[1].script;
    var mapLocker = MapLockBuilder.fromScript(mapScript);
    return mapLocker.map.map((k, v) => MapEntry(k, v.toString()));
  }

  /// Extracts the AIP public key from an identity anchor transaction's AIP output (output[2]).
  static String extractPublicKey(Transaction identityAnchorTx) {
    var aipScript = identityAnchorTx.outputs[2].script;
    var aipLocker = AIPLockBuilder.fromScript(aipScript);
    return aipLocker.publicKey ?? '';
  }

  /// Extracts the AIP signature from an identity anchor transaction's AIP output (output[2]).
  static String extractSignature(Transaction identityAnchorTx) {
    var aipScript = identityAnchorTx.outputs[2].script;
    var aipLocker = AIPLockBuilder.fromScript(aipScript);
    return aipLocker.signature ?? '';
  }
}
