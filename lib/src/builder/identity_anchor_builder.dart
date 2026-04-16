import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';

import 'aip_lockbuilder.dart';
import 'b_lockbuilder.dart';
import 'map_lockbuilder.dart';

/// Builds an identity anchor transaction for token issuers.
///
/// The identity anchor transaction is a standalone on-chain record that
/// establishes an issuer's identity. Output layout:
///   - Output 0: Change (added by TransactionBuilder)
///   - Output 1: OP_RETURN with MAP-formatted identity metadata
///   - Output 2: OP_RETURN with AIP signature + ED25519 pubkey covering
///               a SHA256 hash of the pre-tx (tx without the AIP output)
///   - Output 3: (optional) B:// artwork data
///
/// When artwork is provided, a SHA-256 hash of the artwork bytes is included
/// in the MAP metadata (key: `artworkHash`) so the AIP signature covers it.
class IdentityAnchorBuilder {

  /// Key-value pairs of issuer identity metadata to store on-chain.
  final Map<String, String> identityMetadata;

  /// Optional artwork image bytes to embed via B:// protocol.
  final List<int>? artworkBytes;

  /// MIME type of the artwork (e.g. 'image/png'). Required when [artworkBytes] is provided.
  final String? artworkMimeType;

  /// Creates an identity anchor builder with the given [identityMetadata]
  /// and optional artwork to embed as a B:// output.
  IdentityAnchorBuilder(this.identityMetadata, {this.artworkBytes, this.artworkMimeType});

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

    // NB: P2PKHUnlockBuilder stores signatures in an append-only list and
    // getScriptSig() always reads signatures[0]. If we reuse the same unlocker
    // across the preTx build (step 1) and the fullTx build (step 5), the
    // fullTx ends up embedding the preTx's stale signature — which covers a
    // different output set (no AIP) and fails CHECKSIG on broadcast (ARC 461,
    // NULLFAIL). Build a fresh unlocker for each build to avoid that.
    var preTxUnlocker = P2PKHUnlockBuilder(fundingPubKey);

    // Build the MAP metadata output with app and type prefixed
    var mapData = <String, String>{
      'app': 'tsl1',
      'type': 'issuer_identity',
    };
    mapData.addAll(identityMetadata);

    // If artwork is provided, include its SHA-256 hash in MAP so AIP covers it
    if (artworkBytes != null && artworkBytes!.isNotEmpty) {
      var artworkHash = await Sha256().hash(artworkBytes!);
      mapData['artworkHash'] = hex.encode(artworkHash.bytes);
      if (artworkMimeType != null) {
        mapData['artworkMimeType'] = artworkMimeType!;
      }
    }

    var mapLocker = MapLockBuilder.fromMap(mapData);

    // Optional B:// locker for artwork data
    BLockBuilder? artworkLocker;
    if (artworkBytes != null && artworkBytes!.isNotEmpty) {
      artworkLocker = BLockBuilder(
        artworkBytes!,
        artworkMimeType ?? 'application/octet-stream',
        'binary',
      );
    }

    // Step 1: Build the tx WITHOUT the AIP output (but WITH artwork if present)
    var preTxBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, preTxUnlocker)
        .spendToLockBuilder(mapLocker, BigInt.zero); // MAP identity metadata
    if (artworkLocker != null) {
      preTxBuilder.spendToLockBuilder(artworkLocker, BigInt.zero); // B:// artwork
    }
    var preTx = preTxBuilder
        .sendChangeToPKH(changeAddress)
        .withFeePerKb(100)
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

    // Step 5: Rebuild the full tx with AIP inserted at output[2].
    // Fresh unlocker here — see note at top of buildTransaction for why.
    // Layout: [0]=change, [1]=MAP, [2]=AIP, [3]=B:// artwork (optional)
    var fullTxUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var fullTxBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fullTxUnlocker)
        .spendToLockBuilder(mapLocker, BigInt.zero) // MAP identity metadata
        .spendToLockBuilder(aipLocker, BigInt.zero); // AIP signature
    if (artworkLocker != null) {
      fullTxBuilder.spendToLockBuilder(artworkLocker, BigInt.zero); // B:// artwork
    }
    var fullTx = fullTxBuilder
        .sendChangeToPKH(changeAddress)
        .withFeePerKb(100)
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

  /// Extracts artwork data from an identity anchor transaction's B:// output (output[3]).
  ///
  /// Returns null if no artwork output is present.
  static ({List<int> data, String mediaType})? extractArtwork(Transaction identityAnchorTx) {
    if (identityAnchorTx.outputs.length < 4) return null;
    try {
      var bLocker = BLockBuilder.fromScript(identityAnchorTx.outputs[3].script);
      if (bLocker.data == null || bLocker.data!.isEmpty) return null;
      return (data: bLocker.data!, mediaType: bLocker.mediaType ?? 'application/octet-stream');
    } catch (_) {
      return null;
    }
  }
}
