/*
  Copyright 2024 - Stephan M. February

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import 'dart:typed_data';
import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';
import '../builder/partial_witness_lock_builder.dart';
import '../builder/partial_witness_unlock_builder.dart';
import '../builder/pp1_at_lock_builder.dart';
import '../builder/pp1_at_unlock_builder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import 'utils.dart';

/// High-level API for creating Appendable Token (PP1_AT) transactions.
///
/// Supports issuance, stamp, transfer, redeem, and burn operations.
/// Dual authority model: issuer signs issue/stamp, owner signs transfer/redeem/burn.
class AppendableTokenTool {
  final NetworkType networkType;
  final BigInt defaultFee;

  AppendableTokenTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Creates a witness transaction for an AT token.
  ///
  /// [signer] signs both the funding input and PP1.
  /// [fundingTx] provides the funding UTXO at output[1].
  /// [tokenTx] is the token transaction to witness.
  /// [parentTokenTxBytes] raw bytes of the parent token transaction.
  /// [pubkey] public key of the signer (issuer for issue/stamp, owner for transfer).
  /// [tokenChangePKH] pubkey hash for the token's change output.
  /// [action] specifies the token action.
  /// [stampMetadata] required for STAMP action.
  Transaction createWitnessTxn(
      TransactionSigner signer,
      Transaction fundingTx,
      Transaction tokenTx,
      List<int> parentTokenTxBytes,
      SVPublicKey pubkey,
      String tokenChangePKH,
      AppendableTokenAction action,
      {List<int>? stampMetadata}) {

    var signerAddress = Address.fromPublicKey(pubkey, networkType);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(signerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(pubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var preImageTxnForPP1 = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker) //PP1_AT
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker) //PP2
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript1 = tokenTx.outputs[1].script;
    var preImagePP1 = Sighash().createSighashPreImage(preImageTxnForPP1, sigHashAll, 1, subscript1, BigInt.one);

    var tsl1 = TransactionUtils();
    var tokenTxLHS = tsl1.getTxLHS(tokenTx);
    var paddingBytes = Uint8List(1);
    var pp2Output = tokenTx.outputs[2].serialize();
    var tokenChangeAmount = tokenTx.outputs[0].satoshis;

    var pp1UnlockBuilder = PP1AtUnlockBuilder(preImagePP1!, pp2Output, pubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingTx.hash,
        stampMetadata: stampMetadata);
    var witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1UnlockBuilder = PP1AtUnlockBuilder(preImagePP1, pp2Output, pubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingTx.hash,
        stampMetadata: stampMetadata);

    witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    return witnessTx;
  }

  /// Constructs a 36-byte outpoint (txid + output index 1).
  List<int> getOutpoint(List<int> txId) {
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId);
    outputWriter.writeUint32(1, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates an AT issuance transaction with 5-output structure:
  /// Change, PP1_AT, PP2, PartialWitness, Metadata.
  ///
  /// [tokenFundingTx] funds the issuance; its txid becomes the initial tokenId.
  /// [recipientAddress] is the initial card holder (customer).
  /// [witnessFundingTxId] txid of the transaction that will fund the first witness.
  /// [issuerPKH] is the 20-byte hash160 of the issuer's (shop) public key.
  /// [threshold] stamps required for redemption.
  /// [metadataBytes] optional raw metadata to embed in the OP_RETURN output.
  Transaction createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address recipientAddress,
      List<int> witnessFundingTxId,
      List<int> issuerPKH,
      int threshold,
      {List<int>? metadataBytes}) {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash;

    // Initial stamps hash is SHA256 of 32 zero bytes (empty chain)
    var initialStampsHash = List<int>.filled(32, 0);

    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    // PP1_AT output
    var pp1Locker = PP1AtLockBuilder(recipientAddress, tokenId, issuerPKH, 0, threshold, initialStampsHash);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    // PP2 output
    var outputWriter = ByteDataWriter();
    outputWriter.write(witnessFundingTxId);
    outputWriter.writeUint32(1, Endian.little);
    var fundingOutpoint = outputWriter.toBytes();

    var pp2Locker = PP2LockBuilder(fundingOutpoint, hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    // PartialWitness output
    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

    // Metadata OP_RETURN output
    var metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

    tokenTxBuilder.sendChangeToPKH(recipientAddress);

    return tokenTxBuilder.build(false);
  }

  /// Creates an AT transfer transaction with 5-output structure.
  ///
  /// Owner signs. Only ownerPKH changes in the PP1_AT output.
  ///
  /// [prevWitnessTx] is the previous witness transaction.
  /// [prevTokenTx] is the parent token transaction.
  /// [currentOwnerPubkey] current holder's public key.
  /// [recipientAddress] new holder's address.
  /// [tokenId] persistent token identifier.
  Transaction createTokenTransferTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId,
      List<int> tokenId) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);

    // Parse previous PP1_AT to carry forward immutable params
    var prevPP1 = PP1AtLockBuilder.fromScript(prevTokenTx.outputs[1].script);
    var pp1LockBuilder = PP1AtLockBuilder(recipientAddress, tokenId, prevPP1.issuerPKH!, prevPP1.stampCount, prevPP1.threshold, prevPP1.stampsHash!);

    var pp2Locker = PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        fundingTx.hash);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a stamp transaction that adds a stamp to the AT token.
  ///
  /// Issuer signs. Updates stampCount (+1) and stampsHash (rolling SHA256).
  ///   newStamp = SHA256(stampMetadata)
  ///   newStampsHash = SHA256(parentStampsHash || newStamp)
  ///
  /// [prevWitnessTx] is the previous witness transaction.
  /// [prevTokenTx] is the parent token transaction.
  /// [issuerPubkey] the issuer (shop) public key.
  /// [fundingTx] funds the stamp transaction.
  /// [issuerWitnessFundingTxId] txid of the tx that will fund the stamp witness.
  /// [stampMetadata] arbitrary data for this stamp (e.g., receipt hash).
  Transaction createTokenStampTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey issuerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> issuerWitnessFundingTxId,
      List<int> stampMetadata) {

    var issuerAddress = Address.fromPublicKey(issuerPubkey, networkType);

    // Parse previous PP1_AT to carry forward params and compute rolling hash
    var prevPP1 = PP1AtLockBuilder.fromScript(prevTokenTx.outputs[1].script);
    var ownerAddress = prevPP1.recipientAddress!;

    // Compute new stamp values off-chain
    var newStamp = Uint8List.fromList(crypto.sha256.convert(stampMetadata).bytes);
    var parentStampsHash = prevPP1.stampsHash!;
    var combined = Uint8List.fromList([...parentStampsHash, ...newStamp]);
    var newStampsHash = Uint8List.fromList(crypto.sha256.convert(combined).bytes);
    var newStampCount = prevPP1.stampCount + 1;

    // Build new PP1_AT with updated stampCount and stampsHash (ownerPKH unchanged)
    var pp1LockBuilder = PP1AtLockBuilder(ownerAddress, prevPP1.tokenId!, prevPP1.issuerPKH!,
        newStampCount, prevPP1.threshold, newStampsHash.toList());

    var pp2Locker = PP2LockBuilder(getOutpoint(issuerWitnessFundingTxId),
        hex.decode(ownerAddress.pubkeyHash160), 1, hex.decode(ownerAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(ownerAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(issuerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(issuerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        fundingTx.hash);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(issuerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a burn transaction that destroys an AT token.
  ///
  /// Owner signs. Spends PP1_AT, PP2, and PartialWitness outputs.
  Transaction createBurnTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1BurnUnlocker = PP1AtUnlockBuilder.forBurn(ownerPubkey);
    var pp2BurnUnlocker = PP2UnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return burnTx;
  }

  /// Creates a redeem transaction for an AT token.
  ///
  /// Owner signs. Burns the token (threshold must be met).
  /// Spends PP1_AT, PP2, and PartialWitness outputs.
  Transaction createRedeemTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1RedeemUnlocker = PP1AtUnlockBuilder.forRedeem(ownerPubkey);
    var pp2BurnUnlocker = PP2UnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessUnlockBuilder.forBurn(ownerPubkey);

    var redeemTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1RedeemUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return redeemTx;
  }
}
