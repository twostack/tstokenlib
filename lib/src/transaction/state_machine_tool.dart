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
import '../builder/pp1_sm_lock_builder.dart';
import '../builder/pp1_sm_unlock_builder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import '../crypto/rabin.dart';
import '../script_gen/pp1_sm_script_gen.dart';
import 'utils.dart';

/// High-level API for creating State Machine Token (PP1_SM) transactions.
///
/// Supports: create, enroll, confirm, convert, settle, timeout, burn.
/// Dual authority: merchant signs enroll/settle/timeout; both merchant + customer
/// sign confirm/convert. Owner (whoever is "next expected actor") signs burn.
class StateMachineTool {
  final NetworkType networkType;
  final BigInt defaultFee;

  StateMachineTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Constructs a 36-byte outpoint (txid + output index 1).
  List<int> getOutpoint(List<int> txId) {
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId);
    outputWriter.writeUint32(1, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates an SM issuance transaction with 5-output structure:
  /// Change, PP1_SM, PP2, PartialWitness, Metadata.
  ///
  /// [tokenFundingTx] funds the issuance; its txid becomes the initial tokenId.
  /// [merchantAddress] is the initial owner (merchant creates the funnel).
  /// [merchantPKH] 20-byte hash160 of the merchant's public key.
  /// [customerPKH] 20-byte hash160 of the customer's public key.
  /// [transitionBitmask] bitmask controlling which transitions are enabled.
  /// [timeoutDelta] timeout delta in seconds.
  /// [witnessFundingTxId] txid of the tx that will fund the first witness.
  Transaction createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address merchantAddress,
      List<int> merchantPKH,
      List<int> customerPKH,
      int transitionBitmask,
      int timeoutDelta,
      List<int> witnessFundingTxId,
      List<int> rabinPubKeyHash,
      {List<int>? metadataBytes}) {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash;

    var initialCommitmentHash = List<int>.filled(32, 0);

    // ownerPKH = merchantPKH at creation (merchant is first actor)
    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    var pp1Locker = PP1SmLockBuilder(
        merchantAddress, tokenId, merchantPKH, customerPKH, rabinPubKeyHash,
        0, 0, initialCommitmentHash, transitionBitmask, timeoutDelta);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    // PP2 output
    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId),
        hex.decode(merchantAddress.pubkeyHash160), 1,
        hex.decode(merchantAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    // PartialWitness output
    var shaLocker = PartialWitnessLockBuilder(hex.decode(merchantAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

    // Metadata OP_RETURN output
    var metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

    tokenTxBuilder.sendChangeToPKH(merchantAddress);
    return tokenTxBuilder.build(false);
  }

  /// Creates a witness transaction for a single-sig SM operation (enroll, settle, timeout).
  ///
  /// [action] must be ENROLL, SETTLE, or TIMEOUT.
  /// [merchantPubkey] merchant's public key (signs).
  /// [eventData] operation-specific data (enroll event, settlement data, etc.)
  /// [custRewardAmount] required for SETTLE.
  /// [merchPayAmount] required for SETTLE.
  /// [refundAmount] required for TIMEOUT.
  /// [nLockTime] required for TIMEOUT (must match token tx nLockTime).
  Transaction createWitnessTxn(
      TransactionSigner signer,
      Transaction fundingTx,
      Transaction tokenTx,
      List<int> parentTokenTxBytes,
      SVPublicKey merchantPubkey,
      String tokenChangePKH,
      StateMachineAction action,
      {List<int>? eventData,
      BigInt? custRewardAmount,
      BigInt? merchPayAmount,
      BigInt? refundAmount,
      int? nLockTime,
      int pp1OutputIndex = 1,
      int pp2OutputIndex = 2,
      List<int>? rabinN,
      List<int>? rabinS,
      int? rabinPadding,
      List<int>? identityTxId,
      List<int>? ed25519PubKey}) {

    var signerAddress = Address.fromPublicKey(merchantPubkey, networkType);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(signerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(merchantPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // For TIMEOUT, nSequence must be < MAX to enable nLockTime
    var seqNum = nLockTime != null
        ? TransactionInput.MAX_SEQ_NUMBER - 1
        : TransactionInput.MAX_SEQ_NUMBER;

    var preImageBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, seqNum, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, pp1OutputIndex, seqNum, emptyUnlocker)
        .spendFromTxn(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100));
    if (nLockTime != null) preImageBuilder.lockUntilBlockHeight(nLockTime);
    var preImageTxn = preImageBuilder.build(false);

    var subscript1 = tokenTx.outputs[pp1OutputIndex].script;
    var preImagePP1 = Sighash().createSighashPreImage(preImageTxn, sigHashAll, 1, subscript1, BigInt.one);

    var tsl1 = TransactionUtils();
    var tokenTxLHS = tsl1.getTxLHS(tokenTx);
    var paddingBytes = Uint8List(1);
    var pp2Output = tokenTx.outputs[pp2OutputIndex].serialize();
    var tokenChangeAmount = tokenTx.outputs[0].satoshis;

    // Rabin signature is pre-computed by the caller. The tool never sees the private key.
    var fundingOutpoint = Uint8List(36);
    fundingOutpoint.setAll(0, fundingTx.hash);
    fundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var pp1UnlockBuilder = PP1SmUnlockBuilder(
        preImagePP1!, pp2Output, merchantPubkey, tokenChangePKH,
        tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        action, fundingOutpoint,
        eventData: eventData,
        custRewardAmount: custRewardAmount,
        merchPayAmount: merchPayAmount,
        refundAmount: refundAmount,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: rabinPadding,
        identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);

    var witnessBuilder1 = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, seqNum, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, pp1OutputIndex, seqNum, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one);
    if (nLockTime != null) witnessBuilder1.lockUntilBlockHeight(nLockTime);
    var witnessTx = witnessBuilder1.build(false);

    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1UnlockBuilder = PP1SmUnlockBuilder(
        preImagePP1, pp2Output, merchantPubkey, tokenChangePKH,
        tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        action, fundingOutpoint,
        eventData: eventData,
        custRewardAmount: custRewardAmount,
        merchPayAmount: merchPayAmount,
        refundAmount: refundAmount,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: rabinPadding,
        identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);

    var witnessBuilder2 = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, 1, seqNum, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, pp1OutputIndex, seqNum, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one);
    if (nLockTime != null) witnessBuilder2.lockUntilBlockHeight(nLockTime);
    witnessTx = witnessBuilder2.build(false);

    return witnessTx;
  }

  /// Creates a witness transaction for a dual-sig SM operation (confirm, convert).
  ///
  /// Two-pass: builds tx to compute sighash, signs with both keys, rebuilds.
  /// [action] must be CONFIRM or CONVERT.
  /// [eventData] milestone data or conversion data.
  Transaction createDualWitnessTxn(
      TransactionSigner merchantSigner,
      SVPrivateKey customerPrivateKey,
      Transaction fundingTx,
      Transaction tokenTx,
      List<int> parentTokenTxBytes,
      SVPublicKey merchantPubkey,
      SVPublicKey customerPubkey,
      String tokenChangePKH,
      StateMachineAction action,
      List<int> eventData) {

    var signerAddress = Address.fromPublicKey(merchantPubkey, networkType);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(signerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(merchantPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First pass: build tx to get sighash preimage
    var preImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(merchantSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(merchantSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript1 = tokenTx.outputs[1].script;
    var preImagePP1 = Sighash().createSighashPreImage(preImageTxn, sigHashAll, 1, subscript1, BigInt.one);

    // Compute customer signature off-chain (same sighash preimage)
    var customerSig = DefaultTransactionSigner.signPreimageWithKey(
        customerPrivateKey, Uint8List.fromList(preImagePP1!), sigHashAll);
    var customerSigBytes = hex.decode(customerSig.toTxFormat());

    var tsl1 = TransactionUtils();
    var tokenTxLHS = tsl1.getTxLHS(tokenTx);
    var paddingBytes = Uint8List(1);
    var pp2Output = tokenTx.outputs[2].serialize();
    var tokenChangeAmount = tokenTx.outputs[0].satoshis;

    var dualFundingOutpoint = Uint8List(36);
    dualFundingOutpoint.setAll(0, fundingTx.hash);
    dualFundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var pp1UnlockBuilder = PP1SmUnlockBuilder(
        preImagePP1, pp2Output, merchantPubkey, tokenChangePKH,
        tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        action, dualFundingOutpoint,
        eventData: eventData,
        customerPubKey: customerPubkey,
        customerSigBytes: customerSigBytes);

    var witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(merchantSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(merchantSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1UnlockBuilder = PP1SmUnlockBuilder(
        preImagePP1, pp2Output, merchantPubkey, tokenChangePKH,
        tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        action, dualFundingOutpoint,
        eventData: eventData,
        customerPubKey: customerPubkey,
        customerSigBytes: customerSigBytes);

    witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(merchantSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(merchantSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    return witnessTx;
  }

  /// Creates an enroll token transaction (INIT→ACTIVE).
  ///
  /// Merchant signs. 5-output structure: Change, PP1_SM, PP2, PP3, Metadata.
  /// ownerPKH updates to customerPKH.
  Transaction createEnrollTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey merchantPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      List<int> eventData) {

    var merchantAddress = Address.fromPublicKey(merchantPubkey, networkType);
    var prevPP1 = PP1SmLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    // New ownerPKH = customerPKH (customer acts next)
    var customerAddress = Address.fromPubkeyHash(
        hex.encode(prevPP1.customerPKH!), networkType);

    // Compute new commitment hash off-chain:
    // eventDigest = SHA256(eventData)
    // newCommitHash = SHA256(parentCommitHash || eventDigest)
    var parentCommitHash = prevPP1.commitmentHash!;
    var eventDigest = crypto.sha256.convert(eventData).bytes;
    var newCommitHash = crypto.sha256.convert(
        [...parentCommitHash, ...eventDigest]).bytes;

    var pp1Locker = PP1SmLockBuilder(
        customerAddress, prevPP1.tokenId!, prevPP1.merchantPKH!,
        prevPP1.customerPKH!, prevPP1.rabinPubKeyHash!,
        1, 0, // state=ACTIVE, mc unchanged
        List<int>.from(newCommitHash),
        prevPP1.transitionBitmask, prevPP1.timeoutDelta);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId),
        hex.decode(customerAddress.pubkeyHash160), 1,
        hex.decode(customerAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(customerAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(merchantPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(merchantAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var enrollFundingOutpoint = Uint8List(36);
    enrollFundingOutpoint.setAll(0, fundingTx.hash);
    enrollFundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        enrollFundingOutpoint);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(merchantAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a state transition token transaction.
  ///
  /// Generic method for confirm, convert, settle, timeout transitions.
  /// Spends PP3 from prevTokenTx, creates 5-output structure.
  ///
  /// [newState] the post-transition state value.
  /// [newOwnerPKH] 20-byte PKH for the next expected actor.
  /// [incrementMilestone] if true, milestoneCount is incremented.
  /// [eventData] operation-specific data (null for timeout).
  Transaction createTransitionTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey signerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      int newState,
      List<int> newOwnerPKH,
      {bool incrementMilestone = false,
      List<int>? eventData}) {

    var signerAddress = Address.fromPublicKey(signerPubkey, networkType);
    var prevPP1 = PP1SmLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    var newOwnerAddress = Address.fromPubkeyHash(
        hex.encode(newOwnerPKH), networkType);

    // Compute new commitment hash off-chain
    List<int> newCommitHash;
    if (eventData != null) {
      var parentCommitHash = prevPP1.commitmentHash!;
      var eventDigest = crypto.sha256.convert(eventData).bytes;
      newCommitHash = List<int>.from(
          crypto.sha256.convert([...parentCommitHash, ...eventDigest]).bytes);
    } else {
      newCommitHash = prevPP1.commitmentHash!;
    }

    var newMC = incrementMilestone ? prevPP1.milestoneCount + 1 : prevPP1.milestoneCount;

    var pp1Locker = PP1SmLockBuilder(
        newOwnerAddress, prevPP1.tokenId!, prevPP1.merchantPKH!,
        prevPP1.customerPKH!, prevPP1.rabinPubKeyHash!,
        newState, newMC, newCommitHash,
        prevPP1.transitionBitmask, prevPP1.timeoutDelta);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId),
        hex.decode(newOwnerAddress.pubkeyHash160), 1,
        hex.decode(newOwnerAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(newOwnerAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(signerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var transitionFundingOutpoint = Uint8List(36);
    transitionFundingOutpoint.setAll(0, fundingTx.hash);
    transitionFundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        transitionFundingOutpoint);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a settle token transaction (CONVERTING→SETTLED, 7-output topology).
  ///
  /// 7-output structure: Change(0), CustomerReward(1), MerchantPayment(2),
  /// PP1_SM(3), PP2(4), PP3(5), Metadata(6).
  ///
  /// Customer reward and merchant payment are P2PKH outputs using the immutable
  /// customerPKH and merchantPKH from the PP1_SM header.
  Transaction createSettleTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey signerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      BigInt custRewardAmount,
      BigInt merchPayAmount,
      {List<int>? eventData}) {

    var signerAddress = Address.fromPublicKey(signerPubkey, networkType);
    var prevPP1 = PP1SmLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    // Merchant owns settled token (terminal state)
    var newOwnerPKH = prevPP1.merchantPKH!;
    var newOwnerAddress = Address.fromPubkeyHash(
        hex.encode(newOwnerPKH), networkType);

    // Compute new commitment hash off-chain
    List<int> newCommitHash;
    if (eventData != null) {
      var parentCommitHash = prevPP1.commitmentHash!;
      var eventDigest = crypto.sha256.convert(eventData).bytes;
      newCommitHash = List<int>.from(
          crypto.sha256.convert([...parentCommitHash, ...eventDigest]).bytes);
    } else {
      newCommitHash = prevPP1.commitmentHash!;
    }

    // P2PKH outputs for customer reward and merchant payment
    var custRewardAddress = Address.fromPubkeyHash(
        hex.encode(prevPP1.customerPKH!), networkType);
    var merchPayAddress = Address.fromPubkeyHash(
        hex.encode(prevPP1.merchantPKH!), networkType);
    var custRewardLocker = P2PKHLockBuilder.fromAddress(custRewardAddress);
    var merchPayLocker = P2PKHLockBuilder.fromAddress(merchPayAddress);

    var pp1Locker = PP1SmLockBuilder(
        newOwnerAddress, prevPP1.tokenId!, prevPP1.merchantPKH!,
        prevPP1.customerPKH!, prevPP1.rabinPubKeyHash!,
        4, prevPP1.milestoneCount, newCommitHash,
        prevPP1.transitionBitmask, prevPP1.timeoutDelta);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId),
        hex.decode(newOwnerAddress.pubkeyHash160), 1,
        hex.decode(newOwnerAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(newOwnerAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(signerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First build to compute PP3 spending sighash
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(custRewardLocker, custRewardAmount)
        .spendToLockBuilder(merchPayLocker, merchPayAmount)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var settleFundingOutpoint = Uint8List(36);
    settleFundingOutpoint.setAll(0, fundingTx.hash);
    settleFundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        settleFundingOutpoint);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(custRewardLocker, custRewardAmount)
        .spendToLockBuilder(merchPayLocker, merchPayAmount)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a timeout token transaction (any non-terminal → EXPIRED, 6-output topology).
  ///
  /// 6-output structure: Change(0), MerchantRefund(1), PP1_SM(2), PP2(3), PP3(4), Metadata(5).
  ///
  /// Merchant refund is a P2PKH output using the immutable merchantPKH from the header.
  /// nLockTime is set to [nLockTime] (must be >= header's timeoutDelta).
  Transaction createTimeoutTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey signerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      BigInt refundAmount,
      int nLockTime) {

    var signerAddress = Address.fromPublicKey(signerPubkey, networkType);
    var prevPP1 = PP1SmLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    // Merchant owns expired token (terminal state)
    var newOwnerPKH = prevPP1.merchantPKH!;
    var newOwnerAddress = Address.fromPubkeyHash(
        hex.encode(newOwnerPKH), networkType);

    // Timeout preserves parent's commitment hash (no update)
    var parentCommitHash = prevPP1.commitmentHash!;

    // Merchant refund P2PKH output
    var merchRefundAddress = Address.fromPubkeyHash(
        hex.encode(prevPP1.merchantPKH!), networkType);
    var merchRefundLocker = P2PKHLockBuilder.fromAddress(merchRefundAddress);

    var pp1Locker = PP1SmLockBuilder(
        newOwnerAddress, prevPP1.tokenId!, prevPP1.merchantPKH!,
        prevPP1.customerPKH!, prevPP1.rabinPubKeyHash!,
        5, prevPP1.milestoneCount, parentCommitHash,
        prevPP1.transitionBitmask, prevPP1.timeoutDelta);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId),
        hex.decode(newOwnerAddress.pubkeyHash160), 1,
        hex.decode(newOwnerAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(newOwnerAddress.pubkeyHash160));

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(signerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // nSequence must be < MAX for nLockTime to be enforced
    var lockTimeSeq = TransactionInput.MAX_SEQ_NUMBER - 1;

    // First build to compute PP3 spending sighash
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, lockTimeSeq, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, lockTimeSeq, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, lockTimeSeq, emptyUnlocker)
        .spendToLockBuilder(merchRefundLocker, refundAmount)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .lockUntilBlockHeight(nLockTime)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var timeoutFundingOutpoint = Uint8List(36);
    timeoutFundingOutpoint.setAll(0, fundingTx.hash);
    timeoutFundingOutpoint.buffer.asByteData().setUint32(32, 1, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        timeoutFundingOutpoint);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, lockTimeSeq, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, lockTimeSeq, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, lockTimeSeq, sha256Unlocker)
        .spendToLockBuilder(merchRefundLocker, refundAmount)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(signerAddress)
        .withFee(defaultFee)
        .lockUntilBlockHeight(nLockTime)
        .build(false);

    return childTxn;
  }

  /// Creates a burn transaction for an SM token in terminal state (SETTLED or EXPIRED).
  ///
  /// Owner signs. Spends PP1_SM, PP2, and PartialWitness outputs.
  /// [pp1OutputIndex], [pp2OutputIndex], [pp3OutputIndex] specify the output
  /// positions in [tokenTx] (default 1,2,3 for standard topology; settle uses 3,4,5).
  Transaction createBurnTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      {int pp1OutputIndex = 1,
       int pp2OutputIndex = 2,
       int pp3OutputIndex = 3}) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1BurnUnlocker = PP1SmUnlockBuilder.forBurn(ownerPubkey);
    var pp2BurnUnlocker = PP2UnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, pp1OutputIndex, TransactionInput.MAX_SEQ_NUMBER, pp1BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, pp2OutputIndex, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, pp3OutputIndex, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return burnTx;
  }
}
