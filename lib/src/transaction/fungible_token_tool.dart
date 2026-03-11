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
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';

import '../builder/metadata_lock_builder.dart';
import '../builder/pp1_ft_lock_builder.dart';
import '../builder/pp1_ft_unlock_builder.dart';
import '../builder/pp2_ft_lock_builder.dart';
import '../builder/pp2_ft_unlock_builder.dart';
import '../builder/partial_witness_ft_lock_builder.dart';
import '../builder/partial_witness_ft_unlock_builder.dart';
import 'utils.dart';

/// High-level API for creating fungible token transactions using the TSL1-FT protocol.
///
/// Encapsulates the construction of multi-output token transactions with
/// balance conservation, supporting mint, transfer, split, merge, and burn operations.
///
/// Transaction structures:
/// - Mint/Transfer/Merge: 5 outputs [Change, PP1_FT, PP2-FT, PP3-FT, Metadata]
/// - Split: 8 outputs [Change, PP1_FT-recv, PP2FT-recv, PP3FT-recv, PP1_FT-change, PP2FT-change, PP3FT-change, Metadata]
/// - Witness: 1 output [Witness]
/// - Burn: 1 output [Change]
class FungibleTokenTool {

  /// The BSV network type (mainnet or testnet) used for address derivation.
  final NetworkType networkType;

  /// Default transaction fee in satoshis, applied to transfer and burn transactions.
  final BigInt defaultFee;

  /// Creates a [FungibleTokenTool] instance.
  FungibleTokenTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Constructs a 36-byte outpoint from a transaction ID and output index.
  List<int> getOutpoint(List<int> txId, {int outputIndex = 1}) {
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId);
    outputWriter.writeUint32(outputIndex, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates a 5-output fungible token mint transaction.
  ///
  /// Outputs: [Change, PP1_FT, PP2-FT, PP3-FT, Metadata]
  ///
  /// [tokenFundingTx] funds the mint; its txid becomes the tokenId.
  /// [amount] is the initial token supply.
  /// [witnessFundingTxId] is the txid of the transaction that will fund the first witness.
  Future<Transaction> createFungibleMintTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address recipientAddress,
      List<int> witnessFundingTxId,
      int amount,
      {List<int>? metadataBytes}
  ) async {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash;
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);

    // Fund the transaction
    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    // Output 1: PP1_FT (fungible token state)
    var pp1FtLocker = PP1FtLockBuilder(recipientPKH, tokenId, amount);
    tokenTxBuilder.spendToLockBuilder(pp1FtLocker, BigInt.one);

    // Output 2: PP2-FT (witness bridge)
    var fundingOutpoint = getOutpoint(witnessFundingTxId);
    var pp2FtLocker = PP2FtLockBuilder(fundingOutpoint, recipientPKH, 1, recipientPKH, 1, 2);
    tokenTxBuilder.spendToLockBuilder(pp2FtLocker, BigInt.one);

    // Output 3: PP3-FT (partial SHA256 witness verifier)
    var pp3FtLocker = PartialWitnessFtLockBuilder(recipientPKH, 2);
    tokenTxBuilder.spendToLockBuilder(pp3FtLocker, BigInt.one);

    // Output 4: Metadata (OP_RETURN)
    var metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

    tokenTxBuilder.sendChangeToPKH(recipientAddress);

    return tokenTxBuilder.build(false);
  }

  /// Creates a witness transaction for a fungible token.
  ///
  /// Produces a 1-output transaction: Witness (locked to current token holder).
  /// Spends PP1_FT and PP2-FT from [tokenTx].
  ///
  /// [action] determines which PP1_FT function selector is used:
  /// - MINT: validates hashPrevouts (no parent needed)
  /// - TRANSFER: validates inductive proof from parent
  /// - SPLIT_TRANSFER: validates split with balance conservation
  ///
  /// [parentTokenTxBytes] is required for TRANSFER, SPLIT_TRANSFER, and MERGE actions.
  /// [tripletBaseIndex] is 1 for standard triplet, 4 for change triplet (after split).
  /// For MERGE: [parentTokenTxBytesB], [parentOutputCountB], [parentPP1FtIndexA],
  /// [parentPP1FtIndexB] provide the second parent's data.
  Transaction createFungibleWitnessTxn(
      TransactionSigner fundingSigner,
      Transaction fundingTx,
      Transaction tokenTx,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      FungibleTokenAction action,
      {List<int>? parentTokenTxBytes,
       int parentOutputCount = 5,
       int tripletBaseIndex = 1,
       List<int>? parentTokenTxBytesB,
       int parentOutputCountB = 5,
       int parentPP1FtIndexA = 1,
       int parentPP1FtIndexB = 1}
  ) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var pp1FtIndex = tripletBaseIndex;
    var pp2Index = tripletBaseIndex + 1;

    var pp2FtUnlocker = PP2FtUnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(ownerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First pass: build with empty PP1_FT unlocker to get preImage
    var preImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendFromTxn(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript = tokenTx.outputs[pp1FtIndex].script;
    var preImage = Sighash().createSighashPreImage(preImageTxn, sigHashAll, 1, subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var tokenTxLHS = tsl1.getTxLHS(tokenTx);
    var paddingBytes = Uint8List(1);

    // Build PP1_FT unlocker and rebuild with padding (two passes)
    var pp1FtUnlocker = _buildPP1FtUnlocker(action, preImage!, tokenTx, ownerPubkey,
        tokenChangePKH, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        parentOutputCount, tripletBaseIndex, fundingTx.hash,
        parentTokenTxBytesB: parentTokenTxBytesB,
        parentOutputCountB: parentOutputCountB,
        parentPP1FtIndexA: parentPP1FtIndexA,
        parentPP1FtIndexB: parentPP1FtIndexB);

    var witnessTx = _buildWitnessTxn(fundingSigner, fundingTx, tokenTx,
        pp1FtIndex, pp2Index, ownerPubkey, pp1FtUnlocker, pp2FtUnlocker, witnessLocker);

    // Recalculate padding
    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1FtUnlocker = _buildPP1FtUnlocker(action, preImage, tokenTx, ownerPubkey,
        tokenChangePKH, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        parentOutputCount, tripletBaseIndex, fundingTx.hash,
        parentTokenTxBytesB: parentTokenTxBytesB,
        parentOutputCountB: parentOutputCountB,
        parentPP1FtIndexA: parentPP1FtIndexA,
        parentPP1FtIndexB: parentPP1FtIndexB);

    witnessTx = _buildWitnessTxn(fundingSigner, fundingTx, tokenTx,
        pp1FtIndex, pp2Index, ownerPubkey, pp1FtUnlocker, pp2FtUnlocker, witnessLocker);

    return witnessTx;
  }

  /// Creates a fungible token transfer transaction (5 outputs, full balance transfer).
  ///
  /// Spends: FundingUTXO, previous Witness output, and PP3-FT from [prevTokenTx].
  /// Metadata is carried forward from the parent token transaction.
  ///
  /// [amount] is the full token balance being transferred.
  /// [prevTripletBaseIndex] is 1 for standard triplet, 4 for change triplet.
  Transaction createFungibleTransferTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId,
      List<int> tokenId,
      int amount,
      {int prevTripletBaseIndex = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);
    var prevPP3Index = prevTripletBaseIndex + 2;

    // Build output lockers
    var pp1FtLocker = PP1FtLockBuilder(recipientPKH, tokenId, amount);
    var pp2FtLocker = PP2FtLockBuilder(
        getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
    var pp3FtLocker = PartialWitnessFtLockBuilder(recipientPKH, 2);

    // Carry forward metadata from parent token tx (last output)
    var metadataScript = prevTokenTx.outputs.last.script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    // Input unlockers
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First pass: build with empty PP3-FT unlocker to get preImage
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1FtLocker, BigInt.one)
        .spendToLockBuilder(pp2FtLocker, BigInt.one)
        .spendToLockBuilder(pp3FtLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[prevPP3Index].script;
    var sigPreImage = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    var pp3FtUnlocker = PartialWitnessFtUnlockBuilder(
        sigPreImage!, partialHash, witnessPartialPreImage, fundingTx.hash);

    // Final build with PP3-FT unlocker
    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
        .spendToLockBuilder(pp1FtLocker, BigInt.one)
        .spendToLockBuilder(pp2FtLocker, BigInt.one)
        .spendToLockBuilder(pp3FtLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates an 8-output split transfer transaction.
  ///
  /// Outputs: [Change, PP1_FT-recv, PP2FT-recv, PP3FT-recv, PP1_FT-change, PP2FT-change, PP3FT-change, Metadata]
  ///
  /// [sendAmount] tokens go to [recipientAddress], remainder stays with sender.
  /// [totalAmount] is the full token balance being split (must equal sendAmount + change).
  /// [recipientWitnessFundingTxId] funds the recipient's witness.
  /// [changeWitnessFundingTxId] funds the sender's change witness.
  Transaction createFungibleSplitTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      int sendAmount,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId,
      List<int> changeWitnessFundingTxId,
      List<int> tokenId,
      int totalAmount,
      {int prevTripletBaseIndex = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);
    var senderPKH = hex.decode(currentOwnerAddress.pubkeyHash160);
    var changeTokenAmount = totalAmount - sendAmount;
    var prevPP3Index = prevTripletBaseIndex + 2;

    // Recipient triplet (outputs 1,2,3)
    var pp1FtRecipientLocker = PP1FtLockBuilder(recipientPKH, tokenId, sendAmount);
    var pp2FtRecipientLocker = PP2FtLockBuilder(
        getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
    var pp3FtRecipientLocker = PartialWitnessFtLockBuilder(recipientPKH, 2);

    // Change triplet (outputs 4,5,6)
    var pp1FtChangeLocker = PP1FtLockBuilder(senderPKH, tokenId, changeTokenAmount);
    var pp2FtChangeLocker = PP2FtLockBuilder(
        getOutpoint(changeWitnessFundingTxId), senderPKH, 1, senderPKH, 4, 5);
    var pp3FtChangeLocker = PartialWitnessFtLockBuilder(senderPKH, 5);

    // Metadata (carried forward from parent, last output)
    var metadataScript = prevTokenTx.outputs.last.script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    // Input unlockers
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First pass: empty PP3-FT unlocker to get preImage
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp2FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp3FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp1FtChangeLocker, BigInt.one)
        .spendToLockBuilder(pp2FtChangeLocker, BigInt.one)
        .spendToLockBuilder(pp3FtChangeLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[prevPP3Index].script;
    var sigPreImage = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    var pp3FtUnlocker = PartialWitnessFtUnlockBuilder(
        sigPreImage!, partialHash, witnessPartialPreImage, fundingTx.hash);

    // Final build with PP3-FT unlocker
    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
        .spendToLockBuilder(pp1FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp2FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp3FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp1FtChangeLocker, BigInt.one)
        .spendToLockBuilder(pp2FtChangeLocker, BigInt.one)
        .spendToLockBuilder(pp3FtChangeLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Burns a fungible token by spending all proof outputs (PP1_FT, PP2-FT, PP3-FT).
  ///
  /// Change is sent back to the owner. [tripletBaseIndex] is 1 for standard
  /// triplet, 4 for change triplet (after split).
  Transaction createFungibleBurnTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      {int tripletBaseIndex = 1}
  ) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1FtBurnUnlocker = PP1FtUnlockBuilder.forBurn(ownerPubkey);
    var pp2FtBurnUnlocker = PP2FtUnlockBuilder.forBurn(ownerPubkey);
    var pp3FtBurnUnlocker = PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex, TransactionInput.MAX_SEQ_NUMBER, pp1FtBurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex + 1, TransactionInput.MAX_SEQ_NUMBER, pp2FtBurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex + 2, TransactionInput.MAX_SEQ_NUMBER, pp3FtBurnUnlocker)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return burnTx;
  }

  /// Creates a 5-output merge transaction combining two token UTXOs.
  ///
  /// Inputs: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
  /// Outputs: [Change, PP1_FT_merged, PP2-FT, PP3-FT, Metadata]
  ///
  /// PP3 inputs are burned (P2PKH only) rather than unlocked, because PP3-FT's
  /// hashPrevOuts verification hardcodes 3 inputs and cannot work with 5.
  /// Security is maintained: PP1_FT verifies outpoints, PP3 UTXOs prove parent txs exist.
  ///
  /// Both token UTXOs must have the same tokenId and be owned by [currentOwnerPubkey].
  /// [totalAmount] = amountA + amountB.
  /// [prevTripletBaseIndexA/B] = 1 for standard triplet, 4 for change triplet.
  Transaction createFungibleMergeTxn(
      Transaction prevWitnessTxA,
      Transaction prevTokenTxA,
      Transaction prevWitnessTxB,
      Transaction prevTokenTxB,
      SVPublicKey currentOwnerPubkey,
      TransactionSigner ownerSigner,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> mergedWitnessFundingTxId,
      List<int> tokenId,
      int totalAmount,
      {int prevTripletBaseIndexA = 1,
       int prevTripletBaseIndexB = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var ownerPKH = hex.decode(currentOwnerAddress.pubkeyHash160);
    var prevPP3IndexA = prevTripletBaseIndexA + 2;
    var prevPP3IndexB = prevTripletBaseIndexB + 2;

    // Build output lockers (single merged triplet)
    var pp1FtLocker = PP1FtLockBuilder(ownerPKH, tokenId, totalAmount);
    var pp2FtLocker = PP2FtLockBuilder(
        getOutpoint(mergedWitnessFundingTxId), ownerPKH, 1, ownerPKH, 1, 2);
    var pp3FtLocker = PartialWitnessFtLockBuilder(ownerPKH, 2);

    // Carry forward metadata from parent A (last output)
    var metadataScript = prevTokenTxA.outputs.last.script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    // Input unlockers
    // Inputs: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessAUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var prevWitnessBUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var pp3BurnUnlockerA = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);
    var pp3BurnUnlockerB = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTxA, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessAUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTxB, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessBUnlocker)
        .spendFromTxnWithSigner(ownerSigner, prevTokenTxA, prevPP3IndexA, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerA)
        .spendFromTxnWithSigner(ownerSigner, prevTokenTxB, prevPP3IndexB, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerB)
        .spendToLockBuilder(pp1FtLocker, BigInt.one)
        .spendToLockBuilder(pp2FtLocker, BigInt.one)
        .spendToLockBuilder(pp3FtLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  // --- Private helpers ---

  /// Builds the PP1_FT unlock builder for the given action.
  UnlockingScriptBuilder _buildPP1FtUnlocker(
      FungibleTokenAction action,
      List<int> preImage,
      Transaction tokenTx,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      List<int> tokenTxLHS,
      List<int>? parentTokenTxBytes,
      List<int> paddingBytes,
      int parentOutputCount,
      int tripletBaseIndex,
      List<int> fundingTxHash,
      {List<int>? parentTokenTxBytesB,
       int parentOutputCountB = 5,
       int parentPP1FtIndexA = 1,
       int parentPP1FtIndexB = 1}
  ) {
    var pp2Index = tripletBaseIndex + 1;
    var tokenChangeAmount = tokenTx.outputs[0].satoshis;

    if (action == FungibleTokenAction.MINT) {
      return PP1FtUnlockBuilder.forMint(preImage, fundingTxHash, paddingBytes);
    } else if (action == FungibleTokenAction.TRANSFER) {
      var pp2Output = tokenTx.outputs[pp2Index].serialize();
      return PP1FtUnlockBuilder.forTransfer(
          preImage, pp2Output, ownerPubkey, tokenChangePKH,
          tokenChangeAmount, tokenTxLHS, parentTokenTxBytes!,
          paddingBytes, parentOutputCount, parentPP1FtIndexA);
    } else if (action == FungibleTokenAction.SPLIT_TRANSFER) {
      var pp2RecipientOutput = tokenTx.outputs[2].serialize();
      var pp2ChangeOutput = tokenTx.outputs[5].serialize();

      // Derive split params from tokenTx outputs
      var recipientPP1_FT = PP1FtLockBuilder.fromScript(tokenTx.outputs[1].script);
      var changePP1_FT = PP1FtLockBuilder.fromScript(tokenTx.outputs[4].script);

      return PP1FtUnlockBuilder.forSplitTransfer(
          preImage, pp2RecipientOutput, pp2ChangeOutput, ownerPubkey,
          tokenChangePKH, tokenChangeAmount, tokenTxLHS,
          parentTokenTxBytes!, paddingBytes,
          recipientPP1_FT.amount, changePP1_FT.amount,
          recipientPP1_FT.recipientPKH, tripletBaseIndex, parentOutputCount,
          parentPP1FtIndexA);
    } else if (action == FungibleTokenAction.MERGE) {
      var pp2Output = tokenTx.outputs[2].serialize();
      return PP1FtUnlockBuilder.forMerge(
          preImage, pp2Output, ownerPubkey, tokenChangePKH,
          tokenChangeAmount, tokenTxLHS,
          parentTokenTxBytes!, parentTokenTxBytesB!,
          paddingBytes, parentOutputCount, parentOutputCountB,
          parentPP1FtIndexA, parentPP1FtIndexB);
    } else {
      throw ArgumentError('Unsupported action for witness: $action');
    }
  }

  /// Builds the witness transaction structure.
  Transaction _buildWitnessTxn(
      TransactionSigner fundingSigner,
      Transaction fundingTx,
      Transaction tokenTx,
      int pp1FtIndex,
      int pp2Index,
      SVPublicKey ownerPubkey,
      UnlockingScriptBuilder pp1FtUnlocker,
      PP2FtUnlockBuilder pp2FtUnlocker,
      ModP2PKHLockBuilder witnessLocker,
  ) {
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    return TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, pp1FtUnlocker)
        .spendFromTxn(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);
  }

}
