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
import 'dart:convert';
import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';
import '../builder/map_lockbuilder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp1_rft_lock_builder.dart';
import '../builder/pp1_rft_unlock_builder.dart';
import '../builder/pp2_ft_lock_builder.dart';
import '../builder/pp2_ft_unlock_builder.dart';
import '../builder/partial_witness_ft_lock_builder.dart';
import '../builder/partial_witness_ft_unlock_builder.dart';
import '../crypto/rabin.dart';
import 'utils.dart';

/// High-level API for creating Restricted Fungible Token (RFT) transactions.
///
/// Supports mint, transfer, witness, redeem, and burn operations.
/// Transfer policy is enforced by the flags parameter in the locking script.
class RestrictedFungibleTokenTool {
  final NetworkType networkType;
  final BigInt defaultFee;

  RestrictedFungibleTokenTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Constructs a 36-byte outpoint from a transaction ID and output index.
  List<int> getOutpoint(List<int> txId, {int outputIndex = 1}) {
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId);
    outputWriter.writeUint32(outputIndex, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates a 5-output RFT mint transaction.
  ///
  /// Outputs: [Change, PP1_RFT, PP2-FT, PP3-FT, Metadata]
  ///
  /// [tokenFundingTx] funds the mint; its txid becomes the tokenId.
  /// [amount] is the initial token supply.
  /// [rabinPubKeyHash] is the 20-byte hash160 of the Rabin public key.
  /// [flags] is the transfer policy flags byte.
  /// [witnessFundingTxId] is the txid of the transaction funding the first witness.
  Future<Transaction> createFungibleMintTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address recipientAddress,
      List<int> witnessFundingTxId,
      List<int> rabinPubKeyHash,
      int flags,
      int amount,
      {List<int>? metadataBytes,
       List<int>? identityTxId,
       SignatureWand? issuerWand}) async {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash;
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);

    // Fund the transaction
    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    // Output 1: PP1_RFT
    var pp1RftLocker = PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, amount);
    tokenTxBuilder.spendToLockBuilder(pp1RftLocker, BigInt.one);

    // Output 2: PP2-FT
    var fundingOutpoint = getOutpoint(witnessFundingTxId);
    var pp2FtLocker = PP2FtLockBuilder(fundingOutpoint, recipientPKH, 1, recipientPKH, 1, 2);
    tokenTxBuilder.spendToLockBuilder(pp2FtLocker, BigInt.one);

    // Output 3: PP3-FT (partial SHA256 witness verifier)
    var pp3FtLocker = PartialWitnessFtLockBuilder(recipientPKH, 2);
    tokenTxBuilder.spendToLockBuilder(pp3FtLocker, BigInt.one);

    // Output 4: Metadata OP_RETURN
    LockingScriptBuilder metadataLocker;
    if (identityTxId != null && issuerWand != null) {
      var identityTxIdHex = hex.encode(identityTxId);
      var signature = await issuerWand.sign(identityTxId);
      SimplePublicKey pubkey = (await issuerWand.extractPublicKeyUsedForSignatures() as SimplePublicKey);
      var b64Sig = base64Encode(signature.bytes);
      var mapData = <String, String>{
        'identityTxId': identityTxIdHex,
        'identitySig': b64Sig,
      };
      metadataLocker = MapLockBuilder.fromMap(mapData);
    } else {
      metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    }
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

    tokenTxBuilder.sendChangeToPKH(recipientAddress);

    return tokenTxBuilder.build(false);
  }

  /// Creates a burn transaction that destroys an RFT token.
  ///
  /// Spends PP1_RFT (output[1]), PP2-FT (output[2]), and PP3-FT (output[3])
  /// from [tokenTx]. Change is sent back to the owner.
  Transaction createBurnTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      {int tripletBaseIndex = 1}) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1BurnUnlocker = PP1RftUnlockBuilder.forBurn(ownerPubkey);
    var pp2BurnUnlocker = PP2FtUnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex, TransactionInput.MAX_SEQ_NUMBER, pp1BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex + 1, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, tripletBaseIndex + 2, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return burnTx;
  }

  /// Creates a redeem transaction for an RFT token.
  ///
  /// Spends PP1_RFT (output[1]), PP2-FT (output[2]), and PP3-FT (output[3])
  /// from [tokenTx]. Change is sent back to the owner.
  Transaction createRedeemTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1RedeemUnlocker = PP1RftUnlockBuilder.forRedeem(ownerPubkey);
    var pp2BurnUnlocker = PP2FtUnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey);

    var redeemTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1RedeemUnlocker)  //PP1_RFT
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker)   //PP2-FT
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)    //PP3-FT
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return redeemTx;
  }

  /// Creates a witness transaction for an RFT token.
  ///
  /// Produces a 1-output transaction: Witness (locked to current token holder).
  /// Spends PP1_RFT and PP2-FT from [tokenTx].
  ///
  /// [action] determines which PP1_RFT function selector is used:
  /// - MINT: validates Rabin identity binding + hashPrevouts
  /// - TRANSFER: validates inductive proof from parent
  ///
  /// For MINT: [rabinKeyPair], [identityTxId], [ed25519PubKey] are required.
  /// For TRANSFER: [parentTokenTxBytes] and [parentOutputCount] are required.
  Transaction createRftWitnessTxn(
      TransactionSigner fundingSigner,
      Transaction fundingTx,
      Transaction tokenTx,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      RestrictedFungibleTokenAction action,
      {List<int>? parentTokenTxBytes,
       int parentOutputCount = 5,
       int tripletBaseIndex = 1,
       int parentPP1FtIndex = 1,
       RabinKeyPair? rabinKeyPair,
       List<int>? identityTxId,
       List<int>? ed25519PubKey,
       List<int>? parentTokenTxBytesB,
       int parentOutputCountB = 5,
       int parentPP1FtIndexB = 1}
  ) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var pp1FtIndex = tripletBaseIndex;
    var pp2Index = tripletBaseIndex + 1;

    var pp2FtUnlocker = PP2FtUnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(ownerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    // First pass: build with empty PP1_RFT unlocker to get preImage
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

    // Build PP1_RFT unlocker and rebuild with padding (two passes)
    var pp1RftUnlocker = _buildPP1RftUnlocker(action, preImage!, tokenTx, ownerPubkey,
        tokenChangePKH, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        parentOutputCount, tripletBaseIndex, fundingTx.hash,
        parentPP1FtIndex: parentPP1FtIndex,
        rabinKeyPair: rabinKeyPair, identityTxId: identityTxId, ed25519PubKey: ed25519PubKey,
        parentTokenTxBytesB: parentTokenTxBytesB, parentOutputCountB: parentOutputCountB,
        parentPP1FtIndexB: parentPP1FtIndexB);

    var witnessTx = _buildWitnessTxn(fundingSigner, fundingTx, tokenTx,
        pp1FtIndex, pp2Index, ownerPubkey, pp1RftUnlocker, pp2FtUnlocker, witnessLocker);

    // Recalculate padding
    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1RftUnlocker = _buildPP1RftUnlocker(action, preImage, tokenTx, ownerPubkey,
        tokenChangePKH, tokenTxLHS, parentTokenTxBytes, paddingBytes,
        parentOutputCount, tripletBaseIndex, fundingTx.hash,
        parentPP1FtIndex: parentPP1FtIndex,
        rabinKeyPair: rabinKeyPair, identityTxId: identityTxId, ed25519PubKey: ed25519PubKey,
        parentTokenTxBytesB: parentTokenTxBytesB, parentOutputCountB: parentOutputCountB,
        parentPP1FtIndexB: parentPP1FtIndexB);

    witnessTx = _buildWitnessTxn(fundingSigner, fundingTx, tokenTx,
        pp1FtIndex, pp2Index, ownerPubkey, pp1RftUnlocker, pp2FtUnlocker, witnessLocker);

    return witnessTx;
  }

  /// Creates an RFT transfer transaction (5 outputs, full balance transfer).
  ///
  /// Spends: FundingUTXO, previous Witness output, and PP3-FT from [prevTokenTx].
  /// Metadata is carried forward from the parent token transaction.
  ///
  /// [amount] is the full token balance being transferred.
  /// [prevTripletBaseIndex] is 1 for standard triplet, 4 for change triplet.
  Transaction createRftTransferTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId,
      List<int> tokenId,
      List<int> rabinPubKeyHash,
      int flags,
      int amount,
      {int prevTripletBaseIndex = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);
    var prevPP3Index = prevTripletBaseIndex + 2;

    // Build output lockers
    var pp1RftLocker = PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, amount);
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
        .spendToLockBuilder(pp1RftLocker, BigInt.one)
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
        .spendToLockBuilder(pp1RftLocker, BigInt.one)
        .spendToLockBuilder(pp2FtLocker, BigInt.one)
        .spendToLockBuilder(pp3FtLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates an 8-output RFT split transfer transaction.
  ///
  /// Outputs: [Change, PP1_RFT-recv, PP2FT-recv, PP3FT-recv, PP1_RFT-change, PP2FT-change, PP3FT-change, Metadata]
  ///
  /// [sendAmount] tokens go to [recipientAddress], remainder stays with sender.
  /// [totalAmount] is the full token balance being split (must equal sendAmount + change).
  Transaction createRftSplitTxn(
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
      List<int> rabinPubKeyHash,
      int flags,
      int totalAmount,
      {int prevTripletBaseIndex = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var recipientPKH = hex.decode(recipientAddress.pubkeyHash160);
    var senderPKH = hex.decode(currentOwnerAddress.pubkeyHash160);
    var changeTokenAmount = totalAmount - sendAmount;
    var prevPP3Index = prevTripletBaseIndex + 2;

    // Recipient triplet (outputs 1,2,3)
    var pp1RftRecipientLocker = PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, sendAmount);
    var pp2FtRecipientLocker = PP2FtLockBuilder(
        getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
    var pp3FtRecipientLocker = PartialWitnessFtLockBuilder(recipientPKH, 2);

    // Change triplet (outputs 4,5,6)
    var pp1RftChangeLocker = PP1RftLockBuilder(senderPKH, tokenId, rabinPubKeyHash, flags, changeTokenAmount);
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
        .spendToLockBuilder(pp1RftRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp2FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp3FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp1RftChangeLocker, BigInt.one)
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
        .spendToLockBuilder(pp1RftRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp2FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp3FtRecipientLocker, BigInt.one)
        .spendToLockBuilder(pp1RftChangeLocker, BigInt.one)
        .spendToLockBuilder(pp2FtChangeLocker, BigInt.one)
        .spendToLockBuilder(pp3FtChangeLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a 5-output RFT merge transaction combining two token triplets.
  ///
  /// Inputs: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
  /// Outputs: [Change, PP1_RFT_merged, PP2-FT, PP3-FT, Metadata]
  ///
  /// Both triplets must be owned by the same key and have the same tokenId.
  Transaction createRftMergeTxn(
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
      List<int> rabinPubKeyHash,
      int flags,
      int totalAmount,
      {int prevTripletBaseIndexA = 1,
       int prevTripletBaseIndexB = 1}
  ) {

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);
    var ownerPKH = hex.decode(currentOwnerAddress.pubkeyHash160);
    var prevPP3IndexA = prevTripletBaseIndexA + 2;
    var prevPP3IndexB = prevTripletBaseIndexB + 2;

    // Build output lockers (single merged triplet)
    var pp1RftLocker = PP1RftLockBuilder(ownerPKH, tokenId, rabinPubKeyHash, flags, totalAmount);
    var pp2FtLocker = PP2FtLockBuilder(
        getOutpoint(mergedWitnessFundingTxId), ownerPKH, 1, ownerPKH, 1, 2);
    var pp3FtLocker = PartialWitnessFtLockBuilder(ownerPKH, 2);

    // Carry forward metadata from parent A (last output)
    var metadataScript = prevTokenTxA.outputs.last.script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    // Input unlockers
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
        .spendToLockBuilder(pp1RftLocker, BigInt.one)
        .spendToLockBuilder(pp2FtLocker, BigInt.one)
        .spendToLockBuilder(pp3FtLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  // --- Private helpers ---

  /// Builds the PP1_RFT unlock builder for the given action.
  UnlockingScriptBuilder _buildPP1RftUnlocker(
      RestrictedFungibleTokenAction action,
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
      {int parentPP1FtIndex = 1,
       RabinKeyPair? rabinKeyPair,
       List<int>? identityTxId,
       List<int>? ed25519PubKey,
       List<int>? parentTokenTxBytesB,
       int parentOutputCountB = 5,
       int parentPP1FtIndexB = 1}
  ) {
    var pp2Index = tripletBaseIndex + 1;
    var tokenChangeAmount = tokenTx.outputs[0].satoshis;

    if (action == RestrictedFungibleTokenAction.MINT) {
      var concat = [...identityTxId!, ...ed25519PubKey!];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, rabinKeyPair!.p, rabinKeyPair.q);

      var rabinN = Rabin.bigIntToScriptNum(rabinKeyPair.n);
      var rabinS = Rabin.bigIntToScriptNum(sig.s);

      return PP1RftUnlockBuilder.forMint(preImage, fundingTxHash, paddingBytes,
          rabinN: rabinN.toList(), rabinS: rabinS.toList(), rabinPadding: sig.padding,
          identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);
    } else if (action == RestrictedFungibleTokenAction.TRANSFER) {
      var pp2Output = tokenTx.outputs[pp2Index].serialize();
      return PP1RftUnlockBuilder.forTransfer(
          preImage, pp2Output, ownerPubkey, tokenChangePKH,
          tokenChangeAmount, tokenTxLHS, parentTokenTxBytes!,
          paddingBytes, parentOutputCount, parentPP1FtIndex);
    } else if (action == RestrictedFungibleTokenAction.SPLIT_TRANSFER) {
      var pp2RecipientOutput = tokenTx.outputs[2].serialize();
      var pp2ChangeOutput = tokenTx.outputs[5].serialize();

      var recipientPP1 = PP1RftLockBuilder.fromScript(tokenTx.outputs[1].script);
      var changePP1 = PP1RftLockBuilder.fromScript(tokenTx.outputs[4].script);

      return PP1RftUnlockBuilder.forSplitTransfer(
          preImage, pp2RecipientOutput, pp2ChangeOutput, ownerPubkey,
          tokenChangePKH, tokenChangeAmount, tokenTxLHS,
          parentTokenTxBytes!, paddingBytes,
          recipientPP1.amount, changePP1.amount,
          recipientPP1.recipientPKH, tripletBaseIndex, parentOutputCount,
          parentPP1FtIndex);
    } else if (action == RestrictedFungibleTokenAction.MERGE) {
      var pp2Output = tokenTx.outputs[pp2Index].serialize();
      return PP1RftUnlockBuilder.forMerge(
          preImage, pp2Output, ownerPubkey, tokenChangePKH,
          tokenChangeAmount, tokenTxLHS, parentTokenTxBytes!,
          parentTokenTxBytesB!, paddingBytes,
          parentOutputCount, parentOutputCountB,
          parentPP1FtIndex, parentPP1FtIndexB);
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
      UnlockingScriptBuilder pp1RftUnlocker,
      PP2FtUnlockBuilder pp2FtUnlocker,
      ModP2PKHLockBuilder witnessLocker,
  ) {
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    return TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, pp1RftUnlocker)
        .spendFromTxn(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);
  }
}
