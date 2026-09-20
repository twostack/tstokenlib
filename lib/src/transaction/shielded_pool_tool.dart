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
import '../builder/partial_witness_lock_builder.dart';
import '../builder/partial_witness_unlock_builder.dart';
import '../builder/pp1_sp_lock_builder.dart';
import '../builder/pp1_sp_unlock_builder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import '../script_gen/pp1_sp_script_gen.dart';
import '../shielded_pool/pool_header.dart';
import 'utils.dart';

/// High-level API for building shielded pool (PP1_SP) transactions.
///
/// Two operations: `create`, the TSL1 issuance that is the pool's genesis, and
/// `round`, the inductive transfer that advances the pool header. Each is a
/// pair of transactions, the token transaction and its witness, exactly as in
/// every other TSL1 archetype.
///
/// There is no burn and no state machine lifecycle. See [PP1SpScriptGen].
class ShieldedPoolTool {
  final NetworkType networkType;
  final BigInt defaultFee;

  ShieldedPoolTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Constructs a 36-byte outpoint (txid + output index).
  List<int> getOutpoint(List<int> txId, {int outputIndex = 1}) {
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId);
    outputWriter.writeUint32(outputIndex, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates the pool's genesis token transaction, with the standard TSL1
  /// 5-output structure: change, PP1_SP, PP2, PartialWitness, metadata.
  ///
  /// [tokenFundingTx] funds the issuance and its txid becomes the tokenId.
  /// [ownerAddress] is the coordinator.
  /// [genesisHeader] is the pool's starting state. It is baked into every PP1_SP
  ///   of this pool as a hash, and the create branch refuses any other starting
  ///   header, so the coordinator cannot open with a commitment tree that
  ///   already holds notes nobody deposited for.
  /// [nextSlot] pins the verifier slot the first round must spend; null for a
  ///   pool being exercised without the verifier wired in.
  Transaction createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address ownerAddress,
      PoolHeader genesisHeader,
      List<int> witnessFundingTxId,
      {int fundingVout = 1,
       int witnessFundingVout = 1,
       List<int>? metadataBytes,
       List<int>? nextSlot}) {

    // PP1_SP's create branch requires input 0 to spend (tokenId, 1), which is
    // what makes tokenId unique. Funding from any other index would build an
    // issuance whose witness can never be created.
    if (fundingVout != 1) {
      throw ArgumentError.value(fundingVout, 'fundingVout',
          'PP1_SP issuance must be funded from output 1 of the funding transaction');
    }

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash;
    var encodedGenesis = genesisHeader.encode();

    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, fundingVout,
        TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(100);

    var pp1Locker = PP1SpLockBuilder(
        ownerAddress, tokenId, genesisHeader, encodedGenesis);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId, outputIndex: witnessFundingVout),
        hex.decode(ownerAddress.pubkeyHash160), 1,
        hex.decode(ownerAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    // nextSlot makes PP3 refuse to be spent unless the verifier slot it names is
    // also an input of the spending round. Null for plain TSL1 tokens.
    var shaLocker = PartialWitnessLockBuilder(hex.decode(ownerAddress.pubkeyHash160),
        nextSlot: nextSlot);
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

    var metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

    tokenTxBuilder.sendChangeToPKH(ownerAddress);
    return tokenTxBuilder.build(false);
  }

  /// Creates the witness transaction that carries a token transaction's
  /// inductive proof.
  ///
  /// [action] selects which PP1_SP branch runs. For [ShieldedPoolAction.ROUND],
  /// [newOwnerPKH] and [newHeader] must describe the PP1_SP output the token
  /// transaction actually built, because PP1 rebuilds that output from them and
  /// compares the result against its own outpoint's txid.
  Transaction createWitnessTxn(
      TransactionSigner signer,
      Transaction fundingTx,
      Transaction tokenTx,
      List<int> parentTokenTxBytes,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      ShieldedPoolAction action,
      {int fundingVout = 1,
      List<int>? newOwnerPKH,
      List<int>? newHeader,
      int? nLockTime,
      int pp1OutputIndex = 1,
      int pp2OutputIndex = 2}) {

    var signerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash);
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(signerAddress);
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var seqNum = nLockTime != null
        ? TransactionInput.MAX_SEQ_NUMBER - 1
        : TransactionInput.MAX_SEQ_NUMBER;

    var preImageBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, fundingVout, seqNum, fundingUnlocker)
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

    // CREATE anchors the base case, so PP1 needs THIS token transaction's own
    // bytes to check that its input 0 spends (tokenId, 1). A round is an
    // inductive step and needs the parent's bytes instead.
    var pp1ParentBytes = action == ShieldedPoolAction.CREATE
        ? hex.decode(tokenTx.serialize())
        : parentTokenTxBytes;

    var fundingOutpoint = Uint8List(36);
    fundingOutpoint.setAll(0, fundingTx.hash);
    fundingOutpoint.buffer.asByteData().setUint32(32, fundingVout, Endian.little);

    PP1SpUnlockBuilder unlockerFor(Uint8List padding) => PP1SpUnlockBuilder(
        preImagePP1!, pp2Output, ownerPubkey, tokenChangePKH,
        tokenChangeAmount, tokenTxLHS, pp1ParentBytes, padding,
        action, fundingOutpoint,
        newOwnerPKH: newOwnerPKH, newHeader: newHeader);

    // Two passes: the padding that makes PP3's partial hash land on a 64-byte
    // boundary depends on the witness's own size, so the witness is built once
    // to measure it and once for real.
    var witnessBuilder1 = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, fundingVout, seqNum, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, pp1OutputIndex, seqNum, unlockerFor(paddingBytes))
        .spendFromTxn(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one);
    if (nLockTime != null) witnessBuilder1.lockUntilBlockHeight(nLockTime);
    var witnessTx = witnessBuilder1.build(false);

    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    var witnessBuilder2 = TransactionBuilder()
        .spendFromTxnWithSigner(signer, fundingTx, fundingVout, seqNum, fundingUnlocker)
        .spendFromTxnWithSigner(signer, tokenTx, pp1OutputIndex, seqNum, unlockerFor(paddingBytes))
        .spendFromTxn(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one);
    if (nLockTime != null) witnessBuilder2.lockUntilBlockHeight(nLockTime);
    witnessTx = witnessBuilder2.build(false);

    return witnessTx;
  }

  /// Creates round N+1's token transaction: the 5-output structure carrying the
  /// new pool header.
  ///
  /// It spends the previous witness's ModP2PKH output and the previous token
  /// transaction's PP3, which is the spend that carries the induction forward.
  ///
  /// [newOwnerPKH] defaults to the current owner; supply it to rotate the
  /// coordinator's key.
  /// [nextSlot] pins the verifier slot that round N+2 must spend.
  Transaction createRoundTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      PoolHeader newHeader,
      {int fundingVout = 1,
       int witnessFundingVout = 1,
       List<int>? newOwnerPKH,
       List<int>? nextSlot}) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var prevPP1 = PP1SpLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    var nextOwnerPKH = newOwnerPKH ?? hex.decode(prevPP1.ownerAddress!.pubkeyHash160);
    var nextOwnerAddress =
        Address.fromPubkeyHash(hex.encode(nextOwnerPKH), networkType);

    // The genesis header is immutable, so it comes straight off the parent.
    var pp1Locker = PP1SpLockBuilder(
        nextOwnerAddress, prevPP1.tokenId!, newHeader, prevPP1.genesisHeader!);

    // PP1 rebuilds the next script as parent[0:1] + newPKH + parent[21:294] +
    // newHeader + parent[530:], so anything the generator would change outside
    // those two windows makes the round unspendable. Catch it here, where the
    // error says what happened, rather than in the interpreter.
    var rebuilt = pp1Locker.getScriptPubkey().buffer;
    var parent = prevTokenTx.outputs[1].script.buffer;
    if (rebuilt.length != parent.length ||
        !_sameRange(rebuilt, parent, PP1SpScriptGen.scriptBodyStart, parent.length) ||
        !_sameRange(rebuilt, parent, PP1SpScriptGen.immutableMidStart,
            PP1SpScriptGen.headerDataStart)) {
      throw ArgumentError(
          'The regenerated PP1_SP script differs from the parent outside the '
          'two mutable windows, so PP1 cannot rebuild it.');
    }

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId, outputIndex: witnessFundingVout),
        nextOwnerPKH, 1, nextOwnerPKH);
    var shaLocker = PartialWitnessLockBuilder(nextOwnerPKH, nextSlot: nextSlot);

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var roundFundingOutpoint = Uint8List(36);
    roundFundingOutpoint.setAll(0, fundingTx.hash);
    roundFundingOutpoint.buffer.asByteData().setUint32(32, fundingVout, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        roundFundingOutpoint);

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, BigInt.one)
        .spendToLockBuilder(metadataLocker, BigInt.zero)
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  static bool _sameRange(List<int> a, List<int> b, int start, int end) {
    for (var i = start; i < end; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
