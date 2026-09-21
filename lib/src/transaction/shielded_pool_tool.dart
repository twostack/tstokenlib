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
import 'package:crypto/crypto.dart' as crypto;
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
import '../shielded_pool/pool_outputs.dart';
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

  /// SIGHASH_SINGLE | SIGHASH_FORKID, which a pool PP3 signs; see
  /// `WitnessCheckScriptGen.poolSighashType`.
  var pp3SighashType = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_SINGLE.value;

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
  /// [verifierBodyHash] is SHA-256 of the verifier script body, without its
  ///   header push. It says which verifier this pool's rounds are checked by.
  /// [genesisHeader] is the pool's starting state. It is carried by every
  ///   PP1_SP of this pool and the create branch refuses any other starting
  ///   header, so the coordinator cannot open with a commitment tree that
  ///   already holds notes nobody deposited for.
  /// [nextSlot] pins the verifier slot round 1 must spend: the outpoint of the
  ///   slot transaction carrying V for [genesisHeader].
  Transaction createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address ownerAddress,
      List<int> verifierBodyHash,
      PoolHeader genesisHeader,
      List<int> nextSlot,
      List<int> witnessFundingTxId,
      {int fundingVout = 1,
       int witnessFundingVout = 1,
       List<int>? metadataBytes}) {

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
        ownerAddress, tokenId, verifierBodyHash, genesisHeader, encodedGenesis);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    var pp2Locker = PP2LockBuilder(
        getOutpoint(witnessFundingTxId, outputIndex: witnessFundingVout),
        hex.decode(ownerAddress.pubkeyHash160), 1,
        hex.decode(ownerAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    // nextSlot makes PP3 refuse to be spent unless the verifier slot it names is
    // also an input of the spending round. PP3 holds the pool balance, which at
    // genesis is the dust the output needs to exist. It has no owner and no
    // burn path: whoever could burn it could take every depositor's money.
    var shaLocker = PartialWitnessLockBuilder.forPool(nextSlot);
    tokenTxBuilder.spendToLockBuilder(shaLocker, genesisHeader.balance);

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
  /// compares the result against its own outpoint's txid. [nextSlot], [yInput]
  /// and [verifierBody] describe the slot transaction round N+2 will have to
  /// spend, which PP1 certifies here; [bundles] are the round's ciphertexts,
  /// published by riding in this witness and bound by `newHeader.outHash`.
  ///
  /// [withdrawals] and [receipts] must be the same lists, in the same order,
  /// that [createRoundTxn] was given. PP1 rebuilds those outputs from these
  /// records and hashes the result against the round's txid, so a witness that
  /// describes a different tail than the round carries is simply invalid.
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
      List<int>? nextSlot,
      List<int>? yInput,
      List<int>? verifierBody,
      List<int>? bundles,
      List<PoolWithdrawal>? withdrawals,
      List<PoolReceipt>? receipts,
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
        newOwnerPKH: newOwnerPKH, newHeader: newHeader, nextSlot: nextSlot,
        yInput: yInput, verifierBody: verifierBody, bundles: bundles,
        withdrawals: PoolWithdrawal.encodeAll(withdrawals ?? const []),
        receipts: PoolReceipt.encodeAll(receipts ?? const []));

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
  /// [prevSlotTx] is Y_N, whose output 0 carries the verifier for the parent
  /// header. PP3_N pins it, so it has to be input 2. PP3_N itself is input 3,
  /// not TSL1's usual input 2; see `PP1SpScriptGen.poolPP3Input`.
  /// [newOwnerPKH] defaults to the current owner; supply it to rotate the
  /// coordinator's key.
  /// [nextSlot] pins the verifier slot that round N+2 must spend.
  ///
  /// [nextSlotTx] is Y_{N+1}, the slot transaction [nextSlot] names. It is
  /// checked here against everything PP1 will check in this round's witness,
  /// because that check happens too late to help: PP1 runs after the round is
  /// mined, so a round that pins a slot PP1 will refuse can never produce a
  /// witness, and a PP3 whose witness cannot exist can never be spent. The
  /// pool's balance is frozen permanently. Pass [uncheckedNextSlot] to build
  /// such a round deliberately, which is what the negative tests do.
  ///
  /// This does not, and cannot, check that Y is or ever will be on chain. That
  /// is the other way to freeze a pool: pin a slot whose content is right but
  /// whose funding outpoint has been spent elsewhere, so the transaction can
  /// never be mined and round N+2 has nothing to spend at input 2. Broadcast Y
  /// before the round, not after.
  ///
  /// [receipts] and [withdrawals] are the round's variable output tail, written
  /// after the five TSL1 outputs with the receipts first. That order is not
  /// cosmetic: a deposit covenant proves its receipt with SIGHASH_SINGLE, which
  /// ties output index to input index, and a depositor cannot know in advance
  /// how many withdrawals the round will carry. The same lists have to be
  /// handed to [createWitnessTxn].
  Transaction createRoundTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      Transaction prevSlotTx,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> witnessFundingTxId,
      PoolHeader newHeader,
      List<int> nextSlot,
      {int fundingVout = 1,
       int witnessFundingVout = 1,
       List<int>? newOwnerPKH,
       List<PoolWithdrawal>? withdrawals,
       List<PoolReceipt>? receipts,
       Transaction? nextSlotTx,
       bool uncheckedNextSlot = false,
       UnlockingScriptBuilder? slotUnlocker}) {

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var prevPP1 = PP1SpLockBuilder.fromScript(prevTokenTx.outputs[1].script);

    // PP3_N pins the slot this round must spend at input 2. Without a slot in
    // the parent there is nothing to spend and the round can never be mined, so
    // say that here rather than leaving it to the interpreter.
    var parentPP3 = prevTokenTx.outputs[3].script.buffer;
    if (parentPP3.length < PP1SpScriptGen.pp3NextSlotEnd ||
        parentPP3[PP1SpScriptGen.pp3NextSlotStart - 1] != 0x24) {
      throw ArgumentError(
          'The parent PP3 carries no verifier slot, so this round has nothing '
          'to spend at input 2. The pool was issued without a nextSlot.');
    }
    var parentSlot =
        parentPP3.sublist(PP1SpScriptGen.pp3NextSlotStart, PP1SpScriptGen.pp3NextSlotEnd);
    if (!_sameRange(parentSlot, getOutpoint(prevSlotTx.hash, outputIndex: 0), 0, 36)) {
      throw ArgumentError(
          'prevSlotTx is not the slot PP3 named. PP3 pins output 0 of '
          '${hex.encode(parentSlot.sublist(0, 32).reversed.toList())}.');
    }

    if (nextSlotTx != null) {
      checkSlotIsCertifiable(
          slotTx: nextSlotTx,
          outpoint: nextSlot,
          header: newHeader,
          verifierBodyHash: prevPP1.verifierBodyHash!);
    } else if (!uncheckedNextSlot) {
      throw ArgumentError(
          'Pass nextSlotTx so the slot can be checked before the round is '
          'mined. A round pinning a slot PP1 will not certify can never '
          'produce a witness, and its PP3 can then never be spent: the pool '
          'balance is frozen permanently. Pass uncheckedNextSlot: true to '
          'build such a round on purpose.');
    }

    var nextOwnerPKH = newOwnerPKH ?? hex.decode(prevPP1.ownerAddress!.pubkeyHash160);
    var nextOwnerAddress =
        Address.fromPubkeyHash(hex.encode(nextOwnerPKH), networkType);

    // The genesis header and the verifier body hash are immutable, so they come
    // straight off the parent.
    var pp1Locker = PP1SpLockBuilder(nextOwnerAddress, prevPP1.tokenId!,
        prevPP1.verifierBodyHash!, newHeader, prevPP1.genesisHeader!);

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
    // PP3 holds the pool balance and names the slot round N+2 must spend. PP1
    // checks both against the header when this round's witness is built.
    var shaLocker = PartialWitnessLockBuilder.forPool(nextSlot);

    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    if ((receipts?.length ?? 0) > PoolReceipt.maxPerRound) {
      throw ArgumentError('A round takes at most ${PoolReceipt.maxPerRound} '
          'deposits; PP1 has no unrolled step for the rest.');
    }
    if ((withdrawals?.length ?? 0) > PoolWithdrawal.maxPerRound) {
      throw ArgumentError('A round pays at most ${PoolWithdrawal.maxPerRound} '
          'withdrawals; PP1 has no unrolled step for the rest.');
    }
    // Receipts before withdrawals, because a deposit covenant's SIGHASH_SINGLE
    // check ties its receipt's output index to its own input index.
    var tailLockers = <(LockingScriptBuilder, BigInt)>[
      for (var r in receipts ?? const <PoolReceipt>[])
        (DefaultLockBuilder.fromScript(r.lockingScript), BigInt.zero),
      for (var w in withdrawals ?? const <PoolWithdrawal>[])
        (DefaultLockBuilder.fromScript(w.lockingScript), w.satoshis),
    ];

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var slotUnlock = slotUnlocker ??
        DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());

    var childPreImageBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevSlotTx, 0, TransactionInput.MAX_SEQ_NUMBER, slotUnlock)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, newHeader.balance)
        .spendToLockBuilder(metadataLocker, BigInt.zero);
    for (var (locker, value) in tailLockers) {
      childPreImageBuilder.spendToLockBuilder(locker, value);
    }
    var childPreImageTxn = childPreImageBuilder
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    // The preimage has to carry the value of the output being spent, and PP3
    // holds the pool balance, not a dust satoshi. Hardcoding 1 here worked only
    // while the parent was the genesis round, whose balance is 1; from round 2
    // onwards it produced a preimage the interpreter would not agree with, and
    // PP3 refused to be spent.
    //
    // A pool PP3 signs SIGHASH_SINGLE, over its whole script: SINGLE so that
    // hashOutputs is output 3 alone, which is the successor its forward
    // covenant constrains, and the whole script because it has no
    // OP_CODESEPARATOR and reads its own program out of the preimage.
    var pp3Subscript = prevTokenTx.outputs[3].script;
    var pp3Value = prevTokenTx.outputs[3].satoshis;
    var sigPreImageChildTx = Sighash().createSighashPreImage(
        childPreImageTxn, pp3SighashType, PP1SpScriptGen.poolPP3Input,
        pp3Subscript, pp3Value);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage) = tsl1.computePartialHash(
        hex.decode(prevWitnessTx.serialize()), 2);

    var roundFundingOutpoint = Uint8List(36);
    roundFundingOutpoint.setAll(0, fundingTx.hash);
    roundFundingOutpoint.buffer.asByteData().setUint32(32, fundingVout, Endian.little);

    // The successor PP3 is output 3 of this round: the slot it pins and the
    // balance it holds. PP3's covenant rebuilds it from these and its own code.
    var nextValue = Uint8List(8);
    nextValue.buffer.asByteData().setUint64(0, newHeader.balance.toInt(), Endian.little);
    var sha256Unlocker = PartialWitnessUnlockBuilder.forPool(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        roundFundingOutpoint,
        nextSlot: nextSlot,
        nextValue: nextValue);

    var childBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevSlotTx, 0, TransactionInput.MAX_SEQ_NUMBER, slotUnlock)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1Locker, BigInt.one)
        .spendToLockBuilder(pp2Locker, BigInt.one)
        .spendToLockBuilder(shaLocker, newHeader.balance)
        .spendToLockBuilder(metadataLocker, BigInt.zero);
    for (var (locker, value) in tailLockers) {
      childBuilder.spendToLockBuilder(locker, value);
    }
    var childTxn = childBuilder
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Runs, in Dart, the checks `PP1SpScriptGen.emitVerifySlotIsVerifier` will
  /// run in script, and throws with the reason if any of them would fail.
  ///
  /// Kept as a separate entry point because the interesting caller is not only
  /// [createRoundTxn]. A coordinator that assembles rounds by hand, or a
  /// monitor watching someone else's pool, wants to ask this question of a
  /// slot without building anything.
  ///
  /// The four checks are PP1's, in PP1's order: the outpoint names output 0 of
  /// [slotTx]; Y has exactly one input and one output, which is what forces V
  /// to be output 0; V is `OP_PUSHDATA1 0xec ‖ header ‖ body`; and the body
  /// hashes to the pool's immutable [verifierBodyHash]. PP1 rebuilds Y from
  /// its parts and compares HASH256 against the pin, so a slot that fails any
  /// of these has no passing preimage short of breaking SHA-256.
  static void checkSlotIsCertifiable({
    required Transaction slotTx,
    required List<int> outpoint,
    required PoolHeader header,
    required List<int> verifierBodyHash,
  }) {
    if (outpoint.length != 36) {
      throw ArgumentError('A slot outpoint is 36 bytes, not ${outpoint.length}');
    }
    var vout = Uint8List.fromList(outpoint.sublist(32)).buffer
        .asByteData()
        .getUint32(0, Endian.little);
    if (vout != 0) {
      throw ArgumentError('The slot must name output 0 of Y, not output $vout. '
          'PP1 rebuilds a one-output Y, so no other index can ever certify.');
    }
    if (!_sameRange(outpoint, slotTx.hash, 0, 32)) {
      throw ArgumentError('nextSlot names '
          '${hex.encode(outpoint.sublist(0, 32).reversed.toList())}, which is '
          'not the slot transaction supplied.');
    }
    if (slotTx.inputs.length != 1 || slotTx.outputs.length != 1) {
      throw ArgumentError('Y must have exactly one input and one output, not '
          '${slotTx.inputs.length} and ${slotTx.outputs.length}. That shape is '
          'what forces V to be output 0: a Y with more outputs could park the '
          'real verifier somewhere inert and put an OP_TRUE where the round '
          'looks.');
    }

    var v = slotTx.outputs[0].script.buffer;
    var bodyStart = 2 + PoolHeader.byteSize;
    if (v.length <= bodyStart || v[0] != 0x4c || v[1] != PoolHeader.byteSize) {
      throw ArgumentError('Y output 0 does not open with a '
          '${PoolHeader.byteSize}-byte header push, so it is not a verifier '
          'slot for this pool.');
    }
    var encoded = header.encode();
    if (!_sameRange(v.sublist(2, bodyStart), encoded, 0, PoolHeader.byteSize)) {
      throw ArgumentError('The verifier in Y carries a different header than '
          'the round does. A slot built for another state is a genuine, '
          'spendable verifier that was never told what to check, which is the '
          'case a body hash alone would let through.');
    }
    var bodyHash = crypto.sha256.convert(v.sublist(bodyStart)).bytes;
    if (!_sameRange(bodyHash, verifierBodyHash, 0, 32)) {
      throw ArgumentError('The verifier body in Y is not this pool\'s. Its '
          'hash is ${hex.encode(bodyHash)}, and PP1 carries '
          '${hex.encode(verifierBodyHash)}.');
    }
  }

  /// Builds the slot transaction Y whose single output carries the verifier V
  /// for [header], and returns it with the outpoint that names it and the bytes
  /// of its input that PP1 needs to rebuild it.
  ///
  /// Exactly one input and one output is a requirement, not a convention. It is
  /// what forces V to be output 0: a Y with more outputs could park the real
  /// verifier somewhere inert and put an OP_TRUE where the next round looks.
  /// The coordinator builds Y, so meeting the shape costs nothing.
  ///
  /// V is `OP_PUSHDATA1 0xec ‖ header ‖ verifierBody`, which is what lets PP1
  /// check the slot runs this pool's verifier *and* that the verifier was
  /// initialised with this header.
  ({Transaction tx, List<int> outpoint, List<int> input}) buildSlotTxn({
    required PoolHeader header,
    required List<int> verifierBody,
    required TransactionInput fundingInput,
  }) {
    var v = Uint8List.fromList(
        [0x4c, PoolHeader.byteSize, ...header.encode(), ...verifierBody]);

    var y = Transaction()
      ..version = 1
      ..nLockTime = 0
      ..addInput(fundingInput)
      ..addOutput(TransactionOutput(BigInt.one, SVScript.fromByteArray(v)));

    return (
      tx: y,
      outpoint: getOutpoint(y.hash, outputIndex: 0),
      input: y.inputs[0].serialize(),
    );
  }

  static bool _sameRange(List<int> a, List<int> b, int start, int end) {
    for (var i = start; i < end; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
