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
import '../builder/partial_witness_lock_builder.dart';
import '../builder/partial_witness_unlock_builder.dart';
import '../builder/pp1_nft_lock_builder.dart';
import '../builder/pp1_nft_unlock_builder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import 'utils.dart';

/// High-level API for creating TSToken transactions (issuance, transfer, witness, burn).
///
/// Encapsulates the construction of multi-output token transactions that conform
/// to the TSToken protocol's proof-carrying transaction structure.
class TokenTool {

  /// The BSV network type (mainnet or testnet) used for address derivation.
  final NetworkType networkType;

  /// Default transaction fee in satoshis, applied to transfer and burn transactions.
  final BigInt defaultFee;

  /// Creates a [TokenTool] instance.
  ///
  /// [networkType] defaults to [NetworkType.TEST].
  /// [defaultFee] defaults to 135 satoshis if not specified.
  TokenTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Creates a witness transaction that proves ownership of a token.
  ///
  /// Produces a 1-output transaction: Witness (locked to current token holder).
  /// Spends: FundingUTXO (output[1]), PP1, PP2 from [tokenTx].
  ///
  /// [fundingSigner] signs both the funding input and PP1 (assumes same private key).
  /// [fundingTx] provides the funding UTXO at output[1].
  /// [tokenTx] is the token transaction to witness.
  /// [parentTokenTxBytes] is the raw serialized bytes of the parent token transaction.
  /// [tokenChangePKH] is the pubkey hash for the token's change output.
  /// [action] specifies the token action (e.g., issue or transfer).
  Transaction createWitnessTxn(
      TransactionSigner fundingSigner,
      Transaction fundingTx,
      Transaction tokenTx,
      List<int> parentTokenTxBytes,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      TokenAction action,
      {int fundingVout = 1,
       List<int>? rabinN,
       List<int>? rabinS,
       int? rabinPadding,
       List<int>? identityTxId,
       List<int>? ed25519PubKey}
      ){

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash); //PP2 unlocker only needs token transaction's txid
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(ownerAddress);  //witness is locked to current token holder
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var preImageTxnForPP1 = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker) //PP1
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker) //PP2
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript1 = tokenTx.outputs[1].script;
    var preImagePP1 = Sighash().createSighashPreImage(preImageTxnForPP1, sigHashAll, 1, subscript1 , BigInt.one);


    var tsl1 = TransactionUtils();

    var tokenTxLHS = tsl1.getTxLHS(tokenTx); //everything up to and excluding the first output

    var paddingBytes = Uint8List(1); //1 Byte
    var pp2Output = tokenTx.outputs[2].serialize();

    var tokenChangeAmount = tokenTx.outputs[0].satoshis;
    var fundingOutpoint = Uint8List(36);
    fundingOutpoint.setAll(0, fundingTx.hash);
    fundingOutpoint.buffer.asByteData().setUint32(32, fundingVout, Endian.little);

    var pp1UnlockBuilder = PP1NftUnlockBuilder(preImagePP1!, pp2Output, ownerPubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingOutpoint,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: rabinPadding, identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);
    var witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    //updated padding bytes
    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));

    pp1UnlockBuilder = PP1NftUnlockBuilder( preImagePP1, pp2Output, ownerPubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingOutpoint,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: rabinPadding, identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);

    witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);


    return witnessTx;

  }

  /// Creates a token issuance transaction with a 5-output structure:
  /// Change, PP1, PP2, PartialWitness, Metadata.
  ///
  /// All proof outputs and the expected witness output are locked to [recipientAddress].
  /// The tokenId is set to the txid of [tokenFundingTx].
  ///
  /// [tokenFundingTx] funds the issuance; its txid becomes the initial tokenId.
  /// [witnessFundingTxId] is the txid of the transaction that will fund the first witness.
  /// [metadataBytes] optional raw metadata to embed in the OP_RETURN output.
  /// [identityTxId] optional identity anchor txid for issuer identity linking.
  /// [issuerWand] optional ED25519 signing wand; required when [identityTxId] is provided.
  Future<Transaction> createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address recipientAddress,      //
      List<int> witnessFundingTxId,
      List<int> rabinPubKeyHash,
      {int fundingVout = 1,
       List<int>? metadataBytes,
       List<int>? identityTxId,
       SignatureWand? issuerWand}
      ) async {

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash; //set initial tokenId to fundingTxId

    //fund the txn
    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    //create PP1 Outpoint
    var pp1Locker = PP1NftLockBuilder(recipientAddress, tokenId, rabinPubKeyHash);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    var outputWriter = ByteDataWriter();
    outputWriter.write(witnessFundingTxId); //32 byte txid in txFormat
    outputWriter.writeUint32(1, Endian.little);
    var fundingOutpoint = outputWriter.toBytes();

    var pp2Locker = PP2LockBuilder(fundingOutpoint,  hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

    //metadata OP_RETURN output (output[4]) - required by PP1 transferToken validation
    LockingScriptBuilder metadataLocker;
    if (identityTxId != null && issuerWand != null) {
      // Sign the identity txid with the issuer's ED25519 key
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

  /// Constructs a 36-byte outpoint (txid + output index) from a transaction ID.
  List<int> getOutpoint(List<int> txId, {int outputIndex = 1}){
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId); //32 byte txid
    outputWriter.writeUint32(outputIndex, Endian.little);
    return outputWriter.toBytes();
  }

  /// Creates a token transfer transaction with a 5-output structure:
  /// Change, PP1, PP2, PartialWitness, Metadata.
  ///
  /// Spends: FundingUTXO, previous Witness output, and PartialWitness (output[3])
  /// from [prevTokenTx]. Metadata is carried forward from the parent token transaction.
  ///
  /// [prevWitnessTx] is the previous witness transaction whose output is spent.
  /// [prevTokenTx] is the parent token transaction being transferred from.
  /// [currentOwnerPubkey] is the public key of the current token holder.
  /// [recipientAddress] is the address of the new token recipient.
  /// [recipientWitnessFundingTxId] txid of the recipient's witness funding transaction
  ///   (expected to have funding in output[1]).
  /// [tokenId] is the persistent token identifier carried across transfers.
  Transaction createTokenTransferTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId,
      List<int> tokenId,
      {int fundingVout = 1}
      ){

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);

    // Carry forward rabinPubKeyHash from previous PP1
    var prevPP1 = PP1NftLockBuilder.fromScript(prevTokenTx.outputs[1].script);
    var pp1LockBuilder = PP1NftLockBuilder(recipientAddress, tokenId, prevPP1.rabinPubKeyHash!);

    var pp2Locker = PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));

    //carry forward metadata from parent token tx (output[4])
    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker) //one output only in witness
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one) //PP1
        .spendToLockBuilder(pp2Locker, BigInt.one) //PP2
        .spendToLockBuilder(shaLocker, BigInt.one) //PartialShaLocker
        .spendToLockBuilder(metadataLocker, BigInt.zero) //metadata OP_RETURN
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage)  = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    var transferFundingOutpoint = Uint8List(36);
    transferFundingOutpoint.setAll(0, fundingTx.hash);
    transferFundingOutpoint.buffer.asByteData().setUint32(32, fundingVout, Endian.little);

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        transferFundingOutpoint
    );

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one) //PP1
        .spendToLockBuilder(pp2Locker, BigInt.one) //PP2
        .spendToLockBuilder(shaLocker, BigInt.one) //PartialShaLocker
        .spendToLockBuilder(metadataLocker, BigInt.zero) //metadata OP_RETURN
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(defaultFee)
        .build(false);

    return childTxn;
  }

  /// Creates a burn transaction that destroys a token by spending all its proof outputs.
  ///
  /// Spends PP1 (output[1]), PP2 (output[2]), and PartialWitness (output[3])
  /// from [tokenTx] using burn-mode unlockers. Change is sent back to the owner.
  ///
  /// [tokenTx] is the token transaction to burn.
  /// [ownerSigner] signs the token proof inputs (PP1, PP2, PartialWitness).
  /// [ownerPubkey] is the public key of the current token holder.
  Transaction createBurnTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      {int fundingVout = 1}
      ){

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1BurnUnlocker = PP1NftUnlockBuilder.forBurn(ownerPubkey);
    var pp2BurnUnlocker = PP2UnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, fundingVout, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1BurnUnlocker) //PP1
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2BurnUnlocker) //PP2
        .spendFromTxnWithSigner(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, pwBurnUnlocker)  //PartialWitness
        .sendChangeToPKH(ownerAddress)
        .withFee(defaultFee)
        .build(false);

    return burnTx;
  }

  /// Returns the subscript after the Nth OP_CODESEPARATOR opcode (0-indexed).
  /// Walks raw script bytes following Bitcoin script encoding to skip pushdata.
  SVScript _subscriptAfterCodeSep(SVScript script, int occurrenceIndex) {
    var bytes = script.buffer;
    int i = 0;
    int count = 0;
    while (i < bytes.length) {
      int opcode = bytes[i];
      if (opcode == 0xab) {
        if (count == occurrenceIndex) {
          return SVScript.fromBuffer(Uint8List.fromList(bytes.sublist(i + 1)));
        }
        count++;
        i++;
      } else if (opcode > 0 && opcode <= 75) {
        i += 1 + opcode; // direct push: 1 byte opcode + N bytes data
      } else if (opcode == 76) { // OP_PUSHDATA1
        if (i + 1 < bytes.length) i += 2 + bytes[i + 1];
        else i++;
      } else if (opcode == 77) { // OP_PUSHDATA2
        if (i + 2 < bytes.length) i += 3 + (bytes[i + 1] | (bytes[i + 2] << 8));
        else i++;
      } else if (opcode == 78) { // OP_PUSHDATA4
        if (i + 4 < bytes.length) i += 5 + (bytes[i + 1] | (bytes[i + 2] << 8) | (bytes[i + 3] << 16) | (bytes[i + 4] << 24));
        else i++;
      } else {
        i++; // regular opcode (1 byte)
      }
    }
    return script;
  }

}