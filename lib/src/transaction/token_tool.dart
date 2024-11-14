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

import 'dart:async';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';

import '../builder/partial_witness_lock_builder.dart';
import '../builder/partial_witness_unlock_builder.dart';
import '../builder/pp1_lock_builder.dart';
import '../builder/pp1_unlock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import 'utils.dart';

class TokenTool {

  TokenTool();

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  int readVarIntNum(ByteDataReader reader) {
    var varint = VarInt.fromStream(reader);
    return varint.value;
  }




  Transaction createWitnessTxn(
      TransactionSigner fundingSigner, //assumes the same privatekey spends PP1 & Funding UTXO
      Transaction fundingTx,  //The transaction containing the funding UTXO for the Witness Txn
      Transaction tokenTx, //token to be a witness for
      List<int> parentTokenTxBytes,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      TokenAction action,
      ){

    var ownerAddress = Address.fromPublicKey(ownerPubkey, NetworkType.TEST);
    var pp2Unlocker = PP2UnlockBuilder(tokenTx.hash); //PP2 unlocker only needs token transaction's txid
    var witnessLocker = ModP2PKHLockBuilder.fromAddress(ownerAddress);  //witness is locked to current token holder
    var fundingUnlocker = P2PKHUnlockBuilder(ownerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var preImageTxnForPP1 = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker) //PP1
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker) //PP2
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript1 = tokenTx.outputs[1].script;
    var preImagePP1 = Sighash().createSighashPreImage(preImageTxnForPP1, sigHashAll, 1, subscript1 , BigInt.one);


    print("==============");
    print("PP1 PreImage");
    TransactionUtils.printPreImage(preImagePP1!);


    var tsl1 = TransactionUtils();

    var tokenTxLHS = tsl1.getTxLHS(tokenTx); //everything up to and excluding the first output

    var paddingBytes = Uint8List(1); //1 Byte
    var pp2Output = tokenTx.outputs[2].serialize();

    var tokenChangeAmount = tokenTx.outputs[0].satoshis;
    var pp1UnlockBuilder = PP1UnlockBuilder(preImagePP1!, pp2Output, ownerPubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingTx.hash);
    var witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);

    //updated padding bytes
    paddingBytes = Uint8List.fromList(tsl1.calculatePaddingBytes(witnessTx));
    print("Unpadded Witness Hex: ${witnessTx.serialize()}");
    print( witnessTx.inputs[1].scriptBuilder?.getScriptSig().toString());
    print("Padding bytes: ${hex.encode(paddingBytes)}");
    print("TokenTx LHS : " + hex.encode(tokenTxLHS));
    print("PP2 Output Bytes : ${hex.encode(pp2Output)}");

    pp1UnlockBuilder = PP1UnlockBuilder( preImagePP1, pp2Output, ownerPubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingTx.hash);

    witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);


    ///JUST FOR DEBUG >>>
    var pp2PreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .withFee(BigInt.from(100))
        .build(false);

    var subscript2 = tokenTx.outputs[2].script;
    var preImagePP2 = Sighash().createSighashPreImage(pp2PreImageTxn, sigHashAll, 2, subscript2 , BigInt.one);

    print("=========================");
    print("PreImage PP2 Hex: ${hex.encode(preImagePP2!)}");
    // print("PreImage PP2 Hash: ${hex.encode(Sha256(preImagePP2))}")
    print("Printing PreImage for PP2");
    TransactionUtils.printPreImage(preImagePP2);
    // << DEBUG ////

    return witnessTx;

  }

  /*
   * For the issuance transaction, all PKH are locked to the recipient
   * Additionally the expected Witness PKH output that is asserted within
   * PP2 must also be locked to this recipient, even though the Witness Txn
   * does not yet exist.
   * In essence, both the TokenTx and it's corresponding WitnessTx are locked
   * to one PKH (that of the current token holder).
   *
   * Additionally, we set the tokenId to the TxId of the Fundingin Transaction
   * to the first Witness Transaction. I.e. TokenId = TxId(FirstWitnessFundingTxn)
   */
  Transaction createTokenIssuanceTxn(
      Transaction tokenFundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      Address recipientAddress,      //
      List<int> witnessFundingTxId
      ){

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var tokenTxBuilder = TransactionBuilder();
    var tokenId = tokenFundingTx.hash; //set initial tokenId to fundingTxId

    //fund the txn
    tokenTxBuilder.spendFromTxnWithSigner(fundingTxSigner, tokenFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
    tokenTxBuilder.withFeePerKb(1);

    //create PP1 Outpoint
    var pp1Locker = PP1LockBuilder(recipientAddress, tokenId);
    tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

    var outputWriter = ByteDataWriter();
    outputWriter.write(witnessFundingTxId); //32 byte txid in txFormat
    outputWriter.writeUint32(1, Endian.little);
    var fundingOutpoint = outputWriter.toBytes();
    // print("Witness Funding Outpoint : ${hex.encode(fundingOutpoint)}");

    // var fundingOutpoint = getOutpoint(witnessTxId);

    var pp2Locker = PP2LockBuilder(fundingOutpoint,  hex.decode(recipientAddress.pubkeyHash160), 1);
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    var shaLocker = PartialWitnessLockBuilder();
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);
    tokenTxBuilder.sendChangeToPKH(recipientAddress);

    return tokenTxBuilder.build(false);
  }

  List<int> getOutpoint(List<int> txId){
    var outputWriter = ByteDataWriter();
    outputWriter.write(txId); //32 byte txid
    outputWriter.writeUint32(1, Endian.little);
    return outputWriter.toBytes();
  }

  Transaction createTokenTransferTxn(
      Transaction prevWitnessTx,
      Transaction prevTokenTx,
      SVPublicKey currentOwnerPubkey,
      Address recipientAddress,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      List<int> recipientWitnessFundingTxId, //Witness funding txn funded by the recipient. Is expected to have funding in output[1]
      List<int> tokenId,
      ){

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, NetworkType.TEST);

    //funding is assumed to be by owner
    // var recipientAddress = Address.fromPublicKey(recipientPubKey, NetworkType.TEST);
    var pp1LockBuilder = PP1LockBuilder(recipientAddress, tokenId);

    var pp2Locker = PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), hex.decode(recipientAddress.pubkeyHash160), 1);
    var shaLocker = PartialWitnessLockBuilder();


    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    // var prevWitnessUnlocker = P2PKHUnlockBuilder(currentOwnerPubkey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    // var newWitnessLocker = P2PKHLockBuilder.fromPublicKey(currentOwnerPubKey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker) //one output only in witness
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one) //PP1
        .spendToLockBuilder(pp2Locker, BigInt.one) //PP2
        .spendToLockBuilder(shaLocker, BigInt.one) //PartialShaLocker
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(BigInt.from(135)) //FIXME: This fee !
        .build(false);

    // childPreImageTxn.serialize();

    var pp3Subscript = prevTokenTx.outputs[3].script;
    var sigPreImageChildTx = Sighash().createSighashPreImage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInt.one);

    var tsl1 = TransactionUtils();
    var (partialHash, witnessPartialPreImage)  = tsl1.computePartialHash(hex.decode(prevWitnessTx.serialize()), 2);

    print("Child Token SigPreImage: ${hex.encode(sigPreImageChildTx!)}");
    print("Partial Hash : ${hex.encode(partialHash)}");
    print("Partial PreImage: ${hex.encode(witnessPartialPreImage)}");

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        fundingTx.hash
    );

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker) //fixme. should be child's funding tx
        .spendFromTxnWithSigner(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker) //one output only in witness
        .spendFromTxn(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
        .spendToLockBuilder(pp1LockBuilder, BigInt.one) //PP1
        .spendToLockBuilder(pp2Locker, BigInt.one) //PP2
        .spendToLockBuilder(shaLocker, BigInt.one) //PartialShaLocker
        .sendChangeToPKH(currentOwnerAddress)
        .withFee(BigInt.from(135))
        .build(false);

    return childTxn;
  }


}