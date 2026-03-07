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
import '../builder/pp1_lock_builder.dart';
import '../builder/pp1_unlock_builder.dart';
import '../builder/metadata_lock_builder.dart';
import '../builder/pp2_lock_builder.dart';
import '../builder/pp2_unlock_builder.dart';
import 'utils.dart';

class TokenTool {

  final NetworkType networkType;
  final BigInt defaultFee;

  TokenTool({this.networkType = NetworkType.TEST, BigInt? defaultFee})
      : defaultFee = defaultFee ?? BigInt.from(135);

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  Transaction createWitnessTxn(
      TransactionSigner fundingSigner, //assumes the same privatekey spends PP1 & Funding UTXO
      Transaction fundingTx,  //The transaction containing the funding UTXO for the Witness Txn
      Transaction tokenTx, //token to be a witness for
      List<int> parentTokenTxBytes,
      SVPublicKey ownerPubkey,
      String tokenChangePKH,
      TokenAction action,
      ){

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
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

    pp1UnlockBuilder = PP1UnlockBuilder( preImagePP1, pp2Output, ownerPubkey, tokenChangePKH, tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes, action, fundingTx.hash);

    witnessTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
        .spendFromTxnWithSigner(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1UnlockBuilder)
        .spendFromTxn(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
        .spendToLockBuilder(witnessLocker, BigInt.one)
        .build(false);


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
      List<int> witnessFundingTxId,
      {List<int>? metadataBytes}
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

    var pp2Locker = PP2LockBuilder(fundingOutpoint,  hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));
    tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

    //metadata OP_RETURN output (output[4]) - required by PP1 transferToken validation
    var metadataLocker = MetadataLockBuilder(metadataBytes: metadataBytes);
    tokenTxBuilder.spendToLockBuilder(metadataLocker, BigInt.zero);

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

    var currentOwnerAddress = Address.fromPublicKey(currentOwnerPubkey, networkType);

    var pp1LockBuilder = PP1LockBuilder(recipientAddress, tokenId);

    var pp2Locker = PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), hex.decode(recipientAddress.pubkeyHash160), 1, hex.decode(recipientAddress.pubkeyHash160));
    var shaLocker = PartialWitnessLockBuilder(hex.decode(recipientAddress.pubkeyHash160));

    //carry forward metadata from parent token tx (output[4])
    var metadataScript = prevTokenTx.outputs[4].script;
    var metadataLocker = DefaultLockBuilder.fromScript(metadataScript);

    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var prevWitnessUnlocker = ModP2PKHUnlockBuilder(currentOwnerPubkey);
    var emptyUnlocker = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
    var childPreImageTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
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

    var sha256Unlocker = PartialWitnessUnlockBuilder(
        sigPreImageChildTx!,
        partialHash,
        witnessPartialPreImage,
        fundingTx.hash
    );

    var childTxn = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
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

  Transaction createBurnTokenTxn(
      Transaction tokenTx,
      TransactionSigner ownerSigner,
      SVPublicKey ownerPubkey,
      Transaction fundingTx,
      TransactionSigner fundingTxSigner,
      SVPublicKey fundingPubKey,
      ){

    var ownerAddress = Address.fromPublicKey(ownerPubkey, networkType);
    var fundingUnlocker = P2PKHUnlockBuilder(fundingPubKey);
    var pp1BurnUnlocker = PP1UnlockBuilder.forBurn(ownerPubkey);
    var pp2BurnUnlocker = PP2UnlockBuilder.forBurn(ownerPubkey);
    var pwBurnUnlocker = PartialWitnessUnlockBuilder.forBurn(ownerPubkey);

    var burnTx = TransactionBuilder()
        .spendFromTxnWithSigner(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
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