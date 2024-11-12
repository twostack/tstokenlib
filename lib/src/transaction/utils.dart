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
import 'package:tstokenlib/src/transaction/partial_sha256.dart';

class TransactionUtils {

  int getInOutSize(Transaction tx) {
    return tx.inputs[2].serialize().length + 1 + tx.outputs[0].serialize().length;
  }

  List<int> calculatePaddingBytes(Transaction witnessTx ){

    var witnessBytes = hex.decode(witnessTx.serialize());
    var originalSize = witnessBytes.length;

    // size(last input) + size(all outputs). assumed to be < 128 bytes
    var inOutSize = getInOutSize(witnessTx);

    //pad things so that the start of the last input falls on a 64 byte boundary
    //the sha256 padding will take us the rest of the way
    var lastInputStart = originalSize - inOutSize;

    //we don't want this falling on exact boundary, so fudge by -2 bytes
    if (lastInputStart % 64 == 0){
        lastInputStart -= 2;
    }

    //place the start of the last input on a 64 byte boundary
    //expect (originalSize + lastBlockPadding - inOutSize ) % 64 == 0
    var lastBlockPadding = 64 - (lastInputStart % 64);

    var paddingScriptSize = ScriptBuilder().addData(Uint8List(lastBlockPadding)).build().buffer.length;

    return Uint8List(lastBlockPadding +1 +4);
  }

  /*
   * preImage - The full preimage for which to calculate the partial preimage
   * excludeBlocks - the number of blocks at tail-end to exclude from partial preimage.
   */
  (List<int>, List<int>) computePartialHash(List<int> preImage, int excludeBlocks){

    var blockCount = preImage.length ~/ PartialSha256.BLOCK_BYTES;
    var rounds = blockCount - excludeBlocks;

    var paddedPreImage = PartialSha256.getPaddedPreImage(Uint8List.fromList(preImage));
    var start = 0;
    var end = start + 16;

    final firstBlock = paddedPreImage.sublist(start, end);

    Int32List currentBlock;

    var currentHash = PartialSha256.hashOneBlock(firstBlock, PartialSha256.STD_INIT_VECTOR);

    for (int round = 0; round < rounds; round++){
      start = end;
      end = start + 16;
      currentBlock = paddedPreImage.sublist(start, end);

      currentHash = PartialSha256.hashOneBlock(currentBlock, PartialSha256.uint8ListToInt32List(currentHash));
    }

    var lastBlocks = paddedPreImage.sublist(paddedPreImage.length - 32, paddedPreImage.length );
    var remainder = PartialSha256.int32ListToUint8List(lastBlocks); //lastblocks is 128 bytes in total. Should be reflected in remainder.
    return (currentHash, remainder);

  }

  /*
  Returns the LHS of a Transaction. I.e everything except the Outputs.
   */
  List<int> getTxLHS(Transaction fullTx){

    ByteDataWriter writer = ByteDataWriter();

    // set the transaction version
    writer.writeInt32(fullTx.version, Endian.little);

    // set the number of inputs
    var numInputs= VarInt.fromInt(fullTx.inputs.length);
    writer.write(numInputs.encode());

    // write the inputs
    fullTx.inputs.forEach((input) {
      writer.write(input.serialize());
    });

    return writer.toBytes();
  }


  static void printPreImage(List<int> preImage) {

    var reader = ByteDataReader(endian: Endian.little)..add(preImage);

    var version = reader.readUint32();
    var outpointsHash = reader.read(32);
    var hashSequence = reader.read(32);
    var outpointTxId = reader.read(32);
    var outpointIndex = reader.readUint32();
    var scriptLen = readVarIntNum(reader);
    var scriptPubkeyBytes = reader.read(scriptLen);
    var scriptCode = SVScript.fromByteArray(scriptPubkeyBytes);
    var outputAmount = reader.readUint64();
    var sequenceNum = reader.readUint32();
    var hashScriptPub = reader.read(32);
    var nLocktime = reader.readUint32();
    var sighashType = reader.readUint32();

    print("-------- SigHash PreImage -------");
    print("HEX: ${hex.encode(preImage)}");
    print("version: ${version}");
    print("hashPrevOuts: ${hex.encode(outpointsHash)}");
    print("hashSequence: ${hex.encode(hashSequence)}");
    print("outpointTxId: ${hex.encode(outpointTxId)}");
    print("outpointIndex: ${outpointIndex}");
    print("outputAmount: ${outputAmount}");
    print("sequenceNum: ${sequenceNum}");
    print("nLockTime: ${nLocktime}");
    print("sighashType: ${sighashType}");
    print("scriptPubKey: ${hex.encode(scriptPubkeyBytes)}");
    print("            : ${scriptCode.toString(type: 'asm')}");
    print("hashOutputs: ${hex.encode(hashScriptPub)}");
    print("---------------------------------");


  }
}