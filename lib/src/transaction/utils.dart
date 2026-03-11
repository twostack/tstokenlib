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
import 'partial_sha256.dart';

/// Utility methods for TSToken transaction manipulation.
///
/// Provides helpers for SHA256 block-alignment padding, partial hash
/// computation, and extracting the left-hand side (inputs) of a transaction.
class TransactionUtils {
  // SHA256 processes data in 64-byte (512-bit) blocks
  static const int SHA256_BLOCK_SIZE = 64;

  // Transaction locktime field is always 4 bytes
  static const int LOCKTIME_SIZE = 4;

  /// Returns the combined serialized size of the last input and first output of [tx].
  int getInOutSize(Transaction tx) {
    return tx.inputs[2].serialize().length + 1 + tx.outputs[0].serialize().length;
  }

  /// Calculates padding bytes needed to align the witness transaction's last input
  /// to a SHA256 64-byte block boundary.
  ///
  /// This alignment enables the partial SHA256 witness proof mechanism.
  List<int> calculatePaddingBytes(Transaction witnessTx ){

    var witnessBytes = hex.decode(witnessTx.serialize());
    var originalSize = witnessBytes.length;

    // size(last input) + size(all outputs). assumed to be < 128 bytes
    var inOutSize = getInOutSize(witnessTx);

    // Pad so that the start of the last input falls on a 64-byte (SHA256 block) boundary.
    // The SHA256 padding will take us the rest of the way.
    var lastInputStart = originalSize - (inOutSize + LOCKTIME_SIZE);

    // Calculate bytes needed to reach the next 64-byte boundary.
    // When already on a boundary (remainder=0), we add a full block (64 bytes)
    // to ensure non-empty padding (required by PP1/PP1_FT contracts).
    var remainder = lastInputStart % SHA256_BLOCK_SIZE;
    var lastBlockPadding = remainder == 0 ? SHA256_BLOCK_SIZE : SHA256_BLOCK_SIZE - remainder;

    // We subtract 1 to accommodate the pushdata byte in script.
    // +2 for placeholder padding prior to running this algo
    return Uint8List(lastBlockPadding - 1 + 2);
  }

  /// Computes a partial SHA256 hash over [preImage], excluding the last
  /// [excludeBlocks] 64-byte blocks from the intermediate hash.
  ///
  /// Returns a record of (partialHash, remainderBytes) where remainderBytes
  /// contains the excluded tail blocks (128 bytes total).
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

  /// Returns the left-hand side of a transaction: version, input count, and
  /// all serialized inputs. Excludes outputs and locktime.
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
}