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

class PartialSha256 {

  static int uint32mask = 0xFFFFFFFF;

  static Int32List STD_INIT_VECTOR = Int32List.fromList([
    0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6, 0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19
  ]);

  static const List<int> K = [
    0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b, 0x3956c25b, 0x59f111f1, -0x6dc07d5c, -0x54e3a12b,
    -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
    -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039, -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b,
    -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d, -0x2e6d17e7, -0x2966f9dc, -0xbf1ca7b, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8, -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e
  ];

  static const BLOCK_BITS = 512;
  static const int BLOCK_BYTES = BLOCK_BITS ~/ 8;

  static Int32List getPaddedPreImage(Uint8List message) {
    // New message length: original + 1-bit and padding + 8-byte length
    int finalBlockLength = message.length % BLOCK_BYTES;
    int blockCount = message.length ~/ BLOCK_BYTES + (finalBlockLength + 1 + 8 > BLOCK_BYTES ? 2 : 1);

    Int32List result = Int32List(blockCount * (BLOCK_BYTES ~/ 4));

    // Copy as much of the message as possible
    ByteData buf = ByteData.sublistView(message);
    int i = 0;
    int n = message.length ~/ 4;
    while (i < n) {
      result[i] = buf.getInt32(i * 4, Endian.big);
      i++;
    }

    // Copy the remaining bytes (less than 4) and append 1 bit (rest is zero)
    Uint8List remainder = Uint8List(4);
    for (int j = 0; j < message.length % 4; j++) {
      remainder[j] = message[(message.length ~/ 4) * 4 + j];
    }
    remainder[message.length % 4] = 0x80;

    result[i] = ByteData.view(remainder.buffer).getInt32(0, Endian.big);

    // Ignore however many pad bytes (implicitly calculated in the beginning)
    result[result.length - 2] = (message.length * 8) >> 32;
    result[result.length - 1] = (message.length * 8);

    return result;
  }

  static Uint8List hashOneBlock(Int32List oneChunk, Int32List inputVector) {

    // working arrays
    var W = Int32List(64);
    var H = Int32List(8);
    var TEMP = Int32List(8);

    // let H = H0
    // System.arraycopy(inputVector, 0, H, 0, inputVector.size)
    H.setRange(0, inputVector.length, inputVector);


    // enumerate all blocks (each containing 16 words)
    var i = 0;
    var wordCount = oneChunk.length ~/ 16;

    if (wordCount != 1) {
      throw Exception("We expect to only receive one block at a time. Too much data provided. ");
    }

    while (i < wordCount) {
      // initialize W from the block's words
      // System.arraycopy(message, i * 16, W, 0, 16)
      W.setRange(i * 16, (i * 16) + 16, oneChunk);
      for (int t = 16; t <  W.length ; t++) {
        W[t] = smallSig1(W[t - 2]) + W[t - 7] + smallSig0(W[t - 15]) + W[t - 16];
      }

      //let TEMP = H;
      // System.arraycopy(H, 0, TEMP, 0, H.size)
      TEMP.setRange(0, H.length, H);
      //
      // // operate on TEMP
      for (int t =0;  t < W.length; t++ ) {
        int t1 = TEMP[7] + bigSig1(TEMP[4]) + ch(TEMP[4], TEMP[5], TEMP[6]) + K[t] + W[t];
        int t2 = bigSig0(TEMP[0]) + maj(TEMP[0], TEMP[1], TEMP[2]);
        // System.arraycopy(TEMP, 0, TEMP, 1, TEMP.size - 1);
        TEMP.setRange(1, TEMP.length , TEMP);

        TEMP[4] += t1;
        TEMP[0] = t1 + t2;
      }
      //
      // // add values in TEMP to values in H
      for (int t = 0; t < H.length; t++) {
        H[t] += TEMP[t];
      }
      //
      ++i;
    }
    //
    return int32ListToUint8List(H);
  }


  static Uint8List toByteArray(Int32List vector){

    var bytes = ByteData(32);
    var offset = 0;
    for (int ndx = 0; ndx < vector.length ; ndx++) {
      // return H.buffer.asInt8List();
      offset = ndx * 4;
      bytes.setInt32(offset, vector[ndx], Endian.big);
    }
    return bytes.buffer.asUint8List();
  }

  static int ushr(int value, int shift) {
    return (value >> shift) & ((1 << (32 - shift)) - 1);
  }


  static int rotateRight(int i, int distance) {
    int bits = 32; // Assuming a 32-bit integer
    int unsignedShift = (i >> distance) & ((1 << (bits - distance)) - 1);
    return unsignedShift | (i << (bits - distance)) & ((1 << bits) - 1);
  }

  static int smallSig0(int x) {
    return (rotateRight(x,7) ^ rotateRight(x, 18) ^ (ushr(x, 3)));
  }

  static int smallSig1(int x) {
    return (rotateRight(x, 17) ^ rotateRight(x, 19) ^ (ushr(x ,10)));
  }

  static int ch(int x, int y, int z){
    int invX = ~x;
    return (x & y) | (invX & z);
  }

  static int maj(int x, int y, int z){
    return (x & y) | (x & z) | (y & z);
  }

  static int bigSig0(int x){
    return (rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22));
  }

  static int bigSig1(int x){
    return (rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25));
  }

  static Int32List uint8ListToInt32List(Uint8List uint8List) {
    // Create a ByteData view on the Uint8List
    ByteData byteData = ByteData.sublistView(uint8List);

    // Ensure that the length of Uint8List is a multiple of 4 (size of Int32)
    if (uint8List.length % 4 != 0) {
      throw ArgumentError('Uint8List length must be a multiple of 4 to convert to Int32List.');
    }

    // Create an Int32List using the ByteData
    Int32List int32List = Int32List(byteData.lengthInBytes ~/ 4);

    for (int i = 0; i < int32List.length; i++) {
      int32List[i] = byteData.getInt32(i * 4, Endian.big);
    }

    return int32List;
  }

  static Uint8List int32ListToUint8List(Int32List int32List) {
    // Allocate a ByteData buffer with the same size as the Int32List in bytes
    final byteData = ByteData(int32List.length * 4); // 4 bytes per int

    // Write each Int32 into the ByteData buffer
    for (int i = 0; i < int32List.length; i++) {
      byteData.setInt32(i * 4, int32List[i], Endian.big); // or Endian.little depending on your needs
    }

    // Convert the ByteData buffer to Uint8List
    return byteData.buffer.asUint8List();
  }

}

