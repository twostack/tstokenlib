

import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:convert/convert.dart';
import 'package:tstokenlib/tstokenlib.dart';

void main() {
    test('check on block size calculations', () {
      final txHex = "0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff";

      final txBytes = hex.decode(txHex) as Uint8List;

      final blockCount = txBytes.length ~/ 64;
      final remainderBytes = txBytes.length % 64;

      print('$blockCount blocks, with $remainderBytes bytes left over');

      expect(blockCount, isNotNull); // You can add meaningful assertions here
      expect(remainderBytes, isNotNull); // You can add meaningful assertions here
    });

    test('it can incrementally compute a sha256 hash', () {
      final txHex = "0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff";

      final txBytes = hex.decode(txHex) as Uint8List;

      // Get the padded pre-image
      final paddedPreImage = PartialSha256.getPaddedPreImage(txBytes);

      final firstBlock = paddedPreImage.sublist(0, 16);
      final secondBlock = paddedPreImage.sublist(16, 32);

      final partialHash = PartialSha256.hashOneBlock(firstBlock, Int32List.fromList(PartialSha256.STD_INIT_VECTOR));
      // final partialHash = PartialSha256.processBlock(firstBlock, Int32List.fromList(PartialSha256.STD_INIT_VECTOR));
      final fullHash = PartialSha256.hashOneBlock(secondBlock,  PartialSha256.uint8ListToInt32List(partialHash));
      //
      final fullHashBytes = hex.encode(fullHash);
      //
      print("Hex of partial calc: $fullHashBytes");
      //
      // // Validate against the system's SHA-256 implementation
      final sha256Digest = sha256.convert(txBytes);
      final knownHash = sha256Digest.bytes;
      //
      expect(fullHash, equals(knownHash));
      print("Hex of system algo: ${hex.encode(knownHash)}");
    });
}
