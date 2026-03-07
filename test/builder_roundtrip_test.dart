import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

/// Test keys (same as builder_parse_test.dart)
var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

void main() {
  group('PartialWitnessLockBuilder round-trip', () {
    test('build then parse recovers ownerPKH', () {
      var ownerPKH = hex.decode(bobPubkeyHash);
      var builder = PartialWitnessLockBuilder(ownerPKH);
      var script = builder.getScriptPubkey();

      var parsed = PartialWitnessLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.ownerPKH, ownerPKH.toList()), true,
          reason: 'ownerPKH mismatch after round-trip');
    });

    test('build then parse with different PKH', () {
      var ownerPKH = List<int>.generate(20, (i) => i + 0x10);
      var builder = PartialWitnessLockBuilder(ownerPKH);
      var script = builder.getScriptPubkey();

      var parsed = PartialWitnessLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.ownerPKH, ownerPKH), true,
          reason: 'ownerPKH mismatch with synthetic PKH');
    });

    test('rejects PKH with wrong length', () {
      var badPKH = List<int>.generate(19, (i) => i);
      expect(() => PartialWitnessLockBuilder(badPKH), throwsException);
    });
  });

  group('ModP2PKHLockBuilder round-trip', () {
    test('fromAddress build then parse recovers pubkeyHash', () {
      var builder = ModP2PKHLockBuilder.fromAddress(bobAddress);
      var script = builder.getScriptPubkey();

      var parsed = ModP2PKHLockBuilder.fromScript(script, networkType: NetworkType.TEST);

      expect(
          ListEquality().equals(
              parsed.pubkeyHash, hex.decode(bobPubkeyHash).toList()),
          true,
          reason: 'pubkeyHash mismatch after round-trip');
    });

    test('fromPublicKey build then parse recovers pubkeyHash', () {
      var builder =
          ModP2PKHLockBuilder.fromPublicKey(bobPub, networkType: NetworkType.TEST);
      var script = builder.getScriptPubkey();

      var parsed = ModP2PKHLockBuilder.fromScript(script, networkType: NetworkType.TEST);

      expect(
          ListEquality().equals(
              parsed.pubkeyHash, hex.decode(bobPubkeyHash).toList()),
          true,
          reason: 'pubkeyHash mismatch after fromPublicKey round-trip');
    });

    test('script has OP_SWAP prefix (not standard P2PKH)', () {
      var builder = ModP2PKHLockBuilder.fromAddress(bobAddress);
      var script = builder.getScriptPubkey();
      var chunks = script.chunks;

      // ModP2PKH: OP_SWAP OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
      expect(chunks.length, 6);
      expect(chunks[0].opcodenum, OpCodes.OP_SWAP,
          reason: 'First opcode should be OP_SWAP (modified P2PKH)');
      expect(chunks[1].opcodenum, OpCodes.OP_DUP);
      expect(chunks[2].opcodenum, OpCodes.OP_HASH160);
      expect(chunks[3].len, 20, reason: 'PKH should be 20 bytes');
      expect(chunks[4].opcodenum, OpCodes.OP_EQUALVERIFY);
      expect(chunks[5].opcodenum, OpCodes.OP_CHECKSIG);
    });

    test('parsed address matches original address', () {
      var builder = ModP2PKHLockBuilder.fromAddress(bobAddress);
      var script = builder.getScriptPubkey();

      var parsed = ModP2PKHLockBuilder.fromScript(script, networkType: NetworkType.TEST);

      expect(parsed.address?.pubkeyHash160, bobAddress.pubkeyHash160,
          reason: 'address pubkeyHash160 mismatch');
    });
  });

  group('AIPLockBuilder round-trip', () {
    test('build then parse recovers values via script bytes', () {
      // Use a known pubkey hex and base64 signature
      var pubKeyHex = hex.encode(utf8.encode('test-pubkey-32bytes-padding1234'));
      var signatureBytes = utf8.encode('test-signature-data-for-aip-lck');
      var signatureB64 = base64Encode(signatureBytes);

      var builder = AIPLockBuilder(pubKeyHex, signatureB64);
      var script = builder.getScriptPubkey();

      // Parse it back
      var parsed = AIPLockBuilder.fromScript(script);

      // The parse method stores chunks[4].buf as hex and chunks[5].buf as hex
      // chunks[4].buf contains hex.decode(publicKey) from build
      // chunks[5].buf contains base64Decode(signature) from build
      // parse stores them as hex.encode(chunks[N].buf)
      // So parsed.publicKey == hex.encode(hex.decode(pubKeyHex)) == pubKeyHex
      expect(parsed.publicKey, pubKeyHex,
          reason: 'publicKey mismatch after round-trip');

      // For signature: build puts base64Decode(signatureB64) into script,
      // parse reads the raw bytes and hex-encodes them.
      // So parsed.signature == hex.encode(base64Decode(signatureB64))
      //                     == hex.encode(signatureBytes)
      expect(parsed.signature, hex.encode(signatureBytes),
          reason: 'signature bytes mismatch after round-trip');

      // SIGNING_ALGORITHM: build puts utf8.encode("ED25519") into script,
      // parse reads the raw bytes and hex-encodes them.
      // So parsed.SIGNING_ALGORITHM == hex.encode(utf8.encode("ED25519"))
      expect(parsed.SIGNING_ALGORITHM, hex.encode(utf8.encode("ED25519")),
          reason: 'SIGNING_ALGORITHM mismatch after round-trip');
    });

    test('script structure is correct', () {
      var pubKeyHex = 'aabbccdd';
      var signatureB64 = base64Encode([0x01, 0x02, 0x03, 0x04]);

      var builder = AIPLockBuilder(pubKeyHex, signatureB64);
      var script = builder.getScriptPubkey();
      var chunks = script.chunks;

      // OP_FALSE OP_RETURN <prefix> <algorithm> <pubkey> <signature>
      expect(chunks.length, 6);
      expect(chunks[0].opcodenum, OpCodes.OP_FALSE);
      expect(chunks[1].opcodenum, OpCodes.OP_RETURN);
      expect(utf8.decode(chunks[2].buf ?? []), '15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva');
      expect(utf8.decode(chunks[3].buf ?? []), 'ED25519');
      expect(hex.encode(chunks[4].buf ?? []), pubKeyHex);
      expect(chunks[5].buf, [0x01, 0x02, 0x03, 0x04]);
    });
  });

  group('BLockBuilder round-trip', () {
    test('build then parse recovers all fields', () {
      var data = utf8.encode('Hello, B protocol!');
      var mediaType = 'text/plain';
      var encoding = 'utf-8';
      var filename = 'hello.txt';

      var builder = BLockBuilder(data, mediaType, encoding, filename: filename);
      var script = builder.getScriptPubkey();

      var parsed = BLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.data, data), true,
          reason: 'data mismatch');
      expect(parsed.mediaType, mediaType, reason: 'mediaType mismatch');
      expect(parsed.encoding, encoding, reason: 'encoding mismatch');
      expect(parsed.filename, filename, reason: 'filename mismatch');
    });

    test('build then parse without filename', () {
      var data = [0x00, 0x01, 0x02, 0xFF];
      var mediaType = 'application/octet-stream';
      var encoding = 'binary';

      var builder = BLockBuilder(data, mediaType, encoding);
      var script = builder.getScriptPubkey();

      var parsed = BLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.data, data), true,
          reason: 'data mismatch');
      expect(parsed.mediaType, mediaType, reason: 'mediaType mismatch');
      expect(parsed.encoding, encoding, reason: 'encoding mismatch');
      expect(parsed.filename, isNull, reason: 'filename should be null when omitted');
    });

    test('build then parse with binary data', () {
      var data = List<int>.generate(256, (i) => i % 256);
      var mediaType = 'application/octet-stream';
      var encoding = 'binary';

      var builder = BLockBuilder(data, mediaType, encoding);
      var script = builder.getScriptPubkey();

      var parsed = BLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.data, data), true,
          reason: 'binary data mismatch');
      expect(parsed.mediaType, mediaType);
      expect(parsed.encoding, encoding);
    });
  });

  group('MapLockBuilder round-trip', () {
    test('build then parse recovers map entries', () {
      var map = <String, dynamic>{
        'app': 'tstokenlib',
        'type': 'test',
        'context': 'round-trip',
      };

      var builder = MapLockBuilder.fromMap(map);
      var script = builder.getScriptPubkey();

      var parsed = MapLockBuilder.fromScript(script);

      expect(parsed.map.length, map.length, reason: 'map length mismatch');
      for (var key in map.keys) {
        expect(parsed.map[key], map[key], reason: 'map[$key] mismatch');
      }
    });

    test('build then parse with single entry', () {
      var map = <String, dynamic>{'key': 'value'};

      var builder = MapLockBuilder.fromMap(map);
      var script = builder.getScriptPubkey();

      var parsed = MapLockBuilder.fromScript(script);

      expect(parsed.map['key'], 'value');
    });
  });

  group('BmapLockBuilder round-trip', () {
    test('build then parse recovers B and MAP data', () {
      var data = utf8.encode('BMAP test content');
      var mediaType = 'text/plain';
      var encoding = 'utf-8';
      var filename = 'bmap.txt';
      var map = <String, dynamic>{
        'app': 'tstokenlib',
        'type': 'bmap_test',
      };

      var bLocker = BLockBuilder(data, mediaType, encoding, filename: filename);
      var mapLocker = MapLockBuilder.fromMap(map);

      var builder = BmapLockBuilder(bLocker, mapLocker);
      var script = builder.getScriptPubkey();

      var parsed = BmapLockBuilder.fromScript(script);

      // Verify B protocol fields
      expect(ListEquality().equals(parsed.data, data), true,
          reason: 'B data mismatch');
      expect(parsed.mediaType, mediaType, reason: 'mediaType mismatch');
      expect(parsed.encoding, encoding, reason: 'encoding mismatch');
      expect(parsed.filename, filename, reason: 'filename mismatch');

      // Verify MAP fields
      expect(parsed.map.length, map.length, reason: 'map length mismatch');
      for (var key in map.keys) {
        expect(parsed.map[key], map[key], reason: 'map[$key] mismatch');
      }
    });

    test('build then parse without filename', () {
      var data = utf8.encode('No filename');
      var mediaType = 'text/plain';
      var encoding = 'utf-8';
      var map = <String, dynamic>{'action': 'post'};

      var bLocker = BLockBuilder(data, mediaType, encoding);
      var mapLocker = MapLockBuilder.fromMap(map);

      var builder = BmapLockBuilder(bLocker, mapLocker);
      var script = builder.getScriptPubkey();

      var parsed = BmapLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.data, data), true);
      expect(parsed.mediaType, mediaType);
      expect(parsed.encoding, encoding);
      expect(parsed.map['action'], 'post');
    });
  });

  group('HodlLockBuilder round-trip', () {
    test('build then parse recovers pubKeyHash and lockHeight', () {
      var pubKeyHash = hex.decode(bobPubkeyHash).toList();
      var lockHeight = BigInt.from(800000);

      var builder = HodlLockBuilder(pubKeyHash, lockHeight);
      var script = builder.getScriptPubkey();

      // Parse from hex (HodlLockBuilder.fromHex takes hex string)
      var parsed = HodlLockBuilder.fromHex(script.toHex());

      expect(ListEquality().equals(parsed.pubKeyHash, pubKeyHash), true,
          reason: 'pubKeyHash mismatch after round-trip');
      expect(parsed.lockHeight, lockHeight,
          reason: 'lockHeight mismatch after round-trip');
    });

    test('build then parse with different lock height', () {
      var pubKeyHash = List<int>.generate(20, (i) => i + 0x30);
      var lockHeight = BigInt.from(500000);

      var builder = HodlLockBuilder(pubKeyHash, lockHeight);
      var script = builder.getScriptPubkey();

      var parsed = HodlLockBuilder.fromHex(script.toHex());

      expect(ListEquality().equals(parsed.pubKeyHash, pubKeyHash), true,
          reason: 'pubKeyHash mismatch');
      expect(parsed.lockHeight, lockHeight,
          reason: 'lockHeight mismatch');
    });

    test('build then parse with small lock height', () {
      var pubKeyHash = hex.decode(bobPubkeyHash).toList();
      var lockHeight = BigInt.from(100);

      var builder = HodlLockBuilder(pubKeyHash, lockHeight);
      var script = builder.getScriptPubkey();

      var parsed = HodlLockBuilder.fromHex(script.toHex());

      expect(ListEquality().equals(parsed.pubKeyHash, pubKeyHash), true);
      expect(parsed.lockHeight, lockHeight);
    });
  });
}
