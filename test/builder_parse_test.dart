import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

/// Test keys (same as plugpoint_spending_test.dart)
var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

void main() {
  group('PP2LockBuilder parse', () {
    test('round-trip: build then parse recovers constructor params', () {
      // Known constructor params
      var fundingTxId = List<int>.generate(32, (i) => i + 1); // 32 bytes
      var outputIndex = [0x01, 0x00, 0x00, 0x00]; // LE uint32 = 1
      var fundingOutpoint = fundingTxId + outputIndex; // 36 bytes
      var witnessChangePKH = hex.decode(bobPubkeyHash); // 20 bytes
      var changeAmount = 1;

      // Build the locking script
      var builder = PP2LockBuilder(fundingOutpoint, witnessChangePKH, changeAmount, witnessChangePKH);
      var script = builder.getScriptPubkey();

      // Parse it back
      var parsed = PP2LockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.fundingOutpoint, fundingOutpoint), true,
          reason: 'fundingOutpoint mismatch');
      expect(ListEquality().equals(parsed.witnessChangePKH, witnessChangePKH.toList()), true,
          reason: 'witnessChangePKH mismatch');
      expect(parsed.changeAmount, changeAmount, reason: 'changeAmount mismatch');
      expect(ListEquality().equals(parsed.ownerPKH, witnessChangePKH.toList()), true,
          reason: 'ownerPKH mismatch');
    });

    test('round-trip with larger changeAmount', () {
      var fundingOutpoint = List<int>.generate(36, (i) => 0xAA);
      var witnessChangePKH = List<int>.generate(20, (i) => 0xBB);
      var changeAmount = 1000;

      var builder = PP2LockBuilder(fundingOutpoint, witnessChangePKH, changeAmount, witnessChangePKH);
      var script = builder.getScriptPubkey();
      var parsed = PP2LockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.fundingOutpoint, fundingOutpoint), true);
      expect(ListEquality().equals(parsed.witnessChangePKH, witnessChangePKH), true);
      expect(parsed.changeAmount, changeAmount);
    });

    test('round-trip with zero changeAmount', () {
      var fundingOutpoint = List<int>.generate(36, (i) => 0x00);
      var witnessChangePKH = List<int>.generate(20, (i) => 0xFF);
      var changeAmount = 0;

      var builder = PP2LockBuilder(fundingOutpoint, witnessChangePKH, changeAmount, witnessChangePKH);
      var script = builder.getScriptPubkey();
      var parsed = PP2LockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.fundingOutpoint, fundingOutpoint), true);
      expect(ListEquality().equals(parsed.witnessChangePKH, witnessChangePKH), true);
      expect(parsed.changeAmount, changeAmount);
    });

    test('rejects script with wrong prefix', () {
      var badScript = SVScript.fromHex('76a914' + bobPubkeyHash + '88ac');
      expect(() => PP2LockBuilder.fromScript(badScript), throwsException);
    });
  });

  group('PP2UnlockBuilder parse', () {
    test('round-trip: build then parse recovers outpointTxId', () {
      var txId = List<int>.generate(32, (i) => i + 0x10);

      var builder = PP2UnlockBuilder(txId);
      var script = builder.getScriptSig();
      var parsed = PP2UnlockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.outpointTxId, txId), true,
          reason: 'outpointTxId mismatch');
    });
  });

  group('PartialWitnessUnlockBuilder parse', () {
    test('round-trip: build then parse recovers all fields', () {
      var preImage = List<int>.generate(100, (i) => i);
      var partialHash = List<int>.generate(32, (i) => i + 0x20);
      var partialWitnessPreImage = List<int>.generate(128, (i) => i + 0x40);
      var fundingTxId = List<int>.generate(32, (i) => i + 0x80);

      var builder = PartialWitnessUnlockBuilder(preImage, partialHash, partialWitnessPreImage, fundingTxId);
      // Signing is needed before getScriptSig produces output — but parse works from raw script
      // So we build the script manually as the builder would
      var scriptHex = ScriptBuilder()
          .addData(Uint8List.fromList(preImage))
          .addData(Uint8List.fromList(partialHash))
          .addData(Uint8List.fromList(partialWitnessPreImage))
          .addData(Uint8List.fromList(fundingTxId))
          .build()
          .toHex();

      var script = SVScript.fromHex(scriptHex);
      var parsed = PartialWitnessUnlockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.preImage, preImage), true, reason: 'preImage mismatch');
      expect(ListEquality().equals(parsed.partialHash, partialHash), true, reason: 'partialHash mismatch');
      expect(ListEquality().equals(parsed.partialWitnessPreImage, partialWitnessPreImage), true,
          reason: 'partialWitnessPreImage mismatch');
      expect(ListEquality().equals(parsed.fundingTxId, fundingTxId), true, reason: 'fundingTxId mismatch');
    });

    test('rejects script with too few chunks', () {
      var scriptHex = ScriptBuilder()
          .addData(Uint8List.fromList([1, 2, 3]))
          .addData(Uint8List.fromList([4, 5, 6]))
          .build()
          .toHex();
      var script = SVScript.fromHex(scriptHex);
      expect(() => PartialWitnessUnlockBuilder.fromScript(script), throwsException);
    });
  });

  group('PP1LockBuilder parse', () {
    test('round-trip: build then parse recovers recipientAddress and tokenId', () {
      var tokenId = List<int>.generate(32, (i) => i + 0x10);

      var builder = PP1LockBuilder(bobAddress, tokenId);
      var script = builder.getScriptPubkey();
      var parsed = PP1LockBuilder.fromScript(script);

      // Verify the round-trip produces identical script
      expect(ListEquality().equals(parsed.getScriptPubkey().buffer, script.buffer), true,
          reason: 'PP1 script round-trip mismatch');
      expect(ListEquality().equals(parsed.tokenId, tokenId), true, reason: 'tokenId mismatch');
      expect(parsed.recipientAddress?.pubkeyHash160, bobAddress.pubkeyHash160,
          reason: 'recipientAddress PKH mismatch');
    });
  });

  group('Template consistency with compiled contracts', () {
    test('PP2 DEBUG template matches compiled desc.json', () {
      var descFile = File('scrypt/contracts/out/tsl1_PP2_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_PP2_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var compiledHex = desc['hex'] as String;

      // The Dart builder template should match the compiled output
      var builder = PP2LockBuilder(List.generate(36, (_) => 0), List.generate(20, (_) => 0), 0, List.generate(20, (_) => 0));
      expect(builder.template, compiledHex,
          reason: 'PP2 DEBUG Dart template does not match compiled sCrypt output. '
              'Recompile contracts and update the template in pp2_lock_builder.dart.');
    });

    test('PP1 DEBUG template matches compiled desc.json', () {
      var descFile = File('scrypt/contracts/out/tsl1_PP1_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_PP1_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var compiledHex = desc['hex'] as String;

      // Extract Dart template for comparison
      var builder = PP1LockBuilder(bobAddress, List.generate(32, (_) => 0));
      // The PP1 template has <recipientPKH> and <tokenId> placeholders
      // We need the raw template string, not the substituted script
      // Access it through reflection or compare the substituted forms
      // For now, build with known values and compare against compiled hex with same substitutions
      var dartScript = builder.getScriptPubkey().toHex();
      var compiledScript = compiledHex
          .replaceFirst('<recipientPKH>', ScriptBuilder().addData(Uint8List.fromList(hex.decode(bobAddress.pubkeyHash160))).build().toHex())
          .replaceFirst('<tokenId>', ScriptBuilder().addData(Uint8List.fromList(List.generate(32, (_) => 0))).build().toHex());

      expect(dartScript, compiledScript,
          reason: 'PP1 DEBUG Dart template does not match compiled sCrypt output. '
              'Recompile contracts and update the template in pp1_lock_builder.dart.');
    });

    test('PartialWitness DEBUG template matches compiled desc.json', () {
      var descFile = File('scrypt/contracts/out/tsl1_partial_witness_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_partial_witness_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var compiledHex = desc['hex'] as String;

      var ownerPKH = hex.decode(bobPubkeyHash);
      var builder = PartialWitnessLockBuilder(ownerPKH);
      var dartScript = builder.getScriptPubkey().toHex();
      var compiledScript = compiledHex
          .replaceFirst('<ownerPKH>', ScriptBuilder().addData(Uint8List.fromList(ownerPKH)).build().toHex());

      expect(dartScript, compiledScript,
          reason: 'PartialWitness DEBUG Dart template does not match compiled sCrypt output. '
              'Recompile contracts and update the template in partial_witness_lock_builder.dart.');
    });

    test('PP2 contract abi includes burnToken function', () {
      var descFile = File('scrypt/contracts/out/tsl1_PP2_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_PP2_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var abi = desc['abi'] as List;
      var functionNames = abi.where((e) => e['type'] == 'function').map((e) => e['name']).toList();

      expect(functionNames, contains('burnToken'),
          reason: 'PP2 contract abi missing burnToken. Recompile from updated tsl1_PP2.scrypt.');
    });

    test('PP2 constructor includes ownerPKH param', () {
      var descFile = File('scrypt/contracts/out/tsl1_PP2_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_PP2_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var abi = desc['abi'] as List;
      var constructor = abi.firstWhere((e) => e['type'] == 'constructor');
      var paramNames = (constructor['params'] as List).map((e) => e['name']).toList();

      expect(paramNames, contains('ownerPKH'),
          reason: 'PP2 constructor missing ownerPKH param. Recompile from updated tsl1_PP2.scrypt.');
    });

    test('PartialWitness contract abi includes burnToken function', () {
      var descFile = File('scrypt/contracts/out/tsl1_partial_witness_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_partial_witness_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var abi = desc['abi'] as List;
      var functionNames = abi.where((e) => e['type'] == 'function').map((e) => e['name']).toList();

      expect(functionNames, contains('burnToken'),
          reason: 'PartialWitness contract abi missing burnToken. Recompile from updated tsl1_partial_witness.scrypt.');
    });

    test('PartialWitness constructor includes ownerPKH param', () {
      var descFile = File('scrypt/contracts/out/tsl1_partial_witness_debug_desc.json');
      if (!descFile.existsSync()) {
        fail('Missing compiled contract: tsl1_partial_witness_debug_desc.json');
      }

      var desc = jsonDecode(descFile.readAsStringSync());
      var abi = desc['abi'] as List;
      var constructor = abi.firstWhere((e) => e['type'] == 'constructor');
      var paramNames = (constructor['params'] as List).map((e) => e['name']).toList();

      expect(paramNames, contains('ownerPKH'),
          reason: 'PartialWitness constructor missing ownerPKH param. Recompile from updated tsl1_partial_witness.scrypt.');
    });
  });
}
