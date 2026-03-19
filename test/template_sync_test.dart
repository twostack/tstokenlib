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

/// Tests that the committed JSON templates match the output of the Dart
/// script generators, ensuring templates stay in sync with code changes.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/script_gen/pp1_nft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_ft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/witness_check_script_gen.dart';

void main() {
  group('Template sync guard', () {
    test('PP1 template round-trips correctly', () {
      var templateJson = jsonDecode(File('templates/nft/pp1_nft.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      // Substitute known values
      var ownerPKH = List.generate(20, (i) => i + 1);
      var tokenId = List.generate(32, (i) => i + 0x20);
      var rabinPKH = List.generate(20, (i) => i + 0x40);

      var substituted = templateHex
          .replaceFirst('{{ownerPKH}}', hex.encode(ownerPKH))
          .replaceFirst('{{tokenId}}', hex.encode(tokenId))
          .replaceFirst('{{rabinPubKeyHash}}', hex.encode(rabinPKH));

      // Generate from Dart code with the same values
      var script = PP1NftScriptGen.generate(
        ownerPKH: ownerPKH,
        tokenId: tokenId,
        rabinPubKeyHash: rabinPKH,
      );
      var generatedHex = hex.encode(script.buffer!);

      expect(substituted, equals(generatedHex),
          reason: 'PP1 template output must match PP1NftScriptGen.generate() output');
    });

    test('PP1_FT template round-trips correctly', () {
      var templateJson = jsonDecode(File('templates/ft/pp1_ft.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      var ownerPKH = List.generate(20, (i) => i + 1);
      var tokenId = List.generate(32, (i) => i + 0x20);
      var rabinPKH = List.generate(20, (i) => i + 0x40);
      var amount = 1000000; // 1M satoshis

      // Encode amount as 8-byte LE (same as PP1FtScriptGen)
      var amountBytes = Uint8List(8);
      var val = amount;
      for (var i = 0; i < 7; i++) {
        amountBytes[i] = val & 0xFF;
        val >>= 8;
      }
      amountBytes[7] = val & 0x7F;

      var substituted = templateHex
          .replaceFirst('{{ownerPKH}}', hex.encode(ownerPKH))
          .replaceFirst('{{tokenId}}', hex.encode(tokenId))
          .replaceFirst('{{rabinPubKeyHash}}', hex.encode(rabinPKH))
          .replaceFirst('{{amount}}', hex.encode(amountBytes));

      var script = PP1FtScriptGen.generate(
        ownerPKH: ownerPKH,
        tokenId: tokenId,
        rabinPubKeyHash: rabinPKH,
        amount: amount,
      );
      var generatedHex = hex.encode(script.buffer!);

      expect(substituted, equals(generatedHex),
          reason: 'PP1_FT template output must match PP1FtScriptGen.generate() output');
    });

    test('PP3 NFT witness template round-trips correctly', () {
      var templateJson = jsonDecode(File('templates/nft/pp3_witness.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      var ownerPKH = List.generate(20, (i) => i + 1);

      var substituted = templateHex
          .replaceFirst('{{ownerPKH}}', hex.encode(ownerPKH));

      var script = WitnessCheckScriptGen.generate(
        ownerPKH: ownerPKH,
        pp2OutputIndex: 2,
      );
      var generatedHex = hex.encode(script.buffer!);

      expect(substituted, equals(generatedHex),
          reason: 'PP3 NFT template output must match WitnessCheckScriptGen.generate() output');
    });

    test('PP3 FT witness template round-trips correctly', () {
      var templateJson = jsonDecode(File('templates/ft/pp3_ft_witness.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      var ownerPKH = List.generate(20, (i) => i + 1);

      var substituted = templateHex
          .replaceFirst('{{ownerPKH}}', hex.encode(ownerPKH));

      var script = WitnessCheckScriptGen.generate(
        ownerPKH: ownerPKH,
        pp2OutputIndex: 3,
      );
      var generatedHex = hex.encode(script.buffer!);

      expect(substituted, equals(generatedHex),
          reason: 'PP3 FT template output must match WitnessCheckScriptGen.generate() output');
    });

    test('ModP2PKH template round-trips correctly', () {
      var templateJson = jsonDecode(File('templates/utility/mod_p2pkh.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      var ownerPKH = List.generate(20, (i) => i + 1);

      var substituted = templateHex
          .replaceFirst('{{ownerPKH}}', hex.encode(ownerPKH));

      var builder = ScriptBuilder()
          .opCode(OpCodes.OP_SWAP)
          .opCode(OpCodes.OP_DUP)
          .opCode(OpCodes.OP_HASH160)
          .addData(Uint8List.fromList(ownerPKH))
          .opCode(OpCodes.OP_EQUALVERIFY)
          .opCode(OpCodes.OP_CHECKSIG);
      var generatedHex = hex.encode(builder.build().buffer!);

      expect(substituted, equals(generatedHex),
          reason: 'ModP2PKH template output must match ScriptBuilder output');
    });

    test('PP2 template has correct placeholder structure', () {
      var templateJson = jsonDecode(File('templates/nft/pp2.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      expect(templateHex, contains('{{outpoint}}'));
      expect(templateHex, contains('{{witnessChangePKH}}'));
      expect(templateHex, contains('{{witnessChangeAmount}}'));
      expect(templateHex, contains('{{ownerPKH}}'));
      // Ensure no residual <param> tags
      expect(templateHex, isNot(contains('<outpoint>')));
    });

    test('PP2-FT template has correct placeholder structure', () {
      var templateJson = jsonDecode(File('templates/ft/pp2_ft.json').readAsStringSync());
      var templateHex = templateJson['hex'] as String;

      expect(templateHex, contains('{{outpoint}}'));
      expect(templateHex, contains('{{witnessChangePKH}}'));
      expect(templateHex, contains('{{witnessChangeAmount}}'));
      expect(templateHex, contains('{{ownerPKH}}'));
      expect(templateHex, contains('{{pp1FtOutputIndex}}'));
      expect(templateHex, contains('{{pp2OutputIndex}}'));
      expect(templateHex, isNot(contains('<outpoint>')));
    });

    test('HODL template has correct placeholder structure', () {
      var templateJson = jsonDecode(File('templates/utility/hodl.json').readAsStringSync());
      var templateAsm = templateJson['asm'] as String;

      expect(templateAsm, contains('{{ownerPubkeyHash}}'));
      expect(templateAsm, contains('{{lockHeight}}'));
      expect(templateAsm, isNot(contains('<ownerPubkeyHash>')));
      expect(templateAsm, isNot(contains('<lockHeight>')));
    });

    test('All template files exist', () {
      var expectedFiles = [
        'templates/nft/pp1_nft.json',
        'templates/nft/pp2.json',
        'templates/nft/pp3_witness.json',
        'templates/ft/pp1_ft.json',
        'templates/ft/pp2_ft.json',
        'templates/ft/pp3_ft_witness.json',
        'templates/utility/mod_p2pkh.json',
        'templates/utility/hodl.json',
      ];

      for (var path in expectedFiles) {
        expect(File(path).existsSync(), isTrue, reason: '$path should exist');
        var json = jsonDecode(File(path).readAsStringSync());
        expect(json['name'], isNotNull, reason: '$path should have a name');
        expect(json['version'], equals('1.3.0'), reason: '$path should have correct version');
        expect(json['parameters'], isNotNull, reason: '$path should have parameters');
        expect(json['hex'] ?? json['asm'], isNotNull, reason: '$path should have hex or asm');
      }
    });
  });
}
