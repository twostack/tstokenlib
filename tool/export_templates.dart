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

/// Exports all TSL1 Bitcoin script templates to JSON descriptor files
/// in the templates/ directory.
///
/// Run with: dart run tool/export_templates.dart

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/script_gen/pp1_nft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_ft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_rnft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_rft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_at_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_sm_script_gen.dart';
import 'package:tstokenlib/src/script_gen/witness_check_script_gen.dart';

const String version = '1.3.0';

void main() {
  final baseDir = Directory('templates');
  if (!baseDir.existsSync()) {
    baseDir.createSync(recursive: true);
  }

  print('Exporting TSL1 script templates...');

  exportPP1();
  exportPP1Ft();
  exportPP1Rnft();
  exportPP1Rft();
  exportPP1At();
  exportPP1Sm();
  exportPP3Nft();
  exportPP3Ft();
  exportModP2PKH();
  exportPP2();
  exportPP2FT();
  exportHODL();

  print('Done. Templates written to templates/');
}

/// Generates a script with sentinel values and replaces them with placeholders.
String templatizeHex(String fullHex, Map<String, _SentinelRegion> sentinels) {
  var result = fullHex;
  // Sort by offset descending so replacements don't shift earlier positions
  var entries = sentinels.entries.toList()
    ..sort((a, b) => b.value.byteOffset.compareTo(a.value.byteOffset));

  for (var entry in entries) {
    var sentinel = entry.value;
    // Each byte is 2 hex chars
    var hexStart = sentinel.byteOffset * 2;
    var hexEnd = (sentinel.byteOffset + sentinel.byteLength) * 2;
    var sentinelHex = result.substring(hexStart, hexEnd);
    // Verify sentinel is what we expect
    var expectedHex = hex.encode(List.filled(sentinel.byteLength, sentinel.sentinelByte));
    if (sentinelHex != expectedHex) {
      throw Exception(
          'Sentinel mismatch for {{${entry.key}}} at byte offset ${sentinel.byteOffset}: '
          'expected $expectedHex, got $sentinelHex');
    }
    result = result.substring(0, hexStart) +
        '{{${entry.key}}}' +
        result.substring(hexEnd);
  }
  return result;
}

class _SentinelRegion {
  final int byteOffset;
  final int byteLength;
  final int sentinelByte;
  _SentinelRegion(this.byteOffset, this.byteLength, this.sentinelByte);
}

void writeTemplate(String path, Map<String, dynamic> descriptor) {
  var file = File(path);
  file.parent.createSync(recursive: true);
  var encoder = JsonEncoder.withIndent('  ');
  file.writeAsStringSync(encoder.convert(descriptor) + '\n');
  print('  Wrote $path (${file.lengthSync()} bytes)');
}

// ==========================================================================
// Category A: Hand-optimized scripts
// ==========================================================================

void exportPP1() {
  // Generate with sentinel values
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  var rabinPubKeyHash = List.filled(20, 0xCC);

  var script = PP1NftScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    rabinPubKeyHash: rabinPubKeyHash,
  );

  var fullHex = hex.encode(script.buffer!);

  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1NftScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1NftScriptGen.tokenIdDataStart, 32, 0xBB),
    'rabinPubKeyHash': _SentinelRegion(PP1NftScriptGen.rabinPKHDataStart, 20, 0xCC),
  });

  writeTemplate('templates/nft/pp1_nft.json', {
    'name': 'PP1_NFT',
    'version': version,
    'description': 'NFT inductive proof locking script. Validates parent output structure and token ownership chain.',
    'category': 'nft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid)',
      },
      {
        'name': 'rabinPubKeyHash',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte hash160 of the Rabin public key for identity anchoring',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1NftScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_nft_script_gen.dart',
      'note': 'Pushdata prefixes (0x14, 0x20) are part of the static hex. Substitute raw parameter bytes only.',
    },
  });
}

void exportPP1Ft() {
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  // Amount: 8 bytes of 0xDD sentinel
  // Use a specific amount that produces our sentinel pattern
  // amount is encoded as 8-byte LE with bit 63 clear
  // 0xDDDDDDDDDDDDDD = a known test value
  var amount = 0x0DDDDDDDDDDDDDDD; // bit 63 clear

  var script = PP1FtScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    amount: amount,
  );

  var fullHex = hex.encode(script.buffer!);

  // Verify the amount encoding at the expected offset
  var amountHexStart = PP1FtScriptGen.amountDataStart * 2;
  var amountHexEnd = PP1FtScriptGen.amountDataEnd * 2;
  var amountHex = fullHex.substring(amountHexStart, amountHexEnd);

  // Build template by replacing sentinel regions
  // For amount, we need to find the actual encoded bytes
  var amountBytes = Uint8List(8);
  var val = amount;
  for (var i = 0; i < 7; i++) {
    amountBytes[i] = val & 0xFF;
    val >>= 8;
  }
  amountBytes[7] = val & 0x7F;
  var amountSentinelHex = hex.encode(amountBytes);

  // Replace ownerPKH and tokenId using sentinel approach
  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1FtScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1FtScriptGen.tokenIdDataStart, 32, 0xBB),
  });

  // Replace amount region manually (not uniform sentinel bytes)
  var amountStart = PP1FtScriptGen.amountDataStart * 2;
  // Adjust for placeholder insertions before this offset
  // ownerPKH placeholder: replaced 40 hex chars with "{{ownerPKH}}" (12 chars) = -28 shift
  // tokenId placeholder: replaced 64 hex chars with "{{tokenId}}" (11 chars) = -53 shift
  // But since we used templatizeHex which sorts descending, ownerPKH (offset 1) was replaced last
  // Let's just find the amount hex in the template string
  var amountInTemplate = templateHex.indexOf(amountSentinelHex);
  if (amountInTemplate == -1) {
    throw Exception('Could not find amount sentinel in template hex');
  }
  templateHex = templateHex.substring(0, amountInTemplate) +
      '{{amount}}' +
      templateHex.substring(amountInTemplate + amountSentinelHex.length);

  writeTemplate('templates/ft/pp1_ft.json', {
    'name': 'PP1_FT',
    'version': version,
    'description': 'Fungible token locking script. Enforces amount conservation across mint, transfer, split, merge, and burn operations.',
    'category': 'ft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid)',
      },
      {
        'name': 'amount',
        'size': 8,
        'encoding': 'le_uint56',
        'description': '8-byte little-endian amount (7 bytes value + high byte with bit 7 clear). Max value: 2^55 - 1 satoshis.',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1FtScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_ft_script_gen.dart',
      'note': 'Amount encoding: 8 bytes LE, byte[0..6] = value bits, byte[7] = (value >> 56) & 0x7F. Pushdata prefix 0x08 is in the static hex.',
    },
  });
}

void exportPP1Rnft() {
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  var rabinPubKeyHash = List.filled(20, 0xCC);
  var flags = 0xDDDDDDDD;

  // Without companion
  var script = PP1RnftScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    rabinPubKeyHash: rabinPubKeyHash,
    flags: flags,
  );

  var fullHex = hex.encode(script.buffer!);

  // Flags is encoded as 4-byte LE. Only low byte of each field in generate() is used,
  // so the actual encoded value at flagsDataStart is [0xDD, 0x00, 0x00, 0x00].
  // We use templatizeHex for uniform-byte sentinels and manual replacement for the rest.
  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1RnftScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1RnftScriptGen.tokenIdDataStart, 32, 0xBB),
    'rabinPubKeyHash': _SentinelRegion(PP1RnftScriptGen.rabinPKHDataStart, 20, 0xCC),
  });

  // Replace flags: extract the encoded hex from the original, then use surrounding
  // context (pushdata prefix 0x04 before, script body after) for unique match.
  var flagsEncodedHex = fullHex.substring(
      PP1RnftScriptGen.flagsDataStart * 2, PP1RnftScriptGen.flagsDataEnd * 2);
  // Context: "04" prefix + flagsHex + next opcode from script body
  var flagsWithPrefix = '04$flagsEncodedHex';
  var flagsIdx = templateHex.indexOf(flagsWithPrefix);
  if (flagsIdx == -1) throw Exception('Could not find flags sentinel in template');
  templateHex = templateHex.substring(0, flagsIdx + 2) + // keep "04"
      '{{flags}}' +
      templateHex.substring(flagsIdx + flagsWithPrefix.length);

  writeTemplate('templates/nft/pp1_rnft.json', {
    'name': 'PP1_RNFT',
    'version': version,
    'description': 'Restricted NFT locking script. Extends PP1_NFT with 4-byte flags for transfer/burn/companion restrictions.',
    'category': 'nft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid)',
      },
      {
        'name': 'rabinPubKeyHash',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte hash160 of the Rabin public key for identity anchoring',
      },
      {
        'name': 'flags',
        'size': 4,
        'encoding': 'le_uint32',
        'description': '4-byte little-endian flags bitfield controlling transfer/burn/companion restrictions',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1RnftScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_rnft_script_gen.dart',
      'note': 'Pushdata prefixes are part of the static hex. This is the no-companion variant. With-companion variant has an additional 32-byte companionTokenId field.',
    },
  });
}

void exportPP1Rft() {
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  var rabinPubKeyHash = List.filled(20, 0xCC);
  var flags = 0xDDDDDDDD;
  var amount = 0x0EEEEEEEEEEEEEEE; // bit 63 clear

  var script = PP1RftScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    rabinPubKeyHash: rabinPubKeyHash,
    flags: flags,
    amount: amount,
  );

  var fullHex = hex.encode(script.buffer!);

  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1RftScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1RftScriptGen.tokenIdDataStart, 32, 0xBB),
    'rabinPubKeyHash': _SentinelRegion(PP1RftScriptGen.rabinPKHDataStart, 20, 0xCC),
  });

  // Replace flags: pushdata prefix 0x04 + 4 bytes
  var flagsEncodedHex = fullHex.substring(
      PP1RftScriptGen.flagsDataStart * 2, PP1RftScriptGen.flagsDataEnd * 2);
  var flagsWithPrefix = '04$flagsEncodedHex';
  var flagsIdx = templateHex.indexOf(flagsWithPrefix);
  if (flagsIdx == -1) throw Exception('Could not find flags sentinel');
  templateHex = templateHex.substring(0, flagsIdx + 2) +
      '{{flags}}' +
      templateHex.substring(flagsIdx + flagsWithPrefix.length);

  // Replace amount: pushdata prefix 0x08 + 8 bytes
  var amountEncodedHex = fullHex.substring(
      PP1RftScriptGen.amountDataStart * 2, PP1RftScriptGen.amountDataEnd * 2);
  var amountWithPrefix = '08$amountEncodedHex';
  var amountIdx = templateHex.indexOf(amountWithPrefix);
  if (amountIdx == -1) throw Exception('Could not find amount sentinel');
  templateHex = templateHex.substring(0, amountIdx + 2) +
      '{{amount}}' +
      templateHex.substring(amountIdx + amountWithPrefix.length);

  writeTemplate('templates/ft/pp1_rft.json', {
    'name': 'PP1_RFT',
    'version': version,
    'description': 'Restricted fungible token locking script. Extends PP1_FT with 4-byte flags for transfer/burn restrictions.',
    'category': 'ft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid)',
      },
      {
        'name': 'rabinPubKeyHash',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte hash160 of the Rabin public key for identity anchoring',
      },
      {
        'name': 'flags',
        'size': 4,
        'encoding': 'le_uint32',
        'description': '4-byte little-endian flags bitfield controlling transfer/burn restrictions',
      },
      {
        'name': 'amount',
        'size': 8,
        'encoding': 'le_uint56',
        'description': '8-byte little-endian amount (7 bytes value + high byte with bit 7 clear). Max value: 2^55 - 1.',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1RftScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_rft_script_gen.dart',
      'note': 'Pushdata prefixes are part of the static hex. Flags encoding: 4 bytes LE. Amount encoding: 8 bytes LE with bit 63 clear.',
    },
  });
}

void exportPP1At() {
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  var issuerPKH = List.filled(20, 0xCC);
  var stampCount = 0xDDDDDDDD;
  var threshold = 0xEEEEEEEE;
  var stampsHash = List.filled(32, 0xFF);

  var script = PP1AtScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    issuerPKH: issuerPKH,
    stampCount: stampCount,
    threshold: threshold,
    stampsHash: stampsHash,
  );

  var fullHex = hex.encode(script.buffer!);

  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1AtScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1AtScriptGen.tokenIdDataStart, 32, 0xBB),
    'issuerPKH': _SentinelRegion(PP1AtScriptGen.issuerPKHDataStart, 20, 0xCC),
    'stampsHash': _SentinelRegion(PP1AtScriptGen.stampsHashDataStart, 32, 0xFF),
  });

  // Replace stampCount: pushdata prefix 0x04 + 4 bytes
  var stampCountHex = fullHex.substring(
      PP1AtScriptGen.stampCountDataStart * 2, PP1AtScriptGen.stampCountDataEnd * 2);
  var scWithPrefix = '04$stampCountHex';
  var scIdx = templateHex.indexOf(scWithPrefix);
  if (scIdx == -1) throw Exception('Could not find stampCount sentinel');
  templateHex = templateHex.substring(0, scIdx + 2) +
      '{{stampCount}}' +
      templateHex.substring(scIdx + scWithPrefix.length);

  // Replace threshold: pushdata prefix 0x04 + 4 bytes
  var thresholdHex = fullHex.substring(
      PP1AtScriptGen.thresholdDataStart * 2, PP1AtScriptGen.thresholdDataEnd * 2);
  var thWithPrefix = '04$thresholdHex';
  var thIdx = templateHex.indexOf(thWithPrefix);
  if (thIdx == -1) throw Exception('Could not find threshold sentinel');
  templateHex = templateHex.substring(0, thIdx + 2) +
      '{{threshold}}' +
      templateHex.substring(thIdx + thWithPrefix.length);

  writeTemplate('templates/nft/pp1_at.json', {
    'name': 'PP1_AT',
    'version': version,
    'description': 'Appendable token (loyalty/stamp card) locking script. Tracks stamp count, threshold, and rolling stamps hash.',
    'category': 'nft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid)',
      },
      {
        'name': 'issuerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the stamp issuer',
      },
      {
        'name': 'stampCount',
        'size': 4,
        'encoding': 'le_uint32',
        'description': '4-byte little-endian stamp count (mutable, incremented on each stamp)',
      },
      {
        'name': 'threshold',
        'size': 4,
        'encoding': 'le_uint32',
        'description': '4-byte little-endian threshold (immutable, stamps needed for redemption)',
      },
      {
        'name': 'stampsHash',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte rolling SHA256 hash of all stamp data (mutable)',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1AtScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_at_script_gen.dart',
      'note': 'Pushdata prefixes are part of the static hex. stampCount/threshold are 4-byte LE. stampsHash is raw 32 bytes.',
    },
  });
}

void exportPP1Sm() {
  var ownerPKH = List.filled(20, 0xAA);
  var tokenId = List.filled(32, 0xBB);
  var merchantPKH = List.filled(20, 0xCC);
  var customerPKH = List.filled(20, 0xDD);
  var currentState = 0x11;
  var milestoneCount = 0x22;
  var commitmentHash = List.filled(32, 0xEE);
  var transitionBitmask = 0x33;
  var timeoutDelta = 0x44444444;

  var script = PP1SmScriptGen.generate(
    ownerPKH: ownerPKH,
    tokenId: tokenId,
    merchantPKH: merchantPKH,
    customerPKH: customerPKH,
    currentState: currentState,
    milestoneCount: milestoneCount,
    commitmentHash: commitmentHash,
    transitionBitmask: transitionBitmask,
    timeoutDelta: timeoutDelta,
  );

  var fullHex = hex.encode(script.buffer!);

  // Replace multi-byte sentinel regions first
  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(PP1SmScriptGen.pkhDataStart, 20, 0xAA),
    'tokenId': _SentinelRegion(PP1SmScriptGen.tokenIdDataStart, 32, 0xBB),
    'merchantPKH': _SentinelRegion(PP1SmScriptGen.merchantPKHDataStart, 20, 0xCC),
    'customerPKH': _SentinelRegion(PP1SmScriptGen.customerPKHDataStart, 20, 0xDD),
    'commitmentHash': _SentinelRegion(PP1SmScriptGen.commitmentHashDataStart, 32, 0xEE),
  });

  // Replace 1-byte and 4-byte fields using context from adjacent placeholders.
  // The header layout after multi-byte templatization:
  //   ...{{customerPKH}} 01 <currentState> 01 <milestoneCount> 20 {{commitmentHash}} 01 <bitmask> 04 <timeoutDelta> ...

  // currentState (1 byte, sentinel 0x11): after {{customerPKH}}, prefix 0x01
  var stateHex = fullHex.substring(PP1SmScriptGen.currentStateDataStart * 2,
      PP1SmScriptGen.currentStateDataEnd * 2);
  templateHex = templateHex.replaceFirst(
      '{{customerPKH}}01$stateHex',
      '{{customerPKH}}01{{currentState}}');

  // milestoneCount (1 byte, sentinel 0x22): after {{currentState}}, prefix 0x01
  var mcHex = fullHex.substring(PP1SmScriptGen.milestoneCountDataStart * 2,
      PP1SmScriptGen.milestoneCountDataEnd * 2);
  templateHex = templateHex.replaceFirst(
      '{{currentState}}01${mcHex}20',
      '{{currentState}}01{{milestoneCount}}20');

  // transitionBitmask (1 byte, sentinel 0x33): after {{commitmentHash}}, prefix 0x01
  var bmHex = fullHex.substring(PP1SmScriptGen.transitionBitmaskDataStart * 2,
      PP1SmScriptGen.transitionBitmaskDataEnd * 2);
  templateHex = templateHex.replaceFirst(
      '{{commitmentHash}}01$bmHex',
      '{{commitmentHash}}01{{transitionBitmask}}');

  // timeoutDelta (4 bytes, sentinel 0x44444444): after {{transitionBitmask}}, prefix 0x04
  var tdHex = fullHex.substring(PP1SmScriptGen.timeoutDeltaDataStart * 2,
      PP1SmScriptGen.timeoutDeltaDataEnd * 2);
  templateHex = templateHex.replaceFirst(
      '{{transitionBitmask}}04$tdHex',
      '{{transitionBitmask}}04{{timeoutDelta}}');

  writeTemplate('templates/sm/pp1_sm.json', {
    'name': 'PP1_SM',
    'version': version,
    'description': 'State machine token locking script. Supports 7 operations: create, enroll, confirm, convert, settle, timeout, burn. 140-byte header with 9 fields.',
    'category': 'sm',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the current owner/next expected actor (mutable)',
      },
      {
        'name': 'tokenId',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte unique token identifier (genesis txid, immutable)',
      },
      {
        'name': 'merchantPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the merchant (immutable)',
      },
      {
        'name': 'customerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the customer (immutable)',
      },
      {
        'name': 'currentState',
        'size': 1,
        'encoding': 'hex_byte',
        'description': '1-byte state value: 0x00=created, 0x01=enrolled, 0x02=progressing, 0x03=converting, 0x04=settled, 0x05=expired (mutable)',
      },
      {
        'name': 'milestoneCount',
        'size': 1,
        'encoding': 'hex_byte',
        'description': '1-byte milestone counter (mutable, incremented on confirm)',
      },
      {
        'name': 'commitmentHash',
        'size': 32,
        'encoding': 'hex',
        'description': '32-byte rolling SHA256 commitment hash (mutable)',
      },
      {
        'name': 'transitionBitmask',
        'size': 1,
        'encoding': 'hex_byte',
        'description': '1-byte bitmask enabling/disabling state transitions (immutable). Bit 0=enroll, 1/2=confirm, 3=convert, 4=settle, 5=timeout.',
      },
      {
        'name': 'timeoutDelta',
        'size': 4,
        'encoding': 'le_uint32',
        'description': '4-byte little-endian timeout delta in blocks/seconds for nLockTime (immutable)',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'PP1SmScriptGen',
      'sourceFile': 'lib/src/script_gen/pp1_sm_script_gen.dart',
      'note': 'Pushdata prefixes (0x14, 0x20, 0x01, 0x04) are part of the static hex. 1-byte fields use hex_byte encoding (2 hex chars, no prefix). 4-byte fields use le_uint32 encoding.',
    },
  });
}

void exportPP3Nft() {
  var ownerPKH = List.filled(20, 0xAA);

  var script = WitnessCheckScriptGen.generate(
    ownerPKH: ownerPKH,
    pp2OutputIndex: 2, // NFT default
  );

  var fullHex = hex.encode(script.buffer!);

  // ownerPKH is at bytes 1-21 (after 0x14 pushdata prefix)
  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(1, 20, 0xAA),
  });

  writeTemplate('templates/nft/pp3_witness.json', {
    'name': 'PP3_Witness_NFT',
    'version': version,
    'description': 'Partial SHA256 witness check locking script for NFT tokens. Validates witness transaction via partial SHA256 completion.',
    'category': 'nft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner (used for burn path)',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'WitnessCheckScriptGen',
      'sourceFile': 'lib/src/script_gen/witness_check_script_gen.dart',
      'pp2OutputIndex': 2,
      'note': 'pp2OutputIndex=2 is baked into the script body (NFT standard position). Use pp3_ft_witness.json for fungible tokens.',
    },
  });
}

void exportPP3Ft() {
  var ownerPKH = List.filled(20, 0xAA);

  var script = WitnessCheckScriptGen.generate(
    ownerPKH: ownerPKH,
    pp2OutputIndex: 3, // FT default
  );

  var fullHex = hex.encode(script.buffer!);

  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(1, 20, 0xAA),
  });

  writeTemplate('templates/ft/pp3_ft_witness.json', {
    'name': 'PP3_Witness_FT',
    'version': version,
    'description': 'Partial SHA256 witness check locking script for fungible tokens. Validates witness transaction via partial SHA256 completion.',
    'category': 'ft',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the token owner (used for burn path)',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'generatedBy': 'WitnessCheckScriptGen',
      'sourceFile': 'lib/src/script_gen/witness_check_script_gen.dart',
      'pp2OutputIndex': 3,
      'note': 'pp2OutputIndex=3 is baked into the script body (FT standard position). Use pp3_witness.json for NFTs.',
    },
  });
}

void exportModP2PKH() {
  // ModP2PKH is: OP_SWAP OP_DUP OP_HASH160 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
  // Hex: 7c 76 a9 14 <20 bytes> 88 ac
  var ownerPKH = List.filled(20, 0xAA);
  var builder = ScriptBuilder()
      .opCode(OpCodes.OP_SWAP)
      .opCode(OpCodes.OP_DUP)
      .opCode(OpCodes.OP_HASH160)
      .addData(Uint8List.fromList(ownerPKH))
      .opCode(OpCodes.OP_EQUALVERIFY)
      .opCode(OpCodes.OP_CHECKSIG);

  var fullHex = hex.encode(builder.build().buffer!);

  // PKH is at offset 4 (after 7c 76 a9 14)
  var templateHex = templatizeHex(fullHex, {
    'ownerPKH': _SentinelRegion(4, 20, 0xAA),
  });

  writeTemplate('templates/utility/mod_p2pkh.json', {
    'name': 'ModP2PKH',
    'version': version,
    'description': 'Modified P2PKH locking script using OP_SWAP OP_DUP OP_HASH160. Used as the token value output (index 0).',
    'category': 'utility',
    'parameters': [
      {
        'name': 'ownerPKH',
        'size': 20,
        'encoding': 'hex',
        'description': '20-byte pubkey hash of the owner',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'sourceFile': 'lib/src/builder/mod_p2pkh_builder.dart',
      'note': 'Pushdata prefix 0x14 is part of the static hex.',
    },
  });
}

// ==========================================================================
// Category B: Already template-based scripts
// ==========================================================================

void exportPP2() {
  // PP2 release template from pp2_lock_builder.dart line 47
  var rawTemplate = "0176017c018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000<outpoint><witnessChangePKH><witnessChangeAmount><ownerPKH>5379587a75577a577a577a577a577a577a577a5279577a75567a567a567a567a567a567a78567a757171557a76557a75547a547a547a547a6d6d5e790087630402000000607951546e8b80767682778c7f75007f777777777e01117952546e8b80767682778c7f75007f777777777e01127952546e8b80767682778c7f75007f777777777e577953797e52797e76a8a84c4e76011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a978885f79011179ac77777777777777777777777777777777776700686805ffffffff00546e8b80767682778c7f75007f7777777776767e787ea8a800011279011279855d79011879011a797e0117797e01147e787e0118797e0116797e775d79588078768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5279817654805e795a797e57797e5c797e5979768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5158807e58797e5379a8a87e567954807e787e76a8a876517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8176011979210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810011a79011f79011f7985537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e777777777777777777777777ab76011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a978885f79011179ac777777777777777777777777777777777767006868";

  var templateHex = rawTemplate
      .replaceAll('<outpoint>', '{{outpoint}}')
      .replaceAll('<witnessChangePKH>', '{{witnessChangePKH}}')
      .replaceAll('<witnessChangeAmount>', '{{witnessChangeAmount}}')
      .replaceAll('<ownerPKH>', '{{ownerPKH}}');

  writeTemplate('templates/nft/pp2.json', {
    'name': 'PP2',
    'version': version,
    'description': 'NFT witness bridge locking script. Connects the partial SHA256 witness output to the inductive proof in PP1.',
    'category': 'nft',
    'parameters': [
      {
        'name': 'outpoint',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '36-byte funding outpoint (32B txid + 4B index), encoded with ScriptBuilder.addData() (pushdata prefix + raw bytes)',
      },
      {
        'name': 'witnessChangePKH',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '20-byte witness change pubkey hash, encoded with ScriptBuilder.addData()',
      },
      {
        'name': 'witnessChangeAmount',
        'size': null,
        'encoding': 'script_number',
        'description': 'Satoshi amount for witness change output, encoded with ScriptBuilder.number()',
      },
      {
        'name': 'ownerPKH',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '20-byte owner pubkey hash, encoded with ScriptBuilder.addData()',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'sourceFile': 'lib/src/builder/pp2_lock_builder.dart',
      'note': 'Parameters include their pushdata/scriptnum encoding (length prefix + data). Use ScriptBuilder.addData() for bytes and ScriptBuilder.number() for integers. See encoding/scriptnum.md for details.',
    },
  });
}

void exportPP2FT() {
  // PP2-FT release template from pp2_ft_lock_builder.dart line 28
  var rawTemplate = "0176017c018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c000000000000<outpoint><witnessChangePKH><witnessChangeAmount><ownerPKH><pp1FtOutputIndex><pp2OutputIndex>55795c7a755b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a54795b7a755a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a53795a7a75597a597a597a597a597a597a597a597a597a5279597a75587a587a587a587a587a587a587a587a78587a75577a577a577a577a577a577a577a76577a75567a567a567a567a567a567a6d6d6d607900876304020000000112795379546e8b80767682778c7f75007f777777777e0113795379546e8b80767682778c7f75007f777777777e0114795479546e8b80767682778c7f75007f777777777e597953797e52797e76a8a8010005ffffffff00546e8b80767682778c7f75007f7777777776767e787ea8a800011479011479855f79011a79011c797e0119797e01147e787e011a797e0118797e775f79588078768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5279817654805e795a797e57797e5c797e5979768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5158807e58797e5379a8a87e567954807e787e76a8a876517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8176011b79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810011c7901217901217985537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e777777777777777777777777ab76011b79ac77777777777777777777777777777777777777777777777777777777777777777777777777676079518763011279a9537988011179011379ac7777777777777777777777777777777777777767006868";

  var templateHex = rawTemplate
      .replaceAll('<outpoint>', '{{outpoint}}')
      .replaceAll('<witnessChangePKH>', '{{witnessChangePKH}}')
      .replaceAll('<witnessChangeAmount>', '{{witnessChangeAmount}}')
      .replaceAll('<ownerPKH>', '{{ownerPKH}}')
      .replaceAll('<pp1FtOutputIndex>', '{{pp1FtOutputIndex}}')
      .replaceAll('<pp2OutputIndex>', '{{pp2OutputIndex}}');

  writeTemplate('templates/ft/pp2_ft.json', {
    'name': 'PP2_FT',
    'version': version,
    'description': 'Fungible token witness bridge locking script. Extends PP2 with output index parameters for PP1_FT and PP2-FT outputs.',
    'category': 'ft',
    'parameters': [
      {
        'name': 'outpoint',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '36-byte funding outpoint (32B txid + 4B index), encoded with ScriptBuilder.addData()',
      },
      {
        'name': 'witnessChangePKH',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '20-byte witness change pubkey hash, encoded with ScriptBuilder.addData()',
      },
      {
        'name': 'witnessChangeAmount',
        'size': null,
        'encoding': 'script_number',
        'description': 'Satoshi amount for witness change output, encoded with ScriptBuilder.number()',
      },
      {
        'name': 'ownerPKH',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '20-byte owner pubkey hash, encoded with ScriptBuilder.addData()',
      },
      {
        'name': 'pp1FtOutputIndex',
        'size': null,
        'encoding': 'script_number',
        'description': 'Output index of the PP1_FT fungible token output, encoded with ScriptBuilder.number()',
      },
      {
        'name': 'pp2OutputIndex',
        'size': null,
        'encoding': 'script_number',
        'description': 'Output index of the PP2-FT output, encoded with ScriptBuilder.number()',
      },
    ],
    'hex': templateHex,
    'metadata': {
      'sourceFile': 'lib/src/builder/pp2_ft_lock_builder.dart',
      'note': 'Parameters include their pushdata/scriptnum encoding. See encoding/scriptnum.md for details.',
    },
  });
}

void exportHODL() {
  // The HODL template is in ASM format. We need to also provide the ASM version
  // and convert to hex with placeholder substitution.
  var asmTemplate = "97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026 02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382 1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c 0 0 <ownerPubkeyHash> <lockHeight> OP_NOP 0 OP_PICK 0065cd1d OP_LESSTHAN OP_VERIFY 0 OP_PICK OP_4 OP_ROLL OP_DROP OP_3 OP_ROLL OP_3 OP_ROLL OP_3 OP_ROLL OP_1 OP_PICK OP_3 OP_ROLL OP_DROP OP_2 OP_ROLL OP_2 OP_ROLL OP_DROP OP_DROP OP_NOP OP_5 OP_PICK 41 OP_NOP OP_1 OP_PICK OP_7 OP_PICK OP_7 OP_PICK 0ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800 6c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810 OP_9 OP_PICK OP_6 OP_PICK OP_NOP OP_6 OP_PICK OP_HASH256 0 OP_PICK OP_NOP 0 OP_PICK OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_7 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_6 OP_PICK OP_NOP OP_3 OP_PICK OP_6 OP_PICK OP_4 OP_PICK OP_7 OP_PICK OP_MUL OP_ADD OP_MUL 414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00 OP_1 OP_PICK OP_1 OP_PICK OP_NOP OP_1 OP_PICK OP_1 OP_PICK OP_MOD 0 OP_PICK 0 OP_LESSTHAN OP_IF 0 OP_PICK OP_2 OP_PICK OP_ADD OP_ELSE 0 OP_PICK OP_ENDIF OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_2 OP_ROLL OP_DROP OP_1 OP_ROLL OP_1 OP_PICK OP_1 OP_PICK OP_2 OP_DIV OP_GREATERTHAN OP_IF 0 OP_PICK OP_2 OP_PICK OP_SUB OP_2 OP_ROLL OP_DROP OP_1 OP_ROLL OP_ENDIF OP_3 OP_PICK OP_SIZE OP_NIP OP_2 OP_PICK OP_SIZE OP_NIP OP_3 OP_PICK 20 OP_NUM2BIN OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_1 OP_SPLIT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT 20 OP_2 OP_PICK OP_SUB OP_SPLIT OP_NIP OP_4 OP_3 OP_PICK OP_ADD OP_2 OP_PICK OP_ADD 30 OP_1 OP_PICK OP_CAT OP_2 OP_CAT OP_4 OP_PICK OP_CAT OP_8 OP_PICK OP_CAT OP_2 OP_CAT OP_3 OP_PICK OP_CAT OP_2 OP_PICK OP_CAT OP_7 OP_PICK OP_CAT 0 OP_PICK OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP 0 OP_PICK OP_7 OP_PICK OP_CHECKSIG OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK OP_4 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK OP_8 OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP 0065cd1d OP_LESSTHAN OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK 28 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK 2c OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP ffffffff00 OP_LESSTHAN OP_VERIFY OP_5 OP_PICK OP_NOP 0 OP_PICK OP_NOP 0 OP_PICK OP_SIZE OP_NIP OP_1 OP_PICK OP_1 OP_PICK OP_4 OP_SUB OP_SPLIT OP_DROP OP_1 OP_PICK OP_8 OP_SUB OP_SPLIT OP_NIP OP_1 OP_ROLL OP_DROP OP_1 OP_ROLL OP_DROP OP_NOP OP_NOP 0 OP_PICK 00 OP_CAT OP_BIN2NUM OP_1 OP_ROLL OP_DROP OP_NOP OP_1 OP_ROLL OP_DROP OP_NOP OP_2 OP_PICK OP_GREATERTHANOREQUAL OP_VERIFY OP_6 OP_PICK OP_HASH160 OP_1 OP_PICK OP_EQUAL OP_VERIFY OP_7 OP_PICK OP_7 OP_PICK OP_CHECKSIG OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP";

  var templateAsm = asmTemplate
      .replaceAll('<ownerPubkeyHash>', '{{ownerPubkeyHash}}')
      .replaceAll('<lockHeight>', '{{lockHeight}}');

  writeTemplate('templates/utility/hodl.json', {
    'name': 'HODL',
    'version': version,
    'description': 'Time-lock script that prevents spending until a specified block height.',
    'category': 'utility',
    'format': 'asm',
    'parameters': [
      {
        'name': 'ownerPubkeyHash',
        'size': null,
        'encoding': 'script_pushdata',
        'description': '20-byte owner pubkey hash, encoded with ScriptBuilder.addData() then converted to ASM',
      },
      {
        'name': 'lockHeight',
        'size': null,
        'encoding': 'script_number',
        'description': 'Block height at which funds become spendable, encoded with ScriptBuilder.number() then converted to ASM',
      },
    ],
    'asm': templateAsm,
    'metadata': {
      'sourceFile': 'lib/src/builder/hodl_lockbuilder.dart',
      'note': 'This template is in ASM format. Parse with SVScript.fromASM() or equivalent. Parameters must be ASM-encoded (e.g., "14aabbcc..." for pushdata, "03e80300" for script number).',
    },
  });
}
