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

/// Exports cross-language test vectors for TSL1 lock/unlock builders.
///
/// Each vector captures the inputs and the resulting script hex, enabling
/// Java (monocelo) and TypeScript implementations to verify byte-identical
/// output against the canonical Dart implementation.
///
/// Run with: dart run tool/export_test_vectors.dart

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/builder/pp1_nft_lock_builder.dart';
import 'package:tstokenlib/src/builder/pp1_ft_lock_builder.dart';
import 'package:tstokenlib/src/builder/pp2_lock_builder.dart';
import 'package:tstokenlib/src/builder/pp2_ft_lock_builder.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';
import 'package:tstokenlib/src/builder/pp1_nft_unlock_builder.dart';
import 'package:tstokenlib/src/builder/pp1_ft_unlock_builder.dart';
import 'package:tstokenlib/src/builder/pp2_unlock_builder.dart';
import 'package:tstokenlib/src/builder/pp2_ft_unlock_builder.dart';

// ─── Test Key Material ─────────────────────────────────────────────
// Bob's testnet key (from existing tests)
const bobWif = 'cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS';
const bobPubkeyHash = '650c4adb156f19e36a755c820d892cda108299c4';

// Alice's testnet key
const aliceWif = 'cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5';
const alicePubkeyHash = 'f5d33ee198ad13840ce410ba96e149e463a6c352';

void main() {
  print('Generating cross-language test vectors...');

  var bobKey = SVPrivateKey.fromWIF(bobWif);
  var bobPubKey = bobKey.publicKey;
  var bobAddress = bobPubKey.toAddress(NetworkType.TEST);

  // Create a deterministic signature by signing a known hash
  var knownHashHex = hex.encode(List<int>.generate(32, (i) => i + 1)); // 0x01..0x20
  var svSig = SVSignature.fromPrivateKey(bobKey);
  svSig.nhashtype = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
  svSig.sign(knownHashHex);

  // Capture signature tx format hex for the vectors
  var sigTxFormatHex = svSig.toTxFormat();

  // ─── Synthetic test data ──────────────────────────────────────
  var tokenId = List<int>.generate(32, (i) => i + 0x10);
  var rabinPubKeyHash = List<int>.generate(20, (i) => i + 0x20);
  var outpoint = List<int>.generate(36, (i) => i + 0x40);
  var witnessChangePKH = hex.decode(bobPubkeyHash);
  var preImage = List<int>.generate(64, (i) => i + 0x01);
  var witnessFundingTxId = List<int>.generate(32, (i) => i + 0x80);
  var witnessPadding = List<int>.generate(16, (i) => i + 0xA0);
  var pp2Output = List<int>.generate(48, (i) => i + 0xB0);
  var tokenLHS = List<int>.generate(32, (i) => i + 0xC0);
  var prevTokenTx = List<int>.generate(100, (i) => (i + 0xD0) & 0xFF);
  var prevTokenTxB = List<int>.generate(100, (i) => (i + 0xE0) & 0xFF);
  var recipientPKH = hex.decode(alicePubkeyHash);
  var pp2ChangeOutput = List<int>.generate(48, (i) => (i + 0xF0) & 0xFF);

  // Rabin data (synthetic)
  var rabinN = List<int>.generate(128, (i) => i + 0x01);
  var rabinS = List<int>.generate(128, (i) => i + 0x02);
  var identityTxId = List<int>.generate(32, (i) => i + 0x03);
  var ed25519PubKey = List<int>.generate(32, (i) => i + 0x04);

  var vectors = <Map<String, dynamic>>[];

  // ═══════════════════════════════════════════════════════════════
  // LOCK BUILDER VECTORS
  // ═══════════════════════════════════════════════════════════════

  // 1. ModP2PKH
  {
    var builder = ModP2PKHLockBuilder.fromAddress(bobAddress);
    var script = builder.getScriptPubkey();
    vectors.add({
      'name': 'MOD_P2PKH_LOCK',
      'type': 'lock',
      'builder': 'ModP2PKHLockBuilder',
      'inputs': {
        'ownerPKH': bobPubkeyHash,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 2. PP1_NFT Lock
  {
    var builder = PP1NftLockBuilder(bobAddress, tokenId, rabinPubKeyHash);
    var script = builder.getScriptPubkey();
    vectors.add({
      'name': 'PP1_NFT_LOCK',
      'type': 'lock',
      'builder': 'PP1NftLockBuilder',
      'inputs': {
        'ownerPKH': bobPubkeyHash,
        'tokenId': hex.encode(tokenId),
        'rabinPubKeyHash': hex.encode(rabinPubKeyHash),
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 3. PP1_FT Lock
  {
    var amount = 50000;
    var builder = PP1FtLockBuilder(hex.decode(bobPubkeyHash), tokenId, rabinPubKeyHash, amount);
    var script = builder.getScriptPubkey();
    vectors.add({
      'name': 'PP1_FT_LOCK',
      'type': 'lock',
      'builder': 'PP1FtLockBuilder',
      'inputs': {
        'ownerPKH': bobPubkeyHash,
        'tokenId': hex.encode(tokenId),
        'rabinPubKeyHash': hex.encode(rabinPubKeyHash),
        'amount': amount,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 4. PP2 Lock
  {
    var builder = PP2LockBuilder(outpoint, witnessChangePKH, 1000, witnessChangePKH);
    var script = builder.getScriptPubkey();
    vectors.add({
      'name': 'PP2_LOCK',
      'type': 'lock',
      'builder': 'PP2LockBuilder',
      'inputs': {
        'outpoint': hex.encode(outpoint),
        'witnessChangePKH': bobPubkeyHash,
        'witnessChangeAmount': 1000,
        'ownerPKH': bobPubkeyHash,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 5. PP2_FT Lock
  {
    var builder = PP2FtLockBuilder(outpoint, witnessChangePKH, 1000, witnessChangePKH, 1, 2);
    var script = builder.getScriptPubkey();
    vectors.add({
      'name': 'PP2_FT_LOCK',
      'type': 'lock',
      'builder': 'PP2FtLockBuilder',
      'inputs': {
        'outpoint': hex.encode(outpoint),
        'witnessChangePKH': bobPubkeyHash,
        'witnessChangeAmount': 1000,
        'ownerPKH': bobPubkeyHash,
        'pp1FtOutputIndex': 1,
        'pp2OutputIndex': 2,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // UNLOCK BUILDER VECTORS
  // ═══════════════════════════════════════════════════════════════

  // 6. ModP2PKH Unlock
  {
    var builder = ModP2PKHUnlockBuilder(bobPubKey);
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'MOD_P2PKH_UNLOCK',
      'type': 'unlock',
      'builder': 'ModP2PKHUnlockBuilder',
      'inputs': {
        'signerPubKeyHex': bobPubKey.toHex(),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 7. PP2 Unlock — Normal
  {
    var outpointTxId = List<int>.generate(32, (i) => i + 0x10);
    var builder = PP2UnlockBuilder(outpointTxId);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP2_UNLOCK_NORMAL',
      'type': 'unlock',
      'builder': 'PP2UnlockBuilder',
      'action': 'NORMAL',
      'inputs': {
        'outpointTxId': hex.encode(outpointTxId),
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 8. PP2 Unlock — Burn
  {
    var builder = PP2UnlockBuilder.forBurn(bobPubKey);
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP2_UNLOCK_BURN',
      'type': 'unlock',
      'builder': 'PP2UnlockBuilder',
      'action': 'BURN',
      'inputs': {
        'ownerPubKeyHex': bobPubKey.toHex(),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 9. PP2_FT Unlock — Normal
  {
    var outpointTxId = List<int>.generate(32, (i) => i + 0x10);
    var builder = PP2FtUnlockBuilder(outpointTxId);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP2_FT_UNLOCK_NORMAL',
      'type': 'unlock',
      'builder': 'PP2FtUnlockBuilder',
      'action': 'NORMAL',
      'inputs': {
        'outpointTxId': hex.encode(outpointTxId),
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 10. PP2_FT Unlock — Burn
  {
    var builder = PP2FtUnlockBuilder.forBurn(bobPubKey);
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP2_FT_UNLOCK_BURN',
      'type': 'unlock',
      'builder': 'PP2FtUnlockBuilder',
      'action': 'BURN',
      'inputs': {
        'ownerPubKeyHex': bobPubKey.toHex(),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 11. PP1_NFT Unlock — Issuance
  {
    var builder = PP1NftUnlockBuilder(
      preImage, pp2Output, bobPubKey,
      bobPubkeyHash, BigInt.from(1000),
      tokenLHS, prevTokenTx, witnessPadding,
      TokenAction.ISSUANCE, witnessFundingTxId,
      rabinN: rabinN, rabinS: rabinS, rabinPadding: 0,
      identityTxId: identityTxId, ed25519PubKey: ed25519PubKey,
    );
    builder.signatures.add(svSig); // Required by guard even though not pushed
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_NFT_UNLOCK_ISSUANCE',
      'type': 'unlock',
      'builder': 'PP1NftUnlockBuilder',
      'action': 'ISSUANCE',
      'inputs': {
        'preImage': hex.encode(preImage),
        'witnessFundingTxId': hex.encode(witnessFundingTxId),
        'witnessPadding': hex.encode(witnessPadding),
        'rabinN': hex.encode(rabinN),
        'rabinS': hex.encode(rabinS),
        'rabinPadding': 0,
        'identityTxId': hex.encode(identityTxId),
        'ed25519PubKey': hex.encode(ed25519PubKey),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 12. PP1_NFT Unlock — Transfer
  {
    var builder = PP1NftUnlockBuilder(
      preImage, pp2Output, bobPubKey,
      bobPubkeyHash, BigInt.from(1000),
      tokenLHS, prevTokenTx, witnessPadding,
      TokenAction.TRANSFER, witnessFundingTxId,
    );
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_NFT_UNLOCK_TRANSFER',
      'type': 'unlock',
      'builder': 'PP1NftUnlockBuilder',
      'action': 'TRANSFER',
      'inputs': {
        'preImage': hex.encode(preImage),
        'pp2Output': hex.encode(pp2Output),
        'ownerPubKeyHex': bobPubKey.toHex(),
        'changePKH': bobPubkeyHash,
        'changeAmount': 1000,
        'tokenLHS': hex.encode(tokenLHS),
        'prevTokenTx': hex.encode(prevTokenTx),
        'witnessPadding': hex.encode(witnessPadding),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 13. PP1_NFT Unlock — Burn
  {
    var builder = PP1NftUnlockBuilder.forBurn(bobPubKey);
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_NFT_UNLOCK_BURN',
      'type': 'unlock',
      'builder': 'PP1NftUnlockBuilder',
      'action': 'BURN',
      'inputs': {
        'ownerPubKeyHex': bobPubKey.toHex(),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 14. PP1_FT Unlock — Mint
  {
    var builder = PP1FtUnlockBuilder.forMint(preImage, witnessFundingTxId, witnessPadding,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: 0,
        identityTxId: identityTxId, ed25519PubKey: ed25519PubKey);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_FT_UNLOCK_MINT',
      'type': 'unlock',
      'builder': 'PP1FtUnlockBuilder',
      'action': 'MINT',
      'inputs': {
        'preImage': hex.encode(preImage),
        'witnessFundingTxId': hex.encode(witnessFundingTxId),
        'witnessPadding': hex.encode(witnessPadding),
        'rabinN': hex.encode(rabinN),
        'rabinS': hex.encode(rabinS),
        'rabinPadding': 0,
        'identityTxId': hex.encode(identityTxId),
        'ed25519PubKey': hex.encode(ed25519PubKey),
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 15. PP1_FT Unlock — Transfer
  {
    var builder = PP1FtUnlockBuilder.forTransfer(
      preImage, pp2Output, bobPubKey,
      bobPubkeyHash, BigInt.from(1000),
      tokenLHS, prevTokenTx, witnessPadding,
      5, 1,
    );
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_FT_UNLOCK_TRANSFER',
      'type': 'unlock',
      'builder': 'PP1FtUnlockBuilder',
      'action': 'TRANSFER',
      'inputs': {
        'preImage': hex.encode(preImage),
        'pp2Output': hex.encode(pp2Output),
        'ownerPubKeyHex': bobPubKey.toHex(),
        'changePKH': bobPubkeyHash,
        'changeAmount': 1000,
        'tokenLHS': hex.encode(tokenLHS),
        'prevTokenTx': hex.encode(prevTokenTx),
        'witnessPadding': hex.encode(witnessPadding),
        'parentOutputCount': 5,
        'parentPP1FtIndex': 1,
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 16. PP1_FT Unlock — Split Transfer
  {
    var builder = PP1FtUnlockBuilder.forSplitTransfer(
      preImage, pp2Output, pp2ChangeOutput,
      bobPubKey, bobPubkeyHash, BigInt.from(1000),
      tokenLHS, prevTokenTx, witnessPadding,
      30000, 20000,
      recipientPKH, 3,
      5, 1,
    );
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_FT_UNLOCK_SPLIT_TRANSFER',
      'type': 'unlock',
      'builder': 'PP1FtUnlockBuilder',
      'action': 'SPLIT_TRANSFER',
      'inputs': {
        'preImage': hex.encode(preImage),
        'pp2RecipientOutput': hex.encode(pp2Output),
        'pp2ChangeOutput': hex.encode(pp2ChangeOutput),
        'ownerPubKeyHex': bobPubKey.toHex(),
        'changePKH': bobPubkeyHash,
        'changeAmount': 1000,
        'tokenLHS': hex.encode(tokenLHS),
        'prevTokenTx': hex.encode(prevTokenTx),
        'witnessPadding': hex.encode(witnessPadding),
        'recipientAmount': 30000,
        'tokenChangeAmount': 20000,
        'recipientPKH': hex.encode(recipientPKH),
        'myOutputIndex': 3,
        'parentOutputCount': 5,
        'parentPP1FtIndex': 1,
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 17. PP1_FT Unlock — Merge
  {
    var builder = PP1FtUnlockBuilder.forMerge(
      preImage, pp2Output, bobPubKey,
      bobPubkeyHash, BigInt.from(1000),
      tokenLHS, prevTokenTx, prevTokenTxB,
      witnessPadding,
      5, 6,
      1, 2,
    );
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_FT_UNLOCK_MERGE',
      'type': 'unlock',
      'builder': 'PP1FtUnlockBuilder',
      'action': 'MERGE',
      'inputs': {
        'preImage': hex.encode(preImage),
        'pp2Output': hex.encode(pp2Output),
        'ownerPubKeyHex': bobPubKey.toHex(),
        'changePKH': bobPubkeyHash,
        'changeAmount': 1000,
        'tokenLHS': hex.encode(tokenLHS),
        'prevTokenTxA': hex.encode(prevTokenTx),
        'prevTokenTxB': hex.encode(prevTokenTxB),
        'witnessPadding': hex.encode(witnessPadding),
        'parentOutputCountA': 5,
        'parentOutputCountB': 6,
        'parentPP1FtIndexA': 1,
        'parentPP1FtIndexB': 2,
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // 18. PP1_FT Unlock — Burn
  {
    var builder = PP1FtUnlockBuilder.forBurn(bobPubKey);
    builder.signatures.add(svSig);
    var script = builder.getScriptSig();
    vectors.add({
      'name': 'PP1_FT_UNLOCK_BURN',
      'type': 'unlock',
      'builder': 'PP1FtUnlockBuilder',
      'action': 'BURN',
      'inputs': {
        'ownerPubKeyHex': bobPubKey.toHex(),
        'signatureTxFormatHex': sigTxFormatHex,
      },
      'expectedScriptHex': script.toHex(),
    });
  }

  // ─── Write output ──────────────────────────────────────────────
  var output = {
    'version': '1.0.0',
    'description': 'Cross-language test vectors for TSL1 lock/unlock builders',
    'generatedBy': 'dart run tool/export_test_vectors.dart',
    'keyMaterial': {
      'bobWif': bobWif,
      'bobPubKeyHex': bobPubKey.toHex(),
      'bobPubkeyHash': bobPubkeyHash,
      'alicePubkeyHash': alicePubkeyHash,
      'signatureTxFormatHex': sigTxFormatHex,
      'signatureMessage': 'SHA256 of bytes 0x01..0x20',
    },
    'vectors': vectors,
  };

  var encoder = JsonEncoder.withIndent('  ');
  var json = encoder.convert(output);

  var outFile = File('test_vectors/cross_language_vectors.json');
  outFile.parent.createSync(recursive: true);
  outFile.writeAsStringSync(json);

  print('Generated ${vectors.length} test vectors');
  print('Output: ${outFile.path}');
}
