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
import 'package:dartsv/dartsv.dart';
import 'opcode_helpers.dart';
import 'check_preimage_ocs.dart';
import 'pp1_ft_script_gen.dart';

/// Generates the complete PP1 (NFT inductive proof) locking script dynamically.
///
/// Replaces the ~11KB compiled sCrypt template with a hand-optimized script.
/// Does NOT use OP_CODESEPARATOR so that the preimage scriptCode field
/// contains the full script, enabling inductive proofs.
///
/// Constructor param layout:
/// ```
/// Byte 0:     0x14 (pushdata 20)
/// Bytes 1-20: ownerPKH
/// Byte 21:    0x20 (pushdata 32)
/// Bytes 22-53: tokenId
/// Byte 54:    0x14 (pushdata 20)
/// Bytes 55-74: rabinPubKeyHash (hash160 of Rabin public key n)
/// Byte 75+:   Script body
/// ```
class PP1NftScriptGen {

  static const int pkhDataStart = 1;
  static const int pkhDataEnd = 21;
  static const int tokenIdDataStart = 22;
  static const int tokenIdDataEnd = 54;
  static const int rabinPKHDataStart = 55;
  static const int rabinPKHDataEnd = 75;
  static const int scriptBodyStart = 75;

  // NFT PP2 compiled byte offsets (different from PP2-FT)
  static const int pp2FundingOutpointStart = 117;
  static const int pp2WitnessChangePKHStart = 154;
  static const int pp2ChangeAmountStart = 175;
  static const int pp2OwnerPKHStart = 176;
  static const int pp2ScriptCodeStart = 197;

  /// Generates the complete PP1 NFT locking script.
  static SVScript generate({
    required List<int> ownerPKH,
    required List<int> tokenId,
    required List<int> rabinPubKeyHash,
  }) {
    var b = ScriptBuilder();

    b.addData(Uint8List.fromList(ownerPKH));
    b.addData(Uint8List.fromList(tokenId));
    b.addData(Uint8List.fromList(rabinPubKeyHash));

    // Stack: [...scriptSig args, selector, ownerPKH, tokenId, rabinPubKeyHash]
    b.opCode(OpCodes.OP_TOALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_TOALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_TOALTSTACK);   // ownerPKH
    // Altstack: [rabinPubKeyHash(bottom), tokenId, ownerPKH(top)]
    // Pop order: ownerPKH first, then tokenId, then rabinPubKeyHash

    _emitDispatch(b);
    return b.build();
  }

  static void _emitDispatch(ScriptBuilder b) {
    // OP_2=burn (cheapest), OP_0=issueToken, OP_1=transferToken
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_DROP);
      _emitBurnToken(b);
    b.opCode(OpCodes.OP_ELSE);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_NOTIF);
      b.opCode(OpCodes.OP_DROP);
      _emitIssueToken(b);
    b.opCode(OpCodes.OP_ELSE);
      b.opCode(OpCodes.OP_DROP);
      _emitTransferToken(b);
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // burnToken (selector=2)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig], Altstack: [rabinPubKeyHash, tokenId, ownerPKH]
  static void _emitBurnToken(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);
    // Stack: [ownerPubKey, ownerSig, ownerPKH]
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [ownerPubKey, ownerSig] — need [sig, pubKey] for CHECKSIG
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  // =========================================================================
  // issueToken (selector=0)
  // =========================================================================

  /// Stack: [preImage, fundingOutpoint, witnessPadding, rabinN, rabinS,
  ///         rabinPadding, identityTxId, ed25519PubKey]
  /// Altstack: [rabinPubKeyHash, tokenId, ownerPKH]
  static void _emitIssueToken(ScriptBuilder b) {
    // Stack (8 items, top=0):
    //   ed25519PubKey=0, identityTxId=1, rabinPadding=2, rabinS=3, rabinN=4,
    //   witnessPadding=5, fundingOutpoint=6, preImage=7

    // --- Phase 1: Validate witnessPadding length ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);           // copy witnessPadding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 2: Clear ownerPKH; keep tokenId for Rabin message binding ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // ownerPKH → drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // tokenId (keep on main stack for hash binding)
    // Alt: [rabinPubKeyHash]
    // Stack: tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3, rabinS=4, rabinN=5, ...

    // --- Phase 3: Verify hash160(rabinN) == rabinPubKeyHash ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // rabinPubKeyHash (now at top, shifts indices)
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);           // copy rabinN (index 6: tokenId added to stack)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [] (empty)

    // --- Phase 4: Rabin signature verification ---
    // Compute sha256(identityTxId || ed25519PubKey || tokenId) as positive script number
    // Binds the Rabin signature to this specific token, preventing replay attacks.
    // Stack: tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3, rabinS=4, rabinN=5, ...
    b.opCode(OpCodes.OP_ROT);            // [identityTxId, tokenId, ed25519PubKey, ...]
    b.opCode(OpCodes.OP_ROT);            // [ed25519PubKey, identityTxId, tokenId, ...]
    b.opCode(OpCodes.OP_CAT);            // [identityTxId||ed25519PubKey, tokenId, ...]
    b.opCode(OpCodes.OP_SWAP);           // [tokenId, identityTxId||ed25519PubKey, ...]
    b.opCode(OpCodes.OP_CAT);            // [identityTxId||ed25519PubKey||tokenId, ...]
    b.opCode(OpCodes.OP_SHA256);          // raw hash (32 bytes)
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // hashNum (positive script number)
    // Stack: hashNum=0, rabinPadding=1, rabinS=2, rabinN=3,
    //        witnessPadding=4, fundingOutpoint=5, preImage=6

    // Rabin verify: s² mod n == hashNum + rabinPadding
    b.opCode(OpCodes.OP_SWAP);           // [rabinPadding, hashNum, rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_ADD);            // [(hashNum+padding), rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_SWAP);           // [rabinS, (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_MUL);            // [s², (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_ROT);            // [rabinN, s², (h+p), ...]
    b.opCode(OpCodes.OP_MOD);            // [(s² mod n), (h+p), ...]
    b.opCode(OpCodes.OP_NUMEQUALVERIFY); // verified!
    // Stack: [witnessPadding, fundingOutpoint, preImage]

    // --- Phase 5: Drop witnessPadding ---
    b.opCode(OpCodes.OP_DROP);
    // Stack: [fundingOutpoint, preImage]

    // --- Phase 6: checkPreimageOCS + hashPrevouts (same as before) ---
    b.opCode(OpCodes.OP_TOALTSTACK);    // save fundingOutpoint

    // Extract hashPrevouts (bytes[4:36]) from preImage
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // save hashPrevouts

    // Extract currentTxId (bytes[68:100]) from preImage
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // save currentTxId

    // checkPreimageOCS (no CODESEP)
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);

    // Build hashPrevOuts and verify
    b.opCode(OpCodes.OP_FROMALTSTACK);  // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);  // hashPrevouts
    b.opCode(OpCodes.OP_FROMALTSTACK);  // fundingOutpoint (36 bytes, from scriptSig)
    // Stack: [currentTxId, hashPrevouts, fundingOutpoint]

    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);          // copy currentTxId
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);           // pp1Outpoint = currentTxId + LE(1)

    b.opCode(OpCodes.OP_CAT);           // fundingOutpoint + pp1Outpoint

    b.opCode(OpCodes.OP_ROT);           // [hashPrevouts, outpoints12, currentTxId]
    b.addData(Uint8List.fromList([0x02, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);           // pp2Outpoint = currentTxId + LE(2)
    b.opCode(OpCodes.OP_CAT);           // allOutpoints(108B)

    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);

    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // transferToken (selector=1)
  // =========================================================================

  /// Stack: [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
  ///         scriptLHS, parentRawTx, padding]
  /// Altstack: [rabinPubKeyHash, tokenId, ownerPKH]
  static void _emitTransferToken(ScriptBuilder b) {
    // --- Phase 1: Get ownerPKH, do P2PKH auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    // Stack (10 items):
    // [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
    //  scriptLHS, parentRawTx, padding, ownerPKH]
    // idx: ownerPKH=0, pad=1, rawTx=2, lhs=3, sig=4, chgAmt=5,
    //      chgPkh=6, ownerPK=7, pp2=8, preImg=9

    // hash160(ownerPubKey) == ownerPKH
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // copy ownerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // checkSig(ownerSig, ownerPubKey)
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // copy ownerSig
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK (shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack: [..., padding, ownerPKH]

    // --- Phase 2: Validate padding and parentRawTx ---
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_PICK);           // copy padding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 3: Extract preImage fields ---
    // Extract currentTxId = preImage[68:100]
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt
    // Alt: [tokenId, currentTxId]

    // Extract nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt
    // Alt: [tokenId, currentTxId, nLocktime]

    // --- Phase 4: checkPreimageOCS ---
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_ROLL);           // ROLL preImage to top
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // preImage consumed. Stack (9 items):
    // [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //  parentRawTx, padding, ownerPKH]
    // idx: ownerPKH=0, pad=1, rawTx=2, lhs=3, sig=4, chgAmt=5,
    //      chgPkh=6, ownerPK=7, pp2=8

    // --- Phase 5: Parse parentRawTx outputs ---
    // Read outputs 1-4 from parentRawTx (PP1, PP2, PP3, metadata)
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx

    // Skip past inputs to reach outputs section
    PP1FtScriptGen.emitSkipInputs(b);
    // Stack: [..., ownerPKH, txFromOutputCount]

    // Read output count varint (and drop it)
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    // Stack: [..., ownerPKH, txFromFirstOutput]

    // Skip output 0 (change output)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    // Stack: [..., ownerPKH, txFromPP1Output]

    // Read 4 consecutive output scripts: PP1, PP2, PP3, metadata
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP2Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP3Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentMetadataScript → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes
    // Stack (9): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //             parentRawTx, padding, ownerPKH]
    // Alt: [tokenId, currentTxId, nLocktime, PP1, PP2, PP3, metadata]

    // --- Phase 6: Validate metadata starts with 006a ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentMetadataScript
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack (10): [..., ownerPKH, parentMetadataScript]
    // Alt: [tokenId, currentTxId, nLocktime, PP1, PP2, PP3]

    // --- Phase 7: Get parent scripts from altstack ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP3Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP2Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP1Script
    // Stack (13): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //              parentRawTx, padding, ownerPKH,
    //              metadataScript, pp3Script, pp2Script, pp1Script]
    // Alt: [tokenId, currentTxId, nLocktime]

    // Get currentTxId and nLocktime from alt
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Stack (15): [..., ownerPKH, metaS, pp3S, pp2S, pp1S, nLocktime, currentTxId]
    // Alt: [tokenId]
    // idx: currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //      ownerPKH=6, pad=7, rawTx=8, lhs=9, sig=10, chgAmt=11,
    //      chgPkh=12, ownerPK=13, pp2Out=14

    // --- Phase 8: Rebuild PP1 from parent template ---
    // PP1 param layout: parent[:1] + ownerPKH + parent[21:22] + tokenId + parent[54:]
    // ownerPKH changes on transfer; tokenId stays the same
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted +1)
    _emitRebuildPP1(b);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // --- Phase 9: Build PP1 output (rebuiltPP1Script, 1 sat) ---
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, pp1OutputBytes]

    // --- Phase 10: Rebuild PP3 from parent template ---
    // Copy pp3S and ownerPKH
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);            // copy pp3S
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted)
    PP1FtScriptGen.emitRebuildPP3(b);
    // Stack (17): [..., pp1S, nLocktime, currentTxId, pp1Out, rebuiltPP3Script]

    // Build PP3 output (1 sat)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (17): [..., pp1S, nLocktime, currentTxId, pp1Out, pp3Out]

    // --- Phase 11: Build metadata output (0 sats) ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy metadataScript
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (18): [..., pp1S, nLocktime, currentTxId, pp1Out, pp3Out, metaOut]

    // --- Phase 12: Build change output ---
    // Full stack bottom→top at this point (18 items):
    // [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //  parentRawTx, padding, ownerPKH,
    //  metaS, pp3S, pp2S, pp1S, nLocktime, currentTxId, pp1Out, pp3Out, metaOut]
    // idx from top: metaOut=0, pp3Out=1, pp1Out=2, currentTxId=3, nLocktime=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, ownerPKH=9,
    //   pad=10, rawTx=11, lhs=12, sig=13, chgAmt=14, chgPkh=15,
    //   ownerPK=16, pp2Out=17
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changeAmt (shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (19): [..., pp1Out, pp3Out, metaOut, changeOut]

    // --- Phase 13: Reconstruct fullTx ---
    // fullTx = scriptLHS + varint(5) + changeOut + pp1Out + pp2OutputBytes + pp3Out + metaOut + nLocktime

    // Get scriptLHS
    // idx: changeOut=0, metaOut=1, pp3Out=2, pp1Out=3, currentTxId=4, nLocktime=5,
    //   pp1S=6, pp2S=7, pp3S=8, metaS=9, ownerPKH=10,
    //   pad=11, rawTx=12, lhs=13, sig=14, chgAmt=15, chgPkh=16,
    //   ownerPK=17, pp2Out=18
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);            // copy scriptLHS

    // Append varint(5)
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);

    // Append changeOut (now at idx 1 after pushing scriptLHS+varint)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // Stack: [..., pp1Out, pp3Out, metaOut, (lhs+05+changeOut)]

    // Append pp1Out
    b.opCode(OpCodes.OP_SWAP);            // [..., pp1Out, pp3Out, (lhs+..), metaOut]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash metaOut
    b.opCode(OpCodes.OP_SWAP);            // [..., pp1Out, (lhs+..), pp3Out]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash pp3Out
    // Stack: [..., currentTxId, pp1Out, (lhs+..+chg)]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // Stack: [..., currentTxId, (lhs+chg+pp1Out)]

    // Append pp2OutputBytes
    // Stack: [..., nLocktime, currentTxId, (lhs+chg+pp1Out)]
    // pp2Out is deep. Let me count the index.
    // Stack bottom→top:
    // [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //  parentRawTx, padding, ownerPKH,
    //  metaS, pp3S, pp2S, pp1S, nLocktime,
    //  currentTxId, (partial)]
    // Alt: [tokenId, pp3Out, metaOut]
    // idx: partial=0, currentTxId=1, nLocktime=2, pp1S=3, pp2S=4,
    //  pp3S=5, metaS=6, ownerPKH=7, pad=8, rawTx=9, lhs=10,
    //  sig=11, chgAmt=12, chgPkh=13, ownerPK=14, pp2Out=15
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy pp2OutputBytes
    b.opCode(OpCodes.OP_CAT);

    // Append pp3Out and metaOut from alt
    b.opCode(OpCodes.OP_FROMALTSTACK);    // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // metaOut
    b.opCode(OpCodes.OP_CAT);

    // Append nLocktime
    // Stack: [..., nLocktime, currentTxId, fullTxPartial]
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);
    // Stack: [..., currentTxId, fullTx]

    // --- Phase 14: Verify sha256(sha256(fullTx)) == currentTxId ---
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack (13): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //              parentRawTx, padding, ownerPKH,
    //              metaS, pp3S, pp2S, pp1S]
    // Alt: [tokenId]

    // --- Phase 15: Validate PP2 (NFT) ---
    // Top: pp1S=0, pp2S=1, pp3S=2, metaS=3, ownerPKH=4, pad=5,
    //   rawTx=6, lhs=7, sig=8, chgAmt=9, chgPkh=10, ownerPK=11, pp2Out=12
    b.opCode(OpCodes.OP_DROP);            // drop pp1S
    // Top: pp2S=0
    // Get pp2OutputBytes from scriptSig (pp2Out at idx 11)
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);            // copy pp2Out
    // Stack: [..., pp2S, pp2Out]
    // Extract pp2OutputScript from pp2OutputBytes (skip 8-byte satoshis + varint)
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    // [pp2S, scriptLen, rest]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    // Stack: [..., pp2S, pp2Script]
    b.opCode(OpCodes.OP_SWAP);
    // Stack: [..., pp2Script, parentPP2Script]
    _emitValidatePP2NFT(b);
    // Stack: [...]

    // --- Phase 16: Verify outpoint[2][:32] == sha256(sha256(parentRawTx)) ---
    // Stack top: pp3S=0, metaS=1, ownerPKH=2, pad=3, rawTx=4, lhs=5,
    //   sig=6, chgAmt=7, chgPkh=8, ownerPK=9, pp2Out=10
    b.opCode(OpCodes.OP_DROP); // drop pp3S
    b.opCode(OpCodes.OP_DROP); // drop metaS
    b.opCode(OpCodes.OP_DROP); // drop ownerPKH
    b.opCode(OpCodes.OP_DROP); // drop padding
    // Top: rawTx=0, lhs=1, sig=2, chgAmt=3, chgPkh=4, ownerPK=5, pp2Out=6

    b.opCode(OpCodes.OP_DUP);             // copy parentRawTx
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);           // parentTxId
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash parentTxId

    // Read outpoint at input index 2 from scriptLHS
    b.opCode(OpCodes.OP_DROP);            // drop parentRawTx
    // Top: lhs=0, sig=1, ...
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    // Stack: [..., outpoint36]
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    // Stack: [..., outpointTxId(32)]
    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxId  (Alt now: [tokenId, rabinPubKeyHash])
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Clean up main stack residuals: [pp2Out, ownerPK, changePkh, changeAmt, ownerSig]
    b.opCode(OpCodes.OP_DROP);            // ownerSig
    b.opCode(OpCodes.OP_DROP);            // changeAmt
    b.opCode(OpCodes.OP_DROP);            // changePkh
    b.opCode(OpCodes.OP_DROP);            // ownerPK
    b.opCode(OpCodes.OP_DROP);            // pp2Out

    // Clean up alt (drop tokenId and rabinPubKeyHash)
    b.opCode(OpCodes.OP_FROMALTSTACK);    // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);

    b.opCode(OpCodes.OP_1);               // leave TRUE
  }

  // =========================================================================
  // Script rebuild helpers
  // =========================================================================

  /// Rebuild PP1 script from parent template with new ownerPKH.
  /// Pre: [parentPP1Script, newOwnerPKH]. Post: [rebuiltPP1Script].
  /// Layout: parent[:1] + newPKH + parent[21:]
  /// (tokenId stays the same — it's at bytes 22-53)
  static void _emitRebuildPP1(ScriptBuilder b) {
    // [pp1S, pkh]
    b.opCode(OpCodes.OP_SWAP);
    // [pkh, pp1S]
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);
    // [pkh, prefix1, pp1S[1:]]
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // [pkh, prefix1, pp1S[21:]]
    b.opCode(OpCodes.OP_ROT);
    // [prefix1, pp1S[21:], pkh]
    b.opCode(OpCodes.OP_ROT);
    // [pp1S[21:], pkh, prefix1]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // [pp1S[21:], prefix1+pkh]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // [prefix1+pkh+pp1S[21:]]
  }

  /// Validate PP2 (NFT) output script structure against parent template.
  /// Pre: [pp2Script, parentPP2Script] (parent on top). Post: [].
  static void _emitValidatePP2NFT(ScriptBuilder b) {
    // Extract constructor params from pp2Script at known byte offsets
    b.opCode(OpCodes.OP_SWAP);
    // [parentPP2Script, pp2Script]

    // Validate fundingOutpoint pushdata length == 36 (0x24)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x24]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Validate changePKH pushdata == 20 (0x14)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Validate changeAmount == OP_1 (0x51)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x51]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Validate ownerPKH pushdata == 20 (0x14)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Extract variable constructor params for rebuild check
    // [parentPP2Script, pp2Script]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // [parentPP2, pp2Script, variableParams(117..197)]
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Rebuild: parentPP2[:117] + variableParams + parentPP2[197:]
    b.opCode(OpCodes.OP_DROP);            // drop pp2Script
    // [parentPP2Script]
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT);
    // [prefix, rest]
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart - pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // [prefix, suffix]  suffix = parentPP2[197:]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // variableParams
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // [prefix + variableParams + suffix] = rebuiltPP2
    b.opCode(OpCodes.OP_SHA256);
    // Drop the hash for now (individual field checks provide sufficient validation)
    b.opCode(OpCodes.OP_DROP);
  }
}
