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

/// Generates the complete PP1_RFT (Restricted Fungible Token) locking script.
///
/// Extends the PP1_FT contract with:
/// - Rabin identity anchoring (rabinPubKeyHash)
/// - Transfer policy flags (free / self-only / non-transferable)
/// - One-time redeem vs persistent redeem
/// - Merkle tree whitelist (placeholder)
///
/// Constructor param layout (127-byte header):
/// ```
/// Byte 0:       0x14 (pushdata 20)
/// Bytes 1-20:   ownerPKH
/// Byte 21:      0x20 (pushdata 32)
/// Bytes 22-53:  tokenId
/// Byte 54:      0x14 (pushdata 20)
/// Bytes 55-74:  rabinPubKeyHash
/// Byte 75:      0x04 (pushdata 4)
/// Bytes 76-79:  flags (4-byte LE)
/// Byte 80:      0x08 (pushdata 8)
/// Bytes 81-88:  amount (8-byte LE sign-magnitude)
/// Byte 89:      0x04 (pushdata 4)
/// Bytes 90-93:  tokenSupply (4-byte LE)
/// Byte 94:      0x20 (pushdata 32)
/// Bytes 95-126: merkleRoot (32 bytes)
/// Byte 127+:    Script body
/// ```
///
/// Flags byte layout:
/// - Bits 0-1: Transfer policy (0=free, 1=self-only, 2=non-transferable)
/// - Bit 2:    One-time redeem (1=burn on redeem, 0=persistent)
/// - Bit 3:    Composition required (reserved)
///
/// Dispatch selectors:
/// - OP_5 = burn (cheapest, P2PKH only)
/// - OP_0 = mintToken
/// - OP_1 = transferToken
/// - OP_2 = splitTransfer
/// - OP_3 = mergeTokens
/// - OP_4 = redeemToken
class PP1RftScriptGen {

  // --- Byte offset constants ---
  static const int pkhDataStart = 1;
  static const int pkhDataEnd = 21;
  static const int tokenIdDataStart = 22;
  static const int tokenIdDataEnd = 54;
  static const int rabinPKHDataStart = 55;
  static const int rabinPKHDataEnd = 75;
  static const int flagsDataStart = 76;
  static const int flagsDataEnd = 80;
  static const int amountDataStart = 81;
  static const int amountDataEnd = 89;
  static const int tokenSupplyDataStart = 90;
  static const int tokenSupplyDataEnd = 94;
  static const int merkleRootDataStart = 95;
  static const int merkleRootDataEnd = 127;
  static const int scriptBodyStart = 127;

  // PP2-FT compiled byte offsets (same as PP1FtScriptGen + 40 for tokenSupply/merkleRoot)
  static const int pp2FundingOutpointStart = 159;
  static const int pp2WitnessChangePKHStart = 196;
  static const int pp2ChangeAmountStart = 217;
  static const int pp2OwnerPKHStart = 218;
  static const int pp2PP1_FTOutputIndexStart = 239;
  static const int pp2PP2OutputIndexStart = 240;
  static const int pp2ScriptCodeStart = 241;

  // PP3-FT byte offsets
  static const int pp3PP2OutputIndexStart = 48544;

  /// Generates the complete PP1_RFT restricted fungible token locking script.
  ///
  /// [ownerPKH] - 20-byte owner public key hash
  /// [tokenId] - 32-byte token identifier
  /// [rabinPubKeyHash] - 20-byte hash160 of the Rabin public key n
  /// [flags] - transfer policy flags (0-255)
  /// [amount] - the fungible token amount
  /// [tokenSupply] - total token supply (4-byte LE)
  /// [merkleRoot] - 32-byte Merkle root for whitelist tree
  static SVScript generate({
    required List<int> ownerPKH,
    required List<int> tokenId,
    required List<int> rabinPubKeyHash,
    required int flags,
    required int amount,
    required int tokenSupply,
    required List<int> merkleRoot,
  }) {
    var b = ScriptBuilder();

    // Push constructor params as data
    b.addData(Uint8List.fromList(ownerPKH));        // 0x14 + 20 bytes
    b.addData(Uint8List.fromList(tokenId));          // 0x20 + 32 bytes
    b.addData(Uint8List.fromList(rabinPubKeyHash));  // 0x14 + 20 bytes

    // Encode flags as 4-byte LE to avoid dartsv's addData single-byte gotcha
    var flagsBytes = Uint8List(4);
    flagsBytes[0] = flags & 0xFF;
    b.addData(flagsBytes);                           // 0x04 + 4 bytes

    // Amount as 8-byte LE sign-magnitude
    var amountBytes = Uint8List(8);
    var val = amount;
    for (var i = 0; i < 7; i++) {
      amountBytes[i] = val & 0xFF;
      val >>= 8;
    }
    amountBytes[7] = val & 0x7F;
    b.addData(amountBytes);                          // 0x08 + 8 bytes

    // tokenSupply as 4-byte LE
    var supplyBytes = Uint8List(4);
    var s = tokenSupply;
    for (var i = 0; i < 4; i++) { supplyBytes[i] = s & 0xFF; s >>= 8; }
    b.addData(supplyBytes);                          // 0x04 + 4 bytes

    // merkleRoot (32 bytes)
    b.addData(Uint8List.fromList(merkleRoot));       // 0x20 + 32 bytes

    // Move constructor params to altstack (LIFO order)
    // Push order: merkleRoot last pushed → first to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);     // merkleRoot
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenSupply
    b.opCode(OpCodes.OP_TOALTSTACK);     // amount
    b.opCode(OpCodes.OP_TOALTSTACK);     // flags
    b.opCode(OpCodes.OP_TOALTSTACK);     // rabinPubKeyHash
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenId
    b.opCode(OpCodes.OP_TOALTSTACK);     // ownerPKH
    // Altstack bottom→top: [merkleRoot, tokenSupply, amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
    // Pop order: ownerPKH, tokenId, rabinPubKeyHash, flags, amount, tokenSupply, merkleRoot

    _emitDispatch(b);
    return b.build();
  }

  // =========================================================================
  // Dispatch
  // =========================================================================

  static void _emitDispatch(ScriptBuilder b) {
    // Check for OP_5 (burn) first — cheapest path
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_DROP);
      _emitBurnToken(b);
    b.opCode(OpCodes.OP_ELSE);
      // Check for OP_0 (mint)
      b.opCode(OpCodes.OP_DUP);
      b.opCode(OpCodes.OP_NOTIF);
        b.opCode(OpCodes.OP_DROP);
        _emitMintToken(b);
      b.opCode(OpCodes.OP_ELSE);
        // Check OP_1 (transfer)
        b.opCode(OpCodes.OP_DUP);
        b.opCode(OpCodes.OP_1);
        b.opCode(OpCodes.OP_EQUAL);
        b.opCode(OpCodes.OP_IF);
          b.opCode(OpCodes.OP_DROP);
          _emitTransferToken(b);
        b.opCode(OpCodes.OP_ELSE);
          // Check OP_2 (split)
          b.opCode(OpCodes.OP_DUP);
          b.opCode(OpCodes.OP_2);
          b.opCode(OpCodes.OP_EQUAL);
          b.opCode(OpCodes.OP_IF);
            b.opCode(OpCodes.OP_DROP);
            _emitSplitTransfer(b);
          b.opCode(OpCodes.OP_ELSE);
            // Check OP_3 (merge) vs OP_4 (redeem)
            b.opCode(OpCodes.OP_DUP);
            b.opCode(OpCodes.OP_3);
            b.opCode(OpCodes.OP_EQUAL);
            b.opCode(OpCodes.OP_IF);
              b.opCode(OpCodes.OP_DROP);
              _emitMergeToken(b);
            b.opCode(OpCodes.OP_ELSE);
              // Must be OP_4 (redeem)
              b.opCode(OpCodes.OP_DROP);
              _emitRedeemToken(b);
            b.opCode(OpCodes.OP_ENDIF);
          b.opCode(OpCodes.OP_ENDIF);
        b.opCode(OpCodes.OP_ENDIF);
      b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // burnToken (selector=5)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig]
  /// Altstack: [amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  static void _emitBurnToken(ScriptBuilder b) {
    // Drain altstack: ownerPKH (keep), rest (drop)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // flags
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenSupply
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merkleRoot
    b.opCode(OpCodes.OP_DROP);
    // Stack: [ownerPubKey, ownerSig, ownerPKH]

    // P2PKH: hash160(ownerPubKey) == ownerPKH
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPubKey
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [ownerPubKey, ownerSig]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  // =========================================================================
  // redeemToken (selector=4)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig]
  /// Altstack: [merkleRoot, tokenSupply, amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  ///
  /// Redeem is P2PKH auth only (same as burn). The transaction tool controls
  /// whether the output includes a continuation.
  static void _emitRedeemToken(ScriptBuilder b) {
    // Drain altstack: ownerPKH (keep), rest (drop)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // flags
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenSupply
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merkleRoot
    b.opCode(OpCodes.OP_DROP);
    // Stack: [ownerPubKey, ownerSig, ownerPKH]

    // P2PKH: hash160(ownerPubKey) == ownerPKH
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPubKey
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [ownerPubKey, ownerSig]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  // =========================================================================
  // mintToken (selector=0)
  // =========================================================================

  /// Stack: [preImage, fundingOutpoint, witnessPadding, rabinN, rabinS,
  ///         rabinPadding, identityTxId, ed25519PubKey]
  /// Altstack: [amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  static void _emitMintToken(ScriptBuilder b) {
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
    // Alt: [amount, flags, rabinPubKeyHash]
    // Stack: tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3, rabinS=4, rabinN=5, ...

    // --- Phase 3: Verify hash160(rabinN) == rabinPubKeyHash ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // rabinPubKeyHash
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);           // copy rabinN (index 6: tokenId added to stack)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [amount, flags]

    // --- Phase 2b: Drain remaining altstack (flags, then amount check) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // flags → drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // amount
    b.opCode(OpCodes.OP_0);
    b.opCode(OpCodes.OP_GREATERTHAN);
    b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // tokenSupply → drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // merkleRoot → drop
    b.opCode(OpCodes.OP_DROP);
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
    b.opCode(OpCodes.OP_SHA256);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // hashNum (positive)

    // Rabin verify: s^2 mod n == hashNum + rabinPadding
    b.opCode(OpCodes.OP_SWAP);           // [rabinPadding, hashNum, rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_ADD);            // [(hashNum+padding), rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_SWAP);           // [rabinS, (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_MUL);            // [s^2, (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_ROT);            // [rabinN, s^2, (h+p), ...]
    b.opCode(OpCodes.OP_MOD);            // [(s^2 mod n), (h+p), ...]
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);
    // Stack: [witnessPadding, fundingOutpoint, preImage]

    // --- Phase 5: Drop witnessPadding ---
    b.opCode(OpCodes.OP_DROP);
    // Stack: [fundingOutpoint, preImage]

    // --- Phase 6: checkPreimageOCS + hashPrevouts ---
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
    b.opCode(OpCodes.OP_CAT);           // pp1RftOutpoint

    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_ROT);           // [hashPrevouts, outpoints12, currentTxId]
    b.addData(Uint8List.fromList([0x02, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);           // pp2Outpoint
    b.opCode(OpCodes.OP_CAT);           // allOutpoints(108B)

    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);

    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // transferToken (selector=1) — FULL INDUCTIVE PROOF
  // =========================================================================

  /// ScriptSig (14 items): [preImage, pp2Out, ownerPK, changePkh, changeAmt,
  ///   ownerSig, scriptLHS, parentRawTx, padding, parentOutCnt, parentPP1Idx,
  ///   recipientPKH, merkleProof, merkleSides]
  /// Altstack: [merkleRoot, tokenSupply, amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  ///
  /// Strategy: Phase 1 does P2PKH auth (indices shifted +3 for new items).
  /// Phase 1b drains flags/rabinPKH. Phase 1c does merkle verification and
  /// normalizes the altstack to [amount, tokenId] — matching FT exactly.
  /// Phases 2-16 then follow the FT transfer pattern with RFT byte offsets.
  static void _emitTransferToken(ScriptBuilder b) {
    // --- Phase 1: Get ownerPKH, do P2PKH auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    // Stack (15 items):
    // idx: ownerPKH=0, merkleSides=1, merkleProof=2, recipientPKH=3,
    //      pp1Idx=4, outCnt=5, pad=6, rawTx=7, lhs=8, sig=9,
    //      chgAmt=10, chgPkh=11, ownerPK=12, pp2=13, preImg=14

    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // copy ownerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy ownerSig
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK (shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 1b: Transfer policy enforcement ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_FROMALTSTACK);   // flags
    // Stack (18): flags=0, rabinPKH=1, tokenId=2, ownerPKH=3,
    //   merkleSides=4, merkleProof=5, recipientPKH=6, pp1Idx=7, outCnt=8,
    //   pad=9, rawTx=10, lhs=11, sig=12, chgAmt=13, chgPkh=14, ownerPK=15, pp2=16, preImg=17
    // Alt: [merkleRoot, tokenSupply, amount]

    // Extract transfer policy: bits 0-1 = flags % 4
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_MOD);
    // Stack (19): policy=0, flags=1, ...

    // Non-transferable (policy == 2): fail
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_FALSE);
      b.opCode(OpCodes.OP_RETURN);
    b.opCode(OpCodes.OP_ENDIF);

    // Self-transfer check (policy == 1): recipientPKH must == ownerPKH
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      // Inside IF (19): policy=0, flags=1, rabinPKH=2, tokenId=3, ownerPKH=4,
      //   merkleSides=5, merkleProof=6, recipientPKH=7, ...
      b.opCode(OpCodes.OP_7);
      b.opCode(OpCodes.OP_PICK);         // copy recipientPKH → 20
      b.opCode(OpCodes.OP_5);
      b.opCode(OpCodes.OP_PICK);         // copy ownerPKH (shifted +1) → 21
      b.opCode(OpCodes.OP_EQUALVERIFY);  // back to 19
    b.opCode(OpCodes.OP_ENDIF);

    // Drop policy, flags, rabinPKH
    b.opCode(OpCodes.OP_DROP);           // drop policy → 18
    b.opCode(OpCodes.OP_DROP);           // drop flags → 17
    b.opCode(OpCodes.OP_DROP);           // drop rabinPKH → 16
    // Stack (16): tokenId=0, ownerPKH=1, merkleSides=2, merkleProof=3,
    //   recipientPKH=4, pp1Idx=5, ...
    // Alt: [merkleRoot, tokenSupply, amount]

    // --- Phase 1c: Merkle whitelist verification + altstack normalization ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount → stack (17)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenSupply → stack (18)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merkleRoot → stack (19)
    // merkleRoot=0, tokenSupply=1, amount=2, tokenId=3, ownerPKH=4,
    //   merkleSides=5, merkleProof=6, recipientPKH=7, ...
    // Alt: [] (empty)

    // Drop tokenSupply
    b.opCode(OpCodes.OP_SWAP);           // [tokenSupply, merkleRoot, amount, ...]
    b.opCode(OpCodes.OP_DROP);           // → (18)
    // merkleRoot=0, amount=1, tokenId=2, ownerPKH=3,
    //   merkleSides=4, merkleProof=5, recipientPKH=6, ...

    // Check if merkleRoot is all zeros (whitelist disabled)
    b.opCode(OpCodes.OP_DUP);
    b.addData(Uint8List.fromList(List<int>.filled(32, 0)));
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_NOTIF);          // merkleRoot != zeros → whitelist enabled
      // Compute currentHash = SHA256(recipientPKH)
      b.opCode(OpCodes.OP_6);
      b.opCode(OpCodes.OP_PICK);         // copy recipientPKH → (19)
      b.opCode(OpCodes.OP_SHA256);       // → hash (19)
      // hash=0, merkleRoot=1, amount=2, tokenId=3, ownerPKH=4,
      //   merkleSides=5, merkleProof=6, recipientPKH=7, ...

      // Build verification stack: [hash, proof, sides, root]
      b.opCode(OpCodes.OP_1);
      b.opCode(OpCodes.OP_PICK);         // merkleRoot → (20)
      b.opCode(OpCodes.OP_6);
      b.opCode(OpCodes.OP_PICK);         // merkleSides → (21)
      b.opCode(OpCodes.OP_8);
      b.opCode(OpCodes.OP_PICK);         // merkleProof → (22)
      b.opCode(OpCodes.OP_3);
      b.opCode(OpCodes.OP_ROLL);         // bring hash to top → (22)
      _emitVerifyMerkleProof(b);         // consumes 4 → (18)
    b.opCode(OpCodes.OP_ENDIF);

    // Drop merkleRoot → (17)
    b.opCode(OpCodes.OP_DROP);
    // amount=0, tokenId=1, ownerPKH=2, merkleSides=3, merkleProof=4,
    //   recipientPKH=5, pp1Idx=6, ...

    // Remove recipientPKH, merkleProof, merkleSides from stack
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // remove recipientPKH → (16)
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // remove merkleProof → (15)
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // remove merkleSides → (14)
    // amount=0, tokenId=1, ownerPKH=2, pp1Idx=3, ...

    // Push amount and tokenId to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);     // amount → alt → (13)
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenId → alt → (12)
    // Stack (12): ownerPKH=0, pp1Idx=1, outCnt=2, pad=3, rawTx=4, lhs=5,
    //   sig=6, chgAmt=7, chgPkh=8, ownerPK=9, pp2=10, preImg=11
    // Alt: [amount, tokenId]
    // *** Stack and altstack now match FT layout exactly ***

    // --- Phase 2: Validate padding and parentRawTx ---
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy padding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 3: Extract preImage fields ---
    // currentTxId = preImage[68:100]
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt
    // Alt: [amount, tokenId, currentTxId]

    // nLocktime = preImage[len-8:len-4]
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt
    // Alt: [amount, tokenId, currentTxId, nLocktime]

    // --- Phase 4: checkPreimageOCS ---
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // preImage consumed. Stack (11 items):
    // idx: ownerPKH=0, pp1Idx=1, outCnt=2, pad=3, rawTx=4, lhs=5,
    //      sig=6, chgAmt=7, chgPkh=8, ownerPK=9, pp2=10

    // --- Phase 5: Parse parentRawTx outputs ---
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy parentPP1Idx (shifted)

    b.opCode(OpCodes.OP_TOALTSTACK);     // stash pp1Idx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // get pp1Idx
    PP1FtScriptGen.emitSkipNOutputs(b);

    // Read 3 consecutive output scripts: PP1, PP2, PP3
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP2Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP3Script → alt
    // Stack: [..., ownerPKH, txFromAfterPP3]
    // Alt: [amount, tokenId, currentTxId, nLocktime, PP1, PP2, PP3]

    // Compute metadataSkip = parentOutCnt - 1 - parentPP1Idx - 3
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy parentOutCnt
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy parentPP1Idx (shifted)
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_SUB);

    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentMetadataScript → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes
    // Stack: [..., ownerPKH]
    // Alt: [..., PP1, PP2, PP3, metadata]

    // --- Phase 6: Validate metadata starts with 006a ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metadata
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [..., ownerPKH, metadataScript]

    // --- Phase 7: Verify parent amount == this.amount ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP3
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP2
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP1
    // Stack: [..., ownerPKH, metaS, pp3S, pp2S, pp1S]

    // Extract parentAmount from PP1[81:89] (RFT offsets)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, amountDataEnd); // 89
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, amountDataStart); // 81
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // parentAmount

    // Get this.amount from altstack
    b.opCode(OpCodes.OP_FROMALTSTACK);    // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);    // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // amount (raw 8-byte LE)
    b.opCode(OpCodes.OP_BIN2NUM);
    // Stack: [..., pp1S, parentAmt, nLocktime, currentTxId, tokenId, amount]

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // keep amount in alt
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL);            // move parentAmt to top
    b.opCode(OpCodes.OP_EQUALVERIFY);     // require parentAmt == amount
    // Stack: [..., pp1S, nLocktime, currentTxId, tokenId]
    // Alt: [amount]
    b.opCode(OpCodes.OP_TOALTSTACK);      // tokenId → alt
    // Stack: [..., ownerPKH, metaS, pp3S, pp2S, pp1S, nLocktime, currentTxId]
    // Alt: [amount, tokenId]

    // --- Phase 8: Rebuild PP1_RFT from parent template ---
    // idx: currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5, ownerPKH=6
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted +1)
    b.opCode(OpCodes.OP_FROMALTSTACK);    // tokenId
    b.opCode(OpCodes.OP_DROP);            // drop tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // amount
    _emitRebuildPP1Rft(b);
    // Stack: [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // --- Phase 9: Build PP1 output (1 sat) ---
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack: [..., pp1S, nLocktime, currentTxId, pp1Out]

    // --- Phase 10: Rebuild PP3 from parent template ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);            // copy pp3S
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted)
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack: [..., pp1S, nLocktime, currentTxId, pp1Out, pp3Out]

    // --- Phase 11: Build metadata output (0 sats) ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy metadataScript
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack: [..., pp1S, nLocktime, currentTxId, pp1Out, pp3Out, metaOut]

    // --- Phase 12: Build change output ---
    // Full stack bottom→top:
    // [pp2OutOrig, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //  parentRawTx, padding, parentOutCnt, parentPP1Idx,
    //  ownerPKH, metaS, pp3S, pp2S, pp1S, nLocktime, currentTxId,
    //  pp1Out, pp3Out, metaOut]
    // Total: 20 items. idx from top: metaOut=0 ... pp2OutOrig=19
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);            // copy changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);            // copy changeAmt (shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack: [..., pp1Out, pp3Out, metaOut, changeOut]

    // --- Phase 13: Reconstruct fullTx ---
    // fullTx = scriptLHS + varint(5) + changeOut + pp1Out + pp2OutputBytes + pp3Out + metaOut + nLocktime
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy scriptLHS
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);             // lhs + varint(5)

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + changeOut

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash metaOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + pp1Out

    // Append pp2OutputBytes (pp2OutOrig at idx 17)
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);            // copy pp2OutputBytes
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_FROMALTSTACK);    // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // metaOut
    b.opCode(OpCodes.OP_CAT);

    // Append nLocktime (ROT brings it to top)
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);
    // Stack: [..., currentTxId, fullTx]

    // --- Phase 14: Verify sha256(sha256(fullTx)) == currentTxId ---
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [..., pp1S]
    // Full remaining: [pp2OutOrig, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //  parentRawTx, padding, parentOutCnt, parentPP1Idx,
    //  ownerPKH, metaS, pp3S, pp2S, pp1S]

    // --- Phase 15: Validate PP2-FT ---
    // pp1S=0, pp2S=1, pp3S=2, metaS=3, ownerPKH=4, pp1Idx=5,
    //   outCnt=6, pad=7, rawTx=8, lhs=9, sig=10, chgAmt=11, chgPkh=12,
    //   ownerPK=13, pp2OutOrig=14
    b.opCode(OpCodes.OP_DROP);            // drop pp1S
    // Top: pp2S=0
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);            // copy pp2OutOrig
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    PP1FtScriptGen.emitValidatePP2FT(b, 1, 2);

    // --- Phase 16: Verify outpoint[2][:32] == sha256(sha256(parentRawTx)) ---
    // Top: pp3S=0, metaS=1, ownerPKH=2, pp1Idx=3, outCnt=4, pad=5,
    //   rawTx=6, lhs=7, sig=8, chgAmt=9, chgPkh=10, ownerPK=11, pp2OutOrig=12
    b.opCode(OpCodes.OP_DROP); // drop pp3S
    b.opCode(OpCodes.OP_DROP); // drop metaS
    b.opCode(OpCodes.OP_DROP); // drop ownerPKH
    b.opCode(OpCodes.OP_DROP); // drop pp1Idx
    b.opCode(OpCodes.OP_DROP); // drop outCnt
    b.opCode(OpCodes.OP_DROP); // drop padding
    // Top: rawTx=0, lhs=1, sig=2, chgAmt=3, chgPkh=4, ownerPK=5, pp2OutOrig=6

    b.opCode(OpCodes.OP_DUP);             // copy parentRawTx
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);           // parentTxId
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash parentTxId

    b.opCode(OpCodes.OP_DROP);            // drop parentRawTx
    // Top: lhs=0, sig=1, ...

    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxId
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Clean up main stack residuals: [pp2OutOrig, ownerPK, changePkh, changeAmt, ownerSig]
    b.opCode(OpCodes.OP_DROP);            // ownerSig
    b.opCode(OpCodes.OP_DROP);            // changeAmt
    b.opCode(OpCodes.OP_DROP);            // changePkh
    b.opCode(OpCodes.OP_DROP);            // ownerPK
    b.opCode(OpCodes.OP_DROP);            // pp2OutOrig

    b.opCode(OpCodes.OP_1);               // leave TRUE
  }

  // =========================================================================
  // splitTransfer (selector=2) — placeholder
  // =========================================================================

  /// ScriptSig (16 items): [preImage, pp2RecipOut, pp2ChangeOut, ownerPK, changePkh,
  ///   changeAmt, ownerSig, scriptLHS, parentRawTx, padding, recipientAmt,
  ///   tokenChangeAmt, recipientPKH, myOutIdx, outCnt, pp1FtIdx]
  /// Altstack: [amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  ///
  /// Strategy: Phase 1+1b auth and normalize altstack to [amount, tokenId].
  /// Then reuse FT split phases 2-16 (stack layout matches after normalization).
  static void _emitSplitTransfer(ScriptBuilder b) {
    _emitSplitAuth(b);
    PP1FtScriptGen.emitSplitValidateInputLengths(b);
    PP1FtScriptGen.emitSplitExtractPreimageFields(b);
    PP1FtScriptGen.emitSplitCheckPreimage(b);
    PP1FtScriptGen.emitSplitParseParentOutputs(b);
    PP1FtScriptGen.emitSplitValidateMetadata(b);
    _emitSplitBalanceConservation(b);
    _emitSplitDrainAltstack(b);
    _emitSplitRebuildPP1Rfts(b);
    PP1FtScriptGen.emitSplitVerifyMyOutputIdx(b);
    PP1FtScriptGen.emitSplitRebuildPP3s(b);
    PP1FtScriptGen.emitSplitBuildOutputs(b);
    PP1FtScriptGen.emitSplitReconstructFullTx(b);
    PP1FtScriptGen.emitSplitVerifyTxId(b);
    PP1FtScriptGen.emitSplitValidatePP2s(b);
    PP1FtScriptGen.emitSplitVerifyParentOutpoint(b);
  }

  /// Phase 1: P2PKH auth + Phase 1b: policy enforcement + Phase 1c: merkle + normalize.
  /// Entry: 18 scriptSig items. Alt: [merkleRoot, tokenSupply, amount, flags, rabinPKH, tokenId, ownerPKH]
  /// Exit: 17 items (ownerPKH at top). Alt: [amount, tokenId]
  static void _emitSplitAuth(ScriptBuilder b) {
    // Phase 1: Pop ownerPKH, do P2PKH auth (indices +2 for merkleProof, merkleSides)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    // Stack (19): ownerPKH=0, merkleSides=1, merkleProof=2, pp1FtIdx=3, outCnt=4,
    //   myOutIdx=5, recipientPKH=6, tokenChangeAmt=7, recipientAmt=8, padding=9,
    //   parentRawTx=10, scriptLHS=11, ownerSig=12, changeAmt=13, changePkh=14,
    //   ownerPK=15, pp2ChangeOut=16, pp2RecipOut=17, preImage=18

    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // copy ownerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);

    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // copy ownerSig
    OpcodeHelpers.pushInt(b, 16);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK (shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);

    // Phase 1b: Pop extra altstack items, enforce policy
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_FROMALTSTACK);   // flags
    // Stack (22): flags=0, rabinPKH=1, tokenId=2, ownerPKH=3, merkleSides=4,
    //   merkleProof=5, pp1FtIdx=6, outCnt=7, myOutIdx=8, recipientPKH=9, ...
    // Alt: [merkleRoot, tokenSupply, amount]

    // Extract transfer policy: bits 0-1 = flags % 4
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_MOD);
    // Stack (23): policy=0, flags=1, ..., recipientPKH=10, ...

    // Non-transferable (policy == 2): fail
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_FALSE);
      b.opCode(OpCodes.OP_RETURN);
    b.opCode(OpCodes.OP_ENDIF);

    // Self-transfer check (policy == 1): recipientPKH must == ownerPKH
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      // (23): policy=0, ..., ownerPKH=4, ..., recipientPKH=10
      OpcodeHelpers.pushInt(b, 10);
      b.opCode(OpCodes.OP_PICK);         // copy recipientPKH → 24
      b.opCode(OpCodes.OP_5);
      b.opCode(OpCodes.OP_PICK);         // copy ownerPKH (shifted +1) → 25
      b.opCode(OpCodes.OP_EQUALVERIFY);  // → 23
    b.opCode(OpCodes.OP_ENDIF);

    // Drop policy, flags, rabinPKH
    b.opCode(OpCodes.OP_DROP);           // drop policy → 22
    b.opCode(OpCodes.OP_DROP);           // drop flags → 21
    b.opCode(OpCodes.OP_DROP);           // drop rabinPKH → 20
    // Stack (20): tokenId=0, ownerPKH=1, merkleSides=2, merkleProof=3,
    //   pp1FtIdx=4, outCnt=5, myOutIdx=6, recipientPKH=7, ...
    // Alt: [merkleRoot, tokenSupply, amount]

    // --- Phase 1c: Merkle whitelist verification + altstack normalization ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount → (21)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenSupply → (22)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merkleRoot → (23)
    // merkleRoot=0, tokenSupply=1, amount=2, tokenId=3, ownerPKH=4,
    //   merkleSides=5, merkleProof=6, pp1FtIdx=7, ..., recipientPKH=10, ...
    // Alt: [] (empty)

    // Drop tokenSupply
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DROP);           // → (22)

    // Check if merkleRoot is all zeros (whitelist disabled)
    b.opCode(OpCodes.OP_DUP);
    b.addData(Uint8List.fromList(List<int>.filled(32, 0)));
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_NOTIF);          // merkleRoot != zeros → whitelist enabled
      // Compute currentHash = SHA256(recipientPKH)
      b.opCode(OpCodes.OP_9);
      b.opCode(OpCodes.OP_PICK);         // copy recipientPKH → (23)
      b.opCode(OpCodes.OP_SHA256);       // → hash (23)
      // hash=0, merkleRoot=1, ..., merkleSides=5, merkleProof=6, ...

      // Build verification stack: [hash, proof, sides, root]
      b.opCode(OpCodes.OP_1);
      b.opCode(OpCodes.OP_PICK);         // merkleRoot → (24)
      b.opCode(OpCodes.OP_6);
      b.opCode(OpCodes.OP_PICK);         // merkleSides → (25)
      b.opCode(OpCodes.OP_8);
      b.opCode(OpCodes.OP_PICK);         // merkleProof → (26)
      b.opCode(OpCodes.OP_3);
      b.opCode(OpCodes.OP_ROLL);         // bring hash to top → (26)
      _emitVerifyMerkleProof(b);         // consumes 4 → (22)
    b.opCode(OpCodes.OP_ENDIF);

    // Drop merkleRoot → (21)
    b.opCode(OpCodes.OP_DROP);
    // amount=0, tokenId=1, ownerPKH=2, merkleSides=3, merkleProof=4,
    //   pp1FtIdx=5, outCnt=6, myOutIdx=7, recipientPKH=8, ...

    // Remove merkleProof and merkleSides from stack (recipientPKH stays for split)
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // remove merkleProof → (20)
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // remove merkleSides → (19)
    // amount=0, tokenId=1, ownerPKH=2, pp1FtIdx=3, outCnt=4,
    //   myOutIdx=5, recipientPKH=6, ...

    // Push amount and tokenId to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);     // amount → alt → (18)
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenId → alt → (17)
    // Stack (17): ownerPKH at top. Alt: [amount, tokenId]
    // *** Matches FT split post-auth layout ***
  }

  /// Balance conservation for RFT (uses RFT byte offsets 81-89).
  /// Pops PP3, PP2, PP1 from alt. Verifies recipientAmt + tokenChangeAmt == parentAmount.
  /// Entry stack (18): [..., sha256sc, metadata]  Alt: [..., nLocktime, PP1, PP2, PP3]
  /// Exit stack  (21): [..., sha256sc, metadata, PP3, PP2, PP1]  Alt: [amount, tokenId, currentTxId, nLocktime]
  static void _emitSplitBalanceConservation(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP3
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP2
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP1
    // Stack (21): PP1=0, PP2=1, PP3=2, metadata=3, ...
    // idx: PP1=0, PP2=1, PP3=2, metadata=3, sha256sc=4, ownerPKH=5,
    //   pp1FtIdx=6, outCnt=7, myOutIdx=8, recipientPKH=9, tokenChangeAmt=10,
    //   recipientAmt=11

    // Extract parentAmount from PP1_RFT[81:89] (RFT offsets)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, amountDataEnd); // 89
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, amountDataStart); // 81
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // parentAmount
    // Stack (22): parentAmt=0, ..., tokenChangeAmt=11, recipientAmt=12

    // recipientAmt > 0
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // tokenChangeAmt > 0
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // recipientAmt + tokenChangeAmt == parentAmount
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // tokenChangeAmt
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);           // recipientAmt (shifted +1)
    b.opCode(OpCodes.OP_ADD);
    b.opCode(OpCodes.OP_EQUALVERIFY);    // sum == parentAmount
    // Stack (21): [..., sha256sc, metadata, PP3, PP2, PP1]
  }

  /// Drain altstack for RFT split — get nLocktime and currentTxId, drop tokenId and amount.
  /// Same as FT except we also need to handle the RFT altstack which has already been
  /// normalized to [amount, tokenId, currentTxId, nLocktime] at this point.
  /// Entry stack (21). Alt: [amount, tokenId, currentTxId, nLocktime]
  /// Exit stack (23). Alt: empty
  static void _emitSplitDrainAltstack(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount
    b.opCode(OpCodes.OP_DROP);
  }

  /// Rebuild recipient PP1_RFT and change PP1_RFT from parent template.
  /// Uses _emitRebuildPP1Rft (splices PKH + amount into 89-byte header).
  /// Entry stack (23): [..., PP1, nLocktime, currentTxId]  Alt: empty
  /// Exit stack  (25): [..., PP1, nLocktime, currentTxId, recipientPP1, changePP1]
  static void _emitSplitRebuildPP1Rfts(ScriptBuilder b) {
    // --- Rebuild recipient PP1_RFT ---
    // _emitRebuildPP1Rft expects: [parentScript, newPKH, newAmount]
    // PP1 at idx 2, recipientPKH at idx 11, recipientAmt at idx 13
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy PP1 → 24
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // recipientPKH (was 11, +1) → 25
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);           // recipientAmt (was 13, +2) → 26
    _emitRebuildPP1Rft(b);
    // Stack (24): [..., PP1, nLocktime, currentTxId, recipientPP1_RFT]

    // --- Extract parentOwnerPKH from PP1[1:21] and stash ---
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy PP1 → 25
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack (25): [..., currentTxId, recipientPP1, parentOwnerPKH]
    b.opCode(OpCodes.OP_TOALTSTACK);     // stash parentOwnerPKH
    // Stack (24), Alt: [parentOwnerPKH]

    // --- Rebuild change PP1_RFT ---
    // PP1 at idx 3, parentOwnerPKH in alt, tokenChangeAmt at idx 13
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy PP1 → 25
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentOwnerPKH → 26
    // idx: parentOwnerPKH=0, PP1copy=1, recipPP1=2, curTxId=3, nLock=4, PP1=5,
    //   PP2=6, PP3=7, meta=8, sha256sc=9, ownerPKH=10, pp1FtIdx=11, outCnt=12,
    //   myOutIdx=13, recipientPKH=14, tokenChangeAmt=15
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);           // tokenChangeAmt → 27
    _emitRebuildPP1Rft(b);
    // Stack (25): [..., PP1, nLocktime, currentTxId, recipientPP1, changePP1]
  }

  // =========================================================================
  // mergeTokens (selector=3) — placeholder
  // =========================================================================

  /// ScriptSig (15 items): [preImage, pp2Out, ownerPK, changePkh, changeAmt,
  ///   ownerSig, scriptLHS, parentRawTxA, parentRawTxB, padding,
  ///   outCntA, outCntB, pp1FtIdxA, pp1FtIdxB]
  /// Altstack: [amount, flags, rabinPubKeyHash, tokenId, ownerPKH]
  ///
  /// Strategy: Phase 1 + 1b normalize altstack to [amount, tokenId] (matching FT).
  /// Phases 2-16 follow the FT merge pattern with RFT byte offsets.
  static void _emitMergeToken(ScriptBuilder b) {
    // --- Phase 1: Get ownerPKH, do P2PKH auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    // Stack (15 items):
    // idx: ownerPKH=0, pp1FtIdxB=1, pp1FtIdxA=2, outCntB=3, outCntA=4, pad=5,
    //      rawTxB=6, rawTxA=7, lhs=8, sig=9, chgAmt=10, chgPkh=11,
    //      ownerPK=12, pp2=13, preImg=14

    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // copy ownerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy ownerSig
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);           // copy ownerPK (shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 1b: Drain extra RFT altstack items, normalize ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);           // drop rabinPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // flags
    b.opCode(OpCodes.OP_DROP);           // drop flags
    // Alt: [merkleRoot, tokenSupply, amount]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // amount
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenSupply
    b.opCode(OpCodes.OP_DROP);           // drop tokenSupply
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merkleRoot
    b.opCode(OpCodes.OP_DROP);           // drop merkleRoot
    // Alt: [] — amount on main stack
    b.opCode(OpCodes.OP_TOALTSTACK);     // amount → alt
    // Stack: [..., ownerPKH, tokenId]. Alt: [amount]
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenId → alt
    // Stack (15): ownerPKH at top. Alt: [amount, tokenId]
    // *** Matches FT merge layout ***

    // --- Phase 2: Validate padding and parentRawTxA, parentRawTxB ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);           // copy padding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTxA
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTxB
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 3: Extract preImage fields ---
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt
    // Alt: [amount, tokenId, currentTxId]

    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt
    // Alt: [amount, tokenId, currentTxId, nLocktime]

    // --- Phase 4: checkPreimageOCS ---
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // preImage consumed. Stack (14 items):
    // idx: ownerPKH=0, pp1FtIdxB=1, pp1FtIdxA=2, outCntB=3, outCntA=4, pad=5,
    //      rawTxB=6, rawTxA=7, lhs=8, sig=9, chgAmt=10, chgPkh=11,
    //      ownerPK=12, pp2=13

    // --- Phase 5: Parse parentRawTxA outputs ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTxA
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy pp1FtIdxA

    b.opCode(OpCodes.OP_TOALTSTACK);     // stash pp1FtIdxA
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // get pp1FtIdxA
    PP1FtScriptGen.emitSkipNOutputs(b);

    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP2Script → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP3Script → alt
    // Alt: [..., nLocktime, PP1, PP2, PP3]

    // Compute metadataSkip = outCntA - 1 - pp1FtIdxA - 3
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);           // copy outCntA
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // copy pp1FtIdxA (shifted)
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_SUB);

    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentMetadata → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes
    // Alt: [..., nLocktime, PP1, PP2, PP3, metadata]

    // --- Phase 5b: Parse parentRawTxB → PP1_FTB ---
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTxB
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy pp1FtIdxB (shifted)

    b.opCode(OpCodes.OP_TOALTSTACK);     // stash pp1FtIdxB
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // get pp1FtIdxB
    PP1FtScriptGen.emitSkipNOutputs(b);

    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1ScriptB → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes
    // Alt: [..., nLocktime, PP1_A, PP2, PP3, metadata, PP1_B]

    // --- Phase 6: Validate metadata ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP1_B
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metadata
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [..., ownerPKH, PP1_B, metadata]

    // --- Phase 7: Verify amountA + amountB == this.amount and tokenIdA == tokenIdB ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP3
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP2
    b.opCode(OpCodes.OP_FROMALTSTACK);   // PP1_A
    // Stack: [..., ownerPKH, PP1_B, metadata, PP3, PP2, PP1_A]

    // Extract amountA from PP1_A[81:89] (RFT offsets)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, amountDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, amountDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // amountA

    // Extract amountB from PP1_B
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);           // copy PP1_B
    OpcodeHelpers.pushInt(b, amountDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, amountDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);         // amountB

    b.opCode(OpCodes.OP_ADD);             // amountA + amountB

    // Get this.amount and tokenId from altstack
    b.opCode(OpCodes.OP_FROMALTSTACK);    // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);    // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // amount (raw 8-byte LE)
    b.opCode(OpCodes.OP_BIN2NUM);

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // keep amount in alt
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL);            // move sumAmt to top
    b.opCode(OpCodes.OP_EQUALVERIFY);     // sumAmt == amount
    // Stack: [..., PP1_B, meta, PP3, PP2, PP1_A, nLock, curTxId, tokenId]

    // Verify tokenIdA == tokenIdB
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);           // copy PP1_A
    OpcodeHelpers.pushInt(b, tokenIdDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, tokenIdDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);

    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);           // copy PP1_B (deep)
    OpcodeHelpers.pushInt(b, tokenIdDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, tokenIdDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);

    b.opCode(OpCodes.OP_EQUALVERIFY);     // tokenIdA == tokenIdB

    b.opCode(OpCodes.OP_TOALTSTACK);      // tokenId → alt (to remove)
    // Stack: [..., ownerPKH, PP1_B, meta, PP3, PP2, PP1_A, nLock, curTxId]
    // Alt: [amount, tokenId]

    // --- Phase 8: Rebuild PP1_RFT from parentA template ---
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy PP1_A
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted +1)
    b.opCode(OpCodes.OP_FROMALTSTACK);    // tokenId
    b.opCode(OpCodes.OP_DROP);            // drop tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);    // amount
    _emitRebuildPP1Rft(b);
    // Stack: [..., PP1_A, nLock, curTxId, rebuiltPP1]

    // --- Phase 9: Build PP1 output (1 sat) ---
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 10: Rebuild PP3 from parentA template ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);            // copy PP3
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted +1)
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 11: Build metadata output (0 sats) ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy metadata
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 12: Build change output ---
    // Full stack (24 items):
    // idx: metaOut=0, pp3Out=1, pp1Out=2, curTxId=3, nLock=4, PP1_A=5,
    //      PP2=6, PP3=7, meta=8, PP1_B=9, ownerPKH=10, pp1FtIdxB=11,
    //      pp1FtIdxA=12, outCntB=13, outCntA=14, pad=15, rawTxB=16,
    //      rawTxA=17, lhs=18, sig=19, chgAmt=20, chgPkh=21, ownerPK=22, pp2=23
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_PICK);            // copy changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_PICK);            // copy changeAmt (shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 13: Reconstruct fullTx ---
    OpcodeHelpers.pushInt(b, 19);
    b.opCode(OpCodes.OP_PICK);            // copy scriptLHS

    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);             // lhs + varint(5)

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + changeOut

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash metaOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + pp1Out

    // Append pp2OutputBytes
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_CAT);             // + pp2Out

    b.opCode(OpCodes.OP_FROMALTSTACK);    // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // metaOut
    b.opCode(OpCodes.OP_CAT);

    // Append nLocktime
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);

    // --- Phase 14: Verify sha256(sha256(fullTx)) == currentTxId ---
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Remaining stack (19): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //   rawTxA, rawTxB, padding, outCntA, outCntB, pp1FtIdxA, pp1FtIdxB,
    //   ownerPKH, PP1_B, meta, PP3, PP2, PP1_A]
    // idx: PP1_A=0, PP2=1, PP3=2, meta=3, PP1_B=4, ownerPKH=5, ...

    // --- Phase 15: Validate PP2-FT ---
    b.opCode(OpCodes.OP_DROP);            // drop PP1_A
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);            // copy pp2OutOrig
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    PP1FtScriptGen.emitValidatePP2FT(b, 1, 2);

    // --- Phase 16: Verify outpoints against parent tx hashes ---
    b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP);
    // Top: rawTxB=0, rawTxA=1, lhs=2, sig=3, chgAmt=4, chgPkh=5, ownerPK=6, pp2=7

    b.opCode(OpCodes.OP_OVER);            // copy rawTxA
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);      // parentTxIdA → alt

    b.opCode(OpCodes.OP_DUP);             // copy rawTxB
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);      // parentTxIdB → alt

    b.opCode(OpCodes.OP_DROP);            // drop rawTxB
    b.opCode(OpCodes.OP_DROP);            // drop rawTxA

    b.opCode(OpCodes.OP_DUP);
    PP1FtScriptGen.emitReadOutpoint(b, 3);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);

    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxIdB
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxIdA
    b.opCode(OpCodes.OP_EQUALVERIFY);     // outpoint3_txId == parentTxIdA

    b.opCode(OpCodes.OP_SWAP);
    PP1FtScriptGen.emitReadOutpoint(b, 4);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_EQUALVERIFY);     // outpoint4_txId == parentTxIdB

    b.opCode(OpCodes.OP_1);               // leave TRUE
  }

  // =========================================================================
  // Merkle proof verification (unrolled 16-iteration loop)
  // =========================================================================

  /// Verifies a Merkle inclusion proof in-script.
  ///
  /// Entry stack (top→bottom): currentHash(32), merkleProof(N×32), merkleSides(N), merkleRoot(32)
  /// Exit: all 4 items consumed, script fails (via EQUALVERIFY) if proof invalid.
  ///
  /// Each iteration extracts one 32-byte sibling from proof and one 1-byte side
  /// from sides, concatenates in the correct order, and SHA256-hashes.
  /// Iterations where proof is empty are no-ops (IF skipped).
  /// After all iterations, verifies finalHash == merkleRoot.
  static void _emitVerifyMerkleProof(ScriptBuilder b) {
    for (var i = 0; i < 16; i++) {
      // Check if proof still has bytes
      b.opCode(OpCodes.OP_OVER);           // copy merkleProof
      b.opCode(OpCodes.OP_SIZE);
      b.opCode(OpCodes.OP_NIP);
      b.opCode(OpCodes.OP_0);
      b.opCode(OpCodes.OP_GREATERTHAN);
      b.opCode(OpCodes.OP_IF);

      // Extract 32-byte sibling from proof (SPLIT puts right/rest on top)
      b.opCode(OpCodes.OP_SWAP);           // [proof, hash, sides, root]
      OpcodeHelpers.pushInt(b, 32);
      b.opCode(OpCodes.OP_SPLIT);          // [restProof, sibling, hash, sides, root]
      b.opCode(OpCodes.OP_SWAP);           // [sibling, restProof, hash, sides, root]
      b.opCode(OpCodes.OP_ROT);            // [hash, sibling, restProof, sides, root]

      // Extract 1-byte side from sides
      b.opCode(OpCodes.OP_3);
      b.opCode(OpCodes.OP_ROLL);           // [sides, hash, sibling, restProof, root]
      b.opCode(OpCodes.OP_1);
      b.opCode(OpCodes.OP_SPLIT);          // [firstSide, restSides, hash, sibling, restProof, root]
      b.opCode(OpCodes.OP_TOALTSTACK);     // stash restSides
      b.opCode(OpCodes.OP_BIN2NUM);        // [sideNum, hash, sibling, restProof, root]

      // side!=0 (isLeft=true): sibling on left → sibling‖hash
      // side==0 (isLeft=false): sibling on right → hash‖sibling
      b.opCode(OpCodes.OP_IF);             // side!=0
        b.opCode(OpCodes.OP_CAT);          // [sibling‖hash, restProof, root]
      b.opCode(OpCodes.OP_ELSE);           // side==0
        b.opCode(OpCodes.OP_SWAP);         // [sibling, hash, restProof, root]
        b.opCode(OpCodes.OP_CAT);          // [hash‖sibling, restProof, root]
      b.opCode(OpCodes.OP_ENDIF);

      b.opCode(OpCodes.OP_SHA256);         // [newHash, restProof, root]
      b.opCode(OpCodes.OP_FROMALTSTACK);   // [restSides, newHash, restProof, root]
      b.opCode(OpCodes.OP_ROT);            // [restProof, restSides, newHash, root]
      b.opCode(OpCodes.OP_ROT);            // [newHash, restProof, restSides, root]

      b.opCode(OpCodes.OP_ENDIF);
    }

    // After all iterations: [finalHash, emptyProof, emptySides, merkleRoot]
    b.opCode(OpCodes.OP_NIP);              // remove emptyProof
    b.opCode(OpCodes.OP_NIP);              // remove emptySides
    b.opCode(OpCodes.OP_EQUALVERIFY);      // finalHash == merkleRoot
  }

  // =========================================================================
  // PP1_RFT rebuild helper
  // =========================================================================

  /// Rebuilds PP1_RFT by splicing new ownerPKH and amount into the 89-byte header.
  /// Pre: [parentScript, newPKH, newAmount]. Post: [rebuiltScript].
  ///
  /// Layout: parent[:1] + newPKH + parent[21:81] + num2bin(amount,8) + parent[89:]
  /// Middle section (bytes 21-80) = 60 bytes (tokenId + rabinPKH + flags pushdatas).
  static void _emitRebuildPP1Rft(ScriptBuilder b) {
    // Convert amount to 8-byte LE
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_NUM2BIN);         // [pp1S, pkh, amountBytes8]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash amountBytes8

    b.opCode(OpCodes.OP_SWAP);            // [pkh, pp1S]

    // Split at byte 1 (prefix)
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);
    // [pkh, prefix1, pp1S[1:]]

    // Skip old PKH (20 bytes)
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // [pkh, prefix1, pp1S[21:]]

    // Split off middle (bytes 21-80 = 60 bytes)
    OpcodeHelpers.pushInt(b, 60);
    b.opCode(OpCodes.OP_SPLIT);
    // [pkh, prefix1, middle60, pp1S[81:]]

    // Skip old amount (8 bytes)
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // [pkh, prefix1, middle60, suffix]  suffix = pp1S[89:]

    b.opCode(OpCodes.OP_TOALTSTACK);      // stash suffix
    // Alt: [amountBytes8, suffix]

    // Concatenate: prefix1 + newPKH + middle60
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash middle60
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // [prefix1+pkh]
    b.opCode(OpCodes.OP_FROMALTSTACK);    // middle60
    b.opCode(OpCodes.OP_CAT);             // [prefix1+pkh+middle60]

    // Alt: [amountBytes8, suffix] (bottom to top)
    // Pop suffix first (LIFO), then amountBytes8
    b.opCode(OpCodes.OP_FROMALTSTACK);    // suffix
    b.opCode(OpCodes.OP_FROMALTSTACK);    // amountBytes8
    b.opCode(OpCodes.OP_SWAP);
    // [(prefix1+pkh+middle60), amountBytes8, suffix]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash suffix
    b.opCode(OpCodes.OP_CAT);             // (prefix1+pkh+middle60) + amountBytes8
    b.opCode(OpCodes.OP_FROMALTSTACK);    // suffix
    b.opCode(OpCodes.OP_CAT);             // full rebuilt PP1_RFT
  }
}
