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

/// Generates the complete PP1_AT (Appendable Token) locking script.
///
/// A loyalty/stamp card token with dual authority (issuer + owner),
/// append-only rolling hash, and threshold-based redemption.
///
/// Constructor param layout (139-byte header):
/// ```
/// Byte 0:        0x14 (pushdata 20)
/// Bytes 1-20:    ownerPKH (customer)
/// Byte 21:       0x20 (pushdata 32)
/// Bytes 22-53:   tokenId
/// Byte 54:       0x14 (pushdata 20)
/// Bytes 55-74:   issuerPKH (shop)
/// Byte 75:       0x14 (pushdata 20)
/// Bytes 76-95:   rabinPubKeyHash (identity anchor)
/// Byte 96:       0x04 (pushdata 4)
/// Bytes 97-100:  stampCount (4-byte LE, mutable)
/// Byte 101:      0x04 (pushdata 4)
/// Bytes 102-105: threshold (4-byte LE, immutable)
/// Byte 106:      0x20 (pushdata 32)
/// Bytes 107-138: stampsHash (rolling SHA256, mutable)
/// Byte 139:      start of script body
/// ```
///
/// Dispatch selectors:
/// - OP_4 = burn (cheapest, P2PKH only, owner signs)
/// - OP_0 = issueToken (issuer signs, hashPrevouts check)
/// - OP_1 = stampToken (issuer signs, inductive proof, rolling hash)
/// - OP_2 = redeemToken (owner signs, threshold check, burns token)
/// - OP_3 = transferToken (owner signs, inductive proof, changes ownerPKH)
class PP1AtScriptGen {

  // --- Byte offset constants ---
  static const int pkhDataStart = 1;
  static const int pkhDataEnd = 21;
  static const int tokenIdDataStart = 22;
  static const int tokenIdDataEnd = 54;
  static const int issuerPKHDataStart = 55;
  static const int issuerPKHDataEnd = 75;
  static const int rabinPKHDataStart = 76;
  static const int rabinPKHDataEnd = 96;
  static const int stampCountDataStart = 97;
  static const int stampCountDataEnd = 101;
  static const int thresholdDataStart = 102;
  static const int thresholdDataEnd = 106;
  static const int stampsHashDataStart = 107;
  static const int stampsHashDataEnd = 139;
  static const int scriptBodyStart = 139;

  // PP2 NFT compiled byte offsets (same as PP1NftScriptGen / PP1RnftScriptGen)
  static const int pp2FundingOutpointStart = 117;
  static const int pp2WitnessChangePKHStart = 154;
  static const int pp2ChangeAmountStart = 175;
  static const int pp2OwnerPKHStart = 176;
  static const int pp2ScriptCodeStart = 197;

  /// Generates the complete PP1_AT locking script.
  static SVScript generate({
    required List<int> ownerPKH,
    required List<int> tokenId,
    required List<int> issuerPKH,
    required List<int> rabinPubKeyHash,
    required int stampCount,
    required int threshold,
    required List<int> stampsHash,
  }) {
    var b = ScriptBuilder();

    // Push constructor params as data
    b.addData(Uint8List.fromList(ownerPKH));        // 0x14 + 20 bytes
    b.addData(Uint8List.fromList(tokenId));          // 0x20 + 32 bytes
    b.addData(Uint8List.fromList(issuerPKH));        // 0x14 + 20 bytes
    b.addData(Uint8List.fromList(rabinPubKeyHash));  // 0x14 + 20 bytes

    // stampCount as 4-byte LE (avoids dartsv addData single-byte OP_N mapping)
    var stampCountBytes = Uint8List(4);
    stampCountBytes[0] = stampCount & 0xFF;
    stampCountBytes[1] = (stampCount >> 8) & 0xFF;
    stampCountBytes[2] = (stampCount >> 16) & 0xFF;
    stampCountBytes[3] = (stampCount >> 24) & 0xFF;
    b.addData(stampCountBytes);                      // 0x04 + 4 bytes

    // threshold as 4-byte LE
    var thresholdBytes = Uint8List(4);
    thresholdBytes[0] = threshold & 0xFF;
    thresholdBytes[1] = (threshold >> 8) & 0xFF;
    thresholdBytes[2] = (threshold >> 16) & 0xFF;
    thresholdBytes[3] = (threshold >> 24) & 0xFF;
    b.addData(thresholdBytes);                       // 0x04 + 4 bytes

    b.addData(Uint8List.fromList(stampsHash));       // 0x20 + 32 bytes

    // Move constructor params to altstack (LIFO order)
    // Push order: stampsHash last → first to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);   // stampsHash
    b.opCode(OpCodes.OP_TOALTSTACK);   // threshold
    b.opCode(OpCodes.OP_TOALTSTACK);   // stampCount
    b.opCode(OpCodes.OP_TOALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_TOALTSTACK);   // issuerPKH
    b.opCode(OpCodes.OP_TOALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_TOALTSTACK);   // ownerPKH
    // Altstack bottom→top:
    //   [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
    // Pop order: ownerPKH, tokenId, issuerPKH, rabinPubKeyHash, stampCount, threshold, stampsHash

    _emitDispatch(b);
    return b.build();
  }

  // =========================================================================
  // Dispatch
  // =========================================================================

  static void _emitDispatch(ScriptBuilder b) {
    // Check for OP_4 (burn) first — cheapest path
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_DROP);
      _emitBurnToken(b);
    b.opCode(OpCodes.OP_ELSE);
      // Check for OP_0 (issue)
      b.opCode(OpCodes.OP_DUP);
      b.opCode(OpCodes.OP_NOTIF);
        b.opCode(OpCodes.OP_DROP);
        _emitIssueToken(b);
      b.opCode(OpCodes.OP_ELSE);
        // Check for OP_1 (stamp)
        b.opCode(OpCodes.OP_DUP);
        b.opCode(OpCodes.OP_1);
        b.opCode(OpCodes.OP_EQUAL);
        b.opCode(OpCodes.OP_IF);
          b.opCode(OpCodes.OP_DROP);
          _emitStampToken(b);
        b.opCode(OpCodes.OP_ELSE);
          // Check for OP_2 (redeem) vs OP_3 (transfer)
          b.opCode(OpCodes.OP_DUP);
          b.opCode(OpCodes.OP_2);
          b.opCode(OpCodes.OP_EQUAL);
          b.opCode(OpCodes.OP_IF);
            b.opCode(OpCodes.OP_DROP);
            _emitRedeemToken(b);
          b.opCode(OpCodes.OP_ELSE);
            // Must be OP_3 (transfer)
            b.opCode(OpCodes.OP_DROP);
            _emitTransferToken(b);
          b.opCode(OpCodes.OP_ENDIF);
        b.opCode(OpCodes.OP_ENDIF);
      b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // burnToken (selector=4)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig]
  /// Altstack: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
  static void _emitBurnToken(ScriptBuilder b) {
    // Drain altstack: keep ownerPKH, drop everything else
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // issuerPKH
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // stampCount
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // threshold
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // stampsHash
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
  // redeemToken (selector=2)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig]
  /// Altstack: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
  ///
  /// Burn-redeem: verifies stampCount >= threshold, then P2PKH auth.
  static void _emitRedeemToken(ScriptBuilder b) {
    // Drain altstack: keep ownerPKH, stampCount, threshold
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // issuerPKH
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // rabinPubKeyHash
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // stampCount
    b.opCode(OpCodes.OP_FROMALTSTACK);   // threshold
    b.opCode(OpCodes.OP_FROMALTSTACK);   // stampsHash
    b.opCode(OpCodes.OP_DROP);
    // Stack: [ownerPubKey, ownerSig, ownerPKH, stampCount, threshold]

    // Threshold check: stampCount >= threshold
    // => threshold <= stampCount => swap and use LESSTHANOREQUAL
    b.opCode(OpCodes.OP_BIN2NUM);        // threshold as number
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_BIN2NUM);        // stampCount as number
    // Stack: [ownerPubKey, ownerSig, ownerPKH, thresholdNum, stampCountNum]
    b.opCode(OpCodes.OP_LESSTHANOREQUAL); // threshold <= stampCount
    b.opCode(OpCodes.OP_VERIFY);
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
  // issueToken (selector=0)
  // =========================================================================

  /// Stack: [preImage, fundingOutpoint, witnessPadding, issuerPubKey, issuerSig,
  ///         rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey]
  /// Altstack: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
  static void _emitIssueToken(ScriptBuilder b) {
    // Stack (10 items, top=0):
    //   ed25519PubKey=0, identityTxId=1, rabinPadding=2, rabinS=3, rabinN=4,
    //   issuerSig=5, issuerPubKey=6, witnessPadding=7, fundingOutpoint=8, preImage=9

    // --- Phase 1: Validate witnessPadding length ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);           // copy witnessPadding (idx 7)
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Phase 2: Pop ownerPKH (drop), pop tokenId (keep for Rabin binding) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // ownerPKH -> drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // tokenId -> keep on main stack
    // Alt: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH]
    // Stack (11 items):
    //   tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3, rabinS=4,
    //   rabinN=5, issuerSig=6, issuerPubKey=7, witnessPadding=8, fundingOutpoint=9, preImage=10

    // --- Phase 3: Verify hash160(issuerPubKey) == issuerPKH ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // issuerPKH
    // Stack (12): issuerPKH=0, tokenId=1, ed25519PubKey=2, identityTxId=3,
    //   rabinPadding=4, rabinS=5, rabinN=6, issuerSig=7, issuerPubKey=8,
    //   witnessPadding=9, fundingTxId=10, preImage=11
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);           // copy issuerPubKey (idx 8)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);    // hash160(issuerPK) == issuerPKH; both consumed
    // Stack (11): tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3,
    //   rabinS=4, rabinN=5, issuerSig=6, issuerPubKey=7, witnessPadding=8,
    //   fundingTxId=9, preImage=10

    // --- Phase 3b: CHECKSIG for issuer ---
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);          // copy issuerSig (idx 6)
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);          // copy issuerPubKey (shifted +1 to idx 8)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (11): tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3,
    //   rabinS=4, rabinN=5, issuerSig=6, issuerPubKey=7, witnessPadding=8,
    //   fundingTxId=9, preImage=10

    // --- Phase 3c: Verify hash160(rabinN) == rabinPubKeyHash ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // rabinPubKeyHash
    // Stack (12): rabinPKH=0, tokenId=1, ed25519PubKey=2, identityTxId=3,
    //   rabinPadding=4, rabinS=5, rabinN=6, issuerSig=7, issuerPubKey=8,
    //   witnessPadding=9, fundingTxId=10, preImage=11
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);           // copy rabinN (idx 6)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);    // hash160(rabinN) == rabinPKH; both consumed
    // Stack (11): tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3,
    //   rabinS=4, rabinN=5, issuerSig=6, issuerPubKey=7, witnessPadding=8,
    //   fundingTxId=9, preImage=10

    // --- Phase 4: Drain remaining altstack (stampCount, threshold, stampsHash) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);  // stampCount -> drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // threshold -> drop
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // stampsHash -> drop
    b.opCode(OpCodes.OP_DROP);
    // Alt: [] (empty)

    // --- Phase 5: Rabin signature verification ---
    // Compute sha256(identityTxId || ed25519PubKey || tokenId) as positive script number
    // Stack: tokenId=0, ed25519PubKey=1, identityTxId=2, rabinPadding=3,
    //   rabinS=4, rabinN=5, issuerSig=6, issuerPubKey=7, witnessPadding=8,
    //   fundingTxId=9, preImage=10
    b.opCode(OpCodes.OP_ROT);           // brings identityTxId to top
    b.opCode(OpCodes.OP_ROT);           // brings ed25519PubKey to top
    // Stack: ed25519PubKey=0, identityTxId=1, tokenId=2, rabinPadding=3, ...
    b.opCode(OpCodes.OP_CAT);           // identityTxId||ed25519PubKey
    b.opCode(OpCodes.OP_SWAP);          // tokenId on top
    b.opCode(OpCodes.OP_CAT);           // (identityTxId||ed25519PubKey)||tokenId
    b.opCode(OpCodes.OP_SHA256);         // raw hash (32 bytes)
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);        // hashNum (positive script number)
    // Stack: hashNum=0, rabinPadding=1, rabinS=2, rabinN=3,
    //   issuerSig=4, issuerPubKey=5, witnessPadding=6, fundingOutpoint=7, preImage=8

    // Rabin verify: s^2 mod n == hashNum + rabinPadding
    b.opCode(OpCodes.OP_SWAP);           // [rabinPadding, hashNum, rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_ADD);            // [(hashNum+padding), rabinS, rabinN, ...]
    b.opCode(OpCodes.OP_SWAP);           // [rabinS, (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_MUL);            // [s^2, (h+p), rabinN, ...]
    b.opCode(OpCodes.OP_ROT);            // [rabinN, s^2, (h+p), ...]
    b.opCode(OpCodes.OP_MOD);            // [(s^2 mod n), (h+p), ...]
    b.opCode(OpCodes.OP_NUMEQUALVERIFY); // verified!
    // Stack: [issuerSig, issuerPubKey, witnessPadding, fundingOutpoint, preImage]

    // --- Phase 6: Drop issuerSig, issuerPubKey, witnessPadding ---
    b.opCode(OpCodes.OP_DROP);          // issuerSig
    b.opCode(OpCodes.OP_DROP);          // issuerPubKey
    b.opCode(OpCodes.OP_DROP);          // witnessPadding
    // Stack: [fundingOutpoint, preImage]

    // --- Phase 7: checkPreimageOCS + hashPrevouts ---
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

    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);          // copy currentTxId
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);           // pp1Outpoint

    b.opCode(OpCodes.OP_CAT);           // fundingOutpoint + pp1Outpoint

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
  // stampToken (selector=1) — THE NOVEL OPERATION
  // =========================================================================

  /// Stack: [preImage, pp2Out, issuerPK, changePkh, changeAmt, issuerSig,
  ///         scriptLHS, parentRawTx, padding, stampMetadata]
  /// Altstack: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
  ///
  /// Rolling hash is computed from parent PP1 script (extracted from parentRawTx):
  ///   newStamp = SHA256(stampMetadata)
  ///   newStampsHash = SHA256(parentStampsHash || newStamp)
  ///   newStampCount = parentStampCount + 1
  static void _emitStampToken(ScriptBuilder b) {
    // --- Phase 1: Issuer auth ---
    // Drain ownerPKH, tokenId, and rabinPubKeyHash (not needed for stamp auth)
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH]

    b.opCode(OpCodes.OP_FROMALTSTACK);   // issuerPKH
    // Stack (11): [preImage, pp2Out, issuerPK, changePkh, changeAmt, issuerSig,
    //              scriptLHS, parentRawTx, padding, stampMetadata, issuerPKH]
    // idx: issuerPKH=0, stampMeta=1, pad=2, rawTx=3, lhs=4, sig=5,
    //      chgAmt=6, chgPkh=7, issuerPK=8, pp2=9, preImg=10

    // hash160(issuerPK) == issuerPKH
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);           // copy issuerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // copy issuerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // CHECKSIG(issuerSig, issuerPK)
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);           // copy issuerSig
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy issuerPK (shifted +1 by sig push)
    b.opCode(OpCodes.OP_CHECKSIG);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (11): [..., stampMetadata, issuerPKH]
    // Alt: [stampsHash, threshold, stampCount, rabinPubKeyHash]

    // Drop issuerPKH (no longer needed)
    b.opCode(OpCodes.OP_DROP);
    // Stack (10): [preImage, pp2Out, issuerPK, changePkh, changeAmt, issuerSig,
    //              scriptLHS, parentRawTx, padding, stampMetadata]
    // idx: stampMeta=0, pad=1, rawTx=2, lhs=3, sig=4, chgAmt=5,
    //      chgPkh=6, issuerPK=7, pp2=8, preImg=9

    // --- Phase 1b: Drain remaining altstack items ---
    // Alt: [stampsHash, threshold, stampCount, rabinPubKeyHash]
    // Pop order (LIFO): rabinPubKeyHash, stampCount, threshold, stampsHash
    // These are not needed — rolling hash will be computed from parentPP1Script.
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // rabinPubKeyHash
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // stampCount
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // threshold
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // stampsHash
    // Alt: [] (empty)
    // Stack (10): [preImage, pp2Out, issuerPK, changePkh, changeAmt, issuerSig,
    //              scriptLHS, parentRawTx, padding, stampMetadata]
    // idx: stampMeta=0, pad=1, rawTx=2, lhs=3, sig=4, chgAmt=5,
    //      chgPkh=6, issuerPK=7, pp2=8, preImg=9
    // (Same layout as transfer with stampMetadata at idx 0 = ownerPKH position)

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
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId -> alt

    // Extract nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime -> alt

    // --- Phase 4: checkPreimageOCS ---
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_ROLL);           // ROLL preImage to top
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // preImage consumed. Stack (9):
    // [pp2Out, issuerPK, changePkh, changeAmt, issuerSig, scriptLHS,
    //  parentRawTx, padding, stampMetadata]
    // idx: stampMeta=0, pad=1, rawTx=2, lhs=3, sig=4, chgAmt=5,
    //      chgPkh=6, issuerPK=7, pp2=8

    // --- Phase 5: Parse parentRawTx outputs ---
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP2Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP3Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentMetadataScript -> alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes

    // --- Phase 6: Validate metadata starts with 006a ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentMetadataScript
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // --- Phase 7: Get parent scripts from altstack ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP3Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP2Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP1Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Stack (15): [pp2Out, issuerPK, changePkh, changeAmt, issuerSig, scriptLHS,
    //              parentRawTx, padding, stampMetadata,
    //              metadataS, pp3S, pp2S, pp1S, nLocktime, currentTxId]
    // Alt: [] (empty)
    // idx: currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //      stampMeta=6, pad=7, rawTx=8, lhs=9, sig=10, chgAmt=11,
    //      chgPkh=12, issuerPK=13, pp2Out=14

    // --- Phase 8: Compute rolling hash from parent PP1 and rebuild ---
    // Step 1: Compute newStamp = SHA256(stampMetadata)
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_PICK);            // copy stampMetadata
    b.opCode(OpCodes.OP_SHA256);          // newStamp
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash newStamp

    // Step 2: Extract parentStampsHash from pp1S[86:118]
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S
    OpcodeHelpers.pushInt(b, scriptBodyStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, stampsHashDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack (16): [..., parentStampsHash]

    // Step 3: Compute newStampsHash = SHA256(parentStampsHash || newStamp)
    b.opCode(OpCodes.OP_FROMALTSTACK);    // newStamp
    b.opCode(OpCodes.OP_CAT);             // parentStampsHash || newStamp
    b.opCode(OpCodes.OP_SHA256);          // newStampsHash
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash newStampsHash

    // Step 4: Extract parentStampCount from pp1S[76:80], compute newStampCount
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S (nothing added to main stack)
    OpcodeHelpers.pushInt(b, stampCountDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, stampCountDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack (16): [..., parentStampCount4LE]
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_1ADD);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_NUM2BIN);         // newStampCount4LE
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash newStampCount4LE
    // Alt: [newStampsHash, newStampCount4LE]
    // Stack (15): same as before Phase 8

    // Step 5: Get pp1S and pop new values for rebuild
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);    // newStampCount4LE (LIFO top)
    b.opCode(OpCodes.OP_FROMALTSTACK);    // newStampsHash
    // Stack (18): [..., pp1S_copy, newStampCount4LE, newStampsHash]
    // = [pp1S, newSC, newSH] as expected by _emitRebuildPP1AtStamp
    _emitRebuildPP1AtStamp(b);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // --- Phase 9: Build PP1 output (1 sat) ---
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (16): [..., nLocktime, currentTxId, pp1Out]
    // idx: pp1Out=0, currentTxId=1, nLocktime=2, pp1S=3, pp2S=4, pp3S=5,
    //      metaS=6, stampMeta=7, pad=8, rawTx=9, lhs=10, sig=11,
    //      chgAmt=12, chgPkh=13, issuerPK=14, pp2Out=15

    // --- Phase 10: Build PP3 output (no rebuild for stamp) ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);            // copy pp3S (unchanged)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (17): [..., pp1Out, pp3Out]

    // --- Phase 11: Build metadata output (0 sats) ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy metadataScript
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (18): [..., pp1Out, pp3Out, metaOut]

    // --- Phase 12: Build change output ---
    // idx: metaOut=0, pp3Out=1, pp1Out=2, currentTxId=3, nLocktime=4,
    //      pp1S=5, pp2S=6, pp3S=7, metaS=8, stampMeta=9,
    //      pad=10, rawTx=11, lhs=12, sig=13, chgAmt=14, chgPkh=15,
    //      issuerPK=16, pp2Out=17
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changeAmt (shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (19): [..., pp1Out, pp3Out, metaOut, changeOut]

    // --- Phase 13: Reconstruct fullTx ---
    // fullTx = scriptLHS + varint(5) + changeOut + pp1Out + pp2Out + pp3Out + metaOut + nLocktime
    // idx: changeOut=0, metaOut=1, pp3Out=2, pp1Out=3, currentTxId=4, nLocktime=5,
    //      pp1S=6, pp2S=7, pp3S=8, metaS=9, stampMeta=10,
    //      pad=11, rawTx=12, lhs=13, sig=14, chgAmt=15, chgPkh=16,
    //      issuerPK=17, pp2Out=18
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);            // copy scriptLHS
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);             // lhs + varint(5)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + changeOut

    b.opCode(OpCodes.OP_SWAP);            // [..., pp3Out, (lhs+..), metaOut]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash metaOut
    b.opCode(OpCodes.OP_SWAP);            // [..., pp1Out, (lhs+..), pp3Out]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + pp1Out

    // Append pp2OutputBytes
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy pp2Out
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_FROMALTSTACK);    // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // metaOut
    b.opCode(OpCodes.OP_CAT);

    // Append nLocktime
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);
    // Stack: [..., currentTxId, fullTx]

    // --- Phase 14: Verify sha256(sha256(fullTx)) == currentTxId ---
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack (13): [pp2Out, issuerPK, changePkh, changeAmt, issuerSig, scriptLHS,
    //              parentRawTx, padding, stampMetadata, metaS, pp3S, pp2S, pp1S]

    // --- Phase 15: Validate PP2 (NFT) ---
    // idx: pp1S=0, pp2S=1, pp3S=2, metaS=3, stampMeta=4, pad=5, rawTx=6,
    //      lhs=7, sig=8, chgAmt=9, chgPkh=10, issuerPK=11, pp2Out=12
    b.opCode(OpCodes.OP_DROP);            // drop pp1S
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);            // copy pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // --- Phase 16: Verify outpoint[2][:32] == sha256(sha256(parentRawTx)) ---
    // Stack after PP2 validation:
    // idx: pp3S=0, metaS=1, stampMeta=2, pad=3, rawTx=4, lhs=5, ...
    b.opCode(OpCodes.OP_DROP); // drop pp3S
    b.opCode(OpCodes.OP_DROP); // drop metaS
    b.opCode(OpCodes.OP_DROP); // drop stampMetadata
    b.opCode(OpCodes.OP_DROP); // drop padding

    b.opCode(OpCodes.OP_DUP);             // copy parentRawTx
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);           // parentTxId
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash parentTxId

    b.opCode(OpCodes.OP_DROP);            // drop parentRawTx
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxId
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_1);               // leave TRUE
  }

  // =========================================================================
  // transferToken (selector=3)
  // =========================================================================

  /// Stack: [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
  ///         scriptLHS, parentRawTx, padding]
  /// Altstack: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId, ownerPKH]
  static void _emitTransferToken(ScriptBuilder b) {
    // --- Phase 1: Get ownerPKH, do P2PKH auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    // Stack (10 items):
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

    // Alt: [stampsHash, threshold, stampCount, rabinPubKeyHash, issuerPKH, tokenId]
    // These are all immutable and carried forward by the inductive proof.
    // Leave them on altstack; drain after Phase 16.

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
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId -> alt

    // Extract nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // copy preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime -> alt

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
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // copy parentRawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP1Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP2Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentPP3Script -> alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentMetadataScript -> alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining tx bytes

    // --- Phase 6: Validate metadata starts with 006a ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentMetadataScript
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // --- Phase 7: Get parent scripts from altstack ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP3Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP2Script
    b.opCode(OpCodes.OP_FROMALTSTACK);   // parentPP1Script
    // Stack (13): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //              parentRawTx, padding, ownerPKH,
    //              metadataScript, pp3Script, pp2Script, pp1Script]

    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Stack (15):
    // idx: currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //      ownerPKH=6, pad=7, rawTx=8, lhs=9, sig=10, chgAmt=11,
    //      chgPkh=12, ownerPK=13, pp2Out=14

    // --- Phase 8: Rebuild PP1_AT from parent template ---
    // Only ownerPKH changes on transfer: parent[:1] + newPKH + parent[21:]
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);            // copy pp1S
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted +1)
    _emitRebuildPP1AtOwnerOnly(b);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // --- Phase 9: Build PP1 output (1 sat) ---
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 10: Rebuild PP3 from parent template ---
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_PICK);            // copy pp3S
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_PICK);            // copy ownerPKH (shifted)
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 11: Build metadata output (0 sats) ---
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_PICK);            // copy metadataScript
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 12: Build change output ---
    // Stack (18): [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //              parentRawTx, padding, ownerPKH,
    //              metaS, pp3S, pp2S, pp1S, nLocktime, currentTxId,
    //              pp1Out, pp3Out, metaOut]
    // idx: metaOut=0, pp3Out=1, pp1Out=2, currentTxId=3, nLocktime=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, ownerPKH=9,
    //   pad=10, rawTx=11, lhs=12, sig=13, chgAmt=14, chgPkh=15,
    //   ownerPK=16, pp2Out=17
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy changeAmt (shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);

    // --- Phase 13: Reconstruct fullTx ---
    // idx: changeOut=0, metaOut=1, pp3Out=2, pp1Out=3, currentTxId=4, nLocktime=5,
    //   pp1S=6, pp2S=7, pp3S=8, metaS=9, ownerPKH=10,
    //   pad=11, rawTx=12, lhs=13, sig=14, chgAmt=15, chgPkh=16,
    //   ownerPK=17, pp2Out=18
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);            // copy scriptLHS
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);             // lhs + varint(5)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + changeOut

    b.opCode(OpCodes.OP_SWAP);            // [..., pp3Out, (lhs+..), metaOut]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash metaOut
    b.opCode(OpCodes.OP_SWAP);            // [..., pp1Out, (lhs+..), pp3Out]
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);             // + pp1Out

    // Append pp2OutputBytes
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);            // copy pp2Out
    b.opCode(OpCodes.OP_CAT);

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

    // --- Phase 15: Validate PP2 (NFT) ---
    // Stack: [pp2Out, ownerPK, changePkh, changeAmt, ownerSig, scriptLHS,
    //         parentRawTx, padding, ownerPKH,
    //         metaS, pp3S, pp2S, pp1S]
    b.opCode(OpCodes.OP_DROP);            // drop pp1S
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);            // copy pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // --- Phase 16: Verify outpoint[2][:32] == sha256(sha256(parentRawTx)) ---
    b.opCode(OpCodes.OP_DROP); // drop pp3S
    b.opCode(OpCodes.OP_DROP); // drop metaS
    b.opCode(OpCodes.OP_DROP); // drop ownerPKH
    b.opCode(OpCodes.OP_DROP); // drop padding

    b.opCode(OpCodes.OP_DUP);             // copy parentRawTx
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);           // parentTxId
    b.opCode(OpCodes.OP_TOALTSTACK);      // stash parentTxId

    b.opCode(OpCodes.OP_DROP);            // drop parentRawTx
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // parentTxId
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Clean up main stack residuals: [pp2Out, ownerPK, changePkh, changeAmt, ownerSig]
    b.opCode(OpCodes.OP_DROP);            // ownerSig
    b.opCode(OpCodes.OP_DROP);            // changeAmt
    b.opCode(OpCodes.OP_DROP);            // changePkh
    b.opCode(OpCodes.OP_DROP);            // ownerPK
    b.opCode(OpCodes.OP_DROP);            // pp2Out

    // Clean up alt: drain tokenId, issuerPKH, rabinPubKeyHash, stampCount, threshold, stampsHash
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // issuerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // rabinPubKeyHash
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // stampCount
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // threshold
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // stampsHash

    b.opCode(OpCodes.OP_1);               // leave TRUE
  }

  // =========================================================================
  // Script rebuild helpers
  // =========================================================================

  /// Rebuild PP1_AT script with only ownerPKH changed (for transfer).
  /// Pre: [parentPP1AtScript, newOwnerPKH]. Post: [rebuiltScript].
  /// Layout: parent[:1] + newPKH + parent[21:]
  static void _emitRebuildPP1AtOwnerOnly(ScriptBuilder b) {
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

  /// Rebuild PP1_AT script with stampCount and stampsHash changed (for stamp).
  /// Pre: [parentPP1AtScript, newStampCount4LE, newStampsHash]. Post: [rebuiltScript].
  /// Layout: parent[0:97] + newStampCount + parent[101:107] + newStampsHash + parent[139:]
  static void _emitRebuildPP1AtStamp(ScriptBuilder b) {
    // Stack: [pp1S, newSC, newSH]
    // Goal: pp1S[0:97] + newSC + pp1S[101:107] + newSH + pp1S[139:]

    // Step 1: Bring pp1S to top for splitting
    b.opCode(OpCodes.OP_ROT);           // [newSC, newSH, pp1S]

    // Step 2: Split at byte 97
    OpcodeHelpers.pushInt(b, stampCountDataStart);
    b.opCode(OpCodes.OP_SPLIT);          // [newSC, newSH, prefix97, rest]

    // Step 3: Skip old stampCount (4 bytes)
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT);          // [newSC, newSH, prefix97, oldSC4, rest2]
    b.opCode(OpCodes.OP_NIP);            // [newSC, newSH, prefix97, rest2]

    // Step 4: Extract middle6 (bytes 101-106: 0x04 + threshold(4) + 0x20)
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_SPLIT);          // [newSC, newSH, prefix97, middle6, rest3]

    // Step 5: Skip old stampsHash (32 bytes) to get suffix
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT);          // [newSC, newSH, prefix97, middle6, oldSH32, suffix]
    b.opCode(OpCodes.OP_NIP);            // [newSC, newSH, prefix97, middle6, suffix]

    // Step 6: Reassemble using altstack
    // Need: prefix97 + newSC + middle6 + newSH + suffix
    // Stack b→t: newSC, newSH, prefix97, middle6, suffix
    b.opCode(OpCodes.OP_TOALTSTACK);     // stash suffix       alt:[suffix]
    // ROT top 3: (newSH, prefix97, middle6) -> (prefix97, middle6, newSH)
    b.opCode(OpCodes.OP_ROT);            // [newSC, prefix97, middle6, newSH]
    b.opCode(OpCodes.OP_TOALTSTACK);     // stash newSH         alt:[suffix, newSH]
    // ROT top 3: (newSC, prefix97, middle6) -> (prefix97, middle6, newSC)
    b.opCode(OpCodes.OP_ROT);            // [prefix97, middle6, newSC]
    b.opCode(OpCodes.OP_SWAP);           // [prefix97, newSC, middle6]
    b.opCode(OpCodes.OP_TOALTSTACK);     // stash middle6       alt:[suffix, newSH, middle6]
    // Stack: [prefix97, newSC]
    b.opCode(OpCodes.OP_CAT);            // [prefix97+newSC]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // middle6 (LIFO top)  alt:[suffix, newSH]
    b.opCode(OpCodes.OP_CAT);            // [prefix97+newSC+middle6]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // newSH (LIFO top)    alt:[suffix]
    b.opCode(OpCodes.OP_CAT);            // [prefix97+newSC+middle6+newSH]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // suffix (LIFO top)   alt:[]
    b.opCode(OpCodes.OP_CAT);            // [prefix97+newSC+middle6+newSH+suffix]
  }

  /// Validate PP2 (NFT) output script structure against parent template.
  /// Pre: [pp2Script, parentPP2Script] (parent on top). Post: [].
  static void _emitValidatePP2NFT(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);

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
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);            // drop pp2Script
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart - pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_FROMALTSTACK);    // variableParams
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_DROP);
  }
}
