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

/// Generates the complete PP1_SM (State Machine) locking script.
///
/// Constructor param layout (140-byte header):
/// ```
/// [0:1]     0x14  [1:21]    ownerPKH (mutable)
/// [21:22]   0x20  [22:54]   tokenId (immutable)
/// [54:55]   0x14  [55:75]   merchantPKH (immutable)
/// [75:76]   0x14  [76:96]   customerPKH (immutable)
/// [96:97]   0x01  [97:98]   currentState (mutable)
/// [98:99]   0x01  [99:100]  milestoneCount (mutable)
/// [100:101] 0x20  [101:133] commitmentHash (mutable)
/// [133:134] 0x01  [134:135] transitionBitmask (immutable)
/// [135:136] 0x04  [136:140] timeoutDelta (immutable)
/// [140:]    script body (immutable)
/// ```
///
/// Dispatch: OP_6=burn, OP_0=create, OP_1=enroll, OP_2=confirm,
///           OP_3=convert, OP_4=settle, OP_5=timeout
class PP1SmScriptGen {

  static const int pkhDataStart = 1;
  static const int pkhDataEnd = 21;
  static const int tokenIdDataStart = 22;
  static const int tokenIdDataEnd = 54;
  static const int merchantPKHDataStart = 55;
  static const int merchantPKHDataEnd = 75;
  static const int customerPKHDataStart = 76;
  static const int customerPKHDataEnd = 96;
  static const int currentStateDataStart = 97;
  static const int currentStateDataEnd = 98;
  static const int milestoneCountDataStart = 99;
  static const int milestoneCountDataEnd = 100;
  static const int commitmentHashDataStart = 101;
  static const int commitmentHashDataEnd = 133;
  static const int transitionBitmaskDataStart = 134;
  static const int transitionBitmaskDataEnd = 135;
  static const int timeoutDeltaDataStart = 136;
  static const int timeoutDeltaDataEnd = 140;
  static const int scriptBodyStart = 140;

  static const int pp2FundingOutpointStart = 117;
  static const int pp2WitnessChangePKHStart = 154;
  static const int pp2ChangeAmountStart = 175;
  static const int pp2OwnerPKHStart = 176;
  static const int pp2ScriptCodeStart = 197;

  static SVScript generate({
    required List<int> ownerPKH,
    required List<int> tokenId,
    required List<int> merchantPKH,
    required List<int> customerPKH,
    required int currentState,
    required int milestoneCount,
    required List<int> commitmentHash,
    required int transitionBitmask,
    required int timeoutDelta,
  }) {
    var b = ScriptBuilder();

    b.addData(Uint8List.fromList(ownerPKH));
    b.addData(Uint8List.fromList(tokenId));
    b.addData(Uint8List.fromList(merchantPKH));
    b.addData(Uint8List.fromList(customerPKH));
    _addRawByte(b, currentState & 0xFF);
    _addRawByte(b, milestoneCount & 0xFF);
    b.addData(Uint8List.fromList(commitmentHash));
    _addRawByte(b, transitionBitmask & 0xFF);

    var tdBytes = Uint8List(4);
    tdBytes[0] = timeoutDelta & 0xFF;
    tdBytes[1] = (timeoutDelta >> 8) & 0xFF;
    tdBytes[2] = (timeoutDelta >> 16) & 0xFF;
    tdBytes[3] = (timeoutDelta >> 24) & 0xFF;
    b.addData(tdBytes);

    // Move to altstack (LIFO)
    for (var i = 0; i < 9; i++) {
      b.opCode(OpCodes.OP_TOALTSTACK);
    }
    // Alt bottom→top: [timeoutDelta, bitmask, commitHash, milestoneCount,
    //                   state, custPKH, merchPKH, tokenId, ownerPKH]
    // Pop order: ownerPKH, tokenId, merchPKH, custPKH, state,
    //            milestoneCount, commitHash, bitmask, timeoutDelta

    _emitDispatch(b);
    return b.build();
  }

  // =========================================================================
  // Dispatch
  // =========================================================================

  static void _emitDispatch(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_DROP); _emitBurn(b);
    b.opCode(OpCodes.OP_ELSE);
      b.opCode(OpCodes.OP_DUP); b.opCode(OpCodes.OP_NOTIF);
        b.opCode(OpCodes.OP_DROP); _emitCreateFunnel(b);
      b.opCode(OpCodes.OP_ELSE);
        b.opCode(OpCodes.OP_DUP); b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_EQUAL);
        b.opCode(OpCodes.OP_IF);
          b.opCode(OpCodes.OP_DROP); _emitEnroll(b);
        b.opCode(OpCodes.OP_ELSE);
          b.opCode(OpCodes.OP_DUP); b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_EQUAL);
          b.opCode(OpCodes.OP_IF);
            b.opCode(OpCodes.OP_DROP); _emitConfirm(b);
          b.opCode(OpCodes.OP_ELSE);
            b.opCode(OpCodes.OP_DUP); b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_EQUAL);
            b.opCode(OpCodes.OP_IF);
              b.opCode(OpCodes.OP_DROP); _emitConvert(b);
            b.opCode(OpCodes.OP_ELSE);
              b.opCode(OpCodes.OP_DUP); b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_EQUAL);
              b.opCode(OpCodes.OP_IF);
                b.opCode(OpCodes.OP_DROP); _emitSettle(b);
              b.opCode(OpCodes.OP_ELSE);
                b.opCode(OpCodes.OP_DROP); _emitTimeout(b);
              b.opCode(OpCodes.OP_ENDIF);
            b.opCode(OpCodes.OP_ENDIF);
          b.opCode(OpCodes.OP_ENDIF);
        b.opCode(OpCodes.OP_ENDIF);
      b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // burn (selector=6)
  // =========================================================================

  /// Stack: [ownerPubKey, ownerSig]
  static void _emitBurn(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // merchantPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // customerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentState
    // Stack: [ownerPubKey, ownerSig, ownerPKH, currentState]

    // Check currentState >= 0x04 (terminal): state > 3
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_GREATERTHAN);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack: [ownerPubKey, ownerSig, ownerPKH]

    // Drain remaining
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // milestoneCount
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // commitHash
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // bitmask
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // timeoutDelta

    // P2PKH
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  // =========================================================================
  // createFunnel (selector=0)
  // =========================================================================

  /// Stack: [preImage, fundingTxId, padding]
  static void _emitCreateFunnel(ScriptBuilder b) {
    // Validate padding
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // Validate initial state fields
    b.opCode(OpCodes.OP_FROMALTSTACK);  // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);  // merchantPKH

    // ownerPKH == merchantPKH
    // Stack: [merchPKH=0, ownerPKH=1, padding=2, fundingTxId=3, preImage=4]
    b.opCode(OpCodes.OP_OVER);                           // copy ownerPKH (idx 1)
    b.opCode(OpCodes.OP_OVER);                           // copy merchPKH (idx 1, shifted)
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_DROP); b.opCode(OpCodes.OP_DROP); // drop both

    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // customerPKH

    // currentState == 0
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_EQUALVERIFY);

    // milestoneCount == 0
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_EQUALVERIFY);

    // commitmentHash == 32 zero bytes
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.addData(Uint8List(32));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Drain remaining
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // bitmask
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // timeoutDelta

    // Drop padding
    b.opCode(OpCodes.OP_DROP);
    // Stack: [preImage, fundingTxId]

    // checkPreimageOCS + hashPrevouts
    b.opCode(OpCodes.OP_TOALTSTACK);    // save fundingTxId

    // Extract hashPrevouts [4:36]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Extract currentTxId [68:100]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_FROMALTSTACK);  // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);  // hashPrevouts
    b.opCode(OpCodes.OP_FROMALTSTACK);  // fundingTxId

    // fundingOutpoint
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    // pp1Outpoint
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_CAT);
    // pp2Outpoint
    b.opCode(OpCodes.OP_ROT);
    b.addData(Uint8List.fromList([0x02, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // enroll (selector=1) — INIT→ACTIVE, merchant signs
  // =========================================================================

  /// Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt, merchantSig,
  ///         eventData, scriptLHS, parentRawTx, padding]
  ///
  /// INIT→ACTIVE. Merchant signs. ownerPKH→customerPKH.
  /// eventDigest = SHA256(mSig || eventData)
  static void _emitEnroll(ScriptBuilder b) {
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH, tokenId, ownerPKH]
    // Stack (10): pad=0, rawTx=1, lhs=2, eventData=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9

    // --- Drain ownerPKH, tokenId ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH]

    // --- Pop merchPKH, merchant auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merchPKH
    // Stack (11): merchPKH=0, pad=1, rawTx=2, lhs=3, eventData=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);  // mPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // merchPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);  // mSig
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);  // mPK (+1 for sig push)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);          // drop merchPKH
    // Stack (10): pad=0, rawTx=1, lhs=2, eventData=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
    // Alt: [td, bm, ch, mc, state, custPKH]

    // --- Pop custPKH (will be newOwnerPKH) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // custPKH → main stack
    // Stack (11): custPKH=0, pad=1, rawTx=2, lhs=3, eventData=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    // Alt: [td, bm, ch, mc, state]

    // --- Pop state, check == 0x01 (ACTIVE = post-enroll) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // state
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [td, bm, ch, mc]

    // --- Drain mc, ch ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // mc
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ch
    // Alt: [td, bm]

    // --- Pop bitmask, check bit 0 ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // bitmask
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_AND);
    b.opCode(OpCodes.OP_VERIFY);
    // Alt: [td]

    // --- Drain timeoutDelta ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // td
    // Alt: []

    // --- Compute eventDigest = SHA256(eventData) ---
    // Stack (11): custPKH=0, pad=1, rawTx=2, lhs=3, eventData=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);  // eventData
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);    // eventDigest → alt

    // --- Drop eventData ---
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);
    // Stack (10): custPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
    // Alt: [eventDigest]

    _emitInductiveProofStandard(b,
        newStateValue: 0x01, updateMilestoneCount: false);
  }

  // =========================================================================
  // confirm (selector=2) — ACTIVE/PROGRESSING→PROGRESSING, dual-sig
  // =========================================================================

  /// Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt, merchantSig,
  ///         customerPK, customerSig, milestoneData, scriptLHS, parentRawTx, padding]
  ///
  /// ACTIVE→PROGRESSING (state 0x01→0x02, bitmask bit 1)
  /// or PROGRESSING→PROGRESSING (state 0x02→0x02, bitmask bit 2)
  /// Dual-sig: merchant + customer. milestoneCount++.
  /// eventDigest = SHA256(mSig || custSig || milestoneData)
  static void _emitConfirm(ScriptBuilder b) {
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH, tokenId, ownerPKH]
    // Stack (12): pad=0, rawTx=1, lhs=2, milestoneData=3, custSig=4,
    //   custPK=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11

    // --- Drain ownerPKH, tokenId ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH]

    // --- Pop merchPKH, merchant auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merchPKH
    // Stack (13): merchPKH=0, pad=1, rawTx=2, lhs=3, milestoneData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_PICK);  // mPK (idx 10)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // merchPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // mSig (idx 7)
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // mPK (idx 11, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);           // drop merchPKH
    // Stack (12): pad=0, rawTx=1, lhs=2, milestoneData=3, custSig=4,
    //   custPK=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11

    // --- Pop custPKH, customer auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // custPKH
    // Stack (13): custPKH=0, pad=1, rawTx=2, lhs=3, milestoneData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    // Alt: [td, bm, ch, mc, state]
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_PICK);   // custPK (idx 6)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // custPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);   // custSig (idx 5)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // custPK (idx 7, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    // custPKH stays at idx 0 (will be newOwnerPKH)

    // --- Pop state, check (==1 or ==2), compute bitmask divisor ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // state
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_EQUAL);
    b.opCode(OpCodes.OP_IF);
      b.opCode(OpCodes.OP_DROP);
      b.opCode(OpCodes.OP_2);            // divisor for bit 1
    b.opCode(OpCodes.OP_ELSE);
      b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_EQUALVERIFY);
      b.opCode(OpCodes.OP_4);            // divisor for bit 2
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_TOALTSTACK);     // divisor → alt
    // Alt: [td, bm, ch, mc, divisor]

    // --- Drain alt: divisor, mc, ch, then check bitmask, drain td ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // divisor
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // mc
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ch
    b.opCode(OpCodes.OP_FROMALTSTACK);   // bm
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_SWAP);           // [bm, divisor]
    b.opCode(OpCodes.OP_DIV);            // bm / divisor
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_AND);
    b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // td
    // Stack (13): custPKH=0, pad=1, rawTx=2, lhs=3, milestoneData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    // Alt: []

    // --- Compute eventDigest = SHA256(milestoneData) ---
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // milestoneData (idx 4)
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // eventDigest → alt

    // --- Drop custPK, custSig, milestoneData ---
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // custPK
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // custSig
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // milestoneData
    // Stack (10): custPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
    // Alt: [eventDigest]

    _emitInductiveProofStandard(b,
        newStateValue: 0x02, updateMilestoneCount: true);
  }

  // =========================================================================
  // convert (selector=3) — PROGRESSING→CONVERTING, dual-sig
  // =========================================================================

  /// Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt, merchantSig,
  ///         customerPK, customerSig, conversionData, scriptLHS, parentRawTx, padding]
  ///
  /// PROGRESSING→CONVERTING (state 0x02→0x03, bitmask bit 3).
  /// Dual-sig: merchant + customer. milestoneCount > 0 required.
  /// ownerPKH→merchantPKH (merchant settles next).
  /// eventDigest = SHA256(mSig || custSig || conversionData)
  static void _emitConvert(ScriptBuilder b) {
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH, tokenId, ownerPKH]
    // Stack (12): pad=0, rawTx=1, lhs=2, convData=3, custSig=4,
    //   custPK=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11

    // --- Drain ownerPKH, tokenId ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH]

    // --- Pop merchPKH, merchant auth (keep merchPKH as newOwnerPKH) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merchPKH
    // Stack (13): merchPKH=0, pad=1, rawTx=2, lhs=3, convData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_PICK);  // mPK (idx 10)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // merchPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // mSig (idx 7)
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // mPK (idx 11, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    // merchPKH stays at idx 0 (will be newOwnerPKH)

    // --- Pop custPKH, customer auth, then drop ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // custPKH
    // Stack (14): custPKH=0, merchPKH=1, pad=2, rawTx=3, lhs=4, convData=5,
    //   custSig=6, custPK=7, mSig=8, chgAmt=9, chgPkh=10, mPK=11, pp2=12, preImg=13
    // Alt: [td, bm, ch, mc, state]
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // custPK (idx 7)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // custPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_PICK);   // custSig (idx 6)
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);   // custPK (idx 8, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);           // drop custPKH
    // Stack (13): merchPKH=0, pad=1, rawTx=2, lhs=3, convData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12

    // --- Pop state, check == 0x03 (CONVERTING = post-convert) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // state
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [td, bm, ch, mc]

    // --- Pop milestoneCount, check > 0 ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // mc
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN);
    b.opCode(OpCodes.OP_VERIFY);
    // Alt: [td, bm, ch]

    // --- Drain commitHash ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ch
    // Alt: [td, bm]

    // --- Pop bitmask, check bit 3 (divide by 8) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // bm
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_DIV);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_AND);
    b.opCode(OpCodes.OP_VERIFY);
    // Alt: [td]

    // --- Drain timeoutDelta ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // td
    // Stack (13): merchPKH=0, pad=1, rawTx=2, lhs=3, convData=4,
    //   custSig=5, custPK=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    // Alt: []

    // --- Compute eventDigest = SHA256(conversionData) ---
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // convData (idx 4)
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // eventDigest → alt

    // --- Drop custPK, custSig, convData ---
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // custPK
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // custSig
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);           // convData
    // Stack (10): merchPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
    // Alt: [eventDigest]

    _emitInductiveProofStandard(b,
        newStateValue: 0x03, updateMilestoneCount: false);
  }

  // =========================================================================
  // settle (selector=4) — CONVERTING→SETTLED, 7-output
  // =========================================================================

  /// Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt, merchantSig,
  ///         custRewardAmt, merchPayAmt, settlementData,
  ///         scriptLHS, parentRawTx, padding]
  ///
  /// CONVERTING→SETTLED (state 0x03→0x04, bitmask bit 4).
  /// Merchant signs. 7-output topology with P2PKH reward/payment.
  /// eventDigest = SHA256(mSig || settlementData)
  static void _emitSettle(ScriptBuilder b) {
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH, tokenId, ownerPKH]
    // Stack (12): pad=0, rawTx=1, lhs=2, settlementData=3, merchPayAmt=4,
    //   custRewardAmt=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11

    // --- Drain ownerPKH, tokenId ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH]

    // --- Pop merchPKH, merchant auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merchPKH
    // Stack (13): merchPKH=0, pad=1, rawTx=2, lhs=3, settlementData=4,
    //   merchPayAmt=5, custRewardAmt=6, mSig=7, chgAmt=8, chgPkh=9, mPK=10, pp2=11, preImg=12
    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_PICK);  // mPK (idx 10)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // merchPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // mSig (idx 7)
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // mPK (idx 11, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);           // drop merchPKH
    // Stack (12): pad=0, rawTx=1, lhs=2, settlementData=3, merchPayAmt=4,
    //   custRewardAmt=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11

    // --- Drain custPKH ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // custPKH
    // Alt: [td, bm, ch, mc, state]

    // --- Pop state, check == 0x04 (SETTLED = post-settle) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // state
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [td, bm, ch, mc]

    // --- Drain mc, ch ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // mc
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ch
    // Alt: [td, bm]

    // --- Pop bitmask, check bit 4 (divide by 16) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // bm
    b.opCode(OpCodes.OP_BIN2NUM);
    OpcodeHelpers.pushInt(b, 16);
    b.opCode(OpCodes.OP_DIV);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_AND);
    b.opCode(OpCodes.OP_VERIFY);
    // Alt: [td]

    // --- Drain timeoutDelta ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // td
    // Stack (12): pad=0, rawTx=1, lhs=2, settlementData=3, merchPayAmt=4,
    //   custRewardAmt=5, mSig=6, chgAmt=7, chgPkh=8, mPK=9, pp2=10, preImg=11
    // Alt: []

    // --- Validate amounts > 0 ---
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);   // custRewardAmt
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // merchPayAmt
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // --- Compute eventDigest = SHA256(settlementData) ---
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_PICK);   // settlementData (idx 3)
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // eventDigest → alt

    // --- Drop settlementData ---
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);
    // Stack (11): pad=0, rawTx=1, lhs=2, merchPayAmt=3, custRewardAmt=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    // Alt: [eventDigest]

    _emitInductiveProofSettle(b);
  }

  // =========================================================================
  // timeout (selector=5) — any→EXPIRED, 6-output, nLockTime
  // =========================================================================

  /// Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt, merchantSig,
  ///         refundAmount, scriptLHS, parentRawTx, padding]
  ///
  /// any non-terminal→EXPIRED (state <0x04→0x05, bitmask bit 5).
  /// Merchant signs. nLockTime >= timeoutDelta.
  /// 6-output topology with merchant refund P2PKH.
  /// No commitment hash update (preserves parent's).
  static void _emitTimeout(ScriptBuilder b) {
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH, tokenId, ownerPKH]
    // Stack (10): pad=0, rawTx=1, lhs=2, refundAmt=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9

    // --- Drain ownerPKH, tokenId ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    // Alt: [td, bm, ch, mc, state, custPKH, merchPKH]

    // --- Pop merchPKH, merchant auth ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // merchPKH
    // Stack (11): merchPKH=0, pad=1, rawTx=2, lhs=3, refundAmt=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);   // mPK (idx 8)
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);           // merchPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);   // mSig (idx 5)
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);   // mPK (idx 9, shifted +1)
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);           // drop merchPKH
    // Stack (10): pad=0, rawTx=1, lhs=2, refundAmt=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9

    // --- Drain custPKH ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // custPKH
    // Alt: [td, bm, ch, mc, state]

    // --- Pop state, check == 0x05 (EXPIRED = post-timeout) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // state
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: [td, bm, ch, mc]

    // --- Drain mc, ch ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // mc
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ch
    // Alt: [td, bm]

    // --- Pop bitmask, check bit 5 (divide by 32) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // bm
    b.opCode(OpCodes.OP_BIN2NUM);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_DIV);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_AND);
    b.opCode(OpCodes.OP_VERIFY);
    // Alt: [td]

    // --- Pop timeoutDelta (keep for nLockTime check) ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // timeoutDelta (4-byte LE)
    // Stack (11): td=0, pad=1, rawTx=2, lhs=3, refundAmt=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
    // Alt: []

    // Convert timeoutDelta to unsigned number
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.opCode(OpCodes.OP_TOALTSTACK);     // tdNum → alt

    // Stack (10): pad=0, rawTx=1, lhs=2, refundAmt=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
    // Alt: [tdNum]

    _emitInductiveProofTimeout(b);
  }

  // =========================================================================
  // Settle: 7-output inductive proof
  // =========================================================================

  /// Phases 2-17 for settlement 7-output topology.
  ///
  /// Pre: Stack (11): pad=0, rawTx=1, lhs=2, merchPayAmt=3, custRewardAmt=4,
  ///   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9, preImg=10
  /// Alt: [eventDigest]
  ///
  /// 7-output layout:
  ///   0: change, 1: custReward(P2PKH), 2: merchPayment(P2PKH),
  ///   3: PP1_SM(state=0x04), 4: PP2, 5: PP3, 6: metadata
  ///
  /// customerPKH and merchantPKH for P2PKH outputs are extracted from
  /// parentPP1Script immutable fields (bytes [76:96] and [55:75]).
  static void _emitInductiveProofSettle(ScriptBuilder b) {
    // Phase 2: Validate padding and parentRawTx
    b.opCode(OpCodes.OP_DUP);           // padding (idx 0)
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // rawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // Phase 3: Extract preImage fields
    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_PICK);  // preImage
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt

    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_PICK);  // preImage
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt

    // Phase 4: checkPreimageOCS
    b.opCode(OpCodes.OP_10); b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (10): pad=0, rawTx=1, lhs=2, merchPayAmt=3, custRewardAmt=4,
    //   mSig=5, chgAmt=6, chgPkh=7, mPK=8, pp2=9

    // Phase 5: Parse parentRawTx outputs
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // rawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp1S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp2S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaS → alt
    b.opCode(OpCodes.OP_DROP);

    // Phase 6: Validate metadata 006a
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metaS
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 7: Get parent scripts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp3S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp2S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Alt: [eventDigest]
    // Stack (16): currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //   pad=6, rawTx=7, lhs=8, merchPayAmt=9, custRewardAmt=10,
    //   mSig=11, chgAmt=12, chgPkh=13, mPK=14, pp2Out=15

    // Phase 8: Commitment hash
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    OpcodeHelpers.pushInt(b, commitmentHashDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, commitmentHashDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_FROMALTSTACK);   // eventDigest
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // newCommitHash → alt

    // Phase 8b: Extract custPKH from pp1S[76:96]
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    OpcodeHelpers.pushInt(b, customerPKHDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, customerPKHDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // custPKH → alt

    // Extract merchPKH from pp1S[55:75] (= newOwnerPKH for settle)
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    OpcodeHelpers.pushInt(b, merchantPKHDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, merchantPKHDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack (17): merchPKH=0, currentTxId=1, nLocktime=2, pp1S=3, pp2S=4,
    //   pp3S=5, metaS=6, pad=7, rawTx=8, lhs=9, merchPayAmt=10,
    //   custRewardAmt=11, mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16
    // Alt: [newCommitHash, custPKH]

    // Phase 9: Rebuild PP1_SM (state=0x04, no MC update)
    // Alt before: [newCommitHash, custPKH] (bottom→top)
    // Need: stack=[newCH, merchPKH, pp1S_copy, ...], alt=[custPKH]
    b.opCode(OpCodes.OP_TOALTSTACK);     // merchPKH → alt [nCH, cPKH, mPKH]
    // Stack (16): currentTxId=0, nLocktime=1, pp1S=2, ...
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // mPKH (top of alt). Alt: [nCH, cPKH]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // cPKH (top of alt). Alt: [nCH]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nCH  (top of alt). Alt: []
    // Stack: [nCH, cPKH, mPKH, pp1S_copy, txId, nLt, pp1S, ...]
    b.opCode(OpCodes.OP_ROT);            // rotate nCH,cPKH,mPKH → [mPKH, nCH, cPKH, pp1S_copy, ...]
    b.opCode(OpCodes.OP_ROT);            // rotate mPKH,nCH,cPKH → [cPKH, mPKH, nCH, pp1S_copy, ...]
    b.opCode(OpCodes.OP_TOALTSTACK);     // cPKH → alt [cPKH]
    // Stack: [mPKH, nCH, pp1S_copy, txId, nLt, pp1S, ...]
    b.opCode(OpCodes.OP_SWAP);           // → [nCH, mPKH, pp1S_copy, ...]
    // Stack: [newCH, merchPKH, pp1S_copy, txId, nLt, pp1S, ...]
    // Alt: [custPKH]

    _emitRebuildPP1SM(b, newStateValue: 0x04, updateMilestoneCount: false);
    // Rebuild consumed 3 (pp1S_copy, merchPKH, newCH), produced 1. 19-3+1=17.
    // Stack (17): rebuiltScript=0, currentTxId=1, nLocktime=2, pp1S=3,
    //   pp2S=4, pp3S=5, metaS=6, pad=7, rawTx=8, lhs=9,
    //   merchPayAmt=10, custRewardAmt=11, mSig=12, chgAmt=13,
    //   chgPkh=14, mPK=15, pp2Out=16
    // Alt: [custPKH]

    // Phase 9b: Build PP1 output (1 sat)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (16): pp1Out=0, txId=1, nLt=2, pp1S=3, pp2S=4, pp3S=5,
    //   metaS=6, pad=7, rawTx=8, lhs=9, merchPayAmt=10, custRewardAmt=11,
    //   mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16

    // Phase 10: Build customer reward P2PKH output
    b.opCode(OpCodes.OP_FROMALTSTACK);   // custPKH
    // Stack (17)
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // custRewardAmt (idx 12)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (16): custRewardOut=0, pp1Out=1, txId=2, nLt=3, pp1S=4,
    //   pp2S=5, pp3S=6, metaS=7, pad=8, rawTx=9, lhs=10,
    //   merchPayAmt=11, custRewardAmt=12, mSig=13, chgAmt=14,
    //   chgPkh=15, mPK=16, pp2Out=17

    // Phase 10b: Build merchant payment P2PKH output
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);  // pp1S (idx 4)
    OpcodeHelpers.pushInt(b, merchantPKHDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, merchantPKHDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // merchPayAmt (idx 12)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (17): merchPayOut=0, custRewardOut=1, pp1Out=2, txId=3,
    //   nLt=4, pp1S=5, pp2S=6, pp3S=7, metaS=8, pad=9, rawTx=10,
    //   lhs=11, merchPayAmt=12, custRewardAmt=13, mSig=14, chgAmt=15,
    //   chgPkh=16, mPK=17, pp2Out=18

    // Phase 11: Build PP3 output
    // Extract merchPKH from pp1S as newOwnerPKH for PP3 rebuild
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // pp3S (idx 7)
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_PICK);  // pp1S (idx 5+1=6)
    OpcodeHelpers.pushInt(b, merchantPKHDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, merchantPKHDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack: [merchPKH, pp3S_copy, merchPayOut, ...]
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (18): pp3Out=0, merchPayOut=1, custRewardOut=2, pp1Out=3,
    //   txId=4, nLt=5, pp1S=6, pp2S=7, pp3S=8, metaS=9, pad=10,
    //   rawTx=11, lhs=12, merchPayAmt=13, custRewardAmt=14, mSig=15,
    //   chgAmt=16, chgPkh=17, mPK=18, pp2Out=19

    // Phase 12: Build metadata output (0 sats)
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);  // metaS (idx 9)
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (19): metaOut=0, pp3Out=1, merchPayOut=2, custRewardOut=3,
    //   pp1Out=4, txId=5, nLt=6, pp1S=7, pp2S=8, pp3S=9, metaS=10,
    //   pad=11, rawTx=12, lhs=13, merchPayAmt=14, custRewardAmt=15,
    //   mSig=16, chgAmt=17, chgPkh=18, mPK=19, pp2Out=20

    // Phase 13: Build change output
    OpcodeHelpers.pushInt(b, 18);
    b.opCode(OpCodes.OP_PICK);           // chgPkh (idx 18)
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 18);
    b.opCode(OpCodes.OP_PICK);           // chgAmt (idx 18, shifted +1)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (20): changeOut=0, metaOut=1, pp3Out=2, merchPayOut=3,
    //   custRewardOut=4, pp1Out=5, txId=6, nLt=7, pp1S=8, pp2S=9,
    //   pp3S=10, metaS=11, pad=12, rawTx=13, lhs=14, merchPayAmt=15,
    //   custRewardAmt=16, mSig=17, chgAmt=18, chgPkh=19, mPK=20, pp2Out=21

    // Phase 14: Reconstruct fullTx (7 outputs)
    // Stack (22): changeOut=0, metaOut=1, pp3Out=2, merchPayOut=3,
    //   custRewardOut=4, pp1Out=5, txId=6, nLt=7, pp1S=8, pp2S=9,
    //   pp3S=10, metaS=11, pad=12, rawTx=13, lhs=14, merchPayAmt=15,
    //   custRewardAmt=16, mSig=17, chgAmt=18, chgPkh=19, mPK=20, pp2Out=21
    //
    // Target: lhs + varint(7) + changeOut + custRewardOut + merchPayOut
    //         + pp1Out + pp2Out + pp3Out + metaOut + nLocktime

    // Stash metaOut, pp3Out, merchPayOut to alt (will pop in order)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaOut → alt
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3Out → alt
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // merchPayOut → alt
    // Stack (19): changeOut=0, custRewardOut=1, pp1Out=2, txId=3, nLt=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, pad=9, rawTx=10, lhs=11,
    //   merchPayAmt=12, custRewardAmt=13, mSig=14, chgAmt=15, chgPkh=16,
    //   mPK=17, pp2Out=18
    // Alt: [metaOut, pp3Out, merchPayOut]

    // lhs + varint(7)
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);           // scriptLHS
    b.opCode(OpCodes.OP_7);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);            // lhs + varint(7)

    // + changeOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // + custRewardOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // + merchPayOut (from alt)
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + pp1Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // Stack (16): built=0, txId=1, nLt=2, pp1S=3, pp2S=4, pp3S=5,
    //   metaS=6, pad=7, rawTx=8, lhs=9, merchPayAmt=10, custRewardAmt=11,
    //   mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16
    // Alt: [metaOut, pp3Out]

    // + pp2Out (from deep stack)
    OpcodeHelpers.pushInt(b, 16);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_CAT);

    // + pp3Out (from alt)
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + metaOut (from alt)
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + nLocktime (idx 2 → ROT gets it)
    b.opCode(OpCodes.OP_ROT);           // [nLt, built, txId] → no...
    // Stack: built=0, txId=1, nLt=2 → ROT: [txId, nLt, built]
    // Actually after all the CATs, let me retrace.
    // After pp2Out PICK+CAT: built=0, txId=1, nLt=2, ... (same below)
    // After pp3Out CAT: same indices
    // After metaOut CAT: same indices
    // ROT on [built=0, txId=1, nLt=2]: yields [txId, nLt, built]
    // We want nLt on top to CAT with built.
    // ROT gives us: nLt=0, built=1, txId=2 — no.
    // ROT rotates 3rd to top: [built, txId, nLt] → nLt moves to top? No.
    // ROT: a b c → b c a (moves bottom of 3 to top)
    // [nLt=2, txId=1, built=0] → ROT → [txId, built, nLt]
    // That puts nLt on top. Good.
    b.opCode(OpCodes.OP_CAT);            // built + nLocktime
    // Stack: [fullTx, txId, pp1S=2, pp2S=3, ...]

    // Phase 15: Verify SHA256d(fullTx) == currentTxId
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    // Stack: [hash, txId, pp1S, pp2S, pp3S, metaS, pad, rawTx, lhs,
    //   merchPayAmt, custRewardAmt, mSig, chgAmt, chgPkh, mPK, pp2Out]
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack (14): pp1S=0, pp2S=1, pp3S=2, metaS=3, pad=4, rawTx=5,
    //   lhs=6, merchPayAmt=7, custRewardAmt=8, mSig=9, chgAmt=10,
    //   chgPkh=11, mPK=12, pp2Out=13

    // Phase 16: Validate PP2
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);           // pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // Phase 17: Verify parent chain
    b.opCode(OpCodes.OP_DROP); // pp2S
    b.opCode(OpCodes.OP_DROP); // pp3S
    b.opCode(OpCodes.OP_DROP); // metaS
    b.opCode(OpCodes.OP_DROP); // pad

    b.opCode(OpCodes.OP_DUP);           // rawTx
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // parentTxId → alt

    b.opCode(OpCodes.OP_DROP);           // rawTx
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // Timeout: 6-output inductive proof
  // =========================================================================

  /// Phases 2-17 for timeout 6-output topology.
  ///
  /// Pre: Stack (10): pad=0, rawTx=1, lhs=2, refundAmt=3, mSig=4,
  ///   chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
  /// Alt: [tdNum] (timeoutDelta as unsigned number)
  ///
  /// 6-output layout:
  ///   0: change, 1: merchantRefund(P2PKH), 2: PP1_SM(state=0x05),
  ///   3: PP2, 4: PP3, 5: metadata
  ///
  /// nLockTime must be >= timeoutDelta. No commitment hash update.
  static void _emitInductiveProofTimeout(ScriptBuilder b) {
    // Phase 2: Validate padding and parentRawTx
    b.opCode(OpCodes.OP_DUP);           // padding (idx 0)
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // rawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // Phase 3: Extract preImage fields
    // currentTxId = preImage[68:100]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt

    // nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    // nLocktime (4-byte LE) on stack

    // Phase 3b: Verify nLocktime >= timeoutDelta
    // Alt is [tdNum(bottom), txId(top)]. Must pop txId first to reach tdNum.
    b.opCode(OpCodes.OP_DUP);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);        // nLocktime as unsigned number
    // Stack: [nLT_num, nLT_raw, pad, rawTx, lhs, ...]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // txId (top of alt). Alt: [tdNum]
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tdNum. Alt: []
    // Stack: [tdNum, txId, nLT_num, nLT_raw, pad, ...]
    b.opCode(OpCodes.OP_SWAP);           // [txId, tdNum, nLT_num, nLT_raw, ...]
    b.opCode(OpCodes.OP_TOALTSTACK);     // txId → alt. Alt: [txId]
    // Stack: [tdNum, nLT_num, nLT_raw, pad, ...]
    b.opCode(OpCodes.OP_SWAP);           // [nLT_num, tdNum, nLT_raw, pad, ...]
    b.opCode(OpCodes.OP_GREATERTHANOREQUAL);  // nLT_num >= tdNum
    b.opCode(OpCodes.OP_VERIFY);
    // Stack: [nLT_raw, pad, rawTx, lhs, ...]
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLT_raw → alt. Alt: [txId, nLT_raw]

    // Phase 4: checkPreimageOCS
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (9): pad=0, rawTx=1, lhs=2, refundAmt=3, mSig=4,
    //   chgAmt=5, chgPkh=6, mPK=7, pp2=8

    // Phase 5: Parse parentRawTx outputs
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // rawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp1S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp2S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaS → alt
    b.opCode(OpCodes.OP_DROP);

    // Phase 6: Validate metadata 006a
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metaS
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 7: Get parent scripts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp3S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp2S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Alt: []
    // Stack (15): currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //   pad=6, rawTx=7, lhs=8, refundAmt=9, mSig=10, chgAmt=11,
    //   chgPkh=12, mPK=13, pp2Out=14

    // Phase 8: Timeout uses parent's commitmentHash (no update)
    // Extract merchantPKH from pp1S[55:75] for newOwnerPKH and refund output
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    OpcodeHelpers.pushInt(b, merchantPKHDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, merchantPKHDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // merchPKH on stack as newOwnerPKH
    // Stack (16): merchPKH=0, currentTxId=1, nLocktime=2, pp1S=3, ...

    // Phase 9: Rebuild PP1_SM (state=0x05, preserve parent's MC and CH)
    // Need: [pp1S, newPKH, newCH] for _emitRebuildPP1SM(updateMC=false)
    // newCH = parentCommitHash (no update for timeout)
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_PICK);  // pp1S
    b.opCode(OpCodes.OP_OVER);                            // merchPKH (copy)
    // Extract parent commitHash from pp1S_copy (idx 1)
    b.opCode(OpCodes.OP_OVER);  // pp1S_copy (idx 1 after OVER of merchPKH)
    OpcodeHelpers.pushInt(b, commitmentHashDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, commitmentHashDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    // Stack: [parentCH, merchPKH_copy, pp1S_copy, merchPKH, txId, nLt, pp1S, ...]
    _emitRebuildPP1SM(b, newStateValue: 0x05, updateMilestoneCount: false);
    // Consumed 3 (pp1S_copy, merchPKH_copy, parentCH), produced 1 (rebuiltScript)
    // Stack (15): rebuiltScript=0, merchPKH=1, currentTxId=2, nLocktime=3,
    //   pp1S=4, pp2S=5, pp3S=6, metaS=7, pad=8, rawTx=9, lhs=10,
    //   refundAmt=11, mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16
    // Wait, that's 17. Let me recount.
    // Before 3 PICK + OVER + 2 PICK + extract: added 3 items (pp1S_copy, merchPKH_copy, parentCH) → 19
    // _emitRebuildPP1SM consumes 3, produces 1 → 17
    // Stack (17): rebuiltScript=0, merchPKH=1, currentTxId=2, nLocktime=3,
    //   pp1S=4, pp2S=5, pp3S=6, metaS=7, pad=8, rawTx=9, lhs=10,
    //   refundAmt=11, mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16

    // Phase 9b: Build PP1 output (1 sat)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (16): pp1Out=0, merchPKH=1, txId=2, nLt=3, pp1S=4, pp2S=5,
    //   pp3S=6, metaS=7, pad=8, rawTx=9, lhs=10, refundAmt=11,
    //   mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16

    // Phase 10: Build merchant refund P2PKH output
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // merchPKH
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // refundAmt (idx 12)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (17): merchRefundOut=0, pp1Out=1, merchPKH=2, txId=3, nLt=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, pad=9, rawTx=10, lhs=11,
    //   refundAmt=12, mSig=13, chgAmt=14, chgPkh=15, mPK=16, pp2Out=17

    // Phase 11: Build PP3 output (ownerPKH = merchantPKH)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // pp3S (idx 7)
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_PICK);  // merchPKH (idx 3)
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (18): pp3Out=0, merchRefundOut=1, pp1Out=2, merchPKH=3, txId=4,
    //   nLt=5, pp1S=6, pp2S=7, pp3S=8, metaS=9, pad=10, rawTx=11, lhs=12,
    //   refundAmt=13, mSig=14, chgAmt=15, chgPkh=16, mPK=17, pp2Out=18

    // Phase 12: Build metadata output (0 sats)
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);  // metaS (idx 9)
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (19): metaOut=0, pp3Out=1, merchRefundOut=2, pp1Out=3, merchPKH=4,
    //   txId=5, nLt=6, pp1S=7, pp2S=8, pp3S=9, metaS=10, pad=11, rawTx=12,
    //   lhs=13, refundAmt=14, mSig=15, chgAmt=16, chgPkh=17, mPK=18, pp2Out=19

    // Phase 13: Build change output
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);           // chgPkh (idx 17)
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);           // chgAmt (idx 17)
    PP1FtScriptGen.emitBuildOutput(b);
    // Stack (20): changeOut=0, metaOut=1, pp3Out=2, merchRefundOut=3, pp1Out=4,
    //   merchPKH=5, txId=6, nLt=7, pp1S=8, pp2S=9, pp3S=10, metaS=11,
    //   pad=12, rawTx=13, lhs=14, refundAmt=15, mSig=16, chgAmt=17,
    //   chgPkh=18, mPK=19, pp2Out=20

    // Phase 14: Reconstruct fullTx (6 outputs)
    // Output order: change + merchRefund + pp1 + pp2 + pp3 + meta + nLocktime
    //
    // Stash metaOut, pp3Out to alt
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaOut → alt
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3Out → alt
    // Stack (18): changeOut=0, merchRefundOut=1, pp1Out=2, merchPKH=3,
    //   txId=4, nLt=5, pp1S=6, pp2S=7, pp3S=8, metaS=9, pad=10,
    //   rawTx=11, lhs=12, refundAmt=13, mSig=14, chgAmt=15, chgPkh=16,
    //   mPK=17, pp2Out=18
    // Alt: [metaOut, pp3Out]

    // lhs + varint(6)
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // lhs
    b.opCode(OpCodes.OP_6);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);

    // + changeOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // + merchRefundOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // + pp1Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // Stack (15): built=0, merchPKH=1, txId=2, nLt=3, pp1S=4, pp2S=5,
    //   pp3S=6, metaS=7, pad=8, rawTx=9, lhs=10, refundAmt=11,
    //   mSig=12, chgAmt=13, chgPkh=14, mPK=15, pp2Out=16

    // + pp2Out
    OpcodeHelpers.pushInt(b, 16);
    b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_CAT);

    // + pp3Out (from alt)
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + metaOut (from alt)
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + nLocktime: ROT on [built, merchPKH, txId, nLt]
    // Wait, ROT operates on top 3: [built=top, merchPKH, txId]
    // We need nLt which is at idx 3. Use 3 ROLL.
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_ROLL);  // nLt to top
    b.opCode(OpCodes.OP_CAT);
    // Stack: [fullTx, merchPKH, txId, pp1S, pp2S, pp3S, metaS, pad, rawTx,
    //   lhs, refundAmt, mSig, chgAmt, chgPkh, mPK, pp2Out]

    // Phase 15: Verify SHA256d(fullTx) == currentTxId
    // Stack: [fullTx, merchPKH, txId, ...]
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    // Stack: [hash, merchPKH, txId, ...]
    // txId is at idx 2. ROLL 2 to get it.
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);  // txId to top
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack (13): merchPKH=0, pp1S=1, pp2S=2, pp3S=3, metaS=4, pad=5,
    //   rawTx=6, lhs=7, refundAmt=8, mSig=9, chgAmt=10, chgPkh=11,
    //   mPK=12, pp2Out=13

    // Phase 16: Validate PP2
    b.opCode(OpCodes.OP_DROP);           // merchPKH (no longer needed)
    // Stack (12): pp1S=0, pp2S=1, pp3S=2, metaS=3, pad=4, rawTx=5,
    //   lhs=6, refundAmt=7, mSig=8, chgAmt=9, chgPkh=10, mPK=11, pp2Out=12
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_PICK);           // pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // Phase 17: Verify parent chain
    b.opCode(OpCodes.OP_DROP); // pp2S
    b.opCode(OpCodes.OP_DROP); // pp3S
    b.opCode(OpCodes.OP_DROP); // metaS
    b.opCode(OpCodes.OP_DROP); // pad

    b.opCode(OpCodes.OP_DUP);           // rawTx
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);           // rawTx
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // Shared: Standard 5-output inductive proof (enroll, confirm, convert)
  // =========================================================================

  /// Phases 2-16 for standard 5-output topology.
  ///
  /// Pre: Stack (10): [preImg, pp2, mPK, chgPkh, chgAmt, mSig,
  ///                   lhs, rawTx, pad, newOwnerPKH]
  ///      idx: newOwnerPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
  ///           chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
  ///      Alt: [eventDigest]
  static void _emitInductiveProofStandard(ScriptBuilder b, {
    required int newStateValue,
    required bool updateMilestoneCount,
  }) {
    // Phase 2: Validate padding and parentRawTx
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // padding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // rawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // Phase 3: Extract preImage fields
    // currentTxId = preImage[68:100]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt

    // nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt

    // Phase 4: checkPreimageOCS
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (9): pp2=8→7, mPK=7→6, chgPkh=6→5, chgAmt=5→4, mSig=4→3,
    //            lhs=3→2, rawTx=2→1, pad=1→0... wait, preImage was at 9.
    // After ROLL 9 removes preImage: stack shifts down.
    // Stack (9): newOwnerPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
    //            chgAmt=5, chgPkh=6, mPK=7, pp2=8

    // Phase 5: Parse parentRawTx outputs
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // rawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp1S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp2S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaS → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining

    // Phase 6: Validate metadata 006a
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metaS
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 7: Get parent scripts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp3S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp2S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Alt: [eventDigest]
    // Stack (15): currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //   newOwnerPKH=6, pad=7, rawTx=8, lhs=9, mSig=10, chgAmt=11,
    //   chgPkh=12, mPK=13, pp2Out=14

    // Phase 8: Commitment hash + rebuild
    // Extract parentCommitmentHash from pp1S[101:133]
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    OpcodeHelpers.pushInt(b, commitmentHashDataEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, commitmentHashDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);

    // newCommitHash = SHA256(parentCommitHash || eventDigest)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // eventDigest
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);     // newCommitHash → alt

    if (updateMilestoneCount) {
      // Extract parentMilestoneCount from pp1S[99:100], increment
      b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
      OpcodeHelpers.pushInt(b, milestoneCountDataEnd);
      b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
      OpcodeHelpers.pushInt(b, milestoneCountDataStart);
      b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
      b.opCode(OpCodes.OP_BIN2NUM);
      b.opCode(OpCodes.OP_1ADD);
      b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_NUM2BIN);
      b.opCode(OpCodes.OP_TOALTSTACK);  // newMC → alt
    }

    // Set up rebuild: [pp1S, newOwnerPKH, (newMC), newCommitHash]
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // newOwnerPKH (+1)
    if (updateMilestoneCount) {
      b.opCode(OpCodes.OP_FROMALTSTACK);  // newMC
      b.opCode(OpCodes.OP_FROMALTSTACK);  // newCommitHash
    } else {
      b.opCode(OpCodes.OP_FROMALTSTACK);  // newCommitHash
    }
    _emitRebuildPP1SM(b, newStateValue: newStateValue,
        updateMilestoneCount: updateMilestoneCount);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // Phase 9: Build PP1 output (1 sat)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 10: Build PP3 output
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);  // pp3S
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);  // newOwnerPKH
    PP1FtScriptGen.emitRebuildPP3(b);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 11: Build metadata output (0 sats)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // metaS
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 12: Build change output
    // idx: metaOut=0, pp3Out=1, pp1Out=2, currentTxId=3, nLocktime=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, newOwnerPKH=9,
    //   pad=10, rawTx=11, lhs=12, mSig=13, chgAmt=14, chgPkh=15,
    //   mPK=16, pp2Out=17
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // changeAmt (+1)
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 13: Reconstruct fullTx
    // idx: changeOut=0, metaOut=1, pp3Out=2, pp1Out=3, currentTxId=4, nLocktime=5,
    //   pp1S=6, pp2S=7, pp3S=8, metaS=9, newOwnerPKH=10,
    //   pad=11, rawTx=12, lhs=13, mSig=14, chgAmt=15, chgPkh=16,
    //   mPK=17, pp2Out=18
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);  // scriptLHS
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);   // lhs + varint(5)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);   // + changeOut

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash metaOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);   // + pp1Out

    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // pp2Out
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_FROMALTSTACK);  // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // metaOut
    b.opCode(OpCodes.OP_CAT);

    // nLocktime
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);

    // Phase 14: Verify SHA256d(fullTx) == currentTxId
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 15: Validate PP2
    b.opCode(OpCodes.OP_DROP);  // drop pp1S
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);  // pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // Phase 16: Verify parent chain
    b.opCode(OpCodes.OP_DROP); // pp3S
    b.opCode(OpCodes.OP_DROP); // metaS
    b.opCode(OpCodes.OP_DROP); // newOwnerPKH
    b.opCode(OpCodes.OP_DROP); // padding

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);  // rawTx
    PP1FtScriptGen.emitReadOutpoint(b, 2);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // Rebuild PP1_SM
  // =========================================================================

  /// Pre: [..., pp1S, newPKH, (newMC if updateMC), newCH]
  /// Post: [..., rebuiltScript]
  ///
  /// Result: pp1S[0:1] + newPKH + pp1S[21:97] + newState
  ///         + pp1S[98:99] + newMC + pp1S[100:101] + newCH + pp1S[133:]
  static void _emitRebuildPP1SM(ScriptBuilder b, {
    required int newStateValue,
    required bool updateMilestoneCount,
  }) {
    // Normalize: if !updateMC, extract parent's MC from pp1S
    if (!updateMilestoneCount) {
      // Stack: [..., pp1S, newPKH, newCH]
      b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
      OpcodeHelpers.pushInt(b, milestoneCountDataEnd);
      b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
      OpcodeHelpers.pushInt(b, milestoneCountDataStart);
      b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
      // Stack: [..., pp1S, newPKH, newCH, parentMC]
      b.opCode(OpCodes.OP_SWAP);
      // Stack: [..., pp1S, newPKH, parentMC, newCH]
    }

    // Stack: [..., pp1S, newPKH, newMC, newCH]

    // Bring pp1S to top
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_ROLL);
    // Stack: [..., newPKH, newMC, newCH, pp1S]

    // Split pp1S into segments
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_SPLIT);
    // seg0(1byte), rest=pp1S[1:]
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);  // skip old PKH
    OpcodeHelpers.pushInt(b, 76);
    b.opCode(OpCodes.OP_SPLIT);  // seg1(76), rest=pp1S[97:]
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);  // skip old state
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_SPLIT);     // seg2(1), rest=pp1S[99:]
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);  // skip old MC
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_SPLIT);     // seg3(1), rest=pp1S[101:]
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);  // skip old CH → seg4=pp1S[133:]

    // Stack top: [..., newPKH, newMC, newCH, seg0, seg1, seg2, seg3, seg4]
    // idx: seg4=0, seg3=1, seg2=2, seg1=3, seg0=4, newCH=5, newMC=6, newPKH=7

    // Stash seg4, seg3, seg2, seg1
    b.opCode(OpCodes.OP_TOALTSTACK);  // seg4
    b.opCode(OpCodes.OP_TOALTSTACK);  // seg3
    b.opCode(OpCodes.OP_TOALTSTACK);  // seg2
    b.opCode(OpCodes.OP_TOALTSTACK);  // seg1
    // Stack: [..., newPKH, newMC, newCH, seg0]
    // Alt pop order: seg1, seg2, seg3, seg4

    // seg0 + newPKH
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_ROLL);  // newPKH to top
    b.opCode(OpCodes.OP_CAT);  // seg0+newPKH
    // Stack: [..., newMC, newCH, built]

    // + seg1
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + newState
    _addRawByte(b, newStateValue);
    b.opCode(OpCodes.OP_CAT);

    // + seg2
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + newMC (via ROT)
    b.opCode(OpCodes.OP_ROT);   // [newCH, built, newMC]
    b.opCode(OpCodes.OP_CAT);   // [newCH, built+newMC]

    // + seg3
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);

    // + newCH (via SWAP)
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // + seg4
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);
  }

  // =========================================================================
  // Validate PP2
  // =========================================================================

  static void _emitValidatePP2NFT(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x24]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x51]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart - pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_DROP);
  }

  /// Push a single byte as raw data (0x01 prefix + byte), bypassing
  /// ScriptBuilder.addData's OP_N conversion for values 1-16.
  static void _addRawByte(ScriptBuilder b, int value) {
    var data = Uint8List.fromList([value]);
    b.addChunk(ScriptChunk(data, 1, 1));  // opcodenum=1 means "push 1 byte"
  }
}
