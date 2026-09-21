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
import 'sha256_script_gen.dart';
import 'opcode_helpers.dart';
import 'check_preimage_ocs.dart';

/// Generates the complete PP3 (partial witness check) locking script dynamically.
///
/// Replaces the large (~100KB) compiled sCrypt template with a hand-optimized
/// script (~62KB) that uses [Sha256ScriptGen.emitOneBlock] for SHA256 computation.
///
/// The generated script implements the same contract as `Tsl1WitnessCheck`:
/// - `unlock(preImage, partialHash, witnessPartialPreImage, fundingOutpoint)`:
///   Completes partial SHA256, verifies witness outpoint and hashPrevOuts,
///   then validates the preimage via checkPreimageOCS.
/// - `burnToken(recipientPubKey, recipientSig)`:
///   Simple P2PKH check against ownerPKH. **Not present in the pool variant**,
///   which is the witness check alone; see [generate].
class WitnessCheckScriptGen {

  // OCS constants are now in CheckPreimageOCS shared module.

  // =========================================================================
  // Main entry point
  // =========================================================================

  /// Generates the complete witness check locking script.
  ///
  /// Exactly one of [ownerPKH] and [nextSlot] is given, and which one decides
  /// what kind of PP3 this is.
  ///
  /// [ownerPKH] - 20-byte pubkey hash of the token owner, for the burn path.
  ///   Every archetype except the pool: the owner destroying their own token is
  ///   a feature.
  /// [nextSlot] - 36-byte outpoint of the verifier slot the spending round
  ///   must also spend. Only a shielded pool sets this, and a PP3 that sets it
  ///   has **no burn path and no owner**. A pool's PP3 holds every depositor's
  ///   balance and its owner is the coordinator, so a burn path there is not a
  ///   feature, it is an unconditional withdrawal right: measured 2026-09-21,
  ///   a round's PP3 holding 500,000 satoshis was spent through it with the
  ///   coordinator's key alone. So the pool variant drops the selector dispatch
  ///   and the owner push along with the branch, and the only way to spend it
  ///   is the witness check.
  /// [pp2OutputIndex] - Output index of the PP2 output in the token transaction.
  ///   Default 2 for NFT (standard triplet position).
  static SVScript generate({
    List<int>? ownerPKH,
    int pp2OutputIndex = 2,
    List<int>? nextSlot,
  }) {
    if (nextSlot != null && nextSlot.length != 36) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'nextSlot must be a 36-byte outpoint');
    }
    if ((ownerPKH == null) == (nextSlot == null)) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
          'Give exactly one of ownerPKH and nextSlot. A PP3 with a verifier '
          'slot is a pool\'s, and a pool\'s PP3 has no owner who could burn it.');
    }
    var b = ScriptBuilder();

    if (nextSlot != null) {
      // A pool PP3: the witness check and nothing else.
      _emitPoolScript(b, pp2OutputIndex, nextSlot);
      return b.build();
    }

    // Push constructor params as data (for parseability)
    b.addData(Uint8List.fromList(ownerPKH!));

    // Function selector: scriptSig puts selector on top of stack.
    // After ownerPKH push: [...args, selector, ownerPKH]
    b.opCode(OpCodes.OP_SWAP);    // [...args, ownerPKH, selector]
    b.opCode(OpCodes.OP_NOTIF);   // selector=OP_0 (falsy) → unlock path

    // === UNLOCK PATH ===
    _emitUnlockPath(b, pp2OutputIndex);

    b.opCode(OpCodes.OP_ELSE);    // selector=OP_1 (truthy) → burn path

    // === BURN PATH ===
    _emitBurnPath(b);

    b.opCode(OpCodes.OP_ENDIF);

    return b.build();
  }

  // =========================================================================
  // Pool variant
  // =========================================================================

  /// Emits a pool PP3: the verifier slot push, the witness check, and a
  /// forward covenant on the output that replaces it. No other way in.
  ///
  /// ```
  /// [0]      0x24
  /// [1:37]   nextSlot
  /// [37]     OP_TOALTSTACK
  /// [38:]    the witness check, the covenant, the preimage check
  /// ```
  ///
  /// nextSlot comes first so that the successor differs from this script in
  /// one fixed window at offset 1, and nothing about the owner appears at all:
  /// the same pool keeps byte-identical PP3 code across a coordinator key
  /// rotation. There is exactly one copy of nextSlot, parked on the altstack.
  ///
  /// **Spent at input 3, not input 2.** Every other TSL1 PP3 is input 2. A
  /// pool PP3 swaps places with the verifier slot because its preimage check
  /// signs SIGHASH_SINGLE, whose hashOutputs covers the output at the spending
  /// input's own index, and the output it has to constrain is output 3. The
  /// only place PP3's own index appears is the order of the hashPrevouts
  /// terms, so the move is that order and nothing else.
  ///
  /// **What it asserts**, in order:
  /// 1. The witness of the round this PP3 belongs to exists and spends that
  ///    round's PP2, exactly as every TSL1 PP3 does: [_emitPartialSha256]
  ///    derives the witness txid from the partial hash and
  ///    [_emitOutpointVerification] checks the witness's last input.
  /// 2. The spending round's inputs are exactly funding, (witnessTxId, 0),
  ///    the pinned verifier slot, this output, then the deposit covenants.
  /// 3. The spending round's output 3 runs this same program, with only the
  ///    slot it pins changed. See [_emitPoolForwardCovenant].
  /// 4. The preimage is genuine, via OCS with no OP_CODESEPARATOR, so that the
  ///    preimage's scriptCode is this whole script and step 3 can read it.
  ///
  /// Stack at entry (the spender's pushes), extraPrevouts on top:
  ///   [nextValue, nextSlotOut, preImage, partialHash, witnessPreImage,
  ///    fundingOutpoint, extraPrevouts]
  /// with no selector, because there is nothing to select between.
  static void _emitPoolScript(
      ScriptBuilder b, int pp2OutputIndex, List<int> nextSlot) {
    b.addData(Uint8List.fromList(nextSlot));
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Alt: [nextSlot]

    b.opCode(OpCodes.OP_TOALTSTACK);     // extraPrevouts
    b.opCode(OpCodes.OP_TOALTSTACK);     // fundingOutpoint
    // Alt: [nextSlot, extraPrevouts, fundingOutpoint]
    // Stack: [nextValue, nextSlotOut, preImage, partialHash, witnessPreImage]

    // --- 1. The witness exists and spends this round's PP2 ---
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // witnessPartialOutpoint
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_TOALTSTACK);     // preImage
    _emitPartialSha256(b);
    b.opCode(OpCodes.OP_SHA256);         // witnessTxId
    _emitOutpointVerification(b, pp2OutputIndex);
    // Stack: [nextValue, nextSlotOut, witnessTxId, preImage]
    // Alt: [nextSlot, extraPrevouts, fundingOutpoint]

    // --- 2. The spending round's inputs, with this output at input 3 ---
    _emitPoolHashPrevOuts(b);
    // Stack: [nextValue, nextSlotOut, preImage]

    // --- 3. The output replacing this one runs this program ---
    _emitPoolForwardCovenant(b);
    // Stack: [preImage]

    // --- 4. The preimage is genuine ---
    CheckPreimageOCS.emitCheckPreimageOCS(b,
        useCodeSeparator: false, sighashType: poolSighashType);
  }

  /// SIGHASH_SINGLE | SIGHASH_FORKID. A pool PP3's preimage commits only to
  /// the output at its own index, which is the one its covenant constrains.
  static const int poolSighashType = 0x43;

  /// Checks the spending round's hashPrevouts is
  ///
  /// ```
  /// SHA256d(fundingOutpoint ‖ (witnessTxId, 0) ‖ nextSlot ‖ myOutpoint ‖ extraPrevouts)
  /// ```
  ///
  /// which fixes input 0 to the funding the spender named, input 1 to the
  /// witness's output 0, input 2 to the verifier slot this output pinned when
  /// the round before it was built, input 3 to this output, and inputs 4 and
  /// up to the deposit covenants. The slot has to be spent in the same round
  /// or verification could be skipped entirely; PP1 cannot enforce that,
  /// because it runs in the witness, after the round is already mined.
  ///
  /// Pre:  [witnessTxId, preImage]
  ///       Alt: [nextSlot, extraPrevouts, fundingOutpoint]
  /// Post: [preImage]   Alt: []
  static void _emitPoolHashPrevOuts(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);   // fundingOutpoint
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // witnessTxId
    b.addData(Uint8List.fromList([0x00, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_CAT);            // funding ‖ (witnessTxId, 0)
    b.opCode(OpCodes.OP_FROMALTSTACK);   // extraPrevouts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nextSlot
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);            // ... ‖ nextSlot
    // Stack: [witnessTxId, preImage, extraPrevouts, prefix]
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);           // preImage
    OpcodeHelpers.pushInt(b, 104);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);            // myOutpoint
    b.opCode(OpCodes.OP_CAT);            // ... ‖ myOutpoint
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);            // ... ‖ extraPrevouts
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    // Stack: [witnessTxId, preImage, calcHashPrevOuts]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);            // hashPrevOuts = preImage[4:36]
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_NIP);            // witnessTxId
  }

  /// The forward covenant: the output at this input's index, output 3, must
  /// be this same script with only the pinned slot changed.
  ///
  /// This is what makes a pool's PP3 program mandatory rather than merely
  /// canonical. Without it, PP1 copies the program from the parent only in
  /// the witness, one step after the round is mined, so a coordinator could
  /// mint a round whose PP3 had a way out, spend it, and be refused only by a
  /// witness that no longer mattered. With it, such a round cannot be mined.
  ///
  /// It reads its own program from the preimage's scriptCode, which is the
  /// whole script because this PP3 uses no OP_CODESEPARATOR; that is what the
  /// separator used to save, about 49 KB of preimage. And it reads hashOutputs
  /// from the same preimage, which under SIGHASH_SINGLE is SHA256d of output 3
  /// alone, so no other output has to be pushed. It then requires
  ///
  /// ```
  /// SHA256d(nextValue ‖ varint ‖ 0x24 ‖ nextSlotOut ‖ scriptCode[37:]) == hashOutputs
  /// ```
  ///
  /// where varint and 0x24 are copied from the preimage: a slot is 36 bytes
  /// whatever it names, so the successor is exactly as long as this script.
  ///
  /// The value is not constrained here. The new balance is the proof's to
  /// say, and V checks it; PP1 checks it again in the witness.
  ///
  /// **The two length checks are the security of this function.** The
  /// comparison is between byte strings, and an output's serialization only
  /// fixes where its script starts through the varint. If nextValue could be
  /// longer than 8 bytes, a spender could push `value8 ‖ theirVarint ‖
  /// OP_1 OP_RETURN` as the "value": the same bytes would hash identically
  /// and parse as an output whose script begins with an anyone-can-spend
  /// prefix, with everything after it unexecuted. There is a test that
  /// builds exactly that round. The 3-byte varint check is the same kind of
  /// guard on this script's own length: past 65,535 bytes the varint grows and
  /// the fixed split points would land in the wrong place.
  ///
  /// Pre:  [nextValue, nextSlotOut, preImage]
  /// Post: [preImage]
  static void _emitPoolForwardCovenant(ScriptBuilder b) {
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);   // nextValue is exactly 8 bytes
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_SIZE);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);   // nextSlotOut is exactly 36 bytes
    b.opCode(OpCodes.OP_ROT);
    // Stack: [nextValue, nextSlotOut, preImage]

    // hashOutputs sits 40 bytes from the end: ‖ hashOutputs ‖ locktime ‖ type
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    OpcodeHelpers.pushInt(b, 52);
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT);            // [.., head, value‖seq‖hashOutputs‖lt‖type]
    OpcodeHelpers.pushInt(b, 12);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);       // hashOutputs
    // Stack: [nextValue, nextSlotOut, preImage, head]

    // head[104:] is varint ‖ scriptCode
    OpcodeHelpers.pushInt(b, 104);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT);            // [.., varint‖0x24, oldSlot‖body]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0xfd]));
    b.opCode(OpCodes.OP_EQUALVERIFY);      // a 3-byte varint
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);              // body = scriptCode[37:]
    // Stack: [nextValue, nextSlotOut, preImage, varint‖0x24, body]

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);             // nextValue
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);              // nextValue ‖ varint ‖ 0x24
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_PICK);             // nextSlotOut
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);              // ‖ body
    b.opCode(OpCodes.OP_HASH256);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_NIP);
  }

  // =========================================================================
  // Unlock path
  // =========================================================================

  /// Emits the unlock function body.
  ///
  /// Stack at entry: [preImage, partialHash, witnessPreImage, fundingOutpoint, ownerPKH]
  /// Stack at exit: [TRUE] (from OP_CHECKSIG)
  static void _emitUnlockPath(ScriptBuilder b, int pp2OutputIndex) {
    // Drop ownerPKH (not needed for unlock)
    b.opCode(OpCodes.OP_DROP);
    // Stack: [preImage, partialHash, witnessPreImage, fundingOutpoint]

    // Save fundingOutpoint to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Stack: [preImage, partialHash, witnessPreImage]
    // Altstack: [fundingOutpoint]

    // Extract witnessPartialOutpoint (first 36 bytes of witnessPreImage)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);   // drop rest, keep first 36
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Altstack: [fundingOutpoint, witnessPartialOutpoint]

    // Save preImage to altstack
    b.opCode(OpCodes.OP_ROT);    // [partialHash, witnessPreImage, preImage]
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Altstack: [fundingOutpoint, witnessPartialOutpoint, preImage]
    // Stack: [partialHash, witnessPreImage]

    // === Partial SHA256 computation ===
    _emitPartialSha256(b);
    // Stack: [witnessHash(32B)]
    // Altstack: [fundingOutpoint, witnessPartialOutpoint, preImage]

    // Double SHA256: witnessTxId = sha256(witnessHash)
    b.opCode(OpCodes.OP_SHA256);
    // Stack: [witnessTxId(32B)]

    // === Outpoint verification ===
    _emitOutpointVerification(b, pp2OutputIndex);
    // Stack: [witnessTxId, preImage]
    // Altstack: [fundingOutpoint]

    // === HashPrevOuts verification ===
    _emitHashPrevOutsVerification(b);
    // Stack: [preImage]

    // === checkPreimageOCS ===
    _emitCheckPreimageOCS(b);
    // Stack: [TRUE]
  }

  // =========================================================================
  // Partial SHA256 (1 or 2 blocks)
  // =========================================================================

  /// Computes partial SHA256 from midstate + message blocks.
  ///
  /// Pre: [partialHash(32B), witnessPreImage(64|128B)] on stack.
  /// Post: [witnessHash(32B)] on stack.
  /// Uses altstack temporarily for second block storage.
  static void _emitPartialSha256(ScriptBuilder b) {
    // Split first 64-byte block from witnessPreImage
    OpcodeHelpers.pushInt(b, 64);
    b.opCode(OpCodes.OP_SPLIT);
    // Stack: [partialHash, block1(64B), rest(0|64B)]
    b.opCode(OpCodes.OP_TOALTSTACK);  // save rest
    // Stack: [partialHash(32B), block1(64B)]

    // Process first block
    Sha256ScriptGen.emitOneBlock(b);
    // Stack: [midstate(32B)]

    // Check if there's a second block
    b.opCode(OpCodes.OP_FROMALTSTACK);  // get rest
    // Stack: [midstate, rest]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);
    // Stack: [midstate, rest, size]

    b.opCode(OpCodes.OP_IF);
    // size > 0: process second block
    // Stack: [midstate(32B), block2(64B)]
    Sha256ScriptGen.emitOneBlock(b);
    // Stack: [witnessHash(32B)]

    b.opCode(OpCodes.OP_ELSE);
    // size == 0: drop empty rest, midstate IS the hash
    b.opCode(OpCodes.OP_DROP);
    // Stack: [witnessHash(32B)]

    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // Outpoint verification
  // =========================================================================

  /// Verifies the witness outpoint matches the expected PP2 output.
  ///
  /// Pre: [witnessTxId(32B)] on stack.
  ///      Altstack: [fundingOutpoint, witnessPartialOutpoint, preImage]
  /// Post: [witnessTxId, preImage] on stack.
  ///       Altstack: [fundingOutpoint]
  static void _emitOutpointVerification(ScriptBuilder b, int pp2OutputIndex) {
    // Recover preImage from altstack
    b.opCode(OpCodes.OP_FROMALTSTACK);
    // Stack: [witnessTxId, preImage]
    // Altstack: [fundingOutpoint, witnessPartialOutpoint]

    // Extract myOutpoint from preImage: bytes[68:104] (36 bytes)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 104);   // 0x68
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);       // keep first 104 bytes
    OpcodeHelpers.pushInt(b, 68);    // 0x44
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);        // drop first 68, keep myOutpoint(36B)
    // Stack: [witnessTxId, preImage, myOutpoint(36B)]

    // Build witnessOutpoint = myOutpoint[:32] + pp2OutputIndex(LE, 4B)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);       // myTxId = myOutpoint[:32]

    // Push pp2OutputIndex as 4-byte little-endian
    var pp2LE = Uint8List(4);
    pp2LE[0] = pp2OutputIndex & 0xFF;
    pp2LE[1] = (pp2OutputIndex >> 8) & 0xFF;
    pp2LE[2] = (pp2OutputIndex >> 16) & 0xFF;
    pp2LE[3] = (pp2OutputIndex >> 24) & 0xFF;
    b.addData(pp2LE);
    b.opCode(OpCodes.OP_CAT);        // witnessOutpoint = myTxId + pp2LE
    // Stack: [witnessTxId, preImage, myOutpoint, witnessOutpoint(36B)]

    // Verify witnessOutpoint == witnessPartialOutpoint
    b.opCode(OpCodes.OP_FROMALTSTACK);  // get witnessPartialOutpoint
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Stack: [witnessTxId, preImage, myOutpoint]
    // Altstack: [fundingOutpoint]

    // Drop myOutpoint (no longer needed)
    b.opCode(OpCodes.OP_DROP);
    // Stack: [witnessTxId, preImage]
  }

  // =========================================================================
  // HashPrevOuts verification
  // =========================================================================

  /// Verifies hashPrevOuts in the preImage matches expected outpoints.
  ///
  /// Pre: [witnessTxId, preImage] on stack. Altstack: [fundingOutpoint]
  /// Post: [preImage] on stack. Altstack: empty.
  static void _emitHashPrevOutsVerification(ScriptBuilder b) {
    b.opCode(OpCodes.OP_FROMALTSTACK);  // fundingOutpoint (36 bytes, from scriptSig)
    // Stack: [witnessTxId, preImage, fundingOutpoint(36B)]

    // Build prevOutpoint2 = witnessTxId + LE(0, 4)
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);         // copy witnessTxId
    b.addData(Uint8List.fromList([0x00, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    // Stack: [witnessTxId, preImage, prevOutpoint1, prevOutpoint2(36B)]

    // Concatenate: prevOutpoint1 + prevOutpoint2
    b.opCode(OpCodes.OP_CAT);
    // Stack: [witnessTxId, preImage, (prevOutpoint1||prevOutpoint2)(72B)]

    // Now need to append myOutpoint. Extract it from preImage again.
    b.opCode(OpCodes.OP_OVER);         // copy preImage
    OpcodeHelpers.pushInt(b, 104);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);          // myOutpoint(36B)
    // Stack: [witnessTxId, preImage, prevOutpoints, myOutpoint(36B)]

    b.opCode(OpCodes.OP_CAT);
    // Stack: [witnessTxId, preImage, allOutpoints(108B)]

    // calcHashPrevOuts = sha256(sha256(allOutpoints))
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_SHA256);
    // Stack: [witnessTxId, preImage, calcHashPrevOuts(32B)]

    // Extract hashPrevOuts from preImage: bytes[4:36]
    b.opCode(OpCodes.OP_SWAP);          // [witnessTxId, calcHashPrevOuts, preImage]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);          // first 36 bytes
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);           // hashPrevOuts = bytes[4:36]
    // Stack: [witnessTxId, calcHashPrevOuts, preImage, hashPrevOuts(32B)]

    b.opCode(OpCodes.OP_ROT);           // [witnessTxId, preImage, hashPrevOuts, calcHashPrevOuts]
    b.opCode(OpCodes.OP_EQUALVERIFY);   // verify match
    // Stack: [witnessTxId, preImage]

    // Drop witnessTxId
    b.opCode(OpCodes.OP_NIP);
    // Stack: [preImage]
  }

  // =========================================================================
  // checkPreimageOCS — delegates to shared CheckPreimageOCS module
  // =========================================================================

  static void _emitCheckPreimageOCS(ScriptBuilder b) {
    CheckPreimageOCS.emitCheckPreimageOCS(b);
  }

  // =========================================================================
  // Burn path
  // =========================================================================

  /// Emits the burn function body.
  ///
  /// Stack at entry: [recipientPubKey, recipientSig, ownerPKH]
  /// Stack at exit: [TRUE] (from OP_CHECKSIG)
  static void _emitBurnPath(ScriptBuilder b) {
    // hash160(recipientPubKey) == ownerPKH
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_PICK);          // copy recipientPubKey
    b.opCode(OpCodes.OP_HASH160);       // hash160(pk)
    b.opCode(OpCodes.OP_EQUALVERIFY);   // verify == ownerPKH
    // Stack: [recipientPubKey, recipientSig]
    b.opCode(OpCodes.OP_SWAP);          // [recipientSig, recipientPubKey]
    b.opCode(OpCodes.OP_CHECKSIG);      // CHECKSIG needs [sig, pubKey] (pubKey on top)
    // Stack: [TRUE]
  }
}
