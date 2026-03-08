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
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'sha256_script_gen.dart';
import 'opcode_helpers.dart';

/// Generates the complete PP3 (partial witness check) locking script dynamically.
///
/// Replaces the large (~100KB) compiled sCrypt template with a hand-optimized
/// script (~62KB) that uses [Sha256ScriptGen.emitOneBlock] for SHA256 computation.
///
/// The generated script implements the same contract as `Tsl1WitnessCheck`:
/// - `unlock(preImage, partialHash, witnessPartialPreImage, fundingTxId)`:
///   Completes partial SHA256, verifies witness outpoint and hashPrevOuts,
///   then validates the preimage via checkPreimageOCS.
/// - `burnToken(recipientPubKey, recipientSig)`:
///   Simple P2PKH check against ownerPKH.
class WitnessCheckScriptGen {

  // =========================================================================
  // sCrypt OCS constants (from sCrypt's built-in Tx library)
  // These are used for the checkPreimageOCS ECDSA signature trick.
  // =========================================================================

  /// Private key (LE with sign byte) for OCS signature construction.
  static final Uint8List _privKeyLE = Uint8List.fromList(hex.decode(
      '97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff02600'));

  /// Modular inverse of nonce k (LE with sign byte).
  static final Uint8List _invKLE = Uint8List.fromList(hex.decode(
      '0ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800'));

  /// r value as LE script number (with sign byte).
  static final Uint8List _rLE = Uint8List.fromList(hex.decode(
      '6c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081000'));

  /// r value in big-endian (for DER encoding). Same bytes since r < 2^252.
  static final Uint8List _rBigEndian = Uint8List.fromList(hex.decode(
      '1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c'));

  /// Public key corresponding to the OCS private key.
  static final Uint8List _pubKey = Uint8List.fromList(hex.decode(
      '02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382'));

  /// secp256k1 curve order N (LE with sign byte).
  static final Uint8List _nLE = Uint8List.fromList(hex.decode(
      '414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00'));

  // =========================================================================
  // Main entry point
  // =========================================================================

  /// Generates the complete witness check locking script.
  ///
  /// [ownerPKH] - 20-byte pubkey hash of the token owner (for burn path).
  /// [pp2OutputIndex] - Output index of the PP2 output in the token transaction.
  ///   Default 2 for NFT (standard triplet position).
  static SVScript generate({
    required List<int> ownerPKH,
    int pp2OutputIndex = 2,
  }) {
    var b = ScriptBuilder();

    // Push constructor params as data (for parseability)
    b.addData(Uint8List.fromList(ownerPKH));

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
  // Unlock path
  // =========================================================================

  /// Emits the unlock function body.
  ///
  /// Stack at entry: [preImage, partialHash, witnessPreImage, fundingTxId, ownerPKH]
  /// Stack at exit: [TRUE] (from OP_CHECKSIG)
  static void _emitUnlockPath(ScriptBuilder b, int pp2OutputIndex) {
    // Drop ownerPKH (not needed for unlock)
    b.opCode(OpCodes.OP_DROP);
    // Stack: [preImage, partialHash, witnessPreImage, fundingTxId]

    // Save fundingTxId to altstack
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Stack: [preImage, partialHash, witnessPreImage]
    // Altstack: [fundingTxId]

    // Extract witnessPartialOutpoint (first 36 bytes of witnessPreImage)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);   // drop rest, keep first 36
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Altstack: [fundingTxId, witnessPartialOutpoint]

    // Save preImage to altstack
    b.opCode(OpCodes.OP_ROT);    // [partialHash, witnessPreImage, preImage]
    b.opCode(OpCodes.OP_TOALTSTACK);
    // Altstack: [fundingTxId, witnessPartialOutpoint, preImage]
    // Stack: [partialHash, witnessPreImage]

    // === Partial SHA256 computation ===
    _emitPartialSha256(b);
    // Stack: [witnessHash(32B)]
    // Altstack: [fundingTxId, witnessPartialOutpoint, preImage]

    // Double SHA256: witnessTxId = sha256(witnessHash)
    b.opCode(OpCodes.OP_SHA256);
    // Stack: [witnessTxId(32B)]

    // === Outpoint verification ===
    _emitOutpointVerification(b, pp2OutputIndex);
    // Stack: [witnessTxId, preImage]
    // Altstack: [fundingTxId]

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
  ///      Altstack: [fundingTxId, witnessPartialOutpoint, preImage]
  /// Post: [witnessTxId, preImage] on stack.
  ///       Altstack: [fundingTxId]
  static void _emitOutpointVerification(ScriptBuilder b, int pp2OutputIndex) {
    // Recover preImage from altstack
    b.opCode(OpCodes.OP_FROMALTSTACK);
    // Stack: [witnessTxId, preImage]
    // Altstack: [fundingTxId, witnessPartialOutpoint]

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
    // Altstack: [fundingTxId]

    // Drop myOutpoint (no longer needed)
    b.opCode(OpCodes.OP_DROP);
    // Stack: [witnessTxId, preImage]
  }

  // =========================================================================
  // HashPrevOuts verification
  // =========================================================================

  /// Verifies hashPrevOuts in the preImage matches expected outpoints.
  ///
  /// Pre: [witnessTxId, preImage] on stack. Altstack: [fundingTxId]
  /// Post: [preImage] on stack. Altstack: empty.
  static void _emitHashPrevOutsVerification(ScriptBuilder b) {
    // Build prevOutpoint1 = fundingTxId + LE(1, 4)
    b.opCode(OpCodes.OP_FROMALTSTACK);  // get fundingTxId
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    // Stack: [witnessTxId, preImage, prevOutpoint1(36B)]

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
  // checkPreimageOCS — ECDSA signature verification trick
  // =========================================================================

  /// Implements Tx.checkPreimageOCS: constructs and verifies an ECDSA signature
  /// using known private key and nonce to validate the sighash preimage.
  ///
  /// Pre: [preImage] on stack.
  /// Post: [TRUE] on stack (or script fails).
  ///
  /// Algorithm:
  /// 1. h = hash256(preImage)
  /// 2. hashInt = fromBEUnsigned(h)
  /// 3. s = normalize(invK * (hashInt + r * privKey), N)
  /// 4. Low-S: if s > N/2, s = N - s
  /// 5. DER encode signature with rBigEndian and s
  /// 6. OP_CODESEPARATOR + OP_CHECKSIG with pubKey
  static void _emitCheckPreimageOCS(ScriptBuilder b) {
    // Step 1: hash256(preImage) → sighash (32 bytes)
    b.opCode(OpCodes.OP_HASH256);
    // Stack: [hash(32B)]

    // Step 2: fromBEUnsigned(hash) = unpack(reverseBytes(hash, 32) + 0x00)
    OpcodeHelpers.reverseBytes32(b);     // hash_LE (32B)
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);           // hash_LE + 0x00 (33B)
    b.opCode(OpCodes.OP_BIN2NUM);       // hashInt (unsigned script number)
    // Stack: [hashInt]

    // Step 3: s_raw = invK * (hashInt + r * privKey)
    b.addData(_rLE);
    b.addData(_privKeyLE);
    b.opCode(OpCodes.OP_MUL);           // r * privKey
    b.opCode(OpCodes.OP_ADD);           // hashInt + r*privKey
    b.addData(_invKLE);
    b.opCode(OpCodes.OP_MUL);           // invK * (hashInt + r*privKey)
    // Stack: [s_raw]

    // Step 3b: normalize(s_raw, N) = s_raw % N; if negative, add N
    b.addData(_nLE);
    // Stack: [s_raw, N]
    b.opCode(OpCodes.OP_2DUP);          // [s_raw, N, s_raw, N]
    b.opCode(OpCodes.OP_MOD);           // [s_raw, N, s_mod]
    b.opCode(OpCodes.OP_DUP);           // [s_raw, N, s_mod, s_mod]
    b.opCode(OpCodes.OP_0);             // [s_raw, N, s_mod, s_mod, 0]
    b.opCode(OpCodes.OP_LESSTHAN);      // [s_raw, N, s_mod, is_neg]
    b.opCode(OpCodes.OP_IF);
    b.opCode(OpCodes.OP_OVER);          // s_mod + N (OVER picks N)
    b.opCode(OpCodes.OP_ADD);
    b.opCode(OpCodes.OP_ENDIF);
    // Stack: [s_raw, N, s_normalized]
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_NIP);           // [s_normalized]

    // Step 4: Low-S normalization: if s > N/2, s = N - s
    b.addData(_nLE);
    // Stack: [s, N]
    b.opCode(OpCodes.OP_2DUP);          // [s, N, s, N]
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_DIV);           // [s, N, s, N/2]
    b.opCode(OpCodes.OP_GREATERTHAN);   // [s, N, s>N/2]
    b.opCode(OpCodes.OP_IF);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SUB);           // N - s
    b.opCode(OpCodes.OP_ELSE);
    b.opCode(OpCodes.OP_DROP);           // drop N
    b.opCode(OpCodes.OP_ENDIF);
    // Stack: [s_final]

    // Step 5: DER encode
    _emitDerEncode(b);
    // Stack: [sig]

    // Step 6: OP_CODESEPARATOR + OP_CHECKSIG
    b.addData(_pubKey);
    b.opCode(OpCodes.OP_CODESEPARATOR);
    b.opCode(OpCodes.OP_CHECKSIG);
    // Stack: [TRUE]
  }

  /// Converts script number s to DER-encoded signature.
  ///
  /// Pre: [s_final] on stack (script number, positive, < N/2).
  /// Post: [sig] on stack (DER-encoded signature with sighash type 0x41).
  static void _emitDerEncode(ScriptBuilder b) {
    // Get slen = SIZE of minimal encoding of s
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);
    // Stack: [s, slen]

    // Convert s to 32-byte LE, then reverse to BE
    b.opCode(OpCodes.OP_SWAP);          // [slen, s]
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_NUM2BIN);       // [slen, s_32B_LE]
    OpcodeHelpers.reverseBytes32(b);    // [slen, s_32B_BE]

    // Slice [32-slen:] to get minimal BE representation
    b.opCode(OpCodes.OP_SWAP);          // [s_32B_BE, slen]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // save slen for later
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SUB);           // [s_32B_BE, 32-slen]
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);           // [sBigEndian]

    // Build s component: 0x02 || slen || sBigEndian
    b.opCode(OpCodes.OP_FROMALTSTACK);  // [sBigEndian, slen]
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);       // [sBigEndian, slen_byte]
    b.smallNum(2);                       // pushes OP_2 → byte 0x02 when CAT'd
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);           // [sBigEndian, 0x02||slen_byte]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);           // [0x02||slen_byte||sBigEndian] = s_der

    // Prepend r component (constant): 0x02 0x20 rBigEndian
    var rDer = Uint8List.fromList([0x02, 0x20] + _rBigEndian.toList());
    b.addData(rDer);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);           // [0x0220||rBE||s_der] = inner_der

    // DER sequence header: 0x30 || inner_len
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);           // [inner_der, inner_len]
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);       // [inner_der, inner_len_byte]
    b.addData(Uint8List.fromList([0x30]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);           // [inner_der, 0x30||inner_len_byte]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);           // [0x30||len||inner_der] = der_sig

    // Append sighash type: SIGHASH_ALL | SIGHASH_FORKID = 0x41
    b.addData(Uint8List.fromList([0x41]));
    b.opCode(OpCodes.OP_CAT);           // [sig]
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
