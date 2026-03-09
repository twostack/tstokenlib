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
import 'opcode_helpers.dart';

/// Shared checkPreimageOCS implementation for hand-optimized Bitcoin Script contracts.
///
/// Contains the ECDSA signature trick constants and script emission methods
/// used by both PP3-FT (WitnessCheckScriptGen) and PP5 (PP5ScriptGen).
class CheckPreimageOCS {

  /// Private key (LE with sign byte) for OCS signature construction.
  static final Uint8List privKeyLE = Uint8List.fromList(hex.decode(
      '97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff02600'));

  /// Modular inverse of nonce k (LE with sign byte).
  static final Uint8List invKLE = Uint8List.fromList(hex.decode(
      '0ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800'));

  /// r value as LE script number (with sign byte).
  static final Uint8List rLE = Uint8List.fromList(hex.decode(
      '6c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081000'));

  /// r value in big-endian (for DER encoding).
  static final Uint8List rBigEndian = Uint8List.fromList(hex.decode(
      '1008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c'));

  /// Public key corresponding to the OCS private key.
  static final Uint8List pubKey = Uint8List.fromList(hex.decode(
      '02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382'));

  /// secp256k1 curve order N (LE with sign byte).
  static final Uint8List nLE = Uint8List.fromList(hex.decode(
      '414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00'));

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
  /// When [useCodeSeparator] is true (default), OP_CODESEPARATOR is placed
  /// before OP_CHECKSIG. This is suitable for scripts that don't need to
  /// extract scriptCode from the preimage (e.g. PP3-FT).
  ///
  /// When false, no OP_CODESEPARATOR is emitted. The preimage's scriptCode
  /// field contains the FULL locking script, which allows Util.scriptCode()
  /// to extract it for inductive proof checks (e.g. PP5).
  static void emitCheckPreimageOCS(ScriptBuilder b, {bool useCodeSeparator = true}) {
    // Step 1: hash256(preImage) → sighash (32 bytes)
    b.opCode(OpCodes.OP_HASH256);

    // Step 2: fromBEUnsigned(hash) = unpack(reverseBytes(hash, 32) + 0x00)
    OpcodeHelpers.reverseBytes32(b);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);

    // Step 3: s_raw = invK * (hashInt + r * privKey)
    b.addData(rLE);
    b.addData(privKeyLE);
    b.opCode(OpCodes.OP_MUL);
    b.opCode(OpCodes.OP_ADD);
    b.addData(invKLE);
    b.opCode(OpCodes.OP_MUL);

    // Step 3b: normalize(s_raw, N) = s_raw % N; if negative, add N
    b.addData(nLE);
    b.opCode(OpCodes.OP_2DUP);
    b.opCode(OpCodes.OP_MOD);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_0);
    b.opCode(OpCodes.OP_LESSTHAN);
    b.opCode(OpCodes.OP_IF);
    b.opCode(OpCodes.OP_OVER);
    b.opCode(OpCodes.OP_ADD);
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_NIP);

    // Step 4: Low-S normalization: if s > N/2, s = N - s
    b.addData(nLE);
    b.opCode(OpCodes.OP_2DUP);
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_DIV);
    b.opCode(OpCodes.OP_GREATERTHAN);
    b.opCode(OpCodes.OP_IF);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_ELSE);
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_ENDIF);

    // Step 5: DER encode
    emitDerEncode(b);

    // Step 6: OP_CHECKSIG (optionally with OP_CODESEPARATOR)
    b.addData(pubKey);
    if (useCodeSeparator) {
      b.opCode(OpCodes.OP_CODESEPARATOR);
    }
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  /// Converts script number s to DER-encoded signature.
  ///
  /// Pre: [s_final] on stack (script number, positive, < N/2).
  /// Post: [sig] on stack (DER-encoded signature with sighash type 0x41).
  static void emitDerEncode(ScriptBuilder b) {
    // Get slen = SIZE of minimal encoding of s
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);

    // Convert s to 32-byte LE, then reverse to BE
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_NUM2BIN);
    OpcodeHelpers.reverseBytes32(b);

    // Slice [32-slen:] to get minimal BE representation
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);

    // Build s component: 0x02 || slen || sBigEndian
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.smallNum(2);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // Prepend r component (constant): 0x02 0x20 rBigEndian
    var rDer = Uint8List.fromList([0x02, 0x20] + rBigEndian.toList());
    b.addData(rDer);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // DER sequence header: 0x30 || inner_len
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.addData(Uint8List.fromList([0x30]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);

    // Append sighash type: SIGHASH_ALL | SIGHASH_FORKID = 0x41
    b.addData(Uint8List.fromList([0x41]));
    b.opCode(OpCodes.OP_CAT);
  }
}
