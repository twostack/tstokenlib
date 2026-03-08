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
import '../transaction/partial_sha256.dart';
import 'opcode_helpers.dart';

/// Generates hand-optimized Bitcoin Script for SHA256 computation.
///
/// Architecture:
/// - All 32-bit words stored as **4-byte big-endian** byte strings
/// - OP_LSHIFT/OP_RSHIFT operate on BE byte arrays natively (MSB at byte 0)
/// - No input/output byte reversal needed (SHA256 is BE, BSV shifts are BE)
/// - For additions: reverseBytes4 → BIN2NUM → ADD → truncate → reverseBytes4
/// - W[0..63] stored as a 256-byte blob on altstack
/// - K[0..63] stored as a 256-byte blob on altstack
/// - State variables a..h kept on main stack during compression
///
/// Altstack layout during compression: [W_blob(bottom), K_blob(top)]
class Sha256ScriptGen {

  /// The 64 SHA256 round constants as a 256-byte blob in big-endian order.
  static Uint8List get kConstantsBlob {
    var blob = ByteData(256);
    for (int i = 0; i < 64; i++) {
      int k = PartialSha256.K[i];
      blob.setUint32(i * 4, k, Endian.big);
    }
    return blob.buffer.asUint8List();
  }

  // =========================================================================
  // Addition helper (BE words → LE number → ADD → BE word)
  // =========================================================================

  /// Converts a 4-byte BE word to an unsigned script number.
  ///
  /// Pre: [... x(4B BE)]. Post: [... x_num(script number, unsigned)].
  ///
  /// Reverses to LE, appends 0x00 byte to ensure positive sign, then BIN2NUM.
  /// This handles values with bit 31 set (like 0xFFFFFFFF) that would otherwise
  /// be interpreted as negative by BIN2NUM.
  static ScriptBuilder emitBEToNum(ScriptBuilder b) {
    OpcodeHelpers.reverseBytes4(b);      // BE → LE
    b.addData(Uint8List.fromList([0x00]));  // push 0x00
    b.opCode(OpCodes.OP_CAT);           // append sign byte
    OpcodeHelpers.bin2num(b);            // to unsigned script number
    return b;
  }

  /// Converts a script number back to a 4-byte BE word with 32-bit truncation.
  ///
  /// Pre: [... n(script number)]. Post: [... x(4B BE)].
  static ScriptBuilder emitNumToBE(ScriptBuilder b) {
    OpcodeHelpers.truncate32(b);         // 4-byte LE
    OpcodeHelpers.reverseBytes4(b);      // LE → BE
    return b;
  }

  /// Adds two 4-byte BE words on top of stack, result as 4-byte BE.
  ///
  /// Pre: [... a(4B BE) b(4B BE)] (b on top).
  /// Post: [... (a+b mod 2^32)(4B BE)].
  static ScriptBuilder emitAdd32BE(ScriptBuilder b) {
    emitBEToNum(b);                      // b → unsigned num
    b.opCode(OpCodes.OP_SWAP);
    emitBEToNum(b);                      // a → unsigned num
    b.opCode(OpCodes.OP_ADD);
    emitNumToBE(b);                      // truncate + LE → BE
    return b;
  }

  /// Adds N values on top of stack (all 4-byte BE), with intermediate truncation.
  ///
  /// Pre: [... v0 v1 ... v(n-1)] (v(n-1) on top), all 4-byte BE.
  /// Post: [... sum(4B BE)].
  ///
  /// Sequential approach: convert top, swap next up, convert, add, repeat.
  /// Truncates after every 2 additions to prevent overflow.
  static ScriptBuilder emitAddNBE(ScriptBuilder b, int n) {
    if (n < 2) return b;

    // Convert top value to number
    emitBEToNum(b);

    for (int i = 1; i < n; i++) {
      // Swap to bring next unconverted BE value to top
      b.opCode(OpCodes.OP_SWAP);
      emitBEToNum(b);
      b.opCode(OpCodes.OP_ADD);

      // Intermediate truncation every 2 additions
      if (i < n - 1 && i % 2 == 0) {
        OpcodeHelpers.truncate32(b);
        b.addData(Uint8List.fromList([0x00]));
        b.opCode(OpCodes.OP_CAT);
        OpcodeHelpers.bin2num(b);
      }
    }

    // Final truncate and convert back to BE
    emitNumToBE(b);
    return b;
  }

  // =========================================================================
  // LE conversion helpers (no reverseBytes4 — native to BSV script numbers)
  // =========================================================================

  /// Converts a 4-byte LE word to an unsigned script number.
  ///
  /// Pre: [... x(4B LE)]. Post: [... x_num(script number, unsigned)].
  /// Cost: 4 bytes (vs 16 for emitBEToNum — saves 12 bytes per conversion).
  static ScriptBuilder emitLEToNum(ScriptBuilder b) {
    b.addData(Uint8List.fromList([0x00]));  // push 0x00
    b.opCode(OpCodes.OP_CAT);              // append sign byte
    OpcodeHelpers.bin2num(b);               // to unsigned script number
    return b;
  }

  /// Converts a script number to a 4-byte LE word with 32-bit truncation.
  ///
  /// Pre: [... n(script number)]. Post: [... x(4B LE)].
  /// Cost: 5 bytes (vs 17 for emitNumToBE — saves 12 bytes per conversion).
  static ScriptBuilder emitNumToLE(ScriptBuilder b) {
    OpcodeHelpers.truncate32(b);            // 4-byte LE
    return b;
  }

  /// Adds two 4-byte LE words on top of stack, result as 4-byte LE.
  ///
  /// Pre: [... a(4B LE) b(4B LE)] (b on top).
  /// Post: [... (a+b mod 2^32)(4B LE)].
  /// Cost: 14 bytes (vs 50 for emitAdd32BE — saves 36 bytes per addition).
  static ScriptBuilder emitAdd32LE(ScriptBuilder b) {
    emitLEToNum(b);                         // b → unsigned num
    b.opCode(OpCodes.OP_SWAP);
    emitLEToNum(b);                         // a → unsigned num
    b.opCode(OpCodes.OP_ADD);
    emitNumToLE(b);                         // truncate to 4B LE
    return b;
  }

  /// Adds N values on top of stack (all 4-byte LE), with intermediate truncation.
  ///
  /// Pre: [... v0 v1 ... v(n-1)] (v(n-1) on top), all 4-byte LE.
  /// Post: [... sum(4B LE)].
  /// Cost: ~(4n + 5 + n) bytes vs ~(16n + 17 + n) for BE version.
  static ScriptBuilder emitAddNLE(ScriptBuilder b, int n) {
    if (n < 2) return b;

    emitLEToNum(b);

    for (int i = 1; i < n; i++) {
      b.opCode(OpCodes.OP_SWAP);
      emitLEToNum(b);
      b.opCode(OpCodes.OP_ADD);

      if (i < n - 1 && i % 2 == 0) {
        OpcodeHelpers.truncate32(b);
        b.addData(Uint8List.fromList([0x00]));
        b.opCode(OpCodes.OP_CAT);
        OpcodeHelpers.bin2num(b);
      }
    }

    emitNumToLE(b);
    return b;
  }

  // =========================================================================
  // Sigma functions (message schedule): σ0, σ1
  // =========================================================================

  /// σ0(x) = ROTR(7,x) XOR ROTR(18,x) XOR SHR(3,x)
  ///
  /// Pre: x on top as 4-byte BE. Post: σ0(x) on top as 4-byte BE. x consumed.
  static ScriptBuilder emitSmallSigma0(ScriptBuilder b) {
    // ROTR(7, x) = (x >> 7) | (x << 25)
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 7);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 25);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(7,x)

    // ROTR(18, x) = (x >> 18) | (x << 14)
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 18);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);
    b.opCode(OpCodes.OP_XOR);         // XOR with ROTR(7)

    // SHR(3, x) — note: SHR not ROTR
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_XOR);         // final XOR
    return b;
  }

  /// σ1(x) = ROTR(17,x) XOR ROTR(19,x) XOR SHR(10,x)
  ///
  /// Pre: x on top as 4-byte BE. Post: σ1(x) on top as 4-byte BE. x consumed.
  static ScriptBuilder emitSmallSigma1(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(17,x)

    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 19);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);
    b.opCode(OpCodes.OP_XOR);         // XOR with ROTR(17)

    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 10);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_XOR);         // final XOR
    return b;
  }

  // =========================================================================
  // Sigma functions (compression): Σ0, Σ1
  // =========================================================================

  /// Σ0(a) = ROTR(2,a) XOR ROTR(13,a) XOR ROTR(22,a)
  ///
  /// Pre: a on top as 4-byte BE. Post: Σ0(a) on top as 4-byte BE.
  static ScriptBuilder emitBigSigma0(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);   // stash a copy

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 30);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(2,a)

    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 19);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);
    b.opCode(OpCodes.OP_XOR);         // XOR ROTR(13,a)

    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK); // recover original a

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 22);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 10);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(22,a)
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_XOR);         // final XOR
    return b;
  }

  /// Σ1(e) = ROTR(6,e) XOR ROTR(11,e) XOR ROTR(25,e)
  ///
  /// Pre: e on top as 4-byte BE. Post: Σ1(e) on top as 4-byte BE.
  static ScriptBuilder emitBigSigma1(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);   // stash e copy

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 26);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(6,e)

    b.opCode(OpCodes.OP_OVER);
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);
    b.opCode(OpCodes.OP_XOR);         // XOR ROTR(11,e)

    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK); // recover original e

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 25);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_OVER);
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // ROTR(25,e)
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_XOR);         // final XOR
    return b;
  }

  // =========================================================================
  // LE-wrapped sigma functions (for LE state words in compression)
  // =========================================================================

  /// Σ0 for LE state words: converts LE→BE, computes Σ0, converts BE→LE.
  /// Cost: 24 bytes overhead (2 × reverseBytes4) + Σ0 cost.
  static ScriptBuilder emitBigSigma0LE(ScriptBuilder b) {
    OpcodeHelpers.reverseBytes4(b);   // LE → BE
    emitBigSigma0(b);                 // BE → BE
    OpcodeHelpers.reverseBytes4(b);   // BE → LE
    return b;
  }

  /// Σ1 for LE state words: converts LE→BE, computes Σ1, converts BE→LE.
  static ScriptBuilder emitBigSigma1LE(ScriptBuilder b) {
    OpcodeHelpers.reverseBytes4(b);   // LE → BE
    emitBigSigma1(b);                 // BE → BE
    OpcodeHelpers.reverseBytes4(b);   // BE → LE
    return b;
  }

  // =========================================================================
  // Ch and Maj (bitwise, work on same-length byte arrays — BE or LE doesn't matter)
  // =========================================================================

  /// Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
  ///
  /// Pre: stack [... g f e] (e on top), all 4-byte. Post: [... Ch]. Consumes all 3.
  static ScriptBuilder emitCh(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);    // g f e e
    b.opCode(OpCodes.OP_ROT);    // g e e f
    b.opCode(OpCodes.OP_AND);    // g e (e&f)
    b.opCode(OpCodes.OP_SWAP);   // g (e&f) e
    b.opCode(OpCodes.OP_INVERT); // g (e&f) ~e
    b.opCode(OpCodes.OP_ROT);    // (e&f) ~e g
    b.opCode(OpCodes.OP_AND);    // (e&f) (~e&g)
    b.opCode(OpCodes.OP_XOR);    // Ch
    return b;
  }

  /// Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
  ///
  /// Pre: stack [... c b a] (a on top), all 4-byte. Post: [... Maj]. Consumes all 3.
  static ScriptBuilder emitMaj(ScriptBuilder b) {
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // c b a b
    b.opCode(OpCodes.OP_OVER);                             // c b a b a
    b.opCode(OpCodes.OP_AND);                              // c b a (a&b)
    b.opCode(OpCodes.OP_SWAP);                             // c b (a&b) a
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // c b (a&b) a c
    b.opCode(OpCodes.OP_AND);                              // c b (a&b) (a&c)
    b.opCode(OpCodes.OP_XOR);                              // c b (a&b)^(a&c)
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_ROT); // (a&b)^(a&c) c b
    b.opCode(OpCodes.OP_AND);                              // (a&b)^(a&c) (b&c)
    b.opCode(OpCodes.OP_XOR);                              // Maj
    return b;
  }

  // =========================================================================
  // Blob extraction
  // =========================================================================

  /// Extracts a 4-byte word at offset from blob, consuming blob.
  static ScriptBuilder emitExtractWord(ScriptBuilder b, int byteOffset) {
    if (byteOffset > 0) {
      OpcodeHelpers.pushInt(b, byteOffset);
      b.opCode(OpCodes.OP_SPLIT);
      b.opCode(OpCodes.OP_NIP);
    }
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
    return b;
  }

  /// Extracts a 4-byte word from blob without consuming it (DUPs first).
  static ScriptBuilder emitExtractWordKeep(ScriptBuilder b, int byteOffset) {
    b.opCode(OpCodes.OP_DUP);
    emitExtractWord(b, byteOffset);
    return b;
  }

  /// Fetches K[t] from K blob on altstack top.
  static ScriptBuilder emitFetchK(ScriptBuilder b, int t) {
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);
    emitExtractWord(b, t * 4);
    return b;
  }

  /// Fetches W[t] from W blob (below K blob on altstack).
  static ScriptBuilder emitFetchW(ScriptBuilder b, int t) {
    b.opCode(OpCodes.OP_FROMALTSTACK);  // K
    b.opCode(OpCodes.OP_FROMALTSTACK);  // W
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // W back
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // K back
    emitExtractWord(b, t * 4);
    return b;
  }

  /// Fetches K[t] from K blob on altstack top, returns as 4-byte LE.
  static ScriptBuilder emitFetchKLE(ScriptBuilder b, int t) {
    emitFetchK(b, t);
    OpcodeHelpers.reverseBytes4(b);   // BE → LE
    return b;
  }

  /// Fetches W[t] from W blob (below K blob), returns as 4-byte LE.
  static ScriptBuilder emitFetchWLE(ScriptBuilder b, int t) {
    emitFetchW(b, t);
    OpcodeHelpers.reverseBytes4(b);   // BE → LE
    return b;
  }

  // =========================================================================
  // Message schedule (blob-based, all BE)
  // =========================================================================

  /// Builds W[0..63] blob from 16 input words.
  ///
  /// Pre: 16 × 4-byte BE words on stack, W[0] on top, W[15] at bottom.
  /// Post: W_blob (256 bytes BE) on stack.
  static ScriptBuilder emitMessageScheduleBlob(ScriptBuilder b) {
    // Concatenate W[0..15]: W0 is on top. SWAP+CAT appends each next word.
    // OP_CAT: second_from_top || top. SWAP brings next word to top, blob below.
    // So CAT gives blob || W[i]. ✓
    for (int i = 1; i < 16; i++) {
      b.opCode(OpCodes.OP_SWAP);
      b.opCode(OpCodes.OP_CAT);
    }
    // Stack: W_blob (64 bytes = W[0..15])

    // Expand W[16..63]
    for (int t = 16; t < 64; t++) {
      // W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]

      // σ0(W[t-15])
      emitExtractWordKeep(b, (t - 15) * 4);
      emitSmallSigma0(b);
      b.opCode(OpCodes.OP_TOALTSTACK);

      // σ1(W[t-2])
      emitExtractWordKeep(b, (t - 2) * 4);
      emitSmallSigma1(b);

      // W[t-7]
      b.opCode(OpCodes.OP_OVER);
      emitExtractWord(b, (t - 7) * 4);

      // W[t-16]
      b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // blob is at idx 2
      emitExtractWord(b, (t - 16) * 4);

      // σ0 from altstack
      b.opCode(OpCodes.OP_FROMALTSTACK);

      // Sum all 4: σ1 + W[t-7] + W[t-16] + σ0
      // Stack: σ0 W[t-16] W[t-7] σ1 blob
      // Need to add all 4 values.
      // Convert each to LE number, add, truncate, convert back to BE.
      // Use emitAddNBE for 4 values:
      // But they're scattered on the stack. Let me reorder first.
      // Actually, all 4 values are on top of the blob:
      //   σ0(top), W[t-16], W[t-7], σ1, blob
      // Wait, let me re-trace the stack more carefully.

      // After emitSmallSigma1: σ1 is on top, blob below.
      // Stack: σ1 blob
      // OVER: blob σ1 blob → no, OVER copies second item.
      // Stack after OVER: blob_copy σ1 blob
      // Wait: OP_OVER copies item at idx 1 to top.
      // Stack was: σ1(top) blob. OVER → blob_copy σ1 blob. No!
      // OVER: stack[-2] → copies it to top. So: σ1(idx0) blob(idx1).
      // After OVER: blob(idx0) σ1(idx1) blob(idx2).
      // Then emitExtractWord consumes blob copy, leaving W[t-7].
      // Stack: W[t-7] σ1 blob

      // Then: OP_2 OP_PICK: picks idx 2 = blob.
      // Stack: blob_copy W[t-7] σ1 blob
      // emitExtractWord consumes blob_copy, leaves W[t-16].
      // Stack: W[t-16] W[t-7] σ1 blob

      // Then FROMALTSTACK: σ0
      // Stack: σ0 W[t-16] W[t-7] σ1 blob

      // Now add all 4: σ1 + W[t-7] + σ0 + W[t-16]
      // They're at positions 0-3, with blob at 4.
      // We can use emitAddNBE(b, 4) which converts 4 top items.
      emitAddNBE(b, 4);
      // Stack: W[t](4B BE) blob

      // Append to blob
      b.opCode(OpCodes.OP_CAT);  // blob || W[t]
    }

    return b;
  }

  // =========================================================================
  // Compression round (LE state words, BE blobs)
  // =========================================================================

  /// One compression round with LE state words.
  ///
  /// Stack: a(0) b(1) c(2) d(3) e(4) f(5) g(6) h(7) — all 4-byte LE.
  /// Altstack: [W_blob(BE), K_blob(BE)] (K on top).
  /// After: a' b' c' d' e' f' g' h' (all LE). Altstack unchanged.
  ///
  /// Using LE state saves ~108 bytes/round by eliminating reverseBytes4
  /// from addition conversions (14B per add vs 50B with BE).
  static ScriptBuilder emitCompressionRound(ScriptBuilder b, int t) {
    // ======== T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t] ========

    // Σ1(e): e at idx 4 — LE wrapped (LE→BE→Σ1→BE→LE)
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);
    emitBigSigma1LE(b);
    // STACK: Σ1(LE) a b c d e f g h  (9 items, all LE)

    // Ch(e,f,g): bitwise, endian-agnostic — works on LE directly
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // g
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // f (shifted by g push)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // e (shifted by g,f push)
    emitCh(b);
    // STACK: Ch(LE) Σ1 a b c d e f g h  (10 items)

    // h at idx 9
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    // STACK: h Ch Σ1 a b c d e f g h  (11 items)

    // K[t] — extracted as BE, converted to LE
    emitFetchKLE(b, t);
    // STACK: K(LE) h Ch Σ1 a b c d e f g h  (12 items)

    // W[t] — extracted as BE, converted to LE
    emitFetchWLE(b, t);
    // STACK: W(LE) K h Ch Σ1 a b c d e f g h  (13 items)

    // Sum 5 values using LE addition (saves 72B vs emitAddNBE)
    emitAddNLE(b, 5);
    // STACK: T1(LE) a b c d e f g h  (9 items)

    // ======== T2 = Σ0(a) + Maj(a,b,c) ========

    // Σ0(a): a at idx 1 — LE wrapped
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);
    emitBigSigma0LE(b);
    // STACK: Σ0(LE) T1 a b c d e f g h  (10 items)

    // Maj(a,b,c): bitwise, endian-agnostic
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // c
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // b (shifted)
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // a (shifted)
    emitMaj(b);
    // STACK: Maj(LE) Σ0 T1 a b c d e f g h  (11 items)

    // T2 = Σ0 + Maj (LE addition — saves 36B vs emitAdd32BE)
    emitAdd32LE(b);
    // STACK: T2(LE) T1 a b c d e f g h  (10 items)
    //        0      1  2 3 4 5 6 7 8 9

    // ======== State rotation via altstack ========
    // (Identical structure to BE version — just uses emitAdd32LE)

    // Compute e' = d + T1
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);   // d (idx 5)
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // T1 (idx 1+1=2)
    emitAdd32LE(b);

    // Compute a' = T1 + T2
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // T1 (idx 2)
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // T2 (shifted to idx 2)
    emitAdd32LE(b);

    // Push a' = T1+T2 (idx 0)
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push b' = a (idx 3)
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push c' = b (idx 4)
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push d' = c (idx 5)
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push e' = d+T1 (idx 0)
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push f' = e (idx 6)
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push g' = f (idx 7)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Push h' = g (idx 8)
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Drop old state + T2 + T1: 10 items = 5x 2DROP
    b.opCode(OpCodes.OP_2DROP); b.opCode(OpCodes.OP_2DROP);
    b.opCode(OpCodes.OP_2DROP); b.opCode(OpCodes.OP_2DROP);
    b.opCode(OpCodes.OP_2DROP);

    // Restore new state: a'(top) b' c' d' e' f' g' h'(bottom)
    for (int i = 0; i < 8; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    return b;
  }

  // =========================================================================
  // Full SHA256 block
  // =========================================================================

  /// One SHA256 block.
  ///
  /// Pre: block(64B BE, top) midstate(32B BE, below).
  /// Post: new_hash(32B BE).
  ///
  /// Internally uses LE state words during compression for efficiency.
  /// Message schedule and blobs remain BE. State is converted at boundaries.
  static ScriptBuilder emitOneBlock(ScriptBuilder b) {
    // Save midstate for final addition
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash midstate copy
    b.opCode(OpCodes.OP_SWAP);        // block(top) midstate

    // Split block into 16 × 4-byte BE words
    _emitSplitIntoWords(b, 16);

    // Message schedule: build W blob (all BE)
    emitMessageScheduleBlob(b);

    // Stash W (bottom) then K (top) on altstack
    b.opCode(OpCodes.OP_TOALTSTACK);  // W → alt
    b.addData(kConstantsBlob);
    b.opCode(OpCodes.OP_TOALTSTACK);  // K → alt
    // Altstack: midstate_copy, W, K

    // Split midstate into 8 BE words, then convert each to LE
    _emitSplitIntoWords(b, 8);
    _emitConvertWordsToLE(b, 8);
    // Stack: H0_LE(top=a) ... H7_LE(h)

    // 64 compression rounds (LE state, BE blobs)
    for (int t = 0; t < 64; t++) {
      emitCompressionRound(b, t);
    }
    // Stack: a'(LE) b' c' d' e' f' g' h'(LE)

    // Discard K and W
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP);  // K
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP);  // W

    // Retrieve midstate copy, split into BE words, convert to LE
    b.opCode(OpCodes.OP_FROMALTSTACK);
    _emitSplitIntoWords(b, 8);
    _emitConvertWordsToLE(b, 8);
    // Stack: H0_orig(LE) ... H7_orig(LE) a'(LE) ... h'(LE) — 16 items

    // Add each orig[i] + state[i] using LE addition
    for (int i = 0; i < 8; i++) {
      int stateIdx = 8 - i;
      OpcodeHelpers.pushInt(b, stateIdx);
      b.opCode(OpCodes.OP_ROLL);
      emitAdd32LE(b);               // LE addition (saves 36B per add vs BE)
      if (i < 7) {
        b.opCode(OpCodes.OP_TOALTSTACK);
      }
    }

    for (int i = 0; i < 7; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    // Stack: result_H0(LE) ... result_H7(LE)

    // Convert LE results back to BE for output
    _emitConvertWordsToLE(b, 8);  // reverseBytes4 is its own inverse: LE→BE

    // Concatenate into 32-byte hash: H0||H1||...||H7
    for (int i = 0; i < 7; i++) {
      b.opCode(OpCodes.OP_SWAP);
      b.opCode(OpCodes.OP_CAT);
    }

    return b;
  }

  /// Converts N 4-byte words on stack from BE→LE (or LE→BE, since reversal is symmetric).
  ///
  /// Pre: w0(top) w1 ... w(n-1). Post: w0_reversed(top) ... w(n-1)_reversed.
  /// Uses altstack to preserve order. Cost: n × 13 bytes.
  static ScriptBuilder _emitConvertWordsToLE(ScriptBuilder b, int n) {
    // Reverse each word and push to altstack (LIFO preserves order)
    for (int i = 0; i < n; i++) {
      OpcodeHelpers.reverseBytes4(b);
      b.opCode(OpCodes.OP_TOALTSTACK);
    }
    // Pop all back: first pushed (w0) comes out last, so order preserved
    for (int i = 0; i < n; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    return b;
  }

  /// Splits a byte string into N × 4-byte words.
  ///
  /// Pre: N*4 byte value on top. Post: N words, first at bottom, last on top.
  static ScriptBuilder _emitSplitIntoWords(ScriptBuilder b, int n) {
    for (int i = 0; i < n - 1; i++) {
      b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT);
      b.opCode(OpCodes.OP_SWAP);
      b.opCode(OpCodes.OP_TOALTSTACK);
    }
    b.opCode(OpCodes.OP_TOALTSTACK);
    for (int i = 0; i < n; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    return b;
  }
}
