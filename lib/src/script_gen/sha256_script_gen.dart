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
  /// No intermediate truncation needed — max N=5 values each ≤2^32 sum to
  /// at most ~2^34.3, well within 5-byte NUM2BIN capacity (2^39).
  static ScriptBuilder emitAddNBE(ScriptBuilder b, int n) {
    if (n < 2) return b;

    // Convert top value to number
    emitBEToNum(b);

    for (int i = 1; i < n; i++) {
      // Swap to bring next unconverted BE value to top
      b.opCode(OpCodes.OP_SWAP);
      emitBEToNum(b);
      b.opCode(OpCodes.OP_ADD);
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

  /// Adds N values on top of stack (all 4-byte LE).
  ///
  /// Pre: [... v0 v1 ... v(n-1)] (v(n-1) on top), all 4-byte LE.
  /// Post: [... sum(4B LE)].
  /// No intermediate truncation needed — max N=5 values each ≤2^32 sum to
  /// at most ~2^34.3, well within 5-byte NUM2BIN capacity (2^39).
  static ScriptBuilder emitAddNLE(ScriptBuilder b, int n) {
    if (n < 2) return b;

    emitLEToNum(b);

    for (int i = 1; i < n; i++) {
      b.opCode(OpCodes.OP_SWAP);
      emitLEToNum(b);
      b.opCode(OpCodes.OP_ADD);
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
  /// Chained: ROTR(13)=ROTR(11,ROTR(2)), ROTR(22)=ROTR(9,ROTR(13)).
  /// Pre: a on top as 4-byte BE. Post: Σ0(a) on top as 4-byte BE.
  static ScriptBuilder emitBigSigma0(ScriptBuilder b) {
    // r2 = ROTR(2, a) — consumes a
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 30);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r2

    b.opCode(OpCodes.OP_DUP);         // save r2

    // r13 = ROTR(11, r2) — consumes copy
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 21);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r13

    b.opCode(OpCodes.OP_DUP);         // save r13

    // r22 = ROTR(9, r13) — consumes copy
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 23);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r22

    // Stack: r2 r13 r22
    b.opCode(OpCodes.OP_XOR);         // r2 (r13^r22)
    b.opCode(OpCodes.OP_XOR);         // Σ0
    return b;
  }

  /// Σ1(e) = ROTR(6,e) XOR ROTR(11,e) XOR ROTR(25,e)
  ///
  /// Chained: ROTR(11)=ROTR(5,ROTR(6)), ROTR(25)=ROTR(14,ROTR(11)).
  /// Pre: e on top as 4-byte BE. Post: Σ1(e) on top as 4-byte BE.
  static ScriptBuilder emitBigSigma1(ScriptBuilder b) {
    // r6 = ROTR(6, e) — consumes e
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 26);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r6

    b.opCode(OpCodes.OP_DUP);         // save r6

    // r11 = ROTR(5, r6) — consumes copy
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 27);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r11

    b.opCode(OpCodes.OP_DUP);         // save r11

    // r25 = ROTR(14, r11) — consumes copy
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_RSHIFT);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 18);
    b.opCode(OpCodes.OP_LSHIFT);
    b.opCode(OpCodes.OP_OR);           // r25

    // Stack: r6 r11 r25
    b.opCode(OpCodes.OP_XOR);         // r6 (r11^r25)
    b.opCode(OpCodes.OP_XOR);         // Σ1
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

  /// Ch(e,f,g) = g XOR (e AND (f XOR g))
  ///
  /// Pre: stack [... g f e] (e on top), all 4-byte. Post: [... Ch]. Consumes all 3.
  /// 6 opcodes (vs 8 for the (e&f)^(~e&g) form). Avoids OP_INVERT.
  static ScriptBuilder emitCh(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);                             // g e f
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);   // g e f g
    b.opCode(OpCodes.OP_XOR);                              // g e (f^g)
    b.opCode(OpCodes.OP_AND);                              // g (e&(f^g))
    b.opCode(OpCodes.OP_XOR);                              // g^(e&(f^g)) = Ch
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

  /// Pushes K[t] as a 4-byte LE immediate (5 bytes of script per call).
  ///
  /// Replaces the former K blob extraction + reverseBytes4 pattern,
  /// saving ~17 bytes per round vs the blob approach.
  static ScriptBuilder emitPushKLE(ScriptBuilder b, int t) {
    int k = PartialSha256.K[t];
    var bytes = ByteData(4);
    bytes.setUint32(0, k, Endian.little);
    b.addData(bytes.buffer.asUint8List());
    return b;
  }

  /// Fetches W[t] from W blob on altstack top.
  ///
  /// Altstack: [midstate_copy, W_blob(BE)] (W on top).
  static ScriptBuilder emitFetchW(ScriptBuilder b, int t) {
    b.opCode(OpCodes.OP_FROMALTSTACK);  // W
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);    // W back
    emitExtractWord(b, t * 4);
    return b;
  }

  /// Fetches W[t] from W blob on altstack, returns as 4-byte LE.
  ///
  /// W blob is stored in LE, so no endian conversion needed.
  static ScriptBuilder emitFetchWLE(ScriptBuilder b, int t) {
    emitFetchW(b, t);
    return b;
  }

  // =========================================================================
  // Message schedule (blob-based, LE storage)
  // =========================================================================

  /// Builds W[0..63] blob from 16 input words.
  ///
  /// Pre: 16 × 4-byte BE words on stack, W[0] on top, W[15] at bottom.
  /// Post: W_blob (256 bytes, LE words) on stack.
  ///
  /// Converts input words to LE during concatenation. Expansion uses LE
  /// additions for efficiency; σ0/σ1 are temporarily converted to BE.
  static ScriptBuilder emitMessageScheduleBlob(ScriptBuilder b) {
    // Convert W[0] (top) from BE to LE
    OpcodeHelpers.reverseBytes4(b);

    // Convert remaining words and concatenate into LE blob
    for (int i = 1; i < 16; i++) {
      b.opCode(OpCodes.OP_SWAP);
      OpcodeHelpers.reverseBytes4(b);  // BE → LE
      b.opCode(OpCodes.OP_CAT);       // blob || W[i]_LE
    }
    // Stack: W_blob (64 bytes, LE words)

    // Expand W[16..63] — blob in LE, sigma functions need BE
    for (int t = 16; t < 64; t++) {
      // W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]

      // σ0(W[t-15]): extract LE, convert to BE for σ0, back to LE
      emitExtractWordKeep(b, (t - 15) * 4);
      OpcodeHelpers.reverseBytes4(b);  // LE → BE
      emitSmallSigma0(b);
      OpcodeHelpers.reverseBytes4(b);  // BE → LE
      b.opCode(OpCodes.OP_TOALTSTACK);

      // σ1(W[t-2]): extract LE, convert to BE for σ1, back to LE
      emitExtractWordKeep(b, (t - 2) * 4);
      OpcodeHelpers.reverseBytes4(b);  // LE → BE
      emitSmallSigma1(b);
      OpcodeHelpers.reverseBytes4(b);  // BE → LE

      // W[t-7]: already LE from blob
      b.opCode(OpCodes.OP_OVER);
      emitExtractWord(b, (t - 7) * 4);

      // W[t-16]: already LE from blob
      b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
      emitExtractWord(b, (t - 16) * 4);

      // σ0 from altstack (LE)
      b.opCode(OpCodes.OP_FROMALTSTACK);

      // Sum all 4 LE values
      emitAddNLE(b, 4);
      // Stack: W[t](4B LE) blob

      // Append to blob
      b.opCode(OpCodes.OP_CAT);  // blob || W[t]_LE
    }

    return b;
  }

  // =========================================================================
  // Compression round (LE state words, sliding window W)
  // =========================================================================

  /// One compression round with LE state words and sliding window W.
  ///
  /// Stack: a(0) b(1) c(2) d(3) e(4) f(5) g(6) h(7) W_window(8+) — all LE.
  /// Altstack: [midstate_copy].
  /// After: a' b' c' d' e' f' g' h' W_window (all LE). Altstack unchanged.
  ///
  /// [wPickIdx] is the index of W[t] in the stack at the point of fetch
  /// (after Σ1, Ch, h, K have been pushed = 4 extra items above state).
  /// Rounds 0-15: 27-t. Rounds 16-63: 12.
  ///
  /// If [expand] is true, computes W[t+1] in the state rotation gap
  /// (state on altstack, only W on main stack) with zero extra overhead.
  static ScriptBuilder emitCompressionRound(ScriptBuilder b, int t,
      {required int wPickIdx, bool expand = false}) {
    // ======== T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t] ========

    // Σ1(e): e at idx 4 — LE wrapped (LE→BE→Σ1→BE→LE)
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);
    emitBigSigma1LE(b);

    // Ch(e,f,g): bitwise, endian-agnostic
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // g
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // f
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);   // e
    emitCh(b);

    // h at idx 9
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);

    // K[t] — inlined as 4-byte LE immediate
    emitPushKLE(b, t);

    // W[t] — PICK from sliding window (4 extra items above state)
    OpcodeHelpers.pushInt(b, wPickIdx);
    b.opCode(OpCodes.OP_PICK);

    // Sum 5 values: Σ1 + Ch + h + K + W
    emitAddNLE(b, 5);
    // STACK: T1(LE) a b c d e f g h W_window

    // ======== T2 = Σ0(a) + Maj(a,b,c) ========

    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);
    emitBigSigma0LE(b);

    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // c
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // b
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);   // a
    emitMaj(b);

    emitAdd32LE(b);
    // STACK: T2 T1 a b c d e f g h W_window

    // ======== State rotation via altstack ========

    // Compute e' = d + T1
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    emitAdd32LE(b);

    // Compute a' = T1 + T2
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    emitAdd32LE(b);

    // Push new state to altstack: a' b' c' d' e' f' g' h'
    b.opCode(OpCodes.OP_TOALTSTACK);                       // a'
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // b'=a
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // c'=b
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // d'=c
    b.opCode(OpCodes.OP_TOALTSTACK);                       // e'=d+T1
    b.opCode(OpCodes.OP_6); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // f'=e
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // g'=f
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_TOALTSTACK);                       // h'=g

    // Drop old state + T2 + T1: 10 items
    b.opCode(OpCodes.OP_2DROP); b.opCode(OpCodes.OP_2DROP);
    b.opCode(OpCodes.OP_2DROP); b.opCode(OpCodes.OP_2DROP);
    b.opCode(OpCodes.OP_2DROP);

    // === Gap: state on altstack, only W values on main stack ===
    if (expand) {
      _emitExpansionStep(b);
    }

    // Restore new state
    for (int i = 0; i < 8; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    return b;
  }

  /// Computes W[t+1] from the sliding window during the state rotation gap.
  ///
  /// Pre: only W values on main stack. W[t] at idx 0 (newest), W[t-15] at idx 15.
  /// Post: W[t+1] pushed on top. Window grows by 1.
  /// Altstack: state items below; σ0 temp pushed/popped cleanly above.
  ///
  /// Fixed PICK indices: σ0 input at 14, σ1 input at 1, W[t-6] at 7, W[t-15] at 17.
  static ScriptBuilder _emitExpansionStep(ScriptBuilder b) {
    // σ0(W[t-14]): W[t-14] at idx 14 (note: t+1-15 = t-14)
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.reverseBytes4(b);   // LE → BE
    emitSmallSigma0(b);
    OpcodeHelpers.reverseBytes4(b);   // BE → LE
    b.opCode(OpCodes.OP_TOALTSTACK);

    // σ1(W[t-1]): W[t-1] at idx 1 (note: t+1-2 = t-1)
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.reverseBytes4(b);
    emitSmallSigma1(b);
    OpcodeHelpers.reverseBytes4(b);
    // Stack: σ1(0), W[t](1), W[t-1](2), ..., +1 item above window

    // W[t-6] (= W[(t+1)-7]): was at idx 6, now at idx 7 (+1 for σ1)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);

    // W[t-15] (= W[(t+1)-16]): was at idx 15, now at idx 17 (+2 for σ1, W[t-6])
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_PICK);

    // σ0 from altstack
    b.opCode(OpCodes.OP_FROMALTSTACK);

    // Sum 4 LE values → W[t+1]
    emitAddNLE(b, 4);
    // W[t+1] now at idx 0, window grown by 1
    return b;
  }

  // =========================================================================
  // Full SHA256 block
  // =========================================================================

  /// One SHA256 block using sliding window W.
  ///
  /// Pre: block(64B BE, top) midstate(32B BE, below).
  /// Post: new_hash(32B BE).
  ///
  /// W values kept on main stack (sliding window) instead of blob on altstack.
  /// State in LE on top, W window in LE below. K constants inlined.
  static ScriptBuilder emitOneBlock(ScriptBuilder b) {
    // Stack: block(64B, top) midstate(32B)
    // Stash both midstate copies on altstack, then work with block.
    b.opCode(OpCodes.OP_SWAP);        // midstate(top) block
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash midstate copy for final addition
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash midstate for state init
    // Stack: block. Altstack: [midstate_copy, midstate]

    // Split block into 16 × 4-byte words (reversed: W[0] at bottom, W[15] on top)
    _emitSplitIntoWordsReversed(b, 16);

    // Convert all 16 words from BE to LE
    _emitConvertWordsToLE(b, 16);
    // Stack: W[0](bottom) ... W[15](top) — all LE

    // Retrieve midstate, split into 8 BE words, convert to LE → state on top of W
    b.opCode(OpCodes.OP_FROMALTSTACK);  // pop midstate
    _emitSplitIntoWords(b, 8);
    _emitConvertWordsToLE(b, 8);
    // Stack: W[0]..W[15]  a(top) b c d e f g h
    // Altstack: [midstate_copy]

    // 64 compression rounds with sliding window
    for (int t = 0; t < 64; t++) {
      // W[t] PICK index at fetch point (4 extra items above state: Σ1, Ch, h, K):
      // Rounds 0-15: W[t] at state idx 8+(15-t), plus 4 extra = 27-t
      // Rounds 16-63: W[t] always at state idx 8 (newest), plus 4 = 12
      int wPickIdx = (t < 16) ? (27 - t) : 12;

      // Expand W[t+1] during rounds 15-62 (in the state rotation gap)
      bool expand = (t >= 15 && t <= 62);

      emitCompressionRound(b, t, wPickIdx: wPickIdx, expand: expand);
    }
    // Stack: a'(LE) b' c' d' e' f' g' h' W[0]..W[63] (72 items total)

    // Save state to altstack, drop accumulated W values, restore state
    for (int i = 0; i < 8; i++) {
      b.opCode(OpCodes.OP_TOALTSTACK);
    }
    for (int i = 0; i < 32; i++) {
      b.opCode(OpCodes.OP_2DROP);     // drop 64 W values
    }
    for (int i = 0; i < 8; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }
    // Stack: a' b' c' d' e' f' g' h' (8 items, LE)
    // Altstack: [midstate_copy]

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
      emitAdd32LE(b);
      if (i < 7) {
        b.opCode(OpCodes.OP_TOALTSTACK);
      }
    }

    for (int i = 0; i < 7; i++) {
      b.opCode(OpCodes.OP_FROMALTSTACK);
    }

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

  /// Splits a byte string into N × 4-byte words in reversed order.
  ///
  /// Pre: N*4 byte value on top. Post: N words, first at bottom, last on top.
  /// Simple OP_4 OP_SPLIT loop — no altstack needed. Cost: 2*(N-1) bytes.
  ///
  /// Each split peels off the leftmost 4 bytes (word 0, 1, 2, ...) and leaves
  /// them below the remainder, so word 0 ends up deepest and word N-1 on top.
  static ScriptBuilder _emitSplitIntoWordsReversed(ScriptBuilder b, int n) {
    for (int i = 0; i < n - 1; i++) {
      b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT);
    }
    return b;
  }
}
