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

/// Reusable Bitcoin Script idioms for SHA256 hand-optimization.
///
/// These helpers emit common opcode patterns used throughout the
/// hand-optimized SHA256 implementation, keeping the generator code
/// readable while producing compact script.
class OpcodeHelpers {

  /// Pushes an integer value onto the stack using the most compact encoding.
  ///
  /// - Values 0-16 use OP_0..OP_16 (1 byte each)
  /// - Values 17-255 use a 1-byte data push (2 bytes total)
  /// Pushes an integer value onto the stack using minimal script number encoding.
  ///
  /// Script numbers are little-endian with a sign bit in the MSB of the last byte.
  /// We must ensure the sign bit is never set for positive values.
  static ScriptBuilder pushInt(ScriptBuilder b, int value) {
    if (value >= 0 && value <= 16) {
      return b.smallNum(value);
    }

    // Encode as minimal LE byte array with positive sign
    var bytes = <int>[];
    int v = value;
    while (v > 0) {
      bytes.add(v & 0xFF);
      v >>= 8;
    }
    // If the high bit of the last byte is set, append 0x00 for positive sign
    if (bytes.last & 0x80 != 0) {
      bytes.add(0x00);
    }
    return b.addData(Uint8List.fromList(bytes));
  }

  /// Reverses a 4-byte value on top of stack (big-endian ↔ little-endian).
  ///
  /// Stack: [... x(4 bytes)] → [... x_reversed(4 bytes)]
  /// Cost: 12 bytes of script.
  ///
  /// Pattern: Split into 4 individual bytes, then reassemble in reverse order.
  /// ```
  /// OP_1 OP_SPLIT  →  byte0 | bytes1-3
  /// OP_1 OP_SPLIT  →  byte0 | byte1 | bytes2-3
  /// OP_1 OP_SPLIT  →  byte0 | byte1 | byte2 | byte3
  /// OP_SWAP OP_CAT →  byte0 | byte1 | byte3byte2
  /// OP_SWAP OP_CAT →  byte0 | byte3byte2byte1
  /// OP_SWAP OP_CAT →  byte3byte2byte1byte0
  /// ```
  static ScriptBuilder reverseBytes4(ScriptBuilder b) {
    return b
        .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
        .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
        .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
        .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
        .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
        .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT);
  }

  /// Truncates a script number to 32 bits (4 bytes).
  ///
  /// Stack: [... n(script number)] → [... n_truncated(4-byte LE)]
  /// Cost: 5 bytes of script.
  ///
  /// Serializes to 5 bytes (to capture any overflow bit), splits at 4,
  /// and drops the overflow byte.
  static ScriptBuilder truncate32(ScriptBuilder b) {
    return b
        .opCode(OpCodes.OP_5).opCode(OpCodes.OP_NUM2BIN)
        .opCode(OpCodes.OP_4).opCode(OpCodes.OP_SPLIT)
        .opCode(OpCodes.OP_DROP);
  }

  /// Converts a 4-byte LE byte string to a script number via OP_BIN2NUM.
  ///
  /// Stack: [... x(4-byte LE)] → [... x(script number)]
  /// Cost: 1 byte.
  static ScriptBuilder bin2num(ScriptBuilder b) {
    return b.opCode(OpCodes.OP_BIN2NUM);
  }

  /// Converts a script number to a 4-byte LE byte string via OP_4 OP_NUM2BIN.
  ///
  /// Stack: [... x(script number)] → [... x(4-byte LE)]
  /// Cost: 2 bytes.
  static ScriptBuilder num2bin4(ScriptBuilder b) {
    return b.opCode(OpCodes.OP_4).opCode(OpCodes.OP_NUM2BIN);
  }

  /// Adds two values on stack and truncates to 32 bits.
  ///
  /// Stack: [... a(num) b(num)] → [... (a+b)(4-byte LE)]
  /// Cost: 6 bytes (OP_ADD + truncate32).
  static ScriptBuilder addAndTruncate(ScriptBuilder b) {
    b.opCode(OpCodes.OP_ADD);
    return truncate32(b);
  }
}
