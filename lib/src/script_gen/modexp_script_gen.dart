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

import 'package:dartsv/dartsv.dart';
import '../crypto/rabin.dart';

/// Prototype: in-script modular exponentiation over native BSV bignums.
///
/// Emits an unrolled right-to-left (LSB-first) square-and-multiply loop:
///
/// ```
/// acc = 1
/// for i in 0 .. bits-1:
///     if (e & 1) acc = acc * b mod m
///     b = b * b mod m          (skipped on the final iteration)
///     e = e >> 1
/// ```
///
/// The exponent is consumed as stack data, so the script is correct for any
/// exponent 0 <= e < 2^bits. The modulus is embedded as a constant (a
/// protocol parameter such as a Schnorr-group prime or an RSA modulus).
///
/// Stack layout during the loop:
///   main: [m, b, acc]     alt: [e]
///
/// Entry stack (from scriptSig): [base, e]   (e on top)
/// Exit stack:                   [base^e mod m]
class ModExpScriptGen {
  /// Push a non-negative BigInt as a script number, using OP_0..OP_16 for
  /// small values (ScriptBuilder.addData mis-serializes 1-byte pushes in 1..16).
  static void pushBigInt(ScriptBuilder b, BigInt v) {
    if (v >= BigInt.zero && v <= BigInt.from(16)) {
      b.smallNum(v.toInt());
    } else {
      b.addData(Rabin.bigIntToScriptNum(v));
    }
  }

  /// Emit `base^e mod m` for an exponent of at most [bits] bits.
  static ScriptBuilder emitModExp(ScriptBuilder b, BigInt m, int bits) {
    if (bits < 1) throw ArgumentError('bits must be >= 1');

    // [base, e] -> alt:[e], main:[base]
    b.opCode(OpCodes.OP_TOALTSTACK);
    // [base] -> [m, base]
    pushBigInt(b, m);
    b.opCode(OpCodes.OP_SWAP);
    // [m, base] -> [m, base, 1]
    b.opCode(OpCodes.OP_1);

    for (int i = 0; i < bits; i++) {
      final last = (i == bits - 1);

      // Fetch exponent, extract low bit.
      b.opCode(OpCodes.OP_FROMALTSTACK);
      if (last) {
        // [m, b, acc, e] -> [m, b, acc, bit]
        b.opCode(OpCodes.OP_2).opCode(OpCodes.OP_MOD);
      } else {
        // [m, b, acc, e] -> [m, b, acc, e, bit]
        b.opCode(OpCodes.OP_DUP).opCode(OpCodes.OP_2).opCode(OpCodes.OP_MOD);
        // -> [m, b, acc, bit, e] -> [m, b, acc, bit]   alt:[e>>1]
        b.opCode(OpCodes.OP_SWAP)
         .opCode(OpCodes.OP_2).opCode(OpCodes.OP_DIV)
         .opCode(OpCodes.OP_TOALTSTACK);
      }

      // Conditional multiply: acc = acc * b mod m
      b.opCode(OpCodes.OP_IF);
      //   [m, b, acc] -> [m, b, acc*b]
      b.opCode(OpCodes.OP_OVER).opCode(OpCodes.OP_MUL);
      //   -> [m, b, acc*b mod m]
      b.opCode(OpCodes.OP_2).opCode(OpCodes.OP_PICK).opCode(OpCodes.OP_MOD);
      b.opCode(OpCodes.OP_ENDIF);

      if (!last) {
        // Square: b = b * b mod m
        // [m, b, acc] -> [m, acc, b] -> [m, acc, b*b]
        b.opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_DUP).opCode(OpCodes.OP_MUL);
        // -> [m, acc, b*b mod m]
        b.opCode(OpCodes.OP_2).opCode(OpCodes.OP_PICK).opCode(OpCodes.OP_MOD);
        // -> [m, b, acc]
        b.opCode(OpCodes.OP_SWAP);
      }
    }

    // [m, b, acc] -> [acc]
    b.opCode(OpCodes.OP_NIP).opCode(OpCodes.OP_NIP);
    return b;
  }

  /// Build a scriptPubKey that computes base^e mod m in-script and verifies
  /// the result equals [expected].
  static SVScript generateVerify(BigInt m, int bits, BigInt expected) {
    var b = ScriptBuilder();
    emitModExp(b, m, bits);
    pushBigInt(b, expected);
    b.opCode(OpCodes.OP_NUMEQUAL);
    return b.build();
  }

  /// scriptSig pushing [base, e].
  static SVScript buildScriptSig(BigInt base, BigInt e) {
    var b = ScriptBuilder();
    pushBigInt(b, base);
    pushBigInt(b, e);
    return b.build();
  }
}
