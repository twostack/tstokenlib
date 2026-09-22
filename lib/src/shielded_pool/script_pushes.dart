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

/// Reads the pushes of an unlocking script from its raw bytes.
///
/// A pool reader is handed transactions from wherever a wallet fetched
/// them, so an unlock is read as untrusted bytes: every length is checked
/// against what remains, and anything that is not a push is refused. After
/// Genesis a scriptSig must be push-only, so a mined unlock always parses;
/// one that does not was not mined.
class ScriptPushes {
  /// The data of each push in [script], up to [max] of them when given.
  /// OP_0 reads as empty, OP_1NEGATE and OP_1..OP_16 as their one-byte
  /// script numbers. Throws [FormatException] on a truncated push or an
  /// opcode that is not a push.
  static List<List<int>> read(List<int> script, {int? max}) {
    final out = <List<int>>[];
    var at = 0;
    while (at < script.length && (max == null || out.length < max)) {
      final op = script[at++];
      int n;
      if (op == 0x00) {
        out.add(const []);
        continue;
      } else if (op <= 0x4b) {
        n = op;
      } else if (op == 0x4c) {
        n = _len(script, at, 1);
        at += 1;
      } else if (op == 0x4d) {
        n = _len(script, at, 2);
        at += 2;
      } else if (op == 0x4e) {
        n = _len(script, at, 4);
        at += 4;
      } else if (op == 0x4f) {
        out.add(const [0x81]);
        continue;
      } else if (op >= 0x51 && op <= 0x60) {
        out.add([op - 0x50]);
        continue;
      } else {
        throw FormatException('opcode 0x${op.toRadixString(16)} at byte ${at - 1} is not a push');
      }
      if (n > script.length - at) throw FormatException('a push of $n bytes at byte $at runs past the end');
      out.add(script.sublist(at, at + n));
      at += n;
    }
    return out;
  }

  static int _len(List<int> s, int at, int bytes) {
    if (at + bytes > s.length) throw const FormatException('a push length is cut short');
    var n = 0;
    for (int i = bytes - 1; i >= 0; i--) {
      n = (n << 8) | s[at + i];
    }
    return n;
  }

  /// [push] as a non-negative script number below [bound], refusing any
  /// encoding but the minimal one, which is the only one the verifier's
  /// pushes produce.
  static int number(List<int> push, {required int bound}) {
    if (push.isEmpty) return 0;
    if (push.length > 5) throw FormatException('a number of ${push.length} bytes');
    if (push.last & 0x80 != 0) throw const FormatException('a negative number');
    if (push.last == 0 && (push.length == 1 || push[push.length - 2] & 0x80 == 0)) {
      throw const FormatException('a number that is not minimally encoded');
    }
    var v = 0;
    for (int i = push.length - 1; i >= 0; i--) {
      v = (v << 8) | push[i];
    }
    if (v >= bound) throw FormatException('$v is out of range');
    return v;
  }
}
