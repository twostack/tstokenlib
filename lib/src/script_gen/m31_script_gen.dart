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
import '../crypto/m31.dart';
import 'opcode_helpers.dart';

/// A symbolic view of the interpreter stack used while emitting script.
///
/// Every entry may carry a name so that emitters can say `pick('f0')` or
/// `roll('xinv')` and have the correct OP_PICK / OP_ROLL depth computed for
/// them. Each entry also tracks whether its value is known to be
/// non-negative, which lets [reduce] emit the 6-byte reduction instead of the
/// 18-byte sign-correcting one.
///
/// Arithmetic is *lazy*: [mul], [add] and [sub] emit the bare opcode and leave
/// an unreduced integer on the stack. BSV script numbers are arbitrary
/// precision, so intermediate sums of products are safe. Call [reduce] when a
/// canonical M31 value in [0, p) is needed.
class StackEmitter {
  final ScriptBuilder b;
  final List<_Entry> _stack = [];
  final List<_Entry> _alt = [];
  final List<List<_Entry>> _ifStart = [];
  final List<List<_Entry>?> _ifEnd = [];

  StackEmitter(this.b, {List<String> initial = const []}) {
    for (final n in initial) {
      _stack.add(_Entry(n, nonNeg: true));
    }
  }

  int get size => _stack.length;
  int get altSize => _alt.length;

  int depth(String name) {
    final idx = _stack.lastIndexWhere((e) => e.name == name);
    if (idx < 0) throw StateError('no stack entry named "$name"');
    return _stack.length - 1 - idx;
  }

  bool has(String name) => _stack.any((e) => e.name == name);

  /// Rename the top entry.
  void nameTop(String name) => _stack.last.name = name;

  /// Rename an entry in place (no script emitted).
  void rename(String from, String to) {
    final idx = _stack.lastIndexWhere((e) => e.name == from);
    if (idx < 0) throw StateError('no stack entry named "$from"');
    _stack[idx].name = to;
  }

  void _pushSmall(int n) {
    if (n <= 16) {
      b.smallNum(n);
    } else {
      OpcodeHelpers.pushInt(b, n);
    }
  }

  /// Push a non-negative integer constant.
  void pushConst(int v, {String? as}) {
    if (v < 0) throw ArgumentError('pushConst expects non-negative');
    _pushSmall(v);
    _stack.add(_Entry(as, nonNeg: true));
  }

  /// Push the M31 modulus.
  void pushP() {
    OpcodeHelpers.pushInt(b, M31.p);
    _stack.add(_Entry(null, nonNeg: true));
  }

  /// Push raw bytes (e.g. a 32-byte hash) as data.
  void pushData(List<int> bytes, {String? as}) {
    b.addData(Uint8List.fromList(bytes));
    _stack.add(_Entry(as, nonNeg: true));
  }

  /// Copy a named entry to the top.
  void pick(String name, {String? as}) {
    final d = depth(name);
    final src = _stack[_stack.length - 1 - d];
    if (d == 0) {
      b.opCode(OpCodes.OP_DUP);
    } else if (d == 1) {
      b.opCode(OpCodes.OP_OVER);
    } else {
      _pushSmall(d);
      b.opCode(OpCodes.OP_PICK);
    }
    _stack.add(_Entry(as, nonNeg: src.nonNeg));
  }

  /// Move a named entry to the top (consuming its old position).
  void roll(String name, {String? as}) {
    final d = depth(name);
    final idx = _stack.length - 1 - d;
    final e = _stack.removeAt(idx);
    if (d == 0) {
      // already on top
    } else if (d == 1) {
      b.opCode(OpCodes.OP_SWAP);
    } else if (d == 2) {
      b.opCode(OpCodes.OP_ROT);
    } else {
      _pushSmall(d);
      b.opCode(OpCodes.OP_ROLL);
    }
    if (as != null) e.name = as;
    _stack.add(e);
  }

  void drop() {
    b.opCode(OpCodes.OP_DROP);
    _stack.removeLast();
  }

  /// Drop every remaining main-stack entry (test cleanup).
  void dropAll() {
    while (_stack.isNotEmpty) {
      if (_stack.length >= 2) {
        b.opCode(OpCodes.OP_2DROP);
        _stack.removeLast();
        _stack.removeLast();
      } else {
        drop();
      }
    }
  }

  void dropNamed(String name) {
    final d = depth(name);
    if (d == 0) {
      drop();
    } else if (d == 1) {
      b.opCode(OpCodes.OP_NIP);
      _stack.removeAt(_stack.length - 2);
    } else {
      roll(name);
      drop();
    }
  }

  void swap() {
    b.opCode(OpCodes.OP_SWAP);
    final t = _stack.removeLast();
    _stack.insert(_stack.length - 1, t);
  }

  /// OP_ROT: [a b c] -> [b c a]
  void rot() {
    b.opCode(OpCodes.OP_ROT);
    final a = _stack.removeAt(_stack.length - 3);
    _stack.add(a);
  }

  void dup({String? as}) {
    b.opCode(OpCodes.OP_DUP);
    _stack.add(_Entry(as, nonNeg: _stack.last.nonNeg));
  }

  /// Name the entry at [d] from the top (0 = top).
  void nameAt(int d, String name) => _stack[_stack.length - 1 - d].name = name;

  void toAlt() {
    b.opCode(OpCodes.OP_TOALTSTACK);
    _alt.add(_stack.removeLast());
  }

  void fromAlt() {
    b.opCode(OpCodes.OP_FROMALTSTACK);
    _stack.add(_alt.removeLast());
  }

  // ---- lazy arithmetic -------------------------------------------------

  void mul() {
    final y = _stack.removeLast();
    final x = _stack.removeLast();
    b.opCode(OpCodes.OP_MUL);
    _stack.add(_Entry(null, nonNeg: x.nonNeg && y.nonNeg));
  }

  void add() {
    final y = _stack.removeLast();
    final x = _stack.removeLast();
    b.opCode(OpCodes.OP_ADD);
    _stack.add(_Entry(null, nonNeg: x.nonNeg && y.nonNeg));
  }

  /// second - top
  void sub() {
    _stack.removeLast();
    _stack.removeLast();
    b.opCode(OpCodes.OP_SUB);
    _stack.add(_Entry(null, nonNeg: false));
  }

  /// Multiply top by a constant.
  void mulConst(int c) {
    final x = _stack.removeLast();
    OpcodeHelpers.pushInt(b, c);
    b.opCode(OpCodes.OP_MUL);
    _stack.add(_Entry(null, nonNeg: x.nonNeg && c >= 0));
  }

  /// Reduce the top entry to canonical [0, p).
  ///
  /// Non-negative: `<p> OP_MOD` (6 bytes).
  /// Possibly negative: `<p> OP_MOD <p> OP_ADD <p> OP_MOD` (18 bytes), because
  /// OP_MOD keeps the sign of the dividend.
  void reduce() {
    final e = _stack.last;
    OpcodeHelpers.pushInt(b, M31.p);
    b.opCode(OpCodes.OP_MOD);
    if (!e.nonNeg) {
      OpcodeHelpers.pushInt(b, M31.p);
      b.opCode(OpCodes.OP_ADD);
      OpcodeHelpers.pushInt(b, M31.p);
      b.opCode(OpCodes.OP_MOD);
    }
    e.nonNeg = true;
  }

  /// Negate a canonical value: p - x, then reduce (handles x = 0).
  void negCanonical() {
    pushP();
    swap();
    sub();
    reduce();
  }

  // ---- control flow ----------------------------------------------------


  /// Pops the condition and opens an IF block. The model is snapshotted so
  /// an ELSE branch starts from the same state; a branch may consume or
  /// produce entries as long as both branches end with the same names in
  /// the same order (checked at [ifEnd]).
  void ifBegin() {
    _stack.removeLast();
    b.opCode(OpCodes.OP_IF);
    _ifStart.add([for (final x in _stack) _Entry(x.name, nonNeg: x.nonNeg)]);
    _ifEnd.add(null);
  }

  void ifElse() {
    b.opCode(OpCodes.OP_ELSE);
    _ifEnd[_ifEnd.length - 1] = [for (final x in _stack) _Entry(x.name, nonNeg: x.nonNeg)];
    _stack
      ..clear()
      ..addAll([for (final x in _ifStart.last) _Entry(x.name, nonNeg: x.nonNeg)]);
  }

  /// Closes the IF block. With an ELSE, both branches must leave the same
  /// names in the same order; without one, the branch must be neutral.
  void ifEnd() {
    b.opCode(OpCodes.OP_ENDIF);
    final start = _ifStart.removeLast();
    final other = _ifEnd.removeLast();
    if (other == null) {
      // no ELSE: the branch must be size-neutral; its model stands (a
      // conditional swap leaves names in whichever order the branch chose)
      if (start.length != _stack.length) {
        throw StateError('IF branch changed the stack size: ${start.length} vs ${_stack.length}');
      }
      return;
    }
    if (other.length != _stack.length) {
      throw StateError('IF/ELSE branches end with different stack sizes: ${other.length} vs ${_stack.length}');
    }
    for (int i = 0; i < other.length; i++) {
      final a = other[i].name, c = _stack[i].name;
      if (a != null && c != null && a != c) {
        throw StateError('IF/ELSE branches end with different entries at $i: $a vs $c');
      }
      _stack[i].name ??= a; // a name given in one branch only still applies
      _stack[i].nonNeg = _stack[i].nonNeg && other[i].nonNeg;
    }
  }

  /// Drop every entry except the named ones, which end up on top in their
  /// current relative order.
  void dropAllExcept(Iterable<String> keep) {
    final names = keep.toList();
    for (final n in names) {
      roll(n);
    }
    for (int i = 0; i < names.length; i++) {
      toAlt();
    }
    dropAll();
    for (int i = 0; i < names.length; i++) {
      fromAlt();
    }
  }

  /// Mark a named entry's sign knowledge.
  void setNonNeg(String name, bool v) {
    _stack[_stack.length - 1 - depth(name)].nonNeg = v;
  }

  /// Emit a raw opcode with explicit stack effect (for hashing etc.).
  void raw(int opcode, {required int pops, required int pushes, String? as}) {
    for (int i = 0; i < pops; i++) {
      _stack.removeLast();
    }
    b.opCode(opcode);
    for (int i = 0; i < pushes; i++) {
      _stack.add(_Entry(i == pushes - 1 ? as : null, nonNeg: true));
    }
  }

  /// Verify top equals the constant [v] (consumes top).
  void numEqualVerifyConst(int v) {
    pushConst(v);
    _stack.removeLast();
    _stack.removeLast();
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);
  }

  /// Verify top equals the data [bytes] (consumes top).
  void equalVerifyData(List<int> bytes) {
    pushData(bytes);
    _stack.removeLast();
    _stack.removeLast();
    b.opCode(OpCodes.OP_EQUALVERIFY);
  }

  /// Verify the two top entries are numerically equal (consumes both).
  void numEqualVerify() {
    _stack.removeLast();
    _stack.removeLast();
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);
  }

  List<String?> debugNames() => _stack.map((e) => e.name).toList();
}

class _Entry {
  String? name;
  bool nonNeg;
  _Entry(this.name, {required this.nonNeg});
}

/// Emitters for M31 / QM31 field operations on a [StackEmitter].
///
/// Conventions:
///   * A QM31 element is four named M31 limbs in the order
///     [c0.a, c0.b, c1.a, c1.b] (see [QM31.limbs]).
///   * Inputs may be unreduced (any bounded integer); outputs are reduced
///     unless stated otherwise.
class M31Ops {
  /// Multiply two named entries. The [consume*] flags roll (consume) instead
  /// of picking (copying) the operand — use on the operand's last use.
  static void term(StackEmitter e, String x, String y,
      {bool consumeX = false, bool consumeY = false}) {
    if (consumeX) {
      e.roll(x);
    } else {
      e.pick(x);
    }
    if (consumeY) {
      e.roll(y);
    } else {
      e.pick(y);
    }
    e.mul();
  }

  /// QM31 multiply a * b, leaving four limbs named [out] on top.
  /// All eight input limbs are consumed.
  ///
  /// With a = (A0 + A1 u), b = (B0 + B1 u), u^2 = 2 + i:
  ///   r = A0 B0 + (2+i) A1 B1
  ///   s = A0 B1 + A1 B0
  static void qm31Mul(StackEmitter e, List<String> a, List<String> b,
      List<String> out, {bool reduceOut = true}) {
    if (a.length != 4 || b.length != 4 || out.length != 4) {
      throw ArgumentError('QM31 operands need 4 limbs');
    }
    final a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
    final b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3];

    // t0 = a2 b2 - a3 b3 ; t1 = a2 b3 + a3 b2   (A1 * B1 in CM31)
    term(e, a2, b2);
    term(e, a3, b3);
    e.sub();
    e.nameTop('_t0');
    term(e, a2, b3);
    term(e, a3, b2);
    e.add();
    e.nameTop('_t1');

    // r0 = a0 b0 - a1 b1 + 2 t0 - t1
    term(e, a0, b0);
    term(e, a1, b1);
    e.sub();
    e.pick('_t0');
    e.add();
    e.pick('_t0');
    e.add();
    e.pick('_t1');
    e.sub();
    e.nameTop('_r0');

    // r1 = a0 b1 + a1 b0 + t0 + 2 t1
    term(e, a0, b1);
    term(e, a1, b0);
    e.add();
    e.roll('_t0');
    e.add();
    e.pick('_t1');
    e.add();
    e.roll('_t1');
    e.add();
    e.nameTop('_r1');

    // s0 = a0 b2 - a1 b3 + a2 b0 - a3 b1
    term(e, a0, b2);
    term(e, a1, b3);
    e.sub();
    term(e, a2, b0);
    e.add();
    term(e, a3, b1);
    e.sub();
    e.nameTop('_s0');

    // s1 = a0 b3 + a1 b2 + a2 b1 + a3 b0   (last use of every input: roll)
    term(e, a0, b3, consumeX: true, consumeY: true);
    term(e, a1, b2, consumeX: true, consumeY: true);
    e.add();
    term(e, a2, b1, consumeX: true, consumeY: true);
    e.add();
    term(e, a3, b0, consumeX: true, consumeY: true);
    e.add();
    e.nameTop('_s1');

    // Stack now: [..., _r0, _r1, _s0, _s1]
    if (reduceOut) {
      // Rolling each to the top in turn preserves the order.
      e.roll('_r0');
      e.reduce();
      e.roll('_r1');
      e.reduce();
      e.roll('_s0');
      e.reduce();
      e.roll('_s1');
      e.reduce();
    }
    e.rename('_r0', out[0]);
    e.rename('_r1', out[1]);
    e.rename('_s0', out[2]);
    e.rename('_s1', out[3]);
  }

  /// QM31 add: out = a + b, consuming both. Outputs reduced.
  static void qm31Add(StackEmitter e, List<String> a, List<String> b,
      List<String> out) {
    for (int k = 0; k < 4; k++) {
      e.roll(a[k]);
      e.roll(b[k]);
      e.add();
      e.reduce();
      e.nameTop(out[k]);
    }
  }

  /// QM31 sub: out = a - b, consuming both. Outputs reduced.
  static void qm31Sub(StackEmitter e, List<String> a, List<String> b,
      List<String> out) {
    for (int k = 0; k < 4; k++) {
      e.roll(a[k]);
      e.roll(b[k]);
      e.sub();
      e.reduce();
      e.nameTop(out[k]);
    }
  }

  /// Multiply the four limbs [a] by the base-field entry [m], consuming [a]
  /// (and [m] if [consumeM]). Outputs reduced.
  static void qm31ScaleBy(StackEmitter e, List<String> a, String m,
      List<String> out, {bool consumeM = false}) {
    for (int k = 0; k < 4; k++) {
      e.roll(a[k]);
      if (k == 3 && consumeM) {
        e.roll(m);
      } else {
        e.pick(m);
      }
      e.mul();
      e.reduce();
      e.nameTop(out[k]);
    }
  }

  /// Verify that `x * xinv == 1 (mod p)` for named entries. Consumes [xinv]
  /// if [consumeInv], and [x] if [consumeX]; otherwise picks them.
  static void verifyInverse(StackEmitter e, String x, String xinv,
      {bool consumeX = false, bool consumeInv = true}) {
    if (consumeX) {
      e.roll(x);
    } else {
      e.pick(x);
    }
    if (consumeInv) {
      e.roll(xinv);
    } else {
      e.pick(xinv);
    }
    e.mul();
    e.reduce();
    e.numEqualVerifyConst(1);
  }
}
