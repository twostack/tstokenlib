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
import 'check_preimage_ocs.dart';
import 'm31_script_gen.dart';
import 'slot_script_common.dart';

/// The deposit covenant (design 7.1): the output a depositor pays into, which
/// only the round it names can spend, and only by writing the depositor's
/// receipt.
///
/// Lock: `<cm 32> <pp3Outpoint 36> <refundPKH 20> <refundAfter 4> body`, the
/// body the same bytes for every deposit, so a coordinator recognises one by
/// its hash. `pp3Outpoint` is PP3_N's: a deposit targets round N+1, the one
/// round that can spend PP3_N.
///
/// Two branches, on the unlock's last push:
///
///   * 1, the round (unlock `[prevouts, preimage, 1]`), SIGHASH_SINGLE: the
///     round's input 3 is `pp3Outpoint`, and the output at the covenant's own
///     index is `OP_FALSE OP_RETURN cm value` with value this output's whole
///     value. Naming the outpoint, not the pool's program, is what makes it
///     the live pool: anyone can copy the program into an output of their own,
///     and only one transaction can ever spend PP3_N. V ties receipt r to
///     receipt slot r, and the root proof ties that slot to a transfer whose
///     first output is `cm` with this value and two dummy inputs.
///   * 0, the refund (unlock `[sig, pubkey, preimage, 0]`), SIGHASH_ALL: a
///     signature from the key hashing to `refundPKH`, in a transaction whose
///     nLockTime is at least `refundAfter` and whose input is not final, so
///     consensus holds it back until then. BSV disabled
///     OP_CHECKLOCKTIMEVERIFY at Genesis, so the lock time is read out of the
///     preimage instead.
///
/// The body ends `OP_CODESEPARATOR <ocsKey> OP_CHECKSIGVERIFY OP_IF
/// OP_CHECKSIG OP_ELSE OP_1 OP_ENDIF`: the preimage's scriptCode, and the
/// depositor's in a refund, is those opcodes.
class PoolDepositGen {
  static const sighashRound = 0x43; // SINGLE | FORKID
  static const sighashRefund = 0x41; // ALL | FORKID

  /// nLockTime values from here up are Unix times, not block heights.
  static const lockTimeThreshold = 500000000;

  /// The round's input that spends PP3_N (`PP1SpScriptGen.poolPP3Input`).
  static const pp3Input = 3;

  static Uint8List? _body;

  /// The body after the four pushes.
  static Uint8List body() => _body ??= _build();

  /// The scriptCode both branches' signatures commit to.
  static final SVScript scriptCode = SVScript.fromByteArray(Uint8List.fromList(_tail()));

  static List<int> _tail() => [
        CheckPreimageOCS.pubKey.length, ...CheckPreimageOCS.pubKey,
        OpCodes.OP_CHECKSIGVERIFY,
        OpCodes.OP_IF, OpCodes.OP_CHECKSIG, OpCodes.OP_ELSE, OpCodes.OP_1, OpCodes.OP_ENDIF,
      ];

  /// A deposit's locking script.
  static SVScript lock({
    required List<int> commitment,
    required List<int> pp3Outpoint,
    required List<int> refundPKH,
    required int refundAfter,
  }) {
    if (commitment.length != 32 || pp3Outpoint.length != 36 || refundPKH.length != 20) {
      throw ArgumentError('a 32-byte commitment, a 36-byte outpoint and a 20-byte key hash');
    }
    if (refundAfter <= 0 || refundAfter >= lockTimeThreshold) {
      throw ArgumentError('refundAfter must be a block height, under $lockTimeThreshold');
    }
    final t = ByteData(4)..setUint32(0, refundAfter, Endian.little);
    return SVScript.fromByteArray(Uint8List.fromList([
      32, ...commitment,
      36, ...pp3Outpoint,
      20, ...refundPKH,
      4, ...t.buffer.asUint8List(),
      ...body(),
    ]));
  }

  static void _op(StackEmitter e, int op, {int pops = 2, int pushes = 1, String? as}) =>
      e.raw(op, pops: pops, pushes: pushes, as: as);
  static void _split(StackEmitter e, int n) {
    e.pushConst(n);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
  }

  static void _unsigned(StackEmitter e) {
    e.pushData(const [0]);
    _op(e, OpCodes.OP_CAT);
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
  }

  /// Bytes [n - fromEnd, n - fromEnd + len) of the named preimage, as [as].
  static void _fromEnd(StackEmitter e, String pre, int fromEnd, int len, String as) {
    e.pick(pre);
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(fromEnd);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    _op(e, OpCodes.OP_NIP);
    _split(e, len);
    e.drop();
    e.nameTop(as);
  }

  static Uint8List _build() {
    // the selector is under the four pushes
    final head = ScriptBuilder()
      ..opCode(OpCodes.OP_4)
      ..opCode(OpCodes.OP_ROLL)
      ..opCode(OpCodes.OP_IF);

    // ---- the round ----
    final rb = ScriptBuilder();
    final r = StackEmitter(rb, initial: const ['prevouts', 'pre', 'cm', 'op', 'pkh', 'T']);
    e2drop(r, ['pkh', 'T']);
    // the round's prevouts, exactly the bytes hashPrevouts commits to, so
    // they are whole outpoints in input order; PP3_N is at input 3
    r.pick('prevouts');
    _op(r, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    r.pick('pre');
    _split(r, 4);
    _op(r, OpCodes.OP_NIP);
    _split(r, 32);
    r.drop();
    _op(r, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
    r.roll('prevouts');
    _split(r, 36 * pp3Input);
    _op(r, OpCodes.OP_NIP);
    _split(r, 36);
    r.drop();
    r.roll('op');
    _op(r, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
    // the output at this input's index is the receipt, for this output's
    // whole value: value is 8 bytes at 52 from the end, hashOutputs 32 at 40
    r.pushData(const [0, 0, 0, 0, 0, 0, 0, 0, 0x2c, 0x00, 0x6a, 0x20]);
    r.roll('cm');
    _op(r, OpCodes.OP_CAT);
    r.pushConst(8); // OP_8: the byte 0x08, the value's push length
    _op(r, OpCodes.OP_CAT);
    _fromEnd(r, 'pre', 52, 8, 'value');
    r.roll('value');
    _op(r, OpCodes.OP_CAT);
    _op(r, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    _fromEnd(r, 'pre', 40, 32, 'hashOutputs');
    r.roll('hashOutputs');
    _op(r, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
    r.roll('pre');
    SlotScript.emitSignature(r, sighashRound, as: 'ocsSig');
    r.pushConst(0, as: 'flag');
    r.swap();

    // ---- the refund ----
    final fb = ScriptBuilder();
    final f = StackEmitter(fb, initial: const ['sig', 'pub', 'pre', 'cm', 'op', 'pkh', 'T']);
    e2drop(f, ['cm', 'op']);
    f.pick('pub');
    _op(f, OpCodes.OP_HASH160, pops: 1, pushes: 1);
    f.roll('pkh');
    _op(f, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
    // nLockTime (8 from the end) at least refundAfter, both block heights:
    // from 500,000,000 up it is a Unix time, final since 1985, and would let
    // the depositor take the deposit back at once, racing the round
    _fromEnd(f, 'pre', 8, 4, 'lt');
    f.roll('lt');
    _unsigned(f);
    f.nameTop('ltn');
    f.pick('ltn');
    f.pushConst(lockTimeThreshold);
    _op(f, OpCodes.OP_LESSTHAN);
    _op(f, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
    f.roll('ltn');
    f.roll('T');
    _unsigned(f);
    _op(f, OpCodes.OP_GREATERTHANOREQUAL);
    _op(f, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
    // and this input not final, or the lock time is not enforced: nSequence
    // is 4 bytes at 44 from the end
    _fromEnd(f, 'pre', 44, 4, 'seq');
    f.roll('seq');
    f.pushData(const [0xff, 0xff, 0xff, 0xff]);
    _op(f, OpCodes.OP_EQUAL);
    _op(f, OpCodes.OP_NOT, pops: 1, pushes: 1);
    _op(f, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
    f.roll('pre');
    SlotScript.emitSignature(f, sighashRefund, as: 'ocsSig');
    f.pushConst(1, as: 'flag');
    f.swap();

    return Uint8List.fromList([
      ...head.build().buffer,
      ...rb.build().buffer,
      OpCodes.OP_ELSE,
      ...fb.build().buffer,
      OpCodes.OP_ENDIF,
      OpCodes.OP_CODESEPARATOR,
      ..._tail(),
    ]);
  }

  /// Drops the named entries (the branch does not use them).
  static void e2drop(StackEmitter e, List<String> names) {
    for (final n in names) {
      e.dropNamed(n);
    }
  }

  /// The round's unlock: every prevout of the round, in order, and the
  /// SIGHASH_SINGLE preimage of the covenant's input.
  static SVScript unlockRound(List<int> prevouts, List<int> preimage) {
    final b = ScriptBuilder()
      ..addData(Uint8List.fromList(prevouts))
      ..addData(Uint8List.fromList(preimage))
      ..opCode(OpCodes.OP_1);
    return b.build();
  }

  /// The refund's unlock.
  static SVScript unlockRefund(List<int> sig, List<int> pubKey, List<int> preimage) {
    final b = ScriptBuilder()
      ..addData(Uint8List.fromList(sig))
      ..addData(Uint8List.fromList(pubKey))
      ..addData(Uint8List.fromList(preimage))
      ..opCode(OpCodes.OP_0);
    return b.build();
  }

  /// The terms of a deposit covenant, or null when [lockingScript] is not
  /// one: its four pushes at their fixed sizes, then exactly [body].
  static PoolDepositTerms? parse(List<int> lockingScript) {
    final l = lockingScript;
    final b = body();
    if (l.length != _headSize + b.length) return null;
    if (l[0] != 32 || l[33] != 36 || l[70] != 20 || l[91] != 4) return null;
    for (int i = 0; i < b.length; i++) {
      if (l[_headSize + i] != b[i]) return null;
    }
    final t = ByteData.sublistView(Uint8List.fromList(l.sublist(92, 96))).getUint32(0, Endian.little);
    return PoolDepositTerms(
        commitment: l.sublist(1, 33), pp3Outpoint: l.sublist(34, 70), refundPKH: l.sublist(71, 91), refundAfter: t);
  }

  static const _headSize = 1 + 32 + 1 + 36 + 1 + 20 + 1 + 4;

  /// The receipt output's script the covenant requires.
  static List<int> receiptScript(List<int> commitment, BigInt value) {
    final v = ByteData(8)..setUint64(0, value.toInt(), Endian.little);
    return [0x00, 0x6a, 0x20, ...commitment, 0x08, ...v.buffer.asUint8List()];
  }
}

/// What a deposit covenant says: the note's commitment, the PP3 it targets,
/// and who may take it back from which block height.
class PoolDepositTerms {
  final List<int> commitment;
  final List<int> pp3Outpoint;
  final List<int> refundPKH;
  final int refundAfter;

  const PoolDepositTerms({
    required this.commitment,
    required this.pp3Outpoint,
    required this.refundPKH,
    required this.refundAfter,
  });
}
