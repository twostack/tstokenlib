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
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'check_preimage_ocs.dart';
import 'm31_script_gen.dart';
import 'opcode_helpers.dart';

/// What every PP1_SP slot script shares: the sighash preimage fields it reads,
/// the check that the state is co-spent as input 0 of the same parent, the
/// SIGHASH_SINGLE result-output binding, and the OCS signature with the
/// slot's sighash type. A slot ends with `<pubkey> OP_CODESEPARATOR
/// OP_CHECKSIG`, so its scriptCode in the preimage is that one CHECKSIG.
class SlotScript {
  static const sighashSingle = 0x43; // SINGLE | FORKID
  static const stateVout = 0;

  static void op(StackEmitter e, int op, {int pops = 2, int pushes = 1, String? as}) =>
      e.raw(op, pops: pops, pushes: pushes, as: as);
  static void cat(StackEmitter e, {String? as}) => op(e, OpCodes.OP_CAT, as: as);
  static void split(StackEmitter e, int n) {
    e.pushConst(n);
    op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
  }

  /// 8 lanes -> 32 bytes on top (picks).
  static void lanesToBytes(StackEmitter e, List<String> lanes, {required String as}) {
    for (int k = 0; k < lanes.length; k++) {
      e.pick(lanes[k]);
      e.pushConst(4);
      op(e, OpCodes.OP_NUM2BIN);
      if (k > 0) cat(e);
    }
    e.nameTop(as);
  }

  static Uint8List lanesBytes(List<int> lanes) {
    final out = Uint8List(4 * lanes.length);
    final bd = ByteData.view(out.buffer);
    for (int i = 0; i < lanes.length; i++) {
      bd.setUint32(4 * i, lanes[i], Endian.little);
    }
    return out;
  }

  /// A 0-satoshi `OP_RETURN` output whose script is [script] (serialised
  /// as in a transaction: value, varint length, script).
  static Uint8List output(List<int> script, {int value = 0}) {
    final v = ByteData(8)..setUint64(0, value, Endian.little);
    final n = script.length;
    if (n >= 0x10000) throw ArgumentError('script too long');
    final len = n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8];
    return Uint8List.fromList([...v.buffer.asUint8List(), ...len, ...script]);
  }

  /// `OP_RETURN <32-byte payload>` as an output.
  static Uint8List resultOutput32(List<int> payload32) => output([OpCodes.OP_RETURN, 32, ...payload32]);

  /// `OP_RETURN` alone as an output: the skip result.
  static Uint8List emptyResultOutput() => output([OpCodes.OP_RETURN]);

  static Uint8List hash256(List<int> bytes) =>
      Uint8List.fromList(crypto.sha256.convert(crypto.sha256.convert(bytes).bytes).bytes);

  /// Picks [preimage] and leaves `hashPrevouts` [4:36], `txid` [68:100] and
  /// `hashOutputs` (32 bytes, 8 from the end) as named entries.
  static void emitPreimageFields(StackEmitter e, String preimage) {
    e.pick(preimage);
    split(e, 4);
    op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    split(e, 32);
    e.nameAt(1, 'hashPrevouts');
    split(e, 32);
    op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    split(e, 32);
    e.nameAt(1, 'txid');
    op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(8);
    op(e, OpCodes.OP_SUB);
    op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    e.drop();
    op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(32);
    op(e, OpCodes.OP_SUB);
    op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    op(e, OpCodes.OP_NIP, pops: 2, pushes: 1, as: 'hashOutputs');
  }

  /// hashPrevouts == SHA256d((txid, stateVout) ‖ prevoutsTail). Consumes
  /// `txid`, `hashPrevouts` and [prevoutsTail].
  static void emitStateCoSpent(StackEmitter e, String prevoutsTail) {
    e.roll('txid');
    e.pushData(const [stateVout, 0, 0, 0]);
    cat(e);
    e.roll(prevoutsTail);
    cat(e);
    op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashPrevouts');
    op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
  }

  /// hashOutputs == HASH256 of the output bytes on top (consumed with
  /// `hashOutputs`).
  static void emitOutputBound(StackEmitter e) {
    op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashOutputs');
    op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
  }

  /// Consumes the preimage on top and leaves the DER signature for it under
  /// [as] (the OCS trick with sighash [type]); the caller appends
  /// `<pubkey> OP_CODESEPARATOR OP_CHECKSIG`.
  static void emitSignature(StackEmitter e, int type, {String as = 'sig'}) {
    final b = e.b;
    b.opCode(OpCodes.OP_HASH256);
    OpcodeHelpers.reverseBytes32(b);
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);
    b.addData(CheckPreimageOCS.rLE);
    b.addData(CheckPreimageOCS.privKeyLE);
    b.opCode(OpCodes.OP_MUL);
    b.opCode(OpCodes.OP_ADD);
    b.addData(CheckPreimageOCS.invKLE);
    b.opCode(OpCodes.OP_MUL);
    b.addData(CheckPreimageOCS.nLE);
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
    b.addData(CheckPreimageOCS.nLE);
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
    _derEncode(b, type);
    e.nameTop(as); // one item in, one out
  }

  /// The common tail of a slot script.
  static List<int> checkSigTail() => [
        CheckPreimageOCS.pubKey.length, ...CheckPreimageOCS.pubKey,
        OpCodes.OP_CODESEPARATOR, OpCodes.OP_CHECKSIG,
      ];

  static void _derEncode(ScriptBuilder b, int type) {
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_NUM2BIN);
    OpcodeHelpers.reverseBytes32(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_TOALTSTACK);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_NUM2BIN);
    b.smallNum(2);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.addData(Uint8List.fromList([0x02, 0x20, ...CheckPreimageOCS.rBigEndian]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
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
    b.addData(Uint8List.fromList([type]));
    b.opCode(OpCodes.OP_CAT);
  }
}
