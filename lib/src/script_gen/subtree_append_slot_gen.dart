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
import '../crypto/note_commitment_tree.dart';
import 'check_preimage_ocs.dart';
import 'm31_script_gen.dart';
import 'opcode_helpers.dart';
import 'poseidon2_script_gen.dart';

/// The PP1_SP subtree-append slot: a stateless, single-use sibling of the pool
/// state output that does one round's commitment appends in script.
///
/// It takes the round's 16 commitments (empties as zero lanes), builds their
/// depth-4 subtree (15 permutations), walks the empty subtree root and the
/// built one up the 28 main levels over the same siblings (56 permutations),
/// and publishes `rootBefore ‖ rootAfter ‖ index ‖ SHA256(cms)` by signing
/// SIGHASH_SINGLE over output *i* = `OP_RETURN payload`, *i* being its own
/// input index. The state input rebuilds that output from its own publics, so
/// the two agree on the append. hashPrevouts must start with the state's
/// outpoint (vout 0 of the slot's own parent), so the slot cannot be spent
/// without the state.
///
/// Unlock (bottom to top): preimage, prevoutsTail (every outpoint after the
/// state's, as raw bytes), index, rootBefore lanes (8), siblings 27..0 (8 lanes
/// each, level 0 on top), cms 15..0 (8 lanes each, cm 0 on top).
class SubtreeAppendSlotGen {
  static const sub = NoteCommitmentTree.subtreeDepth;
  static const leaves = NoteCommitmentTree.subtreeLeaves;
  static const main = NoteCommitmentTree.mainDepth;
  static const sighashType = 0x43; // SINGLE | FORKID
  static const stateVout = 0;

  static String cm(int i, int k) => 'cm${i}_$k';
  static String sib(int l, int k) => 'sb${l}_$k';
  static String rb(int k) => 'rb$k';

  static List<String> unlockLayout() => [
        'preimage', 'prevoutsTail', 'index',
        for (int k = 0; k < 8; k++) rb(k),
        for (int l = main - 1; l >= 0; l--) ...[for (int k = 0; k < 8; k++) sib(l, k)],
        for (int i = leaves - 1; i >= 0; i--) ...[for (int k = 0; k < 8; k++) cm(i, k)],
      ];

  /// The payload the state script must reproduce.
  static Uint8List payload(List<int> rootBefore, List<int> rootAfter, int index, List<List<int>> cms) {
    final bd = ByteData(4)..setUint32(0, index, Endian.little);
    final cmBytes = <int>[for (final c in _padded(cms)) ..._lanes(c)];
    return Uint8List.fromList([..._lanes(rootBefore), ..._lanes(rootAfter), ...bd.buffer.asUint8List(), ...crypto.sha256.convert(cmBytes).bytes]);
  }

  /// The result output: 0 sats, `OP_RETURN <payload>`.
  static Uint8List resultOutput(Uint8List payload) {
    if (payload.length != payloadBytes) throw ArgumentError('payload is $payloadBytes bytes');
    final script = [OpCodes.OP_RETURN, OpCodes.OP_PUSHDATA1, payload.length, ...payload];
    return Uint8List.fromList([...List.filled(8, 0), script.length, ...script]);
  }

  static List<List<int>> _padded(List<List<int>> cms) =>
      [...cms, for (int i = cms.length; i < leaves; i++) MerkleFrontier.emptyLeaf];

  static List<int> _lanes(List<int> lanes) {
    final out = Uint8List(4 * lanes.length);
    final bd = ByteData.view(out.buffer);
    for (int i = 0; i < lanes.length; i++) {
      bd.setUint32(4 * i, lanes[i], Endian.little);
    }
    return out;
  }

  static void _pushNum(ScriptBuilder b, int v) {
    if (v <= 16) {
      b.smallNum(v);
    } else {
      OpcodeHelpers.pushInt(b, v);
    }
  }

  SVScript unlock(Uint8List preimage, List<int> prevoutsTail, int index, List<int> rootBefore,
      List<List<int>> siblings, List<List<int>> cms) {
    final b = ScriptBuilder();
    b.addData(preimage);
    b.addData(Uint8List.fromList(prevoutsTail));
    _pushNum(b, index);
    for (final v in rootBefore) {
      _pushNum(b, v);
    }
    for (int l = main - 1; l >= 0; l--) {
      for (final v in siblings[l]) {
        _pushNum(b, v);
      }
    }
    final padded = _padded(cms);
    for (int i = leaves - 1; i >= 0; i--) {
      for (final v in padded[i]) {
        _pushNum(b, v);
      }
    }
    return b.build();
  }

  static void _op(StackEmitter e, int op, {int pops = 2, int pushes = 1, String? as}) =>
      e.raw(op, pops: pops, pushes: pushes, as: as);
  static void _cat(StackEmitter e, {String? as}) => _op(e, OpCodes.OP_CAT, as: as);
  static void _split(StackEmitter e, int n) {
    e.pushConst(n);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
  }

  /// 8 lanes -> 32 bytes on top (picks).
  static void _lanesToBytes(StackEmitter e, List<String> lanes, {required String as}) {
    for (int k = 0; k < lanes.length; k++) {
      e.pick(lanes[k]);
      e.pushConst(4);
      _op(e, OpCodes.OP_NUM2BIN);
      if (k > 0) _cat(e);
    }
    e.nameTop(as);
  }

  /// One level of the two walks: with the direction bit of [index] at level
  /// [l], hash both [a] (empty walk) and [b] (written walk) with the same
  /// sibling; the sibling goes left when the bit is 1.
  static void _level(StackEmitter e, int l, List<String> a, List<String> b) {
    for (final (node, last) in [(a, false), (b, true)]) {
      final s = List.generate(8, (k) => 'w$k');
      for (int k = 0; k < 8; k++) {
        e.roll(node[k]);
      }
      for (int k = 0; k < 8; k++) {
        if (last) {
          e.roll(sib(l, k), as: s[k]);
        } else {
          e.pick(sib(l, k), as: s[k]);
        }
      }
      // [node0..7 w0..7] -> swapped when the bit is set
      e.pick('index');
      e.pushConst(1 << l);
      _op(e, OpCodes.OP_DIV);
      e.pushConst(2);
      _op(e, OpCodes.OP_MOD);
      e.ifBegin();
      for (int k = 0; k < 8; k++) {
        e.pushConst(15);
        _op(e, OpCodes.OP_ROLL, pops: 1, pushes: 0);
      }
      e.ifEnd();
      // the emitter's names no longer match inside; both orders are [left8 right8]
      final lanes = List.generate(16, (k) => 'x$k');
      for (int k = 0; k < 16; k++) {
        e.nameAt(15 - k, lanes[k]);
      }
      Poseidon2ScriptGen.emitNode(e, lanes.sublist(0, 8), lanes.sublist(8), node);
    }
  }

  SVScript lock() {
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: unlockLayout());
    Poseidon2ScriptGen.emitPushP(e);
    // SHA256 of the commitments, before the permutations consume them
    _lanesToBytes(e, [for (int i = 0; i < leaves; i++) for (int k = 0; k < 8; k++) cm(i, k)], as: 'cmB');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'cmH');

    // ---- the subtree: 16 leaves -> 8 -> 4 -> 2 -> 1 ----
    var level = [for (int i = 0; i < leaves; i++) List.generate(8, (k) => cm(i, k))];
    var depth = 0;
    while (level.length > 1) {
      final next = <List<String>>[];
      for (int i = 0; i < level.length; i += 2) {
        final out = List.generate(8, (k) => 'n${depth}_${i ~/ 2}_$k');
        Poseidon2ScriptGen.emitNode(e, level[i], level[i + 1], out);
        next.add(out);
      }
      level = next;
      depth++;
    }
    final built = level[0];

    // ---- the two walks ----
    final empty = List.generate(8, (k) => 'e$k');
    final emptyRoot = MerkleFrontier.emptyRoots[sub];
    for (int k = 0; k < 8; k++) {
      e.pushConst(emptyRoot[k], as: empty[k]);
    }
    for (int l = 0; l < main; l++) {
      _level(e, l, empty, built);
    }
    // the empty walk must reach rootBefore
    for (int k = 0; k < 8; k++) {
      e.roll(empty[k]);
      e.pick(rb(k));
      e.numEqualVerify();
    }

    // ---- the payload: rootBefore ‖ rootAfter ‖ index ‖ SHA256(cms) ----
    _lanesToBytes(e, [for (int k = 0; k < 8; k++) rb(k)], as: 'pay');
    _lanesToBytes(e, built, as: 'raB');
    _cat(e);
    e.pick('index');
    e.pushConst(4);
    _op(e, OpCodes.OP_NUM2BIN);
    _cat(e);
    e.nameTop('pay');
    e.roll('cmH');
    _cat(e, as: 'pay');

    // ---- output i = OP_RETURN payload; hashOutputs (SIGHASH_SINGLE) ----
    e.pushData(List.filled(8, 0)); // value 0
    e.pushConst(payloadBytes + 3); // script length: OP_RETURN, PUSHDATA1, length byte, payload
    e.pushConst(1);
    _op(e, OpCodes.OP_NUM2BIN);
    _cat(e);
    e.pushData(const [OpCodes.OP_RETURN, OpCodes.OP_PUSHDATA1, payloadBytes]);
    _cat(e);
    e.roll('pay');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1, as: 'ho');

    // ---- preimage fields: hashPrevouts [4:36], txid [68:100], hashOutputs from the end ----
    e.pick('preimage');
    _split(e, 4);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1); // version
    _split(e, 32);
    e.nameAt(1, 'hashPrevouts');
    _split(e, 32);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1); // hashSequence
    _split(e, 32);
    e.nameAt(1, 'txid');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(8);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    e.drop(); // locktime, type
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(32);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1, as: 'hashOutputs');
    // hashOutputs == ours
    e.roll('ho');
    _op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
    // hashPrevouts == SHA256d((txid, stateVout) ‖ prevoutsTail)
    e.roll('txid');
    e.pushData(const [stateVout, 0, 0, 0]);
    _cat(e);
    e.roll('prevoutsTail');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashPrevouts');
    _op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);

    // ---- the signature, with OP_CODESEPARATOR so scriptCode is one byte ----
    e.roll('preimage');
    _emitCheckPreimageSingle(b);
    e.nameTop('ok');
    _op(e, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
    e.dropAll();
    e.pushConst(1);
    return b.build();
  }

  static const payloadBytes = 32 + 32 + 4 + 32;

  /// [CheckPreimageOCS.emitCheckPreimageOCS] with sighash type 0x43 and the
  /// code separator. Same s computation; only the type byte differs.
  static void _emitCheckPreimageSingle(ScriptBuilder b) {
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
    _emitDerEncode(b, sighashType);
    b.addData(CheckPreimageOCS.pubKey);
    b.opCode(OpCodes.OP_CODESEPARATOR);
    b.opCode(OpCodes.OP_CHECKSIG);
  }

  static void _emitDerEncode(ScriptBuilder b, int type) {
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
