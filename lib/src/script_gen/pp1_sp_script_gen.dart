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
import '../crypto/m31.dart';
import '../crypto/note_commitment_tree.dart';
import '../crypto/nullifier_set.dart';
import '../crypto/stark_prover_ref.dart';
import 'check_preimage_ocs.dart';
import 'm31_script_gen.dart';
import 'opcode_helpers.dart';
import 'pool_spend_air.dart';
import 'slot_script_common.dart';
import 'subtree_append_slot_gen.dart';
import 'verifier_slot_gen.dart';

/// The PP1_SP header: the pushes at the head of the pool's state script.
///
///   tokenId          32  immutable  the funding txid the create spends (vout 0)
///   rabinPubKeyHash  20  immutable  hash160 of the operator's Rabin n
///   phase             1  mutable    0 issued, 1 live
///   ring[4]          32  mutable    commitment roots, ring[0] current
///   size              4  mutable    leaves in the tree (padding included)
///   nfRoot           32  mutable    the nullifier set's root
class PP1SpHeader {
  static const ringSize = 4;
  static const bytesTotal = 33 + 21 + 2 + ringSize * 33 + 5 + 33;

  final Uint8List tokenId, rabinPubKeyHash, nfRoot;
  final int phase, size;
  final List<Uint8List> ring;

  PP1SpHeader({
    required List<int> tokenId,
    required List<int> rabinPubKeyHash,
    required this.phase,
    required List<List<int>> ring,
    required this.size,
    required List<int> nfRoot,
  })  : tokenId = Uint8List.fromList(tokenId),
        rabinPubKeyHash = Uint8List.fromList(rabinPubKeyHash),
        ring = [for (final r in ring) Uint8List.fromList(r)],
        nfRoot = Uint8List.fromList(nfRoot) {
    if (this.tokenId.length != 32 || this.rabinPubKeyHash.length != 20 || this.nfRoot.length != 32) {
      throw ArgumentError('field sizes');
    }
    if (this.ring.length != ringSize || this.ring.any((r) => r.length != 32)) throw ArgumentError('ring');
    if (phase < 0 || phase > 1 || size < 0 || size >= 1 << 31) throw ArgumentError('phase/size');
  }

  /// The issued pool: empty tree, sentinel-only nullifier set.
  factory PP1SpHeader.issued({required List<int> tokenId, required List<int> rabinPubKeyHash}) => PP1SpHeader(
        tokenId: tokenId,
        rabinPubKeyHash: rabinPubKeyHash,
        phase: 0,
        ring: List.filled(ringSize, emptyRootBytes),
        size: 0,
        nfRoot: NullifierSet().root,
      );

  static final Uint8List emptyRootBytes = SlotScript.lanesBytes(MerkleFrontier.emptyRoots[NoteCommitmentTree.depth]);

  PP1SpHeader live() =>
      PP1SpHeader(tokenId: tokenId, rabinPubKeyHash: rabinPubKeyHash, phase: 1, ring: ring, size: size, nfRoot: nfRoot);

  /// After a round: the new root enters the ring, a subtree of leaves is
  /// appended, the nullifier set advances.
  PP1SpHeader afterRound(List<int> rootAfterLanes, List<int> nfRootAfter, {int leaves = NoteCommitmentTree.subtreeLeaves}) => PP1SpHeader(
        tokenId: tokenId,
        rabinPubKeyHash: rabinPubKeyHash,
        phase: 1,
        ring: [SlotScript.lanesBytes(rootAfterLanes), ...ring.sublist(0, ringSize - 1)],
        size: size + leaves,
        nfRoot: nfRootAfter,
      );

  Uint8List get cmRoot => ring[0];

  Uint8List bytes() {
    final out = <int>[32, ...tokenId, 20, ...rabinPubKeyHash, 1, phase];
    for (final r in ring) {
      out.addAll([32, ...r]);
    }
    final sz = ByteData(4)..setUint32(0, size, Endian.little);
    out.addAll([4, ...sz.buffer.asUint8List(), 32, ...nfRoot]);
    if (out.length != bytesTotal) throw StateError('header size');
    return Uint8List.fromList(out);
  }

  static PP1SpHeader parse(List<int> script) {
    var i = 0;
    Uint8List take(int n) {
      if (script[i] != n) throw FormatException('expected a $n-byte push at $i');
      final v = Uint8List.fromList(script.sublist(i + 1, i + 1 + n));
      i += 1 + n;
      return v;
    }
    final tokenId = take(32), rabin = take(20), phase = take(1)[0];
    final ring = [for (int r = 0; r < ringSize; r++) take(32)];
    final size = ByteData.sublistView(take(4)).getUint32(0, Endian.little);
    final nf = take(32);
    return PP1SpHeader(tokenId: tokenId, rabinPubKeyHash: rabin, phase: phase, ring: ring, size: size, nfRoot: nf);
  }
}

/// One transfer of a round, as the state script's unlock carries it.
class PP1SpTransfer {
  final PoolPublicInputs publics;
  final Uint8List extraOutputs;
  /// Insertion witnesses; null for a dummy input (`publics.real1/2` off),
  /// whose nullifier the state script does not insert.
  final NullifierInsertion? nf1, nf2;
  const PP1SpTransfer(this.publics, this.extraOutputs, this.nf1, this.nf2);
}

/// The PP1_SP state script: header, then a two-way dispatch on the selector
/// under the header: 1 = spend (a round of up to K transfers), 0 = create.
///
/// Spend, input 0 of a round transaction, SIGHASH_ALL, no code separator (the
/// preimage's scriptCode is this script, from which the child is rebuilt):
///   * phase == 1; hashPrevouts == (txid,0) ‖ (txid,1..K) ‖ (txid,K+1) ‖ extra
///     funding outpoints: the parent's K verifier slots and append slot are
///     the co-inputs, in order;
///   * per transfer t, gated by a used flag: canonical lanes, anchor in the
///     ring, the signed balance off the vault, two nullifier insertions, the
///     outHash of its extra outputs, its two commitments into the subtree,
///     its result output `OP_RETURN SHA256(publics)` (or the empty result and
///     no extras when unused);
///   * the append result for the subtree at index size/32 from ring[0] to
///     the supplied rootAfter;
///   * outputs: the state with the rotated ring, size + 32 and the new
///     nullifier root; K + 1 results; K fresh verifier slots and one append
///     slot from bytes checked against the hashes baked in here; the
///     transfers' extra outputs in order. hashOutputs must match.
///
/// Create, the first spend of the issued pool (input 1; input 0 spends
/// (tokenId, 0), which can happen once per tokenId): phase == 0 and the empty
/// state; hash160(rabinN) == rabinPubKeyHash; a Rabin signature over
/// SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId); outputs: the live state
/// with any vault, K + 1 empty results, K verifier slots, the append slot,
/// any extras. Slots therefore always sit at vouts K+2..2K+2 of their parent.
class PP1SpScriptGen {
  static const ringSize = PP1SpHeader.ringSize;
  static const slotSats = 1;
  static const sighashAll = 0x41;
  static const tailBytes = 8 + 4 + 32 + 4 + 4;

  final StarkParams P;
  final int k;
  final VerifierSlotGen verifierSlot;
  final SubtreeAppendSlotGen appendSlot = SubtreeAppendSlotGen();
  late final Uint8List verifierBytes, appendBytes, verifierHash, appendHash;
  SVScript? _body;

  /// Aggregated mode: [n] transfers per round, all verified by ONE slot
  /// (the aggregation's root verifier) whose publics are every transfer's
  /// lanes (padded to [laneChunk]) then the [roundLanes]; the root proof
  /// also proves the tree update, so there is no append slot and the size
  /// grows by [leavesAppended]. 0 = slot mode (K slots + append slot).
  final int n;
  final int leavesAppended;
  bool get aggregated => n > 0;
  static const laneChunk = 8 * ((PoolPublicInputs.count + 7) ~/ 8);
  static const roundLanes = 24;
  int get lanesPerTransfer => aggregated ? laneChunk : PoolPublicInputs.count;
  static String rc(int j) => 'rc$j';

  PP1SpScriptGen(this.P, {this.k = 2})
      : verifierSlot = VerifierSlotGen(P),
        n = 0,
        leavesAppended = 0 {
    if (2 * k > NoteCommitmentTree.subtreeLeaves) throw ArgumentError('at most ${NoteCommitmentTree.subtreeLeaves ~/ 2} transfers');
    verifierBytes = Uint8List.fromList(verifierSlot.lock().buffer);
    appendBytes = Uint8List.fromList(appendSlot.lock().buffer);
    verifierHash = Uint8List.fromList(crypto.sha256.convert(verifierBytes).bytes);
    appendHash = Uint8List.fromList(crypto.sha256.convert(appendBytes).bytes);
  }

  PP1SpScriptGen.aggregated(this.P, {required this.verifierSlot, required int transfers, required this.leavesAppended})
      : k = 0,
        n = transfers {
    if (n <= 0 || leavesAppended % NoteCommitmentTree.subtreeLeaves != 0 || leavesAppended < 2 * n) throw ArgumentError('transfers / leaves');
    if (verifierSlot.numPublics != n * laneChunk + roundLanes) throw ArgumentError('the slot must take the wide statement');
    verifierBytes = Uint8List.fromList(verifierSlot.lock().buffer);
    appendBytes = Uint8List(0);
    verifierHash = Uint8List.fromList(crypto.sha256.convert(verifierBytes).bytes);
    appendHash = Uint8List(0);
  }

  // ---- names ----
  static const headerNames = ['h_tokenId', 'h_rabin', 'h_phase', 'h_ring0', 'h_ring1', 'h_ring2', 'h_ring3', 'h_size', 'h_nf'];
  static String pub(int t, int k) => 'p${t}_$k';
  static String lowSib(int i, int k) => 'ls${i}_$k';
  static String lowBit(int i, int k) => 'lb${i}_$k';
  static String newSib(int i, int k) => 'ns${i}_$k';
  static String newBit(int i, int k) => 'nb${i}_$k';
  static const depth = NullifierSet.depth;

  static List<String> nullifierNames(int i) => [
        'nv$i', 'nn$i',
        for (int j = depth - 1; j >= 0; j--) ...[newSib(i, j), newBit(i, j)],
        for (int j = depth - 1; j >= 0; j--) ...[lowSib(i, j), lowBit(i, j)],
      ];

  List<String> spendLayout() => aggregated
      ? [
          'preimage', 'vBytes', 'extraPrevouts',
          for (int t = n - 1; t >= 0; t--) ...[
            'x$t',
            for (int j = 0; j < laneChunk; j++) pub(t, j),
            ...nullifierNames(2 * t),
            ...nullifierNames(2 * t + 1),
          ],
          for (int j = 0; j < roundLanes; j++) rc(j),
          ...headerNames,
        ]
      : [
        'preimage', 'vBytes', 'aBytes', 'extraPrevouts',
        for (int j = 0; j < 8; j++) 'ra$j',
        for (int t = k - 1; t >= 0; t--) ...[
          'u$t', 'x$t',
          for (int j = 0; j < PoolPublicInputs.count; j++) pub(t, j),
          ...nullifierNames(2 * t),
          ...nullifierNames(2 * t + 1),
        ],
        ...headerNames,
      ];

  List<String> get createLayout => [
        'preimage', 'vBytes', if (!aggregated) 'aBytes', 'rabinN', 'rabinS', 'rabinPad', 'idTxId', 'ed25519', 'vout', 'extras', ...headerNames
      ];

  // ---- script ----
  SVScript lock(PP1SpHeader h) => SVScript.fromByteArray([...h.bytes(), ...body().buffer]);

  /// The body, generated twice so the baked-in body length is exact.
  SVScript body() {
    if (_body != null) return _body!;
    final first = _emitBody(bodyLen: 0);
    final second = _emitBody(bodyLen: first.length);
    if (second.length != first.length) throw StateError('body length did not settle');
    return _body = SVScript.fromByteArray(second);
  }

  List<int> _emitBody({required int bodyLen}) {
    final spend = ScriptBuilder();
    _emitSpend(StackEmitter(spend, initial: spendLayout()), bodyLen: bodyLen);
    final create = ScriptBuilder();
    _emitCreate(StackEmitter(create, initial: createLayout), bodyLen: bodyLen);
    return [
      OpCodes.OP_9, OpCodes.OP_ROLL, OpCodes.OP_IF, // the selector sits under the 9 header pushes
      ...spend.build().buffer,
      OpCodes.OP_ELSE,
      ...create.build().buffer,
      OpCodes.OP_ENDIF,
    ];
  }

  static void _op(StackEmitter e, int op, {int pops = 2, int pushes = 1, String? as}) =>
      e.raw(op, pops: pops, pushes: pushes, as: as);
  static void _cat(StackEmitter e, {String? as}) => _op(e, OpCodes.OP_CAT, as: as);
  static void _verify(StackEmitter e) => _op(e, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
  static void _equalVerify(StackEmitter e) => _op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);

  /// Top: a number -> its varint bytes.
  static void _varint(StackEmitter e) {
    e.dup();
    e.pushConst(0xfd);
    _op(e, OpCodes.OP_LESSTHAN);
    e.ifBegin();
    e.pushConst(1);
    _op(e, OpCodes.OP_NUM2BIN);
    e.ifElse();
    e.dup();
    e.pushConst(0x10000);
    _op(e, OpCodes.OP_LESSTHAN);
    e.ifBegin();
    e.pushConst(2);
    _op(e, OpCodes.OP_NUM2BIN);
    e.pushData(const [0xfd]);
    e.swap();
    _cat(e);
    e.ifElse();
    e.pushConst(4);
    _op(e, OpCodes.OP_NUM2BIN);
    e.pushData(const [0xfe]);
    e.swap();
    _cat(e);
    e.ifEnd();
    e.ifEnd();
  }

  /// [value8 bytes on top? no:] builds `value ‖ varint(len) ‖ script` from
  /// the script bytes on top and [sats]; leaves it named [as].
  static void _outputOf(StackEmitter e, int sats, {required String as}) {
    e.nameTop('_scr');
    e.pick('_scr');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    _varint(e);
    final v = ByteData(8)..setUint64(0, sats, Endian.little);
    e.pushData(v.buffer.asUint8List());
    e.swap();
    _cat(e);
    e.roll('_scr');
    _cat(e, as: as);
  }

  static void _canonical(StackEmitter e, String Function(int) p, int first, int count) {
    for (int j = 0; j < count; j++) {
      e.pick(p(first + j));
      e.pushP();
      _op(e, OpCodes.OP_LESSTHAN);
      _verify(e);
    }
  }

  static void _signedLane(StackEmitter e, String name) {
    e.pick(name);
    e.dup();
    e.pushConst((M31.p - 1) >> 1);
    _op(e, OpCodes.OP_GREATERTHAN);
    e.ifBegin();
    e.pushP();
    _op(e, OpCodes.OP_SUB);
    e.ifEnd();
  }

  static void _unsigned(StackEmitter e) {
    e.pushData(const [0]);
    _cat(e);
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
  }

  static void _dualPath(StackEmitter e, String a, String b, String Function(int) sib, String Function(int) bit) {
    e.roll(a);
    e.roll(b);
    for (int j = 0; j < depth; j++) {
      e.roll(sib(j));
      e.dup();
      e.roll(bit(j));
      e.ifBegin();
      e.pushConst(3);
      _op(e, OpCodes.OP_ROLL, pops: 1, pushes: 0);
      _op(e, OpCodes.OP_ROT, pops: 3, pushes: 3);
      e.pushConst(3);
      _op(e, OpCodes.OP_ROLL, pops: 1, pushes: 0);
      e.ifElse();
      _op(e, OpCodes.OP_ROT, pops: 3, pushes: 3);
      _op(e, OpCodes.OP_SWAP, pops: 2, pushes: 2);
      e.ifEnd();
      _cat(e);
      _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
      _op(e, OpCodes.OP_ROT, pops: 3, pushes: 3);
      _op(e, OpCodes.OP_ROT, pops: 3, pushes: 3);
      _cat(e);
      _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
      _op(e, OpCodes.OP_SWAP, pops: 2, pushes: 2);
      e.nameAt(1, a);
      e.nameTop(b);
    }
  }

  /// One nullifier insertion (witness i, lanes at [p](laneIdx..)), replacing [root].
  static void _insertNullifier(StackEmitter e, int i, String Function(int) p, int laneIdx, String root) {
    SlotScript.lanesToBytes(e, [for (int j = 0; j < 8; j++) p(laneIdx + j)], as: 'nfB');
    e.pick('nv$i');
    _unsigned(e);
    e.pick('nfB');
    _unsigned(e);
    _op(e, OpCodes.OP_LESSTHAN);
    _verify(e);
    e.pick('nfB');
    _unsigned(e);
    e.pick('nn$i');
    _unsigned(e);
    _op(e, OpCodes.OP_LESSTHAN);
    _verify(e);
    e.pick('nv$i');
    e.pick('nn$i');
    _cat(e);
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'leafA');
    e.roll('nv$i');
    e.pick('nfB');
    _cat(e);
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'leafB');
    _dualPath(e, 'leafA', 'leafB', (j) => lowSib(i, j), (j) => lowBit(i, j));
    e.roll('leafA');
    e.roll(root);
    _equalVerify(e);
    e.pushData(NullifierSet.emptyLeaf, as: 'leafC');
    e.roll('nfB');
    e.roll('nn$i');
    _cat(e);
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'leafD');
    _dualPath(e, 'leafC', 'leafD', (j) => newSib(i, j), (j) => newBit(i, j));
    e.roll('leafC');
    e.roll('leafB');
    _equalVerify(e);
    e.rename('leafD', root);
  }

  List<String> get accumulators => aggregated ? const ['vout', 'nfRoot', 'pb', 'extras'] : const ['vout', 'nfRoot', 'cmsB', 'outs', 'extras'];

  void _rollAccumulators(StackEmitter e) {
    for (final a in accumulators) {
      e.roll(a);
    }
  }

  /// Transfer [t], used.
  void _transfer(StackEmitter e, int t) {
    String p(int j) => pub(t, j);
    _canonical(e, p, PoolPublicInputs.idxAnchor, 8);
    _canonical(e, p, PoolPublicInputs.idxNf1, 16);
    _canonical(e, p, PoolPublicInputs.idxPubLo, 2);
    _canonical(e, p, PoolPublicInputs.idxReal1, 2);
    // anchor in the ring
    SlotScript.lanesToBytes(e, [for (int j = 0; j < 8; j++) p(PoolPublicInputs.idxAnchor + j)], as: 'anchorB');
    for (int r = 0; r < ringSize; r++) {
      e.pick('anchorB');
      e.pick('h_ring$r');
      _op(e, OpCodes.OP_EQUAL);
      if (r > 0) _op(e, OpCodes.OP_BOOLOR);
    }
    _verify(e);
    e.dropNamed('anchorB');
    // vault: vout -= lo + 2^28 hi (signed)
    _signedLane(e, p(PoolPublicInputs.idxPubHi));
    e.pushConst(1 << PoolHash.limbBits);
    _op(e, OpCodes.OP_MUL);
    _signedLane(e, p(PoolPublicInputs.idxPubLo));
    _op(e, OpCodes.OP_ADD);
    e.roll('vout');
    e.swap();
    _op(e, OpCodes.OP_SUB, as: 'vout');
    // nullifiers: inserted for a real input note, skipped for a dummy (the
    // flag is a public the proof pinned to the circuit's flag register)
    _insertIfReal(e, 2 * t, p, PoolPublicInputs.idxNf1, PoolPublicInputs.idxReal1, 'nfRoot');
    _insertIfReal(e, 2 * t + 1, p, PoolPublicInputs.idxNf2, PoolPublicInputs.idxReal2, 'nfRoot');
    // outHash of this transfer's extra outputs
    e.pick('x$t');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    for (int j = 0; j < 8; j++) {
      if (j < 7) {
        SlotScript.split(e, 4);
        e.swap();
      }
      e.pushData(const [0xff, 0xff, 0xff, 0x7f]);
      _op(e, OpCodes.OP_AND);
      _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
      e.pick(p(PoolPublicInputs.idxOutHash + j));
      e.numEqualVerify();
    }
    if (aggregated) {
      // the transfer's lanes into the statement bytes (the one result output)
      e.roll('pb');
      SlotScript.lanesToBytes(e, [for (int j = 0; j < laneChunk; j++) p(j)], as: 'tb');
      _cat(e, as: 'pb');
    } else {
      // the two commitments into the subtree
      e.roll('cmsB');
      SlotScript.lanesToBytes(e, [for (int j = 0; j < 16; j++) p(PoolPublicInputs.idxCm1 + j)], as: 'cmB');
      _cat(e, as: 'cmsB');
      // the result output: OP_RETURN SHA256(publics)
      e.roll('outs');
      SlotScript.lanesToBytes(e, [for (int j = 0; j < PoolPublicInputs.count; j++) p(j)], as: 'pb');
      _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
      e.pushData([...List.filled(8, 0), 34, OpCodes.OP_RETURN, 32]);
      e.swap();
      _cat(e);
      _cat(e, as: 'outs');
    }
    // the extra outputs
    e.roll('extras');
    e.roll('x$t');
    _cat(e, as: 'extras');
    for (int j = 0; j < lanesPerTransfer; j++) {
      e.dropNamed(p(j));
    }
    _rollAccumulators(e);
  }

  /// The round lanes of an aggregated round: rootBefore must be ring[0],
  /// rootAfter becomes `raB`, the index is size / 32, the rest zero; then
  /// the one result output `OP_RETURN SHA256(all lanes)`.
  void _roundChunk(StackEmitter e) {
    _canonical(e, rc, 0, roundLanes);
    SlotScript.lanesToBytes(e, [for (int j = 0; j < 8; j++) rc(j)], as: 'rbB');
    e.roll('rbB');
    e.pick('h_ring0');
    _equalVerify(e);
    SlotScript.lanesToBytes(e, [for (int j = 0; j < 8; j++) rc(8 + j)], as: 'raB');
    e.pick('h_size');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1, as: 'sz');
    e.pick('sz');
    e.pushConst(NoteCommitmentTree.subtreeLeaves);
    _op(e, OpCodes.OP_MOD);
    e.pushConst(0);
    e.numEqualVerify();
    e.pick('sz');
    e.pushConst(NoteCommitmentTree.subtreeLeaves);
    _op(e, OpCodes.OP_DIV);
    e.pick(rc(16));
    e.numEqualVerify();
    for (int j = 17; j < roundLanes; j++) {
      e.pick(rc(j));
      e.pushConst(0);
      e.numEqualVerify();
    }
    e.roll('pb');
    SlotScript.lanesToBytes(e, [for (int j = 0; j < roundLanes; j++) rc(j)], as: 'rcB');
    _cat(e);
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    e.pushData([...List.filled(8, 0), 34, OpCodes.OP_RETURN, 32]);
    e.swap();
    _cat(e, as: 'outs');
    for (int j = 0; j < roundLanes; j++) {
      e.dropNamed(rc(j));
    }
  }

  static void _insertIfReal(StackEmitter e, int i, String Function(int) p, int laneIdx, int realIdx, String root) {
    e.pick(p(realIdx));
    e.ifBegin();
    _insertNullifier(e, i, p, laneIdx, root);
    e.ifElse();
    for (final n in nullifierNames(i)) {
      e.dropNamed(n);
    }
    e.roll(root);
    e.ifEnd();
  }

  /// Transfer [t], unused: no extras, an empty result, empty leaves.
  void _skipTransfer(StackEmitter e, int t) {
    e.roll('x$t');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    e.pushConst(0);
    e.numEqualVerify();
    for (int j = 0; j < PoolPublicInputs.count; j++) {
      e.dropNamed(pub(t, j));
    }
    for (final n in [...nullifierNames(2 * t), ...nullifierNames(2 * t + 1)]) {
      e.dropNamed(n);
    }
    e.roll('cmsB');
    e.pushData(List.filled(64, 0));
    _cat(e, as: 'cmsB');
    e.roll('outs');
    e.pushData([...List.filled(8, 0), 1, OpCodes.OP_RETURN]);
    _cat(e, as: 'outs');
    _rollAccumulators(e);
  }

  void _emitSpend(StackEmitter e, {required int bodyLen}) {
    // phase == 1
    e.pick('h_phase');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    e.pushConst(1);
    e.numEqualVerify();
    // accumulators
    e.pushConst(0, as: 'vout'); // minus the total balance leaving the vault
    e.pick('h_nf', as: 'nfRoot');
    if (aggregated) {
      e.pushData(const [], as: 'pb');
      e.pushData(const [], as: 'extras');
      for (int t = 0; t < n; t++) {
        _transfer(e, t);
      }
      _roundChunk(e);
      _emitNewHeaderAndTail(e, bodyLen: bodyLen);
      return;
    }
    e.pushData(const [], as: 'cmsB');
    e.pushData(const [], as: 'outs');
    e.pushData(const [], as: 'extras');
    for (int t = 0; t < k; t++) {
      e.roll('u$t');
      e.ifBegin();
      _transfer(e, t);
      e.ifElse();
      _skipTransfer(e, t);
      e.ifEnd();
    }
    // the append result: subtree size/32 from ring[0] to rootAfter
    e.pick('h_size');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1, as: 'sz');
    e.pick('sz');
    e.pushConst(NoteCommitmentTree.subtreeLeaves);
    _op(e, OpCodes.OP_MOD);
    e.pushConst(0);
    e.numEqualVerify();
    SlotScript.lanesToBytes(e, [for (int j = 0; j < 8; j++) 'ra$j'], as: 'raB');
    e.roll('outs');
    e.pick('h_ring0');
    e.pick('raB');
    _cat(e);
    e.pick('sz');
    e.pushConst(NoteCommitmentTree.subtreeLeaves);
    _op(e, OpCodes.OP_DIV);
    e.pushConst(4);
    _op(e, OpCodes.OP_NUM2BIN);
    _cat(e);
    e.roll('cmsB');
    final pad = 32 * NoteCommitmentTree.subtreeLeaves - 64 * k;
    if (pad > 0) {
      e.pushData(List.filled(pad, 0));
      _cat(e);
    }
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    _cat(e); // payload
    e.pushData([...List.filled(8, 0), SubtreeAppendSlotGen.payloadBytes + 3, OpCodes.OP_RETURN, OpCodes.OP_PUSHDATA1, SubtreeAppendSlotGen.payloadBytes]);
    e.swap();
    _cat(e);
    _cat(e, as: 'outs');
    _emitNewHeaderAndTail(e, bodyLen: bodyLen);
  }

  /// From `raB`, `sz`, `outs`, `vout`, `extras` and the header: the new
  /// header, the preimage checks, the vault, hashPrevouts and hashOutputs.
  void _emitNewHeaderAndTail(StackEmitter e, {required int bodyLen}) {
    // the new header
    e.pushData(const [32]);
    e.pick('h_tokenId');
    _cat(e);
    e.pushData(const [20]);
    _cat(e);
    e.pick('h_rabin');
    _cat(e);
    e.pushData(const [1, 1]);
    _cat(e);
    e.pushData(const [32]);
    _cat(e);
    e.roll('raB');
    _cat(e);
    for (int r = 0; r < ringSize - 1; r++) {
      e.pushData(const [32]);
      _cat(e);
      e.pick('h_ring$r');
      _cat(e);
    }
    e.pushConst(4); // OP_4 pushes the byte 0x04
    _cat(e);
    e.roll('sz');
    e.pushConst(aggregated ? leavesAppended : NoteCommitmentTree.subtreeLeaves);
    _op(e, OpCodes.OP_ADD);
    e.pushConst(4);
    _op(e, OpCodes.OP_NUM2BIN);
    _cat(e);
    e.pushData(const [32]);
    _cat(e);
    e.roll('nfRoot');
    _cat(e, as: 'newHdr');
    // the preimage: fields, then the signature
    _preimageFields(e, bodyLen: bodyLen);
    // vault out = value in + the accumulated (-publicOut) sum, non-negative
    e.roll('valueIn');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    e.roll('vout');
    _op(e, OpCodes.OP_ADD, as: 'vault');
    e.pick('vault');
    e.pushConst(0);
    _op(e, OpCodes.OP_GREATERTHANOREQUAL);
    _verify(e);
    // hashPrevouts: state, K verifier slots, the append slot (the parent's
    // vouts k+2..2k+2, after its k+1 result outputs), then extra inputs
    e.pick('txid');
    e.pushData(const [0, 0, 0, 0]);
    _cat(e);
    for (int v = slotVout0; v <= (aggregated ? slotVout0 : appendVout); v++) {
      e.pick('txid');
      _cat(e);
      e.pushData([v, 0, 0, 0]);
      _cat(e);
    }
    e.dropNamed('txid');
    e.roll('extraPrevouts');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashPrevouts');
    _equalVerify(e);
    // outputs
    _stateOutput(e, 'vault', 'newHdr');
    e.roll('outs');
    _cat(e);
    if (aggregated) {
      _slotOutputsAgg(e);
    } else {
      _slotOutputs(e);
    }
    e.roll('extras');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashOutputs');
    _equalVerify(e);
    e.dropAll();
    e.pushConst(1);
  }

  /// `preimage` -> named `valueIn`, `hashOutputs`, `txid`, `hashPrevouts`,
  /// `body` (the last [bodyLen] bytes of the scriptCode); then the OCS check.
  void _preimageFields(StackEmitter e, {required int bodyLen}) {
    e.pick('preimage');
    SlotScript.split(e, 4);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    SlotScript.split(e, 32);
    e.nameAt(1, 'hashPrevouts');
    SlotScript.split(e, 32);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    SlotScript.split(e, 32);
    e.nameAt(1, 'txid');
    // rest = vout ‖ varint ‖ header ‖ body ‖ value ‖ nSeq ‖ hashOutputs ‖ locktime ‖ type
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(tailBytes);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2, as: 'tail');
    e.nameAt(1, 'head');
    e.roll('tail');
    SlotScript.split(e, 8);
    e.nameAt(1, 'valueIn');
    SlotScript.split(e, 4);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    SlotScript.split(e, 32);
    e.drop();
    e.nameTop('hashOutputs');
    e.roll('head');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushData((ByteData(4)..setUint32(0, bodyLen, Endian.little)).buffer.asUint8List());
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1, as: 'body');
    e.roll('preimage');
    CheckPreimageOCS.emitCheckPreimageOCS(e.b, useCodeSeparator: false);
    e.nameTop('sigOk');
    _verify(e);
  }

  /// `vault ‖ varint ‖ header ‖ body` from the named number [vault] and the
  /// named header bytes; consumes both and `body`. Leaves the bytes on top.
  void _stateOutput(StackEmitter e, String vault, String header) {
    e.roll(header);
    e.roll('body');
    _cat(e);
    e.nameTop('_scr');
    e.pick('_scr');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP, pops: 2, pushes: 1);
    _varint(e);
    e.roll(vault);
    e.pushConst(8);
    _op(e, OpCodes.OP_NUM2BIN);
    e.swap();
    _cat(e);
    e.roll('_scr');
    _cat(e);
  }

  /// Appends the one verifier slot output (aggregated mode).
  void _slotOutputsAgg(StackEmitter e) {
    e.nameTop('acc');
    e.pick('vBytes');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    e.pushData(verifierHash);
    _equalVerify(e);
    e.roll('vBytes');
    _outputOf(e, slotSats, as: 'vOut');
    e.roll('acc');
    e.roll('vOut');
    _cat(e, as: 'acc');
  }

  /// Appends K verifier slot outputs and the append slot output to the bytes
  /// on top, checking the supplied scripts against the baked hashes.
  void _slotOutputs(StackEmitter e) {
    e.nameTop('acc');
    e.pick('vBytes');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    e.pushData(verifierHash);
    _equalVerify(e);
    e.roll('vBytes');
    _outputOf(e, slotSats, as: 'vOut');
    for (int i = 0; i < k; i++) {
      e.roll('acc');
      if (i < k - 1) {
        e.pick('vOut');
      } else {
        e.roll('vOut');
      }
      _cat(e, as: 'acc');
    }
    e.pick('aBytes');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    e.pushData(appendHash);
    _equalVerify(e);
    e.roll('aBytes');
    _outputOf(e, slotSats, as: 'aOut');
    e.roll('acc');
    e.roll('aOut');
    _cat(e, as: 'acc');
  }

  void _emitCreate(StackEmitter e, {required int bodyLen}) {
    // the issued state
    e.pick('h_phase');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    e.pushConst(0);
    e.numEqualVerify();
    e.pushData(PP1SpHeader.emptyRootBytes, as: 'empty');
    for (int r = 0; r < ringSize; r++) {
      e.pick('h_ring$r');
      if (r < ringSize - 1) {
        e.pick('empty');
      } else {
        e.roll('empty');
      }
      _equalVerify(e);
    }
    e.pick('h_size');
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    e.pushConst(0);
    e.numEqualVerify();
    e.pick('h_nf');
    e.pushData(NullifierSet().root);
    _equalVerify(e);
    // the operator's identity: hash160(rabinN) == rabinPubKeyHash, and the
    // Rabin signature over SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId)
    e.pick('rabinN');
    _op(e, OpCodes.OP_HASH160, pops: 1, pushes: 1);
    e.pick('h_rabin');
    _equalVerify(e);
    e.roll('idTxId');
    e.roll('ed25519');
    _cat(e);
    e.pick('h_tokenId');
    _cat(e);
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    _unsigned(e);
    e.roll('rabinPad');
    _op(e, OpCodes.OP_ADD);
    e.roll('rabinS');
    e.dup();
    _op(e, OpCodes.OP_MUL);
    e.roll('rabinN');
    _op(e, OpCodes.OP_MOD);
    e.numEqualVerify();
    // the live header: the same fields, phase 1
    e.pushData(const [32]);
    e.pick('h_tokenId');
    _cat(e);
    e.pushData(const [20]);
    _cat(e);
    e.pick('h_rabin');
    _cat(e);
    e.pushData(const [1, 1]);
    _cat(e);
    for (int r = 0; r < ringSize; r++) {
      e.pushData(const [32]);
      _cat(e);
      e.pick('h_ring$r');
      _cat(e);
    }
    e.pushConst(4);
    _cat(e);
    e.pushData(const [0, 0, 0, 0]);
    _cat(e);
    e.pushData(const [32]);
    _cat(e);
    e.pick('h_nf');
    _cat(e, as: 'newHdr');
    // the preimage
    _preimageFields(e, bodyLen: bodyLen);
    e.dropNamed('valueIn');
    // hashPrevouts == (tokenId, 0) ‖ (txid, 0): the create spends the funding output once
    e.pick('h_tokenId');
    e.pushData(const [0, 0, 0, 0]);
    _cat(e);
    e.roll('txid');
    _cat(e);
    e.pushData(const [0, 0, 0, 0]);
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashPrevouts');
    _equalVerify(e);
    // outputs: the live state with the chosen vault, k+1 empty results (so
    // the slots sit at the same vouts as after a round), the slots, extras
    _stateOutput(e, 'vout', 'newHdr');
    e.pushData([for (int i = 0; i < numResults; i++) ...[...List.filled(8, 0), 1, OpCodes.OP_RETURN]]);
    _cat(e);
    if (aggregated) {
      _slotOutputsAgg(e);
    } else {
      _slotOutputs(e);
    }
    e.roll('extras');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hashOutputs');
    _equalVerify(e);
    e.dropAll();
    e.pushConst(1);
  }

  // ---- unlocking scripts ----
  static void _pushNum(ScriptBuilder b, int v) {
    if (v >= 0 && v <= 16) {
      b.smallNum(v);
    } else {
      OpcodeHelpers.pushInt(b, v);
    }
  }

  static void _pushInsertion(ScriptBuilder b, NullifierInsertion w) {
    b.addData(w.low.value);
    b.addData(w.low.next);
    for (int j = depth - 1; j >= 0; j--) {
      b.addData(w.newPath.siblings[j]);
      b.smallNum((w.newIndex >> j) & 1);
    }
    for (int j = depth - 1; j >= 0; j--) {
      b.addData(w.lowPath.siblings[j]);
      b.smallNum((w.lowIndex >> j) & 1);
    }
  }

  /// A placeholder witness for an unused transfer.
  static NullifierInsertion dummyInsertion() {
    final z = Uint8List(32);
    final path = ShaMerklePath(List.filled(depth, z), 0);
    return NullifierInsertion(
        nullifier: z, lowIndex: 0, low: NullifierLeaf(z, z), lowPath: path, newIndex: 0, created: NullifierLeaf(z, z), newPath: path,
        rootBefore: z, rootMid: z, rootAfter: z);
  }

  SVScript spendUnlock({
    required Uint8List preimage,
    required List<int> extraPrevouts,
    required List<int> rootAfter,
    required List<PP1SpTransfer?> transfers,
    List<int>? roundLanes,
  }) {
    if (aggregated) {
      if (transfers.length != n || transfers.any((t) => t == null)) throw ArgumentError('$n transfers, all present');
      if (roundLanes == null || roundLanes.length != PP1SpScriptGen.roundLanes) throw ArgumentError('${PP1SpScriptGen.roundLanes} round lanes');
      final b = ScriptBuilder();
      b.addData(preimage);
      b.addData(verifierBytes);
      b.addData(Uint8List.fromList(extraPrevouts));
      for (int t = n - 1; t >= 0; t--) {
        final tr = transfers[t]!;
        b.addData(tr.extraOutputs);
        final lanes = tr.publics.toLanes();
        for (final v in [...lanes, ...List.filled(laneChunk - lanes.length, 0)]) {
          _pushNum(b, v);
        }
        _pushInsertion(b, tr.nf1 ?? dummyInsertion());
        _pushInsertion(b, tr.nf2 ?? dummyInsertion());
      }
      for (final v in roundLanes) {
        _pushNum(b, v);
      }
      b.opCode(OpCodes.OP_1);
      return b.build();
    }
    if (transfers.length != k) throw ArgumentError('$k transfer slots');
    final b = ScriptBuilder();
    b.addData(preimage);
    b.addData(verifierBytes);
    b.addData(appendBytes);
    b.addData(Uint8List.fromList(extraPrevouts));
    for (final v in rootAfter) {
      _pushNum(b, v);
    }
    for (int t = k - 1; t >= 0; t--) {
      final tr = transfers[t];
      b.smallNum(tr == null ? 0 : 1);
      b.addData(tr == null ? Uint8List(0) : tr.extraOutputs);
      final lanes = tr == null ? List.filled(PoolPublicInputs.count, 0) : tr.publics.toLanes();
      for (final v in lanes) {
        _pushNum(b, v);
      }
      _pushInsertion(b, tr?.nf1 ?? dummyInsertion());
      _pushInsertion(b, tr?.nf2 ?? dummyInsertion());
    }
    b.opCode(OpCodes.OP_1);
    return b.build();
  }

  SVScript createUnlock({
    required Uint8List preimage,
    required List<int> rabinN,
    required List<int> rabinS,
    required int rabinPadding,
    required List<int> identityTxId,
    required List<int> ed25519PubKey,
    required int vault,
    required List<int> extras,
  }) {
    final b = ScriptBuilder();
    b.addData(preimage);
    b.addData(verifierBytes);
    if (!aggregated) b.addData(appendBytes);
    b.addData(Uint8List.fromList(rabinN));
    b.addData(Uint8List.fromList(rabinS));
    _pushNum(b, rabinPadding);
    b.addData(Uint8List.fromList(identityTxId));
    b.addData(Uint8List.fromList(ed25519PubKey));
    _pushNum(b, vault);
    b.addData(Uint8List.fromList(extras));
    b.opCode(OpCodes.OP_0);
    return b.build();
  }

  // ---- the round's outputs, for the wallet / coordinator ----

  /// The full output list of a round (or a create) transaction, serialised:
  /// state, results, slots, extras. [results] are the K + 1 result outputs
  /// (all empty for the create).
  int get numResults => aggregated ? 1 : k + 1;
  int get numSlots => aggregated ? 1 : k + 1;
  int get slotVout0 => numResults + 1;
  int get appendVout => aggregated ? -1 : 2 * k + 2;

  /// The vouts a round spends after the state: the slots (and append slot).
  List<int> get slotVouts => [for (int v = slotVout0; v < slotVout0 + numSlots; v++) v];
  List<Uint8List> roundOutputs(PP1SpHeader next, int vault, List<Uint8List> results, List<Uint8List> extras) => [
        _output(vault, lock(next).buffer),
        ...results,
        for (int i = 0; i < (aggregated ? 1 : k); i++) _output(slotSats, verifierBytes),
        if (!aggregated) _output(slotSats, appendBytes),
        ...extras,
      ];

  static Uint8List _output(int sats, List<int> script) {
    final v = ByteData(8)..setUint64(0, sats, Endian.little);
    return Uint8List.fromList([...v.buffer.asUint8List(), ...varint(script.length), ...script]);
  }

  static List<int> varint(int n) {
    if (n < 0xfd) return [n];
    if (n < 0x10000) return [0xfd, n & 0xff, n >> 8];
    return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
  }
}
