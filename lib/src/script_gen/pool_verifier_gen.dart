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
import '../crypto/m31.dart' show M31;
import '../recursion/verifier_program.dart' show AggregationTree;
import '../shielded_pool/pool_header.dart';
import '../shielded_pool/pool_outputs.dart';
import 'air.dart';
import 'check_preimage_ocs.dart';
import 'fri_fold_script_gen.dart' show FriQueryVerifierGen;
import 'm31_script_gen.dart';
import 'pool_spend_air.dart';
import 'pp1_sp_script_gen.dart';
import 'slot_script_common.dart';
import 'stark_verifier_gen.dart';

/// Where V finds each part of the root proof's wide statement: the
/// transfers' pinned lanes, then the round chunks (design 5.5).
///
/// It is [AggregationTree]'s layout for the TSL1 pool's tree, which has the
/// anchor ring, a nullifier level and receipt slots, and leaves the anchor
/// and the two commitments out of each transfer's lanes. [of] checks a real
/// tree against it; tests that exercise V's tail without a proof build one
/// directly.
class PoolStatement {
  final int transfers;
  final int receiptSlots;

  static const spendChunks = (PoolPublicInputs.count + 7) ~/ 8;
  static const freeChunks = [PoolPublicInputs.idxAnchor ~/ 8, PoolPublicInputs.idxCm1 ~/ 8, PoolPublicInputs.idxCm2 ~/ 8];
  static const pinnedChunks = spendChunks - 3;
  static const ringSize = PoolHeader.ringEntries;

  const PoolStatement({required this.transfers, required this.receiptSlots});

  factory PoolStatement.of(AggregationTree t) {
    final s = PoolStatement(transfers: t.transfers, receiptSlots: t.receiptSlots);
    final ring = t.ring;
    if (ring == null || ring.size != ringSize || t.nullifierLevel == null) {
      throw ArgumentError('V verifies the pool\'s tree: an anchor ring of $ringSize and a nullifier level');
    }
    if (t.spendPublics != PoolPublicInputs.count || t.freeChunks.join(',') != freeChunks.join(',')) {
      throw ArgumentError('V reads the pool spend\'s reduced lanes');
    }
    if (t.roundOffset != s.roundOffset ||
        t.ringOffset != s.ringOffset ||
        t.nullifierOffset != s.nullifierOffset ||
        t.receiptOffset != s.receiptOffset ||
        t.roundChunks != s.roundChunks ||
        t.leavesAppended != s.leavesAppended) {
      throw StateError('the tree\'s statement layout moved; PoolStatement must follow it');
    }
    return s;
  }

  int get roundOffset => 8 * pinnedChunks * transfers;
  int get ringOffset => roundOffset + 24;
  int get nullifierOffset => ringOffset + 8 * ringSize;
  int get receiptOffset => nullifierOffset + 16;
  int get roundChunks => 3 + ringSize + 2 + 2 * receiptSlots;
  int get numPublics => roundOffset + 8 * roundChunks;

  int get leaves => 2 * transfers;
  int get leavesAppended =>
      (leaves + AggregationTree.subtreeLeaves - 1) ~/ AggregationTree.subtreeLeaves * AggregationTree.subtreeLeaves;

  /// The public index of transfer [t]'s statement lane [lane] (an index
  /// into [PoolPublicInputs.toLanes]); the lane must be a pinned one.
  int lane(int t, int lane) {
    final c = lane ~/ 8;
    if (freeChunks.contains(c)) throw ArgumentError('lane $lane is not public');
    final pos = c - freeChunks.where((f) => f < c).length;
    return 8 * pinnedChunks * t + 8 * pos + lane % 8;
  }
}

/// V, the verifier slot script: the program on output 0 of every slot
/// transaction Y_N, which runs when round N+1 spends it at input 2 and is
/// the one script that gates the pool's money (design 5.5).
///
/// Its lock is `OP_PUSHDATA1 0xec ‖ header_N ‖ 0x14 ‖ signerPKH ‖ body`;
/// PP1 builds the two pushes and pins [body] by hash. When the body starts,
/// the stack is the unlock's pushes with `h0` (header_N) and `sPKH` on top.
///
/// The body binds the root proof's statement to this round before the
/// proof is verified:
///   * the signer: HASH160 of the pushed key is `sPKH`, and the key signs
///     the round SIGHASH_ALL, so a copy of the proof cannot spend Y_N:0 in
///     any other transaction (design 11.15, vector 1);
///   * header_N against the statement's "before" side (rootBefore, the
///     ring, nfBefore, the subtree index), and header_{N+1} against its
///     "after" side, with the ring rotation, the size step and the outHash
///     worked out here;
///   * every transfer: its signed amount moves the balance, only BSV may
///     move it, a transfer taking money out has exactly the next withdrawal
///     for exactly that amount, and its outHash lanes are
///     `SHA256(W_t ‖ c_t)` (`PoolOutHash.check` is the Dart reference);
///   * every receipt slot: used by the next receipt output, with the
///     slot's commitment and minus its amount, or zero;
///   * header_{N+1}.balance = header_N.balance − Σ amounts, which is also
///     the value written into PP3's output;
///   * the round's outputs rebuilt whole and checked against hashOutputs:
///     change, PP1 carrying header_{N+1}, PP2, PP3, metadata, receipts,
///     withdrawals.
///
/// The balance is stepped by the transfers' amounts rather than by the
/// receipt and withdrawal outputs, because an amount no output accounts
/// for would otherwise mint a note the pool holds no money for. Every
/// withdrawal is tied to a transfer, so the two agree whenever every
/// deposit has a receipt; when one has none, PP3 still gains its amount,
/// paid by whoever funded the round.
///
/// PP1's and PP3's programs are constants of the body, so V pins both.
/// They would otherwise be pushed in the round, where bytes are paid three
/// times; in the body they are paid twice (in Y and in the witness that
/// certifies it). PP2 and the metadata script are pushed as they are: a
/// wrong one can only stop the pool, and V needs nothing inside them.
///
/// The body ends `<ocsKey> OP_CODESEPARATOR OP_CHECKSIGVERIFY OP_CHECKSIG`:
/// one separator, so the preimage's scriptCode, and the signer's, is those
/// two opcodes.
class PoolVerifierGen {
  /// SIGHASH_ALL | FORKID: V reads hashOutputs over every output.
  static const sighashType = 0x41;

  /// The unlock's pushes above the proof, bottom to top.
  static const unlockAbove = [
    'bh', // the transfers' bundle hashes c_t, 32 bytes each, in order
    'wd', // withdrawal records, 28 bytes each, in tail order
    'rc', // receipt records, 40 bytes each
    'chg', // the change output's record: pkh ‖ value, 28 bytes
    'pp1Pre', // PP1_{N+1}'s script before its header data
    'h1', // header_{N+1}
    'pp2', // PP2_{N+1}'s script
    'slot', // the slot PP3_{N+1} pins, 36 bytes
    'meta', // the metadata output's script
    'sSig', // the signer's signature
    'sPub', // the signer's key
    'pre', // the sighash preimage of input 2
  ];

  /// The lock's two pushes, above the unlock.
  static const lockPushes = ['h0', 'sPKH'];

  static const pp1PrefixSize = PP1SpScriptGen.headerDataStart;
  static const pp3PrefixSize = PP1SpScriptGen.pp3NextSlotEnd;
  static const _laneMask = [0xff, 0xff, 0xff, 0x7f];

  final PoolStatement stmt;
  final List<int> pp1Program;
  final List<int> pp3Program;

  /// The root proof's verifier; null runs the tail on bare public lanes
  /// with no proof, which is only for testing the tail.
  final StarkVerifierGen? verifier;

  Uint8List? _body;

  /// Tests only: end the body after the named step of the binding with
  /// `OP_1`, so a failing check can be found by bisection. Steps: signer,
  /// preimage, sizes, round, receipts, transfers, headers, outputs.
  String? stopAfter;
  bool _stopped = false;

  bool _stop(StackEmitter e, String step) {
    if (stopAfter != step) return false;
    e.dropAll();
    e.pushConst(1);
    _stopped = true;
    return true;
  }

  PoolVerifierGen(this.stmt, {required this.pp1Program, required this.pp3Program, this.verifier}) {
    final v = verifier;
    if (v != null && v.air.numPublics != stmt.numPublics) {
      throw ArgumentError('the verifier takes ${v.air.numPublics} publics, the statement has ${stmt.numPublics}');
    }
    if (pp1PrefixSize + PoolHeader.byteSize + pp1Program.length >= 0x10000 || pp3PrefixSize + pp3Program.length >= 0x10000) {
      throw ArgumentError('V writes PP1\'s and PP3\'s lengths as 3-byte varints');
    }
  }

  /// PP1's program: its script after the header.
  static List<int> pp1ProgramOf(List<int> pp1Script) => pp1Script.sublist(PP1SpScriptGen.headerDataEnd);

  /// PP3's program: its script after the slot.
  static List<int> pp3ProgramOf(List<int> pp3Script) => pp3Script.sublist(pp3PrefixSize);

  /// The bytes after the lock's two pushes; PP1 pins their SHA256.
  Uint8List body() => _body ??= _build();

  /// The scriptCode both of V's signatures commit to.
  static SVScript get scriptCode => SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_CHECKSIGVERIFY, OpCodes.OP_CHECKSIG]));

  static String _pub(int i) => Air.publicName(i);

  Uint8List _build() {
    final Uint8List code;
    final v = verifier;
    if (v == null) {
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: [
        for (int k = 0; k < stmt.numPublics; k++) _pub(k),
        ...unlockAbove,
        ...lockPushes,
      ]);
      _bind(e);
      if (!_stopped) e.dropAllExcept(const ['sSig', 'sPub', 'ocsSig']);
      code = Uint8List.fromList(b.build().buffer);
      if (_stopped) return code;
    } else {
      v
        ..unlockAbove = const [...unlockAbove, ...lockPushes]
        ..prologue = _bind
        ..epilogue = (e) => e.dropAllExcept(const ['sSig', 'sPub', 'ocsSig']);
      code = Uint8List.fromList(v.generate().buffer);
    }
    return Uint8List.fromList([
      ...code,
      CheckPreimageOCS.pubKey.length, ...CheckPreimageOCS.pubKey,
      OpCodes.OP_CODESEPARATOR, OpCodes.OP_CHECKSIGVERIFY, OpCodes.OP_CHECKSIG,
    ]);
  }

  // ---- emit helpers ----
  static void _op(StackEmitter e, int op, {int pops = 2, int pushes = 1, String? as}) =>
      e.raw(op, pops: pops, pushes: pushes, as: as);
  static void _cat(StackEmitter e, {String? as}) => _op(e, OpCodes.OP_CAT, as: as);
  static void _verify(StackEmitter e) => _op(e, OpCodes.OP_VERIFY, pops: 1, pushes: 0);
  static void _equalVerify(StackEmitter e) => _op(e, OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
  static void _split(StackEmitter e, int n) {
    e.pushConst(n);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
  }

  /// Bytes [from, from + len) of the named 236-byte header, on top as [as].
  static void _field(StackEmitter e, String h, int from, int len, String as) {
    e.pick(h);
    if (from > 0) {
      _split(e, from);
      _op(e, OpCodes.OP_NIP);
    }
    if (from + len < PoolHeader.byteSize) {
      _split(e, len);
      e.drop();
    }
    e.nameTop(as);
  }

  /// Little-endian unsigned bytes on top -> a number.
  static void _unsigned(StackEmitter e) {
    e.pushData(const [0]);
    _cat(e);
    _op(e, OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
  }

  /// SIZE(named) == n.
  static void _sizeIs(StackEmitter e, String name, int n) {
    e.pick(name);
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP);
    e.numEqualVerifyConst(n);
  }

  /// 0 <= lane < p: a lane V reads as bytes or as a number must be the
  /// field element's one representative, or two encodings of the same
  /// statement would read differently here.
  static void _canonical(StackEmitter e, String lane) {
    e.pick(lane);
    e.pushConst(0);
    e.pushP();
    _op(e, OpCodes.OP_WITHIN, pops: 3, pushes: 1);
    _verify(e);
  }

  /// A lane read as signed: residues above (p-1)/2 are negative.
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

  /// The signed amount `lo + 2^28 hi` of the lanes [lo], [hi], on top.
  static void _amount(StackEmitter e, String lo, String hi, String as) {
    _signedLane(e, hi);
    e.pushConst(1 << PoolHash.limbBits);
    _op(e, OpCodes.OP_MUL);
    _signedLane(e, lo);
    _op(e, OpCodes.OP_ADD, as: as);
  }

  /// Eight lanes as 32 bytes equal to the named bytes (consumed).
  static void _lanesEqual(StackEmitter e, List<String> lanes, String bytes) {
    SlotScript.lanesToBytes(e, lanes, as: '_lb');
    e.roll(bytes);
    _equalVerify(e);
  }

  /// A number on top -> its varint (scripts under 64 KB).
  static void _varint(StackEmitter e) {
    e.dup();
    e.pushConst(0xfd);
    _op(e, OpCodes.OP_LESSTHAN);
    e.ifBegin();
    e.pushConst(1);
    _op(e, OpCodes.OP_NUM2BIN);
    e.ifElse();
    e.pushConst(2);
    _op(e, OpCodes.OP_NUM2BIN);
    e.pushData(const [0xfd]);
    e.swap();
    _cat(e);
    e.ifEnd();
  }

  /// `value ‖ varint ‖ script` from the named script (consumed).
  static void _opaqueOutput(StackEmitter e, String script, int sats, String as) {
    final v = ByteData(8)..setUint64(0, sats, Endian.little);
    e.pushData(v.buffer.asUint8List());
    e.pick(script);
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP);
    e.pushConst(0x10000);
    _op(e, OpCodes.OP_LESSTHAN);
    _verify(e);
    e.pick(script);
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    _op(e, OpCodes.OP_NIP);
    _varint(e);
    _cat(e);
    e.roll(script);
    _cat(e, as: as);
  }

  static List<int> _varintBytes(int n) => n < 0xfd ? [n] : [0xfd, n & 0xff, n >> 8];

  // ---- the binding ----
  void _bind(StackEmitter e) {
    final s = stmt;
    String rl(int j) => _pub(s.roundOffset + j);
    List<String> rlanes(int from) => [for (int j = 0; j < 8; j++) rl(from + j)];

    // the signer: its key hashes to the pushed key hash
    e.pick('sPub');
    _op(e, OpCodes.OP_HASH160, pops: 1, pushes: 1);
    e.roll('sPKH');
    _equalVerify(e);
    if (_stop(e, 'signer')) return;

    // the preimage: the OCS signature for it, and hashOutputs
    e.pick('pre');
    SlotScript.emitSignature(e, sighashType, as: 'ocsSig');
    e.roll('pre');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.pushConst(40);
    _op(e, OpCodes.OP_SUB);
    _op(e, OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    _op(e, OpCodes.OP_NIP);
    _split(e, 32);
    e.drop();
    e.nameTop('hO');
    if (_stop(e, 'preimage')) return;

    // the fixed-size pushes are the size they claim, so the outputs V
    // builds from them parse back into the same outputs
    _sizeIs(e, 'h1', PoolHeader.byteSize);
    _sizeIs(e, 'chg', PoolWithdrawal.recordSize);
    _sizeIs(e, 'pp1Pre', pp1PrefixSize);
    _sizeIs(e, 'slot', PP1SpScriptGen.pp3NextSlotEnd - PP1SpScriptGen.pp3NextSlotStart);
    if (_stop(e, 'sizes')) return;

    // ---- the round chunks against the two headers ----
    for (int j = 0; j < 8 * s.roundChunks; j++) {
      _canonical(e, rl(j));
    }
    // cmRoot: rootBefore is header_N's, rootAfter header_{N+1}'s
    _field(e, 'h0', PoolHeader.cmRootOffset, 32, '_f');
    _lanesEqual(e, rlanes(0), '_f');
    _field(e, 'h1', PoolHeader.cmRootOffset, 32, '_f');
    _lanesEqual(e, rlanes(8), '_f');
    // size: the subtree index is size_N / 32 (whole subtrees), and the
    // round appends the tree's fixed leavesAppended
    _field(e, 'h0', PoolHeader.sizeOffset, 4, 'sz0');
    e.roll('sz0');
    _unsigned(e);
    e.nameTop('sz0');
    e.pick('sz0');
    e.pushConst(AggregationTree.subtreeLeaves);
    _op(e, OpCodes.OP_MOD);
    e.numEqualVerifyConst(0);
    e.pick('sz0');
    e.pushConst(AggregationTree.subtreeLeaves);
    _op(e, OpCodes.OP_DIV);
    e.pick(rl(16));
    e.numEqualVerify();
    for (int j = 17; j < 24; j++) {
      e.pick(rl(j));
      e.numEqualVerifyConst(0);
    }
    _field(e, 'h1', PoolHeader.sizeOffset, 4, 'sz1');
    e.roll('sz1');
    _unsigned(e);
    e.roll('sz0');
    e.pushConst(s.leavesAppended);
    _op(e, OpCodes.OP_ADD);
    e.numEqualVerify();
    // the ring the level-1 proofs checked anchors against is header_N's,
    // and header_{N+1}'s is it rotated: [cmRoot_{N+1}, ring_N[0..2]]
    final ringBase = s.ringOffset - s.roundOffset;
    for (int r = 0; r < PoolStatement.ringSize; r++) {
      _field(e, 'h0', PoolHeader.ringOffset + 32 * r, 32, '_f');
      _lanesEqual(e, rlanes(ringBase + 8 * r), '_f');
    }
    _field(e, 'h1', PoolHeader.ringOffset, 32 * PoolStatement.ringSize, '_r1');
    _field(e, 'h1', PoolHeader.cmRootOffset, 32, '_c1');
    _field(e, 'h0', PoolHeader.ringOffset, 32 * (PoolStatement.ringSize - 1), '_r0');
    _cat(e);
    e.roll('_r1');
    _equalVerify(e);
    // the nullifier set's root before and after
    final nfBase = s.nullifierOffset - s.roundOffset;
    _field(e, 'h0', PoolHeader.nfRootOffset, 32, '_f');
    _lanesEqual(e, rlanes(nfBase), '_f');
    _field(e, 'h1', PoolHeader.nfRootOffset, 32, '_f');
    _lanesEqual(e, rlanes(nfBase + 8), '_f');
    if (_stop(e, 'round')) return;

    // ---- receipts: slot r is used by the r-th receipt output, or zero ----
    e.pushConst(0, as: 'routs');
    final rcBase = s.receiptOffset - s.roundOffset;
    for (int r = 0; r < s.receiptSlots; r++) {
      final cm = rlanes(rcBase + 16 * r);
      final lo = rl(rcBase + 16 * r + 8), hi = rl(rcBase + 16 * r + 9), used = rl(rcBase + 16 * r + 10);
      e.roll('routs');
      e.roll('rc');
      e.dup();
      _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
      _op(e, OpCodes.OP_NIP);
      e.ifBegin();
      _split(e, PoolReceipt.recordSize);
      e.nameAt(1, '_rec');
      e.nameTop('rc');
      e.pick(used);
      e.numEqualVerifyConst(1);
      e.roll('_rec');
      _split(e, 32);
      e.nameAt(1, '_rcm');
      e.nameTop('_rv');
      e.pick('_rcm', as: '_rcmc');
      _lanesEqual(e, cm, '_rcmc');
      e.pick('_rv');
      _unsigned(e);
      _amount(e, lo, hi, '_amt');
      _op(e, OpCodes.OP_NEGATE, pops: 1, pushes: 1);
      e.numEqualVerify();
      e.pushData(const [0, 0, 0, 0, 0, 0, 0, 0, 0x2c, 0x00, 0x6a, 0x20]);
      e.roll('_rcm');
      _cat(e);
      e.pushConst(8); // OP_8 pushes the byte 0x08, the value's push length
      _cat(e);
      e.roll('_rv');
      _cat(e);
      e.roll('routs');
      e.swap();
      _cat(e, as: 'routs');
      e.roll('rc');
      e.ifElse();
      for (int j = 0; j < 16; j++) {
        e.pick(rl(rcBase + 16 * r + j));
        e.numEqualVerifyConst(0);
      }
      e.ifEnd();
    }
    e.roll('rc');
    _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
    e.numEqualVerifyConst(0);
    e.drop();
    if (_stop(e, 'receipts')) return;

    // ---- the transfers ----
    _field(e, 'h0', PoolHeader.balanceOffset, 8, 'bal');
    e.roll('bal');
    _unsigned(e);
    e.nameTop('bal');
    e.pushConst(0, as: 'wouts');
    e.pushConst(0, as: 'call');
    for (int t = 0; t < s.transfers; t++) {
      String p(int lane) => _pub(s.lane(t, lane));
      final lo = p(PoolPublicInputs.idxPubLo), hi = p(PoolPublicInputs.idxPubHi);
      final oh = [for (int j = 0; j < 8; j++) p(PoolPublicInputs.idxOutHash + j)];
      final asset = [for (int j = 0; j < PoolHash.assetLanes; j++) p(PoolPublicInputs.idxAsset + j)];
      for (final l in [lo, hi, ...oh, ...asset]) {
        _canonical(e, l);
      }
      _amount(e, lo, hi, 'dl');
      // only BSV moves the balance; any other asset must move nothing
      for (int i = 0; i < PoolHash.assetLanes; i++) {
        e.pick(asset[i]);
        e.pushConst(PoolHash.bsvAsset[i]);
        _op(e, OpCodes.OP_NUMEQUAL);
        if (i > 0) _op(e, OpCodes.OP_BOOLAND);
      }
      e.pick('dl');
      _op(e, OpCodes.OP_NOT, pops: 1, pushes: 1);
      _op(e, OpCodes.OP_BOOLOR);
      _verify(e);
      e.roll('bal');
      e.pick('dl');
      _op(e, OpCodes.OP_SUB, as: 'bal');
      // money out: the next withdrawal, for exactly the amount
      e.roll('wouts');
      e.roll('wd');
      e.pick('dl');
      e.pushConst(0);
      _op(e, OpCodes.OP_GREATERTHAN);
      e.ifBegin();
      _split(e, PoolWithdrawal.recordSize);
      e.nameAt(1, 'W');
      e.nameTop('wd');
      e.pick('W');
      _split(e, 20);
      e.nameAt(1, '_wpkh');
      e.nameTop('_wv');
      e.pick('_wv');
      _unsigned(e);
      e.pick('dl');
      e.numEqualVerify();
      e.roll('_wv');
      e.pushData(const [0x19, 0x76, 0xa9, 0x14]);
      _cat(e);
      e.roll('_wpkh');
      _cat(e);
      e.pushData(const [0x88, 0xac]);
      _cat(e);
      e.roll('wouts');
      e.swap();
      _cat(e, as: 'wouts');
      e.roll('wd');
      e.roll('W');
      e.ifElse();
      e.pushConst(0, as: 'W');
      e.ifEnd();
      // outHash_t = SHA256(W_t ‖ c_t), each 4-byte lane masked to 31 bits
      e.roll('bh');
      _split(e, 32);
      e.nameAt(1, 'ct');
      e.nameTop('bh');
      e.roll('call');
      e.pick('ct');
      _cat(e, as: 'call');
      e.roll('W');
      e.roll('ct');
      _cat(e);
      _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
      e.pushData([for (int k = 0; k < 8; k++) ..._laneMask]);
      _op(e, OpCodes.OP_AND, as: '_oh');
      _lanesEqual(e, oh, '_oh');
      e.dropNamed('dl');
    }
    // every withdrawal and bundle hash belongs to a transfer
    for (final n in ['wd', 'bh']) {
      e.roll(n);
      _op(e, OpCodes.OP_SIZE, pops: 1, pushes: 2);
      e.numEqualVerifyConst(0);
      e.drop();
    }
    if (_stop(e, 'transfers')) return;
    // header_{N+1}.outHash covers the bundle hashes in transfer order
    e.roll('call');
    _op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
    _field(e, 'h1', PoolHeader.outHashOffset, 32, '_f');
    _equalVerify(e);
    // header_{N+1}.balance = header_N.balance − Σ amounts
    _field(e, 'h1', PoolHeader.balanceOffset, 8, 'bal1');
    e.pick('bal1');
    _unsigned(e);
    e.roll('bal');
    e.numEqualVerify();
    if (_stop(e, 'headers')) return;

    // ---- the round's outputs, rebuilt, against hashOutputs ----
    // 0: change, P2PKH
    e.roll('chg');
    _split(e, 20);
    e.pushData(const [0x19, 0x76, 0xa9, 0x14]);
    _cat(e);
    e.swap();
    _cat(e);
    e.pushData(const [0x88, 0xac]);
    _cat(e, as: 'outs');
    // 1: PP1_{N+1}, carrying header_{N+1}, with PP1's program
    final pp1Len = pp1PrefixSize + PoolHeader.byteSize + pp1Program.length;
    e.roll('outs');
    e.pushData([1, 0, 0, 0, 0, 0, 0, 0, ..._varintBytes(pp1Len)]);
    _cat(e);
    e.roll('pp1Pre');
    _cat(e);
    e.roll('h1');
    _cat(e);
    e.pushData(pp1Program);
    _cat(e, as: 'outs');
    // 2: PP2_{N+1}
    _opaqueOutput(e, 'pp2', 1, '_o');
    e.roll('outs');
    e.swap();
    _cat(e, as: 'outs');
    // 3: PP3_{N+1}, holding header_{N+1}.balance, with PP3's program
    e.roll('bal1');
    e.pushData([..._varintBytes(pp3PrefixSize + pp3Program.length), 0x24]);
    _cat(e);
    e.roll('slot');
    _cat(e);
    e.pushData(pp3Program);
    _cat(e);
    e.roll('outs');
    e.swap();
    _cat(e, as: 'outs');
    // 4: metadata, no value
    _opaqueOutput(e, 'meta', 0, '_o');
    e.roll('outs');
    e.swap();
    _cat(e, as: 'outs');
    // receipts, then withdrawals
    e.roll('routs');
    _cat(e);
    e.roll('wouts');
    _cat(e);
    _op(e, OpCodes.OP_HASH256, pops: 1, pushes: 1);
    e.roll('hO');
    _equalVerify(e);
    _stop(e, 'outputs');
  }

  // ---- the Dart side ----

  /// The unlock above the proof, as [unlockAbove] lists it.
  static List<int> unlockTail({
    required List<List<int>> bundleHashes,
    required List<PoolWithdrawal> withdrawals,
    required List<PoolReceipt> receipts,
    required List<int> changePKH,
    required BigInt changeSatoshis,
    required List<int> pp1Prefix,
    required List<int> header1,
    required List<int> pp2Script,
    required List<int> nextSlot,
    required List<int> metadataScript,
    required List<int> signerSig,
    required List<int> signerPubKey,
    required List<int> preimage,
  }) {
    final b = ScriptBuilder();
    void data(List<int> d) {
      if (d.isEmpty) {
        b.opCode(OpCodes.OP_0);
      } else {
        b.addData(Uint8List.fromList(d));
      }
    }

    data([for (final c in bundleHashes) ...c]);
    data(PoolWithdrawal.encodeAll(withdrawals));
    data(PoolReceipt.encodeAll(receipts));
    data(PoolWithdrawal(changePKH, changeSatoshis).encodeRecord());
    data(pp1Prefix);
    data(header1);
    data(pp2Script);
    data(nextSlot);
    data(metadataScript);
    data(signerSig);
    data(signerPubKey);
    data(preimage);
    return b.build().buffer;
  }

  /// The unlock with the public lanes pushed bare, for a V built without a
  /// verifier.
  static List<int> barePublics(List<int> lanes) {
    final b = ScriptBuilder();
    for (final l in lanes) {
      FriQueryVerifierGen.pushNum(b, l);
    }
    return b.build().buffer;
  }

  /// V's whole lock for [header] and [signerPKH].
  Uint8List lock(List<int> header, List<int> signerPKH) =>
      Uint8List.fromList([OpCodes.OP_PUSHDATA1, PoolHeader.byteSize, ...header, 20, ...signerPKH, ...body()]);
}
