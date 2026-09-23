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
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';

import '../crypto/note_commitment_tree.dart' show NoteCommitmentTree;
import '../crypto/stark_prover_ref.dart' show StarkParams;
import '../recursion/pool_aggregator.dart' show PoolAggregation;
import 'pool_evidence.dart';
import 'pool_header.dart';
import 'shielded_ledger.dart';
import 'shielded_transfer.dart';

/// Why a message was not decoded: the field being read and what was wrong
/// with it. A coordinator's inbox and a wallet's feed can both be written
/// by anyone, so every way a message can fail to decode ends here and
/// nowhere else.
class ProtocolRefusal implements Exception {
  final String field;
  final String reason;
  const ProtocolRefusal(this.field, this.reason);
  @override
  String toString() => 'message refused ($field): $reason';
}

/// The six messages a wallet and a coordinator exchange. Each carries its
/// kind in its second byte, so one inbox can hold any of them.
enum PoolMessageKind {
  submission(1),
  reply(2),
  descriptor(3),
  announcement(4),
  catchUpRequest(5),
  catchUpReply(6);

  final int number;
  const PoolMessageKind(this.number);

  static PoolMessageKind? of(int number) {
    for (final k in values) {
      if (k.number == number) return k;
    }
    return null;
  }
}

/// Why a coordinator refused a submission. The numbers are fixed for the
/// protocol's life, so a wallet built later still reads an older
/// coordinator's refusals, and a wallet built earlier at least knows the
/// number of a reason it has no name for. The remedy differs by reason: a
/// malformed or self-inconsistent transfer is the wallet's bug, a pending
/// nullifier is a race to retry after the next round, a deposit naming an
/// old PP3 needs a new covenant, and a bad proof never gets better.
enum RefusalReason {
  /// The submission or its transfer does not decode; the sentence names the field.
  malformed(1),

  /// The transfer is not consistent with itself (pool-transfer's rules).
  transfer(2),

  /// The transfer's anchor is not one of the ring's roots.
  anchor(3),

  /// A real nullifier is already in the pool's nullifier tree.
  nullifierSpent(4),

  /// A real nullifier is claimed by a transfer in a round not yet published.
  nullifierPending(5),

  /// The transfer names a deposit but no covenant transaction came with it,
  /// or a covenant transaction came with a transfer that names no deposit.
  depositMissing(6),

  /// The covenant transaction does not hold, at the named outpoint, a
  /// covenant for this pool's live PP3 with the transfer's receipt.
  depositCovenant(7),

  /// The covenant names a PP3 a closed or in-flight round spends: refund it
  /// and deposit again against the PP3 of the newest announced round.
  depositTarget(8),

  /// The covenant outpoint is already backed by a pending transfer.
  depositPending(9),

  /// The pending round has no receipt slot left.
  receiptSlots(10),

  /// The withdrawal would take more out than the pool's balance covers.
  balance(11),

  /// The spend proof does not verify against the transfer's publics.
  proof(12);

  final int number;
  const RefusalReason(this.number);

  static RefusalReason? of(int number) {
    for (final r in values) {
      if (r.number == number) return r;
    }
    return null;
  }
}

enum ReplyOutcome {
  accepted(1),
  refused(2),
  expired(3);

  final int number;
  const ReplyOutcome(this.number);

  static ReplyOutcome? of(int number) {
    for (final o in values) {
      if (o.number == number) return o;
    }
    return null;
  }
}

/// One message, as bytes any transport can carry and either side decodes
/// as hostile input.
///
/// Every encoding begins with the format version and the kind, then its
/// fields with explicit lengths, little-endian. Equal messages give the
/// same bytes: nothing is written in map order, and no field is optional
/// without a length that says so. A decoder checks the whole size before
/// reading a byte, every length against the bytes that remain and its
/// field's own bound before allocating, and ends in a message or a
/// [ProtocolRefusal] naming the field, never any other failure.
abstract class PoolMessage {
  /// The first byte of every encoding. A change to any encoding bumps it.
  ///
  /// Version 2 (2026-09-23) added the leaf count, the tokenId, the genesis
  /// header and the catch-up range to the descriptor, the block root to the
  /// announcement, and the two catch-up messages. A version 1 message is
  /// refused rather than read: every field version 2 added is one a wallet
  /// needs in order to act without looking anything up.
  static const formatVersion = 2;

  /// The largest submission a decoder reads: a transfer (at most 100 KB) and
  /// a deposit transaction (at most [maxDepositTx]), with room to spare.
  static const maxSubmission = 128 * 1024;

  /// The largest reply, descriptor or announcement a decoder reads.
  static const maxOther = 4 * 1024;

  /// The largest deposit transaction a submission carries. A covenant
  /// transaction with one input and two outputs is about 1.5 KB.
  static const maxDepositTx = 4 * 1024;

  /// Bytes of a submission id.
  static const idSize = 16;

  /// Bytes of a txid.
  static const txidSize = 32;

  /// The longest sentence a reply carries.
  static const maxSentence = 1024;

  /// The most block roots one catch-up reply serves: 2 MB of roots, more
  /// than a year of a pool closing a round every ten minutes.
  static const maxBlockRoots = 65536;

  /// The largest transaction a head proof carries. This is the chain's own
  /// per-transaction limit: a larger one cannot be mined, so it cannot be
  /// part of a head proof.
  static const maxTx = 10 * 1024 * 1024;

  /// The largest catch-up reply a decoder reads: a head proof's two
  /// transactions and its merkle branch.
  static const maxCatchUp = 2 * maxTx + 8 * 1024;

  /// The deepest block merkle branch a head proof carries: 2^40 transactions
  /// in a block is past anything the chain can hold.
  static const maxBranch = 40;

  /// The size of a block hash and of a merkle branch node.
  static const hashSize = 32;

  PoolMessageKind get kind;

  Uint8List encode();

  /// The kind [bytes] claim, or null when they are too short or of another
  /// version. Reading it costs nothing, so a server can route a message
  /// before decoding it.
  static PoolMessageKind? kindOf(List<int> bytes) {
    if (bytes.length < 2 || bytes[0] != formatVersion) return null;
    return PoolMessageKind.of(bytes[1]);
  }

  /// The message [bytes] hold, of whichever kind they claim. A submission is
  /// bounded at [maxSubmission], anything else at [maxOther].
  static PoolMessage decode(List<int> bytes) {
    if (bytes.length > maxCatchUp) throw ProtocolRefusal('size', '${bytes.length} bytes, at most $maxCatchUp');
    final k = bytes.length >= 2 ? PoolMessageKind.of(bytes[1]) : null;
    switch (k) {
      case PoolMessageKind.submission:
        return PoolSubmission.decode(bytes);
      case PoolMessageKind.reply:
        return PoolReply.decode(bytes);
      case PoolMessageKind.descriptor:
        return PoolDescriptor.decode(bytes);
      case PoolMessageKind.announcement:
        return PoolAnnouncement.decode(bytes);
      case PoolMessageKind.catchUpRequest:
        return PoolCatchUpRequest.decode(bytes);
      case PoolMessageKind.catchUpReply:
        return PoolCatchUpReply.decode(bytes);
      case null:
        // let the reader name the version or the kind
        _Reader.open(bytes, PoolMessageKind.submission, maxSubmission);
        throw const ProtocolRefusal('kind', 'unknown');
    }
  }

  @override
  bool operator ==(Object other) => other is PoolMessage && other.kind == kind && _eq(other.encode(), encode());

  @override
  int get hashCode => Object.hashAll(encode());

  static Uint8List u32(int v) => Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.little);
  static Uint8List u16(int v) => Uint8List(2)..buffer.asByteData().setUint16(0, v, Endian.little);

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// [txid] as 32 bytes, refusing any other length. Txids are carried in
  /// display order (the order `Transaction.id` prints), so a message and a
  /// node's answer agree byte for byte.
  static Uint8List txidBytes(List<int> txid, String field) {
    if (txid.length != txidSize) throw ArgumentError('$field is a $txidSize-byte txid, not ${txid.length} bytes');
    return Uint8List.fromList(txid);
  }

  /// The display-order txid bytes of [tx].
  static Uint8List txidOf(Transaction tx) => Uint8List.fromList(hex.decode(tx.id));
}

/// What a wallet sends a coordinator: one transfer in the pool-transfer
/// wire format, the raw deposit transaction when the transfer backs a
/// deposit, and a 16-byte id the wallet chose at random. The id is what a
/// reply names, so it is drawn fresh and derived from nothing: a wallet's
/// keys and notes appear nowhere in the message but inside the transfer's
/// ciphertexts.
///
/// The transfer stays as bytes here because decoding it needs the pool's
/// spend parameters, which the coordinator has and the message does not
/// carry ([transfer]).
class PoolSubmission extends PoolMessage {
  final Uint8List id;
  final Uint8List transferBytes;
  final Uint8List? depositTx;

  PoolSubmission(List<int> id, List<int> transferBytes, {List<int>? depositTx})
      : id = Uint8List.fromList(id),
        transferBytes = Uint8List.fromList(transferBytes),
        depositTx = depositTx == null ? null : Uint8List.fromList(depositTx) {
    if (id.length != PoolMessage.idSize) throw ArgumentError('a submission id is ${PoolMessage.idSize} bytes');
    if (transferBytes.isEmpty || transferBytes.length > ShieldedTransfer.maxEncoded) {
      throw ArgumentError('a transfer is 1 to ${ShieldedTransfer.maxEncoded} bytes');
    }
    if (depositTx != null && (depositTx.isEmpty || depositTx.length > PoolMessage.maxDepositTx)) {
      throw ArgumentError('a deposit transaction is 1 to ${PoolMessage.maxDepositTx} bytes');
    }
  }

  /// A submission of [transfer] at [spendP] under a fresh random id, with
  /// [depositTx] when the transfer backs a deposit.
  factory PoolSubmission.of(ShieldedTransfer transfer, StarkParams spendP, {Transaction? depositTx, Random? rng}) {
    final r = rng ?? Random.secure();
    return PoolSubmission(List.generate(PoolMessage.idSize, (_) => r.nextInt(256)), transfer.encode(spendP),
        depositTx: depositTx == null ? null : hex.decode(depositTx.serialize()));
  }

  @override
  PoolMessageKind get kind => PoolMessageKind.submission;

  /// The transfer, decoded at [spendP]. Throws [TransferRefusal].
  ShieldedTransfer transfer(StarkParams spendP) => ShieldedTransfer.decode(transferBytes, spendP);

  /// The deposit transaction, or null when none came. Throws
  /// [ProtocolRefusal] when the bytes are not a transaction.
  Transaction? depositTransaction() {
    final b = depositTx;
    if (b == null) return null;
    try {
      return ShieldedLedger.parse(b);
    } catch (e) {
      throw ProtocolRefusal('depositTx', 'is not a transaction ($e)');
    }
  }

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   id               16
  //   transfer length  4; 1 to ShieldedTransfer.maxEncoded
  //   transfer
  //   deposit length   2; 0 for none, else 1 to maxDepositTx
  //   deposit

  @override
  Uint8List encode() {
    final out = BytesBuilder(copy: false)
      ..addByte(PoolMessage.formatVersion)
      ..addByte(kind.number)
      ..add(id)
      ..add(PoolMessage.u32(transferBytes.length))
      ..add(transferBytes)
      ..add(PoolMessage.u16(depositTx?.length ?? 0));
    if (depositTx != null) out.add(depositTx!);
    return out.toBytes();
  }

  static PoolSubmission decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.submission, PoolMessage.maxSubmission);
    return r.guard(() {
      final id = r.take('id', PoolMessage.idSize);
      final tl = r.u32('transfer');
      if (tl < 1 || tl > ShieldedTransfer.maxEncoded) throw ProtocolRefusal('transfer', 'declares $tl bytes, 1 to ${ShieldedTransfer.maxEncoded}');
      final transfer = r.take('transfer', tl);
      final dl = r.u16('depositTx');
      if (dl > PoolMessage.maxDepositTx) throw ProtocolRefusal('depositTx', 'declares $dl bytes, at most ${PoolMessage.maxDepositTx}');
      final deposit = dl == 0 ? null : r.take('depositTx', dl);
      r.end();
      return PoolSubmission(id, transfer, depositTx: deposit);
    });
  }

  /// The id [bytes] carry when they begin as a submission of this version,
  /// else null. A coordinator uses it to answer a submission that does not
  /// decode past its id, and drops one that has none to answer to.
  static Uint8List? idOf(List<int> bytes) {
    if (PoolMessage.kindOf(bytes) != PoolMessageKind.submission || bytes.length < 2 + PoolMessage.idSize) return null;
    return Uint8List.fromList(bytes.sublist(2, 2 + PoolMessage.idSize));
  }
}

/// What a coordinator answers: the submission's id and one outcome.
/// Accepted names the round the transfer is pending for, which is a
/// promise and not a fact: the wallet learns its transfer was included by
/// finding its notes in that round. Refused names a numbered reason and a
/// sentence. Expired says a transfer accepted earlier could not be
/// included, with a sentence saying why.
class PoolReply extends PoolMessage {
  final Uint8List id;
  final ReplyOutcome outcome;

  /// Accepted: the round number the transfer is pending for.
  final int? round;

  /// Refused: the reason.
  final RefusalReason? reason;

  /// Refused and expired: one sentence for a person.
  final String? sentence;

  PoolReply._(List<int> id, this.outcome, {this.round, this.reason, this.sentence}) : id = Uint8List.fromList(id) {
    if (id.length != PoolMessage.idSize) throw ArgumentError('a submission id is ${PoolMessage.idSize} bytes');
    if (sentence != null && utf8.encode(sentence!).length > PoolMessage.maxSentence) {
      throw ArgumentError('a sentence is at most ${PoolMessage.maxSentence} bytes');
    }
  }

  factory PoolReply.accepted(List<int> id, int round) {
    if (round < 0 || round > 0xffffffff) throw ArgumentError('a round number fits 32 bits');
    return PoolReply._(id, ReplyOutcome.accepted, round: round);
  }

  factory PoolReply.refused(List<int> id, RefusalReason reason, String sentence) =>
      PoolReply._(id, ReplyOutcome.refused, reason: reason, sentence: sentence);

  factory PoolReply.expired(List<int> id, String sentence) => PoolReply._(id, ReplyOutcome.expired, sentence: sentence);

  @override
  PoolMessageKind get kind => PoolMessageKind.reply;

  bool get isAccepted => outcome == ReplyOutcome.accepted;

  @override
  String toString() => switch (outcome) {
        ReplyOutcome.accepted => 'accepted into round $round',
        ReplyOutcome.refused => 'refused (${reason!.name}): $sentence',
        ReplyOutcome.expired => 'expired: $sentence',
      };

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   id               16
  //   outcome          1
  //   accepted:        round 4
  //   refused:         reason 2, sentence length 2, sentence (UTF-8)
  //   expired:         sentence length 2, sentence

  @override
  Uint8List encode() {
    final out = BytesBuilder(copy: false)
      ..addByte(PoolMessage.formatVersion)
      ..addByte(kind.number)
      ..add(id)
      ..addByte(outcome.number);
    switch (outcome) {
      case ReplyOutcome.accepted:
        out.add(PoolMessage.u32(round!));
      case ReplyOutcome.refused:
        final s = utf8.encode(sentence!);
        out
          ..add(PoolMessage.u16(reason!.number))
          ..add(PoolMessage.u16(s.length))
          ..add(s);
      case ReplyOutcome.expired:
        final s = utf8.encode(sentence!);
        out
          ..add(PoolMessage.u16(s.length))
          ..add(s);
    }
    return out.toBytes();
  }

  static PoolReply decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.reply, PoolMessage.maxOther);
    return r.guard(() {
      final id = r.take('id', PoolMessage.idSize);
      final o = r.byte('outcome');
      final outcome = ReplyOutcome.of(o);
      if (outcome == null) throw ProtocolRefusal('outcome', 'unknown outcome $o');
      final PoolReply reply;
      switch (outcome) {
        case ReplyOutcome.accepted:
          reply = PoolReply.accepted(id, r.u32('round'));
        case ReplyOutcome.refused:
          final n = r.u16('reason');
          final reason = RefusalReason.of(n);
          if (reason == null) throw ProtocolRefusal('reason', 'unknown reason $n');
          reply = PoolReply.refused(id, reason, r.sentence('sentence'));
        case ReplyOutcome.expired:
          reply = PoolReply.expired(id, r.sentence('sentence'));
      }
      r.end();
      return reply;
    });
  }
}

/// What a wallet needs to read a pool and build transfers for it, and
/// nothing a wallet has to take on trust: the txids point at the chain, and
/// the ledger a wallet opens from them refuses an issuance that is not a
/// pool's or a witness that does not certify it. The layout (arities,
/// nullifier level, receipt slots) places leaves and reads statements; the
/// spend parameters make and decode proofs. The level parameters are the
/// coordinator's business and are not here.
class PoolDescriptor extends PoolMessage {
  final NetworkType network;
  final Uint8List issuance, witness0, slot0;
  final List<int> arities;
  final int nullifierLevel, receiptSlots;
  final StarkParams spendP;

  /// Leaves a round appends: a power of two, fixed for the pool's life.
  /// Every path a wallet keeps rests on this number, so a wallet checks
  /// the pool it is talking to still has the shape its stored state was
  /// built under, rather than discovering it at the round where a path
  /// stops reaching the root.
  final int leavesPerRound;

  /// The pool's tokenId and its genesis header, in full.
  ///
  /// These are here because a wallet does not look anything up: the txids
  /// above name transactions it must be given, and until it has them they
  /// tell it nothing. The tokenId is what a round has to carry before a
  /// wallet will believe the round is this pool's, and the genesis header
  /// is what the pool opened on.
  final Uint8List tokenId, genesisHeader;

  /// The run of rounds this pool serves block roots in. Catch-up requests
  /// name an aligned run of this size and nothing else, so every wallet's
  /// request is one of a handful and repeated catch-ups do not draw a
  /// picture of what the asker holds.
  final int catchUpRange;

  static const maxLevels = 8;

  /// The leaves per transfer: a transfer commits two notes.
  static const leavesPerTransfer = 2;

  PoolDescriptor({
    required this.network,
    required List<int> issuance,
    required List<int> witness0,
    required List<int> slot0,
    required List<int> arities,
    required this.nullifierLevel,
    required this.receiptSlots,
    required this.spendP,
    required this.leavesPerRound,
    required List<int> tokenId,
    required List<int> genesisHeader,
    this.catchUpRange = 1024,
  })  : issuance = PoolMessage.txidBytes(issuance, 'issuance'),
        witness0 = PoolMessage.txidBytes(witness0, 'witness0'),
        slot0 = PoolMessage.txidBytes(slot0, 'slot0'),
        tokenId = Uint8List.fromList(tokenId),
        genesisHeader = Uint8List.fromList(genesisHeader),
        arities = List.unmodifiable(arities) {
    if (arities.isEmpty || arities.length > maxLevels || arities.any((a) => a < 2 || a > 255)) {
      throw ArgumentError('1 to $maxLevels arities of 2 to 255');
    }
    if (nullifierLevel < 0 || nullifierLevel >= arities.length) throw ArgumentError('the nullifier level is one of the levels');
    if (receiptSlots < 0 || receiptSlots > 255) throw ArgumentError('receipt slots fit a byte');
    if (tokenId.length != PoolMessage.txidSize) throw ArgumentError('a tokenId is ${PoolMessage.txidSize} bytes');
    if (genesisHeader.length != PoolHeader.byteSize) throw ArgumentError('a genesis header is ${PoolHeader.byteSize} bytes');
    PoolHeader.decode(genesisHeader);
    final want = _leavesFor(transfers);
    if (leavesPerRound != want) throw ArgumentError('$transfers transfers append $want leaves a round, not $leavesPerRound');
    if (leavesPerRound & (leavesPerRound - 1) != 0) {
      throw ArgumentError('a round appends a power of two leaves, not $leavesPerRound: '
          'round N owns the aligned subtree at the block level only while that count is a power of two');
    }
    if (catchUpRange < 1 || catchUpRange > PoolMessage.maxBlockRoots) {
      throw ArgumentError('a catch-up range is 1 to ${PoolMessage.maxBlockRoots} rounds');
    }
    _checkParams(spendP);
  }

  /// The leaves a round of [transfers] appends: two per transfer, rounded
  /// up to whole subtrees, which is what the aggregation appends.
  static int _leavesFor(int transfers) {
    const sub = NoteCommitmentTree.subtreeLeaves;
    final leaves = transfers * leavesPerTransfer;
    return ((leaves + sub - 1) ~/ sub) * sub;
  }

  /// The block level: log2 of [leavesPerRound]. Round N owns the node at
  /// this level, index N - 1.
  int get blockLevel => leavesPerRound.bitLength - 1;

  /// Whether this pool serves block roots over rounds [from] to
  /// `from + count - 1`. Only aligned runs of [catchUpRange] are served.
  bool publishesRange(int from, int count) => from >= 1 && (from - 1) % catchUpRange == 0 && count == catchUpRange;

  /// Refuses a request for a range this pool does not publish, naming it.
  void requireRange(PoolCatchUpRequest request) {
    if (request.what != CatchUpKind.blockRoots) return;
    if (!publishesRange(request.from, request.count)) {
      throw ProtocolRefusal('range',
          'rounds ${request.from} to ${request.from + request.count - 1} are not one of the runs this pool serves '
          '(aligned runs of $catchUpRange from round 1)');
    }
  }

  /// The descriptor of the pool [plan] runs, issued by [issuance] with
  /// [witness0] and [slot0].
  factory PoolDescriptor.forPool(
      {required NetworkType network,
      required Transaction issuance,
      required Transaction witness0,
      required Transaction slot0,
      required PoolAggregation plan,
      int catchUpRange = 1024}) {
    final level = plan.nullifierLevel;
    if (level == null) throw ArgumentError('a TSL1_SP pool inserts nullifiers at one of its levels');
    // the tokenId and the genesis header are read off the issuance's own
    // PP1, through the body check: a descriptor that named a pool the
    // issuance does not carry would send every wallet reading it to check
    // rounds against fields no chain ever enforced
    final (fields, why) = PoolEvidence.readPP1Of(issuance, PoolEvidence.pp1Vout);
    if (fields == null) throw ArgumentError('the issuance carries no PP1_SP at output ${PoolEvidence.pp1Vout} ($why)');
    return PoolDescriptor(
        network: network,
        issuance: PoolMessage.txidOf(issuance),
        witness0: PoolMessage.txidOf(witness0),
        slot0: PoolMessage.txidOf(slot0),
        arities: [for (final l in plan.levelSpec) l.arity],
        nullifierLevel: level,
        receiptSlots: plan.receiptSlots,
        spendP: plan.spendP,
        leavesPerRound: plan.tree.leavesAppended,
        tokenId: fields.tokenId,
        genesisHeader: fields.genesisHeader,
        catchUpRange: catchUpRange);
  }

  @override
  PoolMessageKind get kind => PoolMessageKind.descriptor;

  /// Whether [round] is this pool's, given the [witness] that spends it: the
  /// descriptor's own tokenId and genesis header go straight into the
  /// evidence check, so a payee needs nothing else and looks nothing up.
  ///
  /// The caller has already established that [witness] is mined in a block it
  /// accepts.
  (ProvenRound?, EvidenceRefusal?) provenRound({required Transaction round, required Transaction witness}) =>
      PoolEvidence.provenRound(round: round, witness: witness, tokenId: tokenId, genesisHeader: genesisHeader);

  /// The layout a reader of this pool uses.
  ShieldedPoolLayout get layout =>
      ShieldedPoolLayout.forArities(arities, nullifierLevel: nullifierLevel, receiptSlots: receiptSlots);

  int get transfers => arities.fold(1, (n, a) => n * a);

  static void _checkParams(StarkParams p) {
    for (final (v, name) in [(p.logTrace, 'logTrace'), (p.logBlowup, 'logBlowup'), (p.logExpand, 'logExpand'), (p.logFinal, 'logFinal'), (p.grindBytes, 'grindBytes')]) {
      if (v < 0 || v > 255) throw ArgumentError('$name fits a byte');
    }
    for (final (v, name) in [(p.numQueries, 'numQueries'), (p.zkRandomizers, 'zkRandomizers')]) {
      if (v < 0 || v > 0xffff) throw ArgumentError('$name fits 16 bits');
    }
  }

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   network          1 (NetworkType index)
  //   issuance, witness0, slot0   32 each
  //   levels           1, then that many arities of 1 byte each
  //   nullifier level  1
  //   receipt slots    1
  //   spend parameters logTrace 1, logBlowup 1, logExpand 1, logFinal 1,
  //                    numQueries 2, grindBytes 1, zkRandomizers 2
  //   leaves a round   4
  //   catch-up range   4
  //   tokenId          32
  //   genesis header   236

  @override
  Uint8List encode() {
    final out = BytesBuilder(copy: false)
      ..addByte(PoolMessage.formatVersion)
      ..addByte(kind.number)
      ..addByte(network.index)
      ..add(issuance)
      ..add(witness0)
      ..add(slot0)
      ..addByte(arities.length)
      ..add(arities)
      ..addByte(nullifierLevel)
      ..addByte(receiptSlots)
      ..addByte(spendP.logTrace)
      ..addByte(spendP.logBlowup)
      ..addByte(spendP.logExpand)
      ..addByte(spendP.logFinal)
      ..add(PoolMessage.u16(spendP.numQueries))
      ..addByte(spendP.grindBytes)
      ..add(PoolMessage.u16(spendP.zkRandomizers))
      ..add(PoolMessage.u32(leavesPerRound))
      ..add(PoolMessage.u32(catchUpRange))
      ..add(tokenId)
      ..add(genesisHeader);
    return out.toBytes();
  }

  static PoolDescriptor decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.descriptor, PoolMessage.maxOther);
    return r.guard(() {
      final n = r.byte('network');
      if (n >= NetworkType.values.length) throw ProtocolRefusal('network', 'unknown network $n');
      final issuance = r.take('issuance', PoolMessage.txidSize);
      final witness0 = r.take('witness0', PoolMessage.txidSize);
      final slot0 = r.take('slot0', PoolMessage.txidSize);
      final levels = r.byte('arities');
      if (levels < 1 || levels > maxLevels) throw ProtocolRefusal('arities', '$levels levels, 1 to $maxLevels');
      final arities = r.take('arities', levels);
      if (arities.any((a) => a < 2)) throw ProtocolRefusal('arities', 'an arity below 2');
      final nullifierLevel = r.byte('nullifierLevel');
      if (nullifierLevel >= levels) throw ProtocolRefusal('nullifierLevel', 'level $nullifierLevel of $levels');
      final receiptSlots = r.byte('receiptSlots');
      final spendP = StarkParams(
          logTrace: r.byte('logTrace'),
          logBlowup: r.byte('logBlowup'),
          logExpand: r.byte('logExpand'),
          logFinal: r.byte('logFinal'),
          numQueries: r.u16('numQueries'),
          grindBytes: r.byte('grindBytes'),
          zkRandomizers: r.u16('zkRandomizers'));
      final leavesPerRound = r.u32('leavesPerRound');
      final catchUpRange = r.u32('catchUpRange');
      final tokenId = r.take('tokenId', PoolMessage.txidSize);
      final genesisHeader = r.take('genesisHeader', PoolHeader.byteSize);
      r.end();
      return PoolDescriptor(
          network: NetworkType.values[n],
          issuance: issuance,
          witness0: witness0,
          slot0: slot0,
          arities: arities,
          nullifierLevel: nullifierLevel,
          receiptSlots: receiptSlots,
          spendP: spendP,
          leavesPerRound: leavesPerRound,
          tokenId: tokenId,
          genesisHeader: genesisHeader,
          catchUpRange: catchUpRange);
    });
  }
}

/// What a coordinator publishes about a round: its number, its header, and
/// the txids of the round, its witness and the slot transaction the round
/// pins, which is the triple a reader applies. Nothing per transfer is in
/// it, so a feed of announcements reveals no more than the chain does; and
/// nothing in it is trusted, since a reader applying the triple refuses a
/// round that does not carry the announced header.
class PoolAnnouncement extends PoolMessage {
  final int round;
  final PoolHeader header;
  final Uint8List roundTxId, witnessTxId, slotTxId;

  /// The round's block root: the node at the block level, index
  /// `round - 1`. A party keeping a path current folds this and needs
  /// nothing else from the round; it is the same 32 bytes for every
  /// wallet, so publishing it names nobody.
  final Uint8List blockRoot;

  PoolAnnouncement(
      {required this.round,
      required this.header,
      required List<int> roundTxId,
      required List<int> witnessTxId,
      required List<int> slotTxId,
      required List<int> blockRoot})
      : roundTxId = PoolMessage.txidBytes(roundTxId, 'roundTxId'),
        witnessTxId = PoolMessage.txidBytes(witnessTxId, 'witnessTxId'),
        slotTxId = PoolMessage.txidBytes(slotTxId, 'slotTxId'),
        blockRoot = Uint8List.fromList(blockRoot) {
    if (round < 0 || round > 0xffffffff) throw ArgumentError('a round number fits 32 bits');
    if (blockRoot.length != PoolMessage.hashSize) throw ArgumentError('a block root is ${PoolMessage.hashSize} bytes');
  }

  /// The announcement of round [number] as the transactions carry it.
  factory PoolAnnouncement.of(int number, PoolHeader header, Transaction roundTx, Transaction witnessTx, Transaction slotTx,
          {required List<int> blockRoot}) =>
      PoolAnnouncement(
          round: number,
          header: header,
          roundTxId: PoolMessage.txidOf(roundTx),
          witnessTxId: PoolMessage.txidOf(witnessTx),
          slotTxId: PoolMessage.txidOf(slotTx),
          blockRoot: blockRoot);

  @override
  PoolMessageKind get kind => PoolMessageKind.announcement;

  String get roundId => hex.encode(roundTxId);
  String get witnessId => hex.encode(witnessTxId);
  String get slotId => hex.encode(slotTxId);

  /// Null when [applied], the ledger's account of the announced triple,
  /// is what this announcement claims; else what differs. A wallet fetches
  /// the three transactions by txid, applies them, and checks the result
  /// here: an announcement's number and header are claims, and the round's
  /// own PP1 is the fact.
  String? disagreement(ShieldedRound applied) {
    if (applied.number != round) return 'the ledger applied it as round ${applied.number}, the announcement says $round';
    if (!PoolMessage._eq(applied.header.encode(), header.encode())) {
      return 'the round\'s PP1 carries another header than the announcement';
    }
    if (!PoolMessage._eq(applied.blockRoot, blockRoot)) {
      return 'the round appends leaves under another block root than the announcement';
    }
    return null;
  }

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   round            4
  //   header           236
  //   round, witness, slot txids   32 each
  //   block root       32

  @override
  Uint8List encode() => (BytesBuilder(copy: false)
        ..addByte(PoolMessage.formatVersion)
        ..addByte(kind.number)
        ..add(PoolMessage.u32(round))
        ..add(header.encode())
        ..add(roundTxId)
        ..add(witnessTxId)
        ..add(slotTxId)
        ..add(blockRoot))
      .toBytes();

  static PoolAnnouncement decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.announcement, PoolMessage.maxOther);
    return r.guard(() {
      final round = r.u32('round');
      final PoolHeader header;
      try {
        header = PoolHeader.decode(r.take('header', PoolHeader.byteSize));
      } on ArgumentError catch (e) {
        throw ProtocolRefusal('header', '${e.message}');
      }
      final roundTxId = r.take('roundTxId', PoolMessage.txidSize);
      final witnessTxId = r.take('witnessTxId', PoolMessage.txidSize);
      final slotTxId = r.take('slotTxId', PoolMessage.txidSize);
      final blockRoot = r.take('blockRoot', PoolMessage.hashSize);
      r.end();
      return PoolAnnouncement(
          round: round,
          header: header,
          roundTxId: roundTxId,
          witnessTxId: witnessTxId,
          slotTxId: slotTxId,
          blockRoot: blockRoot);
    });
  }
}

/// What a catch-up request asks for. None of the three is trusted: a block
/// root is checked by folding it and matching the round's `cmRoot`, a
/// frontier by computing the tree's root from it and matching a proven
/// `cmRoot`, and a head proof by `PoolEvidence` and the wallet's own
/// headers. A pool is a convenient server for them and never an authority;
/// a wallet that obtains any of the three elsewhere reaches the same
/// verdict.
enum CatchUpKind {
  /// Block roots over a run of rounds, 32 bytes each.
  blockRoots(1),

  /// The current frontier: what a follower must hold to fold from here on.
  frontier(2),

  /// The tip round, its witness, and the witness's place in a block.
  head(3);

  final int number;
  const CatchUpKind(this.number);

  static CatchUpKind? of(int number) {
    for (final k in values) {
      if (k.number == number) return k;
    }
    return null;
  }
}

/// What a wallet asks a pool for when it is behind, or new.
///
/// A wallet with no notes joins on a frontier and a head proof and reads no
/// history at all. A wallet holding notes must fold every block root from
/// its note's round onward, because a frontier alone cannot bring a
/// particular leaf's siblings up to date.
///
/// The request carries nothing about the asker. A range is one of the
/// aligned runs the descriptor publishes, never a round derived from what
/// the wallet holds: across repeated catch-ups, a range of the wallet's own
/// choosing is a fingerprint.
class PoolCatchUpRequest extends PoolMessage {
  final CatchUpKind what;

  /// The first round asked for, and how many, for [CatchUpKind.blockRoots];
  /// both zero otherwise.
  final int from, count;

  PoolCatchUpRequest._(this.what, this.from, this.count);

  /// Block roots for rounds [from] to `from + count - 1`. The pool serves
  /// only the runs its descriptor publishes ([PoolDescriptor.requireRange]).
  factory PoolCatchUpRequest.blockRoots({required int from, required int count}) {
    if (from < 1 || from > 0xffffffff) throw ArgumentError('the first round is 1 or more');
    if (count < 1 || count > PoolMessage.maxBlockRoots) throw ArgumentError('1 to ${PoolMessage.maxBlockRoots} roots');
    return PoolCatchUpRequest._(CatchUpKind.blockRoots, from, count);
  }

  factory PoolCatchUpRequest.frontier() => PoolCatchUpRequest._(CatchUpKind.frontier, 0, 0);
  factory PoolCatchUpRequest.head() => PoolCatchUpRequest._(CatchUpKind.head, 0, 0);

  @override
  PoolMessageKind get kind => PoolMessageKind.catchUpRequest;

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   what             1
  //   from, count      4 + 4 (zero unless block roots)

  @override
  Uint8List encode() => (BytesBuilder(copy: false)
        ..addByte(PoolMessage.formatVersion)
        ..addByte(kind.number)
        ..addByte(what.number)
        ..add(PoolMessage.u32(from))
        ..add(PoolMessage.u32(count)))
      .toBytes();

  static PoolCatchUpRequest decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.catchUpRequest, PoolMessage.maxOther);
    return r.guard(() {
      final w = r.byte('what');
      final what = CatchUpKind.of(w);
      if (what == null) throw ProtocolRefusal('what', 'unknown catch-up kind $w');
      final from = r.u32('from');
      final count = r.u32('count');
      r.end();
      if (what != CatchUpKind.blockRoots) {
        if (from != 0 || count != 0) throw ProtocolRefusal('from', 'a ${what.name} request names no rounds');
        return PoolCatchUpRequest._(what, 0, 0);
      }
      if (from < 1) throw ProtocolRefusal('from', 'the first round is 1 or more, not $from');
      if (count < 1 || count > PoolMessage.maxBlockRoots) {
        throw ProtocolRefusal('count', 'declares $count roots, 1 to ${PoolMessage.maxBlockRoots}');
      }
      return PoolCatchUpRequest.blockRoots(from: from, count: count);
    });
  }
}

/// What a pool answers a catch-up request with. Nothing in it is derived
/// from who asked: no id, no address, and no round beyond the run served.
///
/// A block-root reply names the run it serves and carries the roots in
/// round order; a pool serves fewer than asked when the run reaches past
/// its tip. A frontier reply carries the round it stands at, that round's
/// block root, and the complete left subtrees a follower needs above the
/// block level, in level order; together they rebuild a follower exactly
/// ([BlockFold.at]). A head reply carries the tip round and its witness
/// whole, because a txid is the hash of the whole serialised transaction,
/// with the block the witness is in and its merkle branch.
class PoolCatchUpReply extends PoolMessage {
  final CatchUpKind what;

  /// Block roots: the first round served and the roots, in round order.
  final int from;
  final List<Uint8List> roots;

  /// Frontier: the round it stands at, that round's block root, and the
  /// left siblings above the block level in level order.
  final int round;
  final Uint8List? blockRoot;
  final List<Uint8List> left;

  /// Head: the tip round and its witness, the block the witness is in, the
  /// witness's index in that block and its merkle branch.
  final Uint8List? roundTx, witnessTx, blockHash;
  final int txIndex;
  final List<Uint8List> branch;

  PoolCatchUpReply._(this.what,
      {this.from = 0,
      this.roots = const [],
      this.round = 0,
      this.blockRoot,
      this.left = const [],
      this.roundTx,
      this.witnessTx,
      this.blockHash,
      this.txIndex = 0,
      this.branch = const []});

  /// Block roots for rounds [from] onward, in round order.
  factory PoolCatchUpReply.blockRoots({required int from, required List<List<int>> roots}) {
    if (from < 1 || from > 0xffffffff) throw ArgumentError('the first round is 1 or more');
    if (roots.length > PoolMessage.maxBlockRoots) throw ArgumentError('at most ${PoolMessage.maxBlockRoots} roots');
    if (roots.any((x) => x.length != PoolMessage.hashSize)) throw ArgumentError('a block root is ${PoolMessage.hashSize} bytes');
    return PoolCatchUpReply._(CatchUpKind.blockRoots, from: from, roots: [for (final x in roots) Uint8List.fromList(x)]);
  }

  /// The frontier at [round]: that round's block root and the left
  /// siblings above the block level, in level order.
  factory PoolCatchUpReply.frontier({required int round, required List<int> blockRoot, required List<List<int>> left}) {
    if (round < 1 || round > 0xffffffff) throw ArgumentError('a frontier stands at round 1 or more');
    if (blockRoot.length != PoolMessage.hashSize) throw ArgumentError('a block root is ${PoolMessage.hashSize} bytes');
    if (left.length > NoteCommitmentTree.depth) throw ArgumentError('at most ${NoteCommitmentTree.depth} nodes');
    if (left.any((x) => x.length != PoolMessage.hashSize)) throw ArgumentError('a node is ${PoolMessage.hashSize} bytes');
    return PoolCatchUpReply._(CatchUpKind.frontier,
        round: round,
        blockRoot: Uint8List.fromList(blockRoot),
        left: [for (final x in left) Uint8List.fromList(x)]);
  }

  /// The head: the tip round at [round], its witness, and the witness's
  /// place in the block [blockHash].
  factory PoolCatchUpReply.head(
      {required int round,
      required List<int> roundTx,
      required List<int> witnessTx,
      required List<int> blockHash,
      required int txIndex,
      required List<List<int>> branch}) {
    if (round < 1 || round > 0xffffffff) throw ArgumentError('a head stands at round 1 or more');
    for (final (b, name) in [(roundTx, 'the round'), (witnessTx, 'the witness')]) {
      if (b.isEmpty || b.length > PoolMessage.maxTx) throw ArgumentError('$name is 1 to ${PoolMessage.maxTx} bytes');
    }
    if (blockHash.length != PoolMessage.hashSize) throw ArgumentError('a block hash is ${PoolMessage.hashSize} bytes');
    if (txIndex < 0 || txIndex > 0xffffffff) throw ArgumentError('a transaction index fits 32 bits');
    if (branch.length > PoolMessage.maxBranch) throw ArgumentError('a branch is at most ${PoolMessage.maxBranch} deep');
    if (branch.any((x) => x.length != PoolMessage.hashSize)) throw ArgumentError('a branch node is ${PoolMessage.hashSize} bytes');
    return PoolCatchUpReply._(CatchUpKind.head,
        round: round,
        roundTx: Uint8List.fromList(roundTx),
        witnessTx: Uint8List.fromList(witnessTx),
        blockHash: Uint8List.fromList(blockHash),
        txIndex: txIndex,
        branch: [for (final x in branch) Uint8List.fromList(x)]);
  }

  @override
  PoolMessageKind get kind => PoolMessageKind.catchUpReply;

  /// The merkle root the head's branch computes for its witness, in the
  /// display order a block header prints it. The caller checks it against
  /// the header of [blockHash] in its own chain: this reply says where the
  /// witness is, and only the wallet's headers say whether that is true.
  List<int> computedMerkleRoot() {
    if (what != CatchUpKind.head) throw StateError('only a head reply carries a merkle branch');
    var cur = hex.decode(ShieldedLedger.parse(witnessTx!).id).reversed.toList();
    var index = txIndex;
    for (final sib in branch) {
      final other = sib.reversed.toList();
      final pair = index.isEven ? [...cur, ...other] : [...other, ...cur];
      cur = crypto.sha256.convert(crypto.sha256.convert(pair).bytes).bytes;
      index >>= 1;
    }
    return cur.reversed.toList();
  }

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   what             1
  //   block roots:     from 4, count 4, roots 32 each
  //   frontier:        round 4, block root 32, count 1, nodes 32 each
  //   head:            round 4, round length 4, round, witness length 4,
  //                    witness, block hash 32, index 4, count 1, branch

  @override
  Uint8List encode() {
    final out = BytesBuilder(copy: false)
      ..addByte(PoolMessage.formatVersion)
      ..addByte(kind.number)
      ..addByte(what.number);
    switch (what) {
      case CatchUpKind.blockRoots:
        out
          ..add(PoolMessage.u32(from))
          ..add(PoolMessage.u32(roots.length));
        for (final x in roots) {
          out.add(x);
        }
      case CatchUpKind.frontier:
        out
          ..add(PoolMessage.u32(round))
          ..add(blockRoot!)
          ..addByte(left.length);
        for (final x in left) {
          out.add(x);
        }
      case CatchUpKind.head:
        out
          ..add(PoolMessage.u32(round))
          ..add(PoolMessage.u32(roundTx!.length))
          ..add(roundTx!)
          ..add(PoolMessage.u32(witnessTx!.length))
          ..add(witnessTx!)
          ..add(blockHash!)
          ..add(PoolMessage.u32(txIndex))
          ..addByte(branch.length);
        for (final x in branch) {
          out.add(x);
        }
    }
    return out.toBytes();
  }

  static PoolCatchUpReply decode(List<int> bytes) {
    final r = _Reader.open(bytes, PoolMessageKind.catchUpReply, PoolMessage.maxCatchUp);
    return r.guard(() {
      final w = r.byte('what');
      final what = CatchUpKind.of(w);
      if (what == null) throw ProtocolRefusal('what', 'unknown catch-up kind $w');
      final PoolCatchUpReply reply;
      switch (what) {
        case CatchUpKind.blockRoots:
          final from = r.u32('from');
          if (from < 1) throw ProtocolRefusal('from', 'the first round is 1 or more, not $from');
          final n = r.u32('roots');
          if (n > PoolMessage.maxBlockRoots) {
            throw ProtocolRefusal('roots', 'declares $n roots, at most ${PoolMessage.maxBlockRoots}');
          }
          reply = PoolCatchUpReply.blockRoots(
              from: from, roots: [for (int i = 0; i < n; i++) r.take('root $i', PoolMessage.hashSize)]);
        case CatchUpKind.frontier:
          final round = r.u32('round');
          if (round < 1) throw ProtocolRefusal('round', 'a frontier stands at round 1 or more, not $round');
          final blockRoot = r.take('blockRoot', PoolMessage.hashSize);
          final n = r.byte('left');
          if (n > NoteCommitmentTree.depth) {
            throw ProtocolRefusal('left', 'declares $n nodes, at most ${NoteCommitmentTree.depth}');
          }
          reply = PoolCatchUpReply.frontier(
              round: round,
              blockRoot: blockRoot,
              left: [for (int i = 0; i < n; i++) r.take('node $i', PoolMessage.hashSize)]);
        case CatchUpKind.head:
          final round = r.u32('round');
          if (round < 1) throw ProtocolRefusal('round', 'a head stands at round 1 or more, not $round');
          final rl = r.u32('roundTx');
          if (rl < 1 || rl > PoolMessage.maxTx) throw ProtocolRefusal('roundTx', 'declares $rl bytes, 1 to ${PoolMessage.maxTx}');
          final roundTx = r.take('roundTx', rl);
          final wl = r.u32('witnessTx');
          if (wl < 1 || wl > PoolMessage.maxTx) throw ProtocolRefusal('witnessTx', 'declares $wl bytes, 1 to ${PoolMessage.maxTx}');
          final witnessTx = r.take('witnessTx', wl);
          final blockHash = r.take('blockHash', PoolMessage.hashSize);
          final txIndex = r.u32('txIndex');
          final n = r.byte('branch');
          if (n > PoolMessage.maxBranch) throw ProtocolRefusal('branch', 'declares $n nodes, at most ${PoolMessage.maxBranch}');
          reply = PoolCatchUpReply.head(
              round: round,
              roundTx: roundTx,
              witnessTx: witnessTx,
              blockHash: blockHash,
              txIndex: txIndex,
              branch: [for (int i = 0; i < n; i++) r.take('branch $i', PoolMessage.hashSize)]);
      }
      r.end();
      return reply;
    });
  }
}

/// A bounded reader over hostile bytes. Every read names its field, checks
/// its length against what remains, and turns any surprise into a
/// [ProtocolRefusal].
class _Reader {
  final List<int> b;
  int at = 0;
  _Reader._(this.b);

  /// A reader past the version and kind of [bytes], refusing a size over
  /// [max], another version or another kind before anything else is read.
  static _Reader open(List<int> bytes, PoolMessageKind kind, int max) {
    if (bytes.length > max) throw ProtocolRefusal('size', '${bytes.length} bytes, at most $max');
    final r = _Reader._(bytes);
    final v = r.byte('version');
    if (v != PoolMessage.formatVersion) throw ProtocolRefusal('version', 'unknown version $v');
    final k = r.byte('kind');
    if (k != kind.number) throw ProtocolRefusal('kind', 'kind $k is not ${kind.name} (${kind.number})');
    return r;
  }

  int get left => b.length - at;

  List<int> take(String field, int n) {
    if (n < 0 || n > left) throw ProtocolRefusal(field, 'needs $n bytes, $left remain');
    final out = b.sublist(at, at + n);
    at += n;
    return out;
  }

  int byte(String field) => take(field, 1)[0];

  int u16(String field) {
    final x = take(field, 2);
    return x[0] | (x[1] << 8);
  }

  int u32(String field) {
    final x = take(field, 4);
    return x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
  }

  String sentence(String field) {
    final n = u16(field);
    if (n > PoolMessage.maxSentence) throw ProtocolRefusal(field, 'declares $n bytes, at most ${PoolMessage.maxSentence}');
    try {
      return utf8.decode(take(field, n));
    } on FormatException catch (e) {
      throw ProtocolRefusal(field, 'is not UTF-8 (${e.message})');
    }
  }

  void end() {
    if (left != 0) throw ProtocolRefusal('end', '$left bytes after the last field');
  }

  /// Runs [f]; anything it throws other than a refusal becomes one, naming
  /// the field last read.
  T guard<T>(T Function() f) {
    try {
      return f();
    } on ProtocolRefusal {
      rethrow;
    } catch (e) {
      throw ProtocolRefusal('malformed', '$e');
    }
  }
}
