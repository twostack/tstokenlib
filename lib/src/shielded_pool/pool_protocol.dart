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
import 'package:dartsv/dartsv.dart';

import '../crypto/stark_prover_ref.dart' show StarkParams;
import '../recursion/pool_aggregator.dart' show PoolAggregation;
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

/// The four messages a wallet and a coordinator exchange. Each carries its
/// kind in its second byte, so one inbox can hold any of them.
enum PoolMessageKind {
  submission(1),
  reply(2),
  descriptor(3),
  announcement(4);

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
  static const formatVersion = 1;

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
    if (bytes.length > maxSubmission) throw ProtocolRefusal('size', '${bytes.length} bytes, at most $maxSubmission');
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

  static const maxLevels = 8;

  PoolDescriptor({
    required this.network,
    required List<int> issuance,
    required List<int> witness0,
    required List<int> slot0,
    required List<int> arities,
    required this.nullifierLevel,
    required this.receiptSlots,
    required this.spendP,
  })  : issuance = PoolMessage.txidBytes(issuance, 'issuance'),
        witness0 = PoolMessage.txidBytes(witness0, 'witness0'),
        slot0 = PoolMessage.txidBytes(slot0, 'slot0'),
        arities = List.unmodifiable(arities) {
    if (arities.isEmpty || arities.length > maxLevels || arities.any((a) => a < 2 || a > 255)) {
      throw ArgumentError('1 to $maxLevels arities of 2 to 255');
    }
    if (nullifierLevel < 0 || nullifierLevel >= arities.length) throw ArgumentError('the nullifier level is one of the levels');
    if (receiptSlots < 0 || receiptSlots > 255) throw ArgumentError('receipt slots fit a byte');
    _checkParams(spendP);
  }

  /// The descriptor of the pool [plan] runs, issued by [issuance] with
  /// [witness0] and [slot0].
  factory PoolDescriptor.forPool(
      {required NetworkType network,
      required Transaction issuance,
      required Transaction witness0,
      required Transaction slot0,
      required PoolAggregation plan}) {
    final level = plan.nullifierLevel;
    if (level == null) throw ArgumentError('a TSL1_SP pool inserts nullifiers at one of its levels');
    return PoolDescriptor(
        network: network,
        issuance: PoolMessage.txidOf(issuance),
        witness0: PoolMessage.txidOf(witness0),
        slot0: PoolMessage.txidOf(slot0),
        arities: [for (final l in plan.levelSpec) l.arity],
        nullifierLevel: level,
        receiptSlots: plan.receiptSlots,
        spendP: plan.spendP);
  }

  @override
  PoolMessageKind get kind => PoolMessageKind.descriptor;

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
      ..add(PoolMessage.u16(spendP.zkRandomizers));
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
      r.end();
      return PoolDescriptor(
          network: NetworkType.values[n],
          issuance: issuance,
          witness0: witness0,
          slot0: slot0,
          arities: arities,
          nullifierLevel: nullifierLevel,
          receiptSlots: receiptSlots,
          spendP: spendP);
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

  PoolAnnouncement(
      {required this.round,
      required this.header,
      required List<int> roundTxId,
      required List<int> witnessTxId,
      required List<int> slotTxId})
      : roundTxId = PoolMessage.txidBytes(roundTxId, 'roundTxId'),
        witnessTxId = PoolMessage.txidBytes(witnessTxId, 'witnessTxId'),
        slotTxId = PoolMessage.txidBytes(slotTxId, 'slotTxId') {
    if (round < 0 || round > 0xffffffff) throw ArgumentError('a round number fits 32 bits');
  }

  /// The announcement of round [number] as the transactions carry it.
  factory PoolAnnouncement.of(int number, PoolHeader header, Transaction roundTx, Transaction witnessTx, Transaction slotTx) =>
      PoolAnnouncement(
          round: number,
          header: header,
          roundTxId: PoolMessage.txidOf(roundTx),
          witnessTxId: PoolMessage.txidOf(witnessTx),
          slotTxId: PoolMessage.txidOf(slotTx));

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
    return null;
  }

  // ---- wire format ----
  //
  //   version, kind    1 + 1
  //   round            4
  //   header           236
  //   round, witness, slot txids   32 each

  @override
  Uint8List encode() => (BytesBuilder(copy: false)
        ..addByte(PoolMessage.formatVersion)
        ..addByte(kind.number)
        ..add(PoolMessage.u32(round))
        ..add(header.encode())
        ..add(roundTxId)
        ..add(witnessTxId)
        ..add(slotTxId))
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
      r.end();
      return PoolAnnouncement(round: round, header: header, roundTxId: roundTxId, witnessTxId: witnessTxId, slotTxId: slotTxId);
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
