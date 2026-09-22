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
import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';

import '../builder/pp1_sp_lock_builder.dart';
import '../builder/pp1_sp_unlock_builder.dart' show ShieldedPoolAction;
import '../crypto/note_commitment_tree.dart';
import '../crypto/stark_prover.dart' show PreCommitment;
import '../crypto/stark_prover_ref.dart' show StarkParams;
import '../recursion/pool_aggregator.dart';
import '../recursion/prover_pool.dart';
import '../script_gen/pool_deposit_gen.dart';
import '../script_gen/pool_verifier_gen.dart';
import '../script_gen/slot_script_common.dart';
import '../script_gen/stark_verifier_gen.dart';
import '../transaction/shielded_pool_tool.dart';
import 'pool_header.dart';
import 'pool_out_hash.dart';
import 'pool_protocol.dart';
import 'shielded_chain_reader.dart';
import 'shielded_ledger.dart';
import 'shielded_transfer.dart';

/// What a coordinator is configured with. The plan fixes the round's shape
/// and every level's parameters, so it is the one thing a coordinator and
/// the pool it runs must agree on; the constructor checks the plan builds
/// the pool's own verifier.
class CoordinatorConfig {
  /// The aggregation plan: its spend parameters are what every transfer is
  /// verified at, its tree is the layout a reader uses.
  final PoolAggregation plan;

  /// How long the pending round waits after its first transfer before it
  /// closes short.
  final Duration roundDeadline;

  /// How many padding transfers to keep proved ahead.
  final int paddingStock;

  /// The level-1 provers this coordinator operates. Empty means every node
  /// is proved here.
  final List<NodeProver> provers;

  /// How long one level-1 node may take at a member before it is proved
  /// here instead.
  final Duration proverTimeout;

  /// Satoshis per kB each transaction pays, and the least (in satoshis)
  /// any pays.
  final int feeRate;
  final int feeFloor;

  /// How many blocks beyond the chain height a deposit covenant's refund
  /// must sit. A refund that could be mined before the round would take
  /// the covenant out from under it and invalidate the round.
  final int depositMargin;

  const CoordinatorConfig({
    required this.plan,
    this.roundDeadline = const Duration(minutes: 10),
    this.paddingStock = 0,
    this.provers = const [],
    this.proverTimeout = const Duration(minutes: 5),
    this.feeRate = 1,
    this.feeFloor = 135,
    this.depositMargin = 100,
  });

  StarkParams get spendP => plan.spendP;
  int get transfers => plan.transfers;
}

/// A spendable P2PKH output a coordinator was given for one transaction.
class FundingOutput {
  final Transaction tx;
  final int vout;
  final TransactionSigner signer;
  final SVPublicKey pubKey;
  FundingOutput(this.tx, this.vout, this.signer, this.pubKey);

  BigInt get value => tx.outputs[vout].satoshis;
}

/// Where the coordinator's transactions get their coins. The library
/// stays wallet-free: the localnet harness supplies outputs from a split
/// transaction, a server from its wallet.
abstract class CoordinatorFunding {
  /// A P2PKH output holding at least [minValue] satoshis, or null when
  /// none can be supplied. Y and the witness have no change output, so
  /// whatever the output holds beyond what they need is fee; the round has
  /// change, so it returns the surplus.
  Future<FundingOutput?> output(BigInt minValue);
}

/// Where a built round goes before it is published. A crash between the
/// round's publish and the witness's would leave a round mined with no
/// witness, which only the coordinator can build (it holds the witness's
/// signer), and the pool frozen; the store makes the witness recoverable.
abstract class CoordinatorStore {
  /// Called with round [number]'s three transactions and the ledger's
  /// snapshot after applying them, before the first of them is published.
  Future<void> roundBuilt(int number, Transaction y, Transaction round, Transaction witness, Uint8List snapshot);
}

/// The clock and timers the coordinator uses, so a test can drive a round's
/// deadline without waiting for it. Production passes [SystemClock], which
/// arms one real timer per pending round rather than polling.
abstract class CoordinatorClock {
  DateTime get now;

  /// Run [what] after [d] unless the returned alarm is cancelled first.
  CoordinatorAlarm after(Duration d, void Function() what);
}

abstract class CoordinatorAlarm {
  void cancel();
}

class SystemClock implements CoordinatorClock {
  const SystemClock();
  @override
  DateTime get now => DateTime.now();
  @override
  CoordinatorAlarm after(Duration d, void Function() what) => _TimerAlarm(Timer(d, what));
}

class _TimerAlarm implements CoordinatorAlarm {
  final Timer _t;
  _TimerAlarm(this._t);
  @override
  void cancel() => _t.cancel();
}

/// A clock a test moves by hand. [advance] fires whatever became due.
class FakeClock implements CoordinatorClock {
  DateTime _now;
  final List<_FakeAlarm> _alarms = [];
  FakeClock([DateTime? start]) : _now = start ?? DateTime.utc(2026, 1, 1);

  @override
  DateTime get now => _now;

  @override
  CoordinatorAlarm after(Duration d, void Function() what) {
    final a = _FakeAlarm(_now.add(d), what, this);
    _alarms.add(a);
    return a;
  }

  void advance(Duration d) {
    _now = _now.add(d);
    final due = [for (final a in _alarms) if (!a.cancelled && !a.dueAt.isAfter(_now)) a];
    due.sort((x, y) => x.dueAt.compareTo(y.dueAt));
    for (final a in due) {
      a.cancelled = true;
      _alarms.remove(a);
      a.what();
    }
  }
}

class _FakeAlarm implements CoordinatorAlarm {
  final DateTime dueAt;
  final void Function() what;
  final FakeClock _clock;
  bool cancelled = false;
  _FakeAlarm(this.dueAt, this.what, this._clock);
  @override
  void cancel() {
    cancelled = true;
    _clock._alarms.remove(this);
  }
}

/// Padding transfers proved ahead of time, so a short round closes
/// without proving its padding on the spot.
class ShieldedPaddingSupply {
  final StarkParams spendP;
  final Random _rng;
  final List<ShieldedTransfer> _stock = [];
  ShieldedPaddingSupply(this.spendP, {Random? rng}) : _rng = rng ?? Random.secure();

  int get stock => _stock.length;

  /// Proves until [target] padding transfers are in stock.
  void fill(int target) {
    while (_stock.length < target) {
      _stock.add(ShieldedTransfer.padding(spendP, rng: _rng));
    }
  }

  /// [n] padding transfers, from stock first, the rest proved now.
  List<ShieldedTransfer> take(int n) {
    final out = <ShieldedTransfer>[];
    while (out.length < n && _stock.isNotEmpty) {
      out.add(_stock.removeLast());
    }
    while (out.length < n) {
      out.add(ShieldedTransfer.padding(spendP, rng: _rng));
    }
    return out;
  }

  /// Padding taken for a round that was not built goes back.
  void giveBack(Iterable<ShieldedTransfer> padding) => _stock.addAll(padding);
}

/// Why a round was not published: the stage that failed and what it said.
class RoundFailure implements Exception {
  final String stage;
  final String reason;
  const RoundFailure(this.stage, this.reason);
  @override
  String toString() => 'round failed at $stage: $reason';
}

/// How long each stage of a round took, for the operator and the round
/// measurement: what a round costs is the aggregation plus the
/// coordinator's own work (trees, the three builds, the apply), and the
/// second is what this change is answerable for.
class RoundTiming {
  final Map<String, Duration> stages = {};
  final Stopwatch _sw = Stopwatch()..start();

  void lap(String stage) {
    stages[stage] = (stages[stage] ?? Duration.zero) + _sw.elapsed;
    _sw.reset();
  }

  Duration get total => stages.values.fold(Duration.zero, (a, b) => a + b);

  @override
  String toString() =>
      '${[for (final e in stages.entries) '${e.key} ${e.value.inMilliseconds} ms'].join(', ')}; total ${total.inMilliseconds} ms';
}

/// Why a coordinator refused to start on the chain it was given.
class RecoveryRefusal implements Exception {
  final String reason;
  const RecoveryRefusal(this.reason);
  @override
  String toString() => 'recovery refused: $reason';
}

/// One accepted submission, as the pending round holds it: the transfer as
/// submitted, its covenant transaction when it backs a deposit, and the
/// submission id a reply names. Nothing else is kept per transfer.
class _Entry {
  final Uint8List id;
  final ShieldedTransfer transfer;
  final Transaction? depositTx;
  _Entry(this.id, this.transfer, this.depositTx);
  bool get isDeposit => transfer.depositOutpoint != null;
}

/// The transfers gathered for one round, with the shadow state acceptance
/// is checked against: the nullifiers this round already claims, the
/// covenant outpoints it already spends, and the BSV it already takes out.
/// The ledger only moves when the round applies, so a round in flight
/// keeps its shadow until then.
class _PendingRound {
  final List<_Entry> entries = [];
  final Set<String> nullifiers = {};
  final Set<String> deposits = {};
  BigInt withdrawn = BigInt.zero;
  DateTime? openedAt;

  bool get isEmpty => entries.isEmpty;
  int get length => entries.length;
  int get depositCount => deposits.length;

  void add(_Entry e) {
    entries.add(e);
    for (final k in _keysOf(e.transfer)) {
      nullifiers.add(k);
    }
    if (e.isDeposit) deposits.add(hex.encode(e.transfer.depositOutpoint!));
    final p = e.transfer.publics;
    if (e.transfer.isBsv && p.publicOut > 0) withdrawn += BigInt.from(p.publicOut);
  }

  static List<String> _keysOf(ShieldedTransfer t) => [
        if (t.publics.real1) t.publics.nf1.join(','),
        if (t.publics.real2) t.publics.nf2.join(','),
      ];
}

/// A snapshot of what the coordinator is doing, for an operator.
class CoordinatorStatus {
  final int pending, capacity, inFlight, paddingStock, rounds;
  final BigInt balance;
  final DateTime? deadline;
  final RoundFailure? lastFailure;
  const CoordinatorStatus({
    required this.pending,
    required this.capacity,
    required this.inFlight,
    required this.paddingStock,
    required this.rounds,
    required this.balance,
    required this.deadline,
    required this.lastFailure,
  });

  @override
  String toString() => 'pending $pending/$capacity, in flight $inFlight, padding $paddingStock, rounds $rounds, '
      'balance $balance sat${lastFailure == null ? '' : ', last failure: $lastFailure'}';
}

/// Runs a TSL1_SP pool over time.
///
/// Wallets submit transfers whenever they like; the coordinator checks each
/// one at once, in cost order, gathers the accepted ones into a pending
/// round, and closes that round when it is full or when its deadline
/// passes. Closing means proving the aggregation and building three
/// transactions, the slot transaction Y_{N+1}, round N+1 and its witness,
/// which at production is minutes of proving, so intake keeps running into
/// the next pending round while it happens. The built round is applied to
/// the coordinator's own ledger with the checks a reader makes, handed to
/// the store, and only then published, Y first.
///
/// There is no transport here on purpose: [submit] is a method, [publish]
/// a callback and [funding] an interface, so a server, a test harness and
/// a CLI wrap the same thing. The coordinator holds no wallet key and
/// nothing per transfer beyond the transfer as submitted and its
/// submission id.
class ShieldedCoordinator {
  final CoordinatorConfig config;
  final ShieldedPoolTool tool;
  final ShieldedLedger ledger;
  final CoordinatorFunding funding;
  final CoordinatorStore store;
  final CoordinatorClock clock;

  /// Where each built transaction goes, in the order Y, round, witness.
  /// Broadcasting is the caller's business.
  final Future<void> Function(Transaction tx) publish;

  /// Where replies that cannot be returned from [submit] go: the expired
  /// replies of transfers dropped at close. The caller maps the id to the
  /// submitter.
  final void Function(PoolReply reply) notify;

  /// The key that owns the pool: it signs V, the anchor, the previous
  /// witness's output and each witness's PP1.
  final TransactionSigner owner;
  final SVPublicKey ownerPub;

  final ShieldedPaddingSupply padding;
  final Random _rng;

  /// The chain height the caller last told the coordinator, which is what
  /// a deposit covenant's refund height is measured against.
  int chainHeight = 0;

  /// How many spend proofs intake has verified. Every accepted transfer
  /// cost exactly one, and a refused one none or one, which is what the
  /// intake tests count.
  int verifications = 0;

  late final List<int> _body;
  late final List<int> _ownerPKH;
  late final int _ySize;
  _PendingRound _pending = _PendingRound();
  final List<_PendingRound> _inFlight = [];
  CoordinatorAlarm? _alarm;
  Future<PoolAnnouncement?>? _building;
  ProverPool? _lastPool;
  RoundTiming? _lastTiming;
  RoundFailure? _lastFailure;
  final List<PoolAnnouncement> _announcements = [];

  ShieldedCoordinator({
    required this.config,
    required this.tool,
    required this.ledger,
    required this.funding,
    required this.store,
    required this.publish,
    required this.owner,
    required this.ownerPub,
    this.clock = const SystemClock(),
    void Function(PoolReply reply)? notify,
    Random? rng,
  })  : notify = notify ?? _ignore,
        padding = ShieldedPaddingSupply(config.spendP, rng: rng),
        _rng = rng ?? Random.secure() {
    _checkPool();
  }

  /// A coordinator at the pool's genesis: its ledger opened from the
  /// [issuance], [witness0] and [slot0] the tool built.
  factory ShieldedCoordinator.open({
    required CoordinatorConfig config,
    required ShieldedPoolTool tool,
    required Transaction issuance,
    required Transaction witness0,
    required Transaction slot0,
    required CoordinatorFunding funding,
    required CoordinatorStore store,
    required Future<void> Function(Transaction tx) publish,
    required TransactionSigner owner,
    required SVPublicKey ownerPub,
    CoordinatorClock clock = const SystemClock(),
    void Function(PoolReply reply)? notify,
    Random? rng,
  }) =>
      ShieldedCoordinator(
          config: config,
          tool: tool,
          ledger: ShieldedLedger.open(ShieldedPoolLayout.of(config.plan.tree), issuance, witness0, slot0),
          funding: funding,
          store: store,
          publish: publish,
          owner: owner,
          ownerPub: ownerPub,
          clock: clock,
          notify: notify,
          rng: rng);

  static void _ignore(PoolReply _) {}

  /// The pool this coordinator is pointed at must be the one its plan
  /// builds and its key owns. The plan's verifier body must hash to what
  /// the pool's PP1 certifies, since Y_{N+1} carries that body, and the
  /// owner's key must be the PP1's owner, since it signs V. Both are found
  /// here, with a sentence, rather than when the first round is refused.
  void _checkPool() {
    final plan = config.plan;
    if (plan.nullifierLevel == null) throw StateError('a TSL1_SP pool inserts nullifiers at one of its levels; the plan has none');
    if (plan.transfers != ledger.layout.transfers) {
      throw StateError('the plan folds ${plan.transfers} transfers, the ledger\'s layout ${ledger.layout.transfers}');
    }
    final stmt = ledger.layout.statement;
    _body = ShieldedPoolTool.poolVerifier(stmt, verifier: StarkVerifierGen(plan.rootP, plan.rootAir(List.filled(stmt.numPublics, 0)))).body();
    final pp1 = PP1SpLockBuilder.fromScript(ledger.tipRound.outputs[1].script);
    final bodyHash = crypto.sha256.convert(_body).bytes;
    if (!_eq(pp1.verifierBodyHash ?? const [], bodyHash)) {
      throw StateError('the plan builds a verifier the pool does not certify: the PP1 names body hash '
          '${hex.encode(pp1.verifierBodyHash ?? const [])}, the plan\'s hashes to ${hex.encode(bodyHash)}');
    }
    _ownerPKH = hex.decode(Address.fromPublicKey(ownerPub, tool.networkType).pubkeyHash160);
    final pkh = hex.decode(pp1.ownerAddress!.pubkeyHash160);
    if (!_eq(pkh, _ownerPKH)) {
      throw StateError('the pool is owned by ${hex.encode(pkh)}, the coordinator\'s key is ${hex.encode(_ownerPKH)}');
    }
    // Y's size is fixed for a pool: a header, a signer and the verifier
    // body behind one funding input, whose P2PKH scriptSig is 107 bytes
    final dry = tool.buildSlotTxn(
        header: ledger.header,
        verifierBody: _body,
        fundingInput: TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER),
        anchorPKH: _ownerPKH,
        signerPKH: _ownerPKH);
    _ySize = hex.decode(dry.tx.serialize()).length + 107;
  }

  // ---- what an operator sees ----

  /// How many transfers one round holds.
  int get capacity => config.transfers;
  int get pending => _pending.length;
  int get inFlight => _inFlight.fold(0, (n, r) => n + r.length);

  /// The round being built, if any. Awaiting it waits for the publish
  /// calls to have run, or for the failure to have been recorded.
  Future<PoolAnnouncement?>? get building => _building;

  /// The pool that proved the last round's level-1 nodes. Its outcomes say
  /// which member took each node and which fell back here.
  ProverPool? get lastPool => _lastPool;

  /// Why the last close failed, if it did; null once a round succeeds.
  RoundFailure? get lastFailure => _lastFailure;

  /// How long each stage of the last close took.
  RoundTiming? get lastTiming => _lastTiming;

  /// Every round this coordinator published, in order.
  List<PoolAnnouncement> get announcements => List.unmodifiable(_announcements);

  /// The verifier body Y carries, which the pool's PP1 certifies.
  List<int> get verifierBody => _body;

  CoordinatorStatus get status => CoordinatorStatus(
        pending: _pending.length,
        capacity: capacity,
        inFlight: inFlight,
        paddingStock: padding.stock,
        rounds: ledger.round,
        balance: ledger.header.balance,
        deadline: _pending.openedAt?.add(config.roundDeadline),
        lastFailure: _lastFailure,
      );

  /// The descriptor of this pool, given its genesis transactions.
  PoolDescriptor descriptor(NetworkType network, Transaction issuance, Transaction witness0, Transaction slot0) =>
      PoolDescriptor.forPool(network: network, issuance: issuance, witness0: witness0, slot0: slot0, plan: config.plan);

  // ------------------------------------------------------------- intake

  /// [submitBytes] for a message that arrived as bytes. Null when the bytes
  /// carry no readable submission id, so there is nothing to answer to; a
  /// submission that decodes no further than its id is refused as
  /// malformed.
  PoolReply? submitBytes(List<int> bytes) {
    final PoolSubmission s;
    try {
      s = PoolSubmission.decode(bytes);
    } on ProtocolRefusal catch (e) {
      final id = PoolSubmission.idOf(bytes);
      return id == null ? null : PoolReply.refused(id, RefusalReason.malformed, '${e.field}: ${e.reason}');
    }
    return submit(s);
  }

  /// Decodes [s]'s transfer and deposit transaction and takes them through
  /// [intake].
  PoolReply submit(PoolSubmission s) {
    try {
      final t = s.transfer(config.spendP);
      final d = s.depositTransaction();
      return intake(s.id, t, depositTx: d);
    } on TransferRefusal catch (e) {
      return PoolReply.refused(s.id, RefusalReason.malformed, 'transfer ${e.field}: ${e.reason}');
    } on ProtocolRefusal catch (e) {
      return PoolReply.refused(s.id, RefusalReason.malformed, '${e.field}: ${e.reason}');
    } catch (e) {
      return PoolReply.refused(s.id, RefusalReason.malformed, 'the submission could not be read ($e)');
    }
  }

  /// Checks [t] and takes it into the pending round, or says why not.
  ///
  /// Everything a round would fail on is checked here, while it costs one
  /// transfer rather than a round, and in cost order: the transfer's own
  /// rules (hashing and parsing), then the ring, the nullifiers, the
  /// deposit covenant and the balance (lookups and one covenant parse),
  /// and the proof last, since an inbox anyone can write to makes the 20 ms
  /// of verification the thing to protect. The round builder trusts what
  /// comes through here and verifies no spend proof again.
  PoolReply intake(List<int> id, ShieldedTransfer t, {Transaction? depositTx}) {
    final (RefusalReason, String)? why;
    try {
      why = _check(t, depositTx);
    } catch (e) {
      return PoolReply.refused(id, RefusalReason.malformed, 'the submission could not be checked ($e)');
    }
    if (why != null) return PoolReply.refused(id, why.$1, why.$2);
    if (_pending.isEmpty) {
      _pending.openedAt = clock.now;
      _alarm = clock.after(config.roundDeadline, _onDeadline);
    }
    _pending.add(_Entry(Uint8List.fromList(id), t, depositTx));
    final number = ledger.round + _inFlight.length + 1;
    if (_pending.length >= capacity) closeRound();
    return PoolReply.accepted(id, number);
  }

  (RefusalReason, String)? _check(ShieldedTransfer t, Transaction? depositTx) {
    final p = t.publics;
    // the transfer against itself: outHash, withdrawal, bundle, deposit shape
    final own = t.refusal();
    if (own != null) return (RefusalReason.transfer, '${own.field}: ${own.reason}');
    // the anchor, unless nothing real is spent
    if (p.real1 || p.real2) {
      if (ledger.roundsLeftInRing(SlotScript.lanesBytes(p.anchor)) == 0) {
        return (RefusalReason.anchor, 'the anchor is not one of the ${PoolHeader.ringEntries} roots this pool accepts');
      }
    }
    // the nullifiers: spent on chain, or claimed by a round not yet published
    for (final (real, nf) in [(p.real1, p.nf1), (p.real2, p.nf2)]) {
      if (!real) continue;
      if (ledger.nullifiers.occupied(nf)) return (RefusalReason.nullifierSpent, 'the note is already spent');
      final k = nf.join(',');
      if (_pending.nullifiers.contains(k) || _inFlight.any((r) => r.nullifiers.contains(k))) {
        return (RefusalReason.nullifierPending, 'another transfer in an unpublished round spends the same note');
      }
    }
    // the deposit covenant
    final deposit = _checkDeposit(t, depositTx);
    if (deposit != null) return deposit;
    // the balance: what the pending and in-flight rounds already take out, plus this
    if (t.isBsv && p.publicOut > 0) {
      final taken = _pending.withdrawn + _inFlight.fold(BigInt.zero, (n, r) => n + r.withdrawn) + BigInt.from(p.publicOut);
      if (taken > ledger.header.balance) {
        return (RefusalReason.balance, 'the round would take $taken satoshis out of a balance of ${ledger.header.balance}');
      }
    }
    // the proof, last
    verifications++;
    final bad = t.verifyProof(config.spendP);
    if (bad != null) return (RefusalReason.proof, bad);
    return null;
  }

  (RefusalReason, String)? _checkDeposit(ShieldedTransfer t, Transaction? depositTx) {
    final o = t.depositOutpoint;
    if (o == null) {
      return depositTx == null ? null : (RefusalReason.depositMissing, 'a covenant transaction came with a transfer that names no deposit');
    }
    if (depositTx == null) return (RefusalReason.depositMissing, 'the transfer backs a deposit but no covenant transaction came with it');
    final vout = ByteData.sublistView(o, 32).getUint32(0, Endian.little);
    if (!_eq(o.sublist(0, 32), depositTx.hash) || vout >= depositTx.outputs.length) {
      return (RefusalReason.depositCovenant, 'the outpoint named is not an output of the transaction sent');
    }
    final pp3 = tool.getOutpoint(ledger.tipRound.hash, outputIndex: 3);
    final min = chainHeight + config.depositMargin;
    final found = ShieldedPoolTool.findDeposits([depositTx], pp3, minRefundAfter: min).where((d) => d.vout == vout).toList();
    if (found.isEmpty) {
      // say why, rather than that it was not found
      final terms = PoolDepositGen.parse(depositTx.outputs[vout].script.buffer);
      if (terms == null) return (RefusalReason.depositCovenant, 'output $vout is not a deposit covenant');
      if (!_eq(terms.pp3Outpoint, pp3)) {
        return (RefusalReason.depositTarget, 'the covenant names PP3 ${_outpoint(terms.pp3Outpoint)}, and this pool\'s live PP3 is '
            '${_outpoint(pp3)} (round ${ledger.round}); refund it and deposit against the live PP3');
      }
      return (RefusalReason.depositCovenant, 'the covenant is refundable from height ${terms.refundAfter}, the round needs at least $min');
    }
    if (_inFlight.isNotEmpty) {
      return (RefusalReason.depositTarget, 'round ${ledger.round + 1} is being built and spends the live PP3; deposit against its PP3 '
          'once it is announced');
    }
    final receipt = t.receipt!, covenant = found.single.receipt;
    if (!_eq(covenant.commitment, receipt.commitment) || covenant.satoshis != receipt.satoshis) {
      return (RefusalReason.depositCovenant, 'the covenant\'s commitment and value are not the transfer\'s receipt');
    }
    final key = hex.encode(o);
    if (_pending.deposits.contains(key)) return (RefusalReason.depositPending, 'a pending transfer already backs this covenant');
    if (_pending.depositCount >= ledger.layout.statement.receiptSlots) {
      return (RefusalReason.receiptSlots, 'the pending round has no receipt slot left; resubmit after it closes');
    }
    return null;
  }

  static String _outpoint(List<int> o) => '${hex.encode(o.sublist(0, 32).reversed.toList())}:${o[32] | (o[33] << 8)}';

  // -------------------------------------------------------------- rounds

  void _onDeadline() {
    _alarm = null;
    closeRound();
  }

  /// Closes the pending round: proves it, builds Y, the round and the
  /// witness, applies them to the ledger, stores them and publishes them.
  /// Returns the announcement, or null when nothing was pending or the
  /// round failed (see [lastFailure]). Rounds are built one at a time: a
  /// second close waits for the first, since both advance the same ledger.
  Future<PoolAnnouncement?> closeRound() {
    if (_pending.isEmpty) return _building ?? Future<PoolAnnouncement?>.value(null);
    // The pending round is taken here and not inside the build, which may
    // start minutes later: a transfer submitted meanwhile joins the next
    // round rather than one that is already closed.
    final round = _pending;
    _pending = _PendingRound();
    _alarm?.cancel();
    _alarm = null;
    _inFlight.add(round);
    final prior = _building ?? Future<PoolAnnouncement?>.value(null);
    final next = prior.then((_) => _buildAndPublish(round));
    _building = next;
    return next;
  }

  Future<PoolAnnouncement?> _buildAndPublish(_PendingRound round) async {
    var stage = 'expiry';
    List<ShieldedTransfer> pad = const [];
    final timing = _lastTiming = RoundTiming();
    try {
      // a transfer whose anchor rotated out, or whose note a round published
      // meanwhile spent, would fail at aggregation minutes in: drop it now
      final live = <_Entry>[];
      for (final e in round.entries) {
        final why = _expired(e.transfer);
        if (why == null) {
          live.add(e);
        } else {
          notify(PoolReply.expired(e.id, why));
        }
      }
      if (live.isEmpty) return null;
      round.entries
        ..clear()
        ..addAll(live);
      timing.lap(stage);

      // funding for Y, before anything is proved: a coordinator with no
      // coins should not spend minutes finding that out
      stage = 'funding';
      final yFee = _fee(_ySize);
      final fY = await _fund(yFee + BigInt.two, 'Y');
      timing.lap(stage);

      stage = 'padding';
      pad = padding.take(capacity - live.length);
      final transfers = [for (final e in live) e.transfer, ...pad];
      timing.lap(stage);

      stage = 'build';
      final built = await _build(transfers, live, fY, yFee, timing);

      stage = 'apply';
      final ShieldedRound applied;
      try {
        applied = ledger.apply(built.round, built.witness, built.y.tx);
      } on LedgerRefusal catch (e) {
        throw RoundFailure('apply', 'the coordinator\'s own ledger refuses the round it built (${e.check}): ${e.reason}');
      }
      pad = const [];
      _inFlight.remove(round);
      _lastFailure = null;
      timing.lap(stage);

      stage = 'store';
      final snapshot = ledger.snapshot();
      await store.roundBuilt(applied.number, built.y.tx, built.round, built.witness, snapshot);
      timing.lap(stage);

      stage = 'publish';
      final a = PoolAnnouncement.of(applied.number, applied.header, built.round, built.witness, built.y.tx);
      _announcements.add(a);
      await publish(built.y.tx);
      await publish(built.round);
      await publish(built.witness);
      timing.lap(stage);
      return a;
    } catch (e) {
      final f = e is RoundFailure ? e : RoundFailure(stage, '$e');
      _lastFailure = f;
      if (_inFlight.contains(round)) {
        // nothing applied: the transfers are pending again, the padding is stock again
        _inFlight.remove(round);
        padding.giveBack(pad);
        _restore(round);
      }
      return null;
    }
  }

  /// Why [t] can no longer go into a round, or null.
  String? _expired(ShieldedTransfer t) {
    final p = t.publics;
    if ((p.real1 || p.real2) && ledger.roundsLeftInRing(SlotScript.lanesBytes(p.anchor)) == 0) {
      return 'the anchor left the ring while the transfer waited; prove it again against a current root';
    }
    for (final (real, nf) in [(p.real1, p.nf1), (p.real2, p.nf2)]) {
      if (real && ledger.nullifiers.occupied(nf)) return 'the note was spent by a round published while the transfer waited';
    }
    return null;
  }

  /// Puts a failed round's transfers back at the front of the pending
  /// round, so they close first.
  void _restore(_PendingRound failed) {
    final merged = _PendingRound()..openedAt = failed.openedAt ?? _pending.openedAt;
    for (final e in [...failed.entries, ..._pending.entries]) {
      merged.add(e);
    }
    _pending = merged;
    _alarm?.cancel();
    _alarm = clock.after(config.roundDeadline, _onDeadline);
  }

  BigInt _fee(int size) {
    final fee = (size * config.feeRate + 999) ~/ 1000;
    return BigInt.from(fee < config.feeFloor ? config.feeFloor : fee);
  }

  Future<FundingOutput> _fund(BigInt minValue, String what) async {
    final FundingOutput? f;
    try {
      f = await funding.output(minValue);
    } catch (e) {
      throw RoundFailure('funding', 'the funding source failed for $what ($e)');
    }
    if (f == null) throw RoundFailure('funding', 'no funding output of $minValue satoshis for $what');
    if (f.value < minValue) throw RoundFailure('funding', 'the output given for $what holds ${f.value} satoshis, it needs $minValue');
    return f;
  }

  Future<({({Transaction tx, List<int> outpoint, List<int> parts}) y, Transaction round, Transaction witness})> _build(
      List<ShieldedTransfer> transfers, List<_Entry> live, FundingOutput fY, BigInt yFee, RoundTiming timing) async {
    final plan = config.plan, L = ledger.layout, stmt = L.statement;
    final publics = [for (final t in transfers) t.publics];
    final spendLanes = [for (final p in publics) p.toLanes()];
    final bundles = [for (final t in transfers) t.bundle];
    final bundleHashes = [for (final t in transfers) t.bundleHash];
    final withdrawals = [for (final t in transfers) if (t.withdrawal != null) t.withdrawal!];
    final receiptTransfers = [for (int i = 0; i < live.length; i++) if (live[i].isDeposit) i];
    final receipts = [for (final i in receiptTransfers) transfers[i].receipt!];
    final deposits = [for (final i in receiptTransfers) (live[i].depositTx!, _voutOf(transfers[i].depositOutpoint!))];

    // the trees, advanced on copies the ledger takes only when the round applies
    final tree = ledger.tree.copy(), nf = ledger.nullifiers.copy();
    final rootBefore = tree.root;
    final j = tree.nextSubtree, paths = <List<List<int>>>[];
    for (int s = 0; s < plan.tree.subtrees; s++) {
      paths.add(tree.subtreePath(j + s));
      tree.appendSubtree([for (final l in plan.tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final ring = [for (final r in ledger.header.ring) _lanesOf(r)];
    timing.lap('trees');

    // the aggregation, level 1 through the prover pool
    final pool = ProverPool(program: plan.levels[0], provers: config.provers, timeout: config.proverTimeout);
    _lastPool = pool;
    final (rootProof, wide) = await plan.aggregate(publics, [for (final t in transfers) t.proof],
        rootBefore: rootBefore,
        rootAfter: tree.root,
        index: j,
        paths: paths,
        ring: ring,
        nullifiers: nf,
        receiptTransfers: receiptTransfers,
        rng: _rng,
        level1: pool);
    timing.lap('aggregation');
    final roundProof = PoolRoundProof.root(plan.rootP, plan.rootAir(wide), rootProof, bundleHashes);
    timing.lap('root unlock');

    // the header the round states, which is what a reader must rebuild
    final moved = publics.fold(BigInt.zero, (a, p) => a + BigInt.from(p.publicOut));
    final header = ledger.header.advance(
        cmRoot: SlotScript.lanesBytes(tree.root),
        nfRoot: SlotScript.lanesBytes(nf.root),
        size: ledger.size + stmt.leavesAppended,
        balance: ledger.header.balance - moved,
        outHash: PoolOutHash.roundOutHash(bundleHashes));

    // Y_{N+1}, funded before the proof
    final y = tool.buildSlotTxn(
        header: header,
        verifierBody: _body,
        fundingTx: fY.tx,
        fundingVout: fY.vout,
        fundingSigner: fY.signer,
        fundingPubKey: fY.pubKey,
        anchorPKH: _ownerPKH,
        signerPKH: _ownerPKH);
    timing.lap('Y');

    // the round and the witness, built once to size them and once with the
    // exact fee and the real funding: the fee moves only the change amount
    // and the funding outpoints only 36-byte fields, so the sizes hold
    final prevRoundBytes = hex.decode(ledger.tipRound.serialize());
    final ownerPKHHex = hex.encode(_ownerPKH);
    final encoded = PoolOutHash.encodeBundles(bundles);
    Transaction round(FundingOutput fR, FundingOutput fW, BigInt fee) => tool.createRoundTxn(
        ledger.tipWitness, ledger.tipRound, ledger.tipSlot, ownerPub, fR.tx, fR.signer, fR.pubKey, fW.tx.hash, header, y.outpoint,
        fundingVout: fR.vout,
        witnessFundingVout: fW.vout,
        nextSlotTx: y.tx,
        receipts: receipts,
        deposits: deposits,
        withdrawals: withdrawals,
        roundProof: roundProof,
        fee: fee,
        ownerSigner: owner);
    Transaction witness(Transaction r, FundingOutput fW) => tool.createWitnessTxn(
        owner, fW.tx, r, prevRoundBytes, ownerPub, ownerPKHHex, ShieldedPoolAction.ROUND,
        fundingVout: fW.vout,
        fundingSigner: fW.signer,
        fundingPubKey: fW.pubKey,
        newOwnerPKH: _ownerPKH,
        newHeader: header.encode(),
        nextSlot: y.outpoint,
        slotParts: y.parts,
        verifierBody: _body,
        bundles: encoded,
        receipts: receipts,
        withdrawals: withdrawals);
    final dryRound = round(fY, fY, BigInt.zero);
    final dryWitness = witness(dryRound, fY);
    timing.lap('dry builds');
    // DER signatures vary by a byte or two; a few bytes of margin keep the
    // priced size from falling under the real one
    final rFee = _fee(hex.decode(dryRound.serialize()).length + 8);
    final wFee = _fee(hex.decode(dryWitness.serialize()).length + 8);
    final fW = await _fund(wFee + BigInt.one, 'the witness');
    final fR = await _fund(rFee + TransactionBuilder.DUST_AMOUNT, 'the round');
    timing.lap('funding');
    final r = round(fR, fW, rFee);
    timing.lap('round');
    final w = witness(r, fW);
    timing.lap('witness');
    return (y: y, round: r, witness: w);
  }

  static int _voutOf(List<int> outpoint) => outpoint[32] | (outpoint[33] << 8) | (outpoint[34] << 16) | (outpoint[35] << 24);

  // ------------------------------------------------------------ idle work

  /// The work worth doing while no round is being built: refill the padding
  /// stock, and let go of the preprocessed commitments.
  ///
  /// The commitments are deliberately not kept warm. Each is gigabytes and
  /// the levels are proved one after another, so holding all of them costs
  /// most of a round's peak memory to save one rebuild per level. Their
  /// 8-lane roots are kept, which is what the statement digests need.
  Future<void> runIdleWork() async {
    PreCommitment.releaseCached();
    if (config.paddingStock > 0) padding.fill(config.paddingStock);
  }

  // ------------------------------------------------------------- recovery

  /// The ledger a restarting coordinator runs on: [snapshot] restored, or
  /// the pool opened from [issuance], [witness0] and [slot0], with every
  /// [triples] since applied through the chain reader. Refuses, naming the
  /// tip and the triple, when a triple does not apply, and when the chain
  /// ends at a round other than [lastRound], the last the store holds: a
  /// round this coordinator published and the chain does not show may be
  /// orphaned or not yet relayed, and building on top of it is not the
  /// library's call.
  static ShieldedLedger recover(
    ShieldedPoolLayout layout, {
    List<int>? snapshot,
    Transaction? issuance,
    Transaction? witness0,
    Transaction? slot0,
    required Iterable<ShieldedRoundTxs> triples,
    int? lastRound,
  }) {
    final ShieldedLedger ledger;
    if (snapshot != null) {
      ledger = ShieldedLedger.restore(layout, snapshot);
    } else if (issuance != null && witness0 != null && slot0 != null) {
      ledger = ShieldedLedger.open(layout, issuance, witness0, slot0);
    } else {
      throw ArgumentError('recover from a snapshot, or from the issuance, witness 0 and Y_0');
    }
    final reader = ShieldedChainReader(ledger);
    final list = triples.toList();
    reader.read(list);
    if (reader.stopped) {
      // the reader applied its rounds from the front of the list, so the
      // refused triple is the next one
      final t = list[reader.rounds.length];
      final tipId = ledger.tipRound.id;
      throw RecoveryRefusal('round ${reader.refusedRound} (${t.round.id}) does not extend the tip, round ${ledger.round} ($tipId): '
          '${reader.refusal}');
    }
    if (lastRound != null && ledger.round != lastRound) {
      throw RecoveryRefusal('the chain ends at round ${ledger.round}, the store\'s last round is $lastRound');
    }
    return ledger;
  }

  // ---- helpers ----

  static List<int> _lanesOf(List<int> bytes) =>
      [for (int i = 0; i < bytes.length; i += 4) bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)];

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
