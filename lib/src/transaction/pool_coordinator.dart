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
import 'package:dartsv/dartsv.dart';
import '../crypto/nullifier_set.dart';
import '../crypto/stark_prover.dart';
import '../crypto/stark_prover_ref.dart';
import '../crypto/stark_verifier_ref.dart';
import '../recursion/pool_aggregator.dart';
import '../recursion/prover_pool.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_legacy_script_gen.dart';
import '../script_gen/verifier_slot_gen.dart';
import 'pool_chain_reader.dart';
import 'shielded_pool_legacy_tool.dart';

/// Which kind of round this pool does. A pool is built by one generator and
/// its state script carries that choice, so the mode is fixed for the
/// pool's life and the coordinator only has to agree with it.
enum CoordinatorMode {
  /// K per-transfer verifier slots and an append slot, each transfer's proof
  /// checked by its own slot on chain.
  direct,

  /// One verifier slot checking the root of an aggregation, the transfers
  /// folded by the coordinator.
  recursive,
}

/// Why a submitted transfer was not taken into the pending round. The
/// submitter is told which of these it was, since the remedy differs: a bad
/// proof is the wallet's bug, a pending double spend is a race it can retry
/// after the next round, and an overdrawn vault is the pool's limit.
enum RejectReason {
  /// The spend proof does not verify against the transfer's publics.
  proof,

  /// The extra outputs do not hash to the outHash the proof committed to.
  outHash,

  /// A mint or a gated asset without the issuer's authorisation.
  authorisation,

  /// The anchor is not one of the roots the state script will accept.
  anchor,

  /// A real nullifier is already in the pool's set.
  nullifierSpent,

  /// A real nullifier is already claimed by a transfer in a round that has
  /// not been published yet.
  nullifierPending,

  /// The BSV leaving the pool this round would exceed the vault.
  vault,

  /// A deposit arrived without the transparent input that funds it.
  funding,
}

/// A refused submission and the sentence to hand back to the submitter.
class Rejection {
  final RejectReason reason;
  final String why;
  const Rejection(this.reason, this.why);
  @override
  String toString() => '${reason.name}: $why';
}

/// What the coordinator is configured to run.
///
/// The two modes share intake and the ledger but not round building, which
/// is why this is a sealed choice made once rather than a flag read per
/// round: a pool cannot change its mind without a new state script.
class CoordinatorConfig {
  final CoordinatorMode mode;

  /// The parameters every submitted spend proof is verified under.
  final StarkParams spendP;

  /// Recursive mode: the aggregation plan. Null in direct mode.
  final PoolAggregation? plan;

  /// How long the pending round waits after its first transfer before it
  /// closes short.
  final Duration roundDeadline;

  /// Recursive mode: how many padding transfers to keep proved ahead.
  final int paddingStock;

  /// Recursive mode: the level-1 provers this coordinator operates. Empty
  /// means every node is proved here.
  final List<NodeProver> provers;

  /// How long one level-1 node may take at a member before it is proved
  /// here instead.
  final Duration proverTimeout;

  const CoordinatorConfig._({
    required this.mode,
    required this.spendP,
    required this.roundDeadline,
    this.plan,
    this.paddingStock = 0,
    this.provers = const [],
    this.proverTimeout = const Duration(minutes: 5),
  });

  /// Direct-slot rounds: the generator's K transfers per round, each proof
  /// checked by its own slot. No aggregation, so no padding and no provers.
  const CoordinatorConfig.direct({
    required StarkParams spendP,
    Duration roundDeadline = const Duration(minutes: 10),
  }) : this._(mode: CoordinatorMode.direct, spendP: spendP, roundDeadline: roundDeadline);

  /// Recursive rounds: [plan].transfers per round, folded into one root
  /// proof, short rounds padded from the stock.
  const CoordinatorConfig.recursive({
    required StarkParams spendP,
    required PoolAggregation plan,
    Duration roundDeadline = const Duration(minutes: 10),
    int paddingStock = 64,
    List<NodeProver> provers = const [],
    Duration proverTimeout = const Duration(minutes: 5),
  }) : this._(
          mode: CoordinatorMode.recursive,
          spendP: spendP,
          plan: plan,
          roundDeadline: roundDeadline,
          paddingStock: paddingStock,
          provers: provers,
          proverTimeout: proverTimeout,
        );
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

/// The transfers gathered for one round, with the shadow state acceptance
/// is checked against: the nullifiers this round already claims and the BSV
/// it already takes out of the vault. The real ledger only moves when the
/// round is published, so a round in flight keeps its shadow until then.
class _PendingRound {
  final List<PoolTransfer> transfers = [];
  final List<FundingInput> funding = [];
  final Set<String> nullifiers = {};
  int withdrawn = 0;
  DateTime? openedAt;

  bool get isEmpty => transfers.isEmpty;
  int get length => transfers.length;
}

/// A snapshot of what the coordinator is doing, for an operator or a status
/// endpoint above it.
class CoordinatorStatus {
  final CoordinatorMode mode;
  final int pending, capacity, inFlight, paddingStock, rounds;
  final int vault;
  final DateTime? deadline;
  const CoordinatorStatus({
    required this.mode,
    required this.pending,
    required this.capacity,
    required this.inFlight,
    required this.paddingStock,
    required this.rounds,
    required this.vault,
    required this.deadline,
  });

  @override
  String toString() => 'mode ${mode.name}, pending $pending/$capacity, in flight $inFlight, '
      'padding $paddingStock, rounds $rounds, vault $vault sat';
}

/// Runs a shielded pool over time.
///
/// Wallets submit transfers whenever they like; the coordinator validates
/// each one immediately, gathers them into a pending round, and closes that
/// round when it is full or when its deadline passes. Closing means building
/// and publishing the round transaction, which in recursive mode is minutes
/// of proving, so intake keeps running into the next pending round while it
/// happens.
///
/// There is no transport here on purpose: [submit] is a method and
/// [publish] is a callback, so a CLI, an HTTP server or a test harness can
/// wrap the same service.
class PoolCoordinator {
  final CoordinatorConfig config;
  final ShieldedPoolLegacyTool tool;
  final PoolLedger ledger;
  final CoordinatorClock clock;

  /// Where a built round transaction goes. Broadcasting to a node is the
  /// caller's business.
  final Future<void> Function(Transaction tx) publish;

  final PaddingSupply padding;
  final Random _rng;
  static const _p2 = Poseidon2ProofHash();

  _PendingRound _pending = _PendingRound();
  final List<_PendingRound> _inFlight = [];
  CoordinatorAlarm? _alarm;
  Future<Transaction?>? _building;
  ProverPool? _lastPool;
  int _rounds = 0;

  PoolCoordinator({
    required this.config,
    required this.tool,
    required this.ledger,
    required this.publish,
    this.clock = const SystemClock(),
    Random? rng,
  })  : padding = PaddingSupply(config.spendP, rng: rng),
        _rng = rng ?? Random.secure() {
    _checkMode();
  }

  /// The pool this coordinator is pointed at must be the one its mode
  /// builds. The generator's mode and the live state script both have to
  /// agree, and a mismatch names what was found against what was expected
  /// rather than failing later inside a round.
  void _checkMode() {
    final want = config.mode;
    final found = tool.gen.aggregated ? CoordinatorMode.recursive : CoordinatorMode.direct;
    if (want != found) {
      throw StateError('configured for ${want.name} rounds but the generator builds ${found.name} rounds');
    }
    if (want == CoordinatorMode.recursive) {
      final plan = config.plan!;
      if (plan.transfers != tool.gen.n) {
        throw StateError('the plan folds ${plan.transfers} transfers but the pool holds ${tool.gen.n} per round');
      }
    }
    final live = ledger.tx.outputs[ShieldedPoolLegacyTool.stateVout].script.buffer;
    final expected = tool.gen.lock(ledger.header).buffer;
    if (!_sameBytes(live, expected)) {
      throw StateError('the pool\'s state script is ${live.length} B and not the ${expected.length} B script this '
          'generator builds: the pool was created for ${found == CoordinatorMode.recursive ? 'direct-slot' : 'recursive'} '
          'rounds or for different parameters');
    }
  }

  static bool _sameBytes(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// How many transfers one round holds.
  int get capacity => config.mode == CoordinatorMode.recursive ? config.plan!.transfers : tool.gen.k;

  int get pending => _pending.length;

  /// The round currently being built, if any. Awaiting it waits for the
  /// publish callback to have run.
  Future<Transaction?>? get building => _building;

  /// The pool that proved the last recursive round's level-1 nodes. Its
  /// outcomes say which member took each node and which fell back here,
  /// which is what an operator watches to tell a slow member from a dead
  /// one.
  ProverPool? get lastPool => _lastPool;

  CoordinatorStatus get status => CoordinatorStatus(
        mode: config.mode,
        pending: _pending.length,
        capacity: capacity,
        inFlight: _inFlight.fold(0, (n, r) => n + r.length),
        paddingStock: padding.stock,
        rounds: _rounds,
        vault: ledger.vault,
        deadline: _pending.openedAt?.add(config.roundDeadline),
      );

  // ------------------------------------------------------------- intake

  /// Validate [t] and take it into the pending round, or say why not.
  ///
  /// Everything a round would fail on is checked here, while it costs one
  /// transfer rather than a round: a bad proof found at round time would
  /// throw away minutes of proving. The round builder is entitled to trust
  /// what comes through here.
  ///
  /// A deposit (BSV coming into the pool) must arrive with the [funding]
  /// input that pays for it, or the round it joins would promise a vault
  /// nothing funded.
  Rejection? submit(PoolTransfer t, {FundingInput? funding}) {
    final bad = _validate(t, funding);
    if (bad != null) return bad;
    if (_pending.isEmpty) {
      _pending.openedAt = clock.now;
      _alarm = clock.after(config.roundDeadline, _onDeadline);
    }
    _pending.transfers.add(t);
    if (funding != null) _pending.funding.add(funding);
    for (final nf in _realNullifiers(t)) {
      _pending.nullifiers.add(nf);
    }
    if (PoolHash.isBsv(t.publics.asset)) _pending.withdrawn += t.publics.publicOut;
    if (_pending.length >= capacity) closeRound();
    return null;
  }

  Rejection? _validate(PoolTransfer t, FundingInput? funding) {
    // the proof, first: nothing else is meaningful if the statement is not proved
    try {
      StarkVerifierRef(config.spendP, PoolSpendAir.air(t.publics), hash: _p2).verify(t.proof);
    } on VerificationFailure catch (e) {
      return Rejection(RejectReason.proof, 'the spend proof does not verify ($e)');
    } catch (e) {
      return Rejection(RejectReason.proof, 'the spend proof could not be checked ($e)');
    }
    final want = PoolPublicInputs.outHashLanes(t.extraOutputs);
    for (int i = 0; i < want.length; i++) {
      if (t.publics.outHash[i] != want[i]) {
        return Rejection(RejectReason.outHash, 'the proof does not commit to the extra outputs supplied with it');
      }
    }
    if (t.needsAuth && t.auth == null) {
      return Rejection(RejectReason.authorisation, 'a mint or a gated asset needs the issuer\'s authorisation');
    }
    // the ring check is waived for a transfer with no real input, which is
    // how padding can be proved at any time against the zero anchor
    if (t.publics.real1 || t.publics.real2) {
      final anchor = NullifierSet.fromLanes(t.publics.anchor);
      if (!ledger.header.ring.any((r) => _sameBytes(r, anchor))) {
        return Rejection(RejectReason.anchor, 'the anchor is not one of the ${PP1SpLegacyHeader.ringSize} roots this pool accepts');
      }
    }
    for (final nf in _realNullifiers(t)) {
      if (ledger.nullifiers.contains(_bytesOf(nf))) {
        return Rejection(RejectReason.nullifierSpent, 'the note is already spent');
      }
      if (_pending.nullifiers.contains(nf) || _inFlight.any((r) => r.nullifiers.contains(nf))) {
        return Rejection(RejectReason.nullifierPending, 'another transfer in an unpublished round spends the same note');
      }
    }
    if (PoolHash.isBsv(t.publics.asset) && t.publics.publicOut < 0 && funding == null) {
      return Rejection(RejectReason.funding, 'a deposit of ${-t.publics.publicOut} satoshis needs the input that funds it');
    }
    if (PoolHash.isBsv(t.publics.asset) && t.publics.publicOut > 0) {
      final taken = _pending.withdrawn + _inFlight.fold(0, (n, r) => n + r.withdrawn) + t.publics.publicOut;
      if (taken > ledger.vault) {
        return Rejection(RejectReason.vault, 'the round would take $taken satoshis out of a vault of ${ledger.vault}');
      }
    }
    return null;
  }

  /// The real nullifiers of [t], as map keys. A dummy input's nullifier is
  /// not a claim on anything, so it is not tracked.
  List<String> _realNullifiers(PoolTransfer t) => [
        if (t.publics.real1) t.publics.nf1.join(','),
        if (t.publics.real2) t.publics.nf2.join(','),
      ];

  static List<int> _bytesOf(String key) => NullifierSet.fromLanes([for (final p in key.split(',')) int.parse(p)]);

  // -------------------------------------------------------------- rounds

  void _onDeadline() {
    _alarm = null;
    closeRound();
  }

  /// Close the pending round: build its transaction and publish it.
  ///
  /// Returns null when there is nothing pending, since an empty round would
  /// spend the state output and append nothing. Rounds are built one at a
  /// time: a second close waits for the first, because both advance the
  /// same ledger.
  Future<Transaction?> closeRound() {
    if (_pending.isEmpty) return _building ?? Future<Transaction?>.value(null);
    // The pending round is taken here and not inside the build, which may
    // start minutes later: a transfer submitted in the meantime has to join
    // the next round rather than one that is already closed.
    final round = _pending;
    _pending = _PendingRound();
    _alarm?.cancel();
    _alarm = null;
    _inFlight.add(round);
    final prior = _building ?? Future<Transaction?>.value(null);
    final next = prior.then((_) => _buildAndPublish(round));
    _building = next;
    return next;
  }

  Future<Transaction?> _buildAndPublish(_PendingRound round) async {
    try {
      final tx = await _build(round.transfers, round.funding);
      _rounds++;
      await publish(tx);
      return tx;
    } finally {
      _inFlight.remove(round);
    }
  }

  Future<Transaction> _build(List<PoolTransfer> transfers, List<FundingInput> funding) async {
    if (config.mode == CoordinatorMode.recursive) {
      final plan = config.plan!;
      final pool = ProverPool(program: plan.levels[0], provers: config.provers, timeout: config.proverTimeout);
      _lastPool = pool;
      return tool.createAggregatedRoundTxn(ledger, transfers, plan, funding: funding, padding: padding, rng: _rng, level1: pool);
    }
    // direct slots: a short round leaves the spare slots idle rather than
    // padding, since each slot is verified on its own
    final slots = <PoolTransfer?>[...transfers, for (int i = transfers.length; i < tool.gen.k; i++) null];
    return tool.createRoundTxn(ledger, slots, funding: funding);
  }

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
    if (config.mode == CoordinatorMode.recursive && config.paddingStock > 0) {
      padding.fill(config.paddingStock);
    }
  }

  // ------------------------------------------------------------- recovery

  /// Rebuild a ledger from the chain: the genesis transaction, then every
  /// round transaction in order.
  ///
  /// The chain is the source of truth, so nothing is persisted and a
  /// restart replays. [lastPublished], when given, is the state the
  /// coordinator believed it had left behind; a disagreement means either
  /// the rebuild or the belief is wrong and the coordinator must not run on
  /// either.
  static PoolLedger recover(PP1SpLegacyScriptGen gen, Transaction genesisTx, Iterable<Transaction> rounds, {Transaction? lastPublished}) {
    final reader = PoolChainReader.fromGenesis(gen, genesisTx);
    for (final r in rounds) {
      reader.apply(r);
    }
    final rebuilt = reader.ledger;
    if (lastPublished != null && rebuilt.tx.id != lastPublished.id) {
      throw StateError('the ledger rebuilt from the chain ends at round ${rebuilt.tx.id} '
          'but the last state published was ${lastPublished.id}');
    }
    return rebuilt;
  }
}

/// A coordinator described by a file, so running a pool does not mean
/// writing Dart.
///
/// The file names the mode, the schedule and the parameters, and points at
/// the genesis transaction and the round transactions published since. The
/// parameters are spelled out rather than named because a pool's scripts
/// are built from them: a coordinator that guessed them would compile a
/// generator that does not match the pool it is pointed at, which is
/// exactly what the mode check catches, one step too late to be useful.
class CoordinatorFile {
  final CoordinatorConfig config;
  final PP1SpLegacyScriptGen gen;
  final String genesis;
  final List<String> rounds;
  const CoordinatorFile({required this.config, required this.gen, required this.genesis, required this.rounds});

  static StarkParams params(Map<String, dynamic> j) => StarkParams(
        logTrace: j['logTrace'] as int,
        logBlowup: j['logBlowup'] as int,
        logExpand: (j['logExpand'] as int?) ?? 3,
        logFinal: j['logFinal'] as int,
        numQueries: j['numQueries'] as int,
        grindBytes: j['grindBytes'] as int,
        zkRandomizers: (j['zkRandomizers'] as int?) ?? 0,
      );

  /// Read a description. [plan] may be the name `throughput` for the
  /// production plan, or a list of levels with their own parameters.
  static CoordinatorFile parse(Map<String, dynamic> j) {
    final mode = j['mode'] == 'direct' ? CoordinatorMode.direct : CoordinatorMode.recursive;
    final deadline = Duration(seconds: (j['roundDeadlineSeconds'] as int?) ?? 600);
    final genesis = j['genesis'] as String;
    final rounds = [for (final r in (j['rounds'] as List? ?? const [])) r as String];
    if (mode == CoordinatorMode.direct) {
      throw UnimplementedError('direct-slot pools are configured by their generator, which this file does not yet describe');
    }
    final PoolAggregation agg;
    final StarkParams spendP;
    if (j['plan'] == 'throughput') {
      spendP = PoolAggregation.spendThroughputParams;
      agg = PoolAggregation.throughput();
    } else {
      spendP = params(j['spend'] as Map<String, dynamic>);
      final levels = [
        for (final l in j['levels'] as List)
          AggregationLevel(
              params: params((l as Map<String, dynamic>)['params'] as Map<String, dynamic>),
              logTrace: l['logTrace'] as int,
              arity: l['arity'] as int)
      ];
      final root = j['root'] as Map<String, dynamic>;
      agg = PoolAggregation(
          spendP: spendP, levelSpec: levels, rootP: params(root['params'] as Map<String, dynamic>), rootLog: root['logTrace'] as int);
    }
    final slot = VerifierSlotGen(agg.rootP, airFor: agg.rootAir, numPublics: agg.widePublicsCount);
    final gen = PP1SpLegacyScriptGen.aggregated(spendP, verifierSlot: slot, transfers: agg.transfers, leavesAppended: agg.tree.leavesAppended);
    return CoordinatorFile(
      config: CoordinatorConfig.recursive(
        spendP: spendP,
        plan: agg,
        roundDeadline: deadline,
        paddingStock: (j['paddingStock'] as int?) ?? 64,
        proverTimeout: Duration(seconds: (j['proverTimeoutSeconds'] as int?) ?? 300),
      ),
      gen: gen,
      genesis: genesis,
      rounds: rounds,
    );
  }
}
