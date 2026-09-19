import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/recursion/prover_pool.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/script_gen/verifier_slot_gen.dart';
import 'package:tstokenlib/src/transaction/pool_coordinator.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_tool.dart';

final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

/// The coordinator running a pool in recursive mode: what it accepts, when
/// it closes a round, that intake stays open while a round is being built,
/// that level 1 goes through the configured prover pool, what it holds
/// while idle, and that a restart rebuilds the same ledger from the chain.
void main() {
  final rng = Random(31);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  const p2 = Poseidon2ProofHash();
  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const l1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const l2 = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const rootP = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  final operatorKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final operatorPub = SVPublicKey.fromPrivateKey(operatorKey);
  final operatorAddress = Address.fromPublicKey(operatorPub, NetworkType.TEST);
  final operatorSigner = DefaultTransactionSigner(sigHashAll, operatorKey);
  final depositorKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
  final depositorPub = SVPublicKey.fromPrivateKey(depositorKey);
  final depositorAddress = Address.fromPublicKey(depositorPub, NetworkType.TEST);
  final depositorSigner = DefaultTransactionSigner(sigHashAll, depositorKey);

  Transaction coinbaseLike(Address to, List<int> sats) {
    final t = Transaction()
      ..version = 1
      ..nLockTime = 0;
    t.inputs.add(TransactionInput('00' * 32, 0xffffffff, TransactionInput.MAX_SEQ_NUMBER,
        scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript.fromByteArray([3, 1, 2, 3]))));
    for (final s in sats) {
      t.outputs.add(TransactionOutput(BigInt.from(s), P2PKHLockBuilder.fromAddress(to).getScriptPubkey()));
    }
    return t;
  }

  late PoolAggregation agg;
  late PP1SpScriptGen gen;
  late Transaction issuanceTx;
  final rabin = Rabin.generateKeyPair(1024);
  final rabinN = Rabin.bigIntToScriptNum(rabin.n).toList();
  final rabinPKH = hash160(rabinN);
  final idTxId = bytes(32), ed25519 = bytes(32);

  setUpAll(() {
    agg = PoolAggregation.uniform(spendP: spendP, levelP: const [l1, l2], levelLog: const [15, 16], rootP: rootP, rootLog: 15, arity: 2);
    final slot = VerifierSlotGen(rootP, airFor: agg.rootAir, numPublics: agg.widePublicsCount);
    gen = PP1SpScriptGen.aggregated(spendP, verifierSlot: slot, transfers: agg.transfers, leavesAppended: agg.tree.leavesAppended);
  });

  /// A fresh pool: issuance, genesis, the tool and a ledger at round zero.
  (ShieldedPoolTool, PoolLedger, Transaction) freshPool({int vault = 2000}) {
    final tool = ShieldedPoolTool(gen);
    final fundingTx = coinbaseLike(operatorAddress, [50000, 20000]);
    issuanceTx = tool.createIssuanceTxn(fundingTx, 1, operatorSigner, operatorPub, operatorAddress, rabinPKH);
    final sig = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...fundingTx.hash]), rabin.p, rabin.q);
    final (genesisTx, ledger) = tool.createGenesisTxn(issuanceTx, fundingTx, operatorSigner, operatorPub, operatorAddress,
        rabinN: rabinN, rabinS: Rabin.bigIntToScriptNum(sig.s).toList(), rabinPadding: sig.padding,
        identityTxId: idTxId, ed25519PubKey: ed25519, vault: vault);
    return (tool, ledger, genesisTx);
  }

  /// A deposit of [sats] with its funding input and change. [sk] and [d],
  /// when given, own the first output note so a later test can spend it.
  (PoolTransfer, FundingInput, OutputNote) deposit(PoolLedger ledger, int sats, int seed, {List<int>? sk, List<int>? d}) {
    final funding = coinbaseLike(depositorAddress, [sats + 2000]);
    final change = ShieldedPoolTool.payout(depositorAddress, 1200);
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final pkd = sk == null ? lanes(8) : PoolHash.pkd(sk, d!);
    final oa = OutputNote(pkd: pkd, value: sats - 7, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 7, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -sats, anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(change));
    final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(seed), hash: p2);
    return (PoolTransfer(w.publics, proof, change), FundingInput(funding, 0, depositorSigner, depositorPub), oa);
  }

  /// Where [note] sits in the tree, found by the only property that pins it
  /// down without knowing the round's leaf layout: the path from that
  /// position reproduces the tree's root.
  int positionOf(PoolLedger ledger, List<int> sk, List<int> d, OutputNote note) {
    for (int i = 0; i < ledger.tree.size; i++) {
      final path = ledger.tree.path(i);
      final s = SpendNote(sk: sk, d: d, value: note.value, rho: note.rho, rcm: note.rcm, siblings: path.siblings, position: i);
      if (_sameLanes(s.root, ledger.tree.root)) return i;
    }
    throw StateError('the note is not in the tree');
  }

  CoordinatorConfig recursiveConfig({int stock = 0, List<NodeProver> provers = const [], Duration? deadline, Duration? timeout}) =>
      CoordinatorConfig.recursive(
          spendP: spendP,
          plan: agg,
          roundDeadline: deadline ?? const Duration(minutes: 10),
          paddingStock: stock,
          provers: provers,
          proverTimeout: timeout ?? const Duration(minutes: 5));

  // ---------------------------------------------------------------- 1.1

  test('the mode is checked against the pool it is pointed at', () {
    final (tool, ledger, _) = freshPool();
    // the matching mode starts
    expect(
        PoolCoordinator(
            config: recursiveConfig(), tool: tool, ledger: ledger, publish: (_) async {}, clock: FakeClock(), rng: Random(1)),
        isA<PoolCoordinator>());
    // the other mode is refused, and the message names both
    expect(
        () => PoolCoordinator(
            config: const CoordinatorConfig.direct(spendP: spendP), tool: tool, ledger: ledger, publish: (_) async {}, clock: FakeClock()),
        throwsA(isA<StateError>().having((e) => e.message, 'message', allOf(contains('direct'), contains('recursive')))));
  }, timeout: const Timeout(Duration(minutes: 10)));

  // ---------------------------------------------------------------- 1.2

  test('intake: what it accepts and the reason it gives for what it does not', () {
    final (tool, ledger, _) = freshPool(vault: 2000);
    final co = PoolCoordinator(
        config: recursiveConfig(), tool: tool, ledger: ledger, publish: (_) async {}, clock: FakeClock(), rng: Random(2));

    final (good, goodFunding, _) = deposit(ledger, 30000, 40);
    expect(co.submit(good, funding: goodFunding), isNull, reason: 'a well formed deposit is accepted');
    expect(co.pending, 1);

    // a deposit without the input that funds it
    final (unfunded, _, _) = deposit(ledger, 1000, 41);
    expect(co.submit(unfunded)?.reason, RejectReason.funding);

    // extra outputs that do not hash to the committed outHash
    final (t3, f3, _) = deposit(ledger, 1000, 42);
    final tampered = PoolTransfer(t3.publics, t3.proof, Uint8List.fromList([...t3.extraOutputs, 7]));
    expect(co.submit(tampered, funding: f3)?.reason, RejectReason.outHash);

    // a proof that does not verify: the publics say one thing, the proof another
    final (t4, f4, _) = deposit(ledger, 1000, 43);
    final (t5, _, _) = deposit(ledger, 1234, 44);
    expect(co.submit(PoolTransfer(t5.publics, t4.proof, t5.extraOutputs), funding: f4)?.reason, RejectReason.proof);

    expect(co.pending, 1, reason: 'nothing rejected reached the pending round');
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('intake: the same note cannot be spent twice, pending or already spent', () async {
    final (tool, ledger, _) = freshPool();
    final published = <Transaction>[];
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 6),
        tool: tool,
        ledger: ledger,
        publish: (tx) async => published.add(tx),
        clock: FakeClock(),
        rng: Random(3));
    await co.runIdleWork();

    // round 1 puts a note this test owns into the tree
    final sk = lanes(5), d = lanes(3);
    final (dep, depFunding, note) = deposit(ledger, 40000, 46, sk: sk, d: d);
    expect(co.submit(dep, funding: depFunding), isNull);
    await co.closeRound();
    final at = positionOf(ledger, sk, d, note);

    /// A spend of that note, with fresh output randomness each time so the
    /// two transfers differ in everything but the nullifier they claim.
    PoolTransfer spendOfNote(int seed) {
      final path = ledger.tree.path(at);
      final a = SpendNote(sk: sk, d: d, value: note.value, rho: note.rho, rcm: note.rcm, siblings: path.siblings, position: at);
      final w = PoolSpendAir.witness(a, SpendNote.dummy(sk: lanes(5), rho: lanes(3)),
          OutputNote(pkd: lanes(8), value: note.value - 10, rho: lanes(3), rcm: lanes(4)),
          OutputNote(pkd: lanes(8), value: 10, rho: lanes(3), rcm: lanes(4)), 0,
          anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
      expect(w.publics.real1, isTrue, reason: 'a real input carries a nullifier claim');
      return PoolTransfer(w.publics, StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(seed), hash: p2), Uint8List(0));
    }

    final first = spendOfNote(47), second = spendOfNote(48);
    expect(first.publics.nf1, second.publics.nf1, reason: 'both spend the same note');
    expect(co.submit(first), isNull);
    expect(co.submit(second)?.reason, RejectReason.nullifierPending);
    expect(co.pending, 1);

    // once the round is published the nullifier is in the set, and the
    // rejection changes from a race to a spend
    await co.closeRound();
    expect(published.length, 2);
    expect(co.submit(spendOfNote(49))?.reason, RejectReason.nullifierSpent);
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('intake: an anchor that has aged out of the ring, and a vault that cannot cover the round', () async {
    final (tool, ledger, _) = freshPool();
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 4), tool: tool, ledger: ledger, publish: (_) async {}, clock: FakeClock(), rng: Random(9));
    await co.runIdleWork();
    final sk = lanes(5), d = lanes(3);
    final (dep, depFunding, note) = deposit(ledger, 30000, 55, sk: sk, d: d);
    expect(co.submit(dep, funding: depFunding), isNull);
    await co.closeRound();
    final at = positionOf(ledger, sk, d, note);

    // the path as it was when the note was created. A wallet that takes too
    // long to spend proves against this root, and the pool has moved on.
    final stalePath = ledger.tree.path(at).siblings;

    /// An unshield of the note against the given path, taking its value out.
    PoolTransfer unshield(List<List<int>> siblings, int seed) {
      final a = SpendNote(sk: sk, d: d, value: note.value, rho: note.rho, rcm: note.rcm, siblings: siblings, position: at);
      final payee = ShieldedPoolTool.payout(depositorAddress, note.value - 500);
      final w = PoolSpendAir.witness(a, SpendNote.dummy(sk: lanes(5), rho: lanes(3)),
          OutputNote(pkd: lanes(8), value: 0, rho: lanes(3), rcm: lanes(4)),
          OutputNote(pkd: lanes(8), value: 0, rho: lanes(3), rcm: lanes(4)), note.value,
          outHash: PoolPublicInputs.outHashLanes(payee));
      return PoolTransfer(w.publics, StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(seed), hash: p2), payee);
    }

    // the ring holds the last four roots, so four more rounds retire the one
    // the stale path proves membership in
    for (int r = 0; r < PP1SpHeader.ringSize; r++) {
      final (t, f, _) = deposit(ledger, 1000 + r, 120 + r);
      expect(co.submit(t, funding: f), isNull);
      await co.closeRound();
    }
    expect(co.status.rounds, 1 + PP1SpHeader.ringSize);

    final stale = unshield(stalePath, 56);
    expect(co.submit(stale)?.reason, RejectReason.anchor,
        reason: 'the root it proves membership in has left the ring');

    // a vault that no longer covers what the pending round would take. A
    // healthy pool cannot reach this, since a note's value came from a
    // deposit that raised the vault by as much; the guard is here for a
    // vault that moved under the round, which is why a deposit is only
    // accepted with the input that funds it.
    final vaultWas = ledger.vault;
    ledger.vault = 10;
    expect(co.submit(unshield(ledger.tree.path(at).siblings, 57))?.reason, RejectReason.vault);

    // with the vault back, the same note against its current path is taken
    ledger.vault = vaultWas;
    expect(co.submit(unshield(ledger.tree.path(at).siblings, 58)), isNull);
    // and now its nullifier is the pending claim, ahead of any other check
    expect(co.submit(unshield(ledger.tree.path(at).siblings, 59))?.reason, RejectReason.nullifierPending);
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 2.1

  test('a short round is padded and published when the deadline passes, and an empty round is not built', () async {
    final (tool, ledger, _) = freshPool();
    final clock = FakeClock();
    final published = <Transaction>[];
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 3, deadline: const Duration(minutes: 5)),
        tool: tool,
        ledger: ledger,
        publish: (tx) async => published.add(tx),
        clock: clock,
        rng: Random(4));
    await co.runIdleWork();
    expect(co.status.paddingStock, 3);

    // nothing pending: the deadline cannot fire and an explicit close builds nothing
    expect(await co.closeRound(), isNull);
    expect(published, isEmpty);

    final (t, f, _) = deposit(ledger, 25000, 50);
    expect(co.submit(t, funding: f), isNull);
    expect(co.status.pending, 1);
    expect(co.status.deadline, clock.now.add(const Duration(minutes: 5)));

    final sizeBefore = ledger.tree.size;
    clock.advance(const Duration(minutes: 5));
    final tx = await co.building;
    expect(tx, isNotNull);
    expect(published.length, 1);
    expect(published.single.id, tx!.id);
    expect(ledger.tree.size, sizeBefore + gen.leavesAppended, reason: 'the round appended a full plan of leaves');
    expect(ledger.vault, 2000 + 25000);
    expect(co.status.rounds, 1);
    expect(co.status.paddingStock, 0, reason: 'three of the four slots were filled from stock');
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 2.2

  test('intake stays open while a round is being built', () async {
    final (tool, ledger, _) = freshPool();
    final clock = FakeClock();
    final published = <Transaction>[];
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 6),
        tool: tool,
        ledger: ledger,
        publish: (tx) async => published.add(tx),
        clock: clock,
        rng: Random(5));
    await co.runIdleWork();

    final (a, fa, _) = deposit(ledger, 10000, 60);
    expect(co.submit(a, funding: fa), isNull);
    final first = co.closeRound();
    // the round is in flight; a transfer arriving now belongs to the next one
    final (b, fb, _) = deposit(ledger, 11000, 61);
    expect(co.submit(b, funding: fb), isNull);
    expect(co.status.pending, 1);
    expect(co.status.inFlight, 1);

    await first;
    expect(published.length, 1);
    expect(co.status.pending, 1, reason: 'the transfer submitted during building is still pending');
    expect(co.status.inFlight, 0);

    await co.closeRound();
    expect(published.length, 2);
    expect(co.status.pending, 0);
    expect(ledger.vault, 2000 + 10000 + 11000);
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 2.3

  test('level 1 goes through the configured prover pool, and a member that never answers costs only the timeout', () async {
    // the same transfer, the same fresh pool, proved twice: once entirely
    // here, once through a pool of one member that never answers and one
    // that does the work
    final (toolA, ledgerA, _) = freshPool();
    final (transfer, funding, _) = deposit(ledgerA, 15000, 70);
    final plan1Nodes = agg.transfers ~/ agg.levelSpec[0].arity;
    final roots = <String, List<int>>{};
    for (final which in ['local', 'pooled']) {
      final (tool, ledger) = which == 'local' ? (toolA, ledgerA) : () {
        final (t, l, _) = freshPool();
        return (t, l);
      }();
      final silent = _SilentProver();
      final provers = which == 'pooled' ? <NodeProver>[silent, _InProcessProver()] : <NodeProver>[];
      final co = PoolCoordinator(
          config: recursiveConfig(stock: 3, provers: provers, timeout: const Duration(milliseconds: 200)),
          tool: tool,
          ledger: ledger,
          publish: (_) async {},
          clock: FakeClock(),
          rng: Random(6));
      await co.runIdleWork();
      expect(co.submit(transfer, funding: funding), isNull);
      final sw = Stopwatch()..start();
      await co.closeRound();
      print('  $which round in ${sw.elapsedMilliseconds} ms');
      roots[which] = ledger.tree.root;
      expect(ledger.vault, 2000 + 15000);
      final pool = co.lastPool!;
      if (which == 'pooled') {
        expect(pool.pooledNodes, 1, reason: 'the member that answers took one node');
        expect(pool.localNodes, 1, reason: 'the silent member timed out and its node was proved here');
        expect(pool.outcomes.map((o) => o.fallback), contains('timeout'));
      } else {
        expect(pool.localNodes, plan1Nodes, reason: 'with no members every node is proved here');
        expect(pool.pooledNodes, 0);
      }
    }
    expect(roots['pooled'], roots['local'],
        reason: 'the levels are not zero-knowledge, so who proved a node does not change the round');
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 3.1

  test('idle work refills the stock and holds no preprocessed commitment', () async {
    final (tool, ledger, _) = freshPool();
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 4), tool: tool, ledger: ledger, publish: (_) async {}, clock: FakeClock(), rng: Random(7));
    await co.runIdleWork();
    expect(co.status.paddingStock, 4);

    final (t, f, _) = deposit(ledger, 9000, 80);
    expect(co.submit(t, funding: f), isNull);
    await co.closeRound();
    expect(co.status.paddingStock, 1, reason: 'the round took three padding transfers');
    expect(PreCommitment.cachedCount, greaterThan(0), reason: 'proving leaves commitments cached');

    await co.runIdleWork();
    expect(co.status.paddingStock, 4, reason: 'the stock is back at its level');
    expect(PreCommitment.cachedCount, 0, reason: 'an idle coordinator holds no preprocessed column set');
    // the roots survive, which is what the statement digests need
    expect(PreCommitment.root(agg.levels[0].air(List.filled(8, 0)), l1, p2).length, 8);
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 3.2

  test('a restart rebuilds the same ledger from the chain', () async {
    final (tool, ledger, genesisTx) = freshPool();
    final published = <Transaction>[];
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 9),
        tool: tool,
        ledger: ledger,
        publish: (tx) async => published.add(tx),
        clock: FakeClock(),
        rng: Random(8));
    await co.runIdleWork();
    for (int r = 0; r < 3; r++) {
      final (t, f, _) = deposit(ledger, 5000 + r, 90 + r);
      expect(co.submit(t, funding: f), isNull);
      await co.closeRound();
    }
    expect(published.length, 3);

    final restarted = PoolCoordinator.recover(gen, genesisTx, published, lastPublished: published.last);
    expect(restarted.header.bytes(), ledger.header.bytes());
    expect(restarted.vault, ledger.vault);
    expect(restarted.tree.root, ledger.tree.root);
    expect(restarted.nullifiers.root, ledger.nullifiers.root);

    // a coordinator that believes it left a different state behind refuses
    expect(() => PoolCoordinator.recover(gen, genesisTx, published.take(2), lastPublished: published.last),
        throwsA(isA<StateError>()));

    // and it runs on the rebuilt ledger
    final again = PoolCoordinator(
        config: recursiveConfig(), tool: ShieldedPoolTool(gen), ledger: restarted, publish: (_) async {}, clock: FakeClock());
    expect(again.status.vault, ledger.vault);
  }, timeout: const Timeout(Duration(minutes: 20)));

  // ---------------------------------------------------------------- 4.1

  test('the entry point starts against a pool described by a file', () async {
    final (tool, ledger, genesisTx) = freshPool();
    final published = <Transaction>[];
    final co = PoolCoordinator(
        config: recursiveConfig(stock: 3),
        tool: tool,
        ledger: ledger,
        publish: (tx) async => published.add(tx),
        clock: FakeClock(),
        rng: Random(11));
    await co.runIdleWork();
    final (t, f, _) = deposit(ledger, 12345, 100);
    expect(co.submit(t, funding: f), isNull);
    await co.closeRound();

    final dir = Directory.systemTemp.createTempSync('pool_coordinator_test');
    addTearDown(() => dir.deleteSync(recursive: true));
    Map<String, dynamic> pj(StarkParams p) => {
          'logTrace': p.logTrace,
          'logBlowup': p.logBlowup,
          'logExpand': p.logExpand,
          'logFinal': p.logFinal,
          'numQueries': p.numQueries,
          'grindBytes': p.grindBytes,
          'zkRandomizers': p.zkRandomizers,
        };
    File('${dir.path}/genesis.hex').writeAsStringSync(genesisTx.serialize());
    File('${dir.path}/round1.hex').writeAsStringSync(published.single.serialize());
    final config = File('${dir.path}/pool.json')
      ..writeAsStringSync(jsonEncode({
        'mode': 'recursive',
        'roundDeadlineSeconds': 600,
        'paddingStock': 2,
        'spend': pj(spendP),
        'levels': [
          {'logTrace': 15, 'arity': 2, 'params': pj(l1)},
          {'logTrace': 16, 'arity': 2, 'params': pj(l2)},
        ],
        'root': {'logTrace': 15, 'params': pj(rootP)},
        'genesis': 'genesis.hex',
        'rounds': ['round1.hex'],
      }));

    final r = Process.runSync('dart', ['run', 'bin/pool_coordinator.dart', config.path, '--check'],
        workingDirectory: Directory.current.path);
    final out = '${r.stdout}${r.stderr}';
    printOnFailure(out);
    expect(r.exitCode, 0, reason: out);
    expect(out, contains('pool aggregated, ${agg.transfers} transfers per round'));
    expect(out, contains('vault ${ledger.vault} sat'));
    expect(out, contains('tree ${ledger.tree.size} leaves'));
    expect(out, contains(ledger.tx.id));
    expect(out, contains('mode recursive'));
    expect(out, contains('--check: not serving'));

    // a configuration pointing at a history that does not lead to the state
    // it claims is refused rather than run on
    final broken = File('${dir.path}/broken.json')
      ..writeAsStringSync(jsonEncode({
        ...jsonDecode(config.readAsStringSync()) as Map<String, dynamic>,
        'rounds': ['genesis.hex'],
      }));
    final r2 = Process.runSync('dart', ['run', 'bin/pool_coordinator.dart', broken.path, '--check'],
        workingDirectory: Directory.current.path);
    expect(r2.exitCode, 65, reason: '${r2.stdout}${r2.stderr}');
    expect('${r2.stdout}', contains('could not be rebuilt'));
  }, timeout: const Timeout(Duration(minutes: 20)));
}

bool _sameLanes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// A member that never answers, so the pool falls back to proving here.
class _SilentProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) => Completer<StarkProof>().future;
}

/// A member on this machine that proves the job it is handed, as a remote
/// one would once there is a transport.
class _InProcessProver implements NodeProver {
  @override
  bool get verifies => false;
  @override
  Future<StarkProof> prove(NodeJob job) async {
    final received = NodeJob.decode(job.encode());
    final prog = received.compile();
    return LocalNodeProver(program: prog).proveNow(received);
  }
}
