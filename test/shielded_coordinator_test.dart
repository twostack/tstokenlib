import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart' show StarkProof;
import 'package:tstokenlib/src/recursion/prover_pool.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_protocol.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_coordinator.dart';

import 'pool_round_v_test.dart' show opKey, strangerKey, sigHashAll;
import 'pool_test_chain.dart';

/// The TSL1_SP coordinator on the test chain: what it accepts and in what
/// order it checks, how it closes and funds a round, that it applies,
/// stores and then publishes, what a failed round leaves behind, and how
/// it recovers.
void main() {
  late PoolTestChain c;
  late ShieldedPoolLayout layout;
  final signer = DefaultTransactionSigner(sigHashAll, opKey);
  final opPub = opKey.publicKey;
  final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);
  final rng = Random(41);
  List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));
  List<int> newId() => List.generate(16, (_) => rng.nextInt(256));

  setUpAll(() async {
    c = await PoolTestChain.build();
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
  });

  ShieldedLedger genesis() => ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
  ShieldedLedger atRound1() => genesis()..apply(c.r1, c.w1, c.y1.tx);

  /// Round 1's deposit transfer, backed by the covenant the test chain built.
  ShieldedTransfer deposit() {
    final d = c.f.transfers1[0];
    return ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: c.depositOutpoint);
  }

  ShieldedCoordinator make({
    ShieldedLedger? ledger,
    int stock = 0,
    Duration deadline = const Duration(minutes: 10),
    List<NodeProver> provers = const [],
    Duration timeout = const Duration(minutes: 5),
    _Funding? funding,
    _Store? store,
    _Log? log,
    ShieldedPoolTool? tool,
    int feeRate = 1,
    FakeClock? clock,
    List<PoolReply>? replies,
    TransactionSigner? owner,
    SVPublicKey? ownerPub,
  }) {
    final l = log ?? _Log();
    return ShieldedCoordinator(
      config: CoordinatorConfig(plan: c.f.agg, roundDeadline: deadline, paddingStock: stock, provers: provers, proverTimeout: timeout, feeRate: feeRate),
      tool: tool ?? c.svc,
      ledger: ledger ?? genesis(),
      funding: funding ?? _Funding(signer, opPub, opAddr),
      store: store ?? _Store(l),
      publish: (tx) async => l.events.add('publish ${tx.id}'),
      owner: owner ?? signer,
      ownerPub: ownerPub ?? opPub,
      clock: clock ?? FakeClock(),
      notify: (r) => replies?.add(r),
      rng: Random(7),
    );
  }

  PoolReply submit(ShieldedCoordinator co, ShieldedTransfer t, {Transaction? depositTx}) => co.intake(newId(), t, depositTx: depositTx);

  /// Closes a round of [transfers] on [co] and returns its announcement.
  Future<PoolAnnouncement> close(ShieldedCoordinator co, List<ShieldedTransfer> transfers, {Transaction? depositTx}) async {
    for (final t in transfers) {
      final r = submit(co, t, depositTx: t.depositOutpoint == null ? null : depositTx);
      expect(r.isAccepted, isTrue, reason: '$r');
    }
    final a = await (co.building ?? co.closeRound());
    expect(a, isNotNull, reason: '${co.lastFailure}');
    return a!;
  }

  ShieldedRoundTxs tripleOf(_Store s, int number) {
    final r = s.rounds.firstWhere((r) => r.number == number);
    return (round: r.round, witness: r.witness, nextSlot: r.y);
  }

  group('opening', () {
    test('a fresh pool: size 0, the genesis header, and the issuance, witness 0 and Y_0 as its tip', () {
      final co = ShieldedCoordinator.open(
          config: CoordinatorConfig(plan: c.f.agg),
          tool: c.svc,
          issuance: c.r0,
          witness0: c.w0,
          slot0: c.y0.tx,
          funding: _Funding(signer, opPub, opAddr),
          store: _Store(_Log()),
          publish: (_) async {},
          owner: signer,
          ownerPub: opPub,
          clock: FakeClock());
      expect(co.ledger.size, 0);
      expect(co.ledger.round, 0);
      expect(co.ledger.header.encode(), c.f.g.encode());
      expect(co.ledger.tipRound.id, c.r0.id);
      expect(co.ledger.tipWitness.id, c.w0.id);
      expect(co.ledger.tipSlot.id, c.y0.tx.id);
      expect(co.pending, 0);
      expect(co.capacity, 4);
      expect(co.verifierBody, c.f.body);
      expect(co.status.toString(), contains('pending 0/4'));
    });

    test('a key that does not own the pool is refused with both key hashes', () {
      expect(() => make(owner: DefaultTransactionSigner(sigHashAll, strangerKey), ownerPub: strangerKey.publicKey),
          throwsA(isA<StateError>().having((e) => e.message, 'message', contains('owned by'))));
    });
  });

  group('intake', () {
    test('a second transfer spending the same note is refused as a pending double spend', () {
      final co = make(ledger: atRound1());
      final t = c.f.transfers2[0];
      final first = submit(co, t);
      expect(first.isAccepted, isTrue, reason: '$first');
      expect(first.round, 2);
      final second = submit(co, t);
      expect(second.reason, RefusalReason.nullifierPending);
      expect(co.pending, 1);
    });

    test('a bad proof is refused after every cheaper check, and a cheap refusal costs no verification', () {
      final co = make(ledger: atRound1());
      final t = c.f.transfers2[0];
      final swapped = ShieldedTransfer(t.publics, c.f.transfers2[1].proof, t.bundle, withdrawal: t.withdrawal);
      final r = submit(co, swapped);
      expect(r.reason, RefusalReason.proof);
      expect(co.verifications, 1, reason: 'the proof was verified once, after the cheap checks passed');
      expect(co.pending, 0);
      // at genesis the anchor is not in the ring: refused before any verification
      final fresh = make();
      expect(submit(fresh, t).reason, RefusalReason.anchor);
      expect(fresh.verifications, 0);
      // a spent note: round 1's ledger with round 2 applied holds the nullifier
      final spent = make(ledger: atRound1()..apply(c.r2, c.w2, c.y2.tx));
      expect(submit(spent, t).reason, RefusalReason.nullifierSpent);
      expect(spent.verifications, 0);
    });

    test('a bundle naming commitments other than the proof\'s is refused before the proof is verified', () async {
      final keys = PoolWalletKeys(lanes(5));
      final a = await NoteAddress.at(keys.ivk, 0);
      NotePlaintext plain() => NotePlaintext(asset: PoolHash.bsvAsset, d: a.d, value: 0, rho: lanes(3), rcm: lanes(4));
      final n1 = plain(), n2 = plain(), m1 = plain(), m2 = plain();
      // the bundle carries m1 and m2; the proof commits to n1 and n2
      final bundle = [
        ...(await NoteEncryption.encrypt(m1, a, keys.ovk, rng: rng)).bytes,
        ...(await NoteEncryption.encrypt(m2, a, keys.ovk, rng: rng)).bytes,
      ];
      SpendNote dummy() => SpendNote.dummy(sk: lanes(5), rho: lanes(3));
      final w = PoolSpendAir.witness(dummy(), dummy(), n1.toOutputNote(a.pkd), n2.toOutputNote(a.pkd), 0,
          outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(bundle)), anchor: List.filled(8, 0));
      final proof = StarkProver.prove(c.f.agg.spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(1), hash: const Poseidon2ProofHash());
      final t = ShieldedTransfer(w.publics, proof, bundle);
      expect(t.verifyProof(c.f.agg.spendP), isNull, reason: 'the proof itself is fine');
      final co = make();
      final r = submit(co, t);
      expect(r.reason, RefusalReason.transfer);
      expect(r.sentence, contains('bundle'));
      expect(co.verifications, 0);
    });

    test('the fixture\'s deposit is accepted with its covenant, and the round carries the receipt at output 5 and the covenant at input 5',
        () async {
      final co = make();
      final r = submit(co, deposit(), depositTx: c.depositTx);
      expect(r.isAccepted, isTrue, reason: '$r');
      expect(r.round, 1);
      final a = await close(co, c.f.transfers1.sublist(1));
      expect(a.round, 1);
      final round = co.ledger.tipRound;
      expect(round.outputs[5].script.buffer, c.f.receipt.lockingScript.buffer);
      expect(round.inputs[5].prevTxnId, c.depositTx.id);
      expect(round.inputs[5].prevTxnOutputIndex, ShieldedPoolTool.depositVout);
      expect(round.outputs[3].satoshis, BigInt.from(501));
      // the same covenant names PP3_0, which round 1 spent
      final again = submit(co, deposit(), depositTx: c.depositTx);
      expect(again.reason, RefusalReason.depositTarget);
      expect(again.sentence, contains('live PP3'));
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a covenant whose commitment is not the transfer\'s, one without its transaction, and one refundable too soon are refused', () {
      final co = make();
      final depositor = strangerKey.publicKey.toAddress(NetworkType.TEST);
      final coins = Transaction()
        ..addInputs([TransactionInput(hex.encode(List.filled(32, 0x31)), 0, 0xffffffff)])
        ..addOutputs([TransactionOutput(BigInt.from(10000), P2PKHLockBuilder.fromAddress(depositor).getScriptPubkey())]);
      Transaction covenant({List<int>? commitment, int refundAfter = 1000}) => c.svc.createDepositTxn(
          fundingTx: coins,
          fundingVout: 0,
          fundingSigner: DefaultTransactionSigner(0x41, strangerKey),
          fundingPubKey: strangerKey.publicKey,
          changeAddress: depositor,
          commitment: commitment ?? c.f.receipt.commitment,
          satoshis: c.f.receipt.satoshis,
          pp3Outpoint: c.svc.getOutpoint(c.r0.hash, outputIndex: 3),
          refundPKH: hex.decode(depositor.pubkeyHash160),
          refundAfter: refundAfter);
      final d = c.f.transfers1[0];
      ShieldedTransfer backing(Transaction tx) =>
          ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: c.svc.getOutpoint(tx.hash, outputIndex: ShieldedPoolTool.depositVout));

      final other = covenant(commitment: List.filled(32, 5));
      final r = submit(co, backing(other), depositTx: other);
      expect(r.reason, RefusalReason.depositCovenant);
      expect(r.sentence, contains('not the transfer\'s receipt'));

      expect(submit(co, deposit()).reason, RefusalReason.depositMissing);
      expect(submit(co, c.f.transfers1[1], depositTx: c.depositTx).reason, RefusalReason.depositMissing);

      final soon = covenant(refundAfter: 1000);
      co.chainHeight = 950;
      final late = submit(co, backing(soon), depositTx: soon);
      expect(late.reason, RefusalReason.depositCovenant);
      expect(late.sentence, contains('refundable'));
      co.chainHeight = 0;

      // a covenant for another pool's PP3 is named as such
      final elsewhere = c.svc.createDepositTxn(
          fundingTx: coins,
          fundingVout: 0,
          fundingSigner: DefaultTransactionSigner(0x41, strangerKey),
          fundingPubKey: strangerKey.publicKey,
          changeAddress: depositor,
          commitment: c.f.receipt.commitment,
          satoshis: c.f.receipt.satoshis,
          pp3Outpoint: List.filled(36, 9),
          refundPKH: hex.decode(depositor.pubkeyHash160),
          refundAfter: 1000);
      expect(submit(co, backing(elsewhere), depositTx: elsewhere).reason, RefusalReason.depositTarget);
      expect(co.pending, 0);
      expect(co.verifications, 0, reason: 'no deposit refusal cost a verification');
    });

    test('a withdrawal beyond the balance is refused', () {
      final co = make(ledger: atRound1());
      final t = c.f.transfers2[0];
      // the balance after round 1 is 501; the fixture withdraws 300, so a
      // second 300 would overdraw it
      expect(submit(co, t).isAccepted, isTrue);
      final other = ShieldedTransfer(t.publics, t.proof, t.bundle, withdrawal: t.withdrawal);
      // the same note again is a pending double spend, which comes first
      expect(submit(co, other).reason, RefusalReason.nullifierPending);
      expect(co.status.balance, BigInt.from(501));
    });
  });

  group('rounds', () {
    test('a round from the test chain\'s transfers, then round 2: a reader reaches headers 1 and 2', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(store: store, log: log);
      final a1 = await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      expect(a1.round, 1);
      expect(a1.header.encode(), c.f.h1.encode());
      expect(co.ledger.header.encode(), c.f.h1.encode());
      final a2 = await close(co, c.f.transfers2);
      expect(a2.round, 2);
      expect(a2.header.encode(), c.f.h2.encode());
      expect(co.ledger.header.balance, BigInt.from(201));

      final reader = ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      reader.read([tripleOf(store, 1), tripleOf(store, 2)]);
      expect(reader.stopped, isFalse, reason: '${reader.refusal}');
      expect(reader.ledger.header.encode(), c.f.h2.encode());
      expect(reader.ledger.snapshot(), co.ledger.snapshot(), reason: 'the reader and the coordinator hold the same ledger');
      expect(a2.disagreement(reader.rounds[1]), isNull);
      expect(co.announcements.length, 2);
      expect(co.lastPool!.localNodes, 2, reason: 'two level-1 nodes at arity 2, both proved here');
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the deadline closes a short round, padded to the plan\'s size, and padding leaves are the padding note\'s', () async {
      final clock = FakeClock();
      final log = _Log();
      final store = _Store(log);
      final co = make(clock: clock, deadline: const Duration(minutes: 3), store: store, log: log);
      expect(submit(co, deposit(), depositTx: c.depositTx).isAccepted, isTrue);
      expect(co.status.deadline, clock.now.add(const Duration(minutes: 3)));
      clock.advance(const Duration(minutes: 2));
      expect(co.building, isNull, reason: 'not due yet');
      clock.advance(const Duration(minutes: 1));
      expect(co.building, isNotNull, reason: 'the deadline closed the round');
      final a = await co.building!;
      expect(a, isNotNull, reason: '${co.lastFailure}');
      expect(a!.round, 1);
      final reader = ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      final applied = reader.read([tripleOf(store, 1)]).single;
      expect(applied.padding, [false, true, true, true]);
      for (int t = 1; t < 4; t++) {
        for (final pos in [applied.positions[t].$1, applied.positions[t].$2]) {
          expect(reader.ledger.tree.nodeAt(0, pos), ShieldedTransfer.paddingCm);
        }
      }
      expect(reader.ledger.header.encode(), a.header.encode());
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a transfer whose anchor four later rounds rotated out is dropped at close with an expired reply', () async {
      final ledger = atRound1();
      final replies = <PoolReply>[];
      final logA = _Log();
      final a = make(ledger: ledger, log: logA, replies: replies);
      final id = newId();
      expect(a.intake(id, c.f.transfers2[0]).isAccepted, isTrue);
      // another coordinator on the same ledger publishes four padding rounds
      final b = make(ledger: ledger);
      for (int n = 0; n < 4; n++) {
        await close(b, [for (int i = 0; i < 4; i++) ShieldedTransfer.padding(c.f.agg.spendP, rng: rng)]);
      }
      expect(ledger.round, 5);
      expect(ledger.roundsLeftInRing(c.f.h1.cmRoot), 0);
      expect(await a.closeRound(), isNull, reason: 'nothing left to build');
      expect(replies.single.outcome, ReplyOutcome.expired);
      expect(replies.single.id, id);
      expect(replies.single.sentence, contains('anchor'));
      expect(a.pending, 0);
      expect(logA.events, isEmpty, reason: 'nothing was published');
      expect(a.lastFailure, isNull);
    }, timeout: const Timeout(Duration(minutes: 10)));

    test('stock consumed: three padding needed, two in stock, one proved on the spot; refilled while idle', () async {
      final clock = FakeClock();
      final co = make(clock: clock, stock: 2, deadline: const Duration(minutes: 1));
      await co.runIdleWork();
      expect(co.padding.stock, 2);
      expect(submit(co, deposit(), depositTx: c.depositTx).isAccepted, isTrue);
      clock.advance(const Duration(minutes: 1));
      expect(await co.building!, isNotNull, reason: '${co.lastFailure}');
      expect(co.padding.stock, 0);
      expect(co.ledger.round, 1);
      await co.runIdleWork();
      expect(co.padding.stock, 2, reason: 'the stock is back at its configured level');
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('nothing is held while idle: no preprocessed column set, the level roots still known', () async {
      final co = make();
      await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      expect(PreCommitment.cachedCount, greaterThan(0), reason: 'proving leaves commitments cached');
      await co.runIdleWork();
      expect(PreCommitment.cachedCount, 0);
      expect(c.f.agg.preRoots.length, 2);
      expect(c.f.agg.preRoots.every((r) => r.length == 8), isTrue);
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('level 1 goes through the prover pool: an empty pool proves here, a silent member costs only the timeout', () async {
      final roots = <String, List<int>>{};
      for (final which in ['local', 'pooled']) {
        final provers = which == 'pooled' ? <NodeProver>[_SilentProver(), _InProcessProver()] : <NodeProver>[];
        final co = make(provers: provers, timeout: const Duration(milliseconds: 200));
        final sw = Stopwatch()..start();
        await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
        print('  $which round in ${sw.elapsedMilliseconds} ms');
        roots[which] = co.ledger.tree.root;
        final pool = co.lastPool!;
        if (which == 'pooled') {
          expect(pool.pooledNodes, 1, reason: 'the member that answers took one node');
          expect(pool.localNodes, 1, reason: 'the silent member timed out and its node was proved here');
          expect(pool.outcomes.map((o) => o.fallback), contains('timeout'));
        } else {
          expect(pool.localNodes, 2);
          expect(pool.pooledNodes, 0);
        }
      }
      expect(roots['pooled'], roots['local']);
    }, timeout: const Timeout(Duration(minutes: 10)));
  });

  group('funding and fees', () {
    test('each transaction pays at least its size times the rate, and at least the floor', () async {
      final funding = _Funding(signer, opPub, opAddr);
      final log = _Log();
      final store = _Store(log);
      final co = make(funding: funding, store: store, log: log, feeRate: 1000);
      await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      expect(funding.asked.length, 3, reason: 'one output for Y, one for the witness, one for the round');
      final r = store.rounds.single;
      final known = {for (final t in [c.r0, c.w0, c.y0.tx, c.depositTx, r.y, r.round, ...funding.given]) t.id: t};
      for (final (name, tx) in [('Y', r.y), ('round', r.round), ('witness', r.witness)]) {
        final size = hex.decode(tx.serialize()).length;
        final fee = _feeOf(tx, known);
        print('  $name $size B pays $fee sat');
        expect(fee, greaterThanOrEqualTo(BigInt.from(size)), reason: '$name pays at least 1 sat/B');
        expect(fee, greaterThanOrEqualTo(BigInt.from(135)), reason: '$name pays at least the floor');
        expect(fee, lessThan(BigInt.from(size + 200)), reason: '$name pays no more than its size and the margin');
      }
      // at 1 sat/kB Y is priced from its size (414 sat for 413 KB), which
      // is above the floor; the floor is what a transaction under 135 KB
      // would pay
      final low = _Funding(signer, opPub, opAddr);
      final lowStore = _Store(_Log());
      final co2 = make(funding: low, store: lowStore, ledger: genesis());
      await close(co2, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      final ySize = hex.decode(lowStore.rounds.single.y.serialize()).length;
      expect(low.asked[0], BigInt.from((ySize + 999) ~/ 1000 + 2), reason: 'Y at 1 sat/kB, plus its two satoshi outputs');
      expect(low.asked[0], greaterThan(BigInt.from(135 + 2)));
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('no funding: the round is refused before aggregation and the transfers stay pending', () async {
      final funding = _Funding(signer, opPub, opAddr)..dead = true;
      final log = _Log();
      final co = make(funding: funding, log: log);
      for (final t in [deposit(), ...c.f.transfers1.sublist(1)]) {
        expect(submit(co, t, depositTx: t.depositOutpoint == null ? null : c.depositTx).isAccepted, isTrue);
      }
      expect(await co.building!, isNull);
      expect(co.lastFailure!.stage, 'funding');
      expect(co.lastPool, isNull, reason: 'nothing was proved');
      expect(co.pending, 4);
      expect(co.ledger.round, 0);
      expect(log.events, isEmpty);
      // with funding back, the pending round closes
      funding.dead = false;
      expect(await co.closeRound(), isNotNull, reason: '${co.lastFailure}');
      expect(co.lastFailure, isNull);
      expect(co.ledger.round, 1);
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('funding fails at close, after proving: nothing published, the ledger unchanged, the transfers pending again', () async {
      final funding = _Funding(signer, opPub, opAddr)..failAt = 1;
      final log = _Log();
      final co = make(funding: funding, log: log);
      final before = co.ledger.snapshot();
      for (final t in [deposit(), ...c.f.transfers1.sublist(1)]) {
        expect(submit(co, t, depositTx: t.depositOutpoint == null ? null : c.depositTx).isAccepted, isTrue);
      }
      expect(await co.building!, isNull);
      expect(co.lastFailure!.stage, 'funding');
      expect(co.lastPool, isNotNull, reason: 'the round was proved before the witness was funded');
      expect(co.ledger.snapshot(), before);
      expect(co.pending, 4);
      expect(log.events, isEmpty);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('apply, store, publish', () {
    test('a round the ledger refuses is not published, and the ledger is unchanged', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(tool: _SwappingTool(), store: store, log: log);
      final before = co.ledger.snapshot();
      for (final t in [deposit(), ...c.f.transfers1.sublist(1)]) {
        expect(submit(co, t, depositTx: t.depositOutpoint == null ? null : c.depositTx).isAccepted, isTrue);
      }
      expect(await co.building!, isNull);
      expect(co.lastFailure!.stage, 'apply');
      expect(co.lastFailure!.reason, contains('outHash'));
      expect(co.ledger.snapshot(), before);
      expect(store.rounds, isEmpty);
      expect(log.events, isEmpty);
      expect(co.pending, 4, reason: 'the transfers are pending again');
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the store receives Y, the round and the witness before the first publish, and publishes come Y, round, witness', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(store: store, log: log);
      final a = await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      final r = store.rounds.single;
      expect(log.events, ['store 1', 'publish ${r.y.id}', 'publish ${r.round.id}', 'publish ${r.witness.id}']);
      expect(a.slotId, r.y.id);
      expect(a.roundId, r.round.id);
      expect(a.witnessId, r.witness.id);
      expect(r.snapshot, co.ledger.snapshot(), reason: 'the snapshot is the ledger after the round');
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('restart and recovery', () {
    test('a restart loses the pending round and nothing else, and resubmitting is accepted', () async {
      final ledger = atRound1();
      final co = make(ledger: ledger);
      expect(submit(co, c.f.transfers2[0]).isAccepted, isTrue);
      expect(submit(co, c.f.transfers2[1]).isAccepted, isTrue);
      expect(co.pending, 2);
      final again = make(ledger: ledger);
      expect(again.pending, 0);
      expect(again.ledger.round, 1);
      expect(again.ledger.header.encode(), c.f.h1.encode());
      expect(submit(again, c.f.transfers2[0]).isAccepted, isTrue);
      expect(submit(again, c.f.transfers2[1]).isAccepted, isTrue);
    });

    test('restart mid-history: a snapshot after round 1 plus round 2 gives the ledger the coordinator had', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(store: store, log: log);
      await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      await close(co, c.f.transfers2);
      final recovered = ShieldedCoordinator.recover(layout,
          snapshot: store.rounds[0].snapshot, triples: [tripleOf(store, 2)], lastRound: 2);
      expect(recovered.round, 2);
      expect(recovered.header.encode(), co.ledger.header.encode());
      expect(recovered.snapshot(), co.ledger.snapshot());
      // and from genesis, with both rounds
      final fromGenesis = ShieldedCoordinator.recover(layout,
          issuance: c.r0, witness0: c.w0, slot0: c.y0.tx, triples: [tripleOf(store, 1), tripleOf(store, 2)], lastRound: 2);
      expect(fromGenesis.snapshot(), co.ledger.snapshot());
      // the recovered ledger runs: round 2's note is spent there
      final back = make(ledger: recovered);
      expect(submit(back, c.f.transfers2[0]).reason, RefusalReason.nullifierSpent);

      // the chain disagrees with the snapshot: round 1's triple again
      expect(
          () => ShieldedCoordinator.recover(layout, snapshot: store.rounds[0].snapshot, triples: [tripleOf(store, 1)]),
          throwsA(isA<RecoveryRefusal>()
              .having((e) => e.reason, 'reason', contains(store.rounds[0].round.id))
              .having((e) => e.reason, 'reason', contains(store.rounds[0].round.id))
              .having((e) => e.reason, 'reason', contains('round 2'))));
      // the chain ends before the store's last round
      expect(() => ShieldedCoordinator.recover(layout, snapshot: store.rounds[0].snapshot, triples: const [], lastRound: 2),
          throwsA(isA<RecoveryRefusal>().having((e) => e.reason, 'reason', contains('ends at round 1'))));
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('a tree built under another plan is refused, naming both counts', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(store: store, log: log);
      await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      final snapshot = store.rounds[0].snapshot;

      // the same snapshot under a plan that appends 128 leaves a round:
      // round 1 should then hold 128 rows and this tree holds 32
      final other = ShieldedPoolLayout.forArities([16, 4], nullifierLevel: 1, receiptSlots: 2);
      expect(other.tree.leavesAppended, 128);
      expect(
          () => ShieldedCoordinator.recover(other, snapshot: snapshot, triples: const []),
          throwsA(isA<RecoveryRefusal>()
              .having((e) => e.reason, 'reason', contains('128 leaves a round'))
              .having((e) => e.reason, 'reason', contains('this one holds 32'))));

      // and a snapshot whose round number does not match its tree: the
      // restore rebuilds the roots and is satisfied, the block count is not
      final edited = Uint8List.fromList(snapshot)..[1 + PoolHeader.byteSize] = 2;
      expect(
          () => ShieldedCoordinator.recover(layout, snapshot: edited, triples: const []),
          throwsA(isA<RecoveryRefusal>()
              .having((e) => e.reason, 'reason', contains('at round 2 the tree should hold 64 rows'))
              .having((e) => e.reason, 'reason', contains('this one holds 32'))));

      // the coordinator will not open on it either
      final off = ShieldedLedger.restore(layout, edited);
      expect(off.round, 2);
      expect(off.size, 32);
      expect(
          () => make(ledger: off),
          throwsA(isA<StateError>()
              .having((e) => e.message, 'message', contains('32 leaves a round'))
              .having((e) => e.message, 'message', contains('this one holds 32'))));
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('the announcement of round 1 carries the number, the header and three txids, and nothing else', () async {
      final log = _Log();
      final store = _Store(log);
      final co = make(store: store, log: log);
      final a = await close(co, [deposit(), ...c.f.transfers1.sublist(1)], depositTx: c.depositTx);
      final bytes = a.encode();
      expect(bytes.length, 2 + 4 + 236 + 96 + 32);
      expect(bytes.length, lessThan(PoolMessage.maxOther));
      final back = PoolAnnouncement.decode(bytes);
      expect(back.round, 1);
      expect(back.header.encode(), c.f.h1.encode());
      expect(back.roundId, store.rounds.single.round.id);
      expect(back.witnessId, store.rounds.single.witness.id);
      expect(back.slotId, store.rounds.single.y.id);
      // nothing in it is a transfer's, a submission's or a wallet's
      expect(_contains(bytes, c.f.receipt.commitment), isFalse);
      expect(_contains(bytes, SlotScript.lanesBytes(c.f.transfers1[0].publics.cmOut1)), isFalse);
      expect(_contains(bytes, c.depositOutpoint.sublist(0, 32)), isFalse);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('untrusted submissions', () {
    test('1,000 single-byte mutations of a valid submission each end accepted, refused or dropped; the ledger is untouched', () {
      final co = make(ledger: atRound1());
      final before = co.ledger.snapshot();
      final valid = PoolSubmission.of(c.f.transfers2[0], c.f.agg.spendP, rng: rng).encode();
      var accepted = 0, refused = 0, dropped = 0;
      final reasons = <RefusalReason, int>{};
      for (int i = 0; i < 1000; i++) {
        final at = rng.nextInt(valid.length);
        final mutated = Uint8List.fromList(valid)..[at] = (valid[at] + 1 + rng.nextInt(255)) & 0xff;
        final r = co.submitBytes(mutated);
        if (r == null) {
          dropped++;
        } else if (r.isAccepted) {
          accepted++;
        } else {
          refused++;
          reasons[r.reason!] = (reasons[r.reason!] ?? 0) + 1;
        }
      }
      print('  accepted $accepted, refused $refused $reasons, dropped $dropped');
      expect(accepted + refused + dropped, 1000);
      expect(co.pending, accepted, reason: 'the pending round holds only the accepted ones');
      expect(accepted, lessThanOrEqualTo(1), reason: 'the same note twice is a pending double spend');
      expect(co.ledger.snapshot(), before);
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}

/// A funding source that mints a P2PKH output of exactly the value asked,
/// paid to the coordinator's key, as a wallet would.
class _Funding implements CoordinatorFunding {
  final TransactionSigner signer;
  final SVPublicKey pubKey;
  final Address to;
  final List<BigInt> asked = [];
  final List<Transaction> given = [];
  bool dead = false;
  int? failAt;
  _Funding(this.signer, this.pubKey, this.to);

  @override
  Future<FundingOutput?> output(BigInt minValue) async {
    final n = asked.length;
    asked.add(minValue);
    if (dead || failAt == n) return null;
    final prev = List.filled(32, 0x50)..[0] = n & 0xff..[1] = n >> 8;
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0
      ..addInput(TransactionInput(hex.encode(prev), 0, TransactionInput.MAX_SEQ_NUMBER))
      ..addOutput(TransactionOutput(minValue, P2PKHLockBuilder.fromAddress(to).getScriptPubkey()));
    given.add(tx);
    return FundingOutput(tx, 0, signer, pubKey);
  }
}

class _Log {
  final events = <String>[];
}

class _Store implements CoordinatorStore {
  final _Log log;
  final rounds = <({int number, Transaction y, Transaction round, Transaction witness, Uint8List snapshot})>[];
  _Store(this.log);

  @override
  Future<void> roundBuilt(int number, Transaction y, Transaction round, Transaction witness, Uint8List snapshot) async {
    log.events.add('store $number');
    rounds.add((number: number, y: y, round: round, witness: witness, snapshot: snapshot));
  }
}

/// A tool whose witness carries the round's bundles in the wrong order,
/// so the round it builds does not hash to its own outHash and the
/// coordinator's ledger refuses it.
class _SwappingTool extends ShieldedPoolTool {
  @override
  Transaction createWitnessTxn(TransactionSigner signer, Transaction fundingTx, Transaction tokenTx, List<int> parentTokenTxBytes,
      SVPublicKey ownerPubkey, String tokenChangePKH, ShieldedPoolAction action,
      {int fundingVout = 1,
      List<int>? newOwnerPKH,
      List<int>? newHeader,
      List<int>? nextSlot,
      List<int>? slotParts,
      List<int>? verifierBody,
      List<int>? bundles,
      List<PoolWithdrawal>? withdrawals,
      List<PoolReceipt>? receipts,
      int? nLockTime,
      int pp1OutputIndex = 1,
      int pp2OutputIndex = 2,
      TransactionSigner? fundingSigner,
      SVPublicKey? fundingPubKey}) {
    final swapped = bundles == null ? null : PoolOutHash.encodeBundles(PoolOutHash.decodeBundles(bundles).reversed.toList());
    return super.createWitnessTxn(signer, fundingTx, tokenTx, parentTokenTxBytes, ownerPubkey, tokenChangePKH, action,
        fundingVout: fundingVout,
        newOwnerPKH: newOwnerPKH,
        newHeader: newHeader,
        nextSlot: nextSlot,
        slotParts: slotParts,
        verifierBody: verifierBody,
        bundles: swapped,
        withdrawals: withdrawals,
        receipts: receipts,
        nLockTime: nLockTime,
        pp1OutputIndex: pp1OutputIndex,
        pp2OutputIndex: pp2OutputIndex,
        fundingSigner: fundingSigner,
        fundingPubKey: fundingPubKey);
  }
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
    return LocalNodeProver(program: received.compile()).proveNow(received);
  }
}

/// [tx]'s fee: what its inputs hold in [known] less what its outputs pay.
BigInt _feeOf(Transaction tx, Map<String, Transaction> known) {
  var fee = BigInt.zero;
  for (final i in tx.inputs) {
    final parent = known[i.prevTxnId];
    if (parent == null) throw StateError('${tx.id} spends ${i.prevTxnId}:${i.prevTxnOutputIndex}, which is not known');
    fee += parent.outputs[i.prevTxnOutputIndex].satoshis;
  }
  for (final o in tx.outputs) {
    fee -= o.satoshis;
  }
  return fee;
}

bool _contains(List<int> hay, List<int> needle) {
  outer:
  for (int i = 0; i + needle.length <= hay.length; i++) {
    for (int j = 0; j < needle.length; j++) {
      if (hay[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
