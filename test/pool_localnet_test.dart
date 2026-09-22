@Tags(['localnet'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_protocol.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_coordinator.dart';
import 'pool_chain_fixture.dart';

/// The pool's first two rounds, as `pool_round_v_test` builds them, mined on
/// the regtest node of ../localnet instead of checked by dartsv alone. Every
/// transaction spends real outputs, pays a fee priced from its size, goes
/// in through ARC with ARC's script validation on, and is mined before the
/// next one is built. A transaction the node refuses fails the run with the
/// node's reason.
///
/// Off unless POOL_LOCALNET is set, since it needs the localnet stack up:
///
///   POOL_LOCALNET=1 dart test test/pool_localnet_test.dart
///
/// POOL_BROADCAST=rpc sends through the node's sendrawtransaction instead
/// of ARC, which says whether a refusal is ARC's or the node's. Production
/// needs it: localnet's ARC (v1.5.10) cannot parse a scriptSig over
/// 1,636,802 bytes in its P2P handler, and every production witness's PP1
/// unlock is larger (W0 1.87 MB), so ARC never sees the node accept it and
/// answers ANNOUNCED_TO_NETWORK. Measured 2026-09-21.
/// POOL_PRODUCTION=1 proves the 256-transfer production plan instead of
/// the 4-transfer test plan (V about 1.8 MB, witnesses about 3.6 MB; set
/// STARK_KERNELS_GPU=1 to prove on the GPU).
/// POOL_PROOF_CACHE names a file the proofs are kept in: read if it exists,
/// written if not. Production proving takes about 13 minutes, the chain
/// under a minute, so a run that fails on the node need not prove again.
/// POOL_FEE_RATE is satoshis per kB, default 1 (the node's minminingtxfee).
/// POOL_CHAIN_DUMP writes the mined chain as JSON, for
/// tool/scratch/two_round_probe.dart.
/// POOL_COORDINATOR=1 runs the second test instead: the coordinator, with a
/// node-backed funding source and the node as its publisher, takes the
/// fixture's transfers and the deposit and mines both rounds itself. Its
/// transfers are kept in POOL_PROOF_CACHE.transfers.json, since only the
/// spend proofs are needed and the coordinator aggregates.
final opKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
final strangerKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

final env = Platform.environment;
final feeRate = int.parse(env['POOL_FEE_RATE'] ?? '1');

void main() {
  test('two pool rounds, a deposit in and a withdrawal out, mined on localnet', () async {
    final net = Localnet(viaRpc: env['POOL_BROADCAST'] == 'rpc');
    final svc = ShieldedPoolTool();
    final signer = DefaultTransactionSigner(sigHashAll, opKey);
    final opPub = opKey.publicKey;
    final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);
    final opPKH = hex.decode(opAddr.pubkeyHash160);
    final stranger = strangerKey.publicKey.toAddress(NetworkType.TEST);

    await net.ready();
    final production = env['POOL_PRODUCTION'] == '1';
    final f = await _Proved.load(env['POOL_PROOF_CACHE'], production,
        () => PoolChainFixture.prove(
            withdrawalPKH: hex.decode(stranger.pubkeyHash160), production: production, verbose: production));
    final body = f.body;

    // ---- coins: one output from the node's wallet, split into one output
    // per transaction that needs its own. Y and every witness have no change
    // output, so whatever funds them beyond their dust is fee; they get
    // outputs sized to that. The issuance must spend output 1 of its funding
    // transaction, and the builder puts change at 0, so the issuance's
    // output is the first one added.
    final coins = await net.fund(opAddr, BigInt.from(100000000));
    final coinsVout = coins.outputs.indexWhere((o) => _pays(o, opPKH));
    final ySats = BigInt.from(((body.length + 1000) * feeRate + 999) ~/ 1000 + 2);
    // a witness carries V's body, its round and the round's bundles
    final wSats = BigInt.from(((3 * body.length + 1000000) * feeRate + 999) ~/ 1000 + 1);
    final roundSats = BigInt.from(1000000);
    const iIssue = 1, iW0 = 2, iY0 = 3, iY1 = 4, iY2 = 5, iR1 = 6, iW1 = 7, iR2 = 8, iW2 = 9, iDep = 10;
    final split = (TransactionBuilder()
          ..spendFromTxnWithSigner(signer, coins, coinsVout, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(opPub))
          ..spendToPKH(opAddr, roundSats) // 1: issuance
          ..spendToPKH(opAddr, wSats) // 2: witness 0
          ..spendToPKH(opAddr, ySats) // 3: Y0
          ..spendToPKH(opAddr, ySats) // 4: Y1
          ..spendToPKH(opAddr, ySats) // 5: Y2
          ..spendToPKH(opAddr, roundSats) // 6: round 1
          ..spendToPKH(opAddr, wSats) // 7: witness 1
          ..spendToPKH(opAddr, roundSats) // 8: round 2
          ..spendToPKH(opAddr, wSats) // 9: witness 2
          ..spendToPKH(stranger, BigInt.from(100000)) // 10: the depositor's coins
          ..sendChangeToPKH(opAddr)
          ..withFeePerKb(feeRate * 10))
        .build(false);
    expect(split.outputs[iIssue].satoshis, roundSats, reason: 'change went somewhere other than output 0');
    expect(split.outputs[iDep].satoshis, BigInt.from(100000));
    await net.submit('split', split);

    Future<({Transaction tx, List<int> outpoint, List<int> parts})> slot(String name, PoolHeader h, int vout) async {
      final y = svc.buildSlotTxn(header: h, verifierBody: body,
          fundingTx: split, fundingVout: vout, fundingSigner: signer, fundingPubKey: opPub,
          anchorPKH: opPKH, signerPKH: opPKH);
      await net.submit(name, y.tx);
      return y;
    }

    // ---- genesis: Y0, then the issuance spending its anchor, then witness 0
    final y0 = await slot('Y0', f.g, iY0);
    final r0 = svc.createTokenIssuanceTxn(split, signer, opPub, opAddr, crypto.sha256.convert(body).bytes, f.g,
        y0.outpoint, split.hash,
        slotTx: y0.tx, witnessFundingVout: iW0);
    await net.submit('R0', r0);
    final w0 = svc.createWitnessTxn(signer, split, r0, hex.decode(split.serialize()), opPub, opAddr.pubkeyHash160,
        ShieldedPoolAction.CREATE,
        fundingVout: iW0, slotParts: y0.parts, verifierBody: body);
    await net.submit('W0', w0);

    // ---- the depositor pays into a covenant naming PP3_0, refundable well
    // after round 1 will have been mined
    final pp3Of0 = svc.getOutpoint(r0.hash, outputIndex: 3);
    final refundAfter = await net.height() + 100;
    final depositTx = svc.createDepositTxn(
        fundingTx: split,
        fundingVout: iDep,
        fundingSigner: DefaultTransactionSigner(sigHashAll, strangerKey),
        fundingPubKey: strangerKey.publicKey,
        changeAddress: stranger,
        commitment: f.receipt.commitment,
        satoshis: f.receipt.satoshis,
        pp3Outpoint: pp3Of0,
        refundPKH: hex.decode(stranger.pubkeyHash160),
        refundAfter: refundAfter);
    await net.submit('D', depositTx);
    final found = ShieldedPoolTool.findDeposits([depositTx], pp3Of0, minRefundAfter: refundAfter);
    expect(found.length, 1);

    // ---- round 1 takes the deposit in
    final y1 = await slot('Y1', f.h1, iY1);
    Transaction round1({BigInt? fee}) => svc.createRoundTxn(w0, r0, y0.tx, opPub, split, signer, opPub, split.hash, f.h1,
        y1.outpoint,
        fundingVout: iR1,
        witnessFundingVout: iW1,
        nextSlotTx: y1.tx,
        receipts: [found[0].receipt],
        deposits: [(found[0].tx, found[0].vout)],
        roundProof: f.proof,
        fee: fee);
    final r1 = _priced(round1);
    expect(r1.outputs[3].satoshis, BigInt.from(501));
    await net.submit('R1', r1);
    final w1 = svc.createWitnessTxn(signer, split, r1, hex.decode(r0.serialize()), opPub, opAddr.pubkeyHash160,
        ShieldedPoolAction.ROUND,
        fundingVout: iW1,
        newOwnerPKH: opPKH,
        newHeader: f.h1.encode(),
        nextSlot: y1.outpoint,
        slotParts: y1.parts,
        verifierBody: body,
        bundles: f.bundles,
        receipts: [found[0].receipt]);
    await net.submit('W1', w1);

    // ---- round 2 spends the deposited note and withdraws 300
    final y2 = await slot('Y2', f.h2, iY2);
    Transaction round2({BigInt? fee}) => svc.createRoundTxn(w1, r1, y1.tx, opPub, split, signer, opPub, split.hash, f.h2,
        y2.outpoint,
        fundingVout: iR2,
        witnessFundingVout: iW2,
        nextSlotTx: y2.tx,
        withdrawals: [f.withdrawal],
        roundProof: f.proof2,
        fee: fee);
    final r2 = _priced(round2);
    expect(r2.outputs[3].satoshis, BigInt.from(201));
    await net.submit('R2', r2);
    final w2 = svc.createWitnessTxn(signer, split, r2, hex.decode(r1.serialize()), opPub, opAddr.pubkeyHash160,
        ShieldedPoolAction.ROUND,
        fundingVout: iW2,
        newOwnerPKH: opPKH,
        newHeader: f.h2.encode(),
        nextSlot: y2.outpoint,
        slotParts: y2.parts,
        verifierBody: body,
        bundles: f.bundles2,
        withdrawals: [f.withdrawal]);
    await net.submit('W2', w2);

    // ---- the withdrawal is a plain P2PKH the payee can spend
    final paid = r2.outputs.indexWhere((o) => _pays(o, hex.decode(stranger.pubkeyHash160)));
    expect(r2.outputs[paid].satoshis, BigInt.from(300));
    final spendPaid = (TransactionBuilder()
          ..spendFromTxnWithSigner(DefaultTransactionSigner(sigHashAll, strangerKey), r2, paid,
              TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(strangerKey.publicKey))
          ..spendToPKH(stranger, BigInt.from(299)))
        .build(false);
    await net.submit('payee', spendPaid);

    final dump = env['POOL_CHAIN_DUMP'];
    if (dump != null) {
      File(dump).writeAsStringSync(jsonEncode({
        for (final (n, t) in [('Y0', y0.tx), ('Y1', y1.tx), ('Y2', y2.tx), ('R0', r0), ('W0', w0),
          ('D', depositTx), ('R1', r1), ('W1', w1), ('R2', r2), ('W2', w2)])
          n: t.serialize(),
        'fundingA': split.serialize(),
        'fundingB': split.serialize(),
      }));
    }
  }, skip: env['POOL_LOCALNET'] == null
          ? 'needs ../localnet up; set POOL_LOCALNET=1'
          : env['POOL_COORDINATOR'] != null
              ? 'POOL_COORDINATOR=1 runs the coordinator path instead'
              : false,
      timeout: const Timeout(Duration(minutes: 120)));

  test('two pool rounds through the coordinator, mined on localnet', () async {
    final net = Localnet(viaRpc: env['POOL_BROADCAST'] == 'rpc');
    final svc = ShieldedPoolTool();
    final signer = DefaultTransactionSigner(sigHashAll, opKey);
    final opPub = opKey.publicKey;
    final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);
    final opPKH = hex.decode(opAddr.pubkeyHash160);
    final stranger = strangerKey.publicKey.toAddress(NetworkType.TEST);

    await net.ready();
    final production = env['POOL_PRODUCTION'] == '1';
    final plan = PoolChainFixture.plan(production: production);
    final t = await _Transfers.load(env['POOL_PROOF_CACHE'], production, plan.spendP,
        () => PoolChainFixture.prove(
            withdrawalPKH: hex.decode(stranger.pubkeyHash160), production: production, verbose: production, aggregate: false));
    final stmt = PoolStatement.of(plan.tree);
    final body = ShieldedPoolTool.poolVerifier(stmt,
            verifier: StarkVerifierGen(plan.rootP, plan.rootAir(List.filled(stmt.numPublics, 0))))
        .body();
    final g = PoolHeader.genesis(
        emptyCmRoot: SlotScript.lanesBytes(NoteCommitmentTree().root), emptyNfRoot: SlotScript.lanesBytes(NullifierTree().root));

    // ---- coins: the node funds the coordinator's key once; every
    // transaction after that is paid from a fresh output of exactly the
    // value asked, mined before it is spent, as a wallet would do it
    final coins = await net.fund(opAddr, BigInt.from(100000000));
    final funding = _NodeFunding(net, coins, coins.outputs.indexWhere((o) => _pays(o, opPKH)), signer, opPub, opAddr);

    // ---- genesis by hand: Y0, the issuance spending its anchor, witness 0
    final ySats = BigInt.from(((body.length + 1000) * feeRate + 999) ~/ 1000 + 2);
    final wSats = BigInt.from(((3 * body.length + 1000000) * feeRate + 999) ~/ 1000 + 1);
    final fY0 = (await funding.output(ySats))!;
    final y0 = svc.buildSlotTxn(header: g, verifierBody: body,
        fundingTx: fY0.tx, fundingVout: fY0.vout, fundingSigner: signer, fundingPubKey: opPub, anchorPKH: opPKH, signerPKH: opPKH);
    await net.submit('Y0', y0.tx);
    final fI = (await funding.output(BigInt.from(1000000)))!;
    final fW0 = (await funding.output(wSats))!;
    final r0 = svc.createTokenIssuanceTxn(fI.tx, signer, opPub, opAddr, crypto.sha256.convert(body).bytes, g, y0.outpoint, fW0.tx.hash,
        slotTx: y0.tx, fundingVout: fI.vout, witnessFundingVout: fW0.vout);
    await net.submit('R0', r0);
    final w0 = svc.createWitnessTxn(signer, fW0.tx, r0, hex.decode(fI.tx.serialize()), opPub, opAddr.pubkeyHash160,
        ShieldedPoolAction.CREATE,
        fundingVout: fW0.vout, slotParts: y0.parts, verifierBody: body);
    await net.submit('W0', w0);

    // ---- the depositor pays into a covenant naming PP3_0
    final depositCoins = await funding.pay(stranger, BigInt.from(100000));
    final height = await net.height();
    final depositTx = svc.createDepositTxn(
        fundingTx: depositCoins,
        fundingVout: 1,
        fundingSigner: DefaultTransactionSigner(sigHashAll, strangerKey),
        fundingPubKey: strangerKey.publicKey,
        changeAddress: stranger,
        commitment: t.receipt.commitment,
        satoshis: t.receipt.satoshis,
        pp3Outpoint: svc.getOutpoint(r0.hash, outputIndex: 3),
        refundPKH: hex.decode(stranger.pubkeyHash160),
        refundAfter: height + 100);
    await net.submit('D', depositTx);
    final depositOutpoint = svc.getOutpoint(depositTx.hash, outputIndex: ShieldedPoolTool.depositVout);

    // ---- the coordinator, publishing through the node
    final store = _ChainStore();
    final co = ShieldedCoordinator.open(
        config: CoordinatorConfig(plan: plan, feeRate: feeRate, depositMargin: 100),
        tool: svc,
        issuance: r0,
        witness0: w0,
        slot0: y0.tx,
        funding: funding,
        store: store,
        publish: (tx) => net.submit(store.nameOf(tx), tx),
        owner: signer,
        ownerPub: opPub)
      ..chainHeight = height;
    final rng = Random(5);
    List<int> id() => List.generate(16, (_) => rng.nextInt(256));

    Future<PoolAnnouncement> round(List<ShieldedTransfer> transfers) async {
      final sw = Stopwatch()..start();
      for (final x in transfers) {
        final r = co.intake(id(), x, depositTx: x.depositOutpoint == null ? null : depositTx);
        expect(r.isAccepted, isTrue, reason: '$r');
      }
      print('${transfers.length} transfers taken in in ${sw.elapsedMilliseconds} ms');
      sw.reset();
      final a = await co.building!;
      expect(a, isNotNull, reason: '${co.lastFailure}');
      print('round ${a!.round} closed to mined in ${sw.elapsedMilliseconds} ms: ${co.lastTiming}');
      return a;
    }

    // ---- round 1 takes the deposit in
    final d = t.transfers1[0];
    final a1 = await round([ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: depositOutpoint), ...t.transfers1.sublist(1)]);
    expect(a1.round, 1);
    expect(co.ledger.tipRound.outputs[3].satoshis, BigInt.from(501));

    // ---- round 2 spends the deposited note and withdraws 300
    final a2 = await round(t.transfers2);
    expect(a2.round, 2);
    final r2 = co.ledger.tipRound;
    expect(r2.outputs[3].satoshis, BigInt.from(201));

    // ---- the withdrawal is a plain P2PKH the payee can spend
    final paid = r2.outputs.indexWhere((o) => _pays(o, hex.decode(stranger.pubkeyHash160)));
    expect(r2.outputs[paid].satoshis, BigInt.from(300));
    final spendPaid = (TransactionBuilder()
          ..spendFromTxnWithSigner(DefaultTransactionSigner(sigHashAll, strangerKey), r2, paid,
              TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(strangerKey.publicKey))
          ..spendToPKH(stranger, BigInt.from(299)))
        .build(false);
    await net.submit('payee', spendPaid);

    // ---- a reader given the chain reaches the coordinator's ledger
    final reader = ShieldedChainReader.open(ShieldedPoolLayout.of(plan.tree), r0, w0, y0.tx);
    reader.read(store.triples);
    expect(reader.stopped, isFalse, reason: '${reader.refusal}');
    expect(reader.ledger.header.encode(), co.ledger.header.encode());
    expect(reader.ledger.snapshot(), co.ledger.snapshot());

    final dump = env['POOL_CHAIN_DUMP'];
    if (dump != null) {
      final r = store.rounds;
      File(dump).writeAsStringSync(jsonEncode({
        for (final (n, tx) in [('Y0', y0.tx), ('Y1', r[0].y), ('Y2', r[1].y), ('R0', r0), ('W0', w0),
          ('D', depositTx), ('R1', r[0].round), ('W1', r[0].witness), ('R2', r[1].round), ('W2', r[1].witness)])
          n: tx.serialize(),
        for (final (i, f) in funding.given.indexed) 'F$i': f.serialize(),
      }));
    }
  }, skip: env['POOL_LOCALNET'] == null || env['POOL_COORDINATOR'] == null
          ? 'needs ../localnet up; set POOL_LOCALNET=1 POOL_COORDINATOR=1'
          : false,
      timeout: const Timeout(Duration(minutes: 120)));
}

/// The fixture's transfers, which can be kept in a file between runs: a
/// coordinator run needs the spend proofs and nothing the fixture
/// aggregates.
class _Transfers {
  final List<ShieldedTransfer> transfers1, transfers2;
  final PoolReceipt receipt;
  final PoolWithdrawal withdrawal;
  _Transfers(this.transfers1, this.transfers2, this.receipt, this.withdrawal);

  static Future<_Transfers> load(String? path, bool production, StarkParams spendP, Future<PoolChainFixture> Function() prove) async {
    final file = path == null ? null : File('$path.transfers.json');
    if (file != null && file.existsSync()) {
      final j = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      if (j['production'] != production) throw StateError('$file holds ${j['production'] ? '' : 'non-'}production transfers');
      List<ShieldedTransfer> ts(String k) => [for (final h in j[k] as List) ShieldedTransfer.decode(hex.decode(h as String), spendP)];
      print('transfers read from ${file.path}');
      return _Transfers(ts('transfers1'), ts('transfers2'), PoolReceipt(hex.decode(j['cm'] as String), BigInt.parse(j['cmSats'] as String)),
          PoolWithdrawal(hex.decode(j['wPKH'] as String), BigInt.parse(j['wSats'] as String)));
    }
    final sw = Stopwatch()..start();
    final f = await prove();
    print('proved the transfers of rounds 1 and 2 in ${sw.elapsedMilliseconds} ms');
    file?.writeAsStringSync(jsonEncode({
      'production': production,
      'transfers1': [for (final t in f.transfers1) hex.encode(t.encode(spendP))],
      'transfers2': [for (final t in f.transfers2) hex.encode(t.encode(spendP))],
      'cm': hex.encode(f.receipt.commitment),
      'cmSats': f.receipt.satoshis.toString(),
      'wPKH': hex.encode(f.withdrawal.pubkeyHash),
      'wSats': f.withdrawal.satoshis.toString(),
    }));
    return _Transfers(f.transfers1, f.transfers2, f.receipt, f.withdrawal);
  }
}

/// A funding source on the node: each request spends the coordinator's
/// current change, pays exactly what was asked to the coordinator's key at
/// output 1 with the change at output 0, and mines it.
class _NodeFunding implements CoordinatorFunding {
  final Localnet net;
  final TransactionSigner signer;
  final SVPublicKey pubKey;
  final Address to;
  final List<Transaction> given = [];
  Transaction _coin;
  int _vout;
  _NodeFunding(this.net, this._coin, this._vout, this.signer, this.pubKey, this.to);

  Future<Transaction> pay(Address a, BigInt sats) async {
    final tx = (TransactionBuilder()
          ..spendFromTxnWithSigner(signer, _coin, _vout, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(pubKey))
          ..spendToPKH(a, sats)
          ..sendChangeToPKH(to)
          ..withFeePerKb(feeRate * 10))
        .build(false);
    if (tx.outputs[1].satoshis != sats) throw StateError('the builder did not put the payment at output 1');
    await net.submit('fund', tx);
    given.add(tx);
    _coin = tx;
    _vout = 0;
    return tx;
  }

  @override
  Future<FundingOutput?> output(BigInt minValue) async => FundingOutput(await pay(to, minValue), 1, signer, pubKey);
}

/// Keeps every built round and names its transactions for the log.
class _ChainStore implements CoordinatorStore {
  final rounds = <({int number, Transaction y, Transaction round, Transaction witness})>[];
  final _names = <String, String>{};

  @override
  Future<void> roundBuilt(int number, Transaction y, Transaction round, Transaction witness, Uint8List snapshot) async {
    rounds.add((number: number, y: y, round: round, witness: witness));
    _names[y.id] = 'Y$number';
    _names[round.id] = 'R$number';
    _names[witness.id] = 'W$number';
  }

  String nameOf(Transaction tx) => _names[tx.id] ?? 'tx';

  List<ShieldedRoundTxs> get triples => [for (final r in rounds) (round: r.round, witness: r.witness, nextSlot: r.y)];
}

/// What the chain needs from [PoolChainFixture], which can be kept in a
/// file between runs.
class _Proved {
  final List<int> body, bundles, bundles2;
  final PoolHeader g, h1, h2;
  final PoolRoundProof proof, proof2;
  final PoolReceipt receipt;
  final PoolWithdrawal withdrawal;

  _Proved(this.body, this.bundles, this.bundles2, this.g, this.h1, this.h2, this.proof, this.proof2, this.receipt,
      this.withdrawal);

  static Future<_Proved> load(String? path, bool production, Future<PoolChainFixture> Function() prove) async {
    final file = path == null ? null : File(path);
    if (file != null && file.existsSync()) {
      final j = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      if (j['production'] != production) throw StateError('$path holds ${j['production'] ? '' : 'non-'}production proofs');
      List<int> b(String k) => hex.decode(j[k] as String);
      PoolRoundProof p(String k) => PoolRoundProof(
          b('${k}Below'), [for (final h in j['${k}Hashes'] as List) hex.decode(h as String)]);
      print('proofs read from $path');
      return _Proved(b('body'), b('bundles'), b('bundles2'), PoolHeader.decode(b('g')), PoolHeader.decode(b('h1')),
          PoolHeader.decode(b('h2')), p('proof'), p('proof2'), PoolReceipt(b('cm'), BigInt.parse(j['cmSats'] as String)),
          PoolWithdrawal(b('wPKH'), BigInt.parse(j['wSats'] as String)));
    }
    final sw = Stopwatch()..start();
    final f = await prove();
    print('proved rounds 1 and 2, V body ${f.body.length} B, in ${sw.elapsedMilliseconds} ms');
    final r = _Proved(f.body, f.bundles, f.bundles2, f.g, f.h1, f.h2, f.proof, f.proof2, f.receipt, f.withdrawal);
    file?.writeAsStringSync(jsonEncode({
      'production': production,
      'body': hex.encode(r.body),
      'bundles': hex.encode(r.bundles),
      'bundles2': hex.encode(r.bundles2),
      'g': hex.encode(r.g.encode()),
      'h1': hex.encode(r.h1.encode()),
      'h2': hex.encode(r.h2.encode()),
      for (final (k, pr) in [('proof', r.proof), ('proof2', r.proof2)]) ...{
        '${k}Below': hex.encode(pr.belowTail),
        '${k}Hashes': [for (final h in pr.bundleHashes) hex.encode(h)],
      },
      'cm': hex.encode(r.receipt.commitment),
      'cmSats': r.receipt.satoshis.toString(),
      'wPKH': hex.encode(r.withdrawal.pubkeyHash),
      'wSats': r.withdrawal.satoshis.toString(),
    }));
    return r;
  }
}

/// A round built once to measure it and again with the fee its size costs.
/// The size does not move with the fee, so the second build is exact.
Transaction _priced(Transaction Function({BigInt? fee}) build) {
  final fee = ShieldedPoolTool.feeFor(build(), satsPerKb: feeRate);
  final min = BigInt.from(135);
  return build(fee: fee < min ? min : fee);
}

bool _pays(TransactionOutput o, List<int> pkh) {
  final s = o.script.buffer;
  return s.length == 25 && s[0] == 0x76 && s[1] == 0xa9 && hex.encode(s.sublist(3, 23)) == hex.encode(pkh);
}

/// The regtest node's RPC and ARC, as ../localnet runs them.
class Localnet {
  final bool viaRpc;
  final rpcUri = Uri.parse(env['LOCALNET_RPC'] ?? 'http://localhost:18332');
  final arcUri = Uri.parse(env['LOCALNET_ARC'] ?? 'http://localhost:9090');
  final _http = HttpClient();
  final _known = <String, Transaction>{};

  Localnet({this.viaRpc = false});

  Future<dynamic> rpc(String method, [List<dynamic> params = const []]) async {
    final req = await _http.postUrl(rpcUri);
    req.headers.set('Authorization', 'Basic ${base64.encode(utf8.encode('bitcoin:bitcoin'))}');
    req.headers.contentType = ContentType.json;
    // The node closes idle connections, and proving can idle this client
    // for minutes, so a pooled connection may be dead when reused.
    req.persistentConnection = false;
    req.write(jsonEncode({'jsonrpc': '1.0', 'id': method, 'method': method, 'params': params}));
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    final json = jsonDecode(body) as Map<String, dynamic>;
    if (json['error'] != null) throw StateError('$method: ${json['error']}');
    return json['result'];
  }

  Future<int> height() async => await rpc('getblockcount') as int;

  Future<void> mine([int n = 1]) async => rpc('generatetoaddress', [n, await rpc('getnewaddress')]);

  /// Checks the node answers and ARC is healthy, and matures coinbase.
  Future<void> ready() async {
    try {
      await height();
    } catch (e) {
      throw StateError('No regtest node at $rpcUri ($e). Start ../localnet (docker compose up -d).');
    }
    if (!viaRpc) {
      final res = await (await _http.getUrl(arcUri.resolve('/v1/health'))).close();
      final body = await res.transform(utf8.decoder).join();
      if (res.statusCode != 200) throw StateError('ARC at $arcUri is not healthy: ${res.statusCode} $body');
    }
    if ((await rpc('getbalance') as num) < 2) await mine(101);
  }

  /// Sends [sats] from the node's wallet to [to], mines it, and returns the
  /// transaction.
  Future<Transaction> fund(Address to, BigInt sats) async {
    final txid = await rpc('sendtoaddress', [to.toBase58(), sats.toInt() / 1e8]) as String;
    await mine();
    final tx = Transaction.fromHex(await rpc('getrawtransaction', [txid, 0]) as String);
    _known[tx.id] = tx;
    return tx;
  }

  /// Broadcasts [tx], mines a block, and checks the block took it.
  Future<void> submit(String name, Transaction tx) async {
    final size = hex.decode(tx.serialize()).length;
    var fee = BigInt.zero;
    for (final i in tx.inputs) {
      fee += _known[i.prevTxnId]!.outputs[i.prevTxnOutputIndex].satoshis;
    }
    for (final o in tx.outputs) {
      fee -= o.satoshis;
    }
    final sw = Stopwatch()..start();
    final status = viaRpc ? await _sendRpc(name, tx) : await _sendArc(name, tx);
    final accepted = sw.elapsedMilliseconds;
    await mine();
    final info = await rpc('getrawtransaction', [tx.id, 1]) as Map<String, dynamic>;
    if ((info['confirmations'] ?? 0) < 1) {
      throw StateError('$name ${tx.id} was accepted ($status) but not mined');
    }
    _known[tx.id] = tx;
    final row = '${name.padRight(6)} ${size.toString().padLeft(9)} B  fee ${fee.toString().padLeft(7)}  '
        '${(fee.toInt() * 1000 / size).toStringAsFixed(2).padLeft(7)} sat/kB  $status in $accepted ms  ${tx.id}';
    print(row);
  }

  Future<String> _sendRpc(String name, Transaction tx) async {
    try {
      await rpc('sendrawtransaction', [tx.serialize()]);
      return 'node';
    } catch (e) {
      throw StateError('node refused $name: $e');
    }
  }

  Future<String> _sendArc(String name, Transaction tx) async {
    final req = await _http.postUrl(arcUri.resolve('/v1/tx'));
    req.headers.contentType = ContentType.json;
    req.headers.set('X-WaitFor', 'SEEN_ON_NETWORK');
    req.headers.set('X-MaxTimeout', '30');
    req.write(jsonEncode({'rawTx': hex.encode(_extended(tx))}));
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    Map<String, dynamic> json;
    try {
      json = jsonDecode(body) as Map<String, dynamic>;
    } catch (_) {
      throw StateError('ARC answered $name with ${res.statusCode}: $body');
    }
    final txStatus = json['txStatus'] as String?;
    // Anything short of a node holding it is not acceptance: ARC with no
    // connected peers stores the transaction and answers STORED.
    const good = {'SEEN_ON_NETWORK', 'ACCEPTED_BY_NETWORK', 'MINED'};
    if (res.statusCode != 200 || txStatus == null || !good.contains(txStatus)) {
      throw StateError('ARC refused $name (${res.statusCode}): ${json['title'] ?? ''} ${json['detail'] ?? ''} '
          '${json['extraInfo'] ?? ''} txStatus=$txStatus');
    }
    return txStatus;
  }

  /// [tx] in Extended Format (BRC-30): each input followed by the value and
  /// locking script it spends, so ARC can validate it without the parents.
  List<int> _extended(Transaction tx) {
    final raw = hex.decode(tx.serialize());
    final out = <int>[...raw.sublist(0, 4), 0, 0, 0, 0, 0, 0xef, ..._varint(tx.inputs.length)];
    for (final i in tx.inputs) {
      final spent = _known[i.prevTxnId]?.outputs[i.prevTxnOutputIndex];
      if (spent == null) throw StateError('input spends ${i.prevTxnId}:${i.prevTxnOutputIndex}, which this run did not make');
      final value = ByteData(8)..setUint64(0, spent.satoshis.toInt(), Endian.little);
      out
        ..addAll(i.serialize())
        ..addAll(value.buffer.asUint8List())
        ..addAll(_varint(spent.script.buffer.length))
        ..addAll(spent.script.buffer);
    }
    out.addAll(_varint(tx.outputs.length));
    for (final o in tx.outputs) {
      out.addAll(o.serialize());
    }
    out.addAll(raw.sublist(raw.length - 4));
    return out;
  }

}

List<int> _varint(int n) {
  if (n < 0xfd) return [n];
  if (n <= 0xffff) return [0xfd, n & 0xff, n >> 8];
  return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}
