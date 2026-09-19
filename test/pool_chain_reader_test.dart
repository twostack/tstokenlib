import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/crypto/nullifier_set.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/transaction/pool_chain_reader.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_tool.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};
final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

void verifyAll(Transaction tx, List<TransactionOutput> spent) {
  for (int i = 0; i < tx.inputs.length; i++) {
    try {
      Interpreter().correctlySpends(tx.inputs[i].script!, spent[i].script, tx, i, verifyFlags, Coin.valueOf(spent[i].satoshis));
    } catch (e) {
      throw StateError('input $i: $e');
    }
  }
}

/// The transaction as a node would hand it to a wallet: re-parsed from bytes.
Transaction onChain(Transaction t) => Transaction.fromHex(t.serialize());

void main() {
  final rng = Random(9);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  const p = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  final gen = PP1SpScriptGen(p, k: 2);
  final tool = ShieldedPoolTool(gen);

  final operatorKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final operatorPub = SVPublicKey.fromPrivateKey(operatorKey);
  final operatorAddress = Address.fromPublicKey(operatorPub, NetworkType.TEST);
  final operatorSigner = DefaultTransactionSigner(sigHashAll, operatorKey);

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

  void expectSameLedger(PoolLedger a, PoolLedger b) {
    expect(a.header.bytes(), b.header.bytes());
    expect(a.vault, b.vault);
    expect(a.tree.size, b.tree.size);
    expect(a.tree.root, b.tree.root);
    expect(a.nullifiers.root, b.nullifiers.root);
    expect(a.tx.id, b.tx.id);
  }

  test('script numbers decode as the emitter pushed them', () {
    for (final v in [0, 1, 16, 17, 127, 128, 255, 256, -1, -128, -129, M31.p - 1, -(1 << 40), 1 << 50]) {
      final b = ScriptBuilder();
      if (v >= 0 && v <= 16) {
        b.smallNum(v);
      } else {
        b.addData(Rabin.bigIntToScriptNum(BigInt.from(v)));
      }
      expect(PoolChainReader.scriptNum(b.build().chunks.single), v, reason: '$v');
    }
  });

  test('publics round-trip through their lanes, deposits included', () {
    for (final out in [0, 1, 300007, -300007, 1 << 40, -(1 << 40)]) {
      for (final (r1, r2) in [(true, true), (true, false), (false, true), (false, false)]) {
        final pi = PoolPublicInputs(lanes(8), lanes(8), lanes(8), lanes(8), lanes(8), out, outHash: lanes(8), real1: r1, real2: r2);
        final back = PoolPublicInputs.fromLanes(pi.toLanes());
        expect(back.toLanes(), pi.toLanes());
        expect(back.publicOut, out);
        expect((back.real1, back.real2), (r1, r2));
      }
    }
    final bad = PoolPublicInputs.zero().toLanes()..[PoolPublicInputs.idxReal1] = 2;
    expect(() => PoolPublicInputs.fromLanes(bad), throwsA(isA<ArgumentError>()));
  });

  final rabin = Rabin.generateKeyPair(1024);
  final rabinN = Rabin.bigIntToScriptNum(rabin.n).toList();
  final idTxId = bytes(32), ed25519 = bytes(32);
  late Transaction fundingTx, issuanceTx, genesisTx, round1Tx, round2Tx;
  late PoolLedger ledger;
  late PoolChainReader reader;

  // notes the test spends later, with their secrets
  final skA = lanes(5), dA = lanes(3);
  final noteA = OutputNote(pkd: PoolHash.pkd(skA, dA), value: 300000, rho: lanes(3), rcm: lanes(4));
  final skB = lanes(5), dB = lanes(3);
  final noteB = OutputNote(pkd: PoolHash.pkd(skB, dB), value: 250000, rho: lanes(3), rcm: lanes(4));

  test('genesis: the reader starts a ledger equal to the tool\'s', () {
    fundingTx = coinbaseLike(operatorAddress, [50000, 20000]);
    issuanceTx = tool.createIssuanceTxn(fundingTx, 1, operatorSigner, operatorPub, operatorAddress, hash160(rabinN));
    final sig = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...fundingTx.hash]), rabin.p, rabin.q);
    (genesisTx, ledger) = tool.createGenesisTxn(issuanceTx, fundingTx, operatorSigner, operatorPub, operatorAddress,
        rabinN: rabinN, rabinS: Rabin.bigIntToScriptNum(sig.s).toList(), rabinPadding: sig.padding,
        identityTxId: idTxId, ed25519PubKey: ed25519, vault: 2000);
    reader = PoolChainReader.fromGenesis(gen, onChain(genesisTx));
    expectSameLedger(reader.ledger, ledger);
    // the issued state is not a genesis
    expect(() => PoolChainReader.fromGenesis(gen, onChain(issuanceTx)), throwsA(isA<FormatException>()));
  });

  test('round 1 (a deposit, one idle slot): the reader follows', () {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final deposit = noteA.value + noteB.value;
    final depositFunding = coinbaseLike(operatorAddress, [deposit + 1000]);
    final w = PoolSpendAir.witness(da, db, noteA, noteB, -deposit, anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    final proof = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(1));
    // a transfer whose publics do not commit to its extra outputs is refused before it reaches the chain
    final wrong = PoolSpendAir.witness(da, db, noteA, noteB, -deposit, anchor: ledger.anchor);
    expect(() => tool.createRoundTxn(ledger, [null, PoolTransfer(wrong.publics, proof, Uint8List(0))]), throwsA(isA<ArgumentError>()));
    final spent = tool.spentByRound(ledger);
    round1Tx = tool.createRoundTxn(ledger, [null, PoolTransfer(w.publics, proof, Uint8List(0))],
        funding: [FundingInput(depositFunding, 0, operatorSigner, operatorPub)]);
    verifyAll(round1Tx, [...spent, depositFunding.outputs[0]]);
    final round = reader.apply(onChain(round1Tx));
    expectSameLedger(reader.ledger, ledger);
    expect(round.transfers[0], isNull);
    expect(round.transfers[1]!.toLanes(), w.publics.toLanes());
    expect(round.transfers[1]!.publicOut, -deposit);
    expect(round.subtreeIndex, 0);
    expect(round.commitments, [MerkleFrontier.emptyLeaf, MerkleFrontier.emptyLeaf, noteA.cm, noteB.cm]);
    expect(reader.ledger.vault, 2000 + deposit);
    // replaying the round, or feeding a round out of order, is refused
    expect(() => reader.apply(onChain(round1Tx)), throwsA(isA<FormatException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('round 2 (a spend and an unshield): the reader follows; a tampered round is caught', () async {
    // the wallet spends note A using the reader's tree, not the tool's
    // note A was the first output of slot 1 in subtree 0: position 2
    final path = reader.ledger.tree.path(2);
    final a = SpendNote(sk: skA, d: dA, value: noteA.value, rho: noteA.rho, rcm: noteA.rcm, siblings: path.siblings, position: 2);
    expect(a.root, reader.ledger.tree.root);
    final dummy = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 200000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 70000, rho: lanes(3), rcm: lanes(4));
    final payee = ShieldedPoolTool.payout(operatorAddress, 29000);
    // the note ciphertexts ride in the transfer's note-data output, under its outHash
    final sender = PoolWalletKeys(lanes(5)), recipient = PoolWalletKeys(lanes(5));
    final to = await NoteAddress.at(recipient.ivk, 1);
    final oaTo = OutputNote(pkd: to.pkd, value: oa.value, rho: oa.rho, rcm: oa.rcm);
    final bundle = await NoteEncryption.encrypt(
        NotePlaintext(asset: PoolHash.bsvAsset, d: to.d, value: oa.value, rho: oa.rho, rcm: oa.rcm, memo: NotePlaintext.memoOf('round 2')),
        to, sender.ovk, rng: rng);
    final extras = ShieldedPoolTool.extras([bundle], [payee]);
    final w = PoolSpendAir.witness(a, dummy, oaTo, ob, noteA.value - oa.value - ob.value,
        anchor: reader.ledger.anchor, outHash: PoolPublicInputs.outHashLanes(extras));
    final proof = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(2));
    final spent = tool.spentByRound(ledger);
    round2Tx = tool.createRoundTxn(ledger, [PoolTransfer(w.publics, proof, extras), null]);
    verifyAll(round2Tx, spent);

    // a round whose slot unlock claims other publics than the results carry
    final tampered = onChain(round2Tx);
    final forged = w.publics.copyWith(publicOut: w.publics.publicOut + 1);
    tampered.inputs[1] = TransactionInput(tampered.inputs[1].prevTxnId, tampered.inputs[1].prevTxnOutputIndex, TransactionInput.MAX_SEQ_NUMBER,
        scriptBuilder: DefaultUnlockBuilder.fromScript(gen.verifierSlot.unlockProof(proof, forged, Uint8List(158), const [])));
    final before = reader.ledger.header.bytes();
    expect(() => reader.apply(tampered), throwsA(isA<FormatException>()));
    expect(reader.ledger.tx.id, round1Tx.id, reason: 'a rejected round leaves the ledger untouched');
    expect(reader.ledger.header.bytes(), before);
    expect(reader.ledger.tree.size, 32);

    final round = reader.apply(onChain(round2Tx));
    expectSameLedger(reader.ledger, ledger);
    expect(round.transfers[0]!.publicOut, 30000);
    // the recipient finds its note in the round; the sender's auditor too
    final bundles = round.noteBundles;
    expect(bundles.length, 1);
    expect(bundles[0].cm, round.transfers[0]!.cmOut1);
    final got = await NoteEncryption.scanIncoming(bundles[0], recipient.ivk, [for (int i = 0; i < 3; i++) PoolHash.diversifier(recipient.ivk, i)]);
    expect(got?.$1.value, oa.value);
    expect(got?.$2, to.d);
    expect((await NoteEncryption.decryptOutgoing(bundles[0], sender.ovk))?.$2, to.pkd);
    expect(round.transfers[1], isNull);
    expect(round.subtreeIndex, 1);
    expect(reader.ledger.tree.size, 64);
    expect(reader.ledger.nullifiers.contains(NullifierSet.fromLanes(w.publics.nf1)), isTrue);
    // the dummies' nullifiers were never inserted: two deposits' dummies and one spend's dummy
    expect(reader.ledger.nullifiers.contains(NullifierSet.fromLanes(w.publics.nf2)), isFalse);
    expect(reader.ledger.nullifiers.size, 1 + 1, reason: 'sentinel + one real nullifier');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('round 3: a spend proved from the reader\'s ledger verifies on chain', () {
    // a second wallet, which only ever saw the chain, spends note B
    final fresh = PoolChainReader.fromGenesis(gen, onChain(genesisTx))
      ..apply(onChain(round1Tx))
      ..apply(onChain(round2Tx));
    expectSameLedger(fresh.ledger, ledger);
    final path = fresh.ledger.tree.path(3);
    final b = SpendNote(sk: skB, d: dB, value: noteB.value, rho: noteB.rho, rcm: noteB.rcm, siblings: path.siblings, position: 3);
    expect(b.root, fresh.ledger.tree.root);
    final dummy = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 240000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 5000, rho: lanes(3), rcm: lanes(4));
    final payee = ShieldedPoolTool.payout(operatorAddress, 4000);
    final w = PoolSpendAir.witness(b, dummy, oa, ob, noteB.value - oa.value - ob.value,
        anchor: fresh.ledger.anchor, outHash: PoolPublicInputs.outHashLanes(payee));
    final proof = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(3));
    // the round is built from the reader's ledger alone
    final coordinator = ShieldedPoolTool(gen);
    final spent = coordinator.spentByRound(fresh.ledger);
    final tx = coordinator.createRoundTxn(fresh.ledger, [null, PoolTransfer(w.publics, proof, payee)]);
    verifyAll(tx, spent);
    reader.apply(onChain(tx));
    expectSameLedger(reader.ledger, fresh.ledger);
  }, timeout: const Timeout(Duration(minutes: 5)));
}
