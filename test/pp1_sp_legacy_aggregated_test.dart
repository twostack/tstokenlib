import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/builder/pp1_sp_legacy_lock_builder.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_legacy_script_gen.dart';
import 'package:tstokenlib/src/script_gen/verifier_slot_gen.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_legacy_tool.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};
final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

void verifyAll(Transaction tx, List<TransactionOutput> spent, {String? label}) {
  final sw = Stopwatch()..start();
  for (int i = 0; i < tx.inputs.length; i++) {
    Interpreter().correctlySpends(tx.inputs[i].script!, spent[i].script, tx, i, verifyFlags, Coin.valueOf(spent[i].satoshis));
  }
  if (label != null) print('  $label: ${tx.inputs.length} inputs verified in ${sw.elapsedMilliseconds} ms, tx ${tx.serialize().length ~/ 2} B');
}

/// The pool in aggregated mode: one verifier slot per round checking the
/// root of a two-level aggregation of four spend proofs, no append slot.
void main() {
  final rng = Random(9);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const p1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const p2p = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const rootP = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  late PoolAggregation agg;
  late PP1SpLegacyScriptGen gen;
  late ShieldedPoolLegacyTool tool;

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

  /// Two output notes with their note-data output, as a wallet publishes
  /// them: in aggregated mode the commitments are not public lanes, so a
  /// reader takes them from these bundles.
  Future<(OutputNote, OutputNote, Uint8List)> notes(int va, int vb, {List<Uint8List> payouts = const []}) async {
    final sender = PoolWalletKeys(lanes(5));
    final ta = await NoteAddress.at(PoolWalletKeys(lanes(5)).ivk, 0), tb = await NoteAddress.at(PoolWalletKeys(lanes(5)).ivk, 0);
    final oa = OutputNote(pkd: ta.pkd, value: va, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: tb.pkd, value: vb, rho: lanes(3), rcm: lanes(4));
    final ba = await NoteEncryption.encrypt(
        NotePlaintext(asset: PoolHash.bsvAsset, d: ta.d, value: va, rho: oa.rho, rcm: oa.rcm, memo: NotePlaintext.memoOf('a')), ta, sender.ovk, rng: rng);
    final bb = await NoteEncryption.encrypt(
        NotePlaintext(asset: PoolHash.bsvAsset, d: tb.d, value: vb, rho: ob.rho, rcm: ob.rcm, memo: NotePlaintext.memoOf('b')), tb, sender.ovk, rng: rng);
    expect(ba.cm, oa.cm);
    return (oa, ob, ShieldedPoolLegacyTool.extras([ba, bb], payouts));
  }

  final rabin = Rabin.generateKeyPair(1024);
  final rabinN = Rabin.bigIntToScriptNum(rabin.n).toList();
  final rabinPKH = hash160(rabinN);
  final idTxId = bytes(32), ed25519 = bytes(32);
  late Transaction fundingTx, issuanceTx, genesisTx, roundTx;
  late PoolLedger ledger;

  test('the generators: aggregation programs, the root slot and the state script', () {
    final sw = Stopwatch()..start();
    agg = PoolAggregation.uniform(spendP: spendP, levelP: const [p1, p2p], levelLog: const [15, 16], rootP: rootP, rootLog: 15, arity: 2);
    print('  aggregation compiled in ${sw.elapsedMilliseconds} ms: ${agg.transfers} transfers, ${agg.widePublicsCount} public lanes');
    final slot = VerifierSlotGen(rootP, airFor: agg.rootAir, numPublics: agg.widePublicsCount);
    gen = PP1SpLegacyScriptGen.aggregated(spendP, verifierSlot: slot, transfers: agg.transfers, leavesAppended: agg.tree.leavesAppended);
    tool = ShieldedPoolLegacyTool(gen);
    print('  verifier slot ${gen.verifierBytes.length} B, state body ${gen.body().buffer.length} B (${sw.elapsedMilliseconds} ms)');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('issuance and genesis: one result, one slot', () {
    fundingTx = coinbaseLike(operatorAddress, [50000, 20000]);
    issuanceTx = tool.createIssuanceTxn(fundingTx, 1, operatorSigner, operatorPub, operatorAddress, rabinPKH);
    final sig = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...fundingTx.hash]), rabin.p, rabin.q);
    (genesisTx, ledger) = tool.createGenesisTxn(issuanceTx, fundingTx, operatorSigner, operatorPub, operatorAddress,
        rabinN: rabinN, rabinS: Rabin.bigIntToScriptNum(sig.s).toList(), rabinPadding: sig.padding,
        identityTxId: idTxId, ed25519PubKey: ed25519, vault: 2000);
    expect(genesisTx.outputs.length, 4);
    expect(genesisTx.outputs[3].satoshis, BigInt.from(50000 + 1 - 2000 - 1 - 1000));
    verifyAll(genesisTx, [fundingTx.outputs[0], issuanceTx.outputs[0]], label: 'genesis');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('a round of four deposits through one aggregated slot', () async {
    final depositFunding = coinbaseLike(depositorAddress, [400000]);
    final amounts = [100000, 50000, 25000, 12500];
    final change = ShieldedPoolLegacyTool.payout(depositorAddress, 400000 - amounts.reduce((a, b) => a + b) - 800);
    final transfers = <PoolTransfer>[];
    for (int n = 0; n < 4; n++) {
      final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
      final (oa, ob, extras) = await notes(amounts[n] - 7, 7, payouts: n == 0 ? [change] : const []);
      final w = PoolSpendAir.witness(da, db, oa, ob, -amounts[n], anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(extras));
      final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(10 + n), hash: const Poseidon2ProofHash());
      transfers.add(PoolTransfer(w.publics, proof, extras));
    }
    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault;
    final sw = Stopwatch()..start();
    roundTx = await tool.createAggregatedRoundTxn(ledger, transfers, agg,
        funding: [FundingInput(depositFunding, 0, depositorSigner, depositorPub)], rng: Random(3), verbose: true);
    print('  round built in ${sw.elapsedMilliseconds} ms');
    expect(ledger.vault, vaultBefore + amounts.reduce((a, b) => a + b));
    expect(ledger.tree.size, 32);
    expect(roundTx.outputs.length, 3 + 4 + 1, reason: 'state, result, slot, four note-data outputs and the change');
    expect(roundTx.inputs.length, 3);
    verifyAll(roundTx, [...spent, depositFunding.outputs[0]], label: 'aggregated round');
    expect(PP1SpLegacyLockBuilder.fromScript(roundTx.outputs[0].script).header.bytes(), ledger.header.bytes());
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('a short round: one deposit and three padding transfers, two of them from stock', () async {
    final depositFunding = coinbaseLike(depositorAddress, [30000]);
    final change = ShieldedPoolLegacyTool.payout(depositorAddress, 30000 - 20000 - 800);
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final (oa, ob, extras) = await notes(19990, 10, payouts: [change]);
    final w = PoolSpendAir.witness(da, db, oa, ob, -20000, anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(extras));
    final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(20), hash: const Poseidon2ProofHash());
    final deposit = PoolTransfer(w.publics, proof, extras);
    expect(deposit.publics.isPadding, isFalse);

    final sw = Stopwatch()..start();
    final supply = PaddingSupply(spendP, rng: Random(21))..fill(2);
    print('  two padding transfers proved ahead in ${sw.elapsedMilliseconds} ms');
    expect(supply.stock, 2);
    // a short round without a supply is refused
    await expectLater(tool.createAggregatedRoundTxn(ledger, [deposit], agg), throwsArgumentError);

    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault, sizeBefore = ledger.tree.size, nfBefore = ledger.nullifiers.root;
    sw.reset();
    final tx = await tool.createAggregatedRoundTxn(ledger, [deposit], agg,
        funding: [FundingInput(depositFunding, 0, depositorSigner, depositorPub)], padding: supply, rng: Random(4));
    print('  short round built in ${sw.elapsedMilliseconds} ms (one padding transfer proved on the spot)');
    expect(supply.stock, 0);
    expect(ledger.vault, vaultBefore + 20000);
    expect(ledger.tree.size, sizeBefore + 32);
    expect(ledger.nullifiers.root, nfBefore); // dummies insert nothing
    verifyAll(tx, [...spent, depositFunding.outputs[0]], label: 'padded round');
  }, timeout: const Timeout(Duration(minutes: 20)));
}
