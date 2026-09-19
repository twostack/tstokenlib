import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/builder/pp1_sp_lock_builder.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/script_gen/verifier_slot_gen.dart';
import 'package:tstokenlib/src/transaction/pool_chain_reader.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_tool.dart';

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
  late PP1SpScriptGen gen;
  late ShieldedPoolTool tool;

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
    gen = PP1SpScriptGen.aggregated(spendP, verifierSlot: slot, transfers: agg.transfers, leavesAppended: agg.tree.leavesAppended);
    tool = ShieldedPoolTool(gen);
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

  test('a round of four deposits through one aggregated slot; the chain reader agrees', () {
    final depositFunding = coinbaseLike(depositorAddress, [400000]);
    final amounts = [100000, 50000, 25000, 12500];
    final change = ShieldedPoolTool.payout(depositorAddress, 400000 - amounts.reduce((a, b) => a + b) - 800);
    final transfers = <PoolTransfer>[];
    for (int n = 0; n < 4; n++) {
      final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
      final oa = OutputNote(pkd: lanes(8), value: amounts[n] - 7, rho: lanes(3), rcm: lanes(4));
      final ob = OutputNote(pkd: lanes(8), value: 7, rho: lanes(3), rcm: lanes(4));
      final extras = n == 0 ? change : Uint8List(0);
      final w = PoolSpendAir.witness(da, db, oa, ob, -amounts[n], anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(extras));
      final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(10 + n), hash: const Poseidon2ProofHash());
      transfers.add(PoolTransfer(w.publics, proof, extras));
    }
    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault;
    final sw = Stopwatch()..start();
    roundTx = tool.createAggregatedRoundTxn(ledger, transfers, agg,
        funding: [FundingInput(depositFunding, 0, depositorSigner, depositorPub)], rng: Random(3), verbose: true);
    print('  round built in ${sw.elapsedMilliseconds} ms');
    expect(ledger.vault, vaultBefore + amounts.reduce((a, b) => a + b));
    expect(ledger.tree.size, 32);
    expect(roundTx.outputs.length, 4);
    expect(roundTx.inputs.length, 3);
    verifyAll(roundTx, [...spent, depositFunding.outputs[0]], label: 'aggregated round');
    expect(PP1SpLockBuilder.fromScript(roundTx.outputs[0].script).header.bytes(), ledger.header.bytes());

    // a reader rebuilds the same ledger from the two transactions
    final reader = PoolChainReader.fromGenesis(gen, genesisTx);
    final round = reader.apply(roundTx);
    expect(round.transfers.length, 4);
    expect(round.subtreeIndex, 0);
    expect(reader.ledger.header.bytes(), ledger.header.bytes());
    expect(reader.ledger.vault, ledger.vault);
    expect(reader.ledger.tree.root, ledger.tree.root);
    expect(reader.ledger.nullifiers.root, ledger.nullifiers.root);
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('a short round: one deposit and three padding transfers, two of them from stock', () {
    final depositFunding = coinbaseLike(depositorAddress, [30000]);
    final change = ShieldedPoolTool.payout(depositorAddress, 30000 - 20000 - 800);
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 19990, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 10, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -20000, anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(change));
    final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(20), hash: const Poseidon2ProofHash());
    final deposit = PoolTransfer(w.publics, proof, change);
    expect(deposit.publics.isPadding, isFalse);

    final sw = Stopwatch()..start();
    final supply = PaddingSupply(spendP, rng: Random(21))..fill(2);
    print('  two padding transfers proved ahead in ${sw.elapsedMilliseconds} ms');
    expect(supply.stock, 2);
    // a short round without a supply is refused
    expect(() => tool.createAggregatedRoundTxn(ledger, [deposit], agg), throwsArgumentError);

    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault, sizeBefore = ledger.tree.size, nfBefore = ledger.nullifiers.root;
    sw.reset();
    final tx = tool.createAggregatedRoundTxn(ledger, [deposit], agg,
        funding: [FundingInput(depositFunding, 0, depositorSigner, depositorPub)], padding: supply, rng: Random(4));
    print('  short round built in ${sw.elapsedMilliseconds} ms (one padding transfer proved on the spot)');
    expect(supply.stock, 0);
    expect(ledger.vault, vaultBefore + 20000);
    expect(ledger.tree.size, sizeBefore + 32);
    expect(ledger.nullifiers.root, nfBefore); // dummies insert nothing
    verifyAll(tx, [...spent, depositFunding.outputs[0]], label: 'padded round');

    final reader = PoolChainReader.fromGenesis(gen, genesisTx);
    reader.apply(roundTx);
    final round = reader.apply(tx);
    expect(round.transfers.length, 4);
    expect(round.transfers.where((t) => t!.isPadding).length, 3);
    expect(reader.ledger.header.bytes(), ledger.header.bytes());
    expect(reader.ledger.tree.root, ledger.tree.root);
    expect(reader.ledger.nullifiers.root, ledger.nullifiers.root);
  }, timeout: const Timeout(Duration(minutes: 20)));
}
