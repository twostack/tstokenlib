import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/builder/pp1_sp_lock_builder.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/transaction/shielded_pool_tool.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};
final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

/// Verify every input of [tx] against the outputs it spends.
void verifyAll(Transaction tx, List<TransactionOutput> spent, {String? label}) {
  final sw = Stopwatch()..start();
  for (int i = 0; i < tx.inputs.length; i++) {
    Interpreter().correctlySpends(tx.inputs[i].script!, spent[i].script, tx, i, verifyFlags, Coin.valueOf(spent[i].satoshis));
  }
  if (label != null) print('  $label: ${tx.inputs.length} inputs verified in ${sw.elapsedMilliseconds} ms, tx ${tx.serialize().length ~/ 2} B');
}

void main() {
  final rng = Random(5);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  const p = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  final gen = PP1SpScriptGen(p, k: 2);
  final tool = ShieldedPoolTool(gen);

  // the operator (creates the pool) and a depositor, with keys
  final operatorKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final operatorPub = SVPublicKey.fromPrivateKey(operatorKey);
  final operatorAddress = Address.fromPublicKey(operatorPub, NetworkType.TEST);
  final operatorSigner = DefaultTransactionSigner(sigHashAll, operatorKey);
  final depositorKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
  final depositorPub = SVPublicKey.fromPrivateKey(depositorKey);
  final depositorAddress = Address.fromPublicKey(depositorPub, NetworkType.TEST);
  final depositorSigner = DefaultTransactionSigner(sigHashAll, depositorKey);

  /// A made-up confirmed transaction paying [sats] to [to] at each vout.
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

  late Transaction fundingTx, issuanceTx, genesisTx;
  late PoolLedger ledger;

  test('issuance: an issued state, a marker and change; tokenId is the funding txid', () {
    fundingTx = coinbaseLike(operatorAddress, [50000, 20000]);
    expect(hex.encode(fundingTx.hash.reversed.toList()), fundingTx.id, reason: 'hash is the internal byte order');
    issuanceTx = tool.createIssuanceTxn(fundingTx, 1, operatorSigner, operatorPub, operatorAddress, rabinPKH);
    expect(issuanceTx.outputs.length, 3);
    final h = PP1SpLockBuilder.fromScript(issuanceTx.outputs[0].script).header;
    expect(h.tokenId, fundingTx.hash);
    expect(h.phase, 0);
    expect(h.size, 0);
    expect(issuanceTx.outputs[2].satoshis, BigInt.from(20000 - 1 - 500));
    verifyAll(issuanceTx, [fundingTx.outputs[1]], label: 'issuance');
    expect(() => tool.createIssuanceTxn(fundingTx, 0, operatorSigner, operatorPub, operatorAddress, rabinPKH), throwsA(isA<ArgumentError>()));
  });

  test('genesis: the identity signs the tokenId; funding output 0 is consumed', () {
    final sig = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...fundingTx.hash]), rabin.p, rabin.q);
    (genesisTx, ledger) = tool.createGenesisTxn(issuanceTx, fundingTx, operatorSigner, operatorPub, operatorAddress,
        rabinN: rabinN, rabinS: Rabin.bigIntToScriptNum(sig.s).toList(), rabinPadding: sig.padding,
        identityTxId: idTxId, ed25519PubKey: ed25519, vault: 2000);
    expect(genesisTx.outputs.length, 1 + 3 + 2 + 1 + 1);
    expect(ledger.header.phase, 1);
    expect(genesisTx.outputs[0].satoshis, BigInt.from(2000));
    expect(genesisTx.outputs[7].satoshis, BigInt.from(50000 + 1 - 2000 - 3 - 1000));
    verifyAll(genesisTx, [fundingTx.outputs[0], issuanceTx.outputs[0]], label: 'genesis');
    // another identity's signature does not create this pool
    final other = Rabin.generateKeyPair(512);
    final bad = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...fundingTx.hash]), other.p, other.q);
    final (badTx, _) = tool.createGenesisTxn(issuanceTx, fundingTx, operatorSigner, operatorPub, operatorAddress,
        rabinN: Rabin.bigIntToScriptNum(other.n).toList(), rabinS: Rabin.bigIntToScriptNum(bad.s).toList(),
        rabinPadding: bad.padding, identityTxId: idTxId, ed25519PubKey: ed25519, vault: 2000);
    expect(() => verifyAll(badTx, [fundingTx.outputs[0], issuanceTx.outputs[0]]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  final skA = lanes(5), dA = lanes(3);
  final noteA = OutputNote(pkd: PoolHash.pkd(skA, dA), value: 300000, rho: lanes(3), rcm: lanes(4));

  test('round 1: a deposit funded by the depositor, with change; one slot idle', () {
    final depositFunding = coinbaseLike(depositorAddress, [400000]);
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final nb = OutputNote(pkd: lanes(8), value: 7, rho: lanes(3), rcm: lanes(4));
    final deposit = noteA.value + nb.value;
    final change = ShieldedPoolTool.payout(depositorAddress, 400000 - deposit - 800);
    final w = PoolSpendAir.witness(da, db, noteA, nb, -deposit, anchor: ledger.anchor, outHash: PoolPublicInputs.outHashLanes(change));
    final proof = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(1));
    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault;
    final tx = tool.createRoundTxn(ledger, [PoolTransfer(w.publics, proof, change), null],
        funding: [FundingInput(depositFunding, 0, depositorSigner, depositorPub)]);
    expect(ledger.vault, vaultBefore + deposit);
    expect(ledger.tree.size, 32);
    expect(tx.outputs.length, 1 + 3 + 3 + 1);
    expect(tx.outputs[0].satoshis, BigInt.from(ledger.vault));
    verifyAll(tx, [...spent, depositFunding.outputs[0]], label: 'round 1');
    // the ledger's header is what the new state output carries
    expect(PP1SpLockBuilder.fromScript(tx.outputs[0].script).header.bytes(), ledger.header.bytes());
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('round 2: the note is spent, an unshield pays the operator; the fee comes from the vault', () {
    final path = ledger.tree.path(0);
    final a = SpendNote(sk: skA, d: dA, value: noteA.value, rho: noteA.rho, rcm: noteA.rcm, siblings: path.siblings, position: 0);
    expect(a.root, ledger.tree.root);
    final dummy = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 250000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 20000, rho: lanes(3), rcm: lanes(4));
    final payee = ShieldedPoolTool.payout(operatorAddress, 29000); // 1000 sats of the 30000 leaving are fee
    final w = PoolSpendAir.witness(a, dummy, oa, ob, noteA.value - oa.value - ob.value, outHash: PoolPublicInputs.outHashLanes(payee));
    final proof = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(2));
    final spent = tool.spentByRound(ledger);
    final vaultBefore = ledger.vault;
    final tx = tool.createRoundTxn(ledger, [PoolTransfer(w.publics, proof, payee), null]);
    expect(ledger.vault, vaultBefore - 30000);
    verifyAll(tx, spent, label: 'round 2');
    // spending it again: the wallet model refuses (the nullifier is in the set)
    expect(() => tool.createRoundTxn(ledger, [PoolTransfer(w.publics, proof, payee), null]), throwsA(isA<StateError>()));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
