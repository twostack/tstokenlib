import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_set.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_legacy_script_gen.dart';
import 'package:tstokenlib/src/script_gen/subtree_append_slot_gen.dart';
import 'package:tstokenlib/src/script_gen/verifier_slot_gen.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

TransactionOutput outputFrom(Uint8List bytes) {
  final sats = ByteData.sublistView(bytes, 0, 8).getUint64(0, Endian.little);
  var i = 8;
  int len;
  if (bytes[i] < 0xfd) {
    len = bytes[i];
    i += 1;
  } else if (bytes[i] == 0xfd) {
    len = bytes[i + 1] | (bytes[i + 2] << 8);
    i += 3;
  } else {
    len = ByteData.sublistView(bytes, i + 1, i + 5).getUint32(0, Endian.little);
    i += 5;
  }
  return TransactionOutput(BigInt.from(sats), SVScript.fromByteArray(bytes.sublist(i, i + len)));
}

TransactionInput inputAt(String txid, int vout) =>
    TransactionInput(txid, vout, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript()));

Transaction txOf(List<TransactionInput> ins, List<Uint8List> outs) {
  final t = Transaction();
  t.version = 1;
  t.nLockTime = 0;
  t.inputs.addAll(ins);
  t.outputs.addAll(outs.map(outputFrom));
  return t;
}

List<int> outpointBytes(TransactionInput i) => [
      ...hex.decode(i.prevTxnId).reversed,
      ...(ByteData(4)..setUint32(0, i.prevTxnOutputIndex, Endian.little)).buffer.asUint8List(),
    ];
List<int> prevoutsAfter(Transaction t, int from) => [for (final i in t.inputs.skip(from)) ...outpointBytes(i)];

Uint8List preimage(Transaction t, int input, SVScript lock, int sats, int type) =>
    Sighash().createSighashPreImage(t, type, input, lock, BigInt.from(sats))!;

void spends(SVScript unlock, SVScript lock, Transaction t, int input, int sats) =>
    Interpreter().correctlySpends(unlock, lock, t, input, verifyFlags, Coin.valueOf(BigInt.from(sats)));

void main() {
  final rng = Random(77);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int k) => List.generate(k, (_) => r31());
  Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  const p = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const k = 2;
  final gen = PP1SpLegacyScriptGen(p, k: k);

  // the operator's identity and the pool's genesis
  final rabin = Rabin.generateKeyPair(1024);
  final rabinN = Rabin.bigIntToScriptNum(rabin.n).toList();
  final rabinPKH = hash160(rabinN);
  final tokenId = bytes(32), idTxId = bytes(32), ed25519 = bytes(32);
  final sig = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...tokenId]), rabin.p, rabin.q);
  final rabinS = Rabin.bigIntToScriptNum(sig.s).toList();
  final h0 = PP1SpLegacyHeader.issued(tokenId: tokenId, rabinPubKeyHash: rabinPKH);
  final change = SlotScript_output(500, hex.decode('76a914${'22' * 20}88ac'));

  // the pool as the wallet / coordinator sees it
  final tree = NoteCommitmentTree();
  final nfs = NullifierSet();
  NullifierInsertion? ins(bool real, List<int> nf) => real ? nfs.insert(NullifierSet.fromLanes(nf)) : null;

  late PP1SpLegacyHeader h1;
  const createVault = 1000;
  final createTxid = 'c1' * 32;

  test('create: the identity and the funding output anchor the genesis', () {
    final lock0 = gen.lock(h0);
    h1 = h0.live();
    final outs = gen.roundOutputs(h1, createVault, [for (int i = 0; i <= k; i++) VerifierSlotGen.emptyResultOutput()], [change]);
    final ins = [inputAt(hex.encode(tokenId.reversed.toList()), 0), inputAt('ab' * 32, 0)];
    final tx = txOf(ins, outs);
    final pre = preimage(tx, 1, lock0, 1, PP1SpLegacyScriptGen.sighashAll);
    SVScript unlock({List<int>? s, Uint8List? pre0}) => gen.createUnlock(
        preimage: pre0 ?? pre, rabinN: rabinN, rabinS: s ?? rabinS, rabinPadding: sig.padding,
        identityTxId: idTxId, ed25519PubKey: ed25519, vault: createVault, extras: change);
    final sw = Stopwatch()..start();
    spends(unlock(), lock0, tx, 1, 1);
    print('  PP1_SP k=$k: lock ${lock0.buffer.length} B (header ${PP1SpLegacyHeader.bytesTotal}); create unlock ${unlock().buffer.length} B; ${sw.elapsedMilliseconds} ms');
    expect(PP1SpLegacyHeader.parse(lock0.buffer).tokenId, tokenId);
    expect(PP1SpLegacyHeader.parse(outs[0].sublist(9 + 2)).phase, 1);
    // a signature for another tokenId
    final other = Rabin.sign(Rabin.sha256ToScriptInt([...idTxId, ...ed25519, ...bytes(32)]), rabin.p, rabin.q);
    expect(() => spends(unlock(s: Rabin.bigIntToScriptNum(other.s).toList()), lock0, tx, 1, 1), throwsA(isA<ScriptException>()));
    // a create that does not spend (tokenId, 0)
    final tx2 = txOf([inputAt(hex.encode(tokenId.reversed.toList()), 1), ins[1]], outs);
    final pre2 = preimage(tx2, 1, lock0, 1, PP1SpLegacyScriptGen.sighashAll);
    expect(() => spends(unlock(pre0: pre2), lock0, tx2, 1, 1), throwsA(isA<ScriptException>()));
    // an output that stays issued
    final tx3 = txOf(ins, gen.roundOutputs(h0, createVault, [for (int i = 0; i <= k; i++) VerifierSlotGen.emptyResultOutput()], [change]));
    final pre3 = preimage(tx3, 1, lock0, 1, PP1SpLegacyScriptGen.sighashAll);
    expect(() => spends(unlock(pre0: pre3), lock0, tx3, 1, 1), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  /// Builds, verifies (every pool input) and applies one round with the
  /// given transfers on the pool at [h] held by [parentTxid] with [vault].
  /// Returns the next header and vault.
  (PP1SpLegacyHeader, int, String) round(PP1SpLegacyHeader h, int vault, String parentTxid, List<PP1SpLegacyTransfer?> transfers,
      {List<TransactionInput> funding = const [], String? label}) {
    final lock = gen.lock(h);
    final rootBefore = NullifierSet.toLanes(h.cmRoot);
    final j = tree.nextSubtree;
    final siblings = tree.subtreePath(j);
    final cms = [for (final t in transfers) if (t != null) ...[t.publics.cmOut1, t.publics.cmOut2]];
    tree.appendSubtree(cms);
    final rootAfter = tree.root;
    final results = [
      for (final t in transfers) t == null ? VerifierSlotGen.emptyResultOutput() : VerifierSlotGen.resultOutput(t.publics.toLanes()),
      SubtreeAppendSlotGen.resultOutput(SubtreeAppendSlotGen.payload(rootBefore, rootAfter, j, cms)),
    ];
    var out = vault;
    for (final t in transfers) {
      if (t != null) out -= t.publics.publicOut;
    }
    final next = h.afterRound(rootAfter, nfs.root);
    final extras = [for (final t in transfers) if (t != null && t.extraOutputs.isNotEmpty) t.extraOutputs];
    final outs = gen.roundOutputs(next, out, results, extras);
    final ins = [inputAt(parentTxid, 0), for (int v = k + 2; v <= 2 * k + 2; v++) inputAt(parentTxid, v), ...funding];
    final tx = txOf(ins, outs);
    final sw = Stopwatch()..start();
    // input 0: the state
    final pre0 = preimage(tx, 0, lock, vault, PP1SpLegacyScriptGen.sighashAll);
    final unlock0 = gen.spendUnlock(preimage: pre0, extraPrevouts: prevoutsAfter(tx, k + 2), rootAfter: rootAfter, transfers: transfers);
    spends(unlock0, lock, tx, 0, vault);
    // inputs 1..k: the verifier slots
    final vlock = gen.verifierSlot.lock();
    for (int t = 0; t < k; t++) {
      final tail = prevoutsAfter(tx, 1);
      final preT = preimage(tx, 1 + t, vlock, 1, SlotScript_single);
      final tr = transfers[t];
      final u = tr == null ? gen.verifierSlot.unlockSkip(preT, tail) : gen.verifierSlot.unlockProof(_proofs[tr]!, tr.publics, preT, tail);
      spends(u, vlock, tx, 1 + t, 1);
    }
    // input k+1: the append slot
    final alock = gen.appendSlot.lock();
    final preA = preimage(tx, k + 1, alock, 1, SlotScript_single);
    spends(gen.appendSlot.unlock(preA, prevoutsAfter(tx, 1), j, rootBefore, siblings, cms), alock, tx, k + 1, 1);
    print('  ${label ?? 'round'}: state lock ${lock.buffer.length} B, state unlock ${unlock0.buffer.length} B, '
        'tx ${tx.serialize().length ~/ 2 + unlock0.buffer.length} B, all inputs verified in ${sw.elapsedMilliseconds} ms');
    return (next, out, 'ee${tx.id.substring(2)}');
  }

  late PP1SpLegacyHeader h2, h3;
  late int vault2, vault3;
  late String txid2;
  final skA = lanes(5), dA = lanes(3);
  final noteA = OutputNote(pkd: PoolHash.pkd(skA, dA), value: 700000, rho: lanes(3), rcm: lanes(4));
  late PP1SpLegacyTransfer deposit;

  test('round 1: a deposit and an unused slot', () {
    final db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final dc = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final nb = OutputNote(pkd: lanes(8), value: 5, rho: lanes(3), rcm: lanes(4));
    final extra = change;
    final w = PoolSpendAir.witness(db, dc, noteA, nb, -(noteA.value + nb.value),
        anchor: NullifierSet.toLanes(h1.cmRoot), outHash: PoolPublicInputs.outHashLanes(extra));
    _proofs[deposit = PP1SpLegacyTransfer(w.publics, extra, ins(w.publics.real1, w.publics.nf1), ins(w.publics.real2, w.publics.nf2))] =
        StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(1));
    (h2, vault2, txid2) = round(h1, createVault, createTxid, [deposit, null], funding: [inputAt('f0' * 32, 0)], label: 'round 1 (deposit)');
    expect(vault2, createVault + noteA.value + nb.value);
    expect(h2.size, NoteCommitmentTree.subtreeLeaves);
    expect(h2.ring[1], h1.ring[0]);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('round 2: the deposited note is spent, part of it unshielded', () {
    final path = tree.path(0);
    final a = SpendNote(sk: skA, d: dA, value: noteA.value, rho: noteA.rho, rcm: noteA.rcm, siblings: path.siblings, position: 0);
    expect(a.cm, noteA.cm);
    expect(a.root, tree.root);
    final dummy = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 600000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 50000, rho: lanes(3), rcm: lanes(4));
    final payee = SlotScript_output(40000, hex.decode('76a914${'33' * 20}88ac'));
    final w = PoolSpendAir.witness(a, dummy, oa, ob, noteA.value - oa.value - ob.value,
        outHash: PoolPublicInputs.outHashLanes(payee));
    expect(w.publics.anchor, NullifierSet.toLanes(h2.cmRoot));
    final tr = PP1SpLegacyTransfer(w.publics, payee, ins(w.publics.real1, w.publics.nf1), ins(w.publics.real2, w.publics.nf2));
    _proofs[tr] = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(2));
    late String txid3;
    (h3, vault3, txid3) = round(h2, vault2, txid2, [tr, null], label: 'round 2 (spend)');
    expect(vault3, vault2 - 50000);
    expect(h3.ring[2], h1.ring[0]);
    // the same transfer again: its nullifiers are in the set now
    expect(() => round(h3, vault3, txid3, [tr, null]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('the state rejects an anchor outside the ring and slots from elsewhere', () {
    // a deposit proof naming a root the pool never had
    final db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final dc = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final na = OutputNote(pkd: lanes(8), value: 10, rho: lanes(3), rcm: lanes(4));
    final nb = OutputNote(pkd: lanes(8), value: 5, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(db, dc, na, nb, -15, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    final tr = PP1SpLegacyTransfer(w.publics, Uint8List(0), ins(w.publics.real1, w.publics.nf1), ins(w.publics.real2, w.publics.nf2));
    _proofs[tr] = StarkProver.prove(p, PoolSpendAir.air(w.publics), w.rows, rng: Random(4));
    expect(() => round(h3, vault3, 'd3' * 32, [tr, null]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));
}

final _proofs = <PP1SpLegacyTransfer, StarkProof>{};
const SlotScript_single = 0x43;
Uint8List SlotScript_output(int sats, List<int> script) {
  final v = ByteData(8)..setUint64(0, sats, Endian.little);
  return Uint8List.fromList([...v.buffer.asUint8List(), script.length, ...script]);
}
