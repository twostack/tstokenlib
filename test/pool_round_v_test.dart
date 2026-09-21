import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_ft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'pool_verifier_proof_test.dart' show spendP, p1, p2, rootP;

final opKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
final strangerKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
const opPKH = '650c4adb156f19e36a755c820d892cda108299c4';
final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
final flags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

final fundingA = Transaction.fromHex(
    '0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000');
final fundingB = Transaction.fromHex(
    '0300000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000');

TransactionInput slotFunding(int n) => TransactionInput(hex.encode(List.filled(32, n)), 0, 0xffffffff);

void spends(Transaction tx, int input, TransactionOutput spent) => Interpreter().correctlySpends(
    tx.inputs[input].script!, spent.script, tx, input, flags, Coin.valueOf(spent.satoshis));

/// A pool issued with the real V, and its first round built by
/// [ShieldedPoolTool.createRoundTxn] from a real root proof. From genesis
/// the tree is empty, so round 1 can only take deposits in: one of 500
/// through receipt slot 0, and three padding transfers.
void main() {
  final rng = Random(71);
  List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));
  final svc = ShieldedPoolTool();
  final signer = DefaultTransactionSigner(sigHashAll, opKey);
  final opPub = opKey.publicKey;
  final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);

  late PoolAggregation agg;
  late PoolVerifierGen v;
  late List<int> body;
  late PoolHeader g, h1;
  late ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1;
  late Transaction r0, w0;
  late PoolRoundProof proof;
  late List<int> bundles;
  late PoolReceipt receipt;

  Transaction round({PoolRoundProof? withProof, TransactionSigner? slotSigner, List<PoolReceipt>? receipts}) =>
      svc.createRoundTxn(w0, r0, y0.tx, opPub, fundingA, signer, opPub, fundingB.hash, h1, y1.outpoint,
          nextSlotTx: y1.tx, receipts: receipts ?? [receipt], roundProof: withProof ?? proof, slotSigner: slotSigner);

  setUpAll(() async {
    final sw = Stopwatch()..start();
    agg = PoolAggregation(
        spendP: spendP,
        levelSpec: const [
          AggregationLevel(params: p1, logTrace: 15, arity: 2),
          AggregationLevel(params: p2, logTrace: 17, arity: 2),
        ],
        rootP: rootP,
        rootLog: 15,
        nullifierLevel: 1,
        receiptSlots: 2);
    final stmt = PoolStatement.of(agg.tree);
    v = ShieldedPoolTool.poolVerifier(stmt,
        verifier: StarkVerifierGen(rootP, agg.rootAir(List.filled(stmt.numPublics, 0))));
    body = v.body();

    final cmTree = NoteCommitmentTree();
    final nullifiers = NullifierTree();
    g = PoolHeader.genesis(
        emptyCmRoot: SlotScript.lanesBytes(cmTree.root), emptyNfRoot: SlotScript.lanesBytes(nullifiers.root));
    final ring = List.filled(4, cmTree.root);

    // the round: a deposit of 500 and three padding transfers, each with its
    // ciphertext bundle
    final perTransfer = [for (int t = 0; t < 4; t++) List<int>.generate(40 + t, (i) => (i * 7 + t) & 0xff)];
    final c = [for (final b in perTransfer) PoolOutHash.bundleHash(b)];
    bundles = PoolOutHash.encodeBundles(perTransfer);
    SpendNote dummy() => SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    OutputNote out(int v) => OutputNote(pkd: lanes(8), value: v, rho: lanes(3), rcm: lanes(4));
    final witnesses = [
      PoolSpendAir.witness(dummy(), dummy(), out(500), out(0), -500,
          outHash: PoolOutHash.transferLanes(c[0]), anchor: lanes(8)),
      for (int t = 1; t < 4; t++)
        PoolSpendAir.witness(dummy(), dummy(), out(0), out(0), 0,
            outHash: PoolOutHash.transferLanes(c[t]), anchor: lanes(8)),
    ];
    final publics = [for (final w in witnesses) w.publics];
    final spendProofs = [
      for (int t = 0; t < 4; t++)
        StarkProver.prove(spendP, PoolSpendAir.air(publics[t]), witnesses[t].rows, rng: Random(1), hash: const Poseidon2ProofHash())
    ];
    final rootBefore = cmTree.root;
    final j = cmTree.nextSubtree, paths = <List<List<int>>>[];
    final spendLanes = [for (final p in publics) p.toLanes()];
    for (int s = 0; s < agg.tree.subtrees; s++) {
      paths.add(cmTree.subtreePath(j + s));
      cmTree.appendSubtree([for (final l in agg.tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final (rootProof, wide) = await agg.aggregate(publics, spendProofs,
        rootBefore: rootBefore,
        rootAfter: cmTree.root,
        index: j,
        paths: paths,
        ring: ring,
        nullifiers: nullifiers,
        receiptTransfers: const [0],
        rng: Random(3));
    proof = PoolRoundProof.root(rootP, agg.rootAir(wide), rootProof, c);
    receipt = PoolReceipt(SlotScript.lanesBytes(publics[0].cmOut1), BigInt.from(500));
    h1 = g.advance(
        cmRoot: SlotScript.lanesBytes(cmTree.root),
        nfRoot: SlotScript.lanesBytes(nullifiers.root),
        size: stmt.leavesAppended,
        balance: g.balance + BigInt.from(500),
        outHash: PoolOutHash.roundOutHash(c));
    print('  proved round 1 and built V (${body.length} B) in ${sw.elapsedMilliseconds} ms');

    final bodyHash = crypto.sha256.convert(body).bytes;
    y0 = svc.buildSlotTxn(header: g, verifierBody: body, fundingInput: slotFunding(0x20),
        anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));
    y1 = svc.buildSlotTxn(header: h1, verifierBody: body, fundingInput: slotFunding(0x21),
        anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));
    r0 = svc.createTokenIssuanceTxn(fundingA, signer, opPub, opAddr, bodyHash, g, y0.outpoint, fundingB.hash, slotTx: y0.tx);
    w0 = svc.createWitnessTxn(signer, fundingB, r0, hex.decode(fundingA.serialize()), opPub, opPKH, ShieldedPoolAction.CREATE,
        slotParts: y0.parts, verifierBody: body);
  });

  test('V accepts round 1 as createRoundTxn builds it, and the rest of the chain accepts it too', () {
    final sw = Stopwatch()..start();
    final r1 = round();
    final size = hex.decode(r1.serialize()).length;
    print('  round 1: $size B, V unlock ${r1.inputs[2].script!.buffer.length} B, built in ${sw.elapsedMilliseconds} ms');
    sw.reset();
    spends(r1, 2, y0.tx.outputs[0]);
    print('  V ran in ${sw.elapsedMilliseconds} ms');
    spends(r1, 3, r0.outputs[3]);
    spends(r1, 4, y1.tx.outputs[1]);
    expect(r1.outputs[3].satoshis, BigInt.from(501));
    final w1 = svc.createWitnessTxn(signer, fundingB, r1, hex.decode(r0.serialize()), opPub, opPKH, ShieldedPoolAction.ROUND,
        newOwnerPKH: hex.decode(opPKH),
        newHeader: h1.encode(),
        nextSlot: y1.outpoint,
        slotParts: y1.parts,
        verifierBody: body,
        bundles: bundles,
        receipts: [receipt]);
    spends(w1, 1, r1.outputs[1]);
    print('  witness 1: ${hex.decode(w1.serialize()).length} B');
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('V refuses the round signed by a key other than the one its slot names', () {
    // The unlock names the owner's key, which hashes to the slot's signer,
    // so what refuses the stranger is the signature not verifying against it.
    // A stranger's own key is refused by the hash check, tested in
    // pool_verifier_test.
    final r1 = round(slotSigner: DefaultTransactionSigner(sigHashAll, strangerKey));
    expect(() => spends(r1, 2, y0.tx.outputs[0]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('V refuses a round that leaves the deposit\'s receipt off', () {
    final r1 = round(receipts: []);
    expect(() => spends(r1, 2, y0.tx.outputs[0]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('the tool refuses a slot signer that does not sign SIGHASH_ALL', () {
    final single = DefaultTransactionSigner(SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_SINGLE.value, opKey);
    expect(() => round(slotSigner: single), throwsArgumentError);
  });

  test('a proof for another round is refused', () {
    // the same proof, but bundle hashes that are not the ones it committed to
    final other = PoolRoundProof(proof.belowTail, [for (final c in proof.bundleHashes) List<int>.filled(32, c[0] ^ 1)]);
    final r1 = round(withProof: other);
    expect(() => spends(r1, 2, y0.tx.outputs[0]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  group('the pool reads 4-byte varints', () {
    // A round whose input 2 unlock is over 64 KB, as V's is in production:
    // its length is a 0xfe varint. Input 3's outpoint is what PP1 reads.
    List<int> rawTx(int inputs, {int bigInput = 2, int bigSize = 70000}) {
      final out = <int>[1, 0, 0, 0, inputs];
      for (int i = 0; i < inputs; i++) {
        out.addAll(List.filled(32, 0x40 + i));
        out.addAll([i, 0, 0, 0]);
        final n = i == bigInput ? bigSize : 1;
        out.addAll(n < 0xfd ? [n] : [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, 0]);
        out.addAll(List.filled(n, 0x51));
        out.addAll([0xff, 0xff, 0xff, 0xff]);
      }
      out.addAll([1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a, 0, 0, 0, 0]);
      return out;
    }

    List<int> outpoint3(List<int> tx, {required bool wide}) {
      final b = ScriptBuilder()..addData(Uint8List.fromList(tx));
      PP1FtScriptGen.emitReadOutpoint(b, 3, wide: wide);
      b.addData(Uint8List.fromList([...List.filled(32, 0x43), 3, 0, 0, 0]));
      b.opCode(OpCodes.OP_EQUAL);
      final interp = Interpreter();
      try {
        interp.correctlySpends(ScriptBuilder().build(), b.build(), Transaction(), 0, flags, Coin.valueOf(BigInt.zero));
        return [1];
      } catch (_) {
        return [0];
      }
    }

    test('input 3\'s outpoint, past a 70 KB unlock at input 2', () {
      expect(outpoint3(rawTx(5), wide: true), [1]);
      expect(outpoint3(rawTx(5), wide: false), [0], reason: 'the narrow reader lands inside input 2');
    });

    test('a transaction with more inputs than PP1 walks is refused, not half-parsed', () {
      void skip(List<int> tx) {
        final b = ScriptBuilder()..addData(Uint8List.fromList(tx));
        PP1FtScriptGen.emitSkipInputs(b, wide: true, maxInputs: PP1SpScriptGen.poolMaxInputs);
        b.opCode(OpCodes.OP_DROP);
        b.opCode(OpCodes.OP_1);
        Interpreter().correctlySpends(ScriptBuilder().build(), b.build(), Transaction(), 0, flags, Coin.valueOf(BigInt.zero));
      }
      skip(rawTx(PP1SpScriptGen.poolMaxInputs, bigSize: 1));
      expect(() => skip(rawTx(PP1SpScriptGen.poolMaxInputs + 1, bigSize: 1)), throwsA(isA<ScriptException>()));
    });
  });
}
