import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/pool_deposit_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_ft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'pool_chain_fixture.dart';

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

/// [tx]'s [input] spends [spent], and leaves the stack clean. Nodes relay
/// only transactions whose scripts leave exactly one item (the CLEANSTACK
/// policy), and dartsv enforces that only on version-1 transactions, so it
/// is counted here.
void spends(Transaction tx, int input, TransactionOutput spent) {
  Interpreter().correctlySpends(
      tx.inputs[input].script!, spent.script, tx, input, flags, Coin.valueOf(spent.satoshis));
  final stack = InterpreterStack<List<int>>();
  final copy = Transaction.fromHex(tx.serialize());
  Interpreter()
    ..executeScript(copy, input, tx.inputs[input].script!, stack, spent.satoshis, flags, lockingScript: spent.script)
    ..executeScript(copy, input, spent.script, stack, spent.satoshis, flags, lockingScript: spent.script);
  if (stack.size() != 1) {
    throw ScriptException(ScriptError.SCRIPT_ERR_CLEANSTACK, 'input $input leaves ${stack.size()} items');
  }
}

/// A pool issued with the real V, and its first two rounds built by
/// [ShieldedPoolTool.createRoundTxn] from real root proofs. From genesis
/// the tree is empty, so round 1 can only take deposits in: one of 500
/// through receipt slot 0, and three padding transfers. Round 2 spends that
/// deposit's note, keeping 200 in the pool and withdrawing 300.
void main() {
  final svc = ShieldedPoolTool();
  final signer = DefaultTransactionSigner(sigHashAll, opKey);
  final opPub = opKey.publicKey;
  final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);

  late List<int> body;
  late PoolHeader g, h1, h2;
  late ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1, y2;
  late Transaction r0, w0;
  late PoolRoundProof proof, proof2;
  late List<int> bundles, bundles2;
  late PoolReceipt receipt;
  late PoolWithdrawal withdrawal;
  late Transaction depositTx;
  late (Transaction, int) deposit;

  Transaction round(
          {PoolRoundProof? withProof, TransactionSigner? slotSigner, List<PoolReceipt>? receipts, List<(Transaction, int)>? deposits}) =>
      svc.createRoundTxn(w0, r0, y0.tx, opPub, fundingA, signer, opPub, fundingB.hash, h1, y1.outpoint,
          nextSlotTx: y1.tx,
          receipts: receipts ?? [receipt],
          deposits: deposits ?? [deposit],
          roundProof: withProof ?? proof,
          slotSigner: slotSigner);

  setUpAll(() async {
    final sw = Stopwatch()..start();
    final f = await PoolChainFixture.prove(
        withdrawalPKH: hex.decode(strangerKey.publicKey.toAddress(NetworkType.TEST).pubkeyHash160));
    body = f.body;
    (g, h1, h2) = (f.g, f.h1, f.h2);
    (proof, proof2) = (f.proof, f.proof2);
    (bundles, bundles2) = (f.bundles, f.bundles2);
    receipt = f.receipt;
    withdrawal = f.withdrawal;
    print('  proved rounds 1 and 2 and built V (${body.length} B) in ${sw.elapsedMilliseconds} ms');

    final bodyHash = crypto.sha256.convert(body).bytes;
    y0 = svc.buildSlotTxn(header: g, verifierBody: body, fundingInput: slotFunding(0x20),
        anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));
    y1 = svc.buildSlotTxn(header: h1, verifierBody: body, fundingInput: slotFunding(0x21),
        anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));
    y2 = svc.buildSlotTxn(header: h2, verifierBody: body, fundingInput: slotFunding(0x22),
        anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));
    r0 = svc.createTokenIssuanceTxn(fundingA, signer, opPub, opAddr, bodyHash, g, y0.outpoint, fundingB.hash, slotTx: y0.tx);
    w0 = svc.createWitnessTxn(signer, fundingB, r0, hex.decode(fundingA.serialize()), opPub, opPKH, ShieldedPoolAction.CREATE,
        slotParts: y0.parts, verifierBody: body);
    // the depositor pays into a covenant targeting round 1 by naming PP3_0,
    // and the coordinator finds it among what it was sent
    final depositor = strangerKey.publicKey.toAddress(NetworkType.TEST);
    final depositorCoins = Transaction()
      ..addInputs([slotFunding(0x30)])
      ..addOutputs([TransactionOutput(BigInt.from(10000), P2PKHLockBuilder.fromAddress(depositor).getScriptPubkey())]);
    final pp3Of0 = svc.getOutpoint(r0.hash, outputIndex: 3);
    depositTx = svc.createDepositTxn(
        fundingTx: depositorCoins,
        fundingVout: 0,
        fundingSigner: DefaultTransactionSigner(0x41, strangerKey),
        fundingPubKey: strangerKey.publicKey,
        changeAddress: depositor,
        commitment: receipt.commitment,
        satoshis: receipt.satoshis,
        pp3Outpoint: pp3Of0,
        refundPKH: hex.decode(depositor.pubkeyHash160),
        refundAfter: 1000);
    final found = ShieldedPoolTool.findDeposits([depositorCoins, depositTx], pp3Of0, minRefundAfter: 1000);
    expect(found.length, 1);
    expect(found[0].receipt.lockingScript.buffer, receipt.lockingScript.buffer);
    deposit = (found[0].tx, found[0].vout);
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
    spends(r1, 5, depositTx.outputs[ShieldedPoolTool.depositVout]);
    expect(r1.inputs.length, 6, reason: 'the deposit covenant at input 5');
    expect(r1.outputs[5].script.buffer, receipt.lockingScript.buffer, reason: 'its receipt at output 5');
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

  Transaction witness1(Transaction r1) =>
      svc.createWitnessTxn(signer, fundingB, r1, hex.decode(r0.serialize()), opPub, opPKH, ShieldedPoolAction.ROUND,
          newOwnerPKH: hex.decode(opPKH),
          newHeader: h1.encode(),
          nextSlot: y1.outpoint,
          slotParts: y1.parts,
          verifierBody: body,
          bundles: bundles,
          receipts: [receipt]);

  Transaction round2(Transaction r1, Transaction w1, {List<PoolWithdrawal>? withdrawals}) =>
      svc.createRoundTxn(w1, r1, y1.tx, opPub, fundingA, signer, opPub, fundingB.hash, h2, y2.outpoint,
          nextSlotTx: y2.tx, withdrawals: withdrawals ?? [withdrawal], roundProof: proof2);

  test('round 2 spends the deposited note and withdraws 300, through V and the rest of the chain', () {
    final r1 = round();
    final w1 = witness1(r1);
    final r2 = round2(r1, w1);
    spends(r2, 2, y1.tx.outputs[0]);
    spends(r2, 3, r1.outputs[3]);
    spends(r2, 4, y2.tx.outputs[1]);
    expect(r2.outputs[3].satoshis, BigInt.from(201), reason: 'PP3 keeps 501 - 300');
    final paid = r2.outputs.last;
    expect(paid.satoshis, BigInt.from(300));
    expect(paid.script.buffer, withdrawal.lockingScript.buffer);
    final w2 = svc.createWitnessTxn(signer, fundingB, r2, hex.decode(r1.serialize()), opPub, opPKH, ShieldedPoolAction.ROUND,
        newOwnerPKH: hex.decode(opPKH),
        newHeader: h2.encode(),
        nextSlot: y2.outpoint,
        slotParts: y2.parts,
        verifierBody: body,
        bundles: bundles2,
        withdrawals: [withdrawal]);
    spends(w2, 1, r2.outputs[1]);
    print('  round 2: ${hex.decode(r2.serialize()).length} B; witness 2: ${hex.decode(w2.serialize()).length} B');
    // the chain as JSON, for tool/scratch/two_round_probe.dart to lay out
    final dump = Platform.environment['POOL_CHAIN_DUMP'];
    if (dump != null) {
      File(dump).writeAsStringSync(jsonEncode({
        for (final (n, t) in [('Y0', y0.tx), ('Y1', y1.tx), ('Y2', y2.tx), ('R0', r0), ('W0', w0),
          ('D', depositTx), ('R1', r1), ('W1', w1), ('R2', r2), ('W2', w2)])
          n: t.serialize(),
        'fundingA': fundingA.serialize(),
        'fundingB': fundingB.serialize(),
      }));
    }
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('round 2 paying the withdrawal to someone else is refused by V', () {
    final r1 = round();
    final r2 = round2(r1, witness1(r1), withdrawals: [PoolWithdrawal(hex.decode(opPKH), BigInt.from(300))]);
    expect(() => spends(r2, 2, y1.tx.outputs[0]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('round 2 paying out more than the note held is refused by V', () {
    // the payee is right and so is everything the tool builds from h2; the
    // payout is 301 against a proof of 300
    final r1 = round();
    final more = PoolWithdrawal(withdrawal.pubkeyHash, BigInt.from(301));
    final r2 = svc.createRoundTxn(witness1(r1), r1, y1.tx, opPub, fundingA, signer, opPub, fundingB.hash, h2, y2.outpoint,
        nextSlotTx: y2.tx, withdrawals: [more], roundProof: proof2);
    expect(() => spends(r2, 2, y1.tx.outputs[0]), throwsA(isA<ScriptException>()));
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
    final r1 = round(receipts: [], deposits: []);
    expect(() => spends(r1, 2, y0.tx.outputs[0]), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('the tool refuses a deposit that does not match its receipt, or targets another round', () {
    expect(() => round(receipts: [PoolReceipt(receipt.commitment, BigInt.from(499))]), throwsArgumentError);
    final elsewhere = Transaction()
      ..addInputs([slotFunding(0x31)])
      ..addOutputs([
        TransactionOutput(
            BigInt.from(500),
            PoolDepositGen.lock(
                commitment: receipt.commitment,
                pp3Outpoint: svc.getOutpoint(r0.hash, outputIndex: 2),
                refundPKH: List.filled(20, 1),
                refundAfter: 1000))
      ]);
    expect(() => round(deposits: [(elsewhere, 0)]), throwsArgumentError);
  });

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
