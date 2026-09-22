import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';

import 'pool_chain_fixture.dart';
import 'pool_round_v_test.dart' show opKey, strangerKey, opPKH, sigHashAll, fundingA, fundingB, slotFunding;

/// The fixture's two rounds as transactions, built the way
/// `pool_round_v_test` builds them: issuance R0, witness W0, slots Y0 to
/// Y2, the depositor's covenant D, rounds R1 and R2 and their witnesses.
/// Nothing here runs a script; the round V test does that for the same
/// chain.
class PoolTestChain {
  final PoolChainFixture f;
  final ShieldedPoolTool svc = ShieldedPoolTool();
  final TransactionSigner signer = DefaultTransactionSigner(sigHashAll, opKey);
  final SVPublicKey opPub = opKey.publicKey;

  late final ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1, y2;
  late final Transaction r0, w0, depositTx, r1, w1, r2, w2;
  late final List<int> depositOutpoint;

  PoolTestChain._(this.f);

  static Future<PoolTestChain> build({bool production = false}) async {
    final f = await PoolChainFixture.prove(
        withdrawalPKH: hex.decode(strangerKey.publicKey.toAddress(NetworkType.TEST).pubkeyHash160), production: production);
    return PoolTestChain._(f).._build();
  }

  ({Transaction tx, List<int> outpoint, List<int> parts}) slot(PoolHeader h, int n) => svc.buildSlotTxn(
      header: h, verifierBody: f.body, fundingInput: slotFunding(n), anchorPKH: hex.decode(opPKH), signerPKH: hex.decode(opPKH));

  void _build() {
    final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);
    final bodyHash = crypto.sha256.convert(f.body).bytes;
    y0 = slot(f.g, 0x20);
    y1 = slot(f.h1, 0x21);
    y2 = slot(f.h2, 0x22);
    r0 = svc.createTokenIssuanceTxn(fundingA, signer, opPub, opAddr, bodyHash, f.g, y0.outpoint, fundingB.hash, slotTx: y0.tx);
    w0 = svc.createWitnessTxn(signer, fundingB, r0, hex.decode(fundingA.serialize()), opPub, opPKH, ShieldedPoolAction.CREATE,
        slotParts: y0.parts, verifierBody: f.body);
    final depositor = strangerKey.publicKey.toAddress(NetworkType.TEST);
    final coins = Transaction()
      ..addInputs([slotFunding(0x30)])
      ..addOutputs([TransactionOutput(BigInt.from(10000), P2PKHLockBuilder.fromAddress(depositor).getScriptPubkey())]);
    depositTx = svc.createDepositTxn(
        fundingTx: coins,
        fundingVout: 0,
        fundingSigner: DefaultTransactionSigner(0x41, strangerKey),
        fundingPubKey: strangerKey.publicKey,
        changeAddress: depositor,
        commitment: f.receipt.commitment,
        satoshis: f.receipt.satoshis,
        pp3Outpoint: svc.getOutpoint(r0.hash, outputIndex: 3),
        refundPKH: hex.decode(depositor.pubkeyHash160),
        refundAfter: 1000);
    depositOutpoint = svc.getOutpoint(depositTx.hash, outputIndex: ShieldedPoolTool.depositVout);
    r1 = round1();
    w1 = witness1(r1);
    r2 = round2(r1, w1);
    w2 = witness2(r2, r1);
  }

  Transaction round1({PoolHeader? header, ({Transaction tx, List<int> outpoint, List<int> parts})? next, UnlockingScriptBuilder? slotUnlocker}) {
    final y = next ?? y1;
    return svc.createRoundTxn(w0, r0, y0.tx, opPub, fundingA, signer, opPub, fundingB.hash, header ?? f.h1, y.outpoint,
        nextSlotTx: y.tx,
        receipts: [f.receipt],
        deposits: [(depositTx, ShieldedPoolTool.depositVout)],
        roundProof: slotUnlocker == null ? f.proof : null,
        slotUnlocker: slotUnlocker);
  }

  Transaction witness1(Transaction r1, {PoolHeader? header, ({Transaction tx, List<int> outpoint, List<int> parts})? next, List<int>? bundles}) {
    final y = next ?? y1;
    return svc.createWitnessTxn(signer, fundingB, r1, hex.decode(r0.serialize()), opPub, opPKH, ShieldedPoolAction.ROUND,
        newOwnerPKH: hex.decode(opPKH),
        newHeader: (header ?? f.h1).encode(),
        nextSlot: y.outpoint,
        slotParts: y.parts,
        verifierBody: f.body,
        bundles: bundles ?? f.bundles,
        receipts: [f.receipt]);
  }

  Transaction round2(Transaction r1, Transaction w1,
      {PoolHeader? header, ({Transaction tx, List<int> outpoint, List<int> parts})? next, UnlockingScriptBuilder? slotUnlocker}) {
    final y = next ?? y2;
    return svc.createRoundTxn(w1, r1, y1.tx, opPub, fundingA, signer, opPub, fundingB.hash, header ?? f.h2, y.outpoint,
        nextSlotTx: y.tx,
        withdrawals: [f.withdrawal],
        roundProof: slotUnlocker == null ? f.proof2 : null,
        slotUnlocker: slotUnlocker);
  }

  Transaction witness2(Transaction r2, Transaction r1,
      {PoolHeader? header, ({Transaction tx, List<int> outpoint, List<int> parts})? next, List<int>? bundles}) {
    final y = next ?? y2;
    return svc.createWitnessTxn(signer, fundingB, r2, hex.decode(r1.serialize()), opPub, opPKH, ShieldedPoolAction.ROUND,
        newOwnerPKH: hex.decode(opPKH),
        newHeader: (header ?? f.h2).encode(),
        nextSlot: y.outpoint,
        slotParts: y.parts,
        verifierBody: f.body,
        bundles: bundles ?? f.bundles2,
        withdrawals: [f.withdrawal]);
  }

  /// The unlock V's slot takes in round 1 or 2 as the tool built it.
  List<int> vUnlock(Transaction round) => round.inputs[2].script!.buffer;
}
