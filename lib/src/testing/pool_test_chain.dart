import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/shielded_pool/pool_evidence.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';

import 'pool_chain_fixture.dart';

/// The keys and funding the test chain is built from.
///
/// They are fixed, published, worthless regtest keys: the chain has to come
/// out byte-identical every run, in this suite and in any package that builds
/// on it, or a test that compares two chains is comparing two different pools.
/// Nothing here is ever a real key, and nothing here is derived from one.
class PoolTestKeys {
  static final op = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  static final stranger = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
  static const opPKH = '650c4adb156f19e36a755c820d892cda108299c4';
  static final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  /// Two funding transactions with an output to [op], one for the round's
  /// fees and one for the witness's.
  static final fundingA = Transaction.fromHex(
      '0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000');
  static final fundingB = Transaction.fromHex(
      '0300000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000');

  /// A funding input naming an outpoint that exists only in this fixture.
  static TransactionInput slotFunding(int n) => TransactionInput(hex.encode(List.filled(32, n)), 0, 0xffffffff);
}

final opKey = PoolTestKeys.op;
final strangerKey = PoolTestKeys.stranger;
const opPKH = PoolTestKeys.opPKH;
final sigHashAll = PoolTestKeys.sigHashAll;
final fundingA = PoolTestKeys.fundingA;
final fundingB = PoolTestKeys.fundingB;
TransactionInput slotFunding(int n) => PoolTestKeys.slotFunding(n);

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

  /// The pool's identity as a descriptor publishes it, read off the
  /// issuance's own PP1 through the body check.
  late final PP1Fields identity = (() {
    final (fields, why) = PoolEvidence.readPP1Of(r0, PoolEvidence.pp1Vout);
    if (fields == null) throw StateError('the issuance carries no PP1_SP ($why)');
    return fields;
  })();

  List<int> get tokenId => identity.tokenId;
  List<int> get genesisHeader => identity.genesisHeader;

  static Future<PoolTestChain> build({bool production = false}) async {
    final f = await PoolChainFixture.prove(
        withdrawalPKH: hex.decode(strangerKey.publicKey.toAddress(NetworkType.TEST).pubkeyHash160), production: production);
    return PoolTestChain._(f).._build();
  }

  /// The pool's descriptor, as its coordinator puts it first on the feed.
  PoolDescriptor descriptor({int catchUpRange = 1024}) => PoolDescriptor.forPool(
      network: NetworkType.TEST, issuance: r0, witness0: w0, slot0: y0.tx, plan: f.agg, catchUpRange: catchUpRange);

  /// The chain as a pool answers catch-up from it, with rounds up to
  /// [minedTip] (0 to 2) mined, so a wallet's fake pool answers exactly as a
  /// coordinator does ([responder]).
  ///
  /// The fixture has no blocks, so where a witness sits is [placement]'s to
  /// say. Without one, each witness is alone in a block: index 0, an empty
  /// branch, and a merkle root equal to its txid, which stands in for the
  /// block hash; a test that checks the branch against headers of its own
  /// passes a placement naming them.
  CatchUpSource catchUpSource({int minedTip = 2, TestPlacement? placement}) {
    if (minedTip < 0 || minedTip > 2) throw RangeError.range(minedTip, 0, 2, 'minedTip');
    return _TestChainSource(this, minedTip, placement ?? _alone);
  }

  /// [catchUpSource] behind the pool's own rules for answering.
  PoolCatchUpResponder responder({int minedTip = 2, TestPlacement? placement, int catchUpRange = 1024}) =>
      PoolCatchUpResponder(descriptor(catchUpRange: catchUpRange), catchUpSource(minedTip: minedTip, placement: placement));

  static ({List<int> blockHash, int txIndex, List<List<int>> branch}) _alone(int round, Transaction witness) =>
      (blockHash: hex.decode(witness.id), txIndex: 0, branch: const <List<int>>[]);

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

/// Where the test chain's round [round] has its [witness] mined: the block,
/// the witness's index in it and its merkle branch.
typedef TestPlacement = ({List<int> blockHash, int txIndex, List<List<int>> branch}) Function(int round, Transaction witness);

class _TestChainSource implements CatchUpSource {
  final PoolTestChain c;
  @override
  final int minedTip;
  final TestPlacement placement;
  final ShieldedLedger ledger;

  _TestChainSource(this.c, this.minedTip, this.placement)
      : ledger = ShieldedLedger.open(ShieldedPoolLayout.of(c.f.agg.tree), c.r0, c.w0, c.y0.tx,
            tokenId: c.tokenId, genesisHeader: c.genesisHeader) {
    ledger.apply(c.r1, c.w1, c.y1.tx);
    ledger.apply(c.r2, c.w2, c.y2.tx);
  }

  void _check(int round) {
    if (round < 1 || round > minedTip) throw RangeError.range(round, 1, minedTip, 'round');
  }

  @override
  List<int> blockRootOf(int round) {
    _check(round);
    return ledger.blockRootOf(round);
  }

  @override
  ({int round, List<int> blockRoot, List<List<int>> left}) frontierAt(int round) {
    _check(round);
    return ledger.frontierAt(round);
  }

  @override
  Future<MinedRound?> mined(int round) async {
    _check(round);
    final (r, w) = round == 1 ? (c.r1, c.w1) : (c.r2, c.w2);
    final at = placement(round, w);
    return MinedRound(
        number: round,
        roundTx: hex.decode(r.serialize()),
        witnessTx: hex.decode(w.serialize()),
        blockHash: at.blockHash,
        txIndex: at.txIndex,
        branch: at.branch);
  }

  @override
  Future<RoundPlace?> placed(int round) async {
    _check(round);
    final (r, w) = round == 1 ? (c.r1, c.w1) : (c.r2, c.w2);
    final at = placement(round, w);
    return RoundPlace(
        number: round,
        roundTxId: hex.decode(r.id),
        witnessTxId: hex.decode(w.id),
        blockHash: at.blockHash,
        txIndex: at.txIndex,
        branch: at.branch);
  }
}
