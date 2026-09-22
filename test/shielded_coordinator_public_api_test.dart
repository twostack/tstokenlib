import 'dart:math';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

import 'pool_round_v_test.dart' show opKey, sigHashAll;
import 'pool_test_chain.dart';

/// The package's public surface is enough to run a pool: open a
/// coordinator on the test chain, submit a transfer as a message, close a
/// round and announce it, with nothing imported from `src/`.
void main() {
  test('a coordinator opens, takes a submission, closes a round and announces it through the public API alone', () async {
    final c = await PoolTestChain.build();
    final signer = DefaultTransactionSigner(sigHashAll, opKey);
    final opPub = opKey.publicKey;
    final opAddr = Address.fromPublicKey(opPub, NetworkType.TEST);
    final published = <String>[];
    final stored = <int>[];
    final co = ShieldedCoordinator.open(
        config: CoordinatorConfig(plan: c.f.agg, paddingStock: 3),
        tool: ShieldedPoolTool(),
        issuance: c.r0,
        witness0: c.w0,
        slot0: c.y0.tx,
        funding: _Funding(signer, opPub, opAddr),
        store: _Store(stored),
        publish: (tx) async => published.add(tx.id),
        owner: signer,
        ownerPub: opPub,
        clock: FakeClock());
    await co.runIdleWork();
    expect(co.padding.stock, 3);

    final d = c.f.transfers1[0];
    final transfer = ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: c.depositOutpoint);
    final submission = PoolSubmission.of(transfer, c.f.agg.spendP, depositTx: c.depositTx, rng: Random(1));
    final reply = co.submitBytes(submission.encode());
    expect(reply, isNotNull);
    expect(PoolReply.decode(reply!.encode()).outcome, ReplyOutcome.accepted);
    expect(reply.round, 1);

    final a = await co.closeRound();
    expect(a, isNotNull, reason: '${co.lastFailure}');
    expect(a!.round, 1);
    expect(published, [a.slotId, a.roundId, a.witnessId]);
    expect(stored, [1]);
    final descriptor = co.descriptor(NetworkType.TEST, c.r0, c.w0, c.y0.tx);
    expect(hex.encode(PoolDescriptor.decode(descriptor.encode()).issuance), c.r0.id);
    expect(co.status.rounds, 1);
    expect(co.lastTiming!.stages.keys, contains('aggregation'));
  }, timeout: const Timeout(Duration(minutes: 5)));
}

class _Funding implements CoordinatorFunding {
  final TransactionSigner signer;
  final SVPublicKey pubKey;
  final Address to;
  int _n = 0;
  _Funding(this.signer, this.pubKey, this.to);

  @override
  Future<FundingOutput?> output(BigInt minValue) async {
    final prev = List.filled(32, 0x60)..[0] = _n++;
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0
      ..addInput(TransactionInput(hex.encode(prev), 0, TransactionInput.MAX_SEQ_NUMBER))
      ..addOutput(TransactionOutput(minValue, P2PKHLockBuilder.fromAddress(to).getScriptPubkey()));
    return FundingOutput(tx, 0, signer, pubKey);
  }
}

class _Store implements CoordinatorStore {
  final List<int> numbers;
  _Store(this.numbers);
  @override
  Future<void> roundBuilt(int number, Transaction y, Transaction round, Transaction witness, List<int> snapshot) async => numbers.add(number);
}
