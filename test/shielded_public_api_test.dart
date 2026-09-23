// Uses the pool through package:tstokenlib/tstokenlib.dart alone: the
// chain helper builds the transactions, and everything this file does with
// them, a wallet can do with the public library.
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

import 'pool_test_chain.dart';
import 'pool_verifier_proof_test.dart' show spendP;

void main() {
  late PoolTestChain c;
  setUpAll(() async => c = await PoolTestChain.build());

  test('a wallet decodes a transfer and reads the test chain with the public library only', () async {
    final StarkParams p = spendP;
    final bytes = c.f.transfers2[0].encode(p);
    final t = ShieldedTransfer.decode(bytes, p);
    expect(t.refusal(), isNull);
    expect(t.withdrawal!.satoshis, BigInt.from(300));
    expect(() => ShieldedTransfer.decode(bytes.sublist(1), p), throwsA(isA<TransferRefusal>()));

    final layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
    final reader = ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader)
      ..read([
        (round: c.r1, witness: c.w1, nextSlot: c.y1.tx),
        (round: c.r2, witness: c.w2, nextSlot: c.y2.tx),
      ]);
    final PoolHeader h = reader.ledger.header;
    expect(h.encode(), c.f.h2.encode());
    final PoolWalletKeys keys = c.f.wallet;
    final scanner = ShieldedNoteScanner.forWallet(keys, [c.f.walletD]);
    for (final r in reader.rounds) {
      await scanner.scan(r);
    }
    final List<ScannedNote> mine = scanner.unspent;
    expect([for (final n in mine) n.value], [200]);
    final MerklePath path = reader.ledger.path(mine.single.position);
    expect(path.position, mine.single.position);
    final List<PoolReceipt> receipts = reader.rounds[0].receipts;
    expect(receipts.single.satoshis, BigInt.from(500));
    final NotePlaintext note = mine.single.note;
    expect(note.value, 200);
    expect(ShieldedTransfer.productionParams.numQueries, 11);
    expect(ShieldedPoolLayout.production.transfers, 256);
  });
}
