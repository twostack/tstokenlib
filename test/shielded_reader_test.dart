import 'dart:io';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_chain_reader.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_ledger.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_note_scanner.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_transfer.dart';

import 'pool_test_chain.dart';

void main() {
  late PoolTestChain c;
  late ShieldedPoolLayout layout;

  setUpAll(() async {
    c = await PoolTestChain.build();
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
  });

  ShieldedChainReader reader() => ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
  List<ShieldedRoundTxs> mined() => [
        (round: c.r1, witness: c.w1, nextSlot: c.y1.tx),
        (round: c.r2, witness: c.w2, nextSlot: c.y2.tx),
      ];

  test('the deposit transfer implies the receipt the round carries at output 5', () {
    final d = c.f.transfers1[0];
    final backed = ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: c.depositOutpoint);
    expect(backed.refusal(), isNull);
    expect(backed.receipt!.lockingScript.buffer, c.r1.outputs[5].script.buffer);
    expect(backed.receipt!.satoshis, BigInt.from(500));
  });

  group('the chain reader', () {
    test('agrees with the builder on the two rounds as mined', () {
      final r = reader();
      final applied = r.read(mined());
      expect(applied.length, 2);
      expect(r.stopped, isFalse);
      expect(r.lastRound, 2);
      expect(r.ledger.header.encode(), c.f.h2.encode());
      expect(SlotScript.lanesBytes(r.ledger.tree.root), c.f.h2.cmRoot);
      expect(SlotScript.lanesBytes(r.ledger.nullifiers.root), c.f.h2.nfRoot);
      expect(r.ledger.header.balance, BigInt.from(201));
      expect(applied[0].padding, [false, true, true, true]);
      expect(applied[0].receipts.single.satoshis, BigInt.from(500));
      expect(applied[1].withdrawals.single.pubkeyHash, c.f.withdrawal.pubkeyHash);
      expect(applied[1].withdrawals.single.satoshis, BigInt.from(300));
    });

    test('stops at a round whose witness bundles do not match its outHash, reporting round 1 as its last', () {
      final r = reader();
      r.read([
        (round: c.r1, witness: c.w1, nextSlot: c.y1.tx),
        (round: c.r2, witness: c.witness2(c.r2, c.r1, bundles: c.f.bundles), nextSlot: c.y2.tx),
        (round: c.r2, witness: c.w2, nextSlot: c.y2.tx),
      ]);
      expect(r.lastRound, 1);
      expect(r.stopped, isTrue);
      expect(r.refusedRound, 2);
      expect(r.refusal!.check, 'outHash');
      expect(r.ledger.header.encode(), c.f.h1.encode());
      expect(r.read(mined()), isEmpty, reason: 'a stopped reader applies nothing more');
    });
  });

  group('scanning', () {
    Future<ShieldedNoteScanner> scanned(ShieldedNoteScanner s, List<ShieldedRound> rounds) async {
      for (final r in rounds) {
        await s.scan(r);
      }
      return s;
    }

    test('the wallet finds its deposit, 500 at leaf 0 in round 1', () async {
      final r = reader()..read(mined().take(1));
      final s = ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]);
      final found = await s.scan(r.rounds[0]);
      expect(found.length, 1);
      expect(found[0].value, 500);
      expect(found[0].position, 0);
      expect(found[0].round, 1);
      expect(found[0].d, c.f.walletD);
      // the path from the ledger proves it against the current root
      expect(SlotScript.lanesBytes(r.ledger.path(0).rootFor(found[0].cm)), r.ledger.header.cmRoot);
    });

    test('a stranger finds nothing', () async {
      final r = reader()..read(mined());
      final stranger = PoolWalletKeys(List.generate(5, (i) => 1000 + i));
      final s = await scanned(ShieldedNoteScanner.forWallet(stranger, [for (int i = 0; i < 3; i++) (await NoteAddress.at(stranger.ivk, i)).d]),
          r.rounds);
      expect(s.notes, isEmpty);
    });

    test('with the wallet\'s wrong address only, nothing is found either', () async {
      final r = reader()..read(mined());
      final other = (await NoteAddress.at(c.f.wallet.ivk, 7)).d;
      final s = await scanned(ShieldedNoteScanner.forWallet(c.f.wallet, [other]), r.rounds);
      expect(s.notes, isEmpty);
    });

    test('after round 2 the 500 note is spent in round 2 and the 200 change note is found', () async {
      final r = reader()..read(mined());
      final s = await scanned(ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]), r.rounds);
      expect([for (final n in s.notes) n.value], [500, 200]);
      expect(s.notes[0].spentIn, 2);
      expect(s.notes[1].spent, isFalse);
      expect(s.notes[1].round, 2);
      expect(s.notes[1].position, layout.statement.leavesAppended, reason: 'the first leaf of round 2');
      expect([for (final n in s.unspent) n.value], [200]);
    });

    test('without the nullifier key it finds notes but cannot tell spends', () async {
      final r = reader()..read(mined());
      final s = await scanned(ShieldedNoteScanner(ivk: c.f.wallet.ivk, diversifiers: [c.f.walletD]), r.rounds);
      expect([for (final n in s.notes) n.value], [500, 200]);
      expect(s.notes.every((n) => !n.spent), isTrue);
    });

    test('rounds read back from files, with nothing fetched, give the same notes', () async {
      final dir = Directory.systemTemp.createTempSync('pool_offline_');
      try {
        final names = {'R0': c.r0, 'W0': c.w0, 'Y0': c.y0.tx, 'R1': c.r1, 'W1': c.w1, 'Y1': c.y1.tx, 'R2': c.r2, 'W2': c.w2, 'Y2': c.y2.tx};
        for (final e in names.entries) {
          File('${dir.path}/${e.key}.tx').writeAsBytesSync(hex.decode(e.value.serialize()));
        }
        Transaction load(String n) => ShieldedLedger.parse(File('${dir.path}/$n.tx').readAsBytesSync());
        final offline =
            ShieldedChainReader.open(layout, load('R0'), load('W0'), load('Y0'), tokenId: c.tokenId, genesisHeader: c.genesisHeader)
          ..read([
            for (final k in [1, 2]) (round: load('R$k'), witness: load('W$k'), nextSlot: load('Y$k'))
          ]);
        final online = reader()..read(mined());
        final a = await scanned(ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]), offline.rounds);
        final b = await scanned(ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]), online.rounds);
        expect(offline.lastRound, 2);
        expect([for (final n in a.notes) (n.value, n.position, n.round, n.spentIn, n.cm.join(","))],
            [for (final n in b.notes) (n.value, n.position, n.round, n.spentIn, n.cm.join(","))]);
        expect(offline.ledger.snapshot(), online.ledger.snapshot());
      } finally {
        dir.deleteSync(recursive: true);
      }
    });
  });
}
