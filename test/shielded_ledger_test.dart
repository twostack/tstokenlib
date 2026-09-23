import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/fri_fold_script_gen.dart' show FriQueryVerifierGen;
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_ledger.dart';

import 'pool_test_chain.dart';

/// [lanes] as V's unlock pushes them.
List<int> encodeLanes(List<int> lanes) {
  final b = ScriptBuilder();
  for (final v in lanes) {
    FriQueryVerifierGen.pushNum(b, v);
  }
  return b.build().buffer;
}

/// [unlock] with its statement replaced by [lanes] and everything after
/// the statement kept.
UnlockingScriptBuilder withStatement(List<int> unlock, List<int> oldLanes, List<int> lanes) => DefaultUnlockBuilder.fromScript(
    SVScript.fromByteArray(Uint8List.fromList([...encodeLanes(lanes), ...unlock.sublist(encodeLanes(oldLanes).length)])));

PoolHeader headerWith(PoolHeader h, {BigInt? balance, List<int>? outHash}) => PoolHeader(
    cmRoot: h.cmRoot, nfRoot: h.nfRoot, ring: h.ring, size: h.size, balance: balance ?? h.balance, outHash: outHash ?? h.outHash);

void main() {
  late PoolTestChain c;
  late ShieldedPoolLayout layout;

  setUpAll(() async {
    c = await PoolTestChain.build();
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
  });

  ShieldedLedger genesis() => ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);

  /// [f] is refused on [check], and the ledger it ran against is as it was.
  void refused(ShieldedLedger l, void Function() f, String check, [String? reason]) {
    final before = l.snapshot();
    expect(f, throwsA(isA<LedgerRefusal>().having((r) => r.check, 'check', check).having((r) => r.reason, 'reason', contains(reason ?? ''))));
    expect(l.snapshot(), before, reason: 'a refused round leaves the ledger unchanged');
  }

  group('reading a round', () {
    test('the witness\'s bundles push decodes, by name, to the fixture\'s bundles', () {
      final pushes = PP1SpUnlockBuilder.readRound(c.w1.inputs[1].script!.buffer);
      expect(PoolOutHash.decodeBundles(pushes['bundles']!), PoolOutHash.decodeBundles(c.f.bundles));
      expect(pushes['newHeader'], c.f.h1.encode());
      expect(PoolOutHash.decodeBundles(PP1SpUnlockBuilder.readRound(c.w2.inputs[1].script!.buffer)['bundles']!),
          [for (final t in c.f.transfers2) t.bundle]);
    });

    test('each transfer\'s pinned lanes in V\'s unlock are the fixture\'s publics', () {
      for (final (round, transfers) in [(c.r1, c.f.transfers1), (c.r2, c.f.transfers2)]) {
        final lanes = layout.readStatement(c.vUnlock(round));
        expect(lanes.length, layout.statement.numPublics);
        for (int t = 0; t < layout.transfers; t++) {
          expect(layout.transferLanes(lanes, t), transfers[t].publics.toReducedLanes());
        }
      }
    });

    test('an unlock with one push missing is refused', () {
      // The pushes after the statement are numbers too, so reading a fixed
      // count cannot tell that one is missing: the statement comes out
      // shifted by a lane. The ledger refuses the round on what the shifted
      // lanes fail to rebuild. An unlock too short for the statement is
      // refused by the parser itself.
      final u = c.vUnlock(c.r1);
      final first = encodeLanes([layout.readStatement(u).first]).length;
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      final r = c.round1(slotUnlocker: DefaultUnlockBuilder.fromScript(SVScript.fromByteArray(Uint8List.fromList(u.sublist(first)))));
      expect(() => l.apply(r, c.witness1(r), c.y1.tx), throwsA(isA<LedgerRefusal>()));
      expect(l.round, 0);
      expect(() => layout.readStatement(u.sublist(0, 40)), throwsA(isA<LedgerRefusal>().having((r) => r.check, 'check', 'statement')));
    });

    test('the layout built from arities is the aggregation\'s, and places the leaves it placed', () {
      final a = c.f.agg.tree, s = layout.statement;
      expect([s.numPublics, s.receiptOffset, s.leavesAppended], [c.f.v.stmt.numPublics, c.f.v.stmt.receiptOffset, c.f.v.stmt.leavesAppended]);
      expect(layout.tree.subtrees, a.subtrees);
      // lanes rebuilt from the bundles and a zero anchor, against the fixture's own
      final rebuilt = [
        for (final t in c.f.transfers1)
          PoolPublicInputs.fromReducedLanes(t.publics.toReducedLanes(), cm1: t.commitments[0], cm2: t.commitments[1]).toLanes()
      ];
      final original = [for (final t in c.f.transfers1) t.publics.toLanes()];
      for (int sub = 0; sub < a.subtrees; sub++) {
        expect(layout.tree.subtreeLeavesOf(rebuilt, sub), a.subtreeLeavesOf(original, sub));
      }
    });
  });

  group('the ledger', () {
    test('genesis: size 0, the genesis header\'s roots, and the issuance as its tip', () {
      final l = genesis();
      expect(l.size, 0);
      expect(l.round, 0);
      expect(SlotScript.lanesBytes(l.tree.root), c.f.g.cmRoot);
      expect(SlotScript.lanesBytes(l.nullifiers.root), c.f.g.nfRoot);
      expect(l.header.encode(), c.f.g.encode());
      expect([l.tipRound.id, l.tipWitness.id, l.tipSlot.id], [c.r0.id, c.w0.id, c.y0.tx.id]);
    });

    test('an issuance whose witness is another\'s is refused', () {
      expect(() => ShieldedLedger.open(layout, c.r0, c.w1, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader), throwsA(isA<LedgerRefusal>().having((r) => r.check, 'check', 'genesis')));
      expect(() => ShieldedLedger.open(layout, c.r0, c.w0, c.y1.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader), throwsA(isA<LedgerRefusal>()));
    });

    test('an honest chain: rounds 1 and 2 reach the headers the builder advanced to', () {
      final l = genesis();
      final a = l.apply(c.r1, c.w1, c.y1.tx);
      expect(l.header.encode(), c.f.h1.encode());
      expect(a.number, 1);
      expect(a.receipts.single.commitment, c.f.receipt.commitment);
      expect(a.padding, [false, true, true, true]);
      expect(a.positions[0], (0, 1), reason: 'the deposit note is leaf 0');
      final b = l.apply(c.r2, c.w2, c.y2.tx);
      expect(l.header.encode(), c.f.h2.encode());
      expect(SlotScript.lanesBytes(l.tree.root), c.f.h2.cmRoot);
      expect(SlotScript.lanesBytes(l.nullifiers.root), c.f.h2.nfRoot);
      expect(b.withdrawals.single.satoshis, BigInt.from(300));
      expect(b.nullifiers.length, 1, reason: 'one real input');
      expect(l.round, 2);
      expect(l.size, 2 * layout.statement.leavesAppended);
    });

    test('a witness carrying a bundle other than the one a transfer committed to is refused', () {
      final l = genesis();
      refused(l, () => l.apply(c.r1, c.witness1(c.r1, bundles: c.f.bundles2), c.y1.tx), 'outHash');
      l.apply(c.r1, c.w1, c.y1.tx); // and the honest witness still applies
    });

    test('a round that does not extend the tip is refused as another chain\'s', () {
      final l = genesis();
      refused(l, () => l.apply(c.r2, c.w2, c.y2.tx), 'tip', 'another chain');
      l.apply(c.r1, c.w1, c.y1.tx);
      refused(l, () => l.apply(c.r1, c.w1, c.y1.tx), 'tip', 'another chain');
    });

    test('a round whose next slot is not the one its PP3 names is refused', () {
      final l = genesis();
      refused(l, () => l.apply(c.r1, c.w1, c.y2.tx), 'tip');
    });

    test('a round whose header claims a balance off by one is refused', () {
      final l = genesis();
      final h = headerWith(c.f.h1, balance: c.f.h1.balance + BigInt.one);
      final y = c.slot(h, 0x41);
      final r = c.round1(header: h, next: y);
      refused(l, () => l.apply(r, c.witness1(r, header: h, next: y), y.tx), 'header', 'balance');
    });

    test('a receipt that is not the deposit the root proved is refused', () {
      final l = genesis();
      final u = c.vUnlock(c.r1);
      final lanes = layout.readStatement(u);
      final forged = [...lanes]..[layout.statement.receiptOffset] ^= 1;
      final r = c.round1(slotUnlocker: withStatement(u, lanes, forged));
      refused(l, () => l.apply(r, c.witness1(r), c.y1.tx), 'receipts');
    });

    test('a nullifier already present is refused', () {
      // round 2 with transfer 1 claiming the spend transfer 0 makes, under
      // bytes of its own that outHash and the header agree with, so the
      // nullifier check is the first to fail
      final l = genesis()..apply(c.r1, c.w1, c.y1.tx);
      final u = c.vUnlock(c.r2);
      final lanes = layout.readStatement(u);
      final spend = c.f.transfers2[0];
      final bundle1 = spend.bundle;
      final per = [spend.bundle, bundle1, for (final t in c.f.transfers2.skip(2)) t.bundle];
      final copy = spend.publics.copyWith(publicOut: 0, outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(bundle1)));
      final w = 8 * 4;
      final forged = [...lanes]..setRange(w, 2 * w, copy.toReducedLanes());
      final h = headerWith(c.f.h2, outHash: PoolOutHash.roundOutHashOf(per));
      final y = c.slot(h, 0x42);
      final r = c.round2(c.r1, c.w1, header: h, next: y, slotUnlocker: withStatement(u, lanes, forged));
      refused(l, () => l.apply(r, c.witness2(r, c.r1, header: h, next: y, bundles: PoolOutHash.encodeBundles(per)), y.tx), 'nullifiers',
          'already spent');
      l.apply(c.r2, c.w2, c.y2.tx);
    });

    test('a witness whose bundles push is cut short is refused as malformed', () {
      final l = genesis();
      final short = c.f.bundles.sublist(0, c.f.bundles.length - 5);
      refused(l, () => l.apply(c.r1, c.witness1(c.r1, bundles: short), c.y1.tx), 'bundles', 'cut short');
    });

    test('1,000 single-byte mutations of round 1 each end in a named refusal and leave the ledger as it was', () {
      // one ledger for every attempt, so the snapshot at the end checks that
      // no refusal changed it
      final l = genesis();
      final before = l.snapshot();
      final r1 = hex.decode(c.r1.serialize());
      final rng = Random(5);
      final checks = <String, int>{};
      var applied = 0;
      for (int i = 0; i < 1000; i++) {
        final m = Uint8List.fromList(r1);
        final k = rng.nextInt(m.length);
        m[k] = (m[k] + 1 + rng.nextInt(255)) & 0xff;
        try {
          (l.round == 0 ? l : genesis()).apply(ShieldedLedger.parse(m), c.w1, c.y1.tx);
          applied++;
        } on LedgerRefusal catch (e) {
          checks[e.check] = (checks[e.check] ?? 0) + 1;
        }
      }
      print('  $applied applied, refused: $checks');
      expect(applied, 0, reason: 'any change to the round changes its txid, which the witness spends');
      expect(l.snapshot(), before);
    }, timeout: const Timeout(Duration(minutes: 10)));

    test('mutations of witness 1 are refused when they touch the bundles, and read past otherwise', () {
      // The ledger reads the witness's bundles push and the two outpoints it
      // spends, nothing else; the miners ran its scripts. So a mutation
      // elsewhere applies, and one in the bundles is refused by outHash.
      final w1 = hex.decode(c.w1.serialize());
      final blob = c.f.bundles;
      var at = -1;
      for (int i = 0; i + blob.length <= w1.length && at < 0; i++) {
        if (w1[i] == blob[0] && w1[i + 1] == blob[1] && w1[i + 2] == blob[2] && w1[i + 40] == blob[40]) at = i;
      }
      expect(at, greaterThan(0));
      final rng = Random(6);
      for (int i = 0; i < 20; i++) {
        final m = Uint8List.fromList(w1);
        final k = at + rng.nextInt(blob.length);
        m[k] ^= 1 + rng.nextInt(255);
        final l = genesis();
        expect(() => l.apply(c.r1, ShieldedLedger.parse(m), c.y1.tx), throwsA(isA<LedgerRefusal>()));
        expect(l.round, 0);
      }
    }, timeout: const Timeout(Duration(minutes: 10)));
  });

  group('snapshots', () {
    test('restart: a ledger restored after round 1 reaches the same header on round 2', () {
      final a = genesis()..apply(c.r1, c.w1, c.y1.tx);
      final b = ShieldedLedger.restore(layout, a.snapshot());
      expect(b.header.encode(), c.f.h1.encode());
      expect(b.snapshot(), a.snapshot());
      a.apply(c.r2, c.w2, c.y2.tx);
      b.apply(c.r2, c.w2, c.y2.tx);
      expect(b.header.encode(), a.header.encode());
      expect(b.snapshot(), a.snapshot());
    });

    test('an edited snapshot, one leaf altered, is refused', () {
      final s = (genesis()..apply(c.r1, c.w1, c.y1.tx)).snapshot();
      // the first leaf sits after the version, header, round and three transactions
      var at = 1 + PoolHeader.byteSize + 4;
      for (int i = 0; i < 3; i++) {
        at += 4 + (s[at] | (s[at + 1] << 8) | (s[at + 2] << 16) | (s[at + 3] << 24));
      }
      at += 4;
      final edited = Uint8List.fromList(s)..[at] ^= 1;
      expect(() => ShieldedLedger.restore(layout, edited),
          throwsA(isA<LedgerRefusal>().having((r) => r.reason, 'reason', contains('do not rebuild the header'))));
    });

    test('an unknown snapshot version, a truncated file and a trailing byte are refused', () {
      final s = genesis().snapshot();
      expect(() => ShieldedLedger.restore(layout, [2, ...s.sublist(1)]),
          throwsA(isA<LedgerRefusal>().having((r) => r.reason, 'reason', contains('unknown version 2'))));
      expect(() => ShieldedLedger.restore(layout, s.sublist(0, s.length - 1)), throwsA(isA<LedgerRefusal>()));
      expect(() => ShieldedLedger.restore(layout, [...s, 0]), throwsA(isA<LedgerRefusal>()));
    });

    test('two ledgers built separately from the same transactions write byte-identical snapshots', () {
      final a = genesis(), b = ShieldedLedger.open(layout, Transaction.fromHex(c.r0.serialize()), Transaction.fromHex(c.w0.serialize()),
          Transaction.fromHex(c.y0.tx.serialize()), tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      for (final (r, w, y) in [(c.r1, c.w1, c.y1.tx), (c.r2, c.w2, c.y2.tx)]) {
        a.apply(r, w, y);
        b.applyBytes(hex.decode(r.serialize()), hex.decode(w.serialize()), hex.decode(y.serialize()));
      }
      expect(b.snapshot(), a.snapshot());
    });
  });

  group('spending from the ledger', () {
    test('the path of leaf 0 after round 2 reproduces the current root', () {
      final l = genesis()..apply(c.r1, c.w1, c.y1.tx)..apply(c.r2, c.w2, c.y2.tx);
      final p = l.path(0);
      expect(SlotScript.lanesBytes(p.rootFor(l.tree.nodeAt(0, 0))), l.header.cmRoot);
      expect(l.tree.nodeAt(0, 0), c.f.transfers1[0].publics.cmOut1, reason: 'leaf 0 is the deposit note');
      expect(l.roundsLeftInRing(l.header.cmRoot), 4);
      expect(l.roundsLeftInRing(c.f.h1.cmRoot), 3);
    });

    test('a root current four rounds ago has left the ring', () {
      // headers advanced by hand: the ring logic reads only the header
      var h = PoolHeader.genesis(emptyCmRoot: List.filled(32, 0), emptyNfRoot: List.filled(32, 0));
      final roots = <List<int>>[];
      for (int n = 1; n <= 5; n++) {
        final root = List.filled(32, n);
        roots.add(root);
        h = h.advance(cmRoot: root, nfRoot: h.nfRoot, size: 32 * n, balance: h.balance, outHash: h.outHash);
      }
      expect([for (final r in roots) ShieldedLedger.roundsLeftIn(h, r)], [0, 1, 2, 3, 4],
          reason: 'round 1\'s root was current four rounds ago, so round 6 would refuse a spend anchored to it');
    });
  });
}
