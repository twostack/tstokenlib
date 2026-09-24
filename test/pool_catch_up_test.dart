import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' show Transaction;
import 'package:test/test.dart';
import 'package:tstokenlib/testing.dart';
import 'package:tstokenlib/tstokenlib.dart';

/// Protocol version 3's catch-up: a random id per request, echoed by its
/// reply; a refusal form; a mined round by number; the mined-round notice
/// a pool sends its submitters; the responder every pool answers with; and
/// a round's leaves read from its transactions alone.
void main() {
  late PoolTestChain c;
  late ShieldedPoolLayout layout;
  late ShieldedLedger at2;
  late List<ShieldedRound> applied;

  setUpAll(() async {
    c = await PoolTestChain.build();
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
    at2 = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
    applied = [at2.apply(c.r1, c.w1, c.y1.tx), at2.apply(c.r2, c.w2, c.y2.tx)];
  });

  List<int> bytesOf(Transaction tx) => hex.decode(tx.serialize());

  group('ids and refusals', () {
    test('every request carries a fresh random id, and a reply echoes the id it answers', () {
      final a = PoolCatchUpRequest.head(), b = PoolCatchUpRequest.head();
      expect(a.id, hasLength(16));
      expect(a.id, isNot(b.id), reason: 'two requests never share an id');
      final given = List.generate(16, (i) => i);
      final q = PoolCatchUpRequest.frontier(id: given);
      expect(PoolCatchUpRequest.decode(q.encode()).id, given);
      final reply = PoolCatchUpReply.frontier(round: 1, blockRoot: List.filled(32, 1), left: const [], id: q.id);
      expect(PoolCatchUpReply.decode(reply.encode()).id, given);
    });

    test('a round request names one round, and round 0 or a count is refused', () {
      final q = PoolCatchUpRequest.round(7);
      final back = PoolCatchUpRequest.decode(q.encode());
      expect(back.what, CatchUpKind.round);
      expect(back.round, 7);
      expect(back, q);
      expect(() => PoolCatchUpRequest.round(0), throwsA(isA<ArgumentError>()));
      // version, kind, id 16, what, from 4 at 19, count 4 at 23
      final zero = q.encode()..setRange(19, 23, [0, 0, 0, 0]);
      expect(() => PoolMessage.decode(zero), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'from')));
      final counted = q.encode()..[23] = 1;
      expect(() => PoolMessage.decode(counted), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'count')));
    });

    test('a refusal names its reason and a sentence, for every kind, and an unknown reason is refused', () {
      for (final what in CatchUpKind.values) {
        for (final why in CatchUpRefusal.values) {
          final r = PoolCatchUpReply.refused(what, why, 'not now', id: List.filled(16, 9));
          final back = PoolCatchUpReply.decode(r.encode());
          expect(back.isRefused, isTrue);
          expect(back.what, what);
          expect(back.refusal, why);
          expect(back.sentence, 'not now');
          expect(back, r);
        }
      }
      // version, kind, id 16, what, status, then the reason at 20
      final bytes = PoolCatchUpReply.refused(CatchUpKind.head, CatchUpRefusal.notYet, 'x').encode()..[20] = 99;
      expect(() => PoolMessage.decode(bytes), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'reason')));
    });

    test('a reply holds nothing about the asker beyond the request\'s own id', () async {
      final r = c.responder();
      final asker = List.generate(16, (i) => 0xc0 + i);
      final q = PoolCatchUpRequest.head();
      final reply = await r.answer(q);
      expect(_contains(reply.encode(), asker), isFalse);
      expect(reply.id, q.id);
    });
  });

  group('the responder on the test chain', () {
    test('Answers at the last mined round: a head and a frontier stand at the same round, below the ledger\'s', () async {
      final r = c.responder(minedTip: 1);
      final head = await r.answer(PoolCatchUpRequest.head());
      final frontier = await r.answer(PoolCatchUpRequest.frontier());
      expect(head.isRefused, isFalse);
      expect(head.round, 1);
      expect(frontier.round, 1);
      expect(head.witnessTx, bytesOf(c.w1));
      expect(head.roundTx, bytesOf(c.r1));
      expect(frontier.blockRoot, applied[0].blockRoot);
      // the frontier at round 1 rebuilds round 1's root
      final follower =
          BlockFold.at(leavesPerRound: layout.leavesPerRound, round: frontier.round, blockRoot: frontier.blockRoot!, left: frontier.left);
      expect(follower.cmRoot, applied[0].header.cmRoot);
    });

    test('A mined round by number, after later rounds are mined', () async {
      final r = c.responder();
      final one = await r.answer(PoolCatchUpRequest.round(1));
      expect(one.what, CatchUpKind.round);
      expect(one.round, 1);
      expect(one.witnessTx, bytesOf(c.w1));
      expect(one.computedMerkleRoot(), hex.decode(c.w1.id), reason: 'alone in its block, the root is the txid');
      final back = PoolCatchUpReply.decode(one.encode());
      expect(back, one);
    });

    test('Not mined yet: head and frontier before round 1, a round past the tip, a range past it', () async {
      final none = c.responder(minedTip: 0);
      for (final q in [PoolCatchUpRequest.head(), PoolCatchUpRequest.frontier(), PoolCatchUpRequest.round(1)]) {
        final a = await none.answer(q);
        expect(a.refusal, CatchUpRefusal.notYet, reason: q.what.name);
        expect(a.id, q.id);
      }
      final r = c.responder(minedTip: 1);
      expect((await r.answer(PoolCatchUpRequest.round(2))).refusal, CatchUpRefusal.notYet);
      expect((await none.answer(PoolCatchUpRequest.blockRoots(from: 1, count: 1024))).refusal, CatchUpRefusal.notYet);
    });

    test('Block roots: a published run up to the tip, an unpublished one refused naming it', () async {
      final r = c.responder(catchUpRange: 4);
      final roots = await r.answer(PoolCatchUpRequest.blockRoots(from: 1, count: 4));
      expect(roots.from, 1);
      expect(roots.roots, [applied[0].blockRoot, applied[1].blockRoot], reason: 'two mined of the run of four');
      final off = await r.answer(PoolCatchUpRequest.blockRoots(from: 2, count: 4));
      expect(off.refusal, CatchUpRefusal.unpublishedRange);
      expect(off.sentence, contains('rounds 2 to 5'));
    });

    test('A source that fails is a refusal the wallet can retry, never a silence', () async {
      final r = PoolCatchUpResponder(c.descriptor(), _Failing(c.catchUpSource()));
      final a = await r.answer(PoolCatchUpRequest.head());
      expect(a.refusal, CatchUpRefusal.unavailable);
      expect(a.sentence, contains('node down'));
      final b = await r.answer(PoolCatchUpRequest.round(1));
      expect(b.refusal, CatchUpRefusal.unavailable);
    });

    test('A submitter\'s notice carries its ids, the txids and the witness\'s place, and no transactions', () async {
      final r = c.responder();
      final ids = [List.filled(16, 1), List.filled(16, 2)];
      final n = (await r.notice(2, ids))!;
      final back = PoolMessage.decode(n.encode()) as PoolRoundMined;
      expect(back.ids, ids);
      expect(back.round, 2);
      expect(hex.encode(back.roundTxId), c.r2.id);
      expect(hex.encode(back.witnessTxId), c.w2.id);
      expect(back.computedMerkleRoot(), hex.decode(c.w2.id), reason: 'alone in its block, the root is the txid');
      expect(back, n);
      expect(() => PoolRoundMined(
          ids: const [], round: 1, roundTxId: List.filled(32, 0), witnessTxId: List.filled(32, 0),
          blockHash: List.filled(32, 0), txIndex: 0, branch: const []),
          throwsA(isA<ArgumentError>()));
      // a notice is small whatever the round's size: one id and a 20-deep
      // branch, as a block of a million transactions has
      final deep = PoolRoundMined(
          ids: [List.filled(16, 1)], round: 9, roundTxId: List.filled(32, 1), witnessTxId: List.filled(32, 2),
          blockHash: List.filled(32, 3), txIndex: 5, branch: List.generate(20, (i) => List.filled(32, i)));
      expect(deep.encode().length, lessThan(1024));
      expect(n.encode().length, lessThan(PoolMessage.maxOther));
      final over = n.encode().toList()..addAll(List.filled(PoolRoundMined.maxNotice, 0));
      expect(() => PoolMessage.decode(over), throwsA(isA<ProtocolRefusal>().having((e) => e.field, 'field', 'size')));
      print('  a mined-round notice at test parameters is ${n.encode().length} bytes; with a 20-deep branch ${deep.encode().length}');
    });
  });

  group('a round\'s leaves from its transactions alone', () {
    test('Round leaves agree with the ledger: block root, positions and nullifiers, for both rounds', () {
      for (final (i, (r, w)) in [(c.r1, c.w1), (c.r2, c.w2)].indexed) {
        final got = ShieldedLedger.readLeaves(layout, r, w);
        final want = applied[i];
        expect(got.leaves, hasLength(layout.leavesPerRound));
        expect(got.blockRoot, want.blockRoot);
        final base = i * layout.leavesPerRound;
        expect([for (final (a, b) in got.positions) (a + base, b + base)], want.positions);
        expect(got.nullifiers, want.nullifiers);
        expect(got.header.encode(), want.header.encode());
      }
      expect(ShieldedLedger.readLeaves(layout, c.r2, c.w2).nullifiers, isNotEmpty, reason: 'round 2 spends the deposit note');
    });

    test('A path from the leaves reaches the round\'s root', () {
      // round 2's change note, pathed from round 2's leaves and the
      // frontier at round 1, as a payer holding a fold does it
      final got = ShieldedLedger.readLeaves(layout, c.r2, c.w2);
      final (offset, _) = got.positions.first;
      final position = layout.leavesPerRound + offset;
      expect(at2.path(position).siblings, isNotEmpty);
      expect(got.leaves[offset], at2.tree.nodeAt(0, position));
    });

    test('A witness of another round is refused, naming the check', () {
      expect(() => ShieldedLedger.readLeaves(layout, c.r2, c.w1),
          throwsA(isA<LedgerRefusal>().having((e) => e.check, 'check', 'tip')));
    });
  });

  group('untrusted input', () {
    test('10,000 mutated version 3 catch-up messages and notices end in a message or a named refusal', () async {
      final r = c.responder();
      final seeds = <Uint8List>[
        PoolCatchUpRequest.round(2).encode(),
        PoolCatchUpRequest.head().encode(),
        PoolCatchUpReply.refused(CatchUpKind.round, CatchUpRefusal.notYet, 'round 9 is not mined yet').encode(),
        (await r.answer(PoolCatchUpRequest.round(1))).encode(),
        (await r.notice(1, [List.filled(16, 3)]))!.encode(),
      ];
      final rng = Random(5);
      var decoded = 0;
      for (int i = 0; i < 10000; i++) {
        final b = Uint8List.fromList(seeds[i % seeds.length]);
        // mutate the head of the message, where every field's length lives
        final at = rng.nextInt(min(b.length, 64));
        b[at] = rng.nextInt(256);
        try {
          PoolMessage.decode(b);
          decoded++;
        } on ProtocolRefusal catch (e) {
          expect(e.field, isNotEmpty);
        }
      }
      print('  10,000 mutated version 3 messages: ${10000 - decoded} refused, $decoded still decoded');
    });
  });
}

class _Failing implements CatchUpSource {
  final CatchUpSource inner;
  _Failing(this.inner);
  @override
  int get minedTip => inner.minedTip;
  @override
  List<int> blockRootOf(int round) => inner.blockRootOf(round);
  @override
  ({int round, List<int> blockRoot, List<List<int>> left}) frontierAt(int round) => inner.frontierAt(round);
  @override
  Future<MinedRound?> mined(int round) async => throw StateError('node down');
  @override
  Future<RoundPlace?> placed(int round) async => throw StateError('node down');
}

bool _contains(List<int> haystack, List<int> needle) {
  outer:
  for (int i = 0; i + needle.length <= haystack.length; i++) {
    for (int j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
