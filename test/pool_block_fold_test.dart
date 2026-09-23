import 'dart:math';

import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart' show PoolHash;
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';

import 'pool_test_chain.dart';

/// Following a pool by its block roots: 32 bytes a round, whatever the
/// round's size. A round appends a fixed power-of-two block of leaves, so
/// round N owns the aligned subtree at the block level, index N - 1; a
/// leaf's siblings below that level freeze when its own round is mined and
/// the ones above it follow from one root a round.
void main() {
  group('the test chain', () {
    late PoolTestChain c;
    late ShieldedPoolLayout layout;

    setUpAll(() async {
      c = await PoolTestChain.build();
      layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
    });

    ShieldedLedger atGenesis() => ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);

    test('a round\'s block root is the tree node at the block level', () {
      expect(layout.leavesPerRound, 32);
      expect(layout.blockLevel, 5);
      final l = atGenesis();
      expect(() => l.blockRoot, throwsA(isA<StateError>()));

      final r1 = l.apply(c.r1, c.w1, c.y1.tx);
      expect(l.size, 32);
      expect(r1.blockRoot, SlotScript.lanesBytes(l.tree.nodeAt(5, 0)));

      final r2 = l.apply(c.r2, c.w2, c.y2.tx);
      expect(l.size, 64);
      expect(r2.number, 2);
      // round 2's block is the second aligned subtree of 32 leaves, so the
      // node at level 5 index 1: round N owns index N - 1
      expect(r2.blockRoot, SlotScript.lanesBytes(l.tree.nodeAt(5, 1)));
      expect(r2.blockRoot, l.blockRoot);
      expect(r2.blockRoot.length, 32);
    });

    test('a path is kept current by folding, and the fold reaches the header\'s root', () {
      final l = atGenesis();
      final r1 = l.apply(c.r1, c.w1, c.y1.tx);

      // the follower joins at the genesis and folds round 1
      final fold = BlockFold(layout.leavesPerRound);
      expect(fold.rounds, 0);
      expect(fold.blockLevel, 5);
      expect(fold.cmRoot, SlotScript.lanesBytes(NoteCommitmentTree().root), reason: 'an empty pool');
      expect(fold.fold(1, r1.blockRoot, cmRoot: r1.header.cmRoot), r1.header.cmRoot);
      expect(fold.rounds, 1);
      expect(fold.size, 32);

      // a leaf of round 1, with the path the pool gave when it was mined
      final position = r1.positions[0].$1;
      final tracked = fold.follow(l.tree.path(position));
      final leaf = l.tree.nodeAt(0, position);
      expect(tracked.path.rootFor(leaf), l.tree.root);

      // round 2 arrives as 32 bytes and nothing else
      final r2 = l.apply(c.r2, c.w2, c.y2.tx);
      final root = fold.fold(2, r2.blockRoot, cmRoot: r2.header.cmRoot);
      expect(root, r2.header.cmRoot);
      expect(fold.cmRoot, r2.header.cmRoot);

      // the folded path is the ledger's own path after round 2
      final want = l.tree.path(position);
      expect(tracked.path.siblings, want.siblings);
      expect(tracked.path.position, want.position);
      expect(tracked.path.rootFor(leaf), l.tree.root);
      expect(SlotScript.lanesBytes(tracked.path.rootFor(leaf)), r2.header.cmRoot);
    });

    test('a fold that does not match is refused, naming the round, and changes nothing', () {
      final l = atGenesis();
      final r1 = l.apply(c.r1, c.w1, c.y1.tx);
      final fold = BlockFold(layout.leavesPerRound);
      fold.fold(1, r1.blockRoot, cmRoot: r1.header.cmRoot);
      final tracked = fold.follow(l.tree.path(r1.positions[0].$1));
      final before = [for (final s in tracked.path.siblings) [...s]];

      final r2 = l.apply(c.r2, c.w2, c.y2.tx);
      final bad = [...r2.blockRoot]..[7] ^= 1;
      expect(
          () => fold.fold(2, bad, cmRoot: r2.header.cmRoot),
          throwsA(isA<FoldRefusal>()
              .having((e) => e.round, 'round', 2)
              .having((e) => e.reason, 'reason', contains('round 2\'s header carries'))));
      expect(fold.rounds, 1, reason: 'a refused fold leaves the follower where it was');
      expect(fold.cmRoot, r1.header.cmRoot);
      expect(tracked.path.siblings, before);

      // and the real one still folds afterwards
      expect(fold.fold(2, r2.blockRoot, cmRoot: r2.header.cmRoot), r2.header.cmRoot);

      // a round out of order is refused too: the rounds between hold the
      // leaves this one sits on
      expect(() => fold.fold(4, r2.blockRoot),
          throwsA(isA<FoldRefusal>().having((e) => e.reason, 'reason', contains('stands at round 2'))));
    });

    test('thirty-two bytes a round, whatever the number of leaves followed', () {
      final l = atGenesis();
      final r1 = l.apply(c.r1, c.w1, c.y1.tx);
      final fold = BlockFold(layout.leavesPerRound);
      var consumed = 0;
      consumed += fold.fold(1, r1.blockRoot, cmRoot: r1.header.cmRoot).length - 32 + r1.blockRoot.length;

      // ten leaves of round 1 followed at once
      final leaves = [for (int p = 0; p < 10; p++) p];
      final tracked = [for (final p in leaves) fold.follow(l.tree.path(p))];

      final r2 = l.apply(c.r2, c.w2, c.y2.tx);
      consumed += r2.blockRoot.length;
      fold.fold(2, r2.blockRoot, cmRoot: r2.header.cmRoot);

      expect(consumed, 2 * 32, reason: 'two rounds followed, 32 bytes each');
      for (int i = 0; i < leaves.length; i++) {
        expect(tracked[i].path.siblings, l.tree.path(leaves[i]).siblings);
      }
      // what the follower holds does not grow with the rounds either
      expect(fold.frontier.length, lessThanOrEqualTo(2 * (fold.upperDepth + 1)));
    });
  });

  group('a thousand blocks', () {
    test('folded roots and paths are the directly built tree\'s, and a fold is under 1 ms', () {
      // production geometry: 512 leaves a round, block level 9
      const leavesPerRound = 512, blocks = 1000;
      final rng = Random(23);
      // the leaves, once: a commitment is a digest, and the same leaf must
      // come back the same whenever it is asked for
      final leaves = [
        for (int i = 0; i < blocks * leavesPerRound; i++)
          PoolHash.node([for (int j = 0; j < 8; j++) rng.nextInt(0x7ffffffe)], [for (int j = 0; j < 8; j++) rng.nextInt(0x7ffffffe)])
      ];
      List<int> leaf(int i) => leaves[i];

      // the tree a coordinator holds, built directly
      final sw = Stopwatch()..start();
      final tree = NoteCommitmentTree.fromLeaves(leaves);
      final built = sw.elapsedMilliseconds;
      expect(tree.size, blocks * leavesPerRound);

      final fold = BlockFold(leavesPerRound);
      expect(fold.blockLevel, 9);
      expect(fold.upperDepth, 23);

      // the leaf the follower keeps: in block 3, so 997 blocks land on top
      // of it after its own round
      const position = 3 * leavesPerRound + 17;
      FoldedPath? tracked;

      sw.reset();
      for (int b = 0; b < blocks; b++) {
        final root = SlotScript.lanesBytes(tree.nodeAt(9, b));
        fold.fold(b + 1, root);
        if (b == 3) {
          // the path as the pool gave it the round that leaf was mined:
          // the tree as it stood then, which is the first four blocks
          final then = NoteCommitmentTree.fromLeaves(leaves.sublist(0, 4 * leavesPerRound));
          expect(SlotScript.lanesBytes(then.root), fold.cmRoot);
          tracked = fold.follow(then.path(position));
        }
      }
      final folded = sw.elapsedMicroseconds;

      expect(fold.rounds, blocks);
      expect(fold.cmRoot, SlotScript.lanesBytes(tree.root));
      expect(tracked!.path.siblings, tree.path(position).siblings, reason: 'the folded path is the tree\'s own');
      expect(tracked.path.rootFor(leaf(position)), tree.root);

      final per = folded / (blocks - 4);
      print('  $blocks blocks of $leavesPerRound leaves: built directly in $built ms, '
          'folded in ${(folded / 1000).toStringAsFixed(1)} ms, ${per.toStringAsFixed(1)} us a fold with one path kept');
      expect(per, lessThan(1000), reason: 'one fold and one path update under 1 ms');
      expect(fold.frontier.length, lessThanOrEqualTo(2 * (fold.upperDepth + 1)));
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}
