import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_chain_air.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

void main() {
  final rng = Random(31);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int k) => List.generate(k, (_) => r31());

  test('empty tree: full store, frontier and the empty-root table agree', () {
    final t = NoteCommitmentTree();
    expect(t.size, 0);
    expect(t.root, MerkleFrontier.emptyRoots[32]);
    expect(t.frontier.root, t.root);
    expect(MerkleFrontier.emptyRoots.length, 33);
    expect(MerkleFrontier.emptyRoots[1], PoolHash.node(MerkleFrontier.emptyLeaf, MerkleFrontier.emptyLeaf));
    expect(() => t.path(0), throwsA(isA<RangeError>()));
  });

  test('appends keep the frontier and the node store in step, and every path verifies', () {
    final t = NoteCommitmentTree();
    final leaves = <List<int>>[];
    // 21 leaves: enough for carries across several levels (10101b)
    for (int i = 0; i < 21; i++) {
      final leaf = lanes(8);
      expect(t.append(leaf), i);
      leaves.add(leaf);
      expect(t.frontier.root, t.root, reason: 'after append $i');
      expect(t.frontier.size, i + 1);
      // peaks present exactly at the set bits of size
      for (int l = 0; l < 32; l++) {
        expect(t.frontier.peaks[l] != null, ((i + 1) >> l) & 1 == 1, reason: 'peak $l at size ${i + 1}');
      }
      // every leaf so far has a path to the current root
      for (int j = 0; j <= i; j++) {
        final p = t.path(j);
        expect(p.position, j);
        expect(p.siblings.length, 32);
        expect(p.rootFor(leaves[j]), t.root, reason: 'leaf $j at size ${i + 1}');
      }
    }
    // a path is against the root of its time: after another append it no longer matches
    final old = t.path(3);
    final oldRoot = t.root;
    t.append(lanes(8));
    expect(old.rootFor(leaves[3]), oldRoot);
    expect(old.rootFor(leaves[3]), isNot(equals(t.root)));
    // and a wrong leaf does not verify
    expect(t.path(5).rootFor(leaves[6]), isNot(equals(t.root)));
  });

  test('the frontier alone reproduces the root of a tree it never saw whole', () {
    final t = NoteCommitmentTree();
    final f = MerkleFrontier();
    for (int i = 0; i < 40; i++) {
      final leaf = lanes(8);
      t.append(leaf);
      f.append(leaf);
    }
    expect(f.root, t.root);
    // the peaks are exactly the complete-subtree roots the store holds
    // size 40 = 101000b: peaks at levels 3 and 5
    expect(f.peaks[3], t.nodeAt(3, 4)); // leaves 32..39
    expect(f.peaks[5], t.nodeAt(5, 0)); // leaves 0..31
  });

  test('two notes from the tree make a valid spend witness', () {
    final t = NoteCommitmentTree();
    // some unrelated commitments first
    for (int i = 0; i < 7; i++) {
      t.append(lanes(8));
    }
    SpendNote noteAt(int value) {
      final sk = lanes(5), d = lanes(3), rho = lanes(3), rcm = lanes(4);
      final cm = PoolHash.commit(PoolHash.pkd(sk, d), value, rho, rcm).$2;
      final pos = t.append(cm);
      // path is taken later, against the final root
      return SpendNote(sk: sk, d: d, value: value, rho: rho, rcm: rcm,
          siblings: List.generate(32, (_) => List.filled(8, 0)), position: pos);
    }
    final a0 = noteAt(5000), b0 = noteAt(700);
    t.append(lanes(8));
    SpendNote withPath(SpendNote s) {
      final p = t.path(s.position);
      return SpendNote(sk: s.sk, d: s.d, value: s.value, rho: s.rho, rcm: s.rcm, siblings: p.siblings, position: p.position);
    }
    final a = withPath(a0), b = withPath(b0);
    expect(a.root, t.root);
    expect(b.root, t.root);
    expect(a.position, 7);
    expect(b.position, 8);
    final oa = OutputNote(pkd: lanes(8), value: 5600, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 90, rho: lanes(3), rcm: lanes(4));
    final anchor = t.root;
    // the spend is state-free: the outputs are appended by the round's slot
    final w = PoolSpendAir.witness(a, b, oa, ob, 10);
    expect(w.publics.anchor, anchor);
    expect(w.publics.cmOut1, oa.cm);
    expect(t.size, 10);
    final air = PoolSpendAir.air(w.publics);
    const n = 1 << PoolSpendAir.logTrace;
    final aux = air.auxColumns(w.rows, [QM31.fromLimbs(3, 1, 4, 1)]);
    final full = [for (int r = 0; r < n; r++) [...w.rows[r], for (final c in aux) c[r]]];
    final out = Uint32List(air.numConstraints);
    final int main = air.numConstraints - air.boundaries.fold<int>(0, (x, g) => x + g.exprs.length);
    for (int r = 0; r < n; r++) {
      final p = air.rowPoint(r);
      air.constraintsM31(
          Uint32List.fromList(full[r]),
          Uint32List.fromList(full[(r + 1) % n]),
          Uint32List.fromList([for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)]),
          Uint32List.fromList([for (final f in air.linearForms) f.atM31(p.x, p.y)]),
          out);
      for (int j = 0; j < main; j++) {
        expect(out[j], 0, reason: 'row $r constraint $j');
      }
      int lo = main;
      for (final g in air.boundaries) {
        if (r == g.row || r == (g.row + (n >> 1)) % n) {
          for (int j = lo; j < lo + g.exprs.length; j++) {
            expect(out[j], 0, reason: 'row $r boundary $j');
          }
        }
        lo += g.exprs.length;
      }
    }
    // the trace's Merkle periods really hold the tree's siblings on the witness side
    final rowA = Poseidon2ChainAir.inputRow(PoolSpendAir.pMerkle + 4);
    final side = (a.position >> 4) & 1 == 1 ? 0 : 8;
    expect(w.rows[rowA].sublist(side, side + 8), t.path(a.position).siblings[4]);
    // a note whose path was taken before the last append is stale
    final stale = SpendNote(sk: a0.sk, d: a0.d, value: a0.value, rho: a0.rho, rcm: a0.rcm,
        siblings: t.path(a.position).siblings, position: a.position);
    t.append(lanes(8));
    expect(() => PoolSpendAir.witness(stale, withPath(b0), oa, ob, 10), throwsA(isA<ArgumentError>()));
  });

  test('a copy advances independently of its original', () {
    final rng = Random(4);
    List<int> leaf() => List.generate(8, (_) => rng.nextInt(M31.p));
    final t = NoteCommitmentTree();
    t.appendSubtree([for (int i = 0; i < 5; i++) leaf()]);
    final root = t.root;
    final c = t.copy();
    expect(c.root, root);
    expect(c.size, 32);
    c.appendSubtree([leaf(), leaf()]);
    expect(c.size, 64);
    expect(t.root, root, reason: 'appending to the copy leaves the original alone');
    expect(t.size, 32);
    expect(t.frontier.root, root);
    t.append(leaf());
    expect(c.size, 64, reason: 'and appending to the original leaves the copy alone');
    expect(c.frontier.root, c.root, reason: 'the copy\'s frontier and store stay in step');
    expect(t.frontier.root, t.root);
    expect(c.root, isNot(t.root));
    expect(c.path(0).rootFor(c.nodeAt(0, 0)), c.root);
    expect(t.path(32).rootFor(t.nodeAt(0, 32)), t.root);
  });
}
