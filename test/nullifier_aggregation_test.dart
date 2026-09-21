import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_air.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'verifier_air_test.dart' show checkTrace;

/// The nullifier insertions a level-2 node proves, at small parameters:
/// four transfers (three real spends and a deposit) under two level-1
/// nodes, inserted into a tree that already holds spent nullifiers.
void main() {
  final rng = Random(53);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  final chk = [QM31.one, QM31.one + QM31.i, QM31.u];

  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const p1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  // notes in the commitment tree, each spendable once
  final cmTree = NoteCommitmentTree();
  final keys = <(List<int>, List<int>, int, List<int>, List<int>, int)>[];
  for (int i = 0; i < 6; i++) {
    final sk = lanes(5), d = lanes(3), rho = lanes(3), rcm = lanes(4), value = 1000 + i;
    final cm = PoolHash.commit(PoolHash.pkd(sk, d), value, rho, rcm).$2;
    keys.add((sk, d, value, rho, rcm, cmTree.append(cm)));
  }
  SpendNote note(int i) {
    final (sk, d, value, rho, rcm, pos) = keys[i];
    final p = cmTree.path(pos);
    return SpendNote(sk: sk, d: d, value: value, rho: rho, rcm: rcm, siblings: p.siblings, position: p.position);
  }

  OutputNote out(int v) => OutputNote(pkd: lanes(8), value: v, rho: lanes(3), rcm: lanes(4));
  final anchor = cmTree.root;
  final ring = [anchor, lanes(8), lanes(8), lanes(8)];
  final witnesses = [
    PoolSpendAir.witness(note(0), note(1), out(2000), out(1), 0),
    PoolSpendAir.witness(note(2), SpendNote.dummy(sk: lanes(5), rho: lanes(3)), out(1002), out(0), 0),
    PoolSpendAir.witness(SpendNote.dummy(sk: lanes(5), rho: lanes(3)), SpendNote.dummy(sk: lanes(5), rho: lanes(3)), out(500), out(0), -500,
        anchor: lanes(8)),
    PoolSpendAir.witness(note(3), note(4), out(2007), out(0), 0),
  ];
  final airs = [for (final w in witnesses) PoolSpendAir.air(w.publics)];
  final spendLanes = [for (final a in airs) a.publicValues];

  late List<VerifierAir> air1;
  late List<StarkProof> proofs1;
  late VerifierProgram prog2;
  late List<List<int>> digests1;

  setUpAll(() {
    final spendProofs = [for (int n = 0; n < 4; n++) StarkProver.prove(spendP, airs[n], witnesses[n].rows, rng: Random(1), hash: p2)];
    final spendDigests = [for (int n = 0; n < 4; n++) VerifierProgram.statementDigest(airs[n], spendProofs[n].preRoot)];
    final shape = InnerShape(spendP, airs[0]);
    final prog1 = VerifierProgram.compileAll([shape, shape], 15, ring: AnchorRing.pool);
    air1 = [];
    proofs1 = [];
    for (int m = 0; m < 2; m++) {
      final rows = prog1.witnessAll([spendProofs[2 * m], spendProofs[2 * m + 1]],
          shapes: [InnerShape(spendP, airs[2 * m]), InnerShape(spendP, airs[2 * m + 1])], ring: ring);
      final air = prog1.air(VerifierProgram.nodeDigest([spendDigests[2 * m], spendDigests[2 * m + 1]], ring: ring));
      air1.add(air);
      proofs1.add(StarkProver.prove(p1, air, rows, rng: Random(2 + m), hash: p2));
      expect(StarkVerifierRef(p1, air, hash: p2).verify(proofs1[m]), isTrue);
    }
    final preRoot1 = PreCommitment.root(air1[0], p1, p2);
    digests1 = [for (int m = 0; m < 2; m++) VerifierProgram.statementDigest(air1[m], preRoot1)];
    prog2 = VerifierProgram.compileAll([InnerShape(p1, air1[0]), InnerShape(p1, air1[0])], 17, nullifierTransfers: 4);
    print('  level 2 with 8 nullifier walks: ${prog2.periodsUsed} periods, ${prog2.vmRows} VM rows');
  });

  /// A tree that already holds some spent nullifiers (the same ones each call).
  final earlier = [for (int i = 0; i < 5; i++) lanes(8)];
  NullifierTree spentTree() {
    final t = NullifierTree();
    for (final nf in earlier) {
      t.insert(nf);
    }
    return t;
  }

  /// The segment as a dishonest prover would lay it out: every path taken
  /// from the tree as it stands, real nullifiers written whether or not the
  /// slot was free.
  NullifierSegment careless(NullifierTree t, List<List<int>> spends) {
    final before = t.root, paths = <List<List<int>>>[];
    for (final l in spends) {
      for (final (at, real) in [(PoolPublicInputs.idxNf1, PoolPublicInputs.idxReal1), (PoolPublicInputs.idxNf2, PoolPublicInputs.idxReal2)]) {
        final nf = l.sublist(at, at + 8);
        paths.add(t.path(nf));
        if (l[real] == 1 && !t.occupied(nf)) t.insert(nf);
      }
    }
    return NullifierSegment(before, t.root, [for (final l in spends) NullifierSegment.chunksOf(l)], paths);
  }

  String? check(NullifierSegment seg) {
    final rows = prog2.witnessAll(proofs1, shapes: [InnerShape(p1, air1[0]), InnerShape(p1, air1[1])], nullifiers: seg);
    return checkTrace(prog2.air(VerifierProgram.nodeDigest(digests1, nullifiers: seg)), rows, chk);
  }

  test('the round\'s real nullifiers are inserted and its dummies leave the tree alone', () {
    final t = spentTree();
    final seg = NullifierSegment.insert(t, spendLanes);
    expect(check(seg), isNull);
    // five spent before, five real inputs now (the deposit has none, spend 1 one)
    final real = [for (final l in spendLanes) l[PoolPublicInputs.idxReal1] + l[PoolPublicInputs.idxReal2]].reduce((a, b) => a + b);
    expect(real, 5);
    final again = spentTree();
    for (final l in spendLanes) {
      for (final (at, r) in [(PoolPublicInputs.idxNf1, PoolPublicInputs.idxReal1), (PoolPublicInputs.idxNf2, PoolPublicInputs.idxReal2)]) {
        if (l[r] == 1) again.insert(l.sublist(at, at + 8));
      }
    }
    expect(seg.after, again.root, reason: 'the node\'s root after is the native insertion of the real inputs only');
  });

  test('a nullifier spent in an earlier round is refused', () {
    final t = spentTree();
    t.insert(spendLanes[3].sublist(PoolPublicInputs.idxNf2, PoolPublicInputs.idxNf2 + 8));
    expect(() => NullifierSegment.insert(spentTree()..insert(spendLanes[3].sublist(PoolPublicInputs.idxNf2, PoolPublicInputs.idxNf2 + 8)), spendLanes),
        throwsStateError);
    expect(check(careless(t, spendLanes)), isNotNull);
  });

  test('the same nullifier twice in one round is refused', () {
    // transfer 3 spends transfer 0's first note again
    final twice = [for (final l in spendLanes) [...l]];
    twice[3].setRange(PoolPublicInputs.idxNf1, PoolPublicInputs.idxNf1 + 8, spendLanes[0].sublist(PoolPublicInputs.idxNf1, PoolPublicInputs.idxNf1 + 8));
    expect(() => NullifierSegment.insert(spentTree(), twice), throwsStateError);
    expect(check(careless(spentTree(), twice)), isNotNull);
  });

  test('a root after other than the insertions reach is refused', () {
    final seg = NullifierSegment.insert(spentTree(), spendLanes);
    final lie = NullifierSegment(seg.before, [...seg.after]..[0] ^= 1, seg.transferChunks, seg.paths);
    expect(check(lie), isNotNull);
  });

  test('a nullifier with a zero lane still has exactly one slot', () {
    final zeroLane = [for (final l in spendLanes) [...l]];
    zeroLane[0][PoolPublicInputs.idxNf1] = 0;
    expect(check(NullifierSegment.insert(spentTree(), zeroLane)), isNull);
  });

  test('the root pins the set\'s roots and binds what level 2 inserted to the transfers\' lanes', () {
    const sha = Sha256ProofHash();
    const p2p = StarkParams(logTrace: 17, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    const rootP = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    final seg = NullifierSegment.insert(spentTree(), spendLanes);
    final digest2 = VerifierProgram.nodeDigest(digests1, nullifiers: seg);
    final air2 = prog2.air(digest2);
    final rows2 = prog2.witnessAll(proofs1, shapes: [InnerShape(p1, air1[0]), InnerShape(p1, air1[1])], nullifiers: seg);
    final proof2 = StarkProver.prove(p2p, air2, rows2, rng: Random(5), hash: p2);
    expect(StarkVerifierRef(p2p, air2, hash: p2).verify(proof2), isTrue);
    final preRoot1 = PreCommitment.root(air1[0], p1, p2);
    final tree = AggregationTree.uniform(PoolPublicInputs.count, const [],
        [(InnerShape(p1, air1[0]), preRoot1), (InnerShape(p2p, air2), PreCommitment.root(air2, p2p, p2))], 2,
        ring: AnchorRing.pool, nullifierLevel: 1);
    final progR = VerifierProgram.compileWide(tree, 15);
    // the round's commitments appended after the notes already in the pool
    // a pool holding one earlier subtree, so the round appends at index 1
    final cm = NoteCommitmentTree()..appendSubtree([for (int i = 0; i < NoteCommitmentTree.subtreeLeaves; i++) lanes(8)]);
    final j = cm.nextSubtree, before = cm.root, paths = <List<List<int>>>[];
    for (int s = 0; s < tree.subtrees; s++) {
      paths.add(cm.subtreePath(j + s));
      cm.appendSubtree([for (final l in tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    List<int> wide({List<int>? nfAfter}) => tree.widePublics(spendLanes,
        rootBefore: before, rootAfter: cm.root, index: j, ring: ring, nfBefore: seg.before, nfAfter: nfAfter ?? seg.after);
    List<List<int>> rowsR(List<int> w) => progR.witnessAll([proof2],
        shapes: [InnerShape(p2p, air2)], widePublics: w, spendLanes: spendLanes, subtreePaths: paths, nullifierRoots: [seg.before, seg.after]);
    final w = wide();
    expect(w.sublist(tree.nullifierOffset, tree.nullifierOffset + 8), seg.before);
    expect(checkTrace(progR.air(w), rowsR(w), chk), isNull);
    // a round claiming another set afterwards
    final lie = wide(nfAfter: [...seg.after]..[3] ^= 1);
    expect(checkTrace(progR.air(lie), rowsR(lie), chk), isNotNull);
    // a transfer's nullifier other than the one level 2 inserted: the root
    // rebuilds level 2's digest from its own pinned lanes
    final other = [...w]..[2 * tree.pinnedChunks * 8 + 1] ^= 1; // transfer 2's nf1, lane 1 (a deposit's dummy)
    expect(checkTrace(progR.air(other), rowsR(other), chk), isNotNull);
    final otherReal = [...w]..[3] ^= 1; // transfer 0's nf1, lane 3
    expect(checkTrace(progR.air(otherReal), rowsR(otherReal), chk), isNotNull);

    final proofR = StarkProver.prove(rootP, progR.air(w), rowsR(w), rng: Random(6), hash: sha);
    expect(StarkVerifierRef(rootP, progR.air(w), hash: sha).verify(proofR), isTrue);
    final gen = StarkVerifierGen(rootP, progR.air(w));
    final lock = gen.generate();
    final sig = gen.buildUnlock(proofR);
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0;
    tx.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
    tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
    Interpreter().correctlySpends(sig, lock, tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    // the same proof does not verify a round claiming another set afterwards
    expect(
        () => Interpreter().correctlySpends(StarkVerifierGen(rootP, progR.air(lie)).buildUnlock(proofR), lock, tx, 0,
            {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000))),
        throwsA(isA<ScriptException>()));
    print('  root with the nullifier chain: ${progR.periodsUsed} periods, script ${lock.buffer.length} B');
  }, timeout: const Timeout(Duration(minutes: 30)));
}
