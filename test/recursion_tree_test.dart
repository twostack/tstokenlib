import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_air.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'verifier_air_test.dart' show checkTrace;

/// An aggregation tree end to end at small parameters: four spend proofs,
/// two level-1 verifiers (two spends each), one level-2 verifier (two
/// level-1 proofs), and the wide root (the level-2 proof plus every
/// transfer's raw publics as its statement) proved in SHA256 flavour and
/// verified by the generated script.
void main() {
  final rng = Random(47);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const sha = Sha256ProofHash();

  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const p1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const p2p = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  const rootP = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  // four deposits
  final spends = <(Air, PoolSpendWitness)>[];
  for (int n = 0; n < 4; n++) {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 1000 + n, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -(1025 + n), anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    spends.add((PoolSpendAir.air(w.publics), w));
  }

  Transaction tx(SVScript sig) {
    final t = Transaction()
      ..version = 1
      ..nLockTime = 0;
    t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
    t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
    return t;
  }

  void run(SVScript sig, SVScript lock) =>
      Interpreter().correctlySpends(sig, lock, tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));

  test('two levels of aggregation and a wide root verified on chain', () {
    final sw = Stopwatch()..start();
    String lap(String what) {
      final s = '$what ${sw.elapsedMilliseconds} ms';
      sw.reset();
      return s;
    }

    // ---- spends ----
    final spendProofs = [for (final (air, w) in spends) StarkProver.prove(spendP, air, w.rows, rng: Random(1), hash: p2)];
    final spendDigests = [for (int n = 0; n < 4; n++) VerifierProgram.statementDigest(spends[n].$1, spendProofs[n].preRoot)];
    print('  4 spend proofs: ${lap('')}');

    // ---- level 1: two spends per node ----
    final spendShape = InnerShape(spendP, spends[0].$1);
    final prog1 = VerifierProgram.compileAll([spendShape, spendShape], 15);
    print('  level-1 program: ${prog1.periodsUsed} periods, ${prog1.vmRows} VM rows');
    final air1 = <VerifierAir>[], proofs1 = <StarkProof>[];
    for (int m = 0; m < 2; m++) {
      final digest = VerifierProgram.nodeDigest([spendDigests[2 * m], spendDigests[2 * m + 1]]);
      final rows = prog1.witnessAll([spendProofs[2 * m], spendProofs[2 * m + 1]],
          shapes: [InnerShape(spendP, spends[2 * m].$1), InnerShape(spendP, spends[2 * m + 1].$1)]);
      final air = prog1.air(digest);
      if (m == 0) expect(checkTrace(air, rows, [QM31.one, QM31.one + QM31.i, QM31.u]), isNull);
      air1.add(air);
      proofs1.add(StarkProver.prove(p1, air, rows, rng: Random(2 + m), hash: p2));
      expect(StarkVerifierRef(p1, air, hash: p2).verify(proofs1[m]), isTrue);
    }
    print('  level-1 proofs: ${lap('')}');
    final preRoot1 = PreCommitment.root(air1[0], p1, p2);
    expect(PreCommitment.root(air1[1], p1, p2), preRoot1, reason: 'one program, one preprocessed root');
    final digests1 = [for (int m = 0; m < 2; m++) VerifierProgram.statementDigest(air1[m], preRoot1)];

    // ---- level 2: the two level-1 proofs ----
    final shape1 = InnerShape(p1, air1[0]);
    final prog2 = VerifierProgram.compileAll([shape1, shape1], 16);
    print('  level-2 program: ${prog2.periodsUsed} periods, ${prog2.vmRows} VM rows');
    final digest2 = VerifierProgram.nodeDigest(digests1);
    final rows2 = prog2.witnessAll(proofs1, shapes: [InnerShape(p1, air1[0]), InnerShape(p1, air1[1])]);
    final air2 = prog2.air(digest2);
    final proof2 = StarkProver.prove(p2p, air2, rows2, rng: Random(5), hash: p2);
    expect(StarkVerifierRef(p2p, air2, hash: p2).verify(proof2), isTrue);
    print('  level-2 proof: ${lap('')}');
    final preRoot2 = PreCommitment.root(air2, p2p, p2);

    // ---- the root: wide statement over the four transfers ----
    final tree = AggregationTree(PoolPublicInputs.count, const [], [(shape1, preRoot1), (InnerShape(p2p, air2), preRoot2)], 2);
    final progR = VerifierProgram.compileWide(tree, 15);
    print('  root program: ${progR.periodsUsed} periods, ${progR.vmRows} VM rows, ${progR.hintRows} hints');
    // the commitment tree: the round's subtree appended to an empty pool tree
    final spendPubs = [for (final (air, _) in spends) air.publicValues];
    final cmTree = NoteCommitmentTree();
    final rootBefore = cmTree.root, j = cmTree.nextSubtree;
    final paths = <List<List<int>>>[];
    for (int s = 0; s < tree.subtrees; s++) {
      paths.add(cmTree.subtreePath(j + s));
      cmTree.appendSubtree([for (final l in tree.subtreeLeavesOf(spendPubs, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final rootAfter = cmTree.root;
    expect(cmTree.size, tree.leavesAppended);
    final widePublics = tree.widePublics(spendPubs, rootBefore: rootBefore, rootAfter: rootAfter, index: j);
    final rowsR = progR.witnessAll([proof2], shapes: [InnerShape(p2p, air2)], widePublics: widePublics, subtreePaths: paths);
    final airR = progR.air(widePublics);
    expect(airR.numPublics, 4 * 56 + 24);
    // a wrong new root does not fit
    final wrongRoot = [...widePublics]..[tree.roundOffset + 8] ^= 1;
    expect(checkTrace(progR.air(wrongRoot), rowsR, [QM31.one, QM31.one + QM31.i, QM31.u]), isNotNull);
    expect(checkTrace(airR, rowsR, [QM31.one, QM31.one + QM31.i, QM31.u]), isNull);
    print('  root witness: ${lap('')}');
    final proofR = StarkProver.prove(rootP, airR, rowsR, rng: Random(6), hash: sha);
    print('  root proof (SHA256): ${lap('')} ${ProofSize.bytes(rootP, airR, sha)} B');
    expect(StarkVerifierRef(rootP, airR, hash: sha).verify(proofR), isTrue);

    // ---- on chain ----
    final gen = StarkVerifierGen(rootP, airR);
    final lock = gen.generate();
    print('  root verifier script: ${lock.buffer.length} bytes, ${lock.chunks.length} chunks (${lap('')})');
    final unlock = gen.buildUnlock(proofR);
    run(unlock, lock);
    print('  interpreter: ${lap('')}, unlock ${unlock.buffer.length} bytes');

    // a transfer's publics altered: the same proof no longer fits the statement
    final bad = [...widePublics]..[56 + PoolPublicInputs.idxNf1] ^= 1;
    expect(() => run(StarkVerifierGen(rootP, progR.air(bad)).buildUnlock(proofR), lock), throwsA(isA<ScriptException>()));
    // and the witness of a wrong tree does not satisfy the AIR
    expect(checkTrace(progR.air(bad), rowsR, [QM31.one, QM31.one + QM31.i, QM31.u]), isNotNull);
  }, timeout: const Timeout(Duration(minutes: 30)));
}
