import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// Every constraint of [air] on the concrete trace: returns the first
/// violation as text, or null.
String? checkTrace(Air air, List<List<int>> rows, List<QM31> chal) {
  final n = rows.length;
  final aux = air.auxColumns(rows, chal);
  final pre = air.preColumns();
  final pub = air.pubColumns();
  final CT = air.totalCols;
  List<int> full(int r) => [
        ...rows[r],
        for (final c in aux) c[r],
        for (final c in pre) c[r],
      ];
  final cur = Uint32List(CT), next = Uint32List(CT);
  final per = Uint32List(air.numPointCols), lin = Uint32List(air.numLinear);
  final out = Uint32List(air.numConstraints);
  final auxOut = List<QM31>.filled(air.numAuxConstraints, QM31.zero);
  for (int r = 0; r < n; r++) {
    cur.setAll(0, full(r));
    next.setAll(0, full((r + 1) % n));
    for (int k = 0; k < air.numPeriodic; k++) {
      per[k] = air.periodicValue(k, r);
    }
    for (int j = 0; j < pub.length; j++) {
      per[air.numPeriodic + j] = pub[j][r];
    }
    final p = air.rowPoint(r);
    for (int k = 0; k < air.numLinear; k++) {
      lin[k] = air.linearForms[k].atM31(p.x, p.y);
    }
    air.constraintsM31(cur, next, per, lin, out);
    for (int j = 0; j < out.length; j++) {
      if (out[j] != 0) return 'constraint $j fails at row $r (period ${r >> 5} row ${r & 31})';
    }
    if (air.numAuxConstraints > 0) {
      air.auxConstraintsM31(cur, next, per, lin, chal, auxOut);
      for (int j = 0; j < auxOut.length; j++) {
        if (auxOut[j] != QM31.zero) return 'aux constraint $j fails at row $r (period ${r >> 5} row ${r & 31})';
      }
    }
  }
  return null;
}

void main() {
  final rng = Random(41);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  QM31 rq() => QM31.fromLimbs(r31(), r31(), r31(), r31());
  const p2 = Poseidon2ProofHash();

  // the inner statement: a pool deposit at small parameters, Poseidon2 flavour
  const inner = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
  final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
  final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
  final w = PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
  final innerAir = PoolSpendAir.air(w.publics);
  late StarkProof innerProof;
  late VerifierProgram program;
  const vLog = 14;

  test('the inner spend proof verifies in the reference verifier', () {
    innerProof = StarkProver.prove(inner, innerAir, w.rows, rng: Random(1), hash: p2);
    expect(StarkVerifierRef(inner, innerAir, hash: p2).verify(innerProof), isTrue);
  });

  test('the program compiles and the witness satisfies every constraint', () {
    final sw = Stopwatch()..start();
    program = VerifierProgram.compile(InnerShape(inner, innerAir), vLog);
    print('  compiled in ${sw.elapsedMilliseconds} ms: ${program.periodsUsed} periods, '
        '${program.vmRows} VM rows, ${program.hintRows} hint rows (trace 2^$vLog = ${1 << vLog} rows)');
    sw.reset();
    final rows = program.witness(innerProof);
    print('  witness in ${sw.elapsedMilliseconds} ms');
    final digest = VerifierProgram.nodeDigestOf(innerAir, innerProof.preRoot);
    final vAir = program.air(digest);
    vAir.validateGroups();
    final chal = [rq(), rq(), rq()];
    expect(checkTrace(vAir, rows, chal), isNull);
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('a tampered inner proof does not fit the program', () {
    final q = innerProof.queries[0];
    final bad = StarkProof(
        traceRoot: innerProof.traceRoot, compRoot: innerProof.compRoot, auxRoot: innerProof.auxRoot,
        preRoot: innerProof.preRoot, zHint: innerProof.zHint, traceAtZ: innerProof.traceAtZ,
        traceAtZg: innerProof.traceAtZg, compAtZ: innerProof.compAtZ, friRoots: innerProof.friRoots,
        finalCoefs: innerProof.finalCoefs, nonce: innerProof.nonce,
        queries: [
          QueryProof(
              index: q.index, compLeaf: [...q.compLeaf]..[1] ^= 1, compPath: q.compPath, lineF0: q.lineF0, lineF1: q.lineF1, linePaths: q.linePaths,
              lineXInv: q.lineXInv, traceLeaf: q.traceLeaf, tracePath: q.tracePath, auxLeaf: q.auxLeaf,
              auxPath: q.auxPath, yBInv: q.yBInv, dBInvP: q.dBInvP, dBInvC: q.dBInvC, dCInvP: q.dCInvP, dCInvC: q.dCInvC),
          ...innerProof.queries.sublist(1)
        ]);
    final rows = program.witness(bad);
    final vAir = program.air(VerifierProgram.nodeDigestOf(innerAir, bad.preRoot));
    final result = checkTrace(vAir, rows, [rq(), rq(), rq()]);
    print('  tampered leaf: $result');
    expect(result, isNotNull);
    // a wrong statement digest
    final vAir2 = program.air(lanes(8));
    expect(checkTrace(vAir2, program.witness(innerProof), [rq(), rq(), rq()]), isNotNull);
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('a level-1 program pins a real spend\'s anchor to the ring: a stale anchor has no witness', () {
    // a note in the tree, spent against the tree's root
    final sk = lanes(5), d = lanes(3);
    final note = OutputNote(pkd: PoolHash.pkd(sk, d), value: 5000, rho: lanes(3), rcm: lanes(4));
    final cmTree = NoteCommitmentTree();
    final pos = cmTree.append(note.cm);
    final path = cmTree.path(pos);
    final a = SpendNote(sk: sk, d: d, value: note.value, rho: note.rho, rcm: note.rcm, siblings: path.siblings, position: pos);
    final dummy = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa2 = OutputNote(pkd: lanes(8), value: 4000, rho: lanes(3), rcm: lanes(4));
    final ob2 = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
    final ws = PoolSpendAir.witness(a, dummy, oa2, ob2, 0, outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    expect(ws.publics.anchor, cmTree.root);
    final spendAir = PoolSpendAir.air(ws.publics);
    final spendProof = StarkProver.prove(inner, spendAir, ws.rows, rng: Random(3), hash: p2);
    final sw = Stopwatch()..start();
    final prog = VerifierProgram.compile(InnerShape(inner, spendAir), vLog, ring: AnchorRing.pool);
    print('  compiled with the ring check in ${sw.elapsedMilliseconds} ms: ${prog.periodsUsed} periods, ${prog.vmRows} VM rows '
        '(${program.periodsUsed} periods, ${program.vmRows} VM rows without)');
    final digestOf = VerifierProgram.statementDigest(spendAir, spendProof.preRoot);
    // the anchor is the ring's third root: the witness selects it
    final ring = [lanes(8), lanes(8), cmTree.root, lanes(8)];
    final rows = prog.witnessAll([spendProof], ring: ring);
    final vAir = prog.air(VerifierProgram.nodeDigest([digestOf], ring: ring));
    expect(checkTrace(vAir, rows, [rq(), rq(), rq()]), isNull);
    // the same trace against another ring's digest is another statement
    final other = [lanes(8), lanes(8), lanes(8), lanes(8)];
    expect(checkTrace(prog.air(VerifierProgram.nodeDigest([digestOf], ring: other)), rows, [rq(), rq(), rq()]), isNotNull);
    // a ring the anchor is not in: no selector can be set, the witness fails
    final stale = prog.witnessAll([spendProof], ring: other);
    final result = checkTrace(prog.air(VerifierProgram.nodeDigest([digestOf], ring: other)), stale, [rq(), rq(), rq()]);
    print('  stale anchor: $result');
    expect(result, isNotNull);
    // a deposit (two dummies) is unconstrained by the ring, as on chain
    final progD = VerifierProgram.compile(InnerShape(inner, innerAir), vLog, ring: AnchorRing.pool);
    final rowsD = progD.witnessAll([innerProof], ring: other);
    expect(checkTrace(progD.air(VerifierProgram.nodeDigest([VerifierProgram.statementDigest(innerAir, innerProof.preRoot)], ring: other)), rowsD,
        [rq(), rq(), rq()]), isNull);
    // and the valid one proves
    const outer = StarkParams(logTrace: vLog, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    final proof = StarkProver.prove(outer, vAir, rows, rng: Random(4), hash: p2);
    expect(StarkVerifierRef(outer, vAir, hash: p2).verify(proof), isTrue);
  }, timeout: const Timeout(Duration(minutes: 15)));

  test('the verifier trace proves and verifies (small parameters)', () {
    const outer = StarkParams(logTrace: vLog, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    final rows = program.witness(innerProof);
    final vAir = program.air(VerifierProgram.nodeDigestOf(innerAir, innerProof.preRoot));
    final sw = Stopwatch()..start();
    final proof = StarkProver.prove(outer, vAir, rows, rng: Random(2), hash: p2, verbose: true);
    print('  outer prover ${sw.elapsedMilliseconds} ms, proof ${ProofSize.bytes(outer, vAir, p2)} B');
    sw.reset();
    expect(StarkVerifierRef(outer, vAir, hash: p2).verify(proof), isTrue);
    print('  outer verify ${sw.elapsedMilliseconds} ms');
  }, timeout: const Timeout(Duration(minutes: 15)));
}
