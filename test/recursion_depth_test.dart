import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_air.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// Recursion depth: a spend proof, then a verifier proof of it, then a
/// verifier proof of that, four levels deep. From level 2 on the inner
/// shape is the verifier itself, so the program, the trace, the proof size
/// and the prover time must not change with depth.
void main() {
  final rng = Random(51);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const inner = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  // every verifier level proves on the same parameters and trace size
  const vLog = 15;
  const vP = StarkParams(logTrace: vLog, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  test('four levels: constant program, proof size and prover time from level 2 on', () {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    final spendAir = PoolSpendAir.air(w.publics);
    var sw = Stopwatch()..start();
    final spendProof = StarkProver.prove(inner, spendAir, w.rows, rng: Random(1), hash: p2);
    print('  level 0 (spend): prover ${sw.elapsedMilliseconds} ms, proof ${ProofSize.bytes(inner, spendAir, p2)} B');

    var shape = InnerShape(inner, spendAir);
    var proof = spendProof;
    final programs = <VerifierProgram>[];
    final sizes = <int>[], times = <int>[];
    for (int level = 1; level <= 4; level++) {
      sw = Stopwatch()..start();
      final program = VerifierProgram.compile(shape, vLog);
      final compileMs = sw.elapsedMilliseconds;
      sw.reset();
      final rows = program.witness(proof);
      final witnessMs = sw.elapsedMilliseconds;
      final vAir = program.air(VerifierProgram.nodeDigestOf(shape.air, proof.preRoot));
      sw.reset();
      final vProof = StarkProver.prove(vP, vAir, rows, rng: Random(level), hash: p2);
      final proveMs = sw.elapsedMilliseconds;
      sw.reset();
      expect(StarkVerifierRef(vP, vAir, hash: p2).verify(vProof), isTrue, reason: 'level $level');
      final verifyMs = sw.elapsedMilliseconds;
      final bytes = ProofSize.bytes(vP, vAir, p2);
      print('  level $level: inner ${shape.air.runtimeType}, ${program.periodsUsed} periods, ${program.vmRows} VM rows, '
          '${program.hintRows} hints; compile $compileMs ms, witness $witnessMs ms, prover $proveMs ms, '
          'verify $verifyMs ms, proof $bytes B, trace 2^$vLog x ${vAir.totalCols} columns');
      programs.add(program);
      sizes.add(bytes);
      times.add(proveMs);
      shape = InnerShape(vP, vAir);
      proof = vProof;
    }
    // the verifier's own shape is the inner shape from level 2 on: identical programs
    for (int level = 3; level <= 4; level++) {
      final a = programs[1].columns.columns, b = programs[level - 1].columns.columns;
      for (int c = 0; c < VerifierProgramColumns.count; c++) {
        expect(b[c], a[c], reason: 'program column ${VerifierProgramColumns.names[c]} differs at level $level');
      }
    }
    expect(sizes.toSet().length, 1, reason: 'every verifier proof has the same size');
    final t2 = times[1];
    for (int level = 3; level <= 4; level++) {
      expect(times[level - 1], lessThan(2 * t2 + 2000), reason: 'prover time at level $level stays flat');
    }
  }, timeout: const Timeout(Duration(minutes: 30)));
}
