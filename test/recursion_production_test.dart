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

/// The depth chain at production-grade parameters: the spend proof as the
/// pool makes it (106 conjectured bits), verifier levels at blowup 16, 22
/// queries and 14-bit grinding (about 102 bits) on a 2^18 trace.
void main() {
  final rng = Random(61);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const inner = PoolSpendAir.productionParams;
  const vLog = 18;
  const vP = StarkParams(logTrace: vLog, logBlowup: 4, logExpand: 3, logFinal: 10, numQueries: 22, grindBytes: 2);

  test('production parameters: four levels', () {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    final spendAir = PoolSpendAir.air(w.publics);
    var sw = Stopwatch()..start();
    final spendProof = StarkProver.prove(inner, spendAir, w.rows, rng: Random(1), hash: p2);
    print('  level 0 (spend, production): prover ${sw.elapsedMilliseconds} ms, proof ${ProofSize.bytes(inner, spendAir, p2)} B');

    var shape = InnerShape(inner, spendAir);
    var proof = spendProof;
    final programs = <VerifierProgram>[];
    for (int level = 1; level <= 4; level++) {
      sw = Stopwatch()..start();
      final program = VerifierProgram.compile(shape, vLog);
      final rows = program.witness(proof);
      final witnessMs = sw.elapsedMilliseconds;
      final vAir = program.air(VerifierProgram.nodeDigestOf(shape.air, proof.preRoot));
      sw.reset();
      final vProof = StarkProver.prove(vP, vAir, rows, rng: Random(level), hash: p2, verbose: level <= 2);
      final proveMs = sw.elapsedMilliseconds;
      sw.reset();
      expect(StarkVerifierRef(vP, vAir, hash: p2).verify(vProof), isTrue, reason: 'level $level');
      final verifyMs = sw.elapsedMilliseconds;
      print('  level $level: inner ${shape.air.runtimeType}, ${program.periodsUsed} periods, ${program.vmRows} VM rows, '
          '${program.hintRows} hints; compile+witness $witnessMs ms, prover $proveMs ms, verify $verifyMs ms, '
          'proof ${ProofSize.bytes(vP, vAir, p2)} B, trace 2^$vLog x ${vAir.totalCols} columns');
      programs.add(program);
      shape = InnerShape(vP, vAir);
      proof = vProof;
    }
    for (int level = 3; level <= 4; level++) {
      for (int c = 0; c < VerifierProgramColumns.count; c++) {
        expect(programs[level - 1].columns.columns[c], programs[1].columns.columns[c],
            reason: 'program column ${VerifierProgramColumns.names[c]} differs at level $level');
      }
    }
  }, timeout: const Timeout(Duration(hours: 2)));
}
