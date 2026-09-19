import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/recursion/verifier_air.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/air_ring.dart';
import 'package:tstokenlib/src/script_gen/deep_quotient_script_gen.dart' show limbNames;
import 'package:tstokenlib/src/script_gen/fri_fold_script_gen.dart';
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';

/// The verifier AIR's constraints in script: the programs recorded over the
/// ring must agree with the QM31 spec, and the compiled OOD check must
/// accept a consistent instance and reject a tampered one.
void main() {
  final rng = Random(7);
  int r31() => rng.nextInt(M31.p);
  QM31 rQ() => QM31.fromLimbs(r31(), r31(), r31(), r31());
  const t = 10;
  final publics = List.generate(8, (_) => r31());
  final air = VerifierAir(t, VerifierProgramColumns(1 << t), publics);
  final CT = air.totalCols;

  test('the recorded programs agree with the QM31 constraints', () {
    final cur = List.generate(CT, (_) => rQ()), next = List.generate(CT, (_) => rQ());
    final per = List.generate(air.numPeriodic, (_) => rQ()), lin = List.generate(air.numLinear, (_) => rQ());
    final chal = List.generate(air.numChallenges, (_) => rQ());
    final main = air.mainProgram(), aux = air.auxProgram();
    print('  main program: ${main.ops.length} ops / ${main.numMuls} muls; aux: ${aux.ops.length} ops / ${aux.numMuls} muls');
    final pubQ = [for (final p in publics) QM31.fromLimbs(p, 0, 0, 0)];
    final gotMain = main.runOutputs([...cur, ...next, ...per, ...lin, ...pubQ]);
    expect(gotMain, air.constraints(cur, next, per, lin));
    final gotAux = aux.runOutputs([...cur, ...next, ...per, ...lin, ...chal]);
    expect(gotAux, air.auxConstraints(cur, next, per, lin, chal));
  });

  group('script OODS check for the verifier AIR', () {
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

    test('accepts a consistent instance, rejects a tampered one, and its size', () {
      final cur = List.generate(CT, (_) => rQ()), next = List.generate(CT, (_) => rQ());
      final beta = rQ(), zx = rQ(), zy = rQ();
      final chal = List.generate(air.numChallenges, (_) => rQ());
      final compZ = air.compositionAt(cur, next, air.periodicAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
      final c1 = rQ(), c2 = rQ(), c3 = rQ();
      final comp = [compZ - (c1 * QM31.i + c2 * QM31.u + c3 * QM31.i * QM31.u), c1, c2, c3];
      // the ring form of the same check is zero
      expect(air.oodCheckG(QM31Ring.instance, cur, next, comp, beta, zx, zy, chal: chal), QM31.zero);

      final names = <String>[
        for (int k = 0; k < 8; k++) Air.publicName(k),
        for (int j = 0; j < CT; j++) ...limbNames('cur$j'),
        for (int j = 0; j < CT; j++) ...limbNames('next$j'),
        for (int k = 0; k < 4; k++) ...limbNames('comp$k'),
        for (int k = 0; k < air.numChallenges; k++) ...limbNames('chal$k'),
        ...limbNames('beta'), ...limbNames('zx'), ...limbNames('zy'),
      ];
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: names);
      AirScriptGen.emitOodsCheck(e, air);
      for (int k = 0; k < 8; k++) {
        e.dropNamed(Air.publicName(k));
      }
      expect(e.size, 0, reason: 'leftover ${e.debugNames()}');
      e.pushConst(1);
      final lock = b.build();
      print('  verifier AIR OODS check: ${lock.buffer.length} bytes, ${lock.chunks.length} chunks');

      SVScript unlock(List<QM31> nx) {
        final ub = ScriptBuilder();
        for (final p in publics) {
          FriQueryVerifierGen.pushNum(ub, p);
        }
        for (final v in [...cur, ...nx, ...comp, ...chal, beta, zx, zy]) {
          for (final l in v.limbs) {
            FriQueryVerifierGen.pushNum(ub, l);
          }
        }
        return ub.build();
      }

      final sw = Stopwatch()..start();
      run(unlock(next), lock);
      print('  interpreter: ${sw.elapsedMilliseconds} ms');
      final bad = [...next]..[3] = next[3] + QM31.one;
      expect(() => run(unlock(bad), lock), throwsA(isA<ScriptException>()));
      final badAux = [...next]..[air.auxCol0 + 1] = next[air.auxCol0 + 1] + QM31.one;
      expect(() => run(unlock(badAux), lock), throwsA(isA<ScriptException>()));
    });
  });
}
