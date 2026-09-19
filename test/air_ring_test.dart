import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/air_ring.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_chain_air.dart';

/// The generic (ring) formulation of the AIR constraints must agree with the
/// M31 fast path and with the QM31 spec, and the program an [ExprRing]
/// records must evaluate to the same values: that program is what a verifier
/// inside a circuit runs.
void main() {
  final rng = Random(31);
  int r31() => rng.nextInt(M31.p);
  QM31 rq() => QM31.fromLimbs(r31(), r31(), r31(), r31());
  List<int> lanes(int n) => List.generate(n, (_) => r31());

  final publics = PoolPublicInputs(lanes(8), lanes(8), lanes(8), lanes(8), lanes(8), 1234, outHash: lanes(8));
  final airs = <String, Air>{
    'Poseidon2Air': Poseidon2Air(6),
    'PoolSpendAir': PoolSpendAir.air(publics),
    'chain with sibling binding':
        Poseidon2ChainAir(9, breakPeriods: const [0, 3], binding: const SiblingBinding(walk1: 0, walk2: 4, steps: 3)),
  };

  for (final entry in airs.entries) {
    final name = entry.key, air = entry.value;
    final CT = air.totalCols;
    const f = QM31Ring.instance;

    test('$name: generic constraints agree with the M31 fast path and the QM31 spec', () {
      for (int trial = 0; trial < 3; trial++) {
        final cur = Uint32List.fromList(lanes(CT)), next = Uint32List.fromList(lanes(CT));
        final per = Uint32List.fromList(lanes(air.numPeriodic)), lin = Uint32List.fromList(lanes(air.numLinear));
        final fast = Uint32List(air.numConstraints);
        air.constraintsM31(cur, next, per, lin, fast);
        List<QM31> emb(Uint32List v) => [for (final x in v) QM31.fromLimbs(x, 0, 0, 0)];
        final generic = air.constraintsG(f, emb(cur), emb(next), emb(per), emb(lin));
        expect(generic.length, air.numConstraints);
        for (int j = 0; j < fast.length; j++) {
          expect(generic[j], QM31.fromLimbs(fast[j], 0, 0, 0), reason: 'constraint $j');
        }
        expect(air.constraints(emb(cur), emb(next), emb(per), emb(lin)), generic);
        if (air.numAuxConstraints > 0) {
          final chal = [for (int k = 0; k < air.numChallenges; k++) rq()];
          final out = List<QM31>.filled(air.numAuxConstraints, QM31.zero);
          air.auxConstraintsM31(cur, next, per, lin, chal, out);
          expect(air.auxConstraintsG(f, emb(cur), emb(next), emb(per), emb(lin), chal), out);
        }
      }
    });

    test('$name: the recorded program evaluates the constraints', () {
      final e = ExprRing();
      final cur = e.inputs('cur', CT), next = e.inputs('next', CT);
      final per = e.inputs('per', air.numPeriodic), lin = e.inputs('lin', air.numLinear);
      final chal = e.inputs('chal', air.numChallenges);
      final outs = [...air.constraintsG(e, cur, next, per, lin), ...air.auxConstraintsG(e, cur, next, per, lin, chal)];
      final prog = e.program(outs);
      final vals = [for (int k = 0; k < prog.numInputs; k++) rq()];
      final curV = vals.sublist(0, CT), nextV = vals.sublist(CT, 2 * CT);
      final perV = vals.sublist(2 * CT, 2 * CT + air.numPeriodic);
      final linV = vals.sublist(2 * CT + air.numPeriodic, 2 * CT + air.numPeriodic + air.numLinear);
      final chalV = vals.sublist(2 * CT + air.numPeriodic + air.numLinear);
      final want = [...air.constraintsG(f, curV, nextV, perV, linV), ...air.auxConstraintsG(f, curV, nextV, perV, linV, chalV)];
      expect(prog.runOutputs(vals), want);
      print('  $name: constraint program ${prog.ops.length} ops, ${prog.numMuls} muls');
    });

    test('$name: the cleared out-of-domain check vanishes exactly at the composition value', () {
      final zx = rq(), zy = rq(), beta = rq();
      final cur = [for (int j = 0; j < CT; j++) rq()], next = [for (int j = 0; j < CT; j++) rq()];
      final chal = [for (int k = 0; k < air.numChallenges; k++) rq()];
      final comp = air.compositionAt(cur, next, air.periodicAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
      final limbs = [for (final l in comp.limbs) QM31.fromLimbs(l, 0, 0, 0)];
      expect(air.oodCheckG(f, cur, next, limbs, beta, zx, zy, chal: chal), QM31.zero);
      final bad = [...limbs]..[2] = limbs[2] + QM31.one;
      expect(air.oodCheckG(f, cur, next, bad, beta, zx, zy, chal: chal), isNot(QM31.zero));
      // the same check as a program
      final e = ExprRing();
      final pc = e.inputs('cur', CT), pn = e.inputs('next', CT), pl = e.inputs('comp', 4);
      final pb = e.input('beta'), px = e.input('zx'), py = e.input('zy');
      final pch = e.inputs('chal', air.numChallenges);
      final prog = e.program([air.oodCheckG(e, pc, pn, pl, pb, px, py, chal: pch)]);
      expect(prog.runOutputs([...cur, ...next, ...limbs, beta, zx, zy, ...chal]), [QM31.zero]);
      expect(prog.runOutputs([...cur, ...next, ...bad, beta, zx, zy, ...chal]), isNot([QM31.zero]));
      print('  $name: OOD program ${prog.ops.length} ops, ${prog.numMuls} muls, ${prog.numInputs} inputs');
    });
  }
}
