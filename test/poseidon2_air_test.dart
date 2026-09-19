import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/poseidon2_m31.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/deep_quotient_script_gen.dart' show limbNames;
import 'package:tstokenlib/src/script_gen/fri_fold_script_gen.dart';
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';

void main() {
  final rng = Random(7);
  int rM31() => rng.nextInt(M31.p);
  QM31 rQ() => QM31.fromLimbs(rM31(), rM31(), rM31(), rM31());
  QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);

  test('instance parameters', () {
    expect(Poseidon2M31.externalRc.length, 8);
    expect(Poseidon2M31.externalRc.every((r) => r.length == 16 && r.every((c) => c < M31.p)), isTrue);
    expect(Poseidon2M31.internalRc.length, 14);
    expect(Poseidon2M31.internalDiag, [M31.p - 2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536]);
    // constants are dense and distinct
    final all = {...Poseidon2M31.externalRc.expand((r) => r), ...Poseidon2M31.internalRc};
    expect(all.length, 8 * 16 + 14);
    // permutation is deterministic and not the identity
    final x = List.generate(16, (i) => i);
    expect(Poseidon2M31.permute(x), Poseidon2M31.permute(x));
    expect(Poseidon2M31.permute(x), isNot(equals(x)));
    print('  permute([0..15])[0..3] = ${Poseidon2M31.permute(x).sublist(0, 4)}');
  });

  test('trace rows follow the schedule and reach the permutation output at row 23', () {
    final air = Poseidon2Air(6);
    final initial = List.generate(16, (_) => rM31());
    final other = List.generate(16, (_) => rM31());
    final rows = air.generateTrace(initial, inputs: [null, other]);
    expect(rows.length, 64);
    expect(rows[0], initial);
    expect(rows[23], Poseidon2M31.permute(initial));
    expect(rows[31], rows[23]);
    expect(rows[32], other);
    expect(rows[55], Poseidon2M31.permute(other));
    // chained by default
    final chained = air.generateTrace(initial);
    expect(chained[32], Poseidon2M31.permute(initial));
  });

  test('constraints vanish on every row of an honest trace, and not on a corrupted one', () {
    final air = Poseidon2Air(6);
    final rows = air.generateTrace(List.generate(16, (_) => rM31()));
    final out = Uint32List(16);
    for (int r = 0; r < 64; r++) {
      final cur = rows[r], next = rows[(r + 1) % 64];
      final per = [for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)];
      air.constraintsM31(Uint32List.fromList(cur), Uint32List.fromList(next), Uint32List.fromList(per), Uint32List(0), out);
      expect(out.every((v) => v == 0), isTrue, reason: 'row $r');
      final q = air.constraints(cur.map(emb).toList(), next.map(emb).toList(), per.map(emb).toList(), const <QM31>[]);
      expect(q.every((v) => v == QM31.zero), isTrue, reason: 'row $r (QM31)');
    }
    // corrupt lane 3 on row 7 (an external-round row) and row 10 (partial)
    for (final r in [7, 10, 0]) {
      final bad = [...rows[r + 1]]..[3] = M31.add(rows[r + 1][3], 1);
      final per = [for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)];
      air.constraintsM31(Uint32List.fromList(rows[r]), Uint32List.fromList(bad), Uint32List.fromList(per), Uint32List(0), out);
      expect(out.any((v) => v != 0), isTrue, reason: 'row $r should fail');
    }
    // free rows accept anything
    final per = [for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, 25)];
    air.constraintsM31(Uint32List.fromList(rows[25]), Uint32List.fromList(List.generate(16, (_) => rM31())), Uint32List.fromList(per), Uint32List(0), out);
    expect(out.every((v) => v == 0), isTrue);
  });

  test('QM31 and M31 constraint paths agree at random points', () {
    final air = Poseidon2Air(7);
    for (int i = 0; i < 5; i++) {
      final cur = List.generate(16, (_) => rM31()), next = List.generate(16, (_) => rM31());
      final per = List.generate(19, (_) => rM31());
      final out = Uint32List(16);
      air.constraintsM31(Uint32List.fromList(cur), Uint32List.fromList(next), Uint32List.fromList(per), Uint32List(0), out);
      final q = air.constraints(cur.map(emb).toList(), next.map(emb).toList(), per.map(emb).toList(), const <QM31>[]);
      expect(q, out.map(emb).toList());
    }
  });

  test('periodic interpolants reproduce the columns on the trace domain', () {
    final air = Poseidon2Air(7);
    final d = HalfCoset(6);
    for (final r in [0, 1, 5, 18, 22, 23, 31, 32, 33, 100, 127]) {
      // cyclic row r of D_7
      final tw = r.isEven ? r >> 1 : d.size + ((2 * d.size - 1 - r) >> 1);
      final i = tw < d.size ? tw : tw - d.size;
      final p = d.at(i);
      final y = tw < d.size ? p.y : M31.neg(p.y);
      final vals = air.periodicAt(emb(p.x), emb(y));
      for (int k = 0; k < air.numPeriodic; k++) {
        expect(vals[k], emb(air.periodicValue(k, r)), reason: 'row $r col $k');
      }
    }
  });

  group('script OODS check for the Poseidon2 AIR', () {
    Transaction tx(SVScript sig) {
      var t = Transaction();
      t.version = 1;
      t.nLockTime = 0;
      t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
      t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
      return t;
    }

    void run(SVScript sig, SVScript lock) =>
        Interpreter().correctlySpends(sig, lock, tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));

    test('accepts a consistent instance, rejects a tampered one, and its size', () {
      const t = 12;
      final air = Poseidon2Air(t);
      final cur = List.generate(16, (_) => rQ()), next = List.generate(16, (_) => rQ());
      final beta = rQ(), zx = rQ(), zy = rQ();
      final compZ =
          air.compositionAt(cur, next, air.periodicAt(zx, zy), air.linearAt(zx, zy), beta, zx);
      final c1 = rQ(), c2 = rQ(), c3 = rQ();
      final comp = [compZ - (c1 * QM31.i + c2 * QM31.u + c3 * QM31.i * QM31.u), c1, c2, c3];

      final names = <String>[
        for (int j = 0; j < 16; j++) ...limbNames('cur$j'),
        for (int j = 0; j < 16; j++) ...limbNames('next$j'),
        for (int k = 0; k < 4; k++) ...limbNames('comp$k'),
        ...limbNames('beta'), ...limbNames('zx'), ...limbNames('zy'),
      ];
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: names);
      AirScriptGen.emitOodsCheck(e, air);
      expect(e.size, 0, reason: 'leftover ${e.debugNames()}');
      e.pushConst(1);
      final lock = b.build();
      print('  Poseidon2 AIR OODS check: ${lock.buffer.length} bytes');

      SVScript unlock(List<QM31> nx) {
        final ub = ScriptBuilder();
        for (final v in [...cur, ...nx, ...comp, beta, zx, zy]) {
          for (final l in v.limbs) {
            FriQueryVerifierGen.pushNum(ub, l);
          }
        }
        return ub.build();
      }

      run(unlock(next), lock);
      final bad = [...next]..[5] = next[5] + QM31.one;
      expect(() => run(unlock(bad), lock), throwsA(isA<ScriptException>()));
    });
  });
}
