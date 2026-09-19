import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/air.dart';
import 'package:tstokenlib/src/script_gen/deep_quotient_script_gen.dart' show limbNames;
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

/// Two columns: col0 is the running sum of col1 (free at the wrap), and both
/// columns are pinned at a half-turn pair of rows to public values. The pins
/// live in a constraint group divided by the linear form that vanishes at
/// exactly those two rows.
class PinAir extends Air {
  @override
  final int logTrace;
  final int pinRow;
  final List<int> pinA, pinB; // (col0, col1) at pinRow and pinRow + 2^(t-1)
  PinAir(this.logTrace, this.pinRow, this.pinA, this.pinB);

  @override
  int get numCols => 2;
  @override
  int get numConstraints => 3;
  @override
  int get logPeriod => logTrace;

  int get n => 1 << logTrace;

  @override
  List<List<int>> get periodic => [
        [for (int r = 0; r < n; r++) r == n - 1 ? 0 : 1]
      ];

  @override
  List<LinearForm> get linearForms => [
        LinearForm.vanishingAt(rowPoint(pinRow)),
        LinearForm.selectorAt(rowPoint(pinRow)),
      ];

  @override
  List<ConstraintGroup> get groups => [
        const ConstraintGroup(1),
        const ConstraintGroup(2, divisor: 0),
      ];

  static final int _half = M31.inv(2);

  /// The degree-1 function that is [a] at pinRow and [b] at its half-turn:
  /// (a+b)/2 + ((a-b)/2)*s.
  (int, int) _lagrange(int a, int b) =>
      (M31.mul(M31.add(a, b), _half), M31.mul(M31.sub(a, b), _half));

  @override
  List<QM31> constraints(List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin) {
    final s = lin[1];
    QM31 pin(int j) {
      final (m, h) = _lagrange(pinA[j], pinB[j]);
      return cur[j] - QM31.fromLimbs(m, 0, 0, 0) - s.scale(h);
    }

    return [per[0] * (next[0] - cur[0] - cur[1]), pin(0), pin(1)];
  }

  @override
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out) {
    out[0] = M31.mul(per[0], M31.sub(M31.sub(next[0], cur[0]), cur[1]));
    for (int j = 0; j < 2; j++) {
      final (m, h) = _lagrange(pinA[j], pinB[j]);
      out[1 + j] = M31.sub(M31.sub(cur[j], m), M31.mul(h, lin[1]));
    }
  }

  @override
  void emitConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next,
      List<List<String>> per, List<List<String>> lin, List<List<String>> out) {
    for (int l = 0; l < 4; l++) {
      e.pick(next[0][l]);
      e.pick(cur[0][l]);
      e.sub();
      e.pick(cur[1][l]);
      e.sub();
      e.reduce();
      e.nameTop('_d_$l');
    }
    M31Ops.qm31Mul(e, per[0], limbNames('_d'), out[0]);
    for (int j = 0; j < 2; j++) {
      final (m, h) = _lagrange(pinA[j], pinB[j]);
      for (int l = 0; l < 4; l++) {
        e.pick(cur[j][l]);
        if (l == 0 && m != 0) {
          e.pushConst(m);
          e.sub();
        }
        if (h != 0) {
          e.pick(lin[1][l]);
          if (h != 1) e.mulConst(h);
          e.sub();
        }
        e.reduce();
        e.nameTop(out[1 + j][l]);
      }
    }
    for (final q in [cur[0], cur[1], next[0], next[1], lin[0], lin[1]]) {
      for (final l in q) {
        e.dropNamed(l);
      }
    }
  }

  static List<List<int>> makeTrace(int logTrace, Random rng) {
    final n = 1 << logTrace;
    final c1 = List.generate(n, (_) => rng.nextInt(M31.p));
    final c0 = List.filled(n, 0);
    c0[0] = rng.nextInt(M31.p);
    for (int r = 0; r + 1 < n; r++) {
      c0[r + 1] = M31.add(c0[r], c1[r]);
    }
    return [for (int r = 0; r < n; r++) [c0[r], c1[r]]];
  }
}

Transaction _tx(SVScript sig) {
  var t = Transaction();
  t.version = 1;
  t.nLockTime = 0;
  t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER,
      scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
  t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return t;
}

void _run(SVScript sig, SVScript lock) => Interpreter()
    .correctlySpends(sig, lock, _tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));

void main() {
  const t = 5;
  final rng = Random(11);
  final rows = PinAir.makeTrace(t, rng);
  const pinRow = 3;
  final partner = pinRow + (1 << (t - 1));
  final air = PinAir(t, pinRow, rows[pinRow], rows[partner]);

  test('a vanishing form is zero at exactly the half-turn pair of trace rows', () {
    final w = air.linearForms[0], s = air.linearForms[1];
    final zeros = <int>[];
    for (int r = 0; r < (1 << t); r++) {
      final p = air.rowPoint(r);
      if (w.atM31(p.x, p.y) == 0) zeros.add(r);
    }
    expect(zeros, [pinRow, partner]);
    final pa = air.rowPoint(pinRow), pb = air.rowPoint(partner);
    expect(pb.x, M31.neg(pa.x));
    expect(pb.y, M31.neg(pa.y));
    expect(s.atM31(pa.x, pa.y), 1);
    expect(s.atM31(pb.x, pb.y), M31.p - 1);
  });

  test('main constraint vanishes everywhere, pins vanish only at the pinned pair', () {
    air.validateGroups();
    final n = 1 << t;
    final out = Uint32List(3);
    for (int r = 0; r < n; r++) {
      final p = air.rowPoint(r);
      final lin = Uint32List.fromList([for (final f in air.linearForms) f.atM31(p.x, p.y)]);
      air.constraintsM31(Uint32List.fromList(rows[r]), Uint32List.fromList(rows[(r + 1) % n]),
          Uint32List.fromList([air.periodicValue(0, r)]), lin, out);
      expect(out[0], 0, reason: 'main constraint at row $r');
      final pinned = r == pinRow || r == partner;
      expect(out[1] == 0 && out[2] == 0, pinned, reason: 'pins at row $r');
      // QM31 path agrees
      QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
      final q = air.constraints(rows[r].map(emb).toList(), rows[(r + 1) % n].map(emb).toList(),
          [emb(air.periodicValue(0, r))], lin.map(emb).toList());
      expect(q, out.map(emb).toList(), reason: 'row $r');
    }
  });

  group('end to end through the prover and the script verifier', () {
    for (final zk in [0, 4]) {
      test('zk=$zk: honest proof verifies; a proof for other pins does not', () {
        final params = StarkParams(
            logTrace: t, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: zk);
        final proof = StarkProver.prove(params, air, rows, rng: Random(3));
        final gen = StarkVerifierGen(params, air);
        final lock = gen.generate();
        _run(gen.buildUnlock(proof), lock);
        print('  zk=$zk lock=${lock.buffer.length} B, unlock=${gen.buildUnlock(proof).buffer.length} B');

        // the same proof against a verifier that expects a different pin
        final otherAir = PinAir(t, pinRow, [M31.add(rows[pinRow][0], 1), rows[pinRow][1]], rows[partner]);
        final otherLock = StarkVerifierGen(params, otherAir).generate();
        expect(() => _run(gen.buildUnlock(proof), otherLock), throwsA(isA<ScriptException>()));
      });
    }

    test('a trace that violates a pin cannot be proved', () {
      const params = StarkParams(
          logTrace: t, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
      final wrong = PinAir(t, pinRow, [M31.add(rows[pinRow][0], 1), rows[pinRow][1]], rows[partner]);
      expect(() => StarkProver.prove(params, wrong, rows, rng: Random(3)), throwsA(isA<StateError>()));
    });

    test('the FFT prover and the reference prover agree with boundary groups', () {
      const params = StarkParams(
          logTrace: t, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
      final a = StarkProver.prove(params, air, rows);
      final b = StarkProverRef.prove(params, air, rows);
      expect(a.traceRoot, b.traceRoot);
      expect(a.compRoot, b.compRoot);
      expect(a.compAtZ, b.compAtZ);
      expect(a.finalCoefs, b.finalCoefs);
    });
  });
}
