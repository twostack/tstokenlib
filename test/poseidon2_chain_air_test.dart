import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/poseidon2_m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_chain_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

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
  const t = 8; // 256 rows = 8 periods, two halves of 4
  const n = 1 << t;
  final rng = Random(23);
  int r31() => rng.nextInt(M31.p);

  // Program: each half starts fresh, then chains three more permutations, one
  // of them with the digest swapped into the high half.
  List<int> w8() => List.generate(8, (_) => r31());
  List<int> w16() => List.generate(16, (_) => r31());
  final steps = <ChainStep>[
    ChainStep.fresh(w16()),
    ChainStep.chained(w8()),
    ChainStep.chained(w8(), swap: true),
    ChainStep.chained(w8()),
    ChainStep.fresh(w16()),
    ChainStep.chained(w8()),
    ChainStep.chained(w8(), swap: true),
    ChainStep.chained(w8()),
  ];

  // Phase 1: the plain chain, to read off the values the pins will bind.
  final plain = Poseidon2ChainAir(t, breakPeriods: [0], registers: [[n - 1], [n - 1]]);
  final plainRows = plain.generateChain(steps);
  final regA = [plainRows[Poseidon2ChainAir.inputRow(1)][0], plainRows[Poseidon2ChainAir.inputRow(1)][1]];
  final regB = [plainRows[Poseidon2ChainAir.inputRow(5)][0], plainRows[Poseidon2ChainAir.inputRow(5)][1]];
  final digestA = plainRows[Poseidon2ChainAir.outputRow(3)];
  final digestB = plainRows[Poseidon2ChainAir.outputRow(7)];

  // Phase 2: pin the final digest of each half to its public value, and tie
  // the register to the state lane it must reach.
  final air = Poseidon2ChainAir(t,
      breakPeriods: [0],
      registers: [[n - 1], [n - 1]],
      boundaries: [
        BoundaryGroup(Poseidon2ChainAir.outputRow(3),
            [for (int j = 0; j < 8; j++) BoundaryExpr.public(j, digestA[j], digestB[j])]),
        BoundaryGroup(Poseidon2ChainAir.inputRow(1),
            [BoundaryExpr.equal(16, 0), BoundaryExpr.equal(17, 1)]),
      ]);
  final rows = air.generateChain(steps);
  for (int r = 0; r < n; r++) {
    final reg = r < (n >> 1) ? regA : regB;
    rows[r][16] = reg[0];
    rows[r][17] = reg[1];
  }

  Uint32List _per(int r) =>
      Uint32List.fromList([for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)]);
  Uint32List _lin(int r) {
    final p = air.rowPoint(r);
    return Uint32List.fromList([for (final f in air.linearForms) f.atM31(p.x, p.y)]);
  }

  test('the chain computes the permutations it claims to', () {
    expect(rows.length, n);
    expect(rows[0].length, 18);
    for (int p = 0; p < 8; p++) {
      final input = rows[Poseidon2ChainAir.inputRow(p)].sublist(0, 16);
      expect(rows[Poseidon2ChainAir.outputRow(p)].sublist(0, 16), Poseidon2M31.permute(input));
    }
    // chained periods absorb the previous digest in the half the swap bit picks
    for (final p in [1, 2, 3, 5, 6, 7]) {
      final prev = rows[Poseidon2ChainAir.outputRow(p - 1)].sublist(0, 8);
      final input = rows[Poseidon2ChainAir.inputRow(p)];
      final swapped = steps[p].swap;
      expect(input.sublist(swapped ? 8 : 0, swapped ? 16 : 8), prev, reason: 'period $p');
      expect(rows[Poseidon2ChainAir.inputRow(p) - 1][Poseidon2ChainAir.colSwapBit], swapped ? 1 : 0);
    }
    // the register holds its half's value
    expect(rows[0].sublist(16), regA);
    expect(rows[n - 1].sublist(16), regB);
  });

  /// Constraint index ranges: the main group, then one range per boundary group.
  int mainCount() => air.numConstraints - air.boundaries.fold(0, (a, g) => a + g.exprs.length);

  test('main constraints vanish on every row; each boundary group vanishes on its own pair', () {
    air.validateGroups();
    final out = Uint32List(air.numConstraints);
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    final main = mainCount();
    for (int r = 0; r < n; r++) {
      final cur = Uint32List.fromList(rows[r]), nxt = Uint32List.fromList(rows[(r + 1) % n]);
      final per = _per(r), lin = _lin(r);
      air.constraintsM31(cur, nxt, per, lin, out);
      for (int j = 0; j < main; j++) {
        expect(out[j], 0, reason: 'main constraint $j at row $r');
      }
      var lo = main;
      for (final g in air.boundaries) {
        final applies = r == g.row || r == (g.row + (n >> 1)) % n;
        final vanishes = [for (int j = lo; j < lo + g.exprs.length; j++) out[j]].every((v) => v == 0);
        if (applies) {
          expect(vanishes, isTrue, reason: 'group at row ${g.row} must hold at row $r');
        }
        lo += g.exprs.length;
      }
      if (r % 37 == 0) {
        final q = air.constraints(rows[r].map(emb).toList(), rows[(r + 1) % n].map(emb).toList(),
            per.map(emb).toList(), lin.map(emb).toList());
        expect(q, out.map(emb).toList(), reason: 'row $r');
      }
    }
  });

  test('breaking the chain, the swap, the register or a pin is caught', () {
    final out = Uint32List(air.numConstraints);
    final main = mainCount();
    bool ok(List<List<int>> rs) {
      for (int r = 0; r < n; r++) {
        air.constraintsM31(Uint32List.fromList(rs[r]), Uint32List.fromList(rs[(r + 1) % n]), _per(r), _lin(r), out);
        for (int j = 0; j < main; j++) {
          if (out[j] != 0) return false;
        }
        var lo = main;
        for (final g in air.boundaries) {
          if (r == g.row || r == (g.row + (n >> 1)) % n) {
            for (int j = lo; j < lo + g.exprs.length; j++) {
              if (out[j] != 0) return false;
            }
          }
          lo += g.exprs.length;
        }
      }
      return true;
    }

    expect(ok(rows), isTrue);
    // inject a digest at a chained period's input instead of carrying it
    var bad = [for (final r in rows) [...r]];
    bad[Poseidon2ChainAir.inputRow(2)][8] = M31.add(bad[Poseidon2ChainAir.inputRow(2)][8], 1);
    expect(ok(bad), isFalse);
    // flip a swap bit
    bad = [for (final r in rows) [...r]];
    bad[Poseidon2ChainAir.inputRow(1) - 1][Poseidon2ChainAir.colSwapBit] = 1;
    expect(ok(bad), isFalse);
    // a non-boolean swap bit
    bad = [for (final r in rows) [...r]];
    bad[Poseidon2ChainAir.inputRow(3) - 1][Poseidon2ChainAir.colSwapBit] = 7;
    expect(ok(bad), isFalse);
    // change the register in one half only
    bad = [for (final r in rows) [...r]];
    bad[5][16] = M31.add(bad[5][16], 1);
    expect(ok(bad), isFalse);
    // a fresh (break) period may take any input: rewriting it only breaks the pins
    bad = [for (final r in rows) [...r]];
    bad[Poseidon2ChainAir.inputRow(0)][3] = M31.add(bad[Poseidon2ChainAir.inputRow(0)][3], 1);
    expect(ok(bad), isFalse, reason: 'the pinned digest no longer follows');
  });

  test('proves and verifies in script', () {
    const params = StarkParams(
        logTrace: t, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    final proof = StarkProver.prove(params, air, rows, rng: Random(5));
    final gen = StarkVerifierGen(params, air);
    final lock = gen.generate();
    final unlock = gen.buildUnlock(proof);
    _run(unlock, lock);
    print('  chain AIR (t=$t, ${air.numCols} cols, ${air.numConstraints} constraints, ${air.linearForms.length} forms)');
    print('    lock=${lock.buffer.length} B  unlock=${unlock.buffer.length} B');

    // a verifier expecting a different public digest rejects this proof
    final other = Poseidon2ChainAir(t,
        breakPeriods: [0],
        registers: [[n - 1], [n - 1]],
        boundaries: [
          BoundaryGroup(Poseidon2ChainAir.outputRow(3),
              [for (int j = 0; j < 8; j++) BoundaryExpr.public(j, j == 2 ? M31.add(digestA[j], 1) : digestA[j], digestB[j])]),
          BoundaryGroup(Poseidon2ChainAir.inputRow(1), [BoundaryExpr.equal(16, 0), BoundaryExpr.equal(17, 1)]),
        ]);
    expect(() => _run(unlock, StarkVerifierGen(params, other).generate()), throwsA(isA<ScriptException>()));
  });
}
