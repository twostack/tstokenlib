import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
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

/// Two Merkle walks over the same siblings, as the commitment append needs:
/// walk 1 from a leaf L (the old root), walk 2 from a leaf hashed in between
/// (the new root). Per half of 8 periods: walk 1 at 0..2, a leaf period at
/// 3, walk 2 at 4..6, filler at 7.
void main() {
  const t = 9;
  const n = 1 << t;
  const steps = 3;
  const binding = SiblingBinding(walk1: 0, walk2: 4, steps: steps);
  final rng = Random(41);
  int r31() => rng.nextInt(M31.p);
  List<int> w8() => List.generate(8, (_) => r31());
  List<int> w16() => List.generate(16, (_) => r31());

  // per half: siblings, direction bits, the walk-1 leaf and the walk-2 leaf preimage
  final sibs = [for (int h = 0; h < 2; h++) [for (int i = 0; i < steps; i++) w8()]];
  final bits = [
    [true, false, true],
    [false, false, true]
  ];
  final leaf1 = [w8(), w8()];
  final leafPre = [w16(), w16()];

  List<ChainStep> program({List<List<List<int>>>? sib2, List<List<bool>>? bits2}) {
    sib2 ??= sibs;
    bits2 ??= bits;
    final out = <ChainStep>[];
    for (int h = 0; h < 2; h++) {
      final s = sibs[h], b = bits[h], s2 = sib2[h], b2 = bits2[h];
      out.add(ChainStep.fresh(b[0] ? [...s[0], ...leaf1[h]] : [...leaf1[h], ...s[0]], swap: b[0]));
      for (int i = 1; i < steps; i++) {
        out.add(ChainStep.chained(s[i], swap: b[i]));
      }
      out.add(ChainStep.fresh(leafPre[h]));
      for (int i = 0; i < steps; i++) {
        out.add(ChainStep.chained(s2[i], swap: b2[i]));
      }
      out.add(ChainStep.chained(w8()));
    }
    return out;
  }

  final air = Poseidon2ChainAir(t, breakPeriods: const [0, 3], binding: binding);
  final rows = air.generateChain(program());
  final gamma = QM31.fromLimbs(r31(), r31(), r31(), r31());

  Uint32List per(int r) => Uint32List.fromList([for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)]);
  Uint32List lin(int r) {
    final p = air.rowPoint(r);
    return Uint32List.fromList([for (final f in air.linearForms) f.atM31(p.x, p.y)]);
  }

  /// Base rows plus the accumulator columns the prover would derive.
  List<List<int>> withAux(List<List<int>> rs, {QM31? g}) {
    final aux = air.auxColumns(rs, [g ?? gamma]);
    return [for (int r = 0; r < n; r++) [...rs[r], for (final c in aux) c[r]]];
  }

  int mainCount() => air.numConstraints - air.boundaries.fold(0, (a, g) => a + g.exprs.length);

  /// All constraints, base and aux, on full rows; reports the failing indices.
  bool holds(List<List<int>> full, {Set<int>? report, QM31? g}) {
    final out = Uint32List(air.numConstraints);
    final auxOut = List<QM31>.filled(air.numAuxConstraints, QM31.zero);
    final main = mainCount();
    var ok = true;
    for (int r = 0; r < n; r++) {
      final cur = Uint32List.fromList(full[r]), nxt = Uint32List.fromList(full[(r + 1) % n]);
      air.constraintsM31(cur, nxt, per(r), lin(r), out);
      air.auxConstraintsM31(cur, nxt, per(r), lin(r), [g ?? gamma], auxOut);
      for (int j = 0; j < main; j++) {
        if (out[j] != 0) {
          ok = false;
          report?.add(j);
        }
      }
      var lo = main;
      for (final grp in air.boundaries) {
        if (r == grp.row || r == (grp.row + (n >> 1)) % n) {
          for (int j = lo; j < lo + grp.exprs.length; j++) {
            if (out[j] != 0) {
              ok = false;
              report?.add(j);
            }
          }
        }
        lo += grp.exprs.length;
      }
      if (auxOut[0] != QM31.zero) {
        ok = false;
        report?.add(air.numConstraints);
      }
    }
    return ok;
  }

  test('layout: mode register, pins, aux round', () {
    expect(air.numCols, 17);
    expect(air.modeCol, 16);
    expect(air.numAuxCols, 4);
    expect(air.numChallenges, 1);
    expect(air.totalCols, 21);
    expect(air.numAuxConstraints, 1);
    air.validateGroups();
    // mode is 1 in walk 1, 2 in walk 2, 0 elsewhere, in both halves
    for (int p = 0; p < 16; p++) {
      final q = p % 8;
      final want = q < 3 ? 1 : (q >= 4 && q < 7 ? 2 : 0);
      expect(rows[p << 5][air.modeCol], want, reason: 'period $p');
      expect(rows[(p << 5) + 31][air.modeCol], want, reason: 'period $p');
    }
    // the swap bit of a fresh period follows its layout flag
    expect(rows[n - 1][Poseidon2ChainAir.colSwapBit], 1);
    expect(rows[(n >> 1) - 1][Poseidon2ChainAir.colSwapBit], 0);
    print('  binding AIR: ${air.numCols}+${air.numAuxCols} cols, ${air.totalConstraints} constraints, '
        '${air.linearForms.length} forms, ${air.allGroups.length} groups');
  });

  test('the honest trace satisfies everything; spec and fast path agree', () {
    final full = withAux(rows);
    final bad = <int>{};
    expect(holds(full, report: bad), isTrue, reason: 'failing constraints $bad');
    // the accumulator is zero from the end of walk 2 up to the glue row into
    // the next half's walk 1, in both halves ...
    for (final r in [7 << 5, (n >> 1) - 1, (n >> 1) + (7 << 5), n - 1]) {
      expect(full[r].sublist(air.auxCol0, air.auxCol0 + 4), [0, 0, 0, 0], reason: 'row $r');
    }
    // ... and nonzero once the first sibling is absorbed
    for (final r in [0, 2 << 5, n >> 1]) {
      expect(full[r].sublist(air.auxCol0, air.auxCol0 + 4), isNot(equals([0, 0, 0, 0])), reason: 'row $r');
    }
    QM31 emb(int v) => QM31.fromLimbs(v, 0, 0, 0);
    for (int r = 0; r < n; r += 29) {
      final cur = full[r].map(emb).toList(), nxt = full[(r + 1) % n].map(emb).toList();
      final p = per(r).map(emb).toList(), l = lin(r).map(emb).toList();
      final out = Uint32List(air.numConstraints);
      air.constraintsM31(Uint32List.fromList(full[r]), Uint32List.fromList(full[(r + 1) % n]), per(r), lin(r), out);
      expect(air.constraints(cur, nxt, p, l), out.map(emb).toList(), reason: 'base at row $r');
      final auxOut = List<QM31>.filled(1, QM31.zero);
      air.auxConstraintsM31(Uint32List.fromList(full[r]), Uint32List.fromList(full[(r + 1) % n]), per(r), lin(r), [gamma], auxOut);
      expect(air.auxConstraints(cur, nxt, p, l, [gamma]), auxOut, reason: 'aux at row $r');
    }
    // another challenge gives another accumulator that also closes
    expect(holds(withAux(rows, g: QM31.fromLimbs(7, 8, 9, 10)), g: QM31.fromLimbs(7, 8, 9, 10)), isTrue);
  });

  test('a second walk over other siblings, or other directions, is caught', () {
    // one sibling lane differs in walk 2 of the first half
    var sib2 = [for (final h in sibs) [for (final s in h) [...s]]];
    sib2[0][1][3] ^= 1;
    var bad = withAux(air.generateChain(program(sib2: sib2)));
    expect(holds(bad), isFalse, reason: 'sibling');
    // second half too
    sib2 = [for (final h in sibs) [for (final s in h) [...s]]];
    sib2[1][2][0] = M31.add(sib2[1][2][0], 1);
    bad = withAux(air.generateChain(program(sib2: sib2)));
    expect(holds(bad), isFalse, reason: 'sibling, second half');
    // same siblings, one direction bit flipped
    final bits2 = [for (final h in bits) [...h]];
    bits2[0][1] = !bits2[0][1];
    bad = withAux(air.generateChain(program(bits2: bits2)));
    expect(holds(bad), isFalse, reason: 'direction');
    // and the only way to fix the accumulator is to break its recurrence
    bad = withAux(air.generateChain(program(sib2: sib2)));
    for (int r = 0; r < n; r++) {
      for (int k = 0; k < 4; k++) {
        bad[r][air.auxCol0 + k] = 0;
      }
    }
    final report = <int>{};
    expect(holds(bad, report: report), isFalse, reason: 'zeroed accumulator');
    expect(report, contains(air.numConstraints), reason: 'the aux constraint itself must fail');
  });

  test('the mode register cannot be moved or switched off', () {
    // walk 2 flagged as "outside": nothing is subtracted, the end pin fails
    var bad = [for (final r in rows) [...r]];
    for (int r = 4 << 5; r < 7 << 5; r++) {
      bad[r][air.modeCol] = 0;
    }
    expect(holds(withAux(bad)), isFalse, reason: 'mode off in walk 2');
    // walk 2 flagged as walk 1: added instead of subtracted
    bad = [for (final r in rows) [...r]];
    for (int r = 4 << 5; r < 7 << 5; r++) {
      bad[r][air.modeCol] = 1;
    }
    expect(holds(withAux(bad)), isFalse, reason: 'mode 1 in walk 2');
    // the region shifted by one period: the register persistence breaks
    bad = [for (final r in rows) [...r]];
    for (int r = 3 << 5; r < 4 << 5; r++) {
      bad[r][air.modeCol] = 2;
    }
    expect(holds(withAux(bad)), isFalse, reason: 'mode region moved');
    // a mode value outside {0, 1, 2} in walk 1
    bad = [for (final r in rows) [...r]];
    for (int r = 0; r < 3 << 5; r++) {
      bad[r][air.modeCol] = 3;
    }
    expect(holds(withAux(bad)), isFalse, reason: 'mode 3');
  });

  test('proves and verifies in script; cheats are rejected', () {
    const params = StarkParams(
        logTrace: t, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    final proof = StarkProver.prove(params, air, rows, rng: Random(5));
    expect(proof.auxRoot, isNotEmpty);
    expect(proof.traceAtZ.length, air.totalCols);
    final gen = StarkVerifierGen(params, air);
    final lock = gen.generate();
    final unlock = gen.buildUnlock(proof);
    _run(unlock, lock);
    print('  binding AIR (t=$t): lock=${lock.buffer.length} B  unlock=${unlock.buffer.length} B');

    // (The reference prover's aux round is checked against the FFT prover in
    // the byte-identical test below; its cubic interpolation cannot run at
    // this trace size.)

    // a trace whose second walk uses another sibling cannot be proven
    final sib2 = [for (final h in sibs) [for (final s in h) [...s]]];
    sib2[0][0][5] ^= 1;
    expect(() => StarkProver.prove(params, air, air.generateChain(program(sib2: sib2)), rng: Random(5)),
        throwsA(isA<StateError>()));

    // an aux opening that does not match the aux root is rejected in script
    final q0 = proof.queries[0];
    final forged = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, auxRoot: proof.auxRoot, zHint: proof.zHint,
        traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ, friRoots: proof.friRoots,
        finalCoefs: proof.finalCoefs, nonce: proof.nonce,
        queries: [
          QueryProof(
              index: q0.index, compLeaf: q0.compLeaf, compPath: q0.compPath, lineF0: q0.lineF0, lineF1: q0.lineF1, linePaths: q0.linePaths, lineXInv: q0.lineXInv,
              traceLeaf: q0.traceLeaf, tracePath: q0.tracePath,
              auxLeaf: [...q0.auxLeaf]..[0] ^= 1, auxPath: q0.auxPath,
              yBInv: q0.yBInv, dBInvP: q0.dBInvP, dBInvC: q0.dBInvC, dCInvP: q0.dCInvP, dCInvC: q0.dCInvC),
          ...proof.queries.sublist(1)
        ]);
    expect(() => _run(gen.buildUnlock(forged), lock), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('cost of the binding at t=13, blowup 256, 10 queries', () {
    const t13 = 13, n13 = 1 << t13;
    const p = StarkParams(
        logTrace: t13, logBlowup: 8, logExpand: 3, logFinal: 13, numQueries: 10, grindBytes: 3, zkRandomizers: 128);
    final base = Poseidon2ChainAir(t13, breakPeriods: const [0], registers: const [
      [n13 - 1]
    ]);
    final bound = Poseidon2ChainAir(t13,
        breakPeriods: const [0],
        registers: const [
          [n13 - 1]
        ],
        binding: const SiblingBinding(walk1: 1, walk2: 33, steps: 32));
    final s0 = StarkVerifierGen(p, base).generate().buffer.length;
    final s1 = StarkVerifierGen(p, bound).generate().buffer.length;
    print('  t=13 b=8 q=10: without binding $s0 B, with binding $s1 B, delta ${s1 - s0} B');
    // measured 36,884 B: 5 columns (mode register + 4 accumulator limbs),
    // 12 pins in 5 groups, the aux opening per query, the constraint itself
    expect(s1 - s0, lessThan(40000));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
