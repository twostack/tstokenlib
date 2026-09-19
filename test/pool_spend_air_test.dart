import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_chain_air.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
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
  const n = 1 << PoolSpendAir.logTrace;
  const half = PoolSpendAir.half;
  final rng = Random(2026);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int k) => List.generate(k, (_) => r31());
  final gamma = QM31.fromLimbs(r31(), r31(), r31(), r31());

  // Two notes under one anchor. There is no tree yet: give note B a path
  // that ends at note A's root by making A's root B's last sibling's partner.
  // Simplest: both notes share the top sibling chain; build A first and
  // derive B as the leaf that pairs with A's subtree at the top level.
  final skA = lanes(5), skB = lanes(5);
  final noteA = SpendNote(
      sk: skA, d: lanes(3), value: 123456789, rho: lanes(3), rcm: lanes(4),
      siblings: List.generate(32, (_) => lanes(8)), position: 0x5A5A5A5A);
  List<int> subtreeRoot(SpendNote s, int upTo) => PoolHash.root(s.cm, s.siblings.sublist(0, upTo), s.position);
  final bBase = SpendNote(
      sk: skB, d: lanes(3), value: 987654321, rho: lanes(3), rcm: lanes(4),
      siblings: List.generate(32, (_) => lanes(8)), position: 0x12345678 ^ (1 << 31));
  final noteB = SpendNote(
      sk: bBase.sk, d: bBase.d, value: bBase.value, rho: bBase.rho, rcm: bBase.rcm,
      siblings: [...bBase.siblings.sublist(0, 31), subtreeRoot(noteA, 31)], position: bBase.position);
  final fixedA = SpendNote(
      sk: noteA.sk, d: noteA.d, value: noteA.value, rho: noteA.rho, rcm: noteA.rcm,
      siblings: [...noteA.siblings.sublist(0, 31), subtreeRoot(noteB, 31)], position: noteA.position);

  // outputs straddle the limb boundary so both limbs, and a carry, are live
  final outA = OutputNote(pkd: lanes(8), value: (1 << 28) + 5, rho: lanes(3), rcm: lanes(4));
  final outB = OutputNote(pkd: lanes(8), value: 222, rho: lanes(3), rcm: lanes(4));
  final publicOut = fixedA.value + noteB.value - outA.value - outB.value;

  late PoolSpendWitness w;
  late Poseidon2ChainAir air;
  late List<List<int>> rows;
  setUpAll(() {
    w = PoolSpendAir.witness(fixedA, noteB, outA, outB, publicOut);
    air = PoolSpendAir.air(w.publics);
    rows = w.rows;
  });

  Uint32List per(Poseidon2ChainAir air, int r) =>
      Uint32List.fromList([for (int k = 0; k < air.numPeriodic; k++) air.periodicValue(k, r)]);
  Uint32List lin(Poseidon2ChainAir air, int r) {
    final p = air.rowPoint(r);
    return Uint32List.fromList([for (final f in air.linearForms) f.atM31(p.x, p.y)]);
  }

  int mainCountOf(Poseidon2ChainAir air) => air.numConstraints - air.boundaries.fold(0, (a, g) => a + g.exprs.length);

  /// Base rows plus the binding accumulator the prover would derive.
  List<List<int>> withAux(Poseidon2ChainAir air, List<List<int>> rs) {
    final aux = air.auxColumns(rs, [gamma]);
    return [for (int r = 0; r < n; r++) [...rs[r], for (final c in aux) c[r]]];
  }

  /// All constraints, base and aux, on base rows; reports the failing indices.
  bool holdsOn(Poseidon2ChainAir air, List<List<int>> rs, {Set<int>? report}) {
    final full = withAux(air, rs);
    final out = Uint32List(air.numConstraints);
    final auxOut = List<QM31>.filled(air.numAuxConstraints, QM31.zero);
    final main = mainCountOf(air);
    var ok = true;
    for (int r = 0; r < n; r++) {
      final cur = Uint32List.fromList(full[r]), nxt = Uint32List.fromList(full[(r + 1) % n]);
      air.constraintsM31(cur, nxt, per(air, r), lin(air, r), out);
      air.auxConstraintsM31(cur, nxt, per(air, r), lin(air, r), [gamma], auxOut);
      for (int j = 0; j < main; j++) {
        if (out[j] != 0) {
          ok = false;
          report?.add(j);
        }
      }
      var lo = main;
      for (final g in air.boundaries) {
        if (r == g.row || r == (g.row + (n >> 1)) % n) {
          for (int j = lo; j < lo + g.exprs.length; j++) {
            if (out[j] != 0) {
              ok = false;
              report?.add(j);
            }
          }
        }
        lo += g.exprs.length;
      }
      for (int k = 0; k < auxOut.length; k++) {
        if (auxOut[k] != QM31.zero) {
          ok = false;
          report?.add(air.numConstraints + k);
        }
      }
    }
    return ok;
  }

  bool holds(List<List<int>> rs, {Set<int>? report}) => holdsOn(air, rs, report: report);

  test('the two notes really are under one anchor and the trace computes the hashes', () {
    expect(fixedA.root, noteB.root);
    expect(w.publics.anchor, fixedA.root);
    // per half: pk_d, cm, root, nf, cm_out land where the pins expect them
    for (final (base, note, out) in [(0, fixedA, outA), (half, noteB, outB)]) {
      List<int> outOf(int p) => rows[Poseidon2ChainAir.outputRow(base + p)].sublist(0, 8);
      expect(outOf(PoolSpendAir.pIvk), PoolHash.ivk(note.sk));
      expect(outOf(PoolSpendAir.pKey), note.pkd);
      expect(outOf(PoolSpendAir.pNk), PoolHash.nk(note.sk));
      expect(outOf(PoolSpendAir.pCm2), note.cm);
      expect(outOf(PoolSpendAir.pMerkle + PoolSpendAir.depth - 1), note.root);
      expect(outOf(PoolSpendAir.pNf), note.nullifier);
      expect(outOf(PoolSpendAir.pOut2), out.cm);
    }
    expect(air.numCols, PoolSpendAir.numCols);
    expect(air.numAuxCols, 0);
    expect(air.numPublics, PoolPublicInputs.count);
    expect(publicOut > 0, isTrue);
    print('  pool AIR: ${air.numCols}+${air.numAuxCols} cols, ${air.totalConstraints} constraints, ${air.numPeriodic} periodic, '
        '${air.linearForms.length} forms, ${air.allGroups.length} groups, ${air.numPublics} publics');
  });

  test('all constraints hold on the honest trace', () {
    air.validateGroups();
    final bad = <int>{};
    expect(holds(rows, report: bad), isTrue, reason: 'failing constraints $bad');
  });

  test('every cheat the circuit is meant to catch is caught', () {
    List<List<int>> copy() => [for (final r in rows) [...r]];
    // a wrong sibling breaks the anchor pin
    var bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pMerkle + 5)][9] ^= 1;
    expect(holds(bad), isFalse, reason: 'wrong sibling');
    // claiming a different nullifier: the pinned row disagrees
    bad = copy();
    bad[Poseidon2ChainAir.outputRow(PoolSpendAir.pNf)][0] ^= 1;
    expect(holds(bad), isFalse, reason: 'forged nullifier');
    // computing nf from a different key: the register pin at the nf input fails
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pNf)][0] ^= 1;
    expect(holds(bad), isFalse, reason: 'nf from another key');
    // a different rho in the nullifier than in the commitment
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pNf)][PoolSpendAir.nfRhoLane] ^= 1;
    expect(holds(bad), isFalse, reason: 'nf with another rho');
    // junk in the nullifier's padding lanes: a second nullifier for the note
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pNf)][PoolSpendAir.nfRhoLane + PoolHash.rhoLanes + 1] = 5;
    expect(holds(bad), isFalse, reason: 'nf padding');
    // the nullifier key derived under the address tag (nk would equal ivk)
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pNk)][PoolSpendAir.tagLane] = PoolHash.tagIvk;
    expect(holds(bad), isFalse, reason: 'nk tag');
    // a viewing key derived from more than sk and its tag
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pIvk)][15] = 1;
    expect(holds(bad), isFalse, reason: 'ivk padding');
    // an address with junk beside the diversifier
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(PoolSpendAir.pKey)][PoolSpendAir.dLane + PoolHash.dLanes] = 1;
    expect(holds(bad), isFalse, reason: 'pk_d padding');
    // a second-half cheat is caught by the same forms
    bad = copy();
    bad[Poseidon2ChainAir.inputRow(half + PoolSpendAir.pIvk)][2] ^= 1;
    expect(holds(bad), isFalse, reason: 'note B key');
    // an output value that is not what its bits say
    bad = copy();
    bad[PoolSpendAir.outValueRow][PoolSpendAir.valueLo] ^= 1;
    expect(holds(bad), isFalse, reason: 'range: value lane vs bits');
    // a non-boolean bit
    bad = copy();
    bad[(PoolSpendAir.pRange << 5) + 25][Poseidon2ChainAir.bitLane0 + 2] = 2;
    expect(holds(bad), isFalse, reason: 'range: bit not boolean');
    // an output that keeps its bits consistent but breaks the balance
    bad = copy();
    final r = PoolSpendAir.outValueRow;
    bad[r][PoolSpendAir.valueLo] = M31.add(bad[r][PoolSpendAir.valueLo], 1);
    bad[(PoolSpendAir.pRange << 5) + 27][Poseidon2ChainAir.bitLane0] ^= 1; // lowest bit of the low limb
    air.fillAccumulators(bad);
    expect(holds(bad), isFalse, reason: 'balance: value minted');
    // a wrong carry
    bad = copy();
    bad[PoolSpendAir.closeRow][PoolSpendAir.carryLane0] ^= 1;
    expect(holds(bad), isFalse, reason: 'balance: carry');
    // a real note flagged as a dummy keeps its value: the limbs must be zero
    bad = copy();
    for (int r = 0; r < n >> 1; r++) {
      bad[r][PoolSpendAir.regFlag] = 0;
    }
    expect(holds(bad), isFalse, reason: 'dummy flag with a nonzero value');
    // a non-boolean flag
    bad = copy();
    for (int r = 0; r < n >> 1; r++) {
      bad[r][PoolSpendAir.regFlag] = 2;
    }
    expect(holds(bad), isFalse, reason: 'flag not boolean');
  });

  group('one-input spend with a dummy second note', () {
    final dummyB = SpendNote.dummy(sk: skB, rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: fixedA.value - 100, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 60, rho: lanes(3), rcm: lanes(4));
    late PoolSpendWitness wd;
    late Poseidon2ChainAir aird;
    setUpAll(() {
      wd = PoolSpendAir.witness(fixedA, dummyB, oa, ob, 40);
      aird = PoolSpendAir.air(wd.publics);
    });
    List<List<int>> copy() => [for (final r in wd.rows) [...r]];
    final dummyRootRow = Poseidon2ChainAir.outputRow(half + PoolSpendAir.pMerkle + PoolSpendAir.depth - 1);
    final dummyValueRow = (n >> 1) + PoolSpendAir.inValueRow;

    test('the anchor comes from the real note and the dummy half is not under it', () {
      expect(wd.publics.anchor, fixedA.root);
      expect(wd.rows[dummyRootRow].sublist(0, 8), isNot(equals(fixedA.root)));
      expect(wd.rows[dummyValueRow][PoolSpendAir.regFlag], 0);
      expect(wd.rows[PoolSpendAir.inValueRow][PoolSpendAir.regFlag], 1);
      expect(wd.publics.nf2, dummyB.nullifier);
      aird.validateGroups();
      final bad = <int>{};
      // ... so the dummy's path is genuinely free: its root is not the anchor, yet everything holds
      expect(holdsOn(aird, wd.rows, report: bad), isTrue, reason: 'failing constraints $bad');
    });

    test('a dummy cannot carry value, and cannot claim to be real', () {
      // limbs lo = 5, hi = -5 would pass a value-sum gate; the zero pins catch it
      var bad = copy();
      bad[dummyValueRow][PoolSpendAir.valueLo] = 5;
      bad[dummyValueRow][PoolSpendAir.valueHi] = M31.p - 5;
      expect(holdsOn(aird, bad), isFalse, reason: 'dummy with lo = -hi');
      bad = copy();
      bad[dummyValueRow][PoolSpendAir.valueHi] = 1;
      expect(holdsOn(aird, bad), isFalse, reason: 'dummy with a high limb');
      // flag on: the anchor pin fires against the bogus root
      bad = copy();
      for (int r = n >> 1; r < n; r++) {
        bad[r][PoolSpendAir.regFlag] = 1;
      }
      expect(holdsOn(aird, bad), isFalse, reason: 'dummy claiming to be real');
      // the flag is public: the publics must say what the trace says
      expect(wd.publics.real1, isTrue);
      expect(wd.publics.real2, isFalse);
      expect(holdsOn(PoolSpendAir.air(wd.publics.copyWith(real2: true)), wd.rows), isFalse, reason: 'publics declare the dummy real');
      expect(holdsOn(PoolSpendAir.air(wd.publics.copyWith(real1: false)), wd.rows), isFalse, reason: 'publics declare the real note a dummy');
      final flipped = copy();
      for (int r = 0; r < n >> 1; r++) {
        flipped[r][PoolSpendAir.regFlag] = 0;
      }
      expect(holdsOn(PoolSpendAir.air(wd.publics.copyWith(real1: false)), flipped), isFalse,
          reason: 'a real note with value cannot be traced as a dummy either');
      // two dummies need an anchor for the covenant, and can only deposit
      final dummyA = SpendNote.dummy(sk: skA, rho: lanes(3));
      expect(() => PoolSpendAir.witness(dummyB, dummyA, oa, ob, 40), throwsA(isA<ArgumentError>()));
      expect(() => PoolSpendAir.witness(dummyB, dummyA, oa, ob, 40, anchor: lanes(8)),
          throwsA(isA<ArgumentError>()));
    });

    test('a deposit: two dummies, a negative public balance', () {
      final dummyA = SpendNote.dummy(sk: skA, rho: lanes(3));
      final deposit = -(oa.value + ob.value);
      final w = PoolSpendAir.witness(dummyB, dummyA, oa, ob, deposit, anchor: lanes(8));
      expect(w.publics.publicOut, deposit);
      final (lo, hi) = PoolHash.signedLimbs(deposit);
      expect(lo + (hi << PoolHash.limbBits), deposit);
      expect(w.publics.toLanes()[PoolPublicInputs.idxPubHi], hi % M31.p);
      expect(holdsOn(PoolSpendAir.air(w.publics), w.rows), isTrue);
      // the same rows do not balance against a smaller deposit
      final less = PoolSpendAir.air(w.publics.copyWith(publicOut: deposit + 1));
      expect(holdsOn(less, w.rows), isFalse);
    });

    test('the proof verifies, and still binds the anchor to the real note', () {
      const p = StarkParams(
          logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
      final proof = StarkProver.prove(p, aird, wd.rows, rng: Random(11));
      final gen = StarkVerifierGen(p, aird);
      final lock = gen.generate();
      _run(gen.buildUnlock(proof), lock);
      final pb = wd.publics;
      final other = PoolSpendAir.air(pb.copyWith(anchor: [...pb.anchor]..[0] ^= 1));
      expect(() => _run(StarkVerifierGen(p, other).buildUnlock(proof), lock), throwsA(isA<ScriptException>()));
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  test('the balance and range checks accept other balanced spends', () {
    // nothing public leaves; one output takes almost everything, with a low-limb carry
    final oa = OutputNote(pkd: lanes(8), value: fixedA.value + noteB.value - 1, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 1, rho: lanes(3), rcm: lanes(4));
    final w2 = PoolSpendAir.witness(fixedA, noteB, oa, ob, 0);
    final air2 = PoolSpendAir.air(w2.publics);
    expect(holdsOn(air2, w2.rows), isTrue);
    // an unbalanced spend cannot even be built
    expect(() => PoolSpendAir.witness(fixedA, noteB, oa, ob, 1), throwsA(isA<ArgumentError>()));
    // nor an out-of-range output
    expect(() => OutputNote(pkd: lanes(8), value: PoolHash.maxValue, rho: lanes(3), rcm: lanes(4)).cm,
        throwsA(isA<ArgumentError>()));
  });

  test('a verifier for other public inputs rejects the proof; the honest one accepts it', () {
    const p = StarkParams(
        logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    final proof = StarkProver.prove(p, air, rows, rng: Random(9));
    final gen = StarkVerifierGen(p, air);
    final lock = gen.generate();
    _run(gen.buildUnlock(proof), lock);
    // the locking script does not depend on the public inputs ...
    final pb = w.publics;
    final other = PoolSpendAir.air(pb.copyWith(nf1: [...pb.nf1]..[3] ^= 1));
    final otherGen = StarkVerifierGen(p, other);
    expect(otherGen.generate().buffer, lock.buffer);
    // ... the unlocking script carries them, and the proof is bound to them
    expect(() => _run(otherGen.buildUnlock(proof), lock), throwsA(isA<ScriptException>()));
    // claiming a different public amount is the fee cheat; it must fail too
    final fee = PoolSpendAir.air(pb.copyWith(publicOut: pb.publicOut - 1));
    expect(() => _run(StarkVerifierGen(p, fee).buildUnlock(proof), lock), throwsA(isA<ScriptException>()));
    // and so is claiming other extra outputs
    final outs = PoolSpendAir.air(pb.copyWith(outHash: [...pb.outHash]..[0] ^= 1));
    expect(() => _run(StarkVerifierGen(p, outs).buildUnlock(proof), lock), throwsA(isA<ScriptException>()));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('production parameters: locking script size, proof size, timings', () {
    const p = PoolSpendAir.productionParams;
    expect(p.zkSufficient, isTrue);
    final gen = StarkVerifierGen(p, air);
    final lock = gen.generate();
    print('--- pool spend, production params (t=12, blowup 32, 18 queries, 16-bit grinding, zk R=128) ---');
    print('  locking script   : ${lock.buffer.length} bytes');
    final sw = Stopwatch()..start();
    final proof = StarkProver.prove(p, air, rows, rng: Random(1), verbose: true);
    final proveMs = sw.elapsedMilliseconds;
    final unlock = gen.buildUnlock(proof);
    sw.reset();
    _run(unlock, lock);
    print('  unlocking script : ${unlock.buffer.length} bytes');
    print('  prover time      : $proveMs ms');
    print('  interp time      : ${sw.elapsedMilliseconds} ms');
  }, timeout: const Timeout(Duration(minutes: 20)));
}
