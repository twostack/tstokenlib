import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/poseidon2_m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

/// The two hash flavours of the proof system: SHA256 (what the script
/// verifies) and Poseidon2 (what a verifier inside a circuit can afford),
/// and the Dart reference verifier that accepts both.
void main() {
  final native = StarkKernels.tryLoad();
  final dart = DartKernels();
  final skipNative = native == null ? 'native kernels not built' : null;
  const sha = Sha256ProofHash();
  const p2 = Poseidon2ProofHash();

  final rng = Random(21);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  Uint32List col(int n) => Uint32List.fromList(List.generate(n, (_) => r31()));

  test('native Poseidon2 permutation matches Dart', () {
    for (int i = 0; i < 20; i++) {
      final s = lanes(16);
      expect(native!.poseidon2(s), Poseidon2M31.permute(s));
    }
  }, skip: skipNative);

  test('Poseidon2 commitments match between native and Dart kernels', () {
    for (final m in [3, 6, 9]) {
      final n = 1 << (m + 1);
      final coefs = [for (int j = 0; j < 5; j++) col(n ~/ 2)];
      final (evD, tD) = dart.commitColumns(coefs, m, p2);
      final (evN, tN) = native!.commitColumns(coefs, m, p2);
      expect([for (int j = 0; j < evN.count; j++) evN.column(j)], [for (int j = 0; j < evD.count; j++) evD.column(j)]);
      evN.release();
      expect(tN.root, tD.root, reason: 'root m=$m');
      for (final leaf in [0, 3, (1 << m) - 1]) {
        expect(tN.path(leaf), tD.path(leaf), reason: 'path $leaf m=$m');
      }
      final layer = col(4 * n);
      final pD = dart.merklePairs(layer, m + 1, p2), pN = native.merklePairs(layer, m + 1, p2);
      expect(pN.root, pD.root, reason: 'pairs root m=$m');
      expect(pN.path(1), pD.path(1));
    }
  }, skip: skipNative);

  test('Poseidon2 transcript and leaves are deterministic and flavour-specific', () {
    final t1 = p2.transcript(), t2 = p2.transcript();
    t1.absorbLimbs([1, 2, 3]);
    t2.absorbLimbs([1, 2, 3]);
    expect(t1.squeezeQM31(), t2.squeezeQM31());
    expect(t1.squeezeIndices(5, 10), t2.squeezeIndices(5, 10));
    expect(t1.squeezeIndices(3, 10).every((i) => i < 1024), isTrue);
    final pre = List<int>.of((t1 as Poseidon2Transcript).state);
    Poseidon2Transcript at(List<int> s) => Poseidon2Transcript()..state = List<int>.of(s);
    final nonce = t1.grind(1);
    expect(at(pre).checkGrinding(nonce, 1), isTrue);
    expect(at(pre).checkGrinding([nonce[0] + 1], 1), isFalse);
    expect(t1.state, isNot(equals(pre)), reason: 'the grind digest is the state (SECURITY_CLAIM D1)');
    expect(p2.leaf(lanes(8)).length, 8);
    expect(p2.leaf(lanes(58)), isNot(equals(p2.leaf(lanes(58)))));
    expect(sha.leaf([1, 2]).length, 32);
  });

  final initial = List.generate(16, (i) => (i * 104729 + 1) % M31.p);

  test('reference and FFT provers agree in the Poseidon2 flavour (zk off)', () {
    const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    final air = Poseidon2Air(params.logTrace);
    final rows = air.generateTrace(initial);
    final ref = StarkProverRef.prove(params, air, rows, hash: p2);
    final fft = StarkProver.prove(params, air, rows, hash: p2, kernels: dart);
    final nat = native == null ? fft : StarkProver.prove(params, air, rows, hash: p2, kernels: native);
    for (final other in [fft, nat]) {
      expect(other.traceRoot, ref.traceRoot);
      expect(other.compRoot, ref.compRoot);
      expect(other.traceAtZ, ref.traceAtZ);
      expect(other.compAtZ, ref.compAtZ);
      expect(other.friRoots, ref.friRoots);
      expect(other.finalCoefs, ref.finalCoefs);
      expect(other.nonce, ref.nonce);
      for (int q = 0; q < ref.queries.length; q++) {
        expect(other.queries[q].index, ref.queries[q].index);
        expect(other.queries[q].compPath, ref.queries[q].compPath);
        expect(other.queries[q].tracePath, ref.queries[q].tracePath);
        expect(other.queries[q].linePaths, ref.queries[q].linePaths);
      }
    }
    expect(StarkVerifierRef(params, air, hash: p2).verify(ref), isTrue);
    expect(StarkVerifierRef(params, air, hash: p2).verify(fft), isTrue);
    // the SHA256 flavour is untouched and the reference verifier accepts it too
    final shaProof = StarkProverRef.prove(params, air, rows);
    expect(StarkVerifierRef(params, air).verify(shaProof), isTrue);
    expect(StarkVerifierRef(params, air, hash: p2).check(shaProof), isNotNull, reason: 'wrong flavour is rejected');
  });

  // a pool deposit at small parameters is a full trace for the real AIR
  PoolSpendWitness witness() {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
    return PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
  }

  const small = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);

  test('Poseidon2-flavour spend proofs verify; tampering and wrong publics are caught', () {
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    final proof = StarkProver.prove(small, air, w.rows, rng: Random(1), hash: p2);
    final v = StarkVerifierRef(small, air, hash: p2);
    expect(v.verify(proof), isTrue);
    // a different transcript: another instance's publics
    final other = PoolSpendAir.air(w.publics.copyWith(publicOut: w.publics.publicOut + 1));
    expect(StarkVerifierRef(small, other, hash: p2).check(proof), isNotNull);
    // a corrupted opening
    final q = proof.queries[0];
    final bad = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, auxRoot: proof.auxRoot, zHint: proof.zHint,
        traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ, friRoots: proof.friRoots,
        finalCoefs: proof.finalCoefs, nonce: proof.nonce,
        queries: [
          QueryProof(
              index: q.index, compLeaf: [...q.compLeaf]..[0] ^= 1, compPath: q.compPath, lineF0: q.lineF0, lineF1: q.lineF1, linePaths: q.linePaths,
              lineXInv: q.lineXInv, traceLeaf: q.traceLeaf, tracePath: q.tracePath, auxLeaf: q.auxLeaf,
              auxPath: q.auxPath, yBInv: q.yBInv, dBInvP: q.dBInvP, dBInvC: q.dBInvC, dCInvP: q.dCInvP, dCInvC: q.dCInvC),
          ...proof.queries.sublist(1)
        ]);
    expect(v.check(bad), contains('composition root'));
    // a wrong nonce
    final badNonce = StarkProof(
        traceRoot: proof.traceRoot, compRoot: proof.compRoot, auxRoot: proof.auxRoot, zHint: proof.zHint,
        traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ, friRoots: proof.friRoots,
        finalCoefs: proof.finalCoefs, nonce: [proof.nonce[0] + 1], queries: proof.queries);
    expect(v.check(badNonce), 'grinding');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('SHA256-flavour spend proofs: the reference verifier agrees with the script', () {
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    final proof = StarkProver.prove(small, air, w.rows, rng: Random(2));
    expect(StarkVerifierRef(small, air).verify(proof), isTrue);
    final gen = StarkVerifierGen(small, air);
    final lock = gen.generate();
    final unlock = gen.buildUnlock(proof);
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0;
    tx.inputs.add(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER,
        scriptBuilder: DefaultUnlockBuilder.fromScript(unlock)));
    tx.outputs.add(TransactionOutput(BigInt.from(1000), P2PKHLockBuilder.fromAddress(Address('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn')).getScriptPubkey()));
    Interpreter().correctlySpends(unlock, lock, tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('production parameters, Poseidon2 flavour: prover time and proof size', () {
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    const p = PoolSpendAir.productionParams;
    final sw = Stopwatch()..start();
    final proof = StarkProver.prove(p, air, w.rows, rng: Random(3), hash: p2, verbose: true);
    final proveMs = sw.elapsedMilliseconds;
    sw.reset();
    expect(StarkVerifierRef(p, air, hash: p2).verify(proof), isTrue);
    print('  poseidon2 flavour: prover $proveMs ms, reference verify ${sw.elapsedMilliseconds} ms, '
        'proof ${ProofSize.bytes(p, air, p2)} B (sha256 flavour ${ProofSize.bytes(p, air, sha)} B)');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
