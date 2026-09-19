import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/script_gen/air_ring.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';

/// A Poseidon2 AIR with one preprocessed column, the row index, and a
/// constraint that reads it: (next - cur - 1) * next == 0 (the wrap row has
/// next == 0). Tests the fourth commitment through both provers and the
/// reference verifier, in both hash flavours.
class RowIdAir extends Poseidon2Air {
  final int offset;
  RowIdAir(super.logTrace, {this.offset = 0});
  @override
  int get numPreCols => 1;
  @override
  int get numConstraints => 17;
  @override
  List<Uint32List> preColumns() => [Uint32List.fromList([for (int r = 0; r < 1 << logTrace; r++) (r + offset) % M31.p])];
  @override
  List<T> constraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin) {
    final base = super.constraintsG(f, cur, next, per, lin);
    final c = preCol0;
    return [...base, f.mul(f.sub(f.sub(next[c], cur[c]), f.one), next[c])];
  }
  @override
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out) {
    super.constraintsM31(cur, next, per, lin, out);
    final c = preCol0;
    out[16] = M31.mul(M31.sub(M31.sub(next[c], cur[c]), 1), next[c]);
  }
}

void main() {
  final initial = List.generate(16, (i) => (i * 7919 + 3) % M31.p);
  const p2 = Poseidon2ProofHash(), sha = Sha256ProofHash();

  test('reference and FFT provers agree with a preprocessed column (zk off)', () {
    const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
    final air = RowIdAir(5);
    final rows = air.generateTrace(initial);
    for (final hash in [sha, p2]) {
      final ref = StarkProverRef.prove(params, air, rows, hash: hash);
      final fft = StarkProver.prove(params, air, rows, hash: hash);
      expect(fft.preRoot, ref.preRoot);
      expect(fft.traceAtZ, ref.traceAtZ);
      expect(fft.friRoots, ref.friRoots);
      expect(fft.queries[0].preLeaf, ref.queries[0].preLeaf);
      expect(fft.queries[0].prePath, ref.queries[0].prePath);
      expect(StarkVerifierRef(params, air, hash: hash).verify(ref), isTrue, reason: hash.name);
      expect(StarkVerifierRef(params, air, hash: hash).verify(fft), isTrue, reason: hash.name);
    }
  });

  test('the verifier pins the preprocessed root and opens the column', () {
    const params = StarkParams(logTrace: 8, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 3, grindBytes: 1, zkRandomizers: 8);
    final air = RowIdAir(8);
    final rows = air.generateTrace(initial);
    final proof = StarkProver.prove(params, air, rows, rng: Random(1), hash: p2);
    expect(proof.preRoot.length, 8);
    expect(StarkVerifierRef(params, air, hash: p2).verify(proof), isTrue);
    // a circuit with different preprocessed data rejects the proof at the root
    expect(StarkVerifierRef(params, RowIdAir(8, offset: 1), hash: p2).check(proof), 'preprocessed root');
    // a trace that disagrees with the fixed column has no low-degree composition: the prover refuses
    expect(() => StarkProver.prove(params, RowIdAir(8, offset: 1), rows, rng: Random(1), hash: p2), throwsA(isA<StateError>()));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
