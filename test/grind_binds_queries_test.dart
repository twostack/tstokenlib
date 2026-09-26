/*
  Copyright 2024 - Stephan M. February
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/script_gen/fiat_shamir_script_gen.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_air.dart';

/// SECURITY_CLAIM D1: the grind digest is the transcript state the query
/// indices are squeezed from. Before the fix the indices came from the state
/// before the nonce, so any nonce meeting the target gave the same queries
/// and the grind bought no soundness. These tests are the attack that passed.

/// [proof] with its nonce replaced.
StarkProof _withNonce(StarkProof proof, List<int> nonce) => StarkProof(
    traceRoot: proof.traceRoot, compRoot: proof.compRoot, auxRoot: proof.auxRoot, preRoot: proof.preRoot,
    zHint: proof.zHint, traceAtZ: proof.traceAtZ, traceAtZg: proof.traceAtZg, compAtZ: proof.compAtZ,
    friRoots: proof.friRoots, finalCoefs: proof.finalCoefs, nonce: nonce, queries: proof.queries);

/// The next nonce after [proof]'s that the verifier accepts as a grind, found
/// by asking the verifier: a nonce that misses the target is refused as
/// 'grinding', one that meets it gets past that check. Returns the nonce and
/// what the verifier said about the proof carrying it.
(List<int>, String) nextValidNonce(StarkVerifierRef v, StarkProof proof, List<int> Function(int) encode, int from) {
  for (int n = from + 1;; n++) {
    final nonce = encode(n);
    try {
      v.verify(_withNonce(proof, nonce));
      return (nonce, 'accepted');
    } on VerificationFailure catch (f) {
      if (f.what != 'grinding') return (nonce, f.what);
    }
  }
}

void main() {
  final initial = List.generate(16, (i) => (i * 104729 + 1) % M31.p);
  const params = StarkParams(logTrace: 5, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  final air = Poseidon2Air(params.logTrace);
  final rows = air.generateTrace(initial);

  List<int> le4(int n) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
  int fromLe4(List<int> b) => b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);

  test('SHA256 transcript: two nonces that both grind give two sets of query indices', () {
    final t = TranscriptRef()..absorbLimbs([1, 2, 3]);
    final pre = List<int>.of(t.state);
    final n1 = t.grind(2);
    final idx1 = t.squeezeIndices(8, 20);
    // the next grinding nonce, tried against the same state
    List<int>? n2;
    for (int n = fromLe4(n1) + 1; n2 == null; n++) {
      final u = TranscriptRef()..state = List<int>.of(pre);
      if (u.checkGrinding(le4(n), 2)) {
        n2 = le4(n);
        expect(u.squeezeIndices(8, 20), isNot(equals(idx1)));
      }
    }
    // a nonce that misses leaves the state as it was
    final miss = TranscriptRef()..state = List<int>.of(pre);
    expect(miss.checkGrinding([1, 2, 3, 4], 2), isFalse);
    expect(miss.state, pre);
  });

  test('Poseidon2 transcript: two nonces that both grind give two sets of query indices', () {
    final t = Poseidon2Transcript()..absorbLimbs([1, 2, 3]);
    final pre = List<int>.of(t.state);
    final n1 = t.grind(2);
    final idx1 = t.squeezeIndices(8, 20);
    List<int>? n2;
    for (int n = n1[0] + 1; n2 == null; n++) {
      final u = Poseidon2Transcript()..state = List<int>.of(pre);
      if (u.checkGrinding([n], 2)) {
        n2 = [n];
        expect(u.squeezeIndices(8, 20), isNot(equals(idx1)));
      }
    }
    final miss = Poseidon2Transcript()..state = List<int>.of(pre);
    expect(miss.checkGrinding([n1[0] + 1], 2), isFalse);
    expect(miss.state, pre);
  });

  test('SHA256 flavour: a proof with the next grinding nonce is refused at the first query index', () {
    final proof = StarkProver.prove(params, air, rows);
    final v = StarkVerifierRef(params, air);
    expect(v.verify(proof), isTrue);
    final (nonce, said) = nextValidNonce(v, proof, le4, fromLe4(proof.nonce));
    expect(nonce, isNot(equals(proof.nonce)));
    expect(said, 'query 0 index', reason: 'before D1 was fixed this proof was accepted');
  });

  test('Poseidon2 flavour: a proof with the next grinding nonce is refused at the first query index', () {
    const p2 = Poseidon2ProofHash();
    final proof = StarkProver.prove(params, air, rows, hash: p2);
    final v = StarkVerifierRef(params, air, hash: p2);
    expect(v.verify(proof), isTrue);
    final (nonce, said) = nextValidNonce(v, proof, (n) => [n], proof.nonce[0]);
    expect(nonce, isNot(equals(proof.nonce)));
    expect(said, 'query 0 index', reason: 'before D1 was fixed this proof was accepted');
  });
}
