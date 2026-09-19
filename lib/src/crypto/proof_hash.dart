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

import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'm31.dart';
import 'poseidon2_m31.dart';
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;

/// The hash a proof is built with: Merkle leaves and nodes, and the
/// Fiat-Shamir transcript. Two flavours exist.
///
/// * [Sha256ProofHash]: what the on-chain verifier checks (`OP_SHA256` is
///   native in script). Digests are 32 bytes.
/// * [Poseidon2ProofHash]: what a verifier *inside a circuit* can afford
///   (one permutation is 32 rows of the Poseidon2 chain AIR). Digests are 8
///   M31 lanes. Inner proofs of a recursion use this flavour; only the
///   outermost proof, the one a script verifies, uses SHA256.
///
/// A digest is a `List<int>`: bytes for SHA256, lanes for Poseidon2. The
/// proof layout does not otherwise depend on the flavour.
abstract class ProofHash {
  String get name;

  /// Digest length in `List<int>` entries (32 bytes or 8 lanes).
  int get digestLen;

  /// Bytes a digest occupies when serialised (32, or 8 lanes x 4 bytes).
  int get digestBytes;

  /// Merkle leaf over M31 lanes.
  List<int> leaf(List<int> lanes);

  /// Merkle node over two digests.
  List<int> node(List<int> left, List<int> right);

  /// A fresh transcript.
  Transcript transcript();

  /// Bytes a nonce occupies when serialised.
  int get nonceBytes;
}

/// The Fiat-Shamir transcript of a proof.
abstract class Transcript {
  void absorb(List<int> digest);
  void absorbLimbs(List<int> limbs);

  /// The statement: the public inputs, then the preprocessed root when the
  /// AIR has one. SHA256 absorbs them as they are; Poseidon2 pads the
  /// publics to [Poseidon2Transcript.statementLanes] lanes and always
  /// absorbs a root chunk (zeros without one), so the state afterwards is a
  /// fixed-shape *statement digest* a verifier circuit can pin.
  void absorbStatement(List<int> publics, List<int> preRoot) {
    if (publics.isNotEmpty) absorbLimbs(publics);
    if (preRoot.isNotEmpty) absorb(preRoot);
  }
  QM31 squeezeQM31();
  List<int> squeezeIndices(int n, int bits);
  bool checkGrinding(List<int> nonce, int grindBytes);
  List<int> grind(int grindBytes);
}

// ---------------------------------------------------------------- SHA256

class Sha256ProofHash implements ProofHash {
  const Sha256ProofHash();

  @override
  String get name => 'sha256';
  @override
  int get digestLen => 32;
  @override
  int get digestBytes => 32;
  @override
  int get nonceBytes => 4;

  static Uint8List serLanes(List<int> lanes) {
    final bd = ByteData(4 * lanes.length);
    for (int i = 0; i < lanes.length; i++) {
      bd.setUint32(4 * i, lanes[i], Endian.little);
    }
    return bd.buffer.asUint8List();
  }

  @override
  List<int> leaf(List<int> lanes) => Uint8List.fromList(crypto.sha256.convert(serLanes(lanes)).bytes);

  @override
  List<int> node(List<int> left, List<int> right) => Uint8List.fromList(crypto.sha256.convert([...left, ...right]).bytes);

  @override
  Transcript transcript() => _ShaTranscript();
}

class _ShaTranscript extends Transcript {
  final TranscriptRef _ts = TranscriptRef();
  @override
  void absorb(List<int> digest) => _ts.absorb(digest);
  @override
  void absorbLimbs(List<int> limbs) => _ts.absorbLimbs(limbs);
  @override
  QM31 squeezeQM31() => _ts.squeezeQM31();
  @override
  List<int> squeezeIndices(int n, int bits) => _ts.squeezeIndices(n, bits);
  @override
  bool checkGrinding(List<int> nonce, int grindBytes) => _ts.checkGrinding(nonce, grindBytes);
  @override
  List<int> grind(int grindBytes) => _ts.grind(grindBytes);
}

// ---------------------------------------------------------------- Poseidon2

/// Poseidon2 over M31 (width 16), everything in the *chain form* a
/// Poseidon2 chain AIR replays one permutation per period: a running 8-lane
/// value h and an 8-lane block w, h' = P(h ‖ w)[0..8].
///
/// * leaf: h = 0^8; for each 8-lane chunk (zero-padded): h = P(h ‖ chunk)[0..8]
/// * node: P(left ‖ right)[0..8]
/// * transcript: state s = 0^8; absorb: s = P(s ‖ chunk)[0..8] per
///   zero-padded 8-lane chunk; squeeze: s = P(s ‖ 0^8)[0..8], read lanes
///   0..3 (a QM31) or lane 0 (one query index per squeeze, masked to the
///   requested bits); grinding: P(s ‖ [nonce, 0..])[0] must have its low
///   7·grindBytes bits zero (the state is not advanced).
class Poseidon2ProofHash implements ProofHash {
  const Poseidon2ProofHash();

  static const rate = 8;

  @override
  String get name => 'poseidon2';
  @override
  int get digestLen => 8;
  @override
  int get digestBytes => 32;
  @override
  int get nonceBytes => 4;

  static List<int> compress(List<int> left8, List<int> right8) => Poseidon2M31.permute([...left8, ...right8]).sublist(0, 8);

  @override
  List<int> leaf(List<int> lanes) {
    var h = List<int>.filled(8, 0);
    final chunks = lanes.isEmpty ? 1 : (lanes.length + rate - 1) ~/ rate;
    for (int c = 0; c < chunks; c++) {
      final chunk = [for (int i = 0; i < rate; i++) c * rate + i < lanes.length ? lanes[c * rate + i] : 0];
      h = compress(h, chunk);
    }
    return h;
  }

  @override
  List<int> node(List<int> left, List<int> right) => compress(left, right);

  @override
  Transcript transcript() => Poseidon2Transcript();

  /// The round constants as one flat array (external 8x16, then internal 14),
  /// for the native kernels.
  static Uint32List get roundConstants => Uint32List.fromList([
        for (final r in Poseidon2M31.externalRc) ...r,
        ...Poseidon2M31.internalRc,
      ]);
}

class Poseidon2Transcript extends Transcript {
  List<int> state = List.filled(8, 0);

  static const zeros = [0, 0, 0, 0, 0, 0, 0, 0];

  /// Public inputs are padded to this many lanes (8 chunks) before the
  /// preprocessed-root chunk; the state after those 9 permutations is the
  /// statement digest.
  static const statementLanes = 64;
  static const statementPeriods = statementLanes ~/ 8 + 1;

  @override
  void absorbStatement(List<int> publics, List<int> preRoot) {
    if (publics.length > statementLanes) throw ArgumentError('at most $statementLanes public lanes');
    absorbLimbs([...publics, ...List.filled(statementLanes - publics.length, 0)]);
    absorb(preRoot.isEmpty ? zeros : preRoot);
  }

  /// Grinding bits for [grindBytes]: one bit-lane row per byte.
  static int grindBits(int grindBytes) => 7 * grindBytes;

  @override
  void absorbLimbs(List<int> limbs) {
    final chunks = limbs.isEmpty ? 1 : (limbs.length + 7) ~/ 8;
    for (int c = 0; c < chunks; c++) {
      final chunk = <int>[];
      for (int i = 0; i < 8; i++) {
        final k = c * 8 + i;
        if (k < limbs.length && (limbs[k] < 0 || limbs[k] >= M31.p)) throw ArgumentError('lane out of range');
        chunk.add(k < limbs.length ? limbs[k] : 0);
      }
      state = Poseidon2ProofHash.compress(state, chunk);
    }
  }

  @override
  void absorb(List<int> digest) {
    if (digest.length != 8) throw ArgumentError('a Poseidon2 digest has 8 lanes');
    state = Poseidon2ProofHash.compress(state, digest);
  }

  @override
  QM31 squeezeQM31() {
    state = Poseidon2ProofHash.compress(state, zeros);
    return QM31.fromLimbs(state[0], state[1], state[2], state[3]);
  }

  @override
  List<int> squeezeIndices(int n, int bits) {
    final mask = (1 << bits) - 1;
    final out = <int>[];
    while (out.length < n) {
      state = Poseidon2ProofHash.compress(state, zeros);
      out.add(state[0] & mask);
    }
    return out;
  }

  @override
  bool checkGrinding(List<int> nonce, int grindBytes) {
    if (nonce.length != 1) throw ArgumentError('a Poseidon2 nonce is one lane');
    if (nonce[0] < 0 || nonce[0] >= M31.p) throw ArgumentError('nonce out of range');
    final h = Poseidon2ProofHash.compress(state, [nonce[0], 0, 0, 0, 0, 0, 0, 0])[0];
    return h & ((1 << grindBits(grindBytes)) - 1) == 0;
  }

  @override
  List<int> grind(int grindBytes) {
    for (int n = 0;; n++) {
      if (checkGrinding([n], grindBytes)) return [n];
    }
  }
}
