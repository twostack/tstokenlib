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

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'circle_fft.dart';
import 'm31.dart';

/// Poseidon2 permutation over M31, width 16, S-box x^5.
///
/// Parameters follow Plonky3's Mersenne-31 instance: 8 external (full)
/// rounds split 4 + 4 around 14 internal (partial) rounds; external matrix
/// circ(2·M4, M4, M4, M4) with the Poseidon2-paper M4; internal matrix
/// J + diag(-2, 2^0, 2^1, ..., 2^16) (shifts 0..8, 10, 12..16); an initial
/// external linear layer before the first round.
///
/// Round constants are this protocol's own, derived from SHA256 of a fixed
/// seed by rejection sampling of 31-bit chunks. Plonky3 has no canonical
/// Mersenne-31 constants (its tests draw them from an RNG), so no
/// interoperability is lost; what matters cryptographically is that they are
/// fixed, dense and not chosen by anyone with a stake in the output.
class Poseidon2M31 {
  static const width = 16;
  static const halfFullRounds = 4;
  static const fullRounds = 2 * halfFullRounds;
  static const partialRounds = 14;
  static const seed = 'TSL1-Poseidon2-M31-w16-RF8-RP14-v1';

  static const m4 = [
    [5, 7, 1, 3],
    [4, 6, 1, 1],
    [1, 3, 5, 7],
    [1, 1, 4, 6],
  ];

  /// Internal-matrix diagonal: M_I = J + diag(internalDiag).
  static final List<int> internalDiag = [
    M31.p - 2,
    for (final s in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16]) 1 << s,
  ];

  /// externalRc[r][k], r < 8, k < 16.
  static final List<List<int>> externalRc = _deriveExternal();

  /// internalRc[r], r < 14 (added to lane 0 only).
  static final List<int> internalRc = _deriveInternal();

  static List<int> _constants(int count) {
    final out = <int>[];
    final seedBytes = utf8.encode(seed);
    for (int ctr = 0; out.length < count; ctr++) {
      final bd = ByteData(4)..setUint32(0, ctr, Endian.little);
      final h = crypto.sha256.convert([...seedBytes, ...bd.buffer.asUint8List()]).bytes;
      final hb = ByteData.sublistView(Uint8List.fromList(h));
      for (int k = 0; k < 8 && out.length < count; k++) {
        final v = hb.getUint32(4 * k, Endian.little) & 0x7fffffff;
        if (v < M31.p) out.add(v);
      }
    }
    return out;
  }

  static List<List<int>> _deriveExternal() {
    final all = _constants(fullRounds * width + partialRounds);
    return [for (int r = 0; r < fullRounds; r++) all.sublist(r * width, (r + 1) * width)];
  }

  static List<int> _deriveInternal() {
    final all = _constants(fullRounds * width + partialRounds);
    return all.sublist(fullRounds * width);
  }

  static int pow5(int x) {
    final x2 = CircleFft.mul(x, x);
    return CircleFft.mul(CircleFft.mul(x2, x2), x);
  }

  /// External linear layer circ(2·M4, M4, M4, M4) on 16 M31 values.
  static List<int> externalLayer(List<int> s) {
    final y = List<int>.filled(16, 0);
    for (int b = 0; b < 4; b++) {
      for (int r = 0; r < 4; r++) {
        var acc = 0;
        for (int c = 0; c < 4; c++) {
          acc = CircleFft.add(acc, CircleFft.mul(s[4 * b + c], m4[r][c]));
        }
        y[4 * b + r] = acc;
      }
    }
    for (int r = 0; r < 4; r++) {
      final sum = CircleFft.add(CircleFft.add(y[r], y[4 + r]), CircleFft.add(y[8 + r], y[12 + r]));
      for (int b = 0; b < 4; b++) {
        y[4 * b + r] = CircleFft.add(y[4 * b + r], sum);
      }
    }
    return y;
  }

  /// Internal linear layer (J + diag) on 16 M31 values.
  static List<int> internalLayer(List<int> s) {
    var sum = 0;
    for (final v in s) {
      sum = CircleFft.add(sum, v);
    }
    return [for (int j = 0; j < 16; j++) CircleFft.add(sum, CircleFft.mul(internalDiag[j], s[j]))];
  }

  static List<int> externalRound(List<int> s, int r) =>
      externalLayer([for (int k = 0; k < 16; k++) pow5(CircleFft.add(s[k], externalRc[r][k]))]);

  static List<int> internalRound(List<int> s, int r) =>
      internalLayer([pow5(CircleFft.add(s[0], internalRc[r])), ...s.sublist(1)]);

  /// The full permutation.
  static List<int> permute(List<int> input) {
    if (input.length != width) throw ArgumentError('state must have $width lanes');
    var s = externalLayer(input);
    for (int r = 0; r < halfFullRounds; r++) {
      s = externalRound(s, r);
    }
    for (int r = 0; r < partialRounds; r++) {
      s = internalRound(s, r);
    }
    for (int r = halfFullRounds; r < fullRounds; r++) {
      s = externalRound(s, r);
    }
    return s;
  }
}
