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

import 'poseidon2_m31.dart';
import 'stark_kernels.dart';

/// Many two-to-one Poseidon2 compressions at once: the node hash of the
/// pool's trees (`PoolHash.node`), a level at a time.
///
/// Rebuilding a tree from its leaves hashes each node once, but there are
/// millions of them in a long-lived pool (a nullifier tree of 512,000 keys
/// has about 23 million nodes) and one costs 8 µs in Dart. The native
/// crate's vectorised permutation does the same arithmetic, on one thread,
/// with byte-identical results; without the crate the Dart permutation
/// runs instead.
class Poseidon2Batch {
  /// Set false to force the Dart path (tests compare the two).
  static bool preferNative = true;

  /// Node i of [pairs] (16 lanes each): the first 8 lanes of pair i
  /// permuted.
  static Uint32List compress(Uint32List pairs) {
    if (pairs.length % 16 != 0) throw ArgumentError('16 lanes a pair');
    if (pairs.isEmpty) return Uint32List(0);
    final k = preferNative ? StarkKernels.tryLoad() : null;
    return k != null ? k.compressPairs(pairs) : compressInDart(pairs);
  }

  static Uint32List compressInDart(Uint32List pairs) {
    final n = pairs.length ~/ 16;
    final out = Uint32List(8 * n);
    for (int i = 0; i < n; i++) {
      final s = Poseidon2M31.permute(Uint32List.sublistView(pairs, 16 * i, 16 * i + 16));
      out.setRange(8 * i, 8 * i + 8, s);
    }
    return out;
  }
}
