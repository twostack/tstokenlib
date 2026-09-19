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

import 'package:dartsv/dartsv.dart';
import '../crypto/poseidon2_m31.dart';
import 'm31_script_gen.dart';

/// The [Poseidon2M31] permutation in script, on 16 named M31 entries.
///
/// Arithmetic is lazy: lanes are reduced once per round, right after the
/// S-box, and the linear layers run on unreduced values (external layer
/// outputs stay below 2^37; the fourteen internal rounds are left unreduced
/// except for lane 0 and grow to a few hundred bits, which BSV bignums take
/// in stride). The modulus is read from a pinned entry named [pName] so a
/// reduction costs 3 bytes instead of 6.
///
/// Cost per permutation is measured by `poseidon2_script_gen_test`.
class Poseidon2ScriptGen {
  static const width = Poseidon2M31.width;

  /// Push the modulus once under the name [pName]; every emitter below picks it.
  static void emitPushP(StackEmitter e, {String pName = 'P'}) {
    e.pushP();
    e.nameTop(pName);
  }

  static void _reduce(StackEmitter e, String pName) {
    e.pick(pName);
    e.raw(OpCodes.OP_MOD, pops: 2, pushes: 1);
  }

  /// x -> (x + rc)^5 mod p, on the top entry (consumed), result named [as].
  static void _sbox(StackEmitter e, int rc, String pName, String as) {
    if (rc != 0) {
      e.pushConst(rc);
      e.add();
    }
    e.dup();
    e.dup();
    e.mul(); // x, x^2
    e.dup();
    e.mul(); // x, x^4
    e.mul(); // x^5
    _reduce(e, pName);
    e.nameTop(as);
  }

  /// One 4-lane M4 block, in place: [a b c d] -> M4 · (a b c d), eight
  /// additions and four doublings (the Poseidon2 paper's schedule). Consumes
  /// the four inputs and leaves the outputs under the same names.
  static void _m4(StackEmitter e, List<String> x) {
    final a = x[0], b = x[1], c = x[2], d = x[3];
    e.roll(a);
    e.pick(b);
    e.add();
    e.nameTop('_t0'); // a + b
    e.roll(c);
    e.pick(d);
    e.add();
    e.nameTop('_t1'); // c + d
    e.roll(b);
    e.dup();
    e.add();
    e.pick('_t1');
    e.add();
    e.nameTop('_t2'); // 2b + t1
    e.roll(d);
    e.dup();
    e.add();
    e.pick('_t0');
    e.add();
    e.nameTop('_t3'); // 2d + t0
    e.roll('_t1');
    e.dup();
    e.add();
    e.dup();
    e.add();
    e.pick('_t3');
    e.add();
    e.nameTop(d); // t4 = 4 t1 + t3 = row 3
    e.roll('_t0');
    e.dup();
    e.add();
    e.dup();
    e.add();
    e.pick('_t2');
    e.add();
    e.nameTop(b); // t5 = 4 t0 + t2 = row 1
    e.roll('_t3');
    e.pick(b);
    e.add();
    e.nameTop(a); // t6 = t3 + t5 = row 0
    e.roll('_t2');
    e.pick(d);
    e.add();
    e.nameTop(c); // t7 = t2 + t4 = row 2
  }

  /// External linear layer circ(2·M4, M4, M4, M4) on the 16 named lanes.
  static void emitExternalLayer(StackEmitter e, List<String> s) {
    for (int blk = 0; blk < 4; blk++) {
      _m4(e, s.sublist(4 * blk, 4 * blk + 4));
    }
    for (int r = 0; r < 4; r++) {
      e.pick(s[r]);
      e.pick(s[4 + r]);
      e.add();
      e.pick(s[8 + r]);
      e.add();
      e.pick(s[12 + r]);
      e.add();
      e.nameTop('_sum');
      for (int blk = 0; blk < 4; blk++) {
        e.roll(s[4 * blk + r]);
        if (blk < 3) {
          e.pick('_sum');
        } else {
          e.roll('_sum');
        }
        e.add();
        e.nameTop(s[4 * blk + r]);
      }
    }
  }

  /// Internal linear layer J + diag on the 16 named lanes (unreduced).
  static void emitInternalLayer(StackEmitter e, List<String> s) {
    e.pick(s[0]);
    for (int j = 1; j < width; j++) {
      e.pick(s[j]);
      e.add();
    }
    e.nameTop('_sum');
    for (int j = 0; j < width; j++) {
      e.roll(s[j]);
      e.mulConst(Poseidon2M31.internalDiag[j]);
      if (j < width - 1) {
        e.pick('_sum');
      } else {
        e.roll('_sum');
      }
      e.add();
      e.nameTop(s[j]);
    }
  }

  /// The full permutation on the 16 named entries [s] (any stack positions;
  /// consumed), leaving 16 canonical outputs under the same names on top.
  static void emitPermute(StackEmitter e, List<String> s, {String pName = 'P'}) {
    if (s.length != width) throw ArgumentError('need $width lane names');
    emitExternalLayer(e, s);
    for (int r = 0; r < Poseidon2M31.halfFullRounds; r++) {
      _externalRound(e, s, r, pName);
    }
    for (int r = 0; r < Poseidon2M31.partialRounds; r++) {
      e.roll(s[0]);
      _sbox(e, Poseidon2M31.internalRc[r], pName, s[0]);
      emitInternalLayer(e, s);
    }
    // the internal rounds left lanes 1..15 unreduced; the next S-box reduces
    // each lane, so nothing to do here
    for (int r = Poseidon2M31.halfFullRounds; r < Poseidon2M31.fullRounds; r++) {
      _externalRound(e, s, r, pName);
    }
    // the last external layer leaves unreduced sums: reduce every lane
    for (int j = 0; j < width; j++) {
      e.roll(s[j]);
      _reduce(e, pName);
      e.nameTop(s[j]);
    }
  }

  static void _externalRound(StackEmitter e, List<String> s, int r, String pName) {
    for (int k = 0; k < width; k++) {
      e.roll(s[k]);
      _sbox(e, Poseidon2M31.externalRc[r][k], pName, s[k]);
    }
    emitExternalLayer(e, s);
  }

  /// Merkle node: H(left || right) = first 8 lanes of the permutation of the
  /// 16 lanes [left] ++ [right]. Consumes both; leaves 8 canonical lanes
  /// named [out].
  static void emitNode(StackEmitter e, List<String> left, List<String> right, List<String> out, {String pName = 'P'}) {
    final s = [...left, ...right];
    emitPermute(e, s, pName: pName);
    for (int j = 8; j < width; j++) {
      e.dropNamed(s[j]);
    }
    for (int j = 0; j < 8; j++) {
      e.rename(s[j], out[j]);
    }
  }
}
