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
import 'package:dartsv/dartsv.dart';
import '../crypto/m31.dart';
import 'm31_script_gen.dart';

/// SHA256 transcript for Fiat-Shamir, with a Dart reference and a script
/// emitter that must produce identical challenges.
///
/// State is a 32-byte digest. Absorbing replaces it with SHA256(state || data).
/// Squeezing replaces it with SHA256(state) and derives values from the new
/// state: each 4-byte little-endian chunk, masked to 31 bits and reduced
/// mod p, is an M31 limb (four chunks make a QM31); or, masked and reduced
/// mod 2^bits, a query index.
class TranscriptRef {
  List<int> state = List.filled(32, 0);

  static List<int> _sha(List<int> a) => crypto.sha256.convert(a).bytes;

  void absorb(List<int> data) => state = _sha([...state, ...data]);

  void absorbLimbs(List<int> limbs) {
    final bd = ByteData(4 * limbs.length);
    for (int i = 0; i < limbs.length; i++) {
      bd.setUint32(4 * i, limbs[i], Endian.little);
    }
    absorb(bd.buffer.asUint8List());
  }

  int _chunk(int k) =>
      ByteData.sublistView(Uint8List.fromList(state)).getUint32(4 * k, Endian.little) & 0x7fffffff;

  QM31 squeezeQM31() {
    state = _sha(state);
    return QM31.fromLimbs(_chunk(0) % M31.p, _chunk(1) % M31.p, _chunk(2) % M31.p, _chunk(3) % M31.p);
  }

  List<int> squeezeIndices(int n, int bits) {
    final out = <int>[];
    while (out.length < n) {
      state = _sha(state);
      for (int k = 0; k < 8 && out.length < n; k++) {
        out.add(_chunk(k) % (1 << bits));
      }
    }
    return out;
  }

  /// Grinding: SHA256(state || nonce) must start with [zeroBytes] zero bytes.
  bool checkGrinding(List<int> nonce, int zeroBytes) {
    final h = _sha([...state, ...nonce]);
    for (int i = 0; i < zeroBytes; i++) {
      if (h[i] != 0) return false;
    }
    return true;
  }

  /// Map a QM31 challenge t to a circle point via the rational
  /// parametrisation z = ((1 - t²) / (1 + t²), 2t / (1 + t²)).
  /// Returns (zx, zy, hint) where hint = (1 + t²)^-1 is supplied to the script.
  static (QM31, QM31, QM31) circlePoint(QM31 t) {
    final t2 = t * t;
    final d = QM31.one + t2;
    final h = d.inv;
    return ((QM31.one - t2) * h, (t + t) * h, h);
  }

  /// A parallel search for the same nonce, installed by the native kernels
  /// when they load. It returns the nonce, or a negative number when it
  /// found none. Null means there is no such search and [grind] counts here.
  static int Function(List<int> state, int zeroBytes)? nativeGrind;

  /// The smallest nonce satisfying [checkGrinding].
  ///
  /// Smallest, not any: the verifier takes any nonce that meets the target,
  /// but two provers must produce the same proof, so a search that returned
  /// whichever hit it found first would break that without failing a
  /// verification.
  List<int> grind(int zeroBytes) {
    final fast = nativeGrind;
    if (fast != null) {
      final n = fast(state, zeroBytes);
      if (n >= 0) return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
    }
    for (int n = 0;; n++) {
      final nonce = [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
      if (checkGrinding(nonce, zeroBytes)) return nonce;
    }
  }
}

class FiatShamirScriptGen {
  static const _mask = [0xff, 0xff, 0xff, 0x7f];

  static void emitInit(StackEmitter e) => e.pushData(List.filled(32, 0), as: 'ts');

  /// ts = SHA256(ts || item). Picks [item].
  static void emitAbsorb(StackEmitter e, String item) {
    e.roll('ts');
    e.pick(item);
    e.raw(OpCodes.OP_CAT, pops: 2, pushes: 1);
    e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'ts');
  }

  /// ts = SHA256(ts || ser(limbs...)). Picks the limbs.
  static void emitAbsorbLimbs(StackEmitter e, List<String> limbs) {
    e.roll('ts');
    for (final l in limbs) {
      e.pick(l);
      e.pushConst(4);
      e.raw(OpCodes.OP_NUM2BIN, pops: 2, pushes: 1);
      e.raw(OpCodes.OP_CAT, pops: 2, pushes: 1);
    }
    e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'ts');
  }

  /// Split the 4-byte chunk on top into an M31 limb: mask, BIN2NUM, mod p.
  static void _chunkToLimb(StackEmitter e, {String? as}) {
    e.pushData(_mask);
    e.raw(OpCodes.OP_AND, pops: 2, pushes: 1);
    e.raw(OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
    e.reduce();
    if (as != null) e.nameTop(as);
  }

  /// ts = SHA256(ts); derive four limbs from it as [out].
  static void emitSqueezeQM31(StackEmitter e, List<String> out) {
    e.roll('ts');
    e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'ts');
    e.dup(as: '_rest');
    for (int k = 0; k < 4; k++) {
      e.roll('_rest');
      e.pushConst(4);
      e.raw(OpCodes.OP_SPLIT, pops: 2, pushes: 2, as: '_rest');
      e.nameAt(1, '_chunk');
      e.roll('_chunk');
      _chunkToLimb(e, as: out[k]);
    }
    e.dropNamed('_rest'); // unused 16 bytes of the digest
  }

  /// Derive [n] query indices of [bits] bits, named [prefix]0..[prefix]n-1.
  static void emitSqueezeIndices(StackEmitter e, int n, int bits, String prefix) {
    int done = 0;
    while (done < n) {
      e.roll('ts');
      e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: 'ts');
      e.dup(as: '_rest');
      final take = (n - done) < 8 ? (n - done) : 8;
      for (int k = 0; k < take; k++) {
        e.roll('_rest');
        if (k < 7) {
          e.pushConst(4);
          e.raw(OpCodes.OP_SPLIT, pops: 2, pushes: 2, as: '_rest');
          e.nameAt(1, '_chunk');
          e.roll('_chunk');
        } else {
          e.pushConst(4);
          e.raw(OpCodes.OP_SPLIT, pops: 2, pushes: 2);
          e.drop();
        }
        e.pushData(_mask);
        e.raw(OpCodes.OP_AND, pops: 2, pushes: 1);
        e.raw(OpCodes.OP_BIN2NUM, pops: 1, pushes: 1);
        e.pushConst(1 << bits);
        e.raw(OpCodes.OP_MOD, pops: 2, pushes: 1, as: '$prefix${done + k}');
      }
      if (e.has('_rest')) e.dropNamed('_rest');
      done += take;
    }
  }

  /// z = ((1 - t²) h, 2t h) with h a prover hint verified as (1 + t²)^-1.
  /// Consumes [t] and [hint]; leaves canonical zx then zy limbs.
  static void emitCirclePoint(StackEmitter e, List<String> t, List<String> hint,
      List<String> zx, List<String> zy) {
    List<String> n(String b) => List.generate(4, (k) => '${b}_$k');
    for (int k = 0; k < 4; k++) {
      e.pick(t[k], as: '_ta_$k');
    }
    for (int k = 0; k < 4; k++) {
      e.pick(t[k], as: '_tb_$k');
    }
    M31Ops.qm31Mul(e, n('_ta'), n('_tb'), n('_t2'));
    // d = 1 + t²
    for (int k = 0; k < 4; k++) {
      e.pick('_t2_$k', as: '_d_$k');
    }
    e.roll('_d_0');
    e.pushConst(1);
    e.add();
    e.nameTop('_d_0');
    for (int k = 0; k < 4; k++) {
      e.pick(hint[k], as: '_h1_$k');
    }
    M31Ops.qm31Mul(e, n('_d'), n('_h1'), n('_one'));
    e.roll('_one_0');
    e.numEqualVerifyConst(1);
    for (int k = 1; k < 4; k++) {
      e.roll('_one_$k');
      e.numEqualVerifyConst(0);
    }
    // zx = (1 - t²) h
    for (int k = 0; k < 4; k++) {
      e.pushConst(k == 0 ? 1 : 0);
      e.roll('_t2_$k');
      e.sub();
      e.nameTop('_nx_$k');
    }
    for (int k = 0; k < 4; k++) {
      e.pick(hint[k], as: '_h2_$k');
    }
    M31Ops.qm31Mul(e, n('_nx'), n('_h2'), zx);
    // zy = 2t h
    for (int k = 0; k < 4; k++) {
      e.roll(t[k]);
      e.dup();
      e.add();
      e.nameTop('_ny_$k');
    }
    M31Ops.qm31Mul(e, n('_ny'), hint, zy);
  }

  /// Verify SHA256(ts || nonce) starts with [zeroBytes] zero bytes. Consumes [nonce].
  static void emitGrindingCheck(StackEmitter e, String nonce, int zeroBytes) {
    e.pick('ts');
    e.roll(nonce);
    e.raw(OpCodes.OP_CAT, pops: 2, pushes: 1);
    e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1);
    e.pushConst(zeroBytes);
    e.raw(OpCodes.OP_SPLIT, pops: 2, pushes: 2);
    e.drop();
    e.equalVerifyData(List.filled(zeroBytes, 0));
  }
}
