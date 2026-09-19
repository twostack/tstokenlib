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
import 'package:dartsv/dartsv.dart';
import '../crypto/m31.dart';
import '../crypto/rabin.dart';
import 'm31_script_gen.dart';

/// Prototype emitters for the pieces of a Circle-STARK FRI verifier:
/// leaf hashing, SHA256 Merkle path verification, domain-point computation
/// from a query index, the twiddle recurrence between layers, and the
/// `fold_line` step itself.
///
/// Domain layout follows [HalfCoset] natural order: at a layer with n points,
/// leaf i (for i < n/2) holds the pair (f(x_i), f(x_{i+n/2})) and
/// x_{i+n/2} = -x_i. The fold
///
///   out_i = (f(x_i) + f(-x_i)) + alpha * (f(x_i) - f(-x_i)) * x_i^{-1}
///
/// lands at index i of the next layer (n/2 points), i.e. in leaf
/// (i mod n/4) as the first component if i < n/4, else the second.
class FriFoldScriptGen {
  /// leaf = SHA256(ser(f0) || ser(f1)), ser(limb) = 4-byte little-endian.
  /// Picks (does not consume) the eight limbs.
  static void emitLeafHash(
      StackEmitter e, List<String> f0, List<String> f1, {String as = 'leaf'}) =>
      emitLeafHashN(e, [...f0, ...f1], as: as);

  /// leaf = SHA256(ser(limbs...)). Picks the limbs.
  static void emitLeafHashN(StackEmitter e, List<String> limbs, {String as = 'leaf'}) {
    for (int k = 0; k < limbs.length; k++) {
      e.pick(limbs[k]);
      e.pushConst(4);
      e.raw(OpCodes.OP_NUM2BIN, pops: 2, pushes: 1);
      if (k > 0) e.raw(OpCodes.OP_CAT, pops: 2, pushes: 1);
    }
    e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: as);
  }

  /// From the canonical index [idx] at a layer whose leaf count is 2^d:
  ///   * copy the full index to [copyAs] (for the Merkle path bits),
  ///   * compute [topBitAs] = idx div 2^(d-1)  (component selector / twiddle sign),
  ///   * replace [idx] with idx mod 2^(d-1)     (next layer's leaf index).
  static void emitIndexSplit(StackEmitter e, String idx, int d,
      {String copyAs = 'ic', String topBitAs = 'topbit'}) {
    e.pick(idx, as: copyAs);
    e.pick(idx);
    e.pushConst(1 << (d - 1));
    e.raw(OpCodes.OP_DIV, pops: 2, pushes: 1, as: topBitAs);
    e.roll(idx);
    e.pushConst(1 << (d - 1));
    e.raw(OpCodes.OP_MOD, pops: 2, pushes: 1, as: idx);
  }

  /// Walks a Merkle path of depth `sibs.length` from [node] using direction
  /// bits taken LSB-first from [idxCopy] (bit = 1 means node is the right
  /// child). Consumes the siblings and the index copy; leaves root on top.
  static void emitMerklePath(
      StackEmitter e, String node, List<String> sibs, String idxCopy,
      {String as = 'root'}) {
    e.roll(idxCopy);
    e.toAlt();
    e.roll(node);
    for (int k = 0; k < sibs.length; k++) {
      e.roll(sibs[k]); // [.., node, sib]
      e.fromAlt(); // [.., node, sib, ic]
      e.dup();
      e.pushConst(2);
      e.raw(OpCodes.OP_MOD, pops: 2, pushes: 1); // [.., node, sib, ic, bit]
      e.swap();
      e.pushConst(2);
      e.raw(OpCodes.OP_DIV, pops: 2, pushes: 1, as: idxCopy);
      e.toAlt(); // [.., node, sib, bit]
      e.ifBegin();
      e.swap();
      e.ifEnd();
      e.raw(OpCodes.OP_CAT, pops: 2, pushes: 1);
      e.raw(OpCodes.OP_SHA256, pops: 1, pushes: 1, as: node);
    }
    e.fromAlt();
    e.drop(); // exhausted index copy
    e.nameTop(as);
  }

  /// x <- ±(2x^2 - 1), negated when [topBit] is 1. Picks [topBit].
  static void emitTwiddleStep(StackEmitter e, String x, String topBit) {
    e.roll(x);
    e.dup();
    e.mul();
    e.dup();
    e.add();
    e.pushConst(1);
    e.sub();
    e.reduce();
    e.pick(topBit);
    e.ifBegin();
    e.negCanonical();
    e.ifEnd();
    e.nameTop(x);
    e.setNonNeg(x, true);
  }

  /// Computes `coset.at(idx)` for idx < 2^bits by fixed-base multiplication:
  /// acc = initial; for each set bit k, acc *= step^(2^k).
  /// Picks [idx]; leaves x named [asX] below y named [asY] on top.
  static void emitDomainPointXY(
      StackEmitter e, HalfCoset coset, String idx, int bits,
      {String asX = 'x', String asY = 'y'}) {
    e.pick(idx, as: '_ib');
    e.toAlt();
    e.pushConst(coset.initial.x, as: '_px');
    e.pushConst(coset.initial.y, as: '_py');
    for (int k = 0; k < bits; k++) {
      final g = CirclePoint.subgroupGen(coset.logSize - k); // step^(2^k)
      e.fromAlt();
      e.dup();
      e.pushConst(2);
      e.raw(OpCodes.OP_MOD, pops: 2, pushes: 1);
      e.swap();
      e.pushConst(2);
      e.raw(OpCodes.OP_DIV, pops: 2, pushes: 1, as: '_ib');
      e.toAlt(); // [.., px, py, bit]
      e.ifBegin();
      // (px, py) * (gx, gy) = (px gx - py gy, px gy + py gx)
      e.raw(OpCodes.OP_2DUP, pops: 0, pushes: 2); // [px, py, px, py]
      e.mulConst(g.y); // [px, py, px, py*gy]
      e.swap();
      e.mulConst(g.x); // [px, py, py*gy, px*gx]
      e.swap();
      e.sub(); // [px, py, px*gx - py*gy]
      e.reduce(); // px'
      e.rot(); // [py, px', px]
      e.mulConst(g.y); // [py, px', px*gy]
      e.rot(); // [px', px*gy, py]
      e.mulConst(g.x); // [px', px*gy, py*gx]
      e.add();
      e.reduce(); // [px', py']
      e.ifEnd();
      e.nameAt(0, '_py');
      e.nameAt(1, '_px');
    }
    e.fromAlt();
    e.drop(); // exhausted index bits
    e.nameAt(0, asY);
    e.nameAt(1, asX);
    e.setNonNeg(asX, true);
    e.setNonNeg(asY, true);
  }

  /// x-coordinate only (see [emitDomainPointXY]).
  static void emitDomainPointX(
      StackEmitter e, HalfCoset coset, String idx, int bits, {String as = 'x'}) {
    emitDomainPointXY(e, coset, idx, bits, asX: as, asY: '_ydrop');
    e.dropNamed('_ydrop');
  }

  /// x <- -x when [topBit] is 1 (circle-to-line transition: the line-domain
  /// twiddle at leaf (i mod n/2) is ±x_i). Picks [topBit].
  static void emitSignStep(StackEmitter e, String x, String topBit) {
    e.roll(x);
    e.pick(topBit);
    e.ifBegin();
    e.negCanonical();
    e.ifEnd();
    e.nameTop(x);
    e.setNonNeg(x, true);
  }

  /// out = (f0 + f1) + alpha * ((f0 - f1) * xinv)
  /// Consumes f0, f1, alpha limbs and xinv. Outputs canonical.
  static void emitFoldLine(StackEmitter e, List<String> f0, List<String> f1,
      String xinv, List<String> alpha, List<String> out) {
    for (int k = 0; k < 4; k++) {
      e.pick(f0[k]);
      e.pick(f1[k]);
      e.add();
      e.nameTop('_g0$k');
    }
    for (int k = 0; k < 4; k++) {
      e.roll(f0[k]);
      e.roll(f1[k]);
      e.sub();
      if (k == 3) {
        e.roll(xinv);
      } else {
        e.pick(xinv);
      }
      e.mul();
      e.nameTop('_g1$k');
    }
    M31Ops.qm31Mul(e, alpha, ['_g10', '_g11', '_g12', '_g13'],
        ['_m0', '_m1', '_m2', '_m3'], reduceOut: false);
    for (int k = 0; k < 4; k++) {
      e.roll('_m$k');
      e.roll('_g0$k');
      e.add();
      e.reduce();
      e.nameTop(out[k]);
    }
  }

  /// Verify the fold output [out] equals the [topBit]-selected component of
  /// the next layer's opened pair (f0n if 0, f1n if 1). Consumes [out] and
  /// [topBit]; picks the pair limbs.
  static void emitSelectCompare(StackEmitter e, List<String> out,
      List<String> f0n, List<String> f1n, String topBit) {
    for (int k = 0; k < 4; k++) {
      e.pick(f0n[k]);
      e.pick(f1n[k]);
      if (k == 3) {
        e.roll(topBit);
      } else {
        e.pick(topBit);
      }
      e.ifBegin();
      e.swap();
      e.ifEnd();
      e.drop();
      e.roll(out[k]);
      e.numEqualVerify();
    }
  }
}

/// Generates a locking script that verifies a single FRI query across
/// [numLayers] fold layers, and the matching unlocking script layout.
///
/// Layer l has 2^(logSize - l) points and depth d_l = logSize - 1 - l.
///
/// Unlocking script pushes, bottom to top:
///   for each layer l: f0 limbs (4), f1 limbs (4), siblings (d_l), xinv
///   then the query index.
class FriQueryVerifierGen {
  static List<String> _f(int l) => List.generate(4, (k) => 'f${l}_$k');
  static List<String> _g(int l) => List.generate(4, (k) => 'g${l}_$k');
  static List<String> _s(int l, int d) => List.generate(d, (k) => 's${l}_$k');
  static String _xi(int l) => 'xi$l';

  static int depthAt(int logSize, int l) => logSize - 1 - l;

  static List<String> _cf() => List.generate(4, (k) => 'cf_$k');
  static List<String> _cg() => List.generate(4, (k) => 'cg_$k');
  static List<String> _cs(int d) => List.generate(d, (k) => 'cs_$k');

  /// With [circleFirst], the unlocking script starts with the circle layer:
  /// f(p) limbs (4), f(conj p) limbs (4), siblings (logSize), y inverse.
  static List<String> unlockLayout(int logSize, int numLayers, {bool circleFirst = false}) {
    final names = <String>[];
    if (circleFirst) {
      names.addAll(_cf());
      names.addAll(_cg());
      names.addAll(_cs(logSize));
      names.add('cyi');
    }
    for (int l = 0; l < numLayers; l++) {
      names.addAll(_f(l));
      names.addAll(_g(l));
      names.addAll(_s(l, depthAt(logSize, l)));
      names.add(_xi(l));
    }
    names.add('idx');
    return names;
  }

  /// [circleFirst]: verify a circle-to-line fold layer (root [circleRoot],
  /// challenge [circleAlpha]) before the [numLayers] line layers. The circle
  /// layer's leaves are pairs (f(p_i), f(conj p_i)) for the 2^logSize points
  /// of the half coset, so its Merkle depth is logSize.
  static SVScript generate({
    required int logSize,
    required int numLayers,
    required List<List<int>> roots,
    required List<QM31> alphas,
    required QM31 expectedFinal,
    bool circleFirst = false,
    List<int>? circleRoot,
    QM31? circleAlpha,
  }) {
    if (numLayers > logSize - 1) throw ArgumentError('too many layers');
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: unlockLayout(logSize, numLayers, circleFirst: circleFirst));
    final coset = HalfCoset(logSize);
    final out = ['o0', 'o1', 'o2', 'o3'];

    if (circleFirst) {
      // Domain point (x, y) for idx < 2^logSize.
      FriFoldScriptGen.emitDomainPointXY(e, coset, 'idx', logSize, asX: 'x', asY: 'y');
      FriFoldScriptGen.emitLeafHash(e, _cf(), _cg(), as: 'leaf');
      FriFoldScriptGen.emitIndexSplit(e, 'idx', logSize);
      FriFoldScriptGen.emitMerklePath(e, 'leaf', _cs(logSize), 'ic', as: 'root');
      e.equalVerifyData(circleRoot!);
      M31Ops.verifyInverse(e, 'y', 'cyi', consumeInv: false);
      e.dropNamed('y');
      final al = List.generate(4, (k) => 'al$k');
      for (int k = 0; k < 4; k++) {
        e.pushConst(circleAlpha!.limbs[k], as: al[k]);
      }
      FriFoldScriptGen.emitFoldLine(e, _cf(), _cg(), 'cyi', al, out);
      FriFoldScriptGen.emitSignStep(e, 'x', 'topbit');
      FriFoldScriptGen.emitSelectCompare(e, out, _f(0), _g(0), 'topbit');
    }

    for (int l = 0; l < numLayers; l++) {
      final d = depthAt(logSize, l);
      final f0 = _f(l), f1 = _g(l);

      if (l == 0 && !circleFirst) {
        FriFoldScriptGen.emitDomainPointX(e, coset, 'idx', d, as: 'x');
      }

      FriFoldScriptGen.emitLeafHash(e, f0, f1, as: 'leaf');
      FriFoldScriptGen.emitIndexSplit(e, 'idx', d);
      FriFoldScriptGen.emitMerklePath(e, 'leaf', _s(l, d), 'ic', as: 'root');
      e.equalVerifyData(roots[l]);

      M31Ops.verifyInverse(e, 'x', _xi(l), consumeInv: false);

      final al = List.generate(4, (k) => 'al$k');
      for (int k = 0; k < 4; k++) {
        e.pushConst(alphas[l].limbs[k], as: al[k]);
      }
      FriFoldScriptGen.emitFoldLine(e, f0, f1, _xi(l), al, out);

      if (l < numLayers - 1) {
        FriFoldScriptGen.emitTwiddleStep(e, 'x', 'topbit');
        FriFoldScriptGen.emitSelectCompare(e, out, _f(l + 1), _g(l + 1), 'topbit');
      } else {
        for (int k = 0; k < 4; k++) {
          e.roll(out[k]);
          e.numEqualVerifyConst(expectedFinal.limbs[k]);
        }
        e.dropNamed('topbit');
      }
    }
    e.dropNamed('x');
    e.dropNamed('idx');
    if (e.size != 0 || e.altSize != 0) {
      throw StateError('leftover stack entries: ${e.debugNames()} alt=${e.altSize}');
    }
    e.pushConst(1);
    return b.build();
  }

  /// Push a canonical (non-negative) script number.
  static void pushNum(ScriptBuilder b, int v) {
    if (v >= 0 && v <= 16) {
      b.smallNum(v);
    } else {
      b.addData(Rabin.bigIntToScriptNum(BigInt.from(v)));
    }
  }

  static SVScript buildUnlock({
    required List<QM31> f0s,
    required List<QM31> f1s,
    required List<List<List<int>>> siblings,
    required List<int> xinvs,
    required int index,
    QM31? circleF0,
    QM31? circleF1,
    List<List<int>>? circleSiblings,
    int? circleYinv,
  }) {
    final b = ScriptBuilder();
    if (circleF0 != null) {
      for (final v in circleF0.limbs) {
        pushNum(b, v);
      }
      for (final v in circleF1!.limbs) {
        pushNum(b, v);
      }
      for (final s in circleSiblings!) {
        b.addData(Uint8List.fromList(s));
      }
      pushNum(b, circleYinv!);
    }
    for (int l = 0; l < f0s.length; l++) {
      for (final v in f0s[l].limbs) {
        pushNum(b, v);
      }
      for (final v in f1s[l].limbs) {
        pushNum(b, v);
      }
      for (final s in siblings[l]) {
        b.addData(Uint8List.fromList(s));
      }
      pushNum(b, xinvs[l]);
    }
    pushNum(b, index);
    return b.build();
  }
}
