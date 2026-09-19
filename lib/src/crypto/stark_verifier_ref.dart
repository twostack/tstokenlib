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

import 'm31.dart';
import 'proof_hash.dart';
import 'stark_prover.dart' show PreCommitment;
import 'stark_prover_ref.dart' show StarkParams, StarkProof, composeColumns;
import '../script_gen/deep_quotient_script_gen.dart' show DeepQuotientRef, DeepConstants;
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;
import '../script_gen/air.dart' show Air;

/// A verification failure, naming the check.
class VerificationFailure implements Exception {
  final String what;
  VerificationFailure(this.what);
  @override
  String toString() => 'verification failed: $what';
}

/// Reference verifier in Dart, for any [ProofHash] flavour. It follows the
/// script verifier (`StarkVerifierGen.generate`) check for check and in the
/// same order, including the hint checks (inverses are verified by
/// multiplication, never recomputed), so it is the executable spec of what
/// the in-circuit verifier of a recursion must do. With the SHA256 flavour
/// it accepts exactly the proofs the script accepts.
class StarkVerifierRef {
  final StarkParams P;
  final Air air;
  final ProofHash hash;
  StarkVerifierRef(this.P, this.air, {this.hash = const Sha256ProofHash()});

  /// True when [proof] verifies; throws [VerificationFailure] otherwise.
  bool verify(StarkProof proof) {
    _verify(proof);
    return true;
  }

  /// Like [verify] but returns the failure instead of throwing.
  String? check(StarkProof proof) {
    try {
      _verify(proof);
      return null;
    } on VerificationFailure catch (e) {
      return e.what;
    }
  }

  static void _need(bool ok, String what) {
    if (!ok) throw VerificationFailure(what);
  }

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// A Merkle path walk with direction bits LSB-first from [index].
  List<int> _root(List<int> leaf, List<List<int>> path, int index) {
    var h = leaf;
    for (int lv = 0; lv < path.length; lv++) {
      final bit = (index >> lv) & 1;
      h = bit == 1 ? hash.node(path[lv], h) : hash.node(h, path[lv]);
    }
    return h;
  }

  static int _double(int x) => M31.sub(M31.mul(2, M31.mul(x, x)), 1);

  /// The out-of-domain point of [pf]: its transcript replayed to z, taking
  /// the proof's z hint as is (the verifier proper checks it). What the
  /// unlocking script's public-column hints are computed at.
  (QM31, QM31) oodPoint(StarkProof pf) {
    final ts = hash.transcript();
    ts.absorbStatement(air.publicValues, pf.preRoot);
    ts.absorb(pf.traceRoot);
    for (int k = 0; k < air.numChallenges; k++) {
      ts.squeezeQM31();
    }
    if (air.numAuxCols > 0) ts.absorb(pf.auxRoot);
    ts.squeezeQM31();
    ts.absorb(pf.compRoot);
    final tch = ts.squeezeQM31();
    final t2 = tch * tch;
    return ((QM31.one - t2) * pf.zHint, (tch + tch) * pf.zHint);
  }

  void _verify(StarkProof pf) {
    final a = P.logCompHalf;
    final CT = air.totalCols, C = air.numCols, A = air.numAuxCols, R = air.numPreCols;
    final gT = CirclePoint.subgroupGen(P.logTrace);
    _need(pf.traceRoot.length == hash.digestLen, 'trace root length');
    _need(pf.compRoot.length == hash.digestLen, 'composition root length');
    _need(pf.traceAtZ.length == CT && pf.traceAtZg.length == CT, 'out-of-domain value count');
    _need(pf.compAtZ.length == StarkParams.compCols, 'composition value count');
    _need(pf.friRoots.length == P.numLineFolds, 'FRI root count');
    _need(pf.finalCoefs.length == P.finalDegree, 'final coefficient count');
    _need(pf.queries.length == P.numQueries, 'query count');
    _need((A > 0) == pf.auxRoot.isNotEmpty, 'aux round presence');
    _need((R > 0) == pf.preRoot.isNotEmpty, 'preprocessed commitment presence');
    if (R > 0) _need(_same(pf.preRoot, PreCommitment.root(air, P, hash)), 'preprocessed root');

    // ---- transcript: challenges, beta, z ----
    final ts = hash.transcript();
    ts.absorbStatement(air.publicValues, pf.preRoot);
    ts.absorb(pf.traceRoot);
    final chal = [for (int k = 0; k < air.numChallenges; k++) ts.squeezeQM31()];
    if (A > 0) ts.absorb(pf.auxRoot);
    final beta = ts.squeezeQM31();
    ts.absorb(pf.compRoot);
    final tch = ts.squeezeQM31();
    // z from t with the hint h = (1 + t^2)^-1, verified by multiplication
    final t2 = tch * tch;
    _need((QM31.one + t2) * pf.zHint == QM31.one, 'z hint');
    final zx = (QM31.one - t2) * pf.zHint, zy = (tch + tch) * pf.zHint;
    ts.absorbLimbs([for (final v in [...pf.traceAtZ, ...pf.traceAtZg, ...pf.compAtZ]) ...v.limbs]);
    final lamA = ts.squeezeQM31(), lamB = ts.squeezeQM31(), lamC = ts.squeezeQM31(), alC = ts.squeezeQM31();

    // ---- out-of-domain constraint check ----
    final rhs = air.compositionAt(pf.traceAtZ, pf.traceAtZg, air.pointColumnsAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
    _need(composeColumns(pf.compAtZ) == rhs, 'composition relation at z');

    // ---- z*g and the DEEP constants ----
    final zgx = zx.scale(gT.x) - zy.scale(gT.y);
    final zgy = zx.scale(gT.y) + zy.scale(gT.x);
    final kA = DeepQuotientRef.precompute(zx, zy, pf.compAtZ, lamA);
    final kB = DeepQuotientRef.precompute(zx, zy, pf.traceAtZ, lamB);
    final kC = DeepQuotientRef.precompute(zgx, zgy, pf.traceAtZg, lamB, base: lamC);

    // ---- FRI roots and alphas, final coefficients, grinding, indices ----
    final alphas = <QM31>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      _need(pf.friRoots[l].length == hash.digestLen, 'FRI root $l length');
      ts.absorb(pf.friRoots[l]);
      alphas.add(ts.squeezeQM31());
    }
    ts.absorbLimbs([for (final c in pf.finalCoefs) ...c.limbs]);
    _need(ts.checkGrinding(pf.nonce, P.grindBytes), 'grinding');
    final indices = ts.squeezeIndices(P.numQueries, a);

    // ---- queries ----
    final hA = HalfCoset(a);
    for (int q = 0; q < P.numQueries; q++) {
      final qp = pf.queries[q];
      final i = indices[q];
      _need(qp.index == i, 'query $q index');
      final pA = hA.at(i);
      var xA = pA.x;
      final yA = pA.y;
      var xB = xA, yB = yA;
      for (int k = 0; k < a - P.logTraceHalf; k++) {
        final nx = _double(xB), ny = M31.mul(2, M31.mul(xB, yB));
        xB = nx;
        yB = ny;
      }
      // composition opening
      _need(qp.compLeaf.length == 8, 'query $q composition leaf');
      _need(qp.compPath.length == a, 'query $q composition path');
      _need(_same(_root(hash.leaf(qp.compLeaf), qp.compPath, i), pf.compRoot), 'query $q composition root');
      var idx = i & ((1 << (a - 1)) - 1);
      var topBit = i >> (a - 1);
      // DEEP group A at p and conj p, then the circle fold
      final qAp = _quotient(kA, xA, yA, qp.compLeaf.sublist(0, 4), qp.dAInvP, 'query $q D_A(p)');
      final qAc = _quotient(kA, xA, M31.neg(yA), qp.compLeaf.sublist(4, 8), qp.dAInvC, 'query $q D_A(conj p)');
      _need(M31.mul(yA, qp.yAInv) == 1, 'query $q y_A inverse');
      var out = _fold(qAp, qAc, qp.yAInv, alC);
      // circle-to-line: layer 0's leaf (i mod 2^(a-1)) has twiddle ±x_i
      xA = topBit == 1 ? M31.neg(xA) : xA;
      _need(out == (topBit == 1 ? qp.lineF1[0] : qp.lineF0[0]), 'query $q circle fold vs layer 0');

      for (int l = 0; l < P.numLineFolds; l++) {
        final d = a - 1 - l;
        QM31? outT;
        if (l == P.foldInIndex) {
          // trace (and aux) opening at p_B, whose leaf index is the current idx
          _need(qp.traceLeaf.length == 2 * C, 'query $q trace leaf');
          _need(qp.tracePath.length == P.logTraceHalf, 'query $q trace path');
          _need(_same(_root(hash.leaf(qp.traceLeaf), qp.tracePath, idx), pf.traceRoot), 'query $q trace root');
          if (A > 0) {
            _need(qp.auxLeaf.length == 2 * A, 'query $q aux leaf');
            _need(_same(_root(hash.leaf(qp.auxLeaf), qp.auxPath, idx), pf.auxRoot), 'query $q aux root');
          }
          if (R > 0) {
            _need(qp.preLeaf.length == 2 * R, 'query $q preprocessed leaf');
            _need(_same(_root(hash.leaf(qp.preLeaf), qp.prePath, idx), pf.preRoot), 'query $q preprocessed root');
          }
          final atP = [...qp.traceLeaf.sublist(0, C), ...qp.auxLeaf.sublist(0, A), ...qp.preLeaf.sublist(0, R)];
          final atC = [...qp.traceLeaf.sublist(C, 2 * C), ...qp.auxLeaf.sublist(A, 2 * A), ...qp.preLeaf.sublist(R, 2 * R)];
          final qTp = _quotient(kB, xB, yB, atP, qp.dBInvP, 'query $q D_B(p)') +
              _quotient(kC, xB, yB, atP, qp.dCInvP, 'query $q D_C(p)');
          final qTc = _quotient(kB, xB, M31.neg(yB), atC, qp.dBInvC, 'query $q D_B(conj p)') +
              _quotient(kC, xB, M31.neg(yB), atC, qp.dCInvC, 'query $q D_C(conj p)');
          _need(M31.mul(yB, qp.yBInv) == 1, 'query $q y_B inverse');
          outT = _fold(qTp, qTc, qp.yBInv, alphas[l]);
        }
        _need(qp.linePaths[l].length == d, 'query $q layer $l path');
        final leaf = hash.leaf([...qp.lineF0[l].limbs, ...qp.lineF1[l].limbs]);
        _need(_same(_root(leaf, qp.linePaths[l], idx), pf.friRoots[l]), 'query $q layer $l root');
        _need(M31.mul(xA, qp.lineXInv[l]) == 1, 'query $q layer $l x inverse');
        out = _fold(qp.lineF0[l], qp.lineF1[l], qp.lineXInv[l], alphas[l]);
        if (outT != null) out = out + outT;
        if (l < P.numLineFolds - 1) {
          topBit = idx >> (d - 1);
          idx = idx & ((1 << (d - 1)) - 1);
          xA = topBit == 1 ? M31.neg(_double(xA)) : _double(xA);
          _need(out == (topBit == 1 ? qp.lineF1[l + 1] : qp.lineF0[l + 1]), 'query $q fold $l vs layer ${l + 1}');
        } else {
          xA = _double(xA);
          var acc = QM31.zero;
          for (int j = P.finalDegree - 1; j >= 0; j--) {
            acc = acc.scale(xA) + pf.finalCoefs[j];
          }
          _need(acc == out, 'query $q final polynomial');
        }
      }
    }
  }

  /// q = (c Σ w_j f_j - y A - B) * dInv, with dInv checked against the
  /// denominator by multiplication.
  QM31 _quotient(DeepConstants k, int px, int py, List<int> openings, QM31 dInv, String what) {
    _need(DeepQuotientRef.denominator(k, px, py) * dInv == QM31.one, '$what inverse');
    var s = QM31.zero;
    for (int j = 0; j < openings.length; j++) {
      s = s + k.weights[j].scale(openings[j]);
    }
    return (k.c * s - k.A.scale(py) - k.B) * dInv;
  }

  static QM31 _fold(QM31 f0, QM31 f1, int twiddleInv, QM31 alpha) => (f0 + f1) + alpha * (f0 - f1).scale(twiddleInv);

  /// The point z of a transcript challenge, as the script derives it.
  static (QM31, QM31, QM31) circlePoint(QM31 t) => TranscriptRef.circlePoint(t);
}

/// Serialised size of a proof of [air] under [P] and [hash], in bytes: the
/// layout of `StarkVerifierGen.buildUnlock` (digests, 4-byte lanes, 16-byte
/// QM31 values) without push opcodes.
class ProofSize {
  static int bytes(StarkParams P, Air air, ProofHash hash) {
    final a = P.logCompHalf, d = hash.digestBytes, CT = air.totalCols, A = air.numAuxCols, R = air.numPreCols;
    var n = 0;
    n += 4 * air.numPublics;
    n += d * (2 + (A > 0 ? 1 : 0) + (R > 0 ? 1 : 0) + P.numLineFolds); // trace, (aux), (pre), comp, FRI roots
    n += 16 * (1 + 2 * CT + StarkParams.compCols + P.finalDegree); // zHint, OOD values, final coefs
    n += hash.nonceBytes;
    var q = 0;
    q += 8 * 4 + a * d + 4 + 2 * 16; // comp leaf, path, yAInv, dA inverses
    for (int l = 0; l < P.numLineFolds; l++) {
      q += 2 * 16 + (a - 1 - l) * d + 4; // pair, path, x inverse
    }
    q += 2 * air.numCols * 4 + P.logTraceHalf * d; // trace leaf, path
    if (A > 0) q += 2 * A * 4 + P.logTraceHalf * d;
    if (R > 0) q += 2 * R * 4 + P.logTraceHalf * d;
    q += 4 + 4 * 16; // yBInv, dB/dC inverses
    return n + P.numQueries * q;
  }
}
