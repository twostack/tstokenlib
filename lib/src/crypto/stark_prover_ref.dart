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

import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'm31.dart';
import '../script_gen/deep_quotient_script_gen.dart' show DeepQuotientRef, DeepConstants;
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;
import '../script_gen/air.dart' show Air;

/// PROTOTYPE reference prover for the Circle-STARK verified by
/// `StarkVerifierGen`. Uses naive O(N^3) interpolation by linear solve, so
/// it is only usable for tiny traces; its purpose is to produce proofs in the
/// exact layout the script verifier consumes, and to validate the protocol
/// end to end (an incorrect DEEP quotient or fold would surface as a
/// non-low-degree final layer).
///
/// Protocol (transcript order):
///   1. absorb trace root            -> beta (constraint combination)
///   2. absorb composition root      -> t, z = circlePoint(t)
///   3. absorb OODS values           -> lambdaA, lambdaB, lambdaC, alphaCircle
///      (trace cols at z, trace cols at z*g, comp cols at z)
///   4. for each FRI line layer l: absorb root_l -> alpha_l
///   5. absorb final polynomial coefficients; grinding; query indices
///
/// Domains: trace on D_t (size 2^t), committed on D_{t+b}; composition on
/// D_{t+e} (constraint degree 6, e = 3), committed on D_{t+b+e}. FRI starts
/// from the composition quotient's circle fold (line size 2^a, a = t+b+e-1)
/// and folds the trace quotients in at line size 2^(t+b-1).
class StarkParams {
  final int logTrace, logBlowup, logExpand, logFinal, numQueries, grindBytes;

  /// Zero-knowledge: number of random coefficients R per trace column. Each
  /// column is masked as f' = f + v_N * r with deg r < R, so f' agrees with
  /// the trace on the trace domain and is uniformly random at up to R other
  /// evaluation points. 0 disables masking (sound but not zero-knowledge).
  final int zkRandomizers;

  const StarkParams({
    required this.logTrace,
    required this.logBlowup,
    this.logExpand = 3,
    required this.logFinal,
    required this.numQueries,
    required this.grindBytes,
    this.zkRandomizers = 0,
  });
  bool get zk => zkRandomizers > 0;

  /// Masked columns have degree up to N and are committed in the 2N space.
  int get logTraceBound => logTrace + (zk ? 1 : 0);
  int get logCompHalf => logTrace + logBlowup + logExpand - 1; // a
  int get logTraceHalf => logTraceBound + logBlowup - 1;
  int get numLineFolds => logCompHalf - logFinal;
  /// Fold whose output line layer has the trace group's size.
  int get foldInIndex => logCompHalf - logTraceHalf - 1;
  int get finalDegree => 1 << (logFinal - logBlowup);

  /// Points at which a trace column's value is revealed, directly (p, conj p
  /// per query) or through the composition openings (p*g, conj(p)*g), plus
  /// the two QM31 out-of-domain evaluations (4 M31 dimensions each).
  int get revealedPerColumn => 4 * numQueries + 8;
  bool get zkSufficient => zk && zkRandomizers >= revealedPerColumn && zkRandomizers < (1 << logTrace);
  static const compCols = 4;
}

List<int> sha(List<int> a) => crypto.sha256.convert(a).bytes;

Uint8List serM31s(List<int> vals) {
  final bd = ByteData(4 * vals.length);
  for (int i = 0; i < vals.length; i++) {
    bd.setUint32(4 * i, vals[i], Endian.little);
  }
  return bd.buffer.asUint8List();
}

class MerkleTreeRef {
  final List<List<List<int>>> levels;
  MerkleTreeRef(List<List<int>> leaves) : levels = [leaves] {
    while (levels.last.length > 1) {
      final prev = levels.last;
      levels.add([for (int i = 0; i < prev.length; i += 2) sha([...prev[i], ...prev[i + 1]])]);
    }
  }
  List<int> get root => levels.last[0];
  int get depth => levels.length - 1;
  List<List<int>> path(int leaf) {
    final out = <List<int>>[];
    var i = leaf;
    for (int lv = 0; lv < depth; lv++) {
      out.add(levels[lv][i ^ 1]);
      i >>= 1;
    }
    return out;
  }
}

/// Standard circle domain of size 2^k: h * g^m, h = gen(k+1), g = gen(k).
List<CirclePoint> circleDomain(int k) {
  final h = CirclePoint.subgroupGen(k + 1), g = CirclePoint.subgroupGen(k);
  final out = <CirclePoint>[];
  var p = h;
  for (int m = 0; m < (1 << k); m++) {
    out.add(p);
    p = p * g;
  }
  return out;
}

/// Gaussian elimination over QM31.
List<QM31> solveQ(List<List<QM31>> a, List<QM31> b) => solveQMulti(a, [b])[0];

/// comp = c0 + c1·i + c2·u + c3·i·u from four base-field column values.
QM31 composeColumns(List<QM31> c) => c[0] + c[1] * QM31.i + c[2] * QM31.u + c[3] * QM31.i * QM31.u;

/// Solve a·x = b for several right-hand sides sharing the matrix.
List<List<QM31>> solveQMulti(List<List<QM31>> a, List<List<QM31>> bs) {
  final n = a.length, r = bs.length;
  final m = [for (int i = 0; i < n; i++) [...a[i], for (final b in bs) b[i]]];
  for (int c = 0; c < n; c++) {
    int piv = c;
    while (piv < n && m[piv][c] == QM31.zero) {
      piv++;
    }
    if (piv == n) throw StateError('singular system at column $c');
    final tmp = m[c];
    m[c] = m[piv];
    m[piv] = tmp;
    final inv = m[c][c].inv;
    for (int j = c; j < n + r; j++) {
      m[c][j] = m[c][j] * inv;
    }
    for (int row = 0; row < n; row++) {
      if (row == c || m[row][c] == QM31.zero) continue;
      final f = m[row][c];
      for (int j = c; j < n + r; j++) {
        m[row][j] = m[row][j] - f * m[c][j];
      }
    }
  }
  return [for (int k = 0; k < r; k++) [for (int i = 0; i < n; i++) m[i][n + k]]];
}

QM31 embed(int v) => QM31.fromLimbs(v, 0, 0, 0);

/// Circle polynomial in the FFT-space basis {x^i, y x^i : i < N/2}.
class CirclePolyRef {
  final List<QM31> coef; // length N
  CirclePolyRef(this.coef);
  int get n => coef.length;

  QM31 eval(QM31 x, QM31 y) {
    final half = n ~/ 2;
    var a0 = QM31.zero, a1 = QM31.zero;
    for (int i = half - 1; i >= 0; i--) {
      a0 = a0 * x + coef[i];
      a1 = a1 * x + coef[half + i];
    }
    return a0 + y * a1;
  }

  QM31 evalP(CirclePoint p) => eval(embed(p.x), embed(p.y));

  static List<QM31> basisAt(int n, QM31 x, QM31 y) {
    final half = n ~/ 2;
    final out = <QM31>[];
    var xp = QM31.one;
    final xs = <QM31>[];
    for (int i = 0; i < half; i++) {
      xs.add(xp);
      xp = xp * x;
    }
    out.addAll(xs);
    out.addAll(xs.map((v) => v * y));
    return out;
  }

  static CirclePolyRef interpolate(List<CirclePoint> pts, List<QM31> vals) => interpolateMulti(pts, [vals])[0];

  static List<CirclePolyRef> interpolateMulti(List<CirclePoint> pts, List<List<QM31>> vals) {
    final n = pts.length;
    final a = [for (final p in pts) basisAt(n, embed(p.x), embed(p.y))];
    return [for (final c in solveQMulti(a, vals)) CirclePolyRef(c)];
  }
}

class QueryProof {
  final int index;
  final List<int> compLeaf; // 4 at p, 4 at conj p
  final List<List<int>> compPath;
  final int yAInv;
  final QM31 dAInvP, dAInvC;
  final List<QM31> lineF0, lineF1; // per line layer
  final List<List<List<int>>> linePaths;
  final List<int> lineXInv;
  final List<int> traceLeaf; // numCols at p, numCols at conj p
  final List<List<int>> tracePath;
  /// Aux-round opening at the same index (empty without an aux round).
  final List<int> auxLeaf;
  final List<List<int>> auxPath;
  final int yBInv;
  final QM31 dBInvP, dBInvC, dCInvP, dCInvC;
  QueryProof({
    required this.index, required this.compLeaf, required this.compPath, required this.yAInv,
    required this.dAInvP, required this.dAInvC, required this.lineF0, required this.lineF1,
    required this.linePaths, required this.lineXInv, required this.traceLeaf, required this.tracePath,
    this.auxLeaf = const [], this.auxPath = const [],
    required this.yBInv, required this.dBInvP, required this.dBInvC, required this.dCInvP, required this.dCInvC,
  });
}

class StarkProof {
  final List<int> traceRoot, compRoot;
  /// Root of the aux-round commitment (empty without an aux round).
  final List<int> auxRoot;
  final QM31 zHint;
  /// Out-of-domain values: trace columns then aux columns.
  final List<QM31> traceAtZ, traceAtZg, compAtZ;
  final List<List<int>> friRoots;
  final List<QM31> finalCoefs;
  final List<int> nonce;
  final List<QueryProof> queries;
  /// Intermediate values keyed by the script names used in StarkVerifierGen
  /// (QM31 or int), for staged debugging.
  final Map<String, Object> debug = {};
  StarkProof({
    required this.traceRoot, required this.compRoot, this.auxRoot = const [], required this.zHint,
    required this.traceAtZ, required this.traceAtZg, required this.compAtZ, required this.friRoots,
    required this.finalCoefs, required this.nonce, required this.queries,
  });
}

class StarkProverRef {
  static QM31 foldPair(QM31 f0, QM31 f1, int twiddle, QM31 alpha) =>
      (f0 + f1) + alpha * (f0 - f1).scale(M31.inv(twiddle));

  /// [rows] is the trace: 2^logTrace rows of air.numCols values.
  static StarkProof prove(StarkParams P, Air air, List<List<int>> rows, {Random? rng}) {
    rng ??= Random.secure();
    final t = P.logTrace, n = 1 << t;
    final gT = CirclePoint.subgroupGen(t);
    if (rows.length != n) throw ArgumentError('trace must have $n rows');
    final nCols = air.numCols;

    // ---- 1. trace on D_t (time order), interpolate the columns ----
    final dT = circleDomain(t);
    final d2 = circleDomain(t + 1);
    final hB = HalfCoset(P.logTraceHalf);

    /// Interpolate column-major values on D_t and, with zk on, mask each
    /// column as f' = f + v_N * r on the 2N domain.
    List<CirclePolyRef> polysFor(List<List<int>> cols) {
      var polys = [for (final c in cols) CirclePolyRef.interpolate(dT, [for (int k = 0; k < n; k++) embed(c[k])])];
      if (P.zk) {
        final R = P.zkRandomizers;
        if (R >= n) throw ArgumentError('zkRandomizers must be < trace size');
        polys = [
          for (final f in polys)
            (() {
              final r = CirclePolyRef([for (int i = 0; i < R; i++) embed(rng!.nextInt(M31.p))]);
              return CirclePolyRef.interpolate(
                  d2, [for (final p in d2) f.evalP(p) + air.vanishing(embed(p.x)) * r.evalP(p)]);
            })()
        ];
      }
      return polys;
    }

    /// Commit a column set on H_B ∪ conj: values at p, at conj p, and the tree.
    (List<List<int>>, List<List<int>>, MerkleTreeRef) commit(List<CirclePolyRef> polys) {
      List<int> valsAt(CirclePoint p) => [for (final q in polys) q.evalP(p).c0.a];
      final atP = [for (int i = 0; i < hB.size; i++) valsAt(hB.at(i))];
      final atC = [for (int i = 0; i < hB.size; i++) valsAt(CirclePoint(hB.at(i).x, M31.neg(hB.at(i).y)))];
      return (atP, atC, MerkleTreeRef([for (int i = 0; i < hB.size; i++) sha([...serM31s(atP[i]), ...serM31s(atC[i])])]));
    }

    final tracePolys = polysFor([for (int j = 0; j < nCols; j++) [for (int k = 0; k < n; k++) rows[k][j]]]);
    // sanity: (masked) interpolation reproduces the trace on D_t
    assert(tracePolys[0].evalP(dT[3]) == embed(rows[3][0]));
    final (traceAtP, traceAtC, traceTree) = commit(tracePolys);

    final ts = TranscriptRef();
    if (air.numPublics > 0) ts.absorbLimbs(air.publicValues);
    ts.absorb(traceTree.root);

    // ---- interaction round: challenges, aux columns, aux commitment ----
    final chal = [for (int k = 0; k < air.numChallenges; k++) ts.squeezeQM31()];
    var auxPolys = <CirclePolyRef>[];
    var auxAtP = <List<int>>[], auxAtC = <List<int>>[];
    MerkleTreeRef? auxTree;
    if (air.numAuxCols > 0) {
      final auxCols = air.auxColumns(rows, chal);
      if (auxCols.length != air.numAuxCols) throw StateError('auxColumns returned ${auxCols.length} columns');
      auxPolys = polysFor([for (final c in auxCols) c.toList()]);
      (auxAtP, auxAtC, auxTree) = commit(auxPolys);
      ts.absorb(auxTree.root);
    }
    final allPolys = [...tracePolys, ...auxPolys];
    final allAtP = [for (int i = 0; i < hB.size; i++) [...traceAtP[i], if (auxTree != null) ...auxAtP[i]]];
    final allAtC = [for (int i = 0; i < hB.size; i++) [...traceAtC[i], if (auxTree != null) ...auxAtC[i]]];
    final beta = ts.squeezeQM31();

    // ---- 2. composition on D_{t+e}, interpolate 4 limb columns ----
    final dC = circleDomain(t + P.logExpand);
    QM31 compAt(CirclePoint p) {
      final cur = [for (final q in allPolys) q.evalP(p)];
      final pg = p * gT;
      final next = [for (final q in allPolys) q.evalP(pg)];
      final px = embed(p.x), py = embed(p.y);
      return air.compositionAt(cur, next, air.periodicAt(px, py), air.linearAt(px, py), beta, px, chal: chal);
    }
    final compVals = [for (final p in dC) compAt(p)];
    final compPolys = CirclePolyRef.interpolateMulti(dC, [
      for (int k = 0; k < 4; k++) [for (final v in compVals) embed(v.limbs[k])]
    ]);
    final hA = HalfCoset(P.logCompHalf);
    List<int> compValsAt(CirclePoint p) => [for (final q in compPolys) q.evalP(p).c0.a];
    final compAtP = [for (int i = 0; i < hA.size; i++) compValsAt(hA.at(i))];
    final compAtCj = [for (int i = 0; i < hA.size; i++) compValsAt(CirclePoint(hA.at(i).x, M31.neg(hA.at(i).y)))];
    final compTree = MerkleTreeRef([for (int i = 0; i < hA.size; i++) sha([...serM31s(compAtP[i]), ...serM31s(compAtCj[i])])]);

    ts.absorb(compTree.root);
    final tch = ts.squeezeQM31();
    final (zx, zy, zHint) = TranscriptRef.circlePoint(tch);

    // ---- 3. OODS values ----
    final zgx = zx.scale(gT.x) - zy.scale(gT.y);
    final zgy = zx.scale(gT.y) + zy.scale(gT.x);
    final traceAtZ = [for (final q in allPolys) q.eval(zx, zy)];
    final traceAtZg = [for (final q in allPolys) q.eval(zgx, zgy)];
    final compAtZ = [for (final q in compPolys) q.eval(zx, zy)];
    // pipeline sanity: composition relation holds at z
    final rhs = air.compositionAt(
        traceAtZ, traceAtZg, air.periodicAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
    if (composeColumns(compAtZ) != rhs) throw StateError('composition relation fails at z');
    ts.absorbLimbs([for (final v in [...traceAtZ, ...traceAtZg, ...compAtZ]) ...v.limbs]);
    final lamA = ts.squeezeQM31(), lamB = ts.squeezeQM31(), lamC = ts.squeezeQM31(), alC = ts.squeezeQM31();
    final dbg = <String, Object>{
      'beta': beta, 'tch': tch, 'zx': zx, 'zy': zy, 'zgx': zgx, 'zgy': zgy,
      'lamA': lamA, 'lamB': lamB, 'lamC': lamC, 'alC': alC,
      // masking probes: column 0 at a trace row (must equal the trace) and at
      // a fixed off-domain point (must vary with the randomizers)
      'probeOn': tracePolys[0].evalP(dT[2]),
      'probeOff': tracePolys[0].evalP(HalfCoset(P.logTraceHalf).at(3)),
    };

    // ---- DEEP quotients ----
    final kA = DeepQuotientRef.precompute(zx, zy, compAtZ, lamA);
    final kB = DeepQuotientRef.precompute(zx, zy, traceAtZ, lamB);
    final kC = DeepQuotientRef.precompute(zgx, zgy, traceAtZg, lamC);
    for (final (tag, k) in [('A', kA), ('B', kB), ('C', kC)]) {
      dbg['c$tag'] = k.c; dbg['A$tag'] = k.A; dbg['B$tag'] = k.B;
      dbg['dA$tag'] = k.dA; dbg['dB$tag'] = k.dB; dbg['dC$tag'] = k.dC;
      dbg['w${tag}1'] = k.weights[1];
    }
    final l0 = <QM31>[];
    for (int i = 0; i < hA.size; i++) {
      final p = hA.at(i);
      final qp = DeepQuotientRef.quotient(kA, p.x, p.y, compAtP[i]);
      final qc = DeepQuotientRef.quotient(kA, p.x, M31.neg(p.y), compAtCj[i]);
      l0.add(foldPair(qp, qc, p.y, alC));
    }
    final qBCp = <QM31>[], qBCc = <QM31>[];
    for (int i = 0; i < hB.size; i++) {
      final p = hB.at(i);
      qBCp.add(DeepQuotientRef.quotient(kB, p.x, p.y, allAtP[i]) + DeepQuotientRef.quotient(kC, p.x, p.y, allAtP[i]));
      qBCc.add(DeepQuotientRef.quotient(kB, p.x, M31.neg(p.y), allAtC[i]) + DeepQuotientRef.quotient(kC, p.x, M31.neg(p.y), allAtC[i]));
    }

    // ---- 4. FRI line layers ----
    final a = P.logCompHalf;
    final layers = <List<QM31>>[l0];
    final trees = <MerkleTreeRef>[];
    final alphas = <QM31>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      final cur = layers[l];
      final half = cur.length ~/ 2;
      final tree = MerkleTreeRef([for (int i = 0; i < half; i++) sha([...serM31s(cur[i].limbs), ...serM31s(cur[i + half].limbs)])]);
      trees.add(tree);
      ts.absorb(tree.root);
      final al = ts.squeezeQM31();
      alphas.add(al);
      dbg['al$l'] = al;
      final coset = HalfCoset(a - l);
      final next = [for (int i = 0; i < half; i++) foldPair(cur[i], cur[i + half], coset.at(i).x, al)];
      if (l == P.foldInIndex) {
        if (next.length != hB.size) throw StateError('fold-in size mismatch');
        for (int i = 0; i < half; i++) {
          next[i] = next[i] + foldPair(qBCp[i], qBCc[i], hB.at(i).y, al);
        }
      }
      layers.add(next);
    }
    // ---- 5. final polynomial (monomial in x), must be low degree ----
    final fin = layers.last;
    final finCoset = HalfCoset(P.logFinal);
    final vander = [for (int i = 0; i < fin.length; i++) CirclePolyRef.basisAt(2 * fin.length, embed(finCoset.at(i).x), QM31.zero).sublist(0, fin.length)];
    final coefs = solveQ(vander, fin);
    for (int i = P.finalDegree; i < coefs.length; i++) {
      if (coefs[i] != QM31.zero) throw StateError('final layer is not low degree (coef $i nonzero)');
    }
    final finalCoefs = coefs.sublist(0, P.finalDegree);
    ts.absorbLimbs([for (final v in finalCoefs) ...v.limbs]);
    final nonce = ts.grind(P.grindBytes);
    if (!ts.checkGrinding(nonce, P.grindBytes)) throw StateError('grind');
    final indices = ts.squeezeIndices(P.numQueries, a);
    for (int q = 0; q < indices.length; q++) {
      dbg['qi$q'] = indices[q];
    }
    // query 0 intermediates
    {
      final i = indices[0];
      final p = hA.at(i);
      dbg['xA'] = p.x; dbg['yA'] = p.y;
      final pB = hB.at(i % hB.size);
      dbg['xB'] = pB.x; dbg['yB'] = pB.y;
      dbg['qAp'] = DeepQuotientRef.quotient(kA, p.x, p.y, compAtP[i]);
      dbg['qAc'] = DeepQuotientRef.quotient(kA, p.x, M31.neg(p.y), compAtCj[i]);
      dbg['circleOut'] = l0[i];
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        il = il % (layers[l].length ~/ 2);
        dbg['fold$l'] = layers[l + 1][il];
      }
      dbg['qTp'] = qBCp[i % hB.size]; dbg['qTc'] = qBCc[i % hB.size];
    }

    // ---- 6. openings ----
    final queries = <QueryProof>[];
    for (final i in indices) {
      final p = hA.at(i);
      final lineF0 = <QM31>[], lineF1 = <QM31>[], linePaths = <List<List<int>>>[], lineXInv = <int>[];
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        final half = layers[l].length ~/ 2;
        il = il % half;
        lineF0.add(layers[l][il]);
        lineF1.add(layers[l][il + half]);
        linePaths.add(trees[l].path(il));
        lineXInv.add(M31.inv(HalfCoset(a - l).at(il).x));
      }
      final iB = i % hB.size;
      final pB = hB.at(iB);
      queries.add(QueryProof(
        index: i,
        compLeaf: [...compAtP[i], ...compAtCj[i]],
        compPath: compTree.path(i),
        yAInv: M31.inv(p.y),
        dAInvP: DeepQuotientRef.denominator(kA, p.x, p.y).inv,
        dAInvC: DeepQuotientRef.denominator(kA, p.x, M31.neg(p.y)).inv,
        lineF0: lineF0, lineF1: lineF1, linePaths: linePaths, lineXInv: lineXInv,
        traceLeaf: [...traceAtP[iB], ...traceAtC[iB]],
        tracePath: traceTree.path(iB),
        auxLeaf: auxTree == null ? const [] : [...auxAtP[iB], ...auxAtC[iB]],
        auxPath: auxTree == null ? const [] : auxTree.path(iB),
        yBInv: M31.inv(pB.y),
        dBInvP: DeepQuotientRef.denominator(kB, pB.x, pB.y).inv,
        dBInvC: DeepQuotientRef.denominator(kB, pB.x, M31.neg(pB.y)).inv,
        dCInvP: DeepQuotientRef.denominator(kC, pB.x, pB.y).inv,
        dCInvC: DeepQuotientRef.denominator(kC, pB.x, M31.neg(pB.y)).inv,
      ));
    }
    final proof = StarkProof(
      traceRoot: traceTree.root, compRoot: compTree.root, auxRoot: auxTree?.root ?? const [], zHint: zHint,
      traceAtZ: traceAtZ, traceAtZg: traceAtZg, compAtZ: compAtZ,
      friRoots: trees.map((t) => t.root).toList(), finalCoefs: finalCoefs, nonce: nonce, queries: queries,
    );
    proof.debug.addAll(dbg);
    return proof;
  }
}
