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
import 'circle_fft.dart';
import 'm31.dart';
import 'stark_prover_ref.dart' show StarkParams, StarkProof, QueryProof, solveQ, embed, composeColumns;
import '../script_gen/deep_quotient_script_gen.dart' show DeepQuotientRef, DeepConstants;
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;
import '../script_gen/air.dart' show Air;

/// FFT-based Circle-STARK prover producing proofs in exactly the layout
/// `StarkVerifierGen` consumes. Protocol and transcript are those of
/// `StarkProverRef` (the executable spec); with zero-knowledge masking off the
/// two provers produce byte-identical proofs.
///
/// All polynomials are kept as base-field coefficient vectors in the circle
/// FFT basis (see `CircleFft`); commitments are evaluations in twin layout.
class StarkProver {
  final StarkParams P;
  final Air air;
  final bool verbose;
  final Stopwatch _sw = Stopwatch()..start();
  int _last = 0;

  StarkProver(this.P, this.air, {this.verbose = false});

  void _lap(String what) {
    if (!verbose) return;
    final now = _sw.elapsedMilliseconds;
    print('  [prover] ${what.padRight(28)} ${(now - _last).toString().padLeft(6)} ms');
    _last = now;
  }

  /// [rows] is the trace: 2^logTrace rows of air.numCols values.
  static StarkProof prove(StarkParams P, Air air, List<List<int>> rows, {Random? rng, bool verbose = false}) =>
      StarkProver(P, air, verbose: verbose)._prove(rows, rng ?? Random.secure());

  // ---------------------------------------------------------------- helpers

  static Uint8List _sha(List<int> a) => Uint8List.fromList(crypto.sha256.convert(a).bytes);

  static Uint8List _serLimbs(List<QM31> vs) {
    final bd = ByteData(16 * vs.length);
    var k = 0;
    for (final v in vs) {
      for (final l in v.limbs) {
        bd.setUint32(4 * k++, l, Endian.little);
      }
    }
    return bd.buffer.asUint8List();
  }

  static QM31 _foldPair(QM31 f0, QM31 f1, int twiddleInv, QM31 alpha) => (f0 + f1) + alpha * (f0 - f1).scale(twiddleInv);

  static List<QM31> _batchInvQ(List<QM31> xs) {
    final n = xs.length;
    final prefix = List<QM31>.filled(n, QM31.one);
    var acc = QM31.one;
    for (int i = 0; i < n; i++) {
      prefix[i] = acc;
      acc = acc * xs[i];
    }
    var inv = acc.inv;
    final out = List<QM31>.filled(n, QM31.zero);
    for (int i = n - 1; i >= 0; i--) {
      out[i] = inv * prefix[i];
      inv = inv * xs[i];
    }
    return out;
  }

  /// DEEP quotients of a column group over a twin-layout domain: returns
  /// q at every position (P side then C side), using batch inversion.
  static List<QM31> _deepQuotients(DeepConstants k, List<Uint32List> cols, CosetTables dom) {
    final m = dom.size, n = 2 * m;
    final nums = List<QM31>.filled(n, QM31.zero);
    final dens = List<QM31>.filled(n, QM31.zero);
    for (int q = 0; q < n; q++) {
      final i = q < m ? q : q - m;
      final px = dom.x[i];
      final py = q < m ? dom.y[i] : M31.neg(dom.y[i]);
      var s = QM31.zero;
      for (int j = 0; j < cols.length; j++) {
        s = s + k.weights[j].scale(cols[j][q]);
      }
      nums[q] = k.c * s - k.A.scale(py) - k.B;
      dens[q] = k.dA.scale(px) + k.dB.scale(py) + k.dC;
    }
    final inv = _batchInvQ(dens);
    return [for (int q = 0; q < n; q++) nums[q] * inv[q]];
  }

  // ---------------------------------------------------------------- prove

  StarkProof _prove(List<List<int>> rows, Random rng) {
    final t = P.logTrace, n = 1 << t;
    final gT = CirclePoint.subgroupGen(t);
    final nCols = air.numCols;
    if (rows.length != n) throw ArgumentError('trace must have $n rows');

    // ---- 1. trace on D_t (cyclic order) -> twin layout -> coefficients ----
    final domB = CosetTables.of(P.logTraceHalf);
    final mB = domB.size;

    /// Coefficients of column-major values, zk-masked when enabled:
    /// f' = f + v_t * r, deg_x r < R/2. v_t(x) = π^(t-1)(x) is the x-basis
    /// element of index 2^(t-1), so multiplying r by it shifts r's
    /// coefficients by 2^t in combined index.
    List<Uint32List> coefsFor(List<Uint32List> cols) {
      final out = <Uint32List>[];
      for (final col in cols) {
        final vals = Uint32List(n);
        for (int k = 0; k < n; k++) {
          vals[CircleFft.twinIndex(t, k)] = col[k];
        }
        var c = CircleFft.interpolate(vals, t - 1);
        if (P.zk) {
          final R = P.zkRandomizers;
          if (R > n) throw ArgumentError('zkRandomizers must be <= trace size');
          final m = Uint32List(2 * n);
          m.setRange(0, n, c);
          for (int i = 0; i < R; i++) {
            m[n + i] = rng.nextInt(M31.p);
          }
          c = m;
        }
        out.add(c);
      }
      return out;
    }

    /// Commit column coefficients on HalfCoset(logTraceHalf) ∪ conj.
    (List<Uint32List>, MerkleTree) commit(List<Uint32List> coefs) {
      final ev = [for (final c in coefs) CircleFft.evaluate(c, P.logTraceHalf)];
      final k = coefs.length;
      final leaves = List<Uint8List>.generate(mB, (i) {
        final bd = ByteData(8 * k);
        for (int j = 0; j < k; j++) {
          bd.setUint32(4 * j, ev[j][i], Endian.little);
          bd.setUint32(4 * (k + j), ev[j][mB + i], Endian.little);
        }
        return _sha(bd.buffer.asUint8List());
      });
      return (ev, MerkleTree(leaves));
    }

    final traceCoefs = coefsFor([
      for (int j = 0; j < nCols; j++) Uint32List.fromList([for (int k = 0; k < n; k++) rows[k][j]])
    ]);
    _lap('trace interpolation');
    final (traceEv, traceTree) = commit(traceCoefs);
    _lap('trace LDE + merkle');

    final ts = TranscriptRef();
    if (air.numPublics > 0) ts.absorbLimbs(air.publicValues);
    ts.absorb(traceTree.root);

    // ---- interaction round: challenges, aux columns, aux commitment ----
    final chal = [for (int k = 0; k < air.numChallenges; k++) ts.squeezeQM31()];
    var auxCoefs = <Uint32List>[];
    var auxEv = <Uint32List>[];
    MerkleTree? auxTree;
    if (air.numAuxCols > 0) {
      final auxCols = air.auxColumns(rows, chal);
      if (auxCols.length != air.numAuxCols) throw StateError('auxColumns returned ${auxCols.length} columns');
      auxCoefs = coefsFor(auxCols);
      (auxEv, auxTree) = commit(auxCoefs);
      ts.absorb(auxTree.root);
      _lap('aux round');
    }
    final allCoefs = [...traceCoefs, ...auxCoefs];
    final allEv = [...traceEv, ...auxEv];
    final nAll = allCoefs.length;
    final beta = ts.squeezeQM31();

    // ---- 2. composition on D_{t+e} (twin layout of HalfCoset(t+e-1)) ----
    final logC = t + P.logExpand, mC = 1 << (logC - 1), nC = 2 * mC;
    final domC = CosetTables.of(logC - 1);
    final traceOnC = [for (final c in allCoefs) CircleFft.evaluate(c, logC - 1)];
    _lap('trace on comp domain');
    final shift = 1 << (logC - t); // p * g_t is a shift by 2^(logC-t) in cyclic order
    // periodic columns on D_{logC}: F_k on D_{logPeriod+logExpand}, index mod its size
    final logPC = air.logPeriod + P.logExpand;
    final perOnC = [for (final c in air.periodicCoefs) CircleFft.evaluate(c, logPC - 1)];
    // v_t(x) on the composition domain, batch-inverted
    final vInv = CircleFft.batchInv(Uint32List.fromList([for (int i = 0; i < mC; i++) air.vanishingM31(domC.x[i])]));
    // linear forms on the composition domain; the ones used as group divisors
    // are batch-inverted too (a form vanishes only on the trace domain, which
    // is disjoint from the composition domain)
    final forms = air.linearForms;
    final linOnC = [for (final _ in forms) Uint32List(nC)];
    for (int q = 0; q < nC; q++) {
      final li = q < mC ? q : q - mC;
      final px = domC.x[li];
      final py = q < mC ? domC.y[li] : M31.neg(domC.y[li]);
      for (int k = 0; k < forms.length; k++) {
        linOnC[k][q] = forms[k].atM31(px, py);
      }
    }
    final groups = air.allGroups;
    final divInv = <int, Uint32List>{};
    for (final g in groups) {
      if (g.divisor >= 0) divInv[g.divisor] ??= CircleFft.batchInv(linOnC[g.divisor]);
    }
    // beta^{lo} for each group
    final groupPow = <QM31>[];
    {
      var bp = QM31.one;
      for (final g in groups) {
        groupPow.add(bp);
        for (int k = 0; k < g.count; k++) {
          bp = bp * beta;
        }
      }
    }
    final compLimbs = List.generate(4, (_) => Uint32List(nC));
    final cur = Uint32List(nAll), nxt = Uint32List(nAll), per = Uint32List(air.numPeriodic);
    final lin = Uint32List(forms.length);
    final nBase = air.numConstraints;
    final cons = Uint32List(nBase);
    final auxCons = List<QM31>.filled(air.numAuxConstraints, QM31.zero);
    for (int q = 0; q < nC; q++) {
      final cyc = CircleFft.cyclicIndex(logC, q);
      final qn = CircleFft.twinIndex(logC, (cyc + shift) & (nC - 1));
      final qp = CircleFft.twinIndex(logPC, cyc & ((1 << logPC) - 1));
      for (int j = 0; j < nAll; j++) {
        cur[j] = traceOnC[j][q];
        nxt[j] = traceOnC[j][qn];
      }
      for (int k = 0; k < per.length; k++) {
        per[k] = perOnC[k][qp];
      }
      for (int k = 0; k < lin.length; k++) {
        lin[k] = linOnC[k][q];
      }
      air.constraintsM31(cur, nxt, per, lin, cons);
      if (auxCons.isNotEmpty) air.auxConstraintsM31(cur, nxt, per, lin, chal, auxCons);
      final li = q < mC ? q : q - mC;
      var total = QM31.zero;
      var lo = 0;
      for (int g = 0; g < groups.length; g++) {
        final gr = groups[g];
        var acc = QM31.zero;
        for (int k = gr.count - 1; k >= 0; k--) {
          final j = lo + k;
          acc = acc * beta + (j < nBase ? embed(cons[j]) : auxCons[j - nBase]);
        }
        final f = gr.divisor < 0 ? vInv[li] : divInv[gr.divisor]![q];
        total = total + (groupPow[g] * acc).scale(f);
        lo += gr.count;
      }
      final limbs = total.limbs;
      for (int k = 0; k < 4; k++) {
        compLimbs[k][q] = limbs[k];
      }
    }
    _lap('composition values');
    final compCoefs = [for (final l in compLimbs) CircleFft.interpolate(l, logC - 1)];
    final domA = CosetTables.of(P.logCompHalf);
    final mA = domA.size;
    final compEv = [for (final c in compCoefs) CircleFft.evaluate(c, P.logCompHalf)];
    _lap('composition LDE');
    final compLeaves = List<Uint8List>.generate(mA, (i) {
      final bd = ByteData(32);
      for (int k = 0; k < 4; k++) {
        bd.setUint32(4 * k, compEv[k][i], Endian.little);
        bd.setUint32(16 + 4 * k, compEv[k][mA + i], Endian.little);
      }
      return _sha(bd.buffer.asUint8List());
    });
    final compTree = MerkleTree(compLeaves);
    _lap('composition merkle');

    ts.absorb(compTree.root);
    final tch = ts.squeezeQM31();
    final (zx, zy, zHint) = TranscriptRef.circlePoint(tch);

    // ---- 3. OODS values ----
    final zgx = zx.scale(gT.x) - zy.scale(gT.y);
    final zgy = zx.scale(gT.y) + zy.scale(gT.x);
    final traceAtZ = [for (final c in allCoefs) CircleFft.evalAt(c, zx, zy)];
    final traceAtZg = [for (final c in allCoefs) CircleFft.evalAt(c, zgx, zgy)];
    final compAtZ = [for (final c in compCoefs) CircleFft.evalAt(c, zx, zy)];
    final rhs = air.compositionAt(
        traceAtZ, traceAtZg, air.periodicAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
    if (composeColumns(compAtZ) != rhs) throw StateError('composition relation fails at z');
    ts.absorbLimbs([for (final v in [...traceAtZ, ...traceAtZg, ...compAtZ]) ...v.limbs]);
    final lamA = ts.squeezeQM31(), lamB = ts.squeezeQM31(), lamC = ts.squeezeQM31(), alC = ts.squeezeQM31();
    final dbg = <String, Object>{
      'beta': beta, 'tch': tch, 'zx': zx, 'zy': zy, 'zgx': zgx, 'zgy': zgy,
      'lamA': lamA, 'lamB': lamB, 'lamC': lamC, 'alC': alC,
      'probeOn': CircleFft.evalAt(traceCoefs[0], embed(CosetTables.of(t - 1).x[1]), embed(CosetTables.of(t - 1).y[1])),
      'probeOff': embed(traceEv[0][3]),
    };
    _lap('oods');

    // ---- DEEP quotients ----
    final kA = DeepQuotientRef.precompute(zx, zy, compAtZ, lamA);
    final kB = DeepQuotientRef.precompute(zx, zy, traceAtZ, lamB);
    final kC = DeepQuotientRef.precompute(zgx, zgy, traceAtZg, lamC);
    for (final (tag, k) in [('A', kA), ('B', kB), ('C', kC)]) {
      dbg['c$tag'] = k.c; dbg['A$tag'] = k.A; dbg['B$tag'] = k.B;
      dbg['dA$tag'] = k.dA; dbg['dB$tag'] = k.dB; dbg['dC$tag'] = k.dC;
      dbg['w${tag}1'] = k.weights[1];
    }
    final qA = _deepQuotients(kA, compEv, domA);
    final yAInv = domA.yInv;
    final l0 = List<QM31>.generate(mA, (i) => _foldPair(qA[i], qA[mA + i], yAInv[i], alC));
    _lap('deep quotient A + circle fold');
    final qB = _deepQuotients(kB, allEv, domB);
    final qC = _deepQuotients(kC, allEv, domB);
    final qBC = List<QM31>.generate(2 * mB, (q) => qB[q] + qC[q]);
    _lap('deep quotients B, C');

    // ---- 4. FRI line layers ----
    final a = P.logCompHalf;
    final layers = <List<QM31>>[l0];
    final trees = <MerkleTree>[];
    final alphas = <QM31>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      final curL = layers[l];
      final half = curL.length ~/ 2;
      final tree = MerkleTree(List<Uint8List>.generate(half, (i) => _sha(_serLimbs([curL[i], curL[i + half]]))));
      trees.add(tree);
      ts.absorb(tree.root);
      final al = ts.squeezeQM31();
      alphas.add(al);
      dbg['al$l'] = al;
      final xInv = CosetTables.of(a - l).xInv;
      final next = List<QM31>.generate(half, (i) => _foldPair(curL[i], curL[i + half], xInv[i], al));
      if (l == P.foldInIndex) {
        if (next.length != mB) throw StateError('fold-in size mismatch');
        final yBInv = domB.yInv;
        for (int i = 0; i < half; i++) {
          next[i] = next[i] + _foldPair(qBC[i], qBC[mB + i], yBInv[i], al);
        }
      }
      layers.add(next);
    }
    _lap('fri layers');

    // ---- 5. final polynomial (monomial in x), must be low degree ----
    final fin = layers.last;
    final finX = CosetTables.of(P.logFinal).x;
    final d = P.finalDegree;
    final vander = [
      for (int i = 0; i < d; i++)
        [for (int j = 0, xp = 1; j < d; j++, xp = CircleFft.mul(xp, finX[i])) embed(xp)]
    ];
    final finalCoefs = solveQ(vander, fin.sublist(0, d));
    for (int i = d; i < fin.length; i++) {
      var acc = QM31.zero;
      for (int j = d - 1; j >= 0; j--) {
        acc = acc.scale(finX[i]) + finalCoefs[j];
      }
      if (acc != fin[i]) throw StateError('final layer is not low degree (mismatch at $i)');
    }
    ts.absorbLimbs([for (final v in finalCoefs) ...v.limbs]);
    _lap('final polynomial');
    final nonce = ts.grind(P.grindBytes);
    _lap('grinding');
    final indices = ts.squeezeIndices(P.numQueries, a);
    for (int q = 0; q < indices.length; q++) {
      dbg['qi$q'] = indices[q];
    }
    {
      final i = indices[0];
      dbg['xA'] = domA.x[i]; dbg['yA'] = domA.y[i];
      final iB = i % mB;
      dbg['xB'] = domB.x[iB]; dbg['yB'] = domB.y[iB];
      dbg['qAp'] = qA[i]; dbg['qAc'] = qA[mA + i];
      dbg['circleOut'] = l0[i];
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        il = il % (layers[l].length ~/ 2);
        dbg['fold$l'] = layers[l + 1][il];
      }
      dbg['qTp'] = qBC[iB]; dbg['qTc'] = qBC[mB + iB];
    }

    // ---- 6. openings ----
    final queries = <QueryProof>[];
    for (final i in indices) {
      final px = domA.x[i], py = domA.y[i];
      final lineF0 = <QM31>[], lineF1 = <QM31>[], linePaths = <List<List<int>>>[], lineXInv = <int>[];
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        final half = layers[l].length ~/ 2;
        il = il % half;
        lineF0.add(layers[l][il]);
        lineF1.add(layers[l][il + half]);
        linePaths.add(trees[l].path(il));
        lineXInv.add(CosetTables.of(a - l).xInv[il]);
      }
      final iB = i % mB;
      final pBx = domB.x[iB], pBy = domB.y[iB];
      queries.add(QueryProof(
        index: i,
        compLeaf: [for (int k = 0; k < 4; k++) compEv[k][i], for (int k = 0; k < 4; k++) compEv[k][mA + i]],
        compPath: compTree.path(i),
        yAInv: yAInv[i],
        dAInvP: DeepQuotientRef.denominator(kA, px, py).inv,
        dAInvC: DeepQuotientRef.denominator(kA, px, M31.neg(py)).inv,
        lineF0: lineF0, lineF1: lineF1, linePaths: linePaths, lineXInv: lineXInv,
        traceLeaf: [for (int j = 0; j < nCols; j++) traceEv[j][iB], for (int j = 0; j < nCols; j++) traceEv[j][mB + iB]],
        tracePath: traceTree.path(iB),
        auxLeaf: [for (final c in auxEv) c[iB], for (final c in auxEv) c[mB + iB]],
        auxPath: auxTree?.path(iB) ?? const [],
        yBInv: domB.yInv[iB],
        dBInvP: DeepQuotientRef.denominator(kB, pBx, pBy).inv,
        dBInvC: DeepQuotientRef.denominator(kB, pBx, M31.neg(pBy)).inv,
        dCInvP: DeepQuotientRef.denominator(kC, pBx, pBy).inv,
        dCInvC: DeepQuotientRef.denominator(kC, pBx, M31.neg(pBy)).inv,
      ));
    }
    _lap('openings');
    final proof = StarkProof(
      traceRoot: traceTree.root, compRoot: compTree.root, auxRoot: auxTree?.root ?? const [], zHint: zHint,
      traceAtZ: traceAtZ, traceAtZg: traceAtZg, compAtZ: compAtZ,
      friRoots: trees.map((t) => t.root).toList(), finalCoefs: finalCoefs, nonce: nonce, queries: queries,
    );
    proof.debug.addAll(dbg);
    return proof;
  }
}

/// SHA256 Merkle tree over pre-hashed leaves; internal node = SHA256(left || right).
class MerkleTree {
  final List<List<Uint8List>> levels;

  MerkleTree(List<Uint8List> leaves) : levels = [leaves] {
    final buf = Uint8List(64);
    while (levels.last.length > 1) {
      final prev = levels.last;
      final next = List<Uint8List>.generate(prev.length ~/ 2, (i) {
        buf.setRange(0, 32, prev[2 * i]);
        buf.setRange(32, 64, prev[2 * i + 1]);
        return Uint8List.fromList(crypto.sha256.convert(buf).bytes);
      });
      levels.add(next);
    }
  }

  Uint8List get root => levels.last[0];
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
