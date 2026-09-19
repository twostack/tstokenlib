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
import 'circle_fft.dart';
import 'm31.dart';
import 'proof_hash.dart';
import 'stark_kernels.dart';
import 'stark_prover_ref.dart' show StarkParams, StarkProof, QueryProof, solveQ, embed;
import '../script_gen/deep_quotient_script_gen.dart' show DeepQuotientRef;
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;
import '../script_gen/air.dart' show Air, ConstraintGroup;

export 'proof_hash.dart' show ProofHash, Sha256ProofHash, Poseidon2ProofHash;
export 'stark_kernels.dart' show MerkleTree, MerkleCommitment, ProverKernels, DartKernels, StarkKernels;

/// FFT-based Circle-STARK prover producing proofs in exactly the layout
/// `StarkVerifierGen` consumes. Protocol and transcript are those of
/// `StarkProverRef` (the executable spec); with zero-knowledge masking off the
/// two provers produce byte-identical proofs.
///
/// All polynomials are kept as base-field coefficient vectors in the circle
/// FFT basis (see `CircleFft`); commitments are evaluations in twin layout.
/// The arithmetic runs on a [ProverKernels]: the native Rust kernels when
/// the library is built, plain Dart otherwise (same proof either way).
class StarkProver {
  final StarkParams P;
  final Air air;
  final bool verbose;
  final ProverKernels kernels;

  /// The hash flavour: SHA256 for a proof a script verifies, Poseidon2 for
  /// one another proof verifies (see [ProofHash]).
  final ProofHash hash;
  final Stopwatch _sw = Stopwatch()..start();
  int _last = 0;

  StarkProver(this.P, this.air, {this.verbose = false, ProverKernels? kernels, this.hash = const Sha256ProofHash()})
      : kernels = kernels ?? ProverKernels.best;

  void _lap(String what) {
    if (!verbose) return;
    final now = _sw.elapsedMilliseconds;
    print('  [prover] ${what.padRight(28)} ${(now - _last).toString().padLeft(6)} ms');
    _last = now;
  }

  /// [rows] is the trace: 2^logTrace rows of air.numCols values.
  static StarkProof prove(StarkParams P, Air air, List<List<int>> rows,
          {Random? rng, bool verbose = false, ProverKernels? kernels, ProofHash hash = const Sha256ProofHash()}) =>
      StarkProver(P, air, verbose: verbose, kernels: kernels, hash: hash)._prove(rows, rng ?? Random.secure());

  // ---------------------------------------------------------------- prove

  StarkProof _prove(List<List<int>> rows, Random rng) {
    final t = P.logTrace, n = 1 << t;
    final gT = CirclePoint.subgroupGen(t);
    final nCols = air.numCols;
    if (rows.length != n) throw ArgumentError('trace must have $n rows');
    if (verbose) print('  [prover] kernels: ${kernels.name}, hash: ${hash.name}');

    // ---- 1. trace on D_t (cyclic order) -> twin layout -> coefficients ----
    final domB = CosetTables.of(P.logTraceHalf);
    final mB = domB.size;

    /// Coefficients of column-major values, zk-masked when enabled:
    /// f' = f + v_t * r, deg_x r < R/2. v_t(x) = π^(t-1)(x) is the x-basis
    /// element of index 2^(t-1), so multiplying r by it shifts r's
    /// coefficients by 2^t in combined index.
    List<Uint32List> coefsFor(List<Uint32List> cols, {bool mask = true}) {
      final twin = <Uint32List>[];
      for (final col in cols) {
        final vals = Uint32List(n);
        for (int k = 0; k < n; k++) {
          vals[CircleFft.twinIndex(t, k)] = col[k];
        }
        twin.add(vals);
      }
      final coefs = kernels.interpolateColumns(twin, t - 1);
      if (!P.zk || !mask) return coefs;
      final R = P.zkRandomizers;
      if (R > n) throw ArgumentError('zkRandomizers must be <= trace size');
      return [
        for (final c in coefs)
          (Uint32List(2 * n)
            ..setRange(0, n, c)
            ..setAll(n, [for (int i = 0; i < R; i++) rng.nextInt(M31.p)]))
      ];
    }

    /// Commit column coefficients on HalfCoset(logTraceHalf) ∪ conj.
    (Columns, MerkleCommitment) commit(List<Uint32List> coefs) => kernels.commitColumns(coefs, P.logTraceHalf, hash);
    // the committed columns of this proof, released when it is done (the
    // preprocessed ones live in the PreCommitment cache)
    final owned = <Columns>[];
    try {

    final traceCoefs = coefsFor([
      for (int j = 0; j < nCols; j++) Uint32List.fromList([for (int k = 0; k < n; k++) rows[k][j]])
    ]);
    _lap('trace interpolation');
    final (traceEv, traceTree) = commit(traceCoefs);
    owned.add(traceEv);
    _lap('trace LDE + merkle');

    // preprocessed columns: public, unmasked, committed on the same domain
    // (cached per instance: the verifier knows this root)
    var preCoefs = <Uint32List>[];
    var preEv = Columns.empty;
    MerkleCommitment? preTree;
    if (air.numPreCols > 0) {
      final pc = PreCommitment.of(air, P, hash, kernels: kernels);
      // same coefficient length as the (masked) trace columns: zero-padding is the same polynomial
      preCoefs = [for (final c in pc.coefs) c.length == traceCoefs[0].length ? c : (Uint32List(traceCoefs[0].length)..setRange(0, c.length, c))];
      preEv = pc.ev;
      preTree = pc.tree;
      _lap('preprocessed columns');
    }

    final ts = hash.transcript();
    ts.absorbStatement(air.publicValues, preTree?.root ?? const []);
    ts.absorb(traceTree.root);

    // ---- interaction round: challenges, aux columns, aux commitment ----
    final chal = [for (int k = 0; k < air.numChallenges; k++) ts.squeezeQM31()];
    var auxCoefs = <Uint32List>[];
    var auxEv = Columns.empty;
    MerkleCommitment? auxTree;
    if (air.numAuxCols > 0) {
      final auxCols = _auxColumns(rows, chal, preEv.isEmpty ? const [] : air.preColumns());
      if (auxCols.length != air.numAuxCols) throw StateError('auxColumns returned ${auxCols.length} columns');
      auxCoefs = coefsFor(auxCols);
      (auxEv, auxTree) = commit(auxCoefs);
      owned.add(auxEv);
      ts.absorb(auxTree.root);
      _lap('aux round');
    }
    final allCoefs = [...traceCoefs, ...auxCoefs, ...preCoefs];
    final allEv = [traceEv, auxEv, preEv];
    final beta = ts.squeezeQM31();

    // ---- 2. composition on D_{t+e} (twin layout of HalfCoset(t+e-1)) ----
    final logC = t + P.logExpand, mC = 1 << (logC - 1), nC = 2 * mC;
    final domC = CosetTables.of(logC - 1);
    final shift = 1 << (logC - t); // p * g_t is a shift by 2^(logC-t) in cyclic order
    // periodic columns on D_{logC}: F_k on D_{logPeriod+logExpand}, index mod its size
    final logPC = air.logPeriod + P.logExpand;
    final perOnC = [for (final c in air.periodicCoefs) CircleFft.evaluate(c, logPC - 1)];
    // public columns: coefficients padded to the trace columns' length (the
    // same polynomial), extended like trace columns
    final coefLen = allCoefs[0].length;
    final pubCoefs = air.numPubCols == 0
        ? <Uint32List>[]
        : [
            for (final c in PreCommitment.twinCoefs(air.pubColumns(), t, kernels))
              c.length == coefLen ? c : (Uint32List(coefLen)..setRange(0, c.length, c))
          ];
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
    // when the composition domain is the commit domain (logExpand ==
    // logBlowup) the committed evaluations are the values the kernel needs
    final reuse = logC - 1 == P.logTraceHalf && pubCoefs.isEmpty;
    List<Uint32List>? compLimbs = reuse
        ? _nativeComposition(groups, groupPow, beta, chal, perOnC, linOnC, vInv, divInv, logC, logPC, shift, values: allEv)
        : _nativeComposition(groups, groupPow, beta, chal, perOnC, linOnC, vInv, divInv, logC, logPC, shift,
            coefs: [...allCoefs, ...pubCoefs], coefLen: coefLen);
    if (compLimbs != null) {
      final k = kernels;
      final split = k is StarkKernels ? k.compositionSplit : null;
      _lap('composition values (native${reuse ? '' : ', from coefficients'})'
          '${split == null ? '' : ' [extend ${split.$1.round()} + program ${split.$2.round()}]'}');
    } else {
      final traceOnC = kernels.evaluateColumns(allCoefs, logC - 1);
      final pubOnC = pubCoefs.isEmpty ? <Uint32List>[] : kernels.evaluateColumns(pubCoefs, logC - 1);
      _lap('trace on comp domain');
      compLimbs = _compositionInDart(groups, groupPow, beta, chal, traceOnC, pubOnC, perOnC, linOnC, vInv, divInv, logC, logPC, shift);
      _lap('composition values');
    }
    final compCoefs = kernels.interpolateColumns(compLimbs, logC - 1);
    // the coefficient blocks, 4 limb columns per block, committed on the trace domain
    final chunkLen = 1 << P.logTraceBound;
    final chunkCoefs = [
      for (int k = 0; k < P.compChunks; k++)
        for (int l = 0; l < 4; l++) compCoefs[l].sublist(k * chunkLen, (k + 1) * chunkLen)
    ];
    final (compEv, compTree) = kernels.commitColumns(chunkCoefs, P.logTraceHalf, hash);
    owned.add(compEv);
    _lap('composition LDE + merkle');

    ts.absorb(compTree.root);
    final tch = ts.squeezeQM31();
    final (zx, zy, zHint) = TranscriptRef.circlePoint(tch);

    // ---- 3. OODS values ----
    final zgx = zx.scale(gT.x) - zy.scale(gT.y);
    final zgy = zx.scale(gT.y) + zy.scale(gT.x);
    final traceAtZ = kernels.evalAt(allCoefs, zx, zy);
    final traceAtZg = kernels.evalAt(allCoefs, zgx, zgy);
    final compAtZ = kernels.evalAt(chunkCoefs, zx, zy);
    final rhs = air.compositionAt(
        traceAtZ, traceAtZg, air.pointColumnsAt(zx, zy), air.linearAt(zx, zy), beta, zx, chal: chal);
    if (P.compositionFromChunks(compAtZ, zx) != rhs) throw StateError('composition relation fails at z');
    ts.absorbLimbs([for (final v in [...traceAtZ, ...traceAtZg, ...compAtZ]) ...v.limbs]);
    final lamB = ts.squeezeQM31(), lamC = ts.squeezeQM31(), alC = ts.squeezeQM31();
    final dbg = <String, Object>{
      'beta': beta, 'tch': tch, 'zx': zx, 'zy': zy, 'zgx': zgx, 'zgy': zgy,
      'lamB': lamB, 'lamC': lamC, 'alC': alC,
      'probeOn': CircleFft.evalAt(traceCoefs[0], embed(CosetTables.of(t - 1).x[1]), embed(CosetTables.of(t - 1).y[1])),
      'probeOff': embed(traceEv.at(0, 3)),
    };
    _lap('oods');

    // ---- DEEP quotients (flat QM31 arrays, 4 limbs per position) ----
    // group B: every column opened at z (trace, aux, pre, then the
    // composition blocks); group C: the trace columns at z*g
    final kB = DeepQuotientRef.precompute(zx, zy, [...traceAtZ, ...compAtZ], lamB);
    final kC = DeepQuotientRef.precompute(zgx, zgy, traceAtZg, lamB, base: lamC);
    for (final (tag, k) in [('B', kB), ('C', kC)]) {
      dbg['c$tag'] = k.c; dbg['A$tag'] = k.A; dbg['B$tag'] = k.B;
      dbg['dA$tag'] = k.dA; dbg['dB$tag'] = k.dB; dbg['dC$tag'] = k.dC;
      dbg['w${tag}1'] = k.weights[1];
    }
    // both groups in one pass: group C reads the same trace, aux and
    // preprocessed columns as group B, which adds the composition blocks
    final qBC = kernels.deepQuotientsPair(kB, kC, [...allEv, compEv], P.logTraceHalf);
    final l0 = kernels.circleFold(qBC, P.logTraceHalf, alC);
    _lap('deep quotients + circle fold');

    // ---- 4. FRI line layers ----
    final a = P.logTraceHalf;
    final layers = <Uint32List>[l0];
    final trees = <MerkleCommitment>[];
    final alphas = <QM31>[];
    for (int l = 0; l < P.numLineFolds; l++) {
      final curL = layers[l];
      final logLen = a - l;
      final tree = kernels.merklePairs(curL, logLen, hash);
      trees.add(tree);
      ts.absorb(tree.root);
      final al = ts.squeezeQM31();
      alphas.add(al);
      dbg['al$l'] = al;
      final next = kernels.lineFold(curL, logLen, al);
      layers.add(next);
    }
    _lap('fri layers');

    // ---- 5. final polynomial (monomial in x), must be low degree ----
    final fin = layers.last;
    final finLen = fin.length ~/ 4;
    final finX = CosetTables.of(P.logFinal).x;
    final d = P.finalDegree;
    final vander = [
      for (int i = 0; i < d; i++)
        [for (int j = 0, xp = 1; j < d; j++, xp = CircleFft.mul(xp, finX[i])) embed(xp)]
    ];
    final finalCoefs = solveQ(vander, [for (int i = 0; i < d; i++) qAt(fin, i)]);
    for (int i = d; i < finLen; i++) {
      var acc = QM31.zero;
      for (int j = d - 1; j >= 0; j--) {
        acc = acc.scale(finX[i]) + finalCoefs[j];
      }
      if (acc != qAt(fin, i)) throw StateError('final layer is not low degree (mismatch at $i)');
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
      dbg['xB'] = domB.x[i]; dbg['yB'] = domB.y[i];
      dbg['circleOut'] = qAt(l0, i);
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        il = il % (layers[l].length ~/ 8);
        dbg['fold$l'] = qAt(layers[l + 1], il);
      }
      dbg['qTp'] = qAt(qBC, i); dbg['qTc'] = qAt(qBC, mB + i);
    }

    // ---- 6. openings ----
    List<int> leafOf(Columns c, int i) => [for (int j = 0; j < c.count; j++) c.at(j, i), for (int j = 0; j < c.count; j++) c.at(j, mB + i)];
    final queries = <QueryProof>[];
    for (final i in indices) {
      final lineF0 = <QM31>[], lineF1 = <QM31>[], linePaths = <List<List<int>>>[], lineXInv = <int>[];
      var il = i;
      for (int l = 0; l < P.numLineFolds; l++) {
        final half = layers[l].length ~/ 8;
        il = il % half;
        lineF0.add(qAt(layers[l], il));
        lineF1.add(qAt(layers[l], il + half));
        linePaths.add(trees[l].path(il));
        lineXInv.add(CosetTables.of(a - l).xInv[il]);
      }
      final iB = i;
      final pBx = domB.x[iB], pBy = domB.y[iB];
      queries.add(QueryProof(
        index: i,
        compLeaf: leafOf(compEv, iB),
        compPath: compTree.path(iB),
        lineF0: lineF0, lineF1: lineF1, linePaths: linePaths, lineXInv: lineXInv,
        traceLeaf: leafOf(traceEv, iB),
        tracePath: traceTree.path(iB),
        auxLeaf: leafOf(auxEv, iB),
        auxPath: auxTree?.path(iB) ?? const [],
        preLeaf: leafOf(preEv, iB),
        prePath: preTree?.path(iB) ?? const [],
        yBInv: domB.yInv[iB],
        dBInvP: DeepQuotientRef.denominator(kB, pBx, pBy).inv,
        dBInvC: DeepQuotientRef.denominator(kB, pBx, M31.neg(pBy)).inv,
        dCInvP: DeepQuotientRef.denominator(kC, pBx, pBy).inv,
        dCInvC: DeepQuotientRef.denominator(kC, pBx, M31.neg(pBy)).inv,
      ));
    }
    _lap('openings');
    final proof = StarkProof(
      traceRoot: traceTree.root, compRoot: compTree.root, auxRoot: auxTree?.root ?? const [],
      preRoot: preTree?.root ?? const [], zHint: zHint,
      traceAtZ: traceAtZ, traceAtZg: traceAtZg, compAtZ: compAtZ,
      friRoots: trees.map((t) => t.root).toList(), finalCoefs: finalCoefs, nonce: nonce, queries: queries,
    );
    proof.debug.addAll(dbg);
    return proof;
    } finally {
      for (final c in owned) {
        c.release();
      }
    }
  }

  /// The aux columns: from the AIR's LogUp program on the native kernels
  /// when it has one, else the AIR's own [Air.auxColumns].
  List<Uint32List> _auxColumns(List<List<int>> rows, List<QM31> chal, List<Uint32List> pre) {
    final spec = air.logUpSpec();
    if (spec != null && kernels is! DartKernels) {
      final r = kernels.logUpColumns(spec, rows, pre, chal, air.numAuxCols);
      if (r != null) {
        final (cols, total) = r;
        if (total != QM31.zero) throw StateError('bus does not balance: $total');
        return cols;
      }
    }
    return air.auxColumns(rows, chal);
  }

  /// The composition values row by row in Dart: the AIR's base-field
  /// constraints and QM31 aux constraints, Horner-combined per group and
  /// divided by the group's divisor.
  List<Uint32List> _compositionInDart(
      List<ConstraintGroup> groups,
      List<QM31> groupPow,
      QM31 beta,
      List<QM31> chal,
      List<Uint32List> traceOnC,
      List<Uint32List> pubOnC,
      List<Uint32List> perOnC,
      List<Uint32List> linOnC,
      Uint32List vInv,
      Map<int, Uint32List> divInv,
      int logC,
      int logPC,
      int shift) {
    final mC = 1 << (logC - 1), nC = 2 * mC, nAll = traceOnC.length;
    final compLimbs = List.generate(4, (_) => Uint32List(nC));
    final cur = Uint32List(nAll), nxt = Uint32List(nAll), per = Uint32List(air.numPointCols);
    final nPer = air.numPeriodic;
    final lin = Uint32List(linOnC.length);
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
      for (int k = 0; k < nPer; k++) {
        per[k] = perOnC[k][qp];
      }
      for (int j = 0; j < pubOnC.length; j++) {
        per[nPer + j] = pubOnC[j][q];
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
    return compLimbs;
  }

  /// The same values from the AIR's recorded programs on the native
  /// kernels, or null when they are unavailable (Dart kernels, an AIR
  /// without generic constraints, or a program the kernel cannot run).
  /// The column values are [values] (on the composition domain) or the
  /// coefficient columns [coefs] of [coefLen] words that the kernel
  /// evaluates itself.
  List<Uint32List>? _nativeComposition(
      List<ConstraintGroup> groups,
      List<QM31> groupPow,
      QM31 beta,
      List<QM31> chal,
      List<Uint32List> perOnC,
      List<Uint32List> linOnC,
      Uint32List vInv,
      Map<int, Uint32List> divInv,
      int logC,
      int logPC,
      int shift,
      {List<Uint32List> coefs = const [],
      int coefLen = 0,
      List<Columns> values = const []}) {
    if (kernels is DartKernels) return null;
    final main = air.mainProgram();
    if (main == null || !CompositionJob.baseOnly(main)) return null;
    final aux = air.auxProgram();
    if (air.numAuxConstraints > 0 && aux == null) return null;
    if (main.outputs.length != air.numConstraints || (aux?.outputs.length ?? 0) != air.numAuxConstraints) return null;
    final nValues = coefLen > 0 ? coefs.length : values.fold(0, (n, c) => n + c.count);
    final nAll = nValues - air.numPubCols, nPer = perOnC.length;
    final mainSrc = CompositionJob.resolve(main, nAll, nPer, air.publicValues);
    final auxSrc = aux == null ? Uint32List(0) : CompositionJob.resolve(aux, nAll, nPer, air.publicValues);
    if (mainSrc == null || auxSrc == null) return null;
    final mC = 1 << (logC - 1), nC = 2 * mC;
    final idxNext = Uint32List(nC), idxPer = Uint32List(nC);
    final vInvFull = Uint32List(nC);
    for (int q = 0; q < nC; q++) {
      final cyc = CircleFft.cyclicIndex(logC, q);
      idxNext[q] = CircleFft.twinIndex(logC, (cyc + shift) & (nC - 1));
      idxPer[q] = CircleFft.twinIndex(logPC, cyc & ((1 << logPC) - 1));
      vInvFull[q] = vInv[q < mC ? q : q - mC];
    }
    final divs = <Uint32List>[vInvFull];
    final divIndex = <int, int>{};
    for (final d in divInv.keys) {
      divIndex[d] = divs.length;
      divs.add(divInv[d]!);
    }
    final weights = <QM31>[];
    final divSel = <int>[];
    for (int g = 0; g < groups.length; g++) {
      var w = groupPow[g];
      for (int k = 0; k < groups[g].count; k++) {
        weights.add(w);
        divSel.add(groups[g].divisor < 0 ? 0 : divIndex[groups[g].divisor]!);
        w = w * beta;
      }
    }
    final result = kernels.composition(CompositionJob(
      main: main,
      aux: aux,
      mainSrc: mainSrc,
      auxSrc: auxSrc,
      cols: coefs,
      coefLen: coefLen,
      values: values,
      per: perOnC,
      lin: linOnC,
      divs: divs,
      logC: logC,
      logPC: logPC,
      idxNext: idxNext,
      idxPer: idxPer,
      chal: chal,
      weights: weights,
      divSel: Uint32List.fromList(divSel),
    ));
    return result;
  }
}

/// The commitment of an AIR's preprocessed columns under given parameters
/// and hash: coefficients, evaluations and tree, computed once per
/// instance (the prover needs all three, the verifier only the root).
class PreCommitment {
  final List<Uint32List> coefs;
  final Columns ev;
  final MerkleCommitment tree;
  PreCommitment(this.coefs, this.ev, this.tree);

  /// The most recent commitments, keyed by the columns' identity (see
  /// [Air.preColumnsIdentity]) and the domain. An entry is gigabytes (4.4 GB
  /// for the narrowing level at 2^20 and blowup 32), and a proof needs one
  /// at a time, so the cache is deliberately small: a level's nodes share a
  /// program and therefore a key, so one entry already spares every node
  /// after the first, and the second is slack across a level boundary.
  static final Map<String, PreCommitment> _cache = {};
  static const cacheEntries = 2;

  /// The roots alone, by the same key and never evicted. A root is 8 lanes;
  /// remembering one costs nothing and spares the caller the commitment
  /// behind it.
  static final Map<String, List<int>> _roots = {};

  static String _key(Air air, StarkParams P, ProofHash hash) =>
      '${identityHashCode(air.preColumnsIdentity)}:${P.logTrace}:${P.logTraceHalf}:${hash.name}';

  static PreCommitment _build(Air air, StarkParams P, ProofHash hash, ProverKernels? kernels) {
    final k = kernels ?? ProverKernels.best;
    final cols = air.preColumns();
    if (cols.length != air.numPreCols) throw StateError('preColumns returned ${cols.length} columns');
    final coefs = twinCoefs(cols, P.logTrace, k);
    final (ev, tree) = k.commitColumns(coefs, P.logTraceHalf, hash);
    return PreCommitment(coefs, ev, tree);
  }

  static PreCommitment of(Air air, StarkParams P, ProofHash hash, {ProverKernels? kernels}) {
    final key = _key(air, P, hash);
    final hit = _cache.remove(key);
    if (hit != null) return _cache[key] = hit; // re-insert: most recent last
    final made = _build(air, P, hash, kernels);
    while (_cache.length >= cacheEntries) {
      _cache.remove(_cache.keys.first)?.ev.release();
    }
    _roots[key] = made.tree.root;
    return _cache[key] = made;
  }

  /// How many commitments the cache is holding. A coordinator between rounds
  /// should see zero: see [releaseCached].
  static int get cachedCount => _cache.length;

  /// Release every cached commitment, keeping the roots.
  ///
  /// A running coordinator calls this when a round is done. The columns and
  /// tree of a level are gigabytes and are needed only while that level is
  /// proving, but the roots are needed whenever a statement digest is
  /// derived, which is throughout. Dropping the commitments and keeping the
  /// roots is what lets an idle coordinator hold nothing.
  static void releaseCached() {
    for (final c in _cache.values) {
      c.ev.release();
    }
    _cache.clear();
  }

  /// Coefficients of columns given in cyclic row order on the trace domain.
  static List<Uint32List> twinCoefs(List<Uint32List> cols, int t, ProverKernels k) {
    final n = 1 << t;
    final twin = <Uint32List>[];
    for (final col in cols) {
      if (col.length != n) throw StateError('column has ${col.length} rows, trace $n');
      final vals = Uint32List(n);
      for (int r = 0; r < n; r++) {
        vals[CircleFft.twinIndex(t, r)] = col[r];
      }
      twin.add(vals);
    }
    return k.interpolateColumns(twin, t - 1);
  }

  /// The root the verifier expects for [air].
  ///
  /// Unlike [of] this does not retain the commitment it may have to build.
  /// An aggregation needs every level's root before it can compile the root
  /// program, but the levels are proved one after another and no two of
  /// their column sets are ever live at once; holding all five was 14.5 GB
  /// of a round's 30.3 GB peak. Each level rebuilds its own when it starts,
  /// which is one extra pass per level and worth the memory.
  static List<int> root(Air air, StarkParams P, ProofHash hash) {
    final key = _key(air, P, hash);
    final known = _roots[key] ?? _cache[key]?.tree.root;
    if (known != null) return _roots[key] = known;
    final made = _build(air, P, hash, null);
    final r = made.tree.root;
    made.ev.release();
    return _roots[key] = r;
  }
}
