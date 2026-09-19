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
import '../crypto/circle_fft.dart';
import '../crypto/m31.dart';
import 'air_ring.dart';
import 'm31_script_gen.dart';
import 'deep_quotient_script_gen.dart' show limbNames;
import 'air_ood_script_gen.dart' show AirOodScriptGen;

/// A linear form alpha*x + gamma*y on the circle.
///
/// A line meets the circle in two points, so the cheapest non-trivial public
/// structure a constraint can use is a form that distinguishes a *half-turn
/// pair* of rows: cyclic rows r and r + 2^(logTrace-1) of the trace domain,
/// whose points are p and -p. Evaluating one costs two multiplications by a
/// constant, at the out-of-domain point and on the composition domain alike.
class LinearForm {
  final int alpha, gamma;
  const LinearForm(this.alpha, this.gamma);

  /// Vanishes exactly at [p] and -p: p.x*y - p.y*x.
  factory LinearForm.vanishingAt(CirclePoint p) => LinearForm(M31.neg(p.y), p.x);

  /// +1 at [p] and -1 at -p: p.x*x + p.y*y (using x^2 + y^2 = 1).
  factory LinearForm.selectorAt(CirclePoint p) => LinearForm(p.x, p.y);

  int atM31(int x, int y) => M31.add(M31.mul(alpha, x), M31.mul(gamma, y));
  QM31 at(QM31 x, QM31 y) => x.scale(alpha) + y.scale(gamma);
}

/// A run of consecutive constraints sharing a divisor.
class ConstraintGroup {
  final int count;

  /// -1: the constraints vanish on every row and are divided by the trace
  /// vanishing polynomial v_t. Otherwise an index into [Air.linearForms]:
  /// the constraints are enforced only at the half-turn pair of rows where
  /// that form vanishes, and are divided by it.
  final int divisor;
  const ConstraintGroup(this.count, {this.divisor = -1});
}

/// An algebraic intermediate representation the STARK prover and the
/// in-script verifier share.
///
/// A trace has [numCols] committed (and zero-knowledge masked) columns and a
/// set of *periodic* columns: public, fixed columns whose values repeat every
/// 2^[logPeriod] rows. They carry selectors and round constants. Because a
/// periodic column of period 2^k is F(phi^(t-k)(p)) for the degree-<2^k circle
/// interpolant F of its 2^k values and the doubling map phi, the verifier
/// evaluates it at the out-of-domain point from 2^k baked-in coefficients,
/// with no commitment and no per-query openings.
///
/// Constraints are polynomials in (current row, next row, periodic values,
/// [linearForms] values). Those in a [ConstraintGroup] with divisor -1 must
/// vanish on every row; those with a linear-form divisor must vanish at that
/// form's two rows, which is how public inputs are bound to trace cells and
/// how a transition is excepted at chosen rows. The composition is
///   comp = sum_g beta^(lo_g) * (sum_k beta^k C_(lo_g+k)) / d_g.
abstract class Air {
  int get logTrace;
  int get numCols;
  int get numConstraints;
  int get logPeriod;

  /// Periodic column values, each list of length 2^logPeriod in row order.
  List<List<int>> get periodic;

  /// Linear forms evaluated at the constraint point and handed to the
  /// constraint functions; also usable as group divisors.
  List<LinearForm> get linearForms => const [];

  /// Public inputs: M31 values supplied by the spender at the bottom of the
  /// unlocking script and absorbed into the transcript before anything else,
  /// so one locking script serves every instance. In script they are single
  /// limbs named [publicName]; the prover and the concrete constraint paths
  /// read [publicValues].
  int get numPublics => 0;
  List<int> get publicValues => const [];
  static String publicName(int k) => 'pub$k';

  /// Constraint groups in constraint order; counts must sum to
  /// [numConstraints].
  List<ConstraintGroup> get groups => [ConstraintGroup(numConstraints)];

  /// Constraint values over QM31 (the executable spec). By default the
  /// generic formulation [constraintsG] evaluated over [QM31Ring].
  List<QM31> constraints(List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin) =>
      constraintsG(QM31Ring.instance, cur, next, per, lin);

  /// The constraints written once against a [Ring], so the same code yields
  /// values (over QM31) or a [Program] (over [ExprRing]) for a verifier that
  /// runs inside another circuit. AIRs that only provide [constraints]
  /// cannot be verified recursively.
  List<T> constraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin) =>
      throw UnimplementedError('$runtimeType has no generic constraints');

  /// Base-field fast path for the prover: fills [out] (numConstraints).
  void constraintsM31(Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, Uint32List out);

  /// Script: from named limbs [cur], [next], [per], [lin] (all consumed)
  /// leave the constraint values as canonical limbs named [out][j].
  void emitConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next,
      List<List<String>> per, List<List<String>> lin, List<List<String>> out);

  // ---------------------------------------------------------------- interaction round
  //
  // An AIR may ask for a second commitment round: after the trace root is
  // absorbed the transcript yields [numChallenges] QM31 challenges, the AIR
  // derives [numAuxCols] further columns from the trace and the challenges
  // ([auxColumns]), and those are committed in a second tree before beta is
  // drawn. Aux columns are opened and masked exactly like trace columns and
  // occupy indices numCols.. in every cur/next list; the [numAuxConstraints]
  // aux constraints are QM31-valued, form one more group divided by v_t at
  // the end of the constraint order, and may use the challenges. This is
  // what makes a random-linear-combination accumulator possible, which is
  // the only affordable way to bind cells that no local constraint reaches.

  int get numChallenges => 0;
  int get numAuxCols => 0;
  int get numAuxConstraints => 0;

  // ---------------------------------------------------------------- preprocessed columns
  //
  // Fixed public columns of the circuit instance (a verifier AIR's program),
  // committed once on the trace domain; the verifier knows the root. They
  // are opened and evaluated out of domain like trace columns and occupy
  // the indices after the aux columns in every cur/next list.

  int get numPreCols => 0;

  /// The preprocessed column values (numPreCols columns of 2^logTrace rows).
  List<Uint32List> preColumns() => const [];

  int get totalCols => numCols + numAuxCols + numPreCols;

  // ---------------------------------------------------------------- public columns
  //
  // A wide statement: columns of public values the verifier knows but that
  // are not committed. The prover extends them like trace columns; the
  // verifier evaluates them out of domain in closed form from the public
  // inputs (with inverse hints in script). Their values follow the
  // periodic values in the `per` list of the constraint functions.

  int get numPubCols => 0;

  /// The public column values on the trace domain (cyclic row order).
  List<Uint32List> pubColumns() => const [];

  /// The public columns at an out-of-domain point.
  List<QM31> pubColumnsAt(QM31 zx, QM31 zy) => const [];

  /// Generic form; only the QM31 ring can invert, so wide statements are
  /// verified by the reference verifier and in script, not recursively.
  List<T> pubColumnsAtG<T>(Ring<T> f, T zx, T zy) =>
      numPubCols == 0 ? const [] : throw UnsupportedError('$runtimeType: public columns need the QM31 ring');

  /// QM31 hints the script needs for [emitPubColumns] (inverses), and
  /// their values at the point.
  int get numPubHints => 0;
  List<QM31> pubHints(QM31 zx, QM31 zy) => const [];

  /// Script: from the named limbs [zx], [zy], the vanishing value [v] (all
  /// picked), the hint limbs [hints] (consumed) and the publics `pub{k}`
  /// (picked), leave canonical limbs [out] (numPubCols entries).
  void emitPubColumns(StackEmitter e, List<String> zx, List<String> zy, List<String> v, List<List<String>> hints,
      List<List<String>> out) {}

  /// Periodic then public column values at a point: the `per` list.
  int get numPointCols => numPeriodic + numPubCols;
  List<QM31> pointColumnsAt(QM31 x, QM31 y) => [...periodicAt(x, y), ...pubColumnsAt(x, y)];
  int get preCol0 => numCols + numAuxCols;
  int get totalConstraints => numConstraints + numAuxConstraints;

  /// The aux column values (numAuxCols columns of 2^logTrace rows) for the
  /// trace [rows] under the challenges [chal].
  List<Uint32List> auxColumns(List<List<int>> rows, List<QM31> chal) => const [];

  /// QM31 spec of the aux constraints; [cur] and [next] have [totalCols]
  /// entries. A QM31-valued aux column is four base columns whose values at a
  /// point compose as [composeLimbs].
  List<QM31> auxConstraints(List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin, List<QM31> chal) =>
      numAuxConstraints == 0 ? const [] : auxConstraintsG(QM31Ring.instance, cur, next, per, lin, chal);

  /// Generic form of [auxConstraints] (see [constraintsG]).
  List<T> auxConstraintsG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> per, List<T> lin, List<T> chal) =>
      numAuxConstraints == 0 ? const [] : throw UnimplementedError('$runtimeType has no generic aux constraints');

  /// Base-field fast path: [cur]/[next] hold [totalCols] M31 values, [out]
  /// receives [numAuxConstraints] QM31 values.
  void auxConstraintsM31(
      Uint32List cur, Uint32List next, Uint32List per, Uint32List lin, List<QM31> chal, List<QM31> out) {}

  /// Script side of the aux constraints. Runs BEFORE [emitConstraints] and
  /// must only pick [cur], [next], [per] and [lin] (the base emitter consumes
  /// them afterwards); it consumes [chal] and leaves canonical limbs [out].
  void emitAuxConstraints(StackEmitter e, List<List<String>> cur, List<List<String>> next, List<List<String>> per,
      List<List<String>> lin, List<List<String>> chal, List<List<String>> out) {}

  /// c0 + c1 i + c2 u + c3 iu: a QM31 whose four limbs were committed as
  /// separate base-field columns, evaluated at a QM31 point.
  static QM31 composeLimbs(List<QM31> c) => c[0] + c[1] * QM31.i + c[2] * QM31.u + c[3] * QM31.i * QM31.u;

  /// All constraint groups: [groups], then the aux group when there is one.
  List<ConstraintGroup> get allGroups =>
      [...groups, if (numAuxConstraints > 0) ConstraintGroup(numAuxConstraints)];

  // ---------------------------------------------------------------- provided

  int get period => 1 << logPeriod;
  int get numPeriodic => periodic.length;
  int get numLinear => linearForms.length;

  int periodicValue(int col, int row) => periodic[col][row & (period - 1)];

  /// Trace-domain point of cyclic row [r]: h*g^r with h = gen(logTrace+1) and
  /// g = gen(logTrace), matching `circleDomain(logTrace)`. Row r + 2^(t-1) is
  /// its half-turn -p.
  CirclePoint rowPoint(int r) =>
      CirclePoint.subgroupGen(logTrace + 1) * CirclePoint.subgroupGen(logTrace).pow(r);

  List<Uint32List>? _periodicCoefs;

  /// Circle-FFT coefficients (natural order, 2^logPeriod each) of the
  /// periodic columns' interpolants on the size-2^logPeriod circle domain.
  List<Uint32List> get periodicCoefs => _periodicCoefs ??= [
        for (final col in periodic)
          CircleFft.interpolate(
              Uint32List.fromList(List.generate(period, (tw) => col[CircleFft.cyclicIndex(logPeriod, tw)])),
              logPeriod - 1)
      ];

  /// Periodic column values at an arbitrary point of the trace domain's
  /// ambient space: F_k(phi^(logTrace-logPeriod)(x, y)).
  List<QM31> periodicAt(QM31 x, QM31 y) {
    var px = x, py = y;
    for (int i = 0; i < logTrace - logPeriod; i++) {
      final nx = px * px + px * px - QM31.one;
      py = (px * py) + (px * py);
      px = nx;
    }
    return [for (final c in periodicCoefs) CircleFft.evalAt(c, px, py)];
  }

  List<QM31> linearAt(QM31 x, QM31 y) => [for (final f in linearForms) f.at(x, y)];

  /// comp at a point: the grouped, divided combination of the constraints.
  /// [zx] supplies the trace vanishing polynomial for divisor -1 groups.
  QM31 compositionAt(
      List<QM31> cur, List<QM31> next, List<QM31> per, List<QM31> lin, QM31 beta, QM31 zx,
      {List<QM31> chal = const []}) {
    final cs = [...constraints(cur, next, per, lin), ...auxConstraints(cur, next, per, lin, chal)];
    final vInv = vanishing(zx).inv;
    var total = QM31.zero, bp = QM31.one;
    int lo = 0;
    for (final g in allGroups) {
      var acc = QM31.zero;
      for (int k = g.count - 1; k >= 0; k--) {
        acc = acc * beta + cs[lo + k];
      }
      total = total + bp * acc * (g.divisor < 0 ? vInv : lin[g.divisor].inv);
      for (int k = 0; k < g.count; k++) {
        bp = bp * beta;
      }
      lo += g.count;
    }
    return total;
  }

  // ---------------------------------------------------------------- generic evaluation

  /// The doubling chain from (x, y): x_i = π^i(x); returns (x_0..x_{n},
  /// y_d) with d = logTrace - logPeriod, as the periodic evaluation needs.
  (List<T>, T) doublingChainG<T>(Ring<T> f, T x, T y) {
    final d = logTrace - logPeriod;
    final xs = <T>[x];
    var py = y;
    for (int i = 0; i < logTrace - 1; i++) {
      final xi = xs[i];
      if (i < d) {
        final xy = f.mul(xi, py);
        py = f.add(xy, xy);
      }
      final x2 = f.mul(xi, xi);
      xs.add(f.sub(f.add(x2, x2), f.one));
    }
    return (xs, py);
  }

  /// `CircleFft.evalAt` over a ring: an M31 coefficient vector at (x, y).
  static T evalCoefsG<T>(Ring<T> f, List<int> coefs, T x, T y) {
    final n = CircleFft.log2(coefs.length);
    if (n == 0) return f.constM31(coefs[0]);
    var v = List<T>.generate(coefs.length >> 1, (j) => f.add(f.constM31(coefs[2 * j]), f.scale(y, coefs[2 * j + 1])));
    var tw = x;
    for (int k = 1; k < n; k++) {
      final t = tw;
      v = List<T>.generate(v.length >> 1, (j) => f.add(v[2 * j], f.mul(t, v[2 * j + 1])));
      final t2 = f.mul(tw, tw);
      tw = f.sub(f.add(t2, t2), f.one);
    }
    return v[0];
  }

  /// [periodicAt] over a ring, given the doubling chain.
  List<T> periodicAtG<T>(Ring<T> f, List<T> xs, T yd) {
    final d = logTrace - logPeriod;
    return [for (final c in periodicCoefs) evalCoefsG(f, c, xs[d], yd)];
  }

  List<T> linearAtG<T>(Ring<T> f, T x, T y) => [for (final lf in linearForms) f.linear([x, y], [lf.alpha, lf.gamma])];

  /// The out-of-domain check with denominators cleared, exactly as the
  /// script does it (`AirScriptGen.emitOodsCheck`): returns
  ///   compose(comp) · v · Lall  −  (Lall · main + v · Σ_d S_d · Lskip_d)
  /// which is zero iff `compose(comp) == compositionAt(...)` (divisors are
  /// nonzero off the trace domain). Every constraint keeps its global power
  /// of beta, as soundness requires.
  T oodCheckG<T>(Ring<T> f, List<T> cur, List<T> next, List<T> comp, T beta, T zx, T zy, {List<T> chal = const []}) {
    final lin = linearAtG(f, zx, zy);
    final (xs, yd) = doublingChainG(f, zx, zy);
    final per = [...periodicAtG(f, xs, yd), ...pubColumnsAtG(f, zx, zy)];
    final v = xs[logTrace - 1];
    final cs = [...constraintsG(f, cur, next, per, lin), ...auxConstraintsG(f, cur, next, per, lin, chal)];
    final groups = allGroups;
    final divs = <int>[];
    for (final g in groups) {
      if (g.divisor >= 0 && !divs.contains(g.divisor)) divs.add(g.divisor);
    }
    // per-group Horner weighted by beta^{lo}
    T? main;
    final byDiv = <int, T>{};
    var lo = 0;
    var bp = f.one;
    for (final g in groups) {
      var h = f.horner(cs.sublist(lo, lo + g.count), beta);
      if (lo > 0) h = f.mul(h, bp);
      if (g.divisor < 0) {
        main = main == null ? h : f.add(main, h);
      } else {
        byDiv[g.divisor] = byDiv.containsKey(g.divisor) ? f.add(byDiv[g.divisor]!, h) : h;
      }
      for (int k = 0; k < g.count; k++) {
        bp = f.mul(bp, beta);
      }
      lo += g.count;
    }
    final mainV = main ?? f.zero;
    T rhs;
    T? lall;
    if (divs.isEmpty) {
      rhs = mainV;
    } else {
      var l = lin[divs[0]];
      for (int i = 1; i < divs.length; i++) {
        l = f.mul(l, lin[divs[i]]);
      }
      lall = l;
      rhs = f.mul(l, mainV);
      for (final d in divs) {
        T? skip;
        for (final e in divs) {
          if (e == d) continue;
          skip = skip == null ? lin[e] : f.mul(skip, lin[e]);
        }
        final term = skip == null ? byDiv[d]! : f.mul(byDiv[d]!, skip);
        rhs = f.add(rhs, f.mul(v, term));
      }
    }
    var lhs = f.mul(f.composeLimbs(comp), v);
    if (lall != null) lhs = f.mul(lhs, lall);
    return f.sub(lhs, rhs);
  }

  /// Sanity check on the group declaration; call once from a test.
  void validateGroups() {
    var n = 0;
    for (final g in allGroups) {
      if (g.count <= 0) throw StateError('empty constraint group');
      if (g.divisor >= numLinear) throw StateError('group divisor ${g.divisor} has no linear form');
      n += g.count;
    }
    if (n != totalConstraints) throw StateError('groups cover $n of $totalConstraints constraints');
    if (numAuxCols > 0 && numChallenges == 0) throw StateError('aux columns need at least one challenge');
  }

  /// v_t(x) = pi^(logTrace-1)(x).
  QM31 vanishing(QM31 zx) {
    var x = zx;
    for (int i = 0; i < logTrace - 1; i++) {
      x = x * x + x * x - QM31.one;
    }
    return x;
  }

  int vanishingM31(int x) {
    var v = x;
    for (int i = 0; i < logTrace - 1; i++) {
      v = CircleFft.sub(CircleFft.mul(2, CircleFft.mul(v, v)), 1);
    }
    return v;
  }
}

/// Generic script side of [Air]: periodic column evaluation, linear forms and
/// the out-of-domain constraint check.
class AirScriptGen {
  static void _copy(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.pick(src[k], as: dst[k]);
    }
  }

  static void _dropQ(StackEmitter e, List<String> q) {
    for (final l in q) {
      e.dropNamed(l);
    }
  }

  static void _rename(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.rename(src[k], dst[k]);
    }
  }

  /// out = a * b for canonical named a, b (both consumed).
  static void _mul(StackEmitter e, List<String> a, List<String> b, List<String> out) =>
      M31Ops.qm31Mul(e, a, b, out);

  /// Linear form values at (zx, zy). Picks zx, zy.
  static void emitLinearForms(
      StackEmitter e, Air air, List<String> zx, List<String> zy, List<List<String>> out) {
    for (int k = 0; k < air.numLinear; k++) {
      final f = air.linearForms[k];
      for (int l = 0; l < 4; l++) {
        var terms = 0;
        if (f.alpha != 0) {
          e.pick(zx[l]);
          if (f.alpha != 1) e.mulConst(f.alpha);
          terms++;
        }
        if (f.gamma != 0) {
          e.pick(zy[l]);
          if (f.gamma != 1) e.mulConst(f.gamma);
          if (terms > 0) e.add();
          terms++;
        }
        if (terms == 0) {
          e.pushConst(0);
        } else {
          e.reduce();
        }
        e.nameTop(out[k][l]);
      }
    }
  }

  /// Doubling chain from (zx, zy): leaves x_i named `_dx$i` for i in
  /// [0, logTrace) and y_d named `_dy` with d = logTrace - logPeriod. Picks
  /// zx, zy. x_{logTrace-1} is the vanishing value v_t(zx).
  static void emitDoublingChain(StackEmitter e, List<String> zx, List<String> zy, int logTrace, int logPeriod) {
    final d = logTrace - logPeriod;
    _copy(e, zx, limbNames('_dx0'));
    _copy(e, zy, limbNames('_dy'));
    for (int i = 0; i < logTrace - 1; i++) {
      final x = limbNames('_dx$i');
      if (i < d) {
        // y_{i+1} = 2 x_i y_i
        _copy(e, x, limbNames('_dxa'));
        M31Ops.qm31Mul(e, limbNames('_dxa'), limbNames('_dy'), limbNames('_dxy'), reduceOut: false);
        for (int k = 0; k < 4; k++) {
          e.roll('_dxy_$k');
          e.dup();
          e.add();
          e.reduce();
          e.nameTop('_dy_$k');
        }
      }
      // x_{i+1} = 2 x_i² - 1
      _copy(e, x, limbNames('_dxa'));
      _copy(e, x, limbNames('_dxb'));
      M31Ops.qm31Mul(e, limbNames('_dxa'), limbNames('_dxb'), limbNames('_dx2'), reduceOut: false);
      for (int k = 0; k < 4; k++) {
        e.roll('_dx2_$k');
        e.dup();
        e.add();
        if (k == 0) {
          e.pushConst(1);
          e.sub();
        }
        e.reduce();
        e.nameTop('_dx${i + 1}_$k');
      }
    }
  }

  /// Periodic column values at z from the doubling chain: basis
  /// B_i = y_d^{b0} x_d^{b1} x_{d+1}^{b2} ... (2^logPeriod values), then
  /// per_k = Σ_i coef_{k,i} B_i. Consumes `_dy` and `_dx{d..logTrace-2}`;
  /// leaves `_dx{logTrace-1}` (the vanishing value) and the outputs.
  static void emitPeriodic(StackEmitter e, Air air, List<List<String>> out) {
    final t = air.logTrace, k = air.logPeriod, d = t - k;
    final n = 1 << k;
    final tw = <List<String>>[limbNames('_dy'), for (int i = 0; i < k; i++) limbNames('_dx${d + i}')];
    // basis
    e.pushConst(1, as: '_B0_0');
    e.pushConst(0, as: '_B0_1');
    e.pushConst(0, as: '_B0_2');
    e.pushConst(0, as: '_B0_3');
    for (int b = 0; b < k; b++) {
      final step = 1 << b;
      for (int i = 0; i < step; i++) {
        final dst = limbNames('_B${i + step}');
        if (i == 0) {
          _copy(e, tw[b], dst);
        } else {
          _copy(e, limbNames('_B$i'), limbNames('_Ba'));
          _copy(e, tw[b], limbNames('_Bb'));
          M31Ops.qm31Mul(e, limbNames('_Ba'), limbNames('_Bb'), dst);
        }
      }
    }
    // drop the chain except x_{t-1}, the vanishing value
    for (int b = 0; b < tw.length - 1; b++) {
      _dropQ(e, tw[b]);
    }
    for (int i = 0; i < d; i++) {
      _dropQ(e, limbNames('_dx$i'));
    }
    // columns
    final coefs = air.periodicCoefs;
    for (int c = 0; c < coefs.length; c++) {
      for (int l = 0; l < 4; l++) {
        var terms = 0;
        for (int i = 0; i < n; i++) {
          final cf = coefs[c][i];
          if (cf == 0) continue;
          e.pick('_B${i}_$l');
          if (cf != 1) e.mulConst(cf);
          if (terms > 0) e.add();
          terms++;
        }
        if (terms == 0) {
          e.pushConst(0);
        } else {
          e.reduce();
        }
        e.nameTop(out[c][l]);
      }
    }
    for (int i = 0; i < n; i++) {
      _dropQ(e, limbNames('_B$i'));
    }
  }

  /// acc = Σ_j β^j c_j by Horner from the top. Consumes [c]; picks beta.
  static void emitHorner(StackEmitter e, List<List<String>> c, List<String> beta, List<String> out) {
    final acc = limbNames('_hacc');
    final top = c.length - 1;
    for (int k = 0; k < 4; k++) {
      e.rename(c[top][k], acc[k]);
    }
    for (int j = top - 1; j >= 0; j--) {
      _copy(e, beta, limbNames('_hbeta'));
      M31Ops.qm31Mul(e, acc, limbNames('_hbeta'), limbNames('_haccb'), reduceOut: false);
      for (int k = 0; k < 4; k++) {
        e.roll('_haccb_$k');
        e.roll(c[j][k]);
        e.add();
        e.reduce();
        e.nameTop(acc[k]);
      }
    }
    for (int k = 0; k < 4; k++) {
      e.rename(acc[k], out[k]);
    }
  }

  /// Full OODS check: comp(z) = Σ_g β^{lo_g} H_g / d_g(z), cleared of
  /// denominators by multiplying through by v_t(z) and the product of the
  /// distinct linear-form divisors. Expects named limbs cur{j}, next{j}
  /// (j < totalCols), comp{k} (k < 4), chal{k} (k < numChallenges), beta,
  /// zx, zy; consumes all of them.
  ///
  /// SOUNDNESS: every constraint must keep its global power of β (group g's
  /// Horner is weighted by β^{lo_g}). At a pinned row both v_t and the
  /// group's form vanish, and a main violation could cancel a boundary
  /// violation there unless the two are separated by distinct β exponents.
  /// Restarting the Horner at β^0 per group would break this silently.
  static void emitOodsCheck(StackEmitter e, Air air) {
    final cur = List.generate(air.totalCols, (j) => limbNames('cur$j'));
    final next = List.generate(air.totalCols, (j) => limbNames('next$j'));
    final comp = List.generate(4, (k) => limbNames('comp$k'));
    final per = List.generate(air.numPointCols, (k) => limbNames('per$k'));
    final lin = List.generate(air.numLinear, (k) => limbNames('lin$k'));
    final chal = List.generate(air.numChallenges, (k) => limbNames('chal$k'));
    final cons = List.generate(air.totalConstraints, (j) => limbNames('c$j'));
    final groups = air.allGroups;

    // distinct divisors, in first-use order
    final divs = <int>[];
    for (final g in groups) {
      if (g.divisor >= 0 && !divs.contains(g.divisor)) divs.add(g.divisor);
    }

    emitLinearForms(e, air, limbNames('zx'), limbNames('zy'), lin);
    // keep a copy of each divisor form; emitConstraints consumes `lin`
    for (final d in divs) {
      _copy(e, lin[d], limbNames('_ld$d'));
    }
    emitDoublingChain(e, limbNames('zx'), limbNames('zy'), air.logTrace, air.logPeriod);
    final v = limbNames('_dx${air.logTrace - 1}');
    if (air.numPubCols > 0) {
      air.emitPubColumns(e, limbNames('zx'), limbNames('zy'), v,
          List.generate(air.numPubHints, (c) => limbNames('pkh$c')), per.sublist(air.numPeriodic));
    }
    _dropQ(e, limbNames('zx'));
    _dropQ(e, limbNames('zy'));
    emitPeriodic(e, air, per.sublist(0, air.numPeriodic));
    // aux constraints first (they only pick), then the base ones (consume)
    if (air.numAuxConstraints > 0) {
      air.emitAuxConstraints(e, cur, next, per, lin, chal, cons.sublist(air.numConstraints));
    }
    for (final c in chal) {
      for (final l in c) {
        if (e.has(l)) e.dropNamed(l);
      }
    }
    air.emitConstraints(e, cur, next, per, lin, cons.sublist(0, air.numConstraints));
    // a base emitter unaware of the aux columns leaves them behind
    for (int j = air.numCols; j < air.totalCols; j++) {
      for (final l in [...cur[j], ...next[j]]) {
        if (e.has(l)) e.dropNamed(l);
      }
    }

    // one Horner per group, then weight by beta^{lo}
    final hs = <List<String>>[];
    final los = <int>[];
    var lo = 0;
    for (int g = 0; g < groups.length; g++) {
      los.add(lo);
      emitHorner(e, cons.sublist(lo, lo + groups[g].count), limbNames('beta'), limbNames('_H$g'));
      hs.add(limbNames('_H$g'));
      lo += groups[g].count;
    }
    final maxLo = los.isEmpty ? 0 : los.last;
    if (maxLo > 0) {
      final bits = maxLo.bitLength;
      final sq = <List<String>>[limbNames('_bs0')];
      _copy(e, limbNames('beta'), sq[0]);
      for (int k = 1; k < bits; k++) {
        _copy(e, sq[k - 1], limbNames('_bsa'));
        _copy(e, sq[k - 1], limbNames('_bsb'));
        _mul(e, limbNames('_bsa'), limbNames('_bsb'), limbNames('_bs$k'));
        sq.add(limbNames('_bs$k'));
      }
      for (int g = 0; g < groups.length; g++) {
        for (int k = 0; k < bits; k++) {
          if ((los[g] >> k) & 1 == 0) continue;
          _copy(e, sq[k], limbNames('_bp'));
          _mul(e, hs[g], limbNames('_bp'), limbNames('_Hb'));
          _rename(e, limbNames('_Hb'), hs[g]);
        }
      }
      for (final s in sq) {
        _dropQ(e, s);
      }
    }
    _dropQ(e, limbNames('beta'));

    // sum the group contributions per divisor class
    List<String>? sumInto(List<String>? acc, List<String> h, String tag) {
      if (acc == null) {
        _rename(e, h, limbNames(tag));
        return limbNames(tag);
      }
      for (int k = 0; k < 4; k++) {
        e.roll(acc[k]);
        e.roll(h[k]);
        e.add();
        e.reduce();
        e.nameTop(acc[k]);
      }
      return acc;
    }

    List<String>? main;
    final byDiv = <int, List<String>>{};
    for (int g = 0; g < groups.length; g++) {
      final d = groups[g].divisor;
      if (d < 0) {
        main = sumInto(main, hs[g], '_Smain');
      } else {
        byDiv[d] = sumInto(byDiv[d], hs[g], '_Sd$d')!;
      }
    }
    if (main == null) {
      main = limbNames('_Smain');
      e.pushConst(0, as: main[0]);
      for (int k = 1; k < 4; k++) {
        e.pushConst(0, as: main[k]);
      }
    }

    // rhs = Lall * main + v * Σ_d Sd * Lskip_d ; lhs = comp * v * Lall
    // Lskip_d (the product of every other divisor form) comes from prefix
    // and suffix products: 3D multiplications instead of D².
    final nd = divs.length;
    final pre = <List<String>?>[], suf = <List<String>?>[];
    for (int i = 0; i < nd; i++) {
      // pre[i] = Π_{j<i} ld_j (null for i = 0), suf[i] = Π_{j>i} ld_j (null for the last)
      if (i == 0) {
        pre.add(null);
      } else if (i == 1) {
        _copy(e, limbNames('_ld${divs[0]}'), limbNames('_pre1'));
        pre.add(limbNames('_pre1'));
      } else {
        _copy(e, pre[i - 1]!, limbNames('_pra'));
        _copy(e, limbNames('_ld${divs[i - 1]}'), limbNames('_prb'));
        _mul(e, limbNames('_pra'), limbNames('_prb'), limbNames('_pre$i'));
        pre.add(limbNames('_pre$i'));
      }
    }
    for (int i = nd - 1; i >= 0; i--) {
      if (i == nd - 1) {
        suf.add(null);
      } else if (i == nd - 2) {
        _copy(e, limbNames('_ld${divs[nd - 1]}'), limbNames('_suf$i'));
        suf.add(limbNames('_suf$i'));
      } else {
        _copy(e, suf[nd - 2 - i]!, limbNames('_sfa')); // suf[i+1]
        _copy(e, limbNames('_ld${divs[i + 1]}'), limbNames('_sfb'));
        _mul(e, limbNames('_sfa'), limbNames('_sfb'), limbNames('_suf$i'));
        suf.add(limbNames('_suf$i'));
      }
    }
    final sufOf = List<List<String>?>.generate(nd, (i) => suf[nd - 1 - i]);
    List<String> rhs;
    if (divs.isEmpty) {
      rhs = main;
    } else {
      // Lall = pre[last] * ld[last]
      if (pre[nd - 1] == null) {
        _copy(e, limbNames('_ld${divs[0]}'), limbNames('_Lall'));
      } else {
        _copy(e, pre[nd - 1]!, limbNames('_lla'));
        _copy(e, limbNames('_ld${divs[nd - 1]}'), limbNames('_llb'));
        _mul(e, limbNames('_lla'), limbNames('_llb'), limbNames('_Lall'));
      }
      _copy(e, limbNames('_Lall'), limbNames('_Lm'));
      _mul(e, main, limbNames('_Lm'), limbNames('_rhs0'));
      var acc = limbNames('_rhs0');
      for (int i = 0; i < nd; i++) {
        final d = divs[i];
        final p = pre[i], s = sufOf[i];
        if (p == null && s == null) {
          e.pushConst(1, as: '_Lsk_0');
          for (int k = 1; k < 4; k++) {
            e.pushConst(0, as: '_Lsk_$k');
          }
        } else if (p == null) {
          _copy(e, s!, limbNames('_Lsk'));
        } else if (s == null) {
          _copy(e, p, limbNames('_Lsk'));
        } else {
          _copy(e, p, limbNames('_lka'));
          _copy(e, s, limbNames('_lkb'));
          _mul(e, limbNames('_lka'), limbNames('_lkb'), limbNames('_Lsk'));
        }
        _mul(e, byDiv[d]!, limbNames('_Lsk'), limbNames('_Sb'));
        _copy(e, v, limbNames('_vb'));
        _mul(e, limbNames('_Sb'), limbNames('_vb'), limbNames('_Sv'));
        for (int k = 0; k < 4; k++) {
          e.roll(acc[k]);
          e.roll('_Sv_$k');
          e.add();
          e.reduce();
          e.nameTop(acc[k]);
        }
      }
      rhs = acc;
      for (final d in divs) {
        _dropQ(e, limbNames('_ld$d'));
      }
      for (final p in [...pre, ...suf]) {
        if (p != null) _dropQ(e, p);
      }
    }

    AirOodScriptGen.emitComposeColumns(e, comp, limbNames('_comp'));
    _mul(e, limbNames('_comp'), v, limbNames('_lhs0'));
    List<String> lhs = limbNames('_lhs0');
    if (divs.isNotEmpty) {
      _mul(e, lhs, limbNames('_Lall'), limbNames('_lhs1'));
      lhs = limbNames('_lhs1');
    }
    for (int k = 0; k < 4; k++) {
      e.roll(lhs[k]);
      e.roll(rhs[k]);
      e.numEqualVerify();
    }
  }
}
