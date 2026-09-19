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
import '../crypto/stark_prover_ref.dart';
import 'm31_script_gen.dart';
import 'fri_fold_script_gen.dart';
import 'deep_quotient_script_gen.dart';
import 'fiat_shamir_script_gen.dart';
import 'air.dart';

/// Assembled Circle-STARK verifier: one locking script that consumes a
/// [StarkProof] from the unlocking script in transcript order and verifies
/// it completely (see [StarkProverRef] for the protocol).
class StarkVerifierGen {
  final StarkParams P;
  final Air air;
  StarkVerifierGen(this.P, this.air);

  /// Names of unlocking-script entries pushed ABOVE the proof (bottom to top)
  /// and a hook that runs first, before the transcript. A covenant wrapping
  /// the verifier consumes its own witness there; it may pick the publics,
  /// which sit at the bottom, and whatever it leaves behind is dropped with
  /// the rest at the end.
  List<String> unlockAbove = const [];
  void Function(StackEmitter e)? prologue;

  /// Replaces the final cleanup (drop everything, push TRUE) when set.
  void Function(StackEmitter e)? epilogue;
  /// Trace columns, aux-round columns, and both together (the DEEP groups
  /// B and C and the out-of-domain values span both).
  int get C => air.numCols;
  int get A => air.numAuxCols;
  int get CT => air.totalCols;

  static List<String> L(String b) => limbNames(b);

  // ---- unlocking-script layout (bottom to top) ----
  List<String> layout() {
    if (air.numPreCols > 0) throw UnimplementedError('the script verifier does not open preprocessed columns yet');
    final names = <String>[
      for (int k = 0; k < air.numPublics; k++) Air.publicName(k),
      'troot',
      if (A > 0) 'aroot',
      'croot',
      ...L('zh')
    ];
    for (int j = 0; j < CT; j++) {
      names.addAll(L('tz$j'));
    }
    for (int j = 0; j < CT; j++) {
      names.addAll(L('tzg$j'));
    }
    for (int k = 0; k < StarkParams.compCols; k++) {
      names.addAll(L('cz$k'));
    }
    for (int l = 0; l < P.numLineFolds; l++) {
      names.add('fr$l');
    }
    for (int i = 0; i < P.finalDegree; i++) {
      names.addAll(L('fc$i'));
    }
    names.add('nonce');
    final a = P.logCompHalf;
    for (int q = 0; q < P.numQueries; q++) {
      names.addAll(List.generate(8, (i) => 'cl${q}_$i'));
      names.addAll(List.generate(a, (i) => 'cs${q}_$i'));
      names.add('yai$q');
      names.addAll(L('dap$q'));
      names.addAll(L('dac$q'));
      for (int l = 0; l < P.numLineFolds; l++) {
        names.addAll(L('lf${q}_$l'));
        names.addAll(L('lg${q}_$l'));
        names.addAll(List.generate(a - 1 - l, (i) => 'ls${q}_${l}_$i'));
        names.add('lxi${q}_$l');
      }
      names.addAll(List.generate(2 * C, (i) => 'tl${q}_$i'));
      names.addAll(List.generate(P.logTraceHalf, (i) => 'ts${q}_$i'));
      if (A > 0) {
        // ('al$l' is a FRI alpha; these must not collide with its limbs)
        names.addAll(List.generate(2 * A, (i) => 'axl${q}_$i'));
        names.addAll(List.generate(P.logTraceHalf, (i) => 'axs${q}_$i'));
      }
      names.add('ybi$q');
      names.addAll(L('dbp$q'));
      names.addAll(L('dbc$q'));
      names.addAll(L('dcp$q'));
      names.addAll(L('dcc$q'));
    }
    return names;
  }

  static void _pushNum(ScriptBuilder b, int v) => FriQueryVerifierGen.pushNum(b, v);
  static void _pushQ(ScriptBuilder b, QM31 v) {
    for (final l in v.limbs) {
      _pushNum(b, l);
    }
  }

  SVScript buildUnlock(StarkProof pf) {
    final b = ScriptBuilder();
    if (air.publicValues.length != air.numPublics) throw StateError('public inputs: values do not match count');
    for (final v in air.publicValues) {
      _pushNum(b, v);
    }
    b.addData(Uint8List.fromList(pf.traceRoot));
    if (A > 0) {
      if (pf.auxRoot.isEmpty) throw StateError('proof has no aux round');
      b.addData(Uint8List.fromList(pf.auxRoot));
    }
    b.addData(Uint8List.fromList(pf.compRoot));
    _pushQ(b, pf.zHint);
    for (final v in pf.traceAtZ) {
      _pushQ(b, v);
    }
    for (final v in pf.traceAtZg) {
      _pushQ(b, v);
    }
    for (final v in pf.compAtZ) {
      _pushQ(b, v);
    }
    for (final r in pf.friRoots) {
      b.addData(Uint8List.fromList(r));
    }
    for (final c in pf.finalCoefs) {
      _pushQ(b, c);
    }
    b.addData(Uint8List.fromList(pf.nonce));
    for (final q in pf.queries) {
      for (final v in q.compLeaf) {
        _pushNum(b, v);
      }
      for (final s in q.compPath) {
        b.addData(Uint8List.fromList(s));
      }
      _pushNum(b, q.yAInv);
      _pushQ(b, q.dAInvP);
      _pushQ(b, q.dAInvC);
      for (int l = 0; l < P.numLineFolds; l++) {
        _pushQ(b, q.lineF0[l]);
        _pushQ(b, q.lineF1[l]);
        for (final s in q.linePaths[l]) {
          b.addData(Uint8List.fromList(s));
        }
        _pushNum(b, q.lineXInv[l]);
      }
      for (final v in q.traceLeaf) {
        _pushNum(b, v);
      }
      for (final s in q.tracePath) {
        b.addData(Uint8List.fromList(s));
      }
      if (A > 0) {
        for (final v in q.auxLeaf) {
          _pushNum(b, v);
        }
        for (final s in q.auxPath) {
          b.addData(Uint8List.fromList(s));
        }
      }
      _pushNum(b, q.yBInv);
      _pushQ(b, q.dBInvP);
      _pushQ(b, q.dBInvC);
      _pushQ(b, q.dCInvP);
      _pushQ(b, q.dCInvC);
    }
    return b.build();
  }

  // ---- helpers ----
  static void _copy(StackEmitter e, List<String> src, List<String> dst) {
    for (int k = 0; k < 4; k++) {
      e.pick(src[k], as: dst[k]);
    }
  }

  static void _addQ(StackEmitter e, List<String> a, List<String> b, List<String> out) {
    for (int k = 0; k < 4; k++) {
      e.roll(a[k]);
      e.roll(b[k]);
      e.add();
      e.reduce();
      e.nameTop(out[k]);
    }
  }

  /// (x, y) <- (2x² - 1, 2xy), keeping names.
  static void _doublePoint(StackEmitter e, String x, String y) {
    e.pick(x);
    e.pick(y);
    e.mul();
    e.dup();
    e.add();
    e.reduce();
    e.nameTop('_ny');
    e.roll(x);
    e.dup();
    e.mul();
    e.dup();
    e.add();
    e.pushConst(1);
    e.sub();
    e.reduce();
    e.nameTop(x);
    e.dropNamed(y);
    e.rename('_ny', y);
  }

  /// z*g for the constant M31 point g: (zx gx - zy gy, zx gy + zy gx).
  static void _mulByConstPoint(StackEmitter e, List<String> zx, List<String> zy, CirclePoint g,
      List<String> ox, List<String> oy) {
    for (int k = 0; k < 4; k++) {
      e.pick(zx[k]);
      e.mulConst(g.x);
      e.pick(zy[k]);
      e.mulConst(g.y);
      e.sub();
      e.reduce();
      e.nameTop(ox[k]);
    }
    for (int k = 0; k < 4; k++) {
      e.pick(zx[k]);
      e.mulConst(g.y);
      e.pick(zy[k]);
      e.mulConst(g.x);
      e.add();
      e.reduce();
      e.nameTop(oy[k]);
    }
  }

  static void _equalVerifyNamed(StackEmitter e, String top, String constant) {
    e.roll(top);
    e.pick(constant);
    e.raw(OpCodes.OP_EQUALVERIFY, pops: 2, pushes: 0);
  }

  /// Horner evaluation of the final polynomial at the M31 entry [x]:
  /// acc = fc_{m-1}; acc = acc * x + fc_i. Leaves canonical [out].
  void _emitFinalPoly(StackEmitter e, String x, List<String> out) {
    final m = P.finalDegree;
    _copy(e, L('fc${m - 1}'), L('_fa'));
    for (int i = m - 2; i >= 0; i--) {
      for (int k = 0; k < 4; k++) {
        e.roll('_fa_$k');
        e.pick(x);
        e.mul();
        e.pick('fc${i}_$k');
        e.add();
        e.reduce();
        e.nameTop('_fa_$k');
      }
    }
    for (int k = 0; k < 4; k++) {
      e.rename('_fa_$k', out[k]);
    }
  }

  /// Debug: values to check at checkpoints (name -> QM31 or int), and the
  /// checkpoint after which to stop (script then succeeds trivially).
  Map<String, Object> expect = {};
  int stopStage = 1 << 30;
  bool _stopped = false;

  void _checkpoint(StackEmitter e, int stage, List<String> names) {
    if (_stopped) return;
    for (final n in names) {
      final v = expect[n];
      if (v == null) continue;
      if (v is QM31) {
        for (int k = 0; k < 4; k++) {
          e.pick('${n}_$k');
          e.numEqualVerifyConst(v.limbs[k]);
        }
      } else {
        e.pick(n);
        e.numEqualVerifyConst(v as int);
      }
    }
    if (stage >= stopStage) {
      e.dropAll();
      e.pushConst(1);
      _stopped = true;
    }
  }

  SVScript generate() {
    _stopped = false;
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: [...layout(), ...unlockAbove]);
    prologue?.call(e);
    final a = P.logCompHalf;
    final hA = HalfCoset(a);
    final gT = CirclePoint.subgroupGen(P.logTrace);

    // ---- transcript: beta, z ----
    FiatShamirScriptGen.emitInit(e);
    if (air.numPublics > 0) {
      FiatShamirScriptGen.emitAbsorbLimbs(e, [for (int k = 0; k < air.numPublics; k++) Air.publicName(k)]);
    }
    FiatShamirScriptGen.emitAbsorb(e, 'troot');
    // interaction round: challenges from the trace root, then the aux root
    for (int k = 0; k < air.numChallenges; k++) {
      FiatShamirScriptGen.emitSqueezeQM31(e, L('chal$k'));
    }
    if (A > 0) FiatShamirScriptGen.emitAbsorb(e, 'aroot');
    FiatShamirScriptGen.emitSqueezeQM31(e, L('beta'));
    _checkpoint(e, 1, ['beta']);
    if (_stopped) return b.build();
    FiatShamirScriptGen.emitAbsorb(e, 'croot');
    FiatShamirScriptGen.emitSqueezeQM31(e, L('tch'));
    _checkpoint(e, 2, ['tch']);
    if (_stopped) return b.build();
    FiatShamirScriptGen.emitCirclePoint(e, L('tch'), L('zh'), L('zx'), L('zy'));
    _checkpoint(e, 3, ['zx', 'zy']);
    if (_stopped) return b.build();
    final oodsLimbs = <String>[
      for (int j = 0; j < CT; j++) ...L('tz$j'),
      for (int j = 0; j < CT; j++) ...L('tzg$j'),
      for (int k = 0; k < StarkParams.compCols; k++) ...L('cz$k'),
    ];
    FiatShamirScriptGen.emitAbsorbLimbs(e, oodsLimbs);
    FiatShamirScriptGen.emitSqueezeQM31(e, L('lamA'));
    FiatShamirScriptGen.emitSqueezeQM31(e, L('lamB'));
    FiatShamirScriptGen.emitSqueezeQM31(e, L('lamC'));
    FiatShamirScriptGen.emitSqueezeQM31(e, L('alC'));
    _checkpoint(e, 4, ['lamA', 'lamB', 'lamC', 'alC']);
    if (_stopped) return b.build();

    // ---- OODS constraint check (on copies; the challenges are consumed) ----
    for (int j = 0; j < CT; j++) {
      _copy(e, L('tz$j'), L('cur$j'));
    }
    for (int j = 0; j < CT; j++) {
      _copy(e, L('tzg$j'), L('next$j'));
    }
    for (int k = 0; k < 4; k++) {
      _copy(e, L('cz$k'), L('comp$k'));
    }
    _copy(e, L('beta'), L('beta2'));
    for (final l in L('beta')) {
      e.dropNamed(l);
    }
    for (int k = 0; k < 4; k++) {
      e.rename('beta2_$k', 'beta_$k');
    }
    for (final n in ['zx', 'zy']) {
      _copy(e, L(n), L('${n}2'));
      for (int k = 0; k < 4; k++) {
        e.rename('${n}_$k', '${n}k_$k');
        e.rename('${n}2_$k', '${n}_$k');
      }
    }
    AirScriptGen.emitOodsCheck(e, air);
    for (final n in ['zx', 'zy']) {
      for (int k = 0; k < 4; k++) {
        e.rename('${n}k_$k', '${n}_$k');
      }
    }
    _checkpoint(e, 5, []);
    if (_stopped) return b.build();

    // ---- z*g and DEEP precompute for the three sample groups ----
    _mulByConstPoint(e, L('zx'), L('zy'), gT, L('zgx'), L('zgy'));
    _checkpoint(e, 6, ['zgx', 'zgy']);
    if (_stopped) return b.build();
    DeepQuotientScriptGen.emitPrecompute(e, L('zx'), L('zy'), L('lamA'),
        List.generate(4, (k) => L('cz$k')), tag: 'A');
    DeepQuotientScriptGen.emitPrecompute(e, L('zx'), L('zy'), L('lamB'),
        List.generate(CT, (j) => L('tz$j')), tag: 'B');
    DeepQuotientScriptGen.emitPrecompute(e, L('zgx'), L('zgy'), L('lamC'),
        List.generate(CT, (j) => L('tzg$j')), tag: 'C');
    _checkpoint(e, 7, ['cA', 'AA', 'BA', 'dAA', 'dBA', 'dCA', 'wA1', 'cB', 'AB', 'BB', 'wB1', 'cC', 'AC', 'BC', 'dCC', 'wC1']);
    if (_stopped) return b.build();

    // ---- FRI roots / alphas, final coefficients, grinding, indices ----
    for (int l = 0; l < P.numLineFolds; l++) {
      FiatShamirScriptGen.emitAbsorb(e, 'fr$l');
      FiatShamirScriptGen.emitSqueezeQM31(e, L('al$l'));
    }
    FiatShamirScriptGen.emitAbsorbLimbs(e, [for (int i = 0; i < P.finalDegree; i++) ...L('fc$i')]);
    FiatShamirScriptGen.emitGrindingCheck(e, 'nonce', P.grindBytes);
    FiatShamirScriptGen.emitSqueezeIndices(e, P.numQueries, a, 'qi');
    _checkpoint(e, 8, [for (int l = 0; l < P.numLineFolds; l++) 'al$l', for (int q = 0; q < P.numQueries; q++) 'qi$q']);
    if (_stopped) return b.build();

    // ---- queries ----
    final out = L('out');
    for (int q = 0; q < P.numQueries; q++) {
      e.rename('qi$q', 'idx');
      FriFoldScriptGen.emitDomainPointXY(e, hA, 'idx', a, asX: 'xA', asY: 'yA');
      e.pick('xA', as: 'xB');
      e.pick('yA', as: 'yB');
      for (int i = 0; i < P.logCompHalf - P.logTraceHalf; i++) {
        _doublePoint(e, 'xB', 'yB');
      }
      if (q == 0) {
        _checkpoint(e, 9, ['xA', 'yA', 'xB', 'yB']);
        if (_stopped) return b.build();
      }
      // composition opening
      FriFoldScriptGen.emitLeafHashN(e, List.generate(8, (i) => 'cl${q}_$i'), as: 'leaf');
      FriFoldScriptGen.emitIndexSplit(e, 'idx', a);
      FriFoldScriptGen.emitMerklePath(e, 'leaf', List.generate(a, (i) => 'cs${q}_$i'), 'ic', as: 'root');
      _equalVerifyNamed(e, 'root', 'croot');
      if (q == 0) {
        _checkpoint(e, 10, []);
        if (_stopped) return b.build();
      }
      // DEEP group A at p and conj p, then circle fold
      DeepQuotientScriptGen.emitQuotient(e, 'xA', 'yA', List.generate(4, (i) => 'cl${q}_$i'), L('dap$q'), L('qAp'), tag: 'A');
      DeepQuotientScriptGen.emitQuotient(e, 'xA', 'yA', List.generate(4, (i) => 'cl${q}_${4 + i}'), L('dac$q'), L('qAc'), tag: 'A', negY: true);
      if (q == 0) {
        _checkpoint(e, 11, ['qAp', 'qAc']);
        if (_stopped) return b.build();
      }
      M31Ops.verifyInverse(e, 'yA', 'yai$q', consumeInv: false);
      _copy(e, L('alC'), L('_al'));
      FriFoldScriptGen.emitFoldLine(e, L('qAp'), L('qAc'), 'yai$q', L('_al'), out);
      if (q == 0) {
        for (int k = 0; k < 4; k++) {
          e.rename('out_$k', 'circleOut_$k');
        }
        _checkpoint(e, 12, ['circleOut']);
        if (_stopped) return b.build();
        for (int k = 0; k < 4; k++) {
          e.rename('circleOut_$k', 'out_$k');
        }
      }
      FriFoldScriptGen.emitSignStep(e, 'xA', 'topbit');
      FriFoldScriptGen.emitSelectCompare(e, out, L('lf${q}_0'), L('lg${q}_0'), 'topbit');

      for (int l = 0; l < P.numLineFolds; l++) {
        final d = a - 1 - l;
        final bool foldIn = l == P.foldInIndex;
        if (foldIn) {
          // trace opening at p_B = 8 p_A, leaf index = current idx
          e.pick('idx', as: 'tic');
          FriFoldScriptGen.emitLeafHashN(e, List.generate(2 * C, (i) => 'tl${q}_$i'), as: 'tleaf');
          FriFoldScriptGen.emitMerklePath(e, 'tleaf', List.generate(P.logTraceHalf, (i) => 'ts${q}_$i'), 'tic', as: 'troot2');
          _equalVerifyNamed(e, 'troot2', 'troot');
          if (A > 0) {
            // aux-round opening at the same index, against the aux root
            e.pick('idx', as: 'aic');
            FriFoldScriptGen.emitLeafHashN(e, List.generate(2 * A, (i) => 'axl${q}_$i'), as: 'aleaf');
            FriFoldScriptGen.emitMerklePath(e, 'aleaf', List.generate(P.logTraceHalf, (i) => 'axs${q}_$i'), 'aic', as: 'aroot2');
            _equalVerifyNamed(e, 'aroot2', 'aroot');
          }
          // column openings at p: trace then aux; likewise at conj p
          final atP = [for (int i = 0; i < C; i++) 'tl${q}_$i', for (int i = 0; i < A; i++) 'axl${q}_$i'];
          final atC = [for (int i = 0; i < C; i++) 'tl${q}_${C + i}', for (int i = 0; i < A; i++) 'axl${q}_${A + i}'];
          for (int i = 0; i < CT; i++) {
            e.pick(atP[i], as: 'tlb_$i');
          }
          DeepQuotientScriptGen.emitQuotient(e, 'xB', 'yB', List.generate(CT, (i) => 'tlb_$i'), L('dbp$q'), L('qBp'), tag: 'B');
          DeepQuotientScriptGen.emitQuotient(e, 'xB', 'yB', atP, L('dcp$q'), L('qCp'), tag: 'C');
          _addQ(e, L('qBp'), L('qCp'), L('qTp'));
          for (int i = 0; i < CT; i++) {
            e.pick(atC[i], as: 'tlb_$i');
          }
          DeepQuotientScriptGen.emitQuotient(e, 'xB', 'yB', List.generate(CT, (i) => 'tlb_$i'), L('dbc$q'), L('qBc'), tag: 'B', negY: true);
          DeepQuotientScriptGen.emitQuotient(e, 'xB', 'yB', atC, L('dcc$q'), L('qCc'), tag: 'C', negY: true);
          _addQ(e, L('qBc'), L('qCc'), L('qTc'));
          M31Ops.verifyInverse(e, 'yB', 'ybi$q', consumeInv: false);
          if (q == 0) {
            _checkpoint(e, 13, ['qTp', 'qTc']);
            if (_stopped) return b.build();
          }
          _copy(e, L('al$l'), L('_al'));
          FriFoldScriptGen.emitFoldLine(e, L('qTp'), L('qTc'), 'ybi$q', L('_al'), L('outT'));
        }
        FriFoldScriptGen.emitLeafHash(e, L('lf${q}_$l'), L('lg${q}_$l'), as: 'leaf');
        FriFoldScriptGen.emitIndexSplit(e, 'idx', d);
        FriFoldScriptGen.emitMerklePath(e, 'leaf', List.generate(d, (i) => 'ls${q}_${l}_$i'), 'ic', as: 'root');
        _equalVerifyNamed(e, 'root', 'fr$l');
        M31Ops.verifyInverse(e, 'xA', 'lxi${q}_$l', consumeInv: false);
        _copy(e, L('al$l'), L('_al'));
        FriFoldScriptGen.emitFoldLine(e, L('lf${q}_$l'), L('lg${q}_$l'), 'lxi${q}_$l', L('_al'), out);
        if (foldIn) {
          _addQ(e, out, L('outT'), L('out2'));
          for (int k = 0; k < 4; k++) {
            e.rename('out2_$k', out[k]);
          }
        }
        if (q == 0) {
          for (int k = 0; k < 4; k++) {
            e.rename('out_$k', 'fold${l}_$k');
          }
          _checkpoint(e, 20 + l, ['fold$l']);
          if (_stopped) return b.build();
          for (int k = 0; k < 4; k++) {
            e.rename('fold${l}_$k', 'out_$k');
          }
        }
        if (l < P.numLineFolds - 1) {
          FriFoldScriptGen.emitTwiddleStep(e, 'xA', 'topbit');
          FriFoldScriptGen.emitSelectCompare(e, out, L('lf${q}_${l + 1}'), L('lg${q}_${l + 1}'), 'topbit');
        } else {
          // The fold output sits at the point 2p, whose x is 2x² - 1 with no
          // sign correction (the twiddle step's flip yields the next leaf's x,
          // which is only needed to feed another fold).
          e.dropNamed('topbit');
          e.roll('xA');
          e.dup();
          e.mul();
          e.dup();
          e.add();
          e.pushConst(1);
          e.sub();
          e.reduce();
          e.nameTop('xA');
          _emitFinalPoly(e, 'xA', L('fin'));
          for (int k = 0; k < 4; k++) {
            e.roll('fin_$k');
            e.roll(out[k]);
            e.numEqualVerify();
          }
        }
      }
      for (final n in ['xA', 'yA', 'xB', 'yB', 'idx']) {
        e.dropNamed(n);
      }
    }
    if (epilogue != null) {
      epilogue!(e);
    } else {
      e.dropAll();
      e.pushConst(1);
    }
    return b.build();
  }
}
