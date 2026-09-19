import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';
import 'package:tstokenlib/src/script_gen/deep_quotient_script_gen.dart';
import 'package:tstokenlib/src/script_gen/fiat_shamir_script_gen.dart';
import 'package:tstokenlib/src/script_gen/air_ood_script_gen.dart';
import 'package:tstokenlib/src/script_gen/fri_fold_script_gen.dart';

Transaction _createDummyTx(SVScript scriptSig) {
  var tx = Transaction();
  tx.version = 1;
  tx.nLockTime = 0;
  tx.inputs.add(TransactionInput(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    0,
    TransactionInput.MAX_SEQ_NUMBER,
    scriptBuilder: DefaultUnlockBuilder.fromScript(scriptSig),
  ));
  tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return tx;
}

int _run(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  var sw = Stopwatch()..start();
  interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
      {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  sw.stop();
  return sw.elapsedMicroseconds;
}

final _rng = Random(0x5EED);
int _rM31() => _rng.nextInt(M31.p);
QM31 _rQM31() => QM31.fromLimbs(_rM31(), _rM31(), _rM31(), _rM31());

class _Unlock {
  final b = ScriptBuilder();
  final names = <String>[];
  void num(String name, int v) {
    FriQueryVerifierGen.pushNum(b, v);
    names.add(name);
  }

  void qm31(String base, QM31 v) {
    for (int k = 0; k < 4; k++) {
      num('${base}_$k', v.limbs[k]);
    }
  }

  void data(String name, List<int> bytes) {
    b.addData(Uint8List.fromList(bytes));
    names.add(name);
  }

  SVScript build() => b.build();
}

void _verifyQ(StackEmitter e, List<String> names, QM31 expected) {
  for (int k = 0; k < 4; k++) {
    e.roll(names[k]);
    e.numEqualVerifyConst(expected.limbs[k]);
  }
}

int _bytes(void Function(StackEmitter e) emit, List<String> initial) {
  final b = ScriptBuilder();
  emit(StackEmitter(b, initial: initial));
  return b.build().buffer.length;
}

void main() {
  group('DEEP quotient', () {
    const C = 20;
    late QM31 zx, zy, alpha;
    late List<QM31> values;
    late DeepConstants ref;

    setUp(() {
      zx = _rQM31();
      zy = _rQM31();
      alpha = _rQM31();
      values = List.generate(C, (_) => _rQM31());
      ref = DeepQuotientRef.precompute(zx, zy, values, alpha);
    });

    test('precompute matches reference', () {
      final u = _Unlock();
      u.qm31('zx', zx);
      u.qm31('zy', zy);
      u.qm31('alpha', alpha);
      for (int j = 0; j < C; j++) {
        u.qm31('v$j', values[j]);
      }
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: u.names);
      DeepQuotientScriptGen.emitPrecompute(e, limbNames('zx'), limbNames('zy'),
          limbNames('alpha'), List.generate(C, (j) => limbNames('v$j')));
      _verifyQ(e, limbNames('c'), ref.c);
      _verifyQ(e, limbNames('A'), ref.A);
      _verifyQ(e, limbNames('B'), ref.B);
      _verifyQ(e, limbNames('dA'), ref.dA);
      _verifyQ(e, limbNames('dB'), ref.dB);
      _verifyQ(e, limbNames('dC'), ref.dC);
      for (int j = 0; j < C; j++) {
        _verifyQ(e, limbNames('w$j'), ref.weights[j]);
      }
      e.dropAll();
      e.pushConst(1);
      _run(u.build(), b.build());
    });

    test('quotient at (p) and (conj p) matches reference; wrong hint fails', () {
      final px = _rM31(), py = _rM31();
      final o1 = List.generate(C, (_) => _rM31());
      final o2 = List.generate(C, (_) => _rM31());
      final d1 = DeepQuotientRef.denominator(ref, px, py);
      final d2 = DeepQuotientRef.denominator(ref, px, M31.neg(py));
      final q1 = DeepQuotientRef.quotient(ref, px, py, o1);
      final q2 = DeepQuotientRef.quotient(ref, px, M31.neg(py), o2);

      SVScript lock(_Unlock u) {
        final b = ScriptBuilder();
        final e = StackEmitter(b, initial: u.names);
        DeepQuotientScriptGen.emitPrecompute(e, limbNames('zx'), limbNames('zy'),
            limbNames('alpha'), List.generate(C, (j) => limbNames('v$j')));
        DeepQuotientScriptGen.emitQuotient(e, 'px', 'py',
            List.generate(C, (j) => 'o1_$j'), limbNames('h1'), limbNames('q1'));
        _verifyQ(e, limbNames('q1'), q1);
        DeepQuotientScriptGen.emitQuotient(e, 'px', 'py',
            List.generate(C, (j) => 'o2_$j'), limbNames('h2'), limbNames('q2'), negY: true);
        _verifyQ(e, limbNames('q2'), q2);
        e.dropAll();
        e.pushConst(1);
        return b.build();
      }

      _Unlock unlock(QM31 h1) {
        final u = _Unlock();
        u.qm31('zx', zx);
        u.qm31('zy', zy);
        u.qm31('alpha', alpha);
        for (int j = 0; j < C; j++) {
          u.qm31('v$j', values[j]);
        }
        u.num('px', px);
        u.num('py', py);
        for (int j = 0; j < C; j++) {
          u.num('o1_$j', o1[j]);
        }
        u.qm31('h1', h1);
        for (int j = 0; j < C; j++) {
          u.num('o2_$j', o2[j]);
        }
        u.qm31('h2', d2.inv);
        return u;
      }

      final good = unlock(d1.inv);
      _run(good.build(), lock(good));
      final bad = unlock(d1.inv + QM31.one);
      expect(() => _run(bad.build(), lock(bad)), throwsA(isA<ScriptException>()));
    });

    test('sizes', () {
      final pre = _bytes(
          (e) => DeepQuotientScriptGen.emitPrecompute(e, limbNames('zx'), limbNames('zy'),
              limbNames('alpha'), List.generate(C, (j) => limbNames('v$j'))),
          [...limbNames('zx'), ...limbNames('zy'), ...limbNames('alpha'),
           for (int j = 0; j < C; j++) ...limbNames('v$j')]);
      final consts = [
        ...limbNames('c'), ...limbNames('A'), ...limbNames('B'),
        ...limbNames('dA'), ...limbNames('dB'), ...limbNames('dC'),
        for (int j = 0; j < C; j++) ...limbNames('w$j'),
      ];
      final q = _bytes(
          (e) => DeepQuotientScriptGen.emitQuotient(e, 'px', 'py',
              List.generate(C, (j) => 'o_$j'), limbNames('h'), limbNames('q')),
          [...consts, 'px', 'py', for (int j = 0; j < C; j++) 'o_$j', ...limbNames('h')]);
      print('DEEP, C=$C columns:');
      print('  precompute (once per sample point) : $pre bytes  (${(pre / C).toStringAsFixed(0)}/col)');
      print('  quotient (per query point)         : $q bytes');
    });
  });

  group('Fiat-Shamir transcript', () {
    test('script challenges equal reference; grinding enforced', () {
      final root1 = List.generate(32, (_) => _rng.nextInt(256));
      final root2 = List.generate(32, (_) => _rng.nextInt(256));
      final vals = List.generate(12, (_) => _rM31());
      final ref = TranscriptRef();
      ref.absorb(root1);
      final beta = ref.squeezeQM31();
      ref.absorb(root2);
      ref.absorbLimbs(vals);
      final lam = ref.squeezeQM31();
      final nonce = ref.grind(2);
      expect(ref.checkGrinding(nonce, 2), isTrue);
      final idx = ref.squeezeIndices(16, 17);

      SVScript lock() {
        final b = ScriptBuilder();
        final e = StackEmitter(b, initial: ['root1', 'root2', for (int i = 0; i < 12; i++) 'v$i', 'nonce']);
        FiatShamirScriptGen.emitInit(e);
        FiatShamirScriptGen.emitAbsorb(e, 'root1');
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('beta'));
        FiatShamirScriptGen.emitAbsorb(e, 'root2');
        FiatShamirScriptGen.emitAbsorbLimbs(e, List.generate(12, (i) => 'v$i'));
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('lam'));
        FiatShamirScriptGen.emitGrindingCheck(e, 'nonce', 2);
        FiatShamirScriptGen.emitSqueezeIndices(e, 16, 17, 'q');
        _verifyQ(e, limbNames('beta'), beta);
        _verifyQ(e, limbNames('lam'), lam);
        for (int i = 0; i < 16; i++) {
          e.roll('q$i');
          e.numEqualVerifyConst(idx[i]);
        }
        e.dropAll();
        e.pushConst(1);
        return b.build();
      }

      _Unlock unlock(List<int> n) {
        final u = _Unlock();
        u.data('root1', root1);
        u.data('root2', root2);
        for (int i = 0; i < 12; i++) {
          u.num('v$i', vals[i]);
        }
        u.data('nonce', n);
        return u;
      }

      _run(unlock(nonce).build(), lock());
      expect(() => _run(unlock([1, 2, 3, 4]).build(), lock()), throwsA(isA<ScriptException>()));

      final size = _bytes((e) {
        FiatShamirScriptGen.emitInit(e);
        FiatShamirScriptGen.emitAbsorb(e, 'root1');
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('beta'));
        FiatShamirScriptGen.emitAbsorb(e, 'root2');
        FiatShamirScriptGen.emitAbsorbLimbs(e, List.generate(12, (i) => 'v$i'));
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('lam'));
        FiatShamirScriptGen.emitGrindingCheck(e, 'nonce', 2);
        FiatShamirScriptGen.emitSqueezeIndices(e, 16, 17, 'q');
      }, ['root1', 'root2', for (int i = 0; i < 12; i++) 'v$i', 'nonce']);
      final sq = _bytes((e) => FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('x')), ['ts']);
      final ab = _bytes((e) => FiatShamirScriptGen.emitAbsorb(e, 'r'), ['r', 'ts']);
      final abl = _bytes((e) => FiatShamirScriptGen.emitAbsorbLimbs(e, ['a', 'b', 'c', 'd']), ['a', 'b', 'c', 'd', 'ts']);
      final qi = _bytes((e) => FiatShamirScriptGen.emitSqueezeIndices(e, 16, 17, 'q'), ['ts']);
      print('Fiat-Shamir:');
      print('  absorb 32-byte item      : $ab bytes');
      print('  absorb 4 limbs           : $abl bytes');
      print('  squeeze QM31             : $sq bytes');
      print('  squeeze 16 x 17-bit idx  : $qi bytes');
      print('  sample transcript total  : $size bytes');
    });
  });

  group('OODS point from transcript challenge', () {
    test('script point equals reference and lies on the circle; wrong hint fails', () {
      final t = _rQM31();
      final (zx, zy, h) = TranscriptRef.circlePoint(t);
      expect(zx * zx + zy * zy, QM31.one);

      SVScript lock() {
        final b = ScriptBuilder();
        final e = StackEmitter(b, initial: [...limbNames('t'), ...limbNames('h')]);
        FiatShamirScriptGen.emitCirclePoint(e, limbNames('t'), limbNames('h'), limbNames('zx'), limbNames('zy'));
        _verifyQ(e, limbNames('zx'), zx);
        _verifyQ(e, limbNames('zy'), zy);
        if (e.size != 0) throw StateError('leftover ${e.debugNames()}');
        e.pushConst(1);
        return b.build();
      }

      _Unlock unlock(QM31 hint) {
        final u = _Unlock();
        u.qm31('t', t);
        u.qm31('h', hint);
        return u;
      }

      _run(unlock(h).build(), lock());
      expect(() => _run(unlock(h + QM31.one).build(), lock()), throwsA(isA<ScriptException>()));
      final size = _bytes(
          (e) => FiatShamirScriptGen.emitCirclePoint(e, limbNames('t'), limbNames('h'), limbNames('zx'), limbNames('zy')),
          [...limbNames('t'), ...limbNames('h')]);
      print('OODS point from challenge: $size bytes');
    });
  });

  group('OODS constraint check, Poseidon2 external round AIR', () {
    const logTrace = 12;
    late Poseidon2AirRef air;
    late List<QM31> cur, next, comp;
    late QM31 beta, zx;

    setUp(() {
      air = Poseidon2AirRef(List.generate(16, (_) => _rM31()), logTrace);
      cur = List.generate(16, (_) => _rQM31());
      next = List.generate(16, (_) => _rQM31());
      beta = _rQM31();
      zx = _rQM31();
      // Build a consistent instance: comp(z) = rhs / v(z), split across 4 columns.
      final rhs = air.combined(cur, next, beta);
      final v = air.vanishing(zx);
      final compZ = rhs * v.inv;
      final c1 = _rQM31(), c2 = _rQM31(), c3 = _rQM31();
      final c0 = compZ - (c1 * QM31.i + c2 * QM31.u + c3 * QM31.i * QM31.u);
      comp = [c0, c1, c2, c3];
      expect(Poseidon2AirRef.composeColumns(comp), compZ);
    });

    _Unlock unlock(List<QM31> nx) {
      final u = _Unlock();
      for (int j = 0; j < 16; j++) {
        u.qm31('cur$j', cur[j]);
      }
      for (int j = 0; j < 16; j++) {
        u.qm31('next$j', nx[j]);
      }
      for (int k = 0; k < 4; k++) {
        u.qm31('comp$k', comp[k]);
      }
      u.qm31('beta', beta);
      u.qm31('zx', zx);
      return u;
    }

    SVScript lock(List<String> names) {
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: names);
      AirOodScriptGen.emitOodsCheck(e, air);
      if (e.size != 0) throw StateError('leftover ${e.debugNames()}');
      e.pushConst(1);
      return b.build();
    }

    test('component emitters match reference', () {
      final x = _rQM31();
      final sb = _bytes((e) {
        AirOodScriptGen.emitSbox(e, limbNames('x'), 7, limbNames('y'));
        _verifyQ(e, limbNames('y'), Poseidon2AirRef.pow5(x + QM31.fromLimbs(7, 0, 0, 0)));
        e.dropAll();
        e.pushConst(1);
      }, limbNames('x'));
      expect(sb, greaterThan(0));
      // run it
      final b = ScriptBuilder();
      final e = StackEmitter(b, initial: limbNames('x'));
      AirOodScriptGen.emitSbox(e, limbNames('x'), 7, limbNames('y'));
      _verifyQ(e, limbNames('y'), Poseidon2AirRef.pow5(x + QM31.fromLimbs(7, 0, 0, 0)));
      e.dropAll();
      e.pushConst(1);
      final u = _Unlock();
      u.qm31('x', x);
      _run(u.build(), b.build());

      // compose columns
      final b2 = ScriptBuilder();
      final e2 = StackEmitter(b2, initial: [for (int k = 0; k < 4; k++) ...limbNames('c$k')]);
      AirOodScriptGen.emitComposeColumns(e2, List.generate(4, (k) => limbNames('c$k')), limbNames('out'));
      _verifyQ(e2, limbNames('out'), Poseidon2AirRef.composeColumns(comp));
      e2.pushConst(1);
      final u2 = _Unlock();
      for (int k = 0; k < 4; k++) {
        u2.qm31('c$k', comp[k]);
      }
      _run(u2.build(), b2.build());

      // vanishing
      final b3 = ScriptBuilder();
      final e3 = StackEmitter(b3, initial: limbNames('zx'));
      AirOodScriptGen.emitVanishing(e3, limbNames('zx'), logTrace, limbNames('v'));
      _verifyQ(e3, limbNames('v'), air.vanishing(zx));
      e3.dropAll();
      e3.pushConst(1);
      final u3 = _Unlock();
      u3.qm31('zx', zx);
      _run(u3.build(), b3.build());
    });

    test('valid instance passes; tampered next fails; sizes', () {
      final u = unlock(next);
      final l = lock(u.names);
      final us = _run(u.build(), l);
      final badNext = [...next];
      badNext[5] = badNext[5] + QM31.one;
      final ub = unlock(badNext);
      expect(() => _run(ub.build(), lock(ub.names)), throwsA(isA<ScriptException>()));

      final sbox = _bytes((e) => AirOodScriptGen.emitSbox(e, limbNames('x'), 7, limbNames('y')), limbNames('x'));
      final lin = _bytes(
          (e) => AirOodScriptGen.emitExternalLayer(e, List.generate(16, (j) => limbNames('s$j')), 'o'),
          [for (int j = 0; j < 16; j++) ...limbNames('s$j')]);
      final comb = _bytes(
          (e) => AirOodScriptGen.emitCombine(e, List.generate(16, (j) => limbNames('n$j')),
              List.generate(16, (j) => limbNames('l$j')), limbNames('beta'), limbNames('r')),
          [for (int j = 0; j < 16; j++) ...limbNames('n$j'), for (int j = 0; j < 16; j++) ...limbNames('l$j'), ...limbNames('beta')]);
      final van = _bytes((e) => AirOodScriptGen.emitVanishing(e, limbNames('zx'), logTrace, limbNames('v')), limbNames('zx'));
      final compose = _bytes(
          (e) => AirOodScriptGen.emitComposeColumns(e, List.generate(4, (k) => limbNames('c$k')), limbNames('o')),
          [for (int k = 0; k < 4; k++) ...limbNames('c$k')]);
      print('OODS check, width-16 Poseidon2 external round, trace 2^$logTrace:');
      print('  one S-box (x^5)              : $sbox bytes  (x16 = ${16 * sbox})');
      print('  external linear layer        : $lin bytes');
      print('  beta-combine 16 constraints  : $comb bytes');
      print('  vanishing polynomial         : $van bytes');
      print('  compose 4 columns            : $compose bytes');
      print('  full OODS locking script     : ${l.buffer.length} bytes');
      print('  unlocking script             : ${u.build().buffer.length} bytes');
      print('  interp time                  : ${(us / 1000).toStringAsFixed(1)} ms');
    });
  });

  group('Projection', () {
    test('full verifier estimate from measured pieces', () {
      const C = 20; // 16 trace + 4 composition columns opened per point
      const t = 12, b = 5, Q = 16, k = 5;
      final top = t + b - 1;
      // FRI per query (from m31_fri test: optimized per-layer 436 + 15.4*depth, domain 65/bit, final 20/coef)
      double fri = 65.0 * top;
      for (int l = 0; l < t + b - k; l++) {
        fri += 436 + 15.4 * (top - l);
      }
      fri += 20 * (1 << k);
      // DEEP per query: two sample points (z: 20 cols; z*g: 16 cols), two points (p, -p)
      final pre = _bytes(
          (e) => DeepQuotientScriptGen.emitPrecompute(e, limbNames('zx'), limbNames('zy'),
              limbNames('alpha'), List.generate(C, (j) => limbNames('v$j'))),
          [...limbNames('zx'), ...limbNames('zy'), ...limbNames('alpha'),
           for (int j = 0; j < C; j++) ...limbNames('v$j')]);
      final consts = [
        ...limbNames('c'), ...limbNames('A'), ...limbNames('B'),
        ...limbNames('dA'), ...limbNames('dB'), ...limbNames('dC'),
        for (int j = 0; j < C; j++) ...limbNames('w$j'),
      ];
      final qpt = _bytes(
          (e) => DeepQuotientScriptGen.emitQuotient(e, 'px', 'py',
              List.generate(C, (j) => 'o_$j'), limbNames('h'), limbNames('q')),
          [...consts, 'px', 'py', for (int j = 0; j < C; j++) 'o_$j', ...limbNames('h')]);
      final deepPerQuery = 2 * 2 * qpt; // 2 sample points x (p, -p)
      final deepPre = 2 * pre;
      // Trace + composition Merkle openings per query: 2 commitments, leaf = 2*C values
      final merkle = 2 * (15.4 * top + 5.0 * 2 * C + 40);
      final oods = _bytes((e) => AirOodScriptGen.emitOodsCheck(e, Poseidon2AirRef(List.filled(16, 5), t)), [
        for (int j = 0; j < 16; j++) ...limbNames('cur$j'),
        for (int j = 0; j < 16; j++) ...limbNames('next$j'),
        for (int k = 0; k < 4; k++) ...limbNames('comp$k'),
        ...limbNames('beta'), ...limbNames('zx'),
      ]);
      // Realistic transcript: trace root, beta, comp root, z, 36 OODS values,
      // lambda, 12 FRI roots + alphas, 32 final coefficients, grinding, 16 indices.
      final oodsLimbs = [for (int i = 0; i < 36; i++) ...limbNames('ov$i')];
      final finalLimbs = [for (int i = 0; i < 32; i++) ...limbNames('fc$i')];
      final fs = _bytes((e) {
        FiatShamirScriptGen.emitInit(e);
        FiatShamirScriptGen.emitAbsorb(e, 'troot');
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('beta'));
        FiatShamirScriptGen.emitAbsorb(e, 'croot');
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('zt'));
        FiatShamirScriptGen.emitAbsorbLimbs(e, oodsLimbs);
        FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('lam'));
        for (int l = 0; l < 12; l++) {
          FiatShamirScriptGen.emitAbsorb(e, 'fr$l');
          FiatShamirScriptGen.emitSqueezeQM31(e, limbNames('al$l'));
        }
        FiatShamirScriptGen.emitAbsorbLimbs(e, finalLimbs);
        FiatShamirScriptGen.emitGrindingCheck(e, 'nonce', 3);
        FiatShamirScriptGen.emitSqueezeIndices(e, Q, top, 'q');
      }, ['troot', 'croot', ...oodsLimbs, for (int l = 0; l < 12; l++) 'fr$l', ...finalLimbs, 'nonce']);
      final perQuery = fri + deepPerQuery + merkle;
      final total = Q * perQuery + deepPre + oods + fs;
      print('Projection: t=$t blowup=${1 << b} Q=$Q final=${1 << k} C=$C');
      print('  FRI per query            : ${fri.toStringAsFixed(0)}');
      print('  DEEP per query           : $deepPerQuery  (4 x $qpt)');
      print('  Merkle openings per query: ${merkle.toStringAsFixed(0)}');
      print('  per query total          : ${perQuery.toStringAsFixed(0)}');
      print('  DEEP precompute (once)   : $deepPre');
      print('  OODS (once)              : $oods');
      print('  Fiat-Shamir (once)       : $fs');
      print('  TOTAL                    : ${(total / 1024).toStringAsFixed(0)} KB');
    });
  });
}
