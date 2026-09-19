import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';
import 'package:tstokenlib/src/script_gen/fri_fold_script_gen.dart';

// ---------------------------------------------------------------------------
// Interpreter harness
// ---------------------------------------------------------------------------

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

int _runTimed(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  var sw = Stopwatch()..start();
  interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
      {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
  sw.stop();
  return sw.elapsedMicroseconds;
}

final _rng = Random(0xC1AC1E);
int _rM31() => _rng.nextInt(M31.p);
QM31 _rQM31() => QM31.fromLimbs(_rM31(), _rM31(), _rM31(), _rM31());

SVScript _unlockNums(List<int> nums) {
  final b = ScriptBuilder();
  for (final v in nums) {
    FriQueryVerifierGen.pushNum(b, v);
  }
  return b.build();
}

/// Locking script tail: verify the top N entries equal [expected] (top last).
void _verifyTopEquals(StackEmitter e, List<String> names, List<int> expected) {
  for (int k = 0; k < names.length; k++) {
    e.roll(names[k]);
    e.numEqualVerifyConst(expected[k]);
  }
}

// ---------------------------------------------------------------------------
// Reference Merkle tree and FRI prover
// ---------------------------------------------------------------------------

List<int> _sha(List<int> a) => crypto.sha256.convert(a).bytes;

Uint8List _ser(QM31 v) {
  final out = ByteData(16);
  for (int k = 0; k < 4; k++) {
    out.setUint32(k * 4, v.limbs[k], Endian.little);
  }
  return out.buffer.asUint8List();
}

List<int> _leafHash(QM31 f0, QM31 f1) => _sha([..._ser(f0), ..._ser(f1)]);

class MerkleTree {
  final List<List<List<int>>> levels; // levels[0] = leaves
  MerkleTree(List<List<int>> leaves) : levels = [leaves] {
    while (levels.last.length > 1) {
      final prev = levels.last;
      final next = <List<int>>[];
      for (int i = 0; i < prev.length; i += 2) {
        next.add(_sha([...prev[i], ...prev[i + 1]]));
      }
      levels.add(next);
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

class FriReference {
  final int logSize;
  final int numLayers;
  final List<QM31> alphas;
  final List<HalfCoset> cosets = [];
  final List<List<QM31>> evals = [];
  final List<MerkleTree> trees = [];

  // Optional circle layer: evaluations over the full circle domain
  // (half coset p_i, i < n, then conj p_i at n + i), folded with y_i^-1.
  final bool circle;
  final QM31? circleAlpha;
  List<QM31>? circleEvals;
  MerkleTree? circleTree;

  FriReference(this.logSize, this.numLayers, this.alphas,
      {this.circle = false, this.circleAlpha}) {
    List<QM31> cur;
    if (circle) {
      final n = 1 << logSize;
      final coset = HalfCoset(logSize);
      circleEvals = List.generate(2 * n, (_) => _rQM31());
      circleTree = MerkleTree(List.generate(n, (i) => _leafHash(circleEvals![i], circleEvals![n + i])));
      cur = List.generate(n, (i) => foldPair(circleEvals![i], circleEvals![n + i], coset.at(i).y, circleAlpha!));
    } else {
      cur = List.generate(1 << logSize, (_) => _rQM31());
    }
    for (int l = 0; l < numLayers; l++) {
      final coset = HalfCoset(logSize - l);
      cosets.add(coset);
      evals.add(cur);
      final n = cur.length;
      final leaves = List.generate(n ~/ 2, (i) => _leafHash(cur[i], cur[i + n ~/ 2]));
      trees.add(MerkleTree(leaves));
      final next = <QM31>[];
      for (int i = 0; i < n ~/ 2; i++) {
        next.add(foldPair(cur[i], cur[i + n ~/ 2], coset.at(i).x, alphas[l]));
      }
      cur = next;
    }
    evals.add(cur);
  }

  static QM31 foldPair(QM31 f0, QM31 f1, int x, QM31 alpha) {
    final g0 = f0 + f1;
    final g1 = (f0 - f1).scale(M31.inv(x));
    return g0 + alpha * g1;
  }

  List<List<int>> get roots => trees.map((t) => t.root).toList();

  /// Query data for index i0 (< 2^(logSize-1), or < 2^logSize with a circle layer).
  ({List<QM31> f0s, List<QM31> f1s, List<List<List<int>>> sibs, List<int> xinvs, QM31 finalValue,
    QM31? cf0, QM31? cf1, List<List<int>>? csibs, int? cyinv})
      query(int i0) {
    final f0s = <QM31>[], f1s = <QM31>[], sibs = <List<List<int>>>[], xinvs = <int>[];
    var i = i0;
    QM31? cf0, cf1;
    List<List<int>>? csibs;
    int? cyinv;
    if (circle) {
      final n = 1 << logSize;
      cf0 = circleEvals![i];
      cf1 = circleEvals![n + i];
      csibs = circleTree!.path(i);
      cyinv = M31.inv(HalfCoset(logSize).at(i).y);
      i = i % (n ~/ 2);
    }
    for (int l = 0; l < numLayers; l++) {
      final n = evals[l].length;
      f0s.add(evals[l][i]);
      f1s.add(evals[l][i + n ~/ 2]);
      sibs.add(trees[l].path(i));
      xinvs.add(M31.inv(cosets[l].at(i).x));
      final d = FriQueryVerifierGen.depthAt(logSize, l);
      i = i % (1 << (d - 1));
    }
    // Final value: output of the last fold at the last layer's index.
    var iLast = circle ? i0 % (1 << (logSize - 1)) : i0;
    for (int l = 0; l < numLayers - 1; l++) {
      iLast = iLast % (1 << (FriQueryVerifierGen.depthAt(logSize, l) - 1));
    }
    return (f0s: f0s, f1s: f1s, sibs: sibs, xinvs: xinvs, finalValue: evals[numLayers][iLast],
            cf0: cf0, cf1: cf1, csibs: csibs, cyinv: cyinv);
  }
}

int _scriptBytes(void Function(StackEmitter e) emit, {List<String> initial = const []}) {
  final b = ScriptBuilder();
  final e = StackEmitter(b, initial: initial);
  emit(e);
  return b.build().buffer.length;
}

// ---------------------------------------------------------------------------

void main() {
  group('M31 reference', () {
    test('inverse and pow', () {
      for (int i = 0; i < 20; i++) {
        final a = _rM31() + 1;
        expect(M31.mul(a, M31.inv(a)), 1);
      }
      expect(M31.pow(3, 0), 1);
    });

    test('circle generator has order 2^31', () {
      expect(CirclePoint.generator.isOnCircle, isTrue);
      expect(CirclePoint.generator.pow(1 << 31), CirclePoint.identity);
      expect(CirclePoint.generator.pow(1 << 30), isNot(CirclePoint.identity));
      expect(CirclePoint.subgroupGen(5).pow(32), CirclePoint.identity);
      expect(CirclePoint.subgroupGen(5).pow(16), isNot(CirclePoint.identity));
    });

    test('half coset pairing and doubling properties', () {
      final c = HalfCoset(6);
      final n = c.size;
      final pts = c.points;
      for (int i = 0; i < n ~/ 2; i++) {
        expect(pts[i + n ~/ 2].x, M31.neg(pts[i].x));
      }
      // Quarter turn multiplies by (0, ±1), so x(i + n/4) = ±y(i). Only the
      // square matters for the twiddle recurrence.
      for (int i = 0; i < n ~/ 4; i++) {
        final xq = pts[i + n ~/ 4].x;
        expect(M31.mul(xq, xq), M31.mul(pts[i].y, pts[i].y));
      }
      final dbl = c.doubled;
      for (int i = 0; i < n ~/ 2; i++) {
        expect(pts[i].double_(), dbl.at(i));
      }
      // twiddle recurrence used by the script: x_next = ±(2x^2 - 1)
      for (int i = 0; i < n ~/ 2; i++) {
        final half = n ~/ 4;
        final topBit = i ~/ half;
        final iNext = i % half;
        var t = M31.sub(M31.mul(2, M31.mul(pts[i].x, pts[i].x)), 1);
        if (topBit == 1) t = M31.neg(t);
        expect(dbl.at(iNext).x, t);
      }
    });
  });

  group('M31 / QM31 script ops', () {
    test('QM31 mul matches reference (10 random)', () {
      for (int i = 0; i < 10; i++) {
        final a = _rQM31(), c = _rQM31();
        final expected = (a * c).limbs;
        final b = ScriptBuilder();
        final e = StackEmitter(b,
            initial: ['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3']);
        M31Ops.qm31Mul(e, ['a0', 'a1', 'a2', 'a3'], ['b0', 'b1', 'b2', 'b3'],
            ['r0', 'r1', 'r2', 'r3']);
        _verifyTopEquals(e, ['r0', 'r1', 'r2', 'r3'], expected);
        e.pushConst(1);
        _runTimed(_unlockNums([...a.limbs, ...c.limbs]), b.build());
      }
    });

    test('QM31 mul with unreduced signed inputs', () {
      // Feed b = limbs - p (negative) and check the reduced product matches.
      final a = _rQM31(), c = _rQM31();
      final expected = (a * c).limbs;
      final b = ScriptBuilder();
      final e = StackEmitter(b,
          initial: ['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3']);
      for (final n in ['b0', 'b1', 'b2', 'b3']) {
        e.setNonNeg(n, false);
      }
      M31Ops.qm31Mul(e, ['a0', 'a1', 'a2', 'a3'], ['b0', 'b1', 'b2', 'b3'],
          ['r0', 'r1', 'r2', 'r3']);
      _verifyTopEquals(e, ['r0', 'r1', 'r2', 'r3'], expected);
      e.pushConst(1);
      final ub = ScriptBuilder();
      for (final v in a.limbs) {
        FriQueryVerifierGen.pushNum(ub, v);
      }
      for (final v in c.limbs) {
        ub.number(v - M31.p);
      }
      _runTimed(ub.build(), b.build());
    });

    test('QM31 add / sub / scale match reference', () {
      final a = _rQM31(), c = _rQM31();
      final m = _rM31();
      final b = ScriptBuilder();
      final e = StackEmitter(b,
          initial: ['a0', 'a1', 'a2', 'a3', 'b0', 'b1', 'b2', 'b3', 'm']);
      final aN = ['a0', 'a1', 'a2', 'a3'], bN = ['b0', 'b1', 'b2', 'b3'];
      for (final n in aN) {
        e.pick(n, as: 'p$n');
      }
      for (final n in bN) {
        e.pick(n, as: 'p$n');
      }
      M31Ops.qm31Add(e, aN.map((n) => 'p$n').toList(), bN.map((n) => 'p$n').toList(), ['s0', 's1', 's2', 's3']);
      _verifyTopEquals(e, ['s0', 's1', 's2', 's3'], (a + c).limbs);
      for (final n in aN) {
        e.pick(n, as: 'p$n');
      }
      M31Ops.qm31Sub(e, aN.map((n) => 'p$n').toList(), bN, ['d0', 'd1', 'd2', 'd3']);
      _verifyTopEquals(e, ['d0', 'd1', 'd2', 'd3'], (a - c).limbs);
      M31Ops.qm31ScaleBy(e, aN, 'm', ['k0', 'k1', 'k2', 'k3'], consumeM: true);
      _verifyTopEquals(e, ['k0', 'k1', 'k2', 'k3'], a.scale(m).limbs);
      e.pushConst(1);
      _runTimed(_unlockNums([...a.limbs, ...c.limbs, m]), b.build());
    });

    test('inverse hint accepted, wrong hint rejected', () {
      final x = _rM31() + 1;
      SVScript lock() {
        final b = ScriptBuilder();
        final e = StackEmitter(b, initial: ['x', 'xi']);
        M31Ops.verifyInverse(e, 'x', 'xi', consumeX: true);
        e.pushConst(1);
        return b.build();
      }
      _runTimed(_unlockNums([x, M31.inv(x)]), lock());
      expect(() => _runTimed(_unlockNums([x, M31.inv(x) + 1]), lock()),
          throwsA(isA<ScriptException>()));
    });
  });

  group('FRI components', () {
    test('fold step matches reference (10 random)', () {
      for (int i = 0; i < 10; i++) {
        final f0 = _rQM31(), f1 = _rQM31(), alpha = _rQM31();
        final x = _rM31() + 1;
        final expected = FriReference.foldPair(f0, f1, x, alpha).limbs;
        final b = ScriptBuilder();
        final f0N = ['f0', 'f1', 'f2', 'f3'], f1N = ['g0', 'g1', 'g2', 'g3'];
        final alN = ['a0', 'a1', 'a2', 'a3'];
        final e = StackEmitter(b, initial: [...f0N, ...f1N, 'xi', ...alN]);
        FriFoldScriptGen.emitFoldLine(e, f0N, f1N, 'xi', alN, ['o0', 'o1', 'o2', 'o3']);
        _verifyTopEquals(e, ['o0', 'o1', 'o2', 'o3'], expected);
        e.pushConst(1);
        _runTimed(_unlockNums([...f0.limbs, ...f1.limbs, M31.inv(x), ...alpha.limbs]), b.build());
      }
    });

    test('Merkle path depth 6 verifies, tampered sibling fails', () {
      final leaves = List.generate(64, (_) => _sha([_rng.nextInt(256)]));
      final tree = MerkleTree(leaves);
      final leaf = 37;
      final path = tree.path(leaf);
      SVScript lock() {
        final b = ScriptBuilder();
        final sibs = List.generate(6, (k) => 's$k');
        final e = StackEmitter(b, initial: ['leaf', ...sibs, 'idx']);
        e.pick('idx', as: 'ic');
        FriFoldScriptGen.emitMerklePath(e, 'leaf', sibs, 'ic');
        e.equalVerifyData(tree.root);
        e.drop();
        e.pushConst(1);
        return b.build();
      }
      SVScript unlock(List<List<int>> p) {
        final b = ScriptBuilder();
        b.addData(Uint8List.fromList(leaves[leaf]));
        for (final s in p) {
          b.addData(Uint8List.fromList(s));
        }
        FriQueryVerifierGen.pushNum(b, leaf);
        return b.build();
      }
      _runTimed(unlock(path), lock());
      final bad = [...path];
      bad[2] = _sha([1, 2, 3]);
      expect(() => _runTimed(unlock(bad), lock()), throwsA(isA<ScriptException>()));
    });

    test('domain point x from index matches coset', () {
      final coset = HalfCoset(9);
      for (final i in [0, 1, 2, 77, 128, 255]) {
        final b = ScriptBuilder();
        final e = StackEmitter(b, initial: ['idx']);
        FriFoldScriptGen.emitDomainPointX(e, coset, 'idx', 8, as: 'x');
        e.numEqualVerifyConst(coset.at(i).x);
        e.drop();
        e.pushConst(1);
        _runTimed(_unlockNums([i]), b.build());
      }
    });
  });

  group('FRI verifier with circle-to-line first layer', () {
    const logSize = 13; // half coset 8192 points, circle domain 16384; circle depth 13
    const numLayers = 9; // line depths 12 .. 4
    late FriReference ref;

    setUpAll(() {
      ref = FriReference(logSize, numLayers, List.generate(numLayers, (_) => _rQM31()),
          circle: true, circleAlpha: _rQM31());
    });

    SVScript lockFor(int i) => FriQueryVerifierGen.generate(
          logSize: logSize,
          numLayers: numLayers,
          roots: ref.roots,
          alphas: ref.alphas,
          expectedFinal: ref.query(i).finalValue,
          circleFirst: true,
          circleRoot: ref.circleTree!.root,
          circleAlpha: ref.circleAlpha,
        );

    SVScript unlockFor(int i, {QM31? tamperCf1}) {
      final q = ref.query(i);
      return FriQueryVerifierGen.buildUnlock(
          f0s: q.f0s, f1s: q.f1s, siblings: q.sibs, xinvs: q.xinvs, index: i,
          circleF0: q.cf0, circleF1: tamperCf1 ?? q.cf1, circleSiblings: q.csibs, circleYinv: q.cyinv);
    }

    test('valid queries pass (both halves of the circle index range)', () {
      for (final i in [0, 3, 4095, 4096, 7777, 8191]) {
        _runTimed(unlockFor(i), lockFor(i));
      }
    });

    test('tampered circle opening fails', () {
      final q = ref.query(4096);
      expect(() => _runTimed(unlockFor(4096, tamperCf1: q.cf1! + QM31.one), lockFor(4096)),
          throwsA(isA<ScriptException>()));
    });

    test('sizes', () {
      final lock = lockFor(4096);
      final unlock = unlockFor(4096);
      // Same domain without the circle layer, for the marginal cost.
      final refLine = FriReference(logSize, numLayers, ref.alphas);
      final lineOnly = FriQueryVerifierGen.generate(
          logSize: logSize, numLayers: numLayers, roots: refLine.roots,
          alphas: refLine.alphas, expectedFinal: refLine.query(1).finalValue);
      final us = _runTimed(unlock, lock);
      print('--- circle-first query verifier: circle depth $logSize + $numLayers line layers ---');
      print('  locking script         : ${lock.buffer.length} bytes');
      print('  line-only, same layers : ${lineOnly.buffer.length} bytes');
      print('  circle layer marginal  : ${lock.buffer.length - lineOnly.buffer.length} bytes');
      print('  unlocking script       : ${unlock.buffer.length} bytes');
      print('  interp time            : ${(us / 1000).toStringAsFixed(1)} ms');
    });
  });

  group('FRI single-query verifier', () {
    const logSize = 14; // 16384 points, 8192 leaves at layer 0 (depth 13)
    const numLayers = 10; // depths 13 .. 4
    late FriReference ref;
    late SVScript lock;
    late int lockBytes;

    setUpAll(() {
      final alphas = List.generate(numLayers, (_) => _rQM31());
      ref = FriReference(logSize, numLayers, alphas);
      // Build against a specific query so the final constant is fixed.
      final q = ref.query(5123);
      lock = FriQueryVerifierGen.generate(
        logSize: logSize,
        numLayers: numLayers,
        roots: ref.roots,
        alphas: alphas,
        expectedFinal: q.finalValue,
      );
      lockBytes = lock.buffer.length;
    });

    test('valid query passes; report sizes and time', () {
      final q = ref.query(5123);
      final unlock = FriQueryVerifierGen.buildUnlock(
          f0s: q.f0s, f1s: q.f1s, siblings: q.sibs, xinvs: q.xinvs, index: 5123);
      final us = _runTimed(unlock, lock);

      // Component sizes (script bytes), measured in isolation.
      final f0N = ['f0', 'f1', 'f2', 'f3'], f1N = ['g0', 'g1', 'g2', 'g3'];
      final alN = ['a0', 'a1', 'a2', 'a3'];
      final qm31MulReduced = _scriptBytes(
          (e) => M31Ops.qm31Mul(e, f0N, f1N, ['r0', 'r1', 'r2', 'r3']),
          initial: [...f0N, ...f1N]);
      final qm31MulLazy = _scriptBytes(
          (e) => M31Ops.qm31Mul(e, f0N, f1N, ['r0', 'r1', 'r2', 'r3'], reduceOut: false),
          initial: [...f0N, ...f1N]);
      final qm31Add = _scriptBytes(
          (e) => M31Ops.qm31Add(e, f0N, f1N, ['r0', 'r1', 'r2', 'r3']),
          initial: [...f0N, ...f1N]);
      final fold = _scriptBytes(
          (e) => FriFoldScriptGen.emitFoldLine(e, f0N, f1N, 'xi', alN, ['o0', 'o1', 'o2', 'o3']),
          initial: [...f0N, ...f1N, 'xi', ...alN]);
      final leaf = _scriptBytes((e) => FriFoldScriptGen.emitLeafHash(e, f0N, f1N),
          initial: [...f0N, ...f1N]);
      final sibs13 = List.generate(13, (k) => 's$k');
      final merkle13 = _scriptBytes((e) {
        e.pick('idx', as: 'ic');
        FriFoldScriptGen.emitMerklePath(e, 'leaf', sibs13, 'ic');
      }, initial: ['leaf', ...sibs13, 'idx']);
      final twiddle = _scriptBytes((e) => FriFoldScriptGen.emitTwiddleStep(e, 'x', 'tb'),
          initial: ['x', 'tb']);
      final domain13 = _scriptBytes(
          (e) => FriFoldScriptGen.emitDomainPointX(e, HalfCoset(logSize), 'idx', 13),
          initial: ['idx']);
      final select = _scriptBytes(
          (e) => FriFoldScriptGen.emitSelectCompare(e, ['o0', 'o1', 'o2', 'o3'], f0N, f1N, 'tb'),
          initial: [...f0N, ...f1N, 'tb', 'o0', 'o1', 'o2', 'o3']);
      final m31MulLazy = _scriptBytes((e) { e.pick('a'); e.pick('b'); e.mul(); }, initial: ['a', 'b']);
      final m31MulReduced = _scriptBytes((e) { e.pick('a'); e.pick('b'); e.mul(); e.reduce(); }, initial: ['a', 'b']);

      final perQuery26 = lockBytes * 26;
      print('--- component sizes (bytes) ---');
      print('  M31 mul (lazy / reduced)        : $m31MulLazy / $m31MulReduced');
      print('  QM31 mul (lazy / reduced)       : $qm31MulLazy / $qm31MulReduced');
      print('  QM31 add                        : $qm31Add');
      print('  fold_line step                  : $fold');
      print('  leaf hash (8 limbs)             : $leaf');
      print('  Merkle path depth 13            : $merkle13  (${(merkle13 / 13).toStringAsFixed(1)}/level)');
      print('  twiddle step                    : $twiddle');
      print('  domain point, 13 bits           : $domain13  (${(domain13 / 13).toStringAsFixed(1)}/bit)');
      print('  select+compare next layer       : $select');
      print('--- single query, $numLayers layers (depths 13..4) ---');
      print('  locking script                  : $lockBytes bytes');
      print('  unlocking script                : ${unlock.buffer.length} bytes');
      print('  interp time                     : ${(us / 1000).toStringAsFixed(1)} ms');
      print('  x26 queries (FRI only, naive)   : ${(perQuery26 / 1024).toStringAsFixed(0)} KB lock');
    });

    test('tampered opening fails', () {
      final q = ref.query(5123);
      final badF1 = [...q.f1s];
      badF1[3] = badF1[3] + QM31.one;
      final unlock = FriQueryVerifierGen.buildUnlock(
          f0s: q.f0s, f1s: badF1, siblings: q.sibs, xinvs: q.xinvs, index: 5123);
      expect(() => _runTimed(unlock, lock), throwsA(isA<ScriptException>()));
    });

    test('wrong index fails', () {
      final q = ref.query(5123);
      final unlock = FriQueryVerifierGen.buildUnlock(
          f0s: q.f0s, f1s: q.f1s, siblings: q.sibs, xinvs: q.xinvs, index: 5122);
      expect(() => _runTimed(unlock, lock), throwsA(isA<ScriptException>()));
    });

    test('several other query indices verify against their own final value', () {
      for (final i in [0, 1, 4095, 4096, 8191]) {
        final q = ref.query(i);
        final l = FriQueryVerifierGen.generate(
          logSize: logSize,
          numLayers: numLayers,
          roots: ref.roots,
          alphas: ref.alphas,
          expectedFinal: q.finalValue,
        );
        final unlock = FriQueryVerifierGen.buildUnlock(
            f0s: q.f0s, f1s: q.f1s, siblings: q.sibs, xinvs: q.xinvs, index: i);
        _runTimed(unlock, l);
      }
    });
  });
}
