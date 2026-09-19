import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/stark_kernels.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/proof_hash.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/deep_quotient_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';

/// The native kernels must compute exactly what the Dart kernels compute.
void main() {
  final native = StarkKernels.tryLoad();
  final dart = DartKernels();
  final skip = native == null
      ? 'native kernels not built: cargo build --release --manifest-path native/stark_kernels/Cargo.toml'
      : null;
  if (native != null) print('native kernels: ${native.path}');

  final rng = Random(11);
  int r31() => rng.nextInt(M31.p);
  Uint32List col(int n) => Uint32List.fromList(List.generate(n, (_) => r31()));
  QM31 rq() => QM31.fromLimbs(r31(), r31(), r31(), r31());

  test('sha256 matches package:crypto', () {
    for (final len in [0, 1, 31, 32, 55, 56, 63, 64, 65, 100, 128, 232, 1000]) {
      final data = Uint8List.fromList(List.generate(len, (_) => rng.nextInt(256)));
      expect(native!.sha256(data), crypto.sha256.convert(data).bytes, reason: 'length $len');
    }
  }, skip: skip);

  List<Uint32List> lists(Columns c) => [for (int j = 0; j < c.count; j++) c.column(j)];

  test('interpolate, evaluate and commit match', () {
    for (final m in [2, 5, 9]) {
      final n = 1 << (m + 1);
      final vals = [for (int j = 0; j < 3; j++) col(n)];
      final cd = dart.interpolateColumns(vals, m), cn = native!.interpolateColumns(vals, m);
      expect(cn, cd, reason: 'interpolate m=$m');
      expect(native.evaluateColumns(cd, m), dart.evaluateColumns(cd, m), reason: 'evaluate m=$m');
      // low-degree extension: shorter coefficient vectors onto a larger domain, plus the commitment
      final short = [for (final c in cd) Uint32List.fromList(c.sublist(0, n ~/ 4))];
      final (evD, treeD) = dart.commitColumns(short, m + 2, const Sha256ProofHash());
      final (evN, treeN) = native.commitColumns(short, m + 2, const Sha256ProofHash());
      expect(lists(evN), lists(evD), reason: 'LDE m=$m');
      expect(evN.at(1, 5), evD.at(1, 5));
      evN.release();
      expect(() => evN.at(0, 0), throwsStateError);
      expect(treeN.root, treeD.root, reason: 'root m=$m');
      expect(treeN.depth, treeD.depth);
      for (final leaf in [0, 1, (1 << (m + 2)) - 1, rng.nextInt(1 << (m + 2))]) {
        expect(treeN.path(leaf), treeD.path(leaf), reason: 'path $leaf m=$m');
      }
    }
  }, skip: skip);

  test('DEEP quotients, folds and pair trees match', () {
    for (final m in [3, 7, 11]) {
      final n = 1 << (m + 1), mm = 1 << m;
      final cols = [for (int j = 0; j < 5; j++) col(n)];
      final k = DeepConstants(rq(), rq(), rq(), rq(), rq(), rq(), [for (int j = 0; j < 5; j++) rq()]);
      // two sets, the native ones stored natively; a Dart set is copied in for the call
      final setsD = [DartColumns(cols.sublist(0, 2)), DartColumns(cols.sublist(2))];
      final stored = native!.storeColumns(cols.sublist(0, 2));
      final setsN = [stored, DartColumns(cols.sublist(2))];
      final qD = dart.deepQuotients(k, setsD, m), qN = native.deepQuotients(k, setsN, m);
      expect(qN, qD, reason: 'deep m=$m');
      final k2 = DeepConstants(rq(), rq(), rq(), rq(), rq(), rq(), [for (int j = 0; j < 5; j++) rq()]);
      final accD = Uint32List.fromList(qD), accN = Uint32List.fromList(qN);
      dart.deepQuotients(k2, setsD, m, into: accD);
      native.deepQuotients(k2, setsN, m, into: accN);
      stored.release();
      expect(accN, accD, reason: 'deep accumulate m=$m');
      final alpha = rq();
      expect(native.circleFold(qD, m, alpha), dart.circleFold(qD, m, alpha), reason: 'circle fold m=$m');
      final intoD = Uint32List.fromList(qD.sublist(0, 4 * mm)), intoN = Uint32List.fromList(intoD);
      dart.circleFold(accD, m, alpha, into: intoD);
      native.circleFold(accD, m, alpha, into: intoN);
      expect(intoN, intoD, reason: 'circle fold accumulate m=$m');
      // a line layer of length 2^m (4 limbs each)
      final layer = Uint32List.fromList(qD.sublist(0, 4 * mm));
      expect(native.lineFold(layer, m, alpha), dart.lineFold(layer, m, alpha), reason: 'line fold m=$m');
      final tD = dart.merklePairs(layer, m, const Sha256ProofHash()), tN = native.merklePairs(layer, m, const Sha256ProofHash());
      expect(tN.root, tD.root, reason: 'pairs root m=$m');
      expect(tN.path(mm ~/ 2 - 1), tD.path(mm ~/ 2 - 1), reason: 'pairs path m=$m');
    }
  }, skip: skip);

  // a pool deposit at small parameters is a full trace for the real AIR
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  PoolSpendWitness witness() {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 1000, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 25, rho: lanes(3), rcm: lanes(4));
    return PoolSpendAir.witness(da, db, oa, ob, -1025, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
  }

  test('proofs are byte-identical at test parameters', () {
    const p = StarkParams(
        logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    final pd = StarkProver.prove(p, air, w.rows, rng: Random(3), kernels: dart);
    final pn = StarkProver.prove(p, air, w.rows, rng: Random(3), kernels: native);
    final gen = StarkVerifierGen(p, air);
    expect(gen.buildUnlock(pn).buffer, gen.buildUnlock(pd).buffer);
  }, skip: skip, timeout: const Timeout(Duration(minutes: 5)));

  test('verifier AIR proofs (aux constraints, pre columns, native composition) are byte-identical', () {
    const p2 = Poseidon2ProofHash();
    const inner = StarkParams(
        logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    // blowup 4 (the kernel evaluates the coefficient columns itself) and
    // blowup 8 = expansion (the committed evaluations are reused)
    const outers = [
      StarkParams(logTrace: 14, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1),
      StarkParams(logTrace: 14, logBlowup: 3, logExpand: 3, logFinal: 4, numQueries: 2, grindBytes: 1),
    ];
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    final innerProof = StarkProver.prove(inner, air, w.rows, rng: Random(5), hash: p2);
    final program = VerifierProgram.compile(InnerShape(inner, air), 14);
    final rows = program.witness(innerProof);
    final vAir = program.air(VerifierProgram.nodeDigestOf(air, innerProof.preRoot));
    expect(vAir.mainProgram(), isNotNull);
    expect(vAir.auxProgram(), isNotNull);
    for (final outer in outers) {
      final sw = Stopwatch()..start();
      final pn = StarkProver.prove(outer, vAir, rows, rng: Random(6), kernels: native, hash: p2, verbose: true);
      final tn = sw.elapsedMilliseconds;
      sw.reset();
      final pd = StarkProver.prove(outer, vAir, rows, rng: Random(6), kernels: dart, hash: p2);
      print('  verifier AIR at 2^14 blowup ${1 << outer.logBlowup}: native ${tn} ms, dart ${sw.elapsedMilliseconds} ms');
      expect(pn.preRoot, pd.preRoot);
      expect(pn.compRoot, pd.compRoot);
      expect(pn.compAtZ, pd.compAtZ);
      expect(pn.friRoots, pd.friRoots);
      expect(pn.finalCoefs, pd.finalCoefs);
      expect(pn.nonce, pd.nonce);
    }
  }, skip: skip, timeout: const Timeout(Duration(minutes: 5)));

  test('production parameters: byte-identical, timed', () {
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    const p = PoolSpendAir.productionParams;
    final sw = Stopwatch()..start();
    final pn = StarkProver.prove(p, air, w.rows, rng: Random(4), kernels: native, verbose: true);
    final nativeMs = sw.elapsedMilliseconds;
    sw.reset();
    final pd = StarkProver.prove(p, air, w.rows, rng: Random(4), kernels: dart);
    final dartMs = sw.elapsedMilliseconds;
    print('  prover: native $nativeMs ms, dart $dartMs ms');
    final gen = StarkVerifierGen(p, air);
    expect(gen.buildUnlock(pn).buffer, gen.buildUnlock(pd).buffer);
  }, skip: skip, timeout: const Timeout(Duration(minutes: 5)));
}
