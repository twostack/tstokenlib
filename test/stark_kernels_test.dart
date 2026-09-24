import 'dart:io';
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
import 'package:tstokenlib/src/script_gen/fiat_shamir_script_gen.dart';
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

  // The GPU backend is asked for by the environment, so every comparison
  // above runs against the GPU when it is on and against the CPU kernels when
  // it is not; the two tests at the end pin that it really is on and that a
  // GPU proof, a CPU-native proof and a Dart proof are the same bytes.
  final wantGpu = const ['1', 'true'].contains(Platform.environment[StarkKernels.gpuEnvVar]);
  if (native != null) print('GPU backend: ${native.gpuStatus}');
  final gpuSkip = skip ??
      (!wantGpu
          ? 'GPU backend not asked for: set ${StarkKernels.gpuEnvVar}=1 (build with --features metal)'
          : native!.gpuEnabled
              ? null
              : 'GPU backend ${native.gpuStatus}');

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

  test('grinding finds the same nonce as the Dart loop, past the first block', () {
    // The verifier takes any nonce that meets the target, so a parallel
    // search that returned whichever hit it found first would still produce
    // proofs that verify while no longer matching the Dart prover's. The
    // search hands each thread a block of 2^14 nonces, so a test only
    // exercises that if the smallest nonce lies past the first block; the
    // existing byte-identity suites grind one byte, where it never does.
    const block = 1 << 14;

    /// The Dart loop's answer, with the kernels' search taken out of the way.
    List<int> byHand(List<int> Function() grind, void Function() off, void Function() on) {
      off();
      try {
        return grind();
      } finally {
        on();
      }
    }

    // SHA256: two zero bytes is 2^16 expected tries, four blocks in
    final shaSaved = TranscriptRef.nativeGrind;
    expect(shaSaved, isNotNull, reason: 'the native kernels install a search when they load');
    final ts = TranscriptRef()..absorb(List<int>.generate(32, (i) => i * 7 + 1));
    final want = byHand(() => ts.grind(2), () => TranscriptRef.nativeGrind = null, () => TranscriptRef.nativeGrind = shaSaved);
    final wantN = want[0] | (want[1] << 8) | (want[2] << 16) | (want[3] << 24);
    print('  sha256 grind: smallest nonce $wantN (${(wantN / block).floor()} blocks in)');
    expect(wantN, greaterThan(block), reason: 'the case worth testing is a nonce past the first block');
    expect(ts.grind(2), want, reason: 'the kernel returns the smallest nonce, not the first hit');
    expect(native!.grindSha(ts.state, 2), wantN);

    // Poseidon2: 14 bits, and a state whose answer is far enough out
    final p2Saved = Poseidon2Transcript.nativeGrind;
    expect(p2Saved, isNotNull);
    Poseidon2Transcript? far;
    List<int>? farWant;
    for (int seed = 1; seed < 40 && far == null; seed++) {
      final t = Poseidon2Transcript()..absorb(List<int>.generate(8, (i) => seed * 1000 + i));
      final w = byHand(() => t.grind(2), () => Poseidon2Transcript.nativeGrind = null, () => Poseidon2Transcript.nativeGrind = p2Saved);
      if (w[0] > block) {
        far = t;
        farWant = w;
      }
    }
    expect(far, isNotNull, reason: 'a state whose smallest nonce is past the first block');
    print('  poseidon2 grind: smallest nonce ${farWant![0]} (${(farWant[0] / block).floor()} blocks in)');
    expect(far!.grind(2), farWant, reason: 'the kernel returns the smallest nonce, not the first hit');
    expect(native.grindP2(far.state, Poseidon2Transcript.grindBits(2)), farWant[0]);
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
      expect(accN, accD, reason: 'deep accumulate m=$m');

      // the fused pass: group B over all five columns, group C over the
      // first two, both in one read of the shared columns. It must equal the
      // two calls it replaces, which is exactly what accD holds when k2's
      // weights cover only the first set.
      final kc = DeepConstants(rq(), rq(), rq(), rq(), rq(), rq(), [for (int j = 0; j < 2; j++) rq()]);
      final wantD = dart.deepQuotients(kc, [setsD[0]], m, into: Uint32List.fromList(qD));
      expect(dart.deepQuotientsPair(k, kc, setsD, m), wantD, reason: 'dart fused pair m=$m');
      expect(native.deepQuotientsPair(k, kc, setsN, m), wantD, reason: 'native fused pair m=$m');
      stored.release();
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

  test('the kernels under test are the GPU ones', () {
    expect(native!.gpuEnabled, isTrue);
    expect(native.name, 'native+metal');
  }, skip: gpuSkip);

  test('GPU proofs equal the CPU native proofs and the Dart proofs', () {
    const p2 = Poseidon2ProofHash();
    const inner = StarkParams(
        logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
    const outer = StarkParams(logTrace: 14, logBlowup: 3, logExpand: 3, logFinal: 4, numQueries: 2, grindBytes: 1);
    final w = witness();
    final air = PoolSpendAir.air(w.publics);
    final innerProof = StarkProver.prove(inner, air, w.rows, rng: Random(5), hash: p2);
    final program = VerifierProgram.compile(InnerShape(inner, air), 14);
    final rows = program.witness(innerProof);
    final vAir = program.air(VerifierProgram.nodeDigestOf(air, innerProof.preRoot));

    StarkProof proveWith(bool gpu) {
      native!.enableGpu(gpu);
      expect(native.gpuEnabled, gpu);
      return StarkProver.prove(outer, vAir, rows, rng: Random(6), kernels: native, hash: p2);
    }

    final onGpu = proveWith(true);
    final onCpu = proveWith(false);
    native!.enableGpu(true); // leave it as the suite found it
    final inDart = StarkProver.prove(outer, vAir, rows, rng: Random(6), kernels: dart, hash: p2);
    for (final (what, other) in [('the CPU kernels', onCpu), ('the Dart kernels', inDart)]) {
      expect(onGpu.traceRoot, other.traceRoot, reason: 'trace root against $what');
      expect(onGpu.preRoot, other.preRoot, reason: 'preprocessed root against $what');
      expect(onGpu.compRoot, other.compRoot, reason: 'composition root against $what');
      expect(onGpu.friRoots, other.friRoots, reason: 'FRI roots against $what');
      expect(onGpu.finalCoefs, other.finalCoefs, reason: 'final coefficients against $what');
      expect(onGpu.nonce, other.nonce, reason: 'grinding nonce against $what');
    }
  }, skip: gpuSkip, timeout: const Timeout(Duration(minutes: 5)));

  // An installed program is a compiled executable with the library beside it
  // (a .deb's /opt/<app>/bin) or in ../lib (a tarball), run from anywhere,
  // with no source tree for the other candidates to find.
  group('beside the executable', () {
    late Directory tmp;
    late String probe;
    setUpAll(() async {
      if (native == null) return;
      tmp = Directory.systemTemp.createTempSync('kernels_probe');
      Directory('${tmp.path}/bin').createSync();
      probe = '${tmp.path}/bin/probe';
      final r = await Process.run(Platform.resolvedExecutable,
          ['compile', 'exe', 'test/support/kernels_probe.dart', '-o', probe]);
      if (r.exitCode != 0) throw StateError('compile failed: ${r.stderr}');
    });
    tearDownAll(() {
      if (native != null) tmp.deleteSync(recursive: true);
    });

    // Runs the probe from the temporary directory, where the working
    // directory search and the package config find nothing.
    Future<String> run({String? envLib}) async {
      final env = Map.of(Platform.environment)..remove(StarkKernels.envVar);
      if (envLib != null) env[StarkKernels.envVar] = envLib;
      final r = await Process.run(probe, const [],
          workingDirectory: tmp.path, environment: env, includeParentEnvironment: false);
      return (r.stdout as String).trim();
    }

    void place(String dir) {
      Directory(dir).createSync(recursive: true);
      File(native!.path).copySync('$dir/${StarkKernels.fileName}');
    }

    void clear() {
      for (final d in ['bin', 'lib']) {
        final f = File('${tmp.path}/$d/${StarkKernels.fileName}');
        if (f.existsSync()) f.deleteSync();
      }
    }

    test('finds nothing when no library is installed', () async {
      clear();
      expect(await run(), 'none');
    }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));

    test('finds the library in the executable\'s directory', () async {
      clear();
      place('${tmp.path}/bin');
      expect(await run(), File('${tmp.path}/bin/${StarkKernels.fileName}').resolveSymbolicLinksSync());
    }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));

    test('finds the library in ../lib from the executable', () async {
      clear();
      place('${tmp.path}/lib');
      expect(await run(), endsWith('/lib/${StarkKernels.fileName}'));
    }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));

    test('an explicit STARK_KERNELS_LIB still wins', () async {
      clear();
      place('${tmp.path}/bin');
      expect(await run(envLib: native!.path), native.path);
    }, skip: skip, timeout: const Timeout(Duration(minutes: 2)));
  });
}
