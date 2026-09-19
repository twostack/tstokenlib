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

import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:ffi/ffi.dart';
import 'circle_fft.dart';
import 'm31.dart';
import 'proof_hash.dart';
import '../script_gen/deep_quotient_script_gen.dart' show DeepConstants;

/// The heavy arithmetic of the prover, behind one interface with two
/// implementations: [DartKernels] (the reference, plain Dart) and
/// [StarkKernels] (the Rust crate in `native/stark_kernels`, via FFI). Both
/// compute exactly the same values, so proofs are byte-identical whichever
/// one the prover is given.
///
/// Conventions: a QM31 array is a `Uint32List` of 4 limbs per element
/// (`[c0.a, c0.b, c1.a, c1.b]`); a domain of size 2^(m+1) is in twin layout
/// (position i < M holds HalfCoset(m).at(i), position M + i its conjugate).
abstract class ProverKernels {
  String get name;

  /// Column values in twin layout (2^(m+1) each) -> coefficient columns.
  List<Uint32List> interpolateColumns(List<Uint32List> vals, int m);

  /// Coefficient columns (any power-of-two length <= 2^(m+1), zero-padded)
  /// -> value columns on HalfCoset(m) ∪ conj.
  List<Uint32List> evaluateColumns(List<Uint32List> coefs, int m);

  /// [evaluateColumns] plus the Merkle commitment under [hash], whose leaf
  /// i is `hash.leaf` of the 2k lanes `ev[j][i]`, `ev[j][M + i]`.
  (List<Uint32List>, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash);

  /// DEEP quotients of value columns on HalfCoset(m) ∪ conj at every
  /// position: `(c Σ w_j col_j - A y - B) / (dA x + dB y + dC)`. Added into
  /// [into] when given (and returned), else a fresh array.
  Uint32List deepQuotients(DeepConstants k, List<Uint32List> cols, int m, {Uint32List? into});

  /// Circle fold of a twin-layout QM31 array on HalfCoset(m):
  /// `(q_i + q_{M+i}) + alpha (q_i - q_{M+i}) / y_i`; accumulates into [into].
  Uint32List circleFold(Uint32List q, int m, QM31 alpha, {Uint32List? into});

  /// Line fold of a layer of length 2^logLen over HalfCoset(logLen):
  /// `(f_i + f_{i+h}) + alpha (f_i - f_{i+h}) / x_i`.
  Uint32List lineFold(Uint32List cur, int logLen, QM31 alpha);

  /// Merkle commitment under [hash] of a layer of length 2^logLen whose
  /// leaf i is `hash.leaf` of the 8 limbs of `cur[i]`, `cur[i + h]`.
  MerkleCommitment merklePairs(Uint32List cur, int logLen, ProofHash hash);

  /// The default: the native kernels when the library is built, else Dart.
  static ProverKernels get best => StarkKernels.tryLoad() ?? DartKernels();
}

/// A Merkle tree: root, depth and authentication paths. Digests are
/// `List<int>`: bytes (SHA256) or lanes (Poseidon2).
abstract class MerkleCommitment {
  List<int> get root;
  int get depth;
  List<List<int>> path(int leaf);
}

/// Merkle tree over pre-hashed leaves with a pluggable node function
/// (SHA256(left || right) by default).
class MerkleTree implements MerkleCommitment {
  final List<List<List<int>>> levels;

  MerkleTree(List<List<int>> leaves, {List<int> Function(List<int>, List<int>)? node}) : levels = [leaves] {
    final nodeFn = node ?? _shaNode;
    while (levels.last.length > 1) {
      final prev = levels.last;
      levels.add(List<List<int>>.generate(prev.length ~/ 2, (i) => nodeFn(prev[2 * i], prev[2 * i + 1])));
    }
  }

  static final Uint8List _buf = Uint8List(64);
  static List<int> _shaNode(List<int> l, List<int> r) {
    _buf.setRange(0, 32, l);
    _buf.setRange(32, 64, r);
    return Uint8List.fromList(crypto.sha256.convert(_buf).bytes);
  }

  @override
  List<int> get root => levels.last[0];
  @override
  int get depth => levels.length - 1;

  @override
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

/// A Merkle tree in the flat layout the native kernels write: the leaf
/// level, then each level above it, the root last; [unit] entries per node
/// (32 bytes for SHA256, 8 lanes for Poseidon2) in a typed list.
class FlatMerkleTree implements MerkleCommitment {
  final List<int> data;
  final int leaves, unit;
  final List<int> _offsets = [];

  FlatMerkleTree(this.data, this.leaves, {this.unit = 32}) {
    var off = 0, len = leaves;
    while (true) {
      _offsets.add(off);
      if (len == 1) break;
      off += unit * len;
      len ~/= 2;
    }
    if (data.length != (2 * leaves - 1) * unit) throw ArgumentError('tree length');
  }

  static int byteLength(int leaves) => (2 * leaves - 1) * 32;
  static int laneLength(int leaves) => (2 * leaves - 1) * 8;

  List<int> node(int level, int i) {
    final o = _offsets[level] + unit * i;
    final d = data;
    if (d is Uint8List) return Uint8List.sublistView(d, o, o + unit);
    if (d is Uint32List) return Uint32List.sublistView(d, o, o + unit);
    return d.sublist(o, o + unit);
  }

  @override
  List<int> get root => List<int>.from(node(depth, 0));
  @override
  int get depth => _offsets.length - 1;

  @override
  List<List<int>> path(int leaf) {
    final out = <List<int>>[];
    var i = leaf;
    for (int lv = 0; lv < depth; lv++) {
      out.add(List<int>.from(node(lv, i ^ 1)));
      i >>= 1;
    }
    return out;
  }
}

QM31 qAt(Uint32List a, int i) => QM31.fromLimbs(a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]);

void qSet(Uint32List a, int i, QM31 v) {
  a[4 * i] = v.c0.a;
  a[4 * i + 1] = v.c0.b;
  a[4 * i + 2] = v.c1.a;
  a[4 * i + 3] = v.c1.b;
}

Uint32List qFlat(List<QM31> vs) {
  final out = Uint32List(4 * vs.length);
  for (int i = 0; i < vs.length; i++) {
    qSet(out, i, vs[i]);
  }
  return out;
}

/// The reference kernels in plain Dart.
class DartKernels implements ProverKernels {
  @override
  String get name => 'dart';

  static QM31 foldPair(QM31 f0, QM31 f1, int twiddleInv, QM31 alpha) => (f0 + f1) + alpha * (f0 - f1).scale(twiddleInv);

  static List<QM31> batchInvQ(List<QM31> xs) {
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

  @override
  List<Uint32List> interpolateColumns(List<Uint32List> vals, int m) => [for (final c in vals) CircleFft.interpolate(c, m)];

  @override
  List<Uint32List> evaluateColumns(List<Uint32List> coefs, int m) => [for (final c in coefs) CircleFft.evaluate(c, m)];

  @override
  (List<Uint32List>, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash) {
    final ev = evaluateColumns(coefs, m);
    final k = coefs.length, mB = 1 << m;
    final lanes = List<int>.filled(2 * k, 0);
    final leaves = List<List<int>>.generate(mB, (i) {
      for (int j = 0; j < k; j++) {
        lanes[j] = ev[j][i];
        lanes[k + j] = ev[j][mB + i];
      }
      return hash.leaf(lanes);
    });
    return (ev, MerkleTree(leaves, node: hash.node));
  }

  @override
  Uint32List deepQuotients(DeepConstants k, List<Uint32List> cols, int m, {Uint32List? into}) {
    final dom = CosetTables.of(m);
    final mm = dom.size, n = 2 * mm;
    final nums = List<QM31>.filled(n, QM31.zero);
    final dens = List<QM31>.filled(n, QM31.zero);
    for (int q = 0; q < n; q++) {
      final i = q < mm ? q : q - mm;
      final px = dom.x[i];
      final py = q < mm ? dom.y[i] : M31.neg(dom.y[i]);
      var s = QM31.zero;
      for (int j = 0; j < cols.length; j++) {
        s = s + k.weights[j].scale(cols[j][q]);
      }
      nums[q] = k.c * s - k.A.scale(py) - k.B;
      dens[q] = k.dA.scale(px) + k.dB.scale(py) + k.dC;
    }
    final inv = batchInvQ(dens);
    final out = into ?? Uint32List(4 * n);
    for (int q = 0; q < n; q++) {
      final v = nums[q] * inv[q];
      qSet(out, q, into == null ? v : qAt(out, q) + v);
    }
    return out;
  }

  @override
  Uint32List circleFold(Uint32List q, int m, QM31 alpha, {Uint32List? into}) {
    final mm = 1 << m;
    final yInv = CosetTables.of(m).yInv;
    final out = into ?? Uint32List(4 * mm);
    for (int i = 0; i < mm; i++) {
      final v = foldPair(qAt(q, i), qAt(q, mm + i), yInv[i], alpha);
      qSet(out, i, into == null ? v : qAt(out, i) + v);
    }
    return out;
  }

  @override
  Uint32List lineFold(Uint32List cur, int logLen, QM31 alpha) {
    final len = 1 << logLen, h = len >> 1;
    final xInv = CosetTables.of(logLen).xInv;
    final out = Uint32List(4 * h);
    for (int i = 0; i < h; i++) {
      qSet(out, i, foldPair(qAt(cur, i), qAt(cur, h + i), xInv[i], alpha));
    }
    return out;
  }

  @override
  MerkleCommitment merklePairs(Uint32List cur, int logLen, ProofHash hash) {
    final len = 1 << logLen, h = len >> 1;
    return MerkleTree(List<List<int>>.generate(h, (i) {
      return hash.leaf([for (int l = 0; l < 4; l++) cur[4 * i + l], for (int l = 0; l < 4; l++) cur[4 * (h + i) + l]]);
    }), node: hash.node);
  }
}

// ---- FFI signatures of native/stark_kernels/src/lib.rs ----
typedef _VersionC = ffi.Uint32 Function();
typedef _VersionD = int Function();
typedef _InterpC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _InterpD = void Function(ffi.Pointer<ffi.Uint32>, int, int, ffi.Pointer<ffi.Uint32>);
typedef _EvalC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _EvalD = void Function(ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _CommitC = ffi.Void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint8>);
typedef _CommitD = void Function(ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint8>);
typedef _DeepC = ffi.Void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Uint32, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _DeepD = void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _CircleFoldC = ffi.Void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _CircleFoldD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>);
typedef _LineFoldC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _LineFoldD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint8>);
typedef _MerklePairsD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint8>);
typedef _CommitP2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>,
    ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _CommitP2D = void Function(
    ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsP2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsP2D = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _PermuteP2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _PermuteP2D = void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _ShaC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _ShaD = void Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);
typedef _KemPkC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemPkD = void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemEncapsC = ffi.Uint32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemEncapsD = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemDecapsC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemDecapsD = void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

/// The native kernels (`native/stark_kernels`, built with
/// `cargo build --release --manifest-path native/stark_kernels/Cargo.toml`).
///
/// Inputs are copied into native memory and results copied back; at the
/// sizes involved (a few MB per call) the copies are negligible next to the
/// arithmetic. Every kernel is exact, so [tryLoad] returning null (library
/// not built) only costs speed.
class StarkKernels implements ProverKernels {
  static const abiVersion = 3;
  static const envVar = 'STARK_KERNELS_LIB';

  final ffi.DynamicLibrary _lib;
  final String path;
  late final _InterpD _interp = _lib.lookupFunction<_InterpC, _InterpD>('sk_interpolate_columns');
  late final _EvalD _eval = _lib.lookupFunction<_EvalC, _EvalD>('sk_evaluate_columns');
  late final _CommitD _commit = _lib.lookupFunction<_CommitC, _CommitD>('sk_commit_columns');
  late final _DeepD _deep = _lib.lookupFunction<_DeepC, _DeepD>('sk_deep_quotients');
  late final _CircleFoldD _circleFold = _lib.lookupFunction<_CircleFoldC, _CircleFoldD>('sk_circle_fold');
  late final _LineFoldD _lineFold = _lib.lookupFunction<_LineFoldC, _LineFoldD>('sk_line_fold');
  late final _MerklePairsD _merklePairs = _lib.lookupFunction<_MerklePairsC, _MerklePairsD>('sk_merkle_pairs');
  late final _ShaD _sha = _lib.lookupFunction<_ShaC, _ShaD>('sk_sha256');
  late final _CommitP2D _commitP2 = _lib.lookupFunction<_CommitP2C, _CommitP2D>('sk_commit_columns_p2');
  late final _MerklePairsP2D _merklePairsP2 = _lib.lookupFunction<_MerklePairsP2C, _MerklePairsP2D>('sk_merkle_pairs_p2');
  late final _PermuteP2D _permuteP2 = _lib.lookupFunction<_PermuteP2C, _PermuteP2D>('sk_poseidon2_permute');
  late final _KemPkD _kemPk = _lib.lookupFunction<_KemPkC, _KemPkD>('sk_mlkem768_public_key');
  late final _KemEncapsD _kemEncaps = _lib.lookupFunction<_KemEncapsC, _KemEncapsD>('sk_mlkem768_encaps');
  late final _KemDecapsD _kemDecaps = _lib.lookupFunction<_KemDecapsC, _KemDecapsD>('sk_mlkem768_decaps');
  late final Uint32List _rc = Poseidon2ProofHash.roundConstants;
  final DartKernels _fallback = DartKernels();

  StarkKernels._(this._lib, this.path);

  @override
  String get name => 'native';

  static StarkKernels? _loaded;
  static bool _tried = false;

  /// The library file name for this platform.
  static String get fileName => Platform.isMacOS
      ? 'libstark_kernels.dylib'
      : Platform.isWindows
          ? 'stark_kernels.dll'
          : 'libstark_kernels.so';

  /// Loads the library from [path], `$STARK_KERNELS_LIB`, or the crate's
  /// release directory under the current directory or its parents. Returns
  /// null when none is found or the ABI version differs. Cached.
  static StarkKernels? tryLoad({String? path}) {
    if (path == null && _tried) return _loaded;
    final candidates = <String>[
      if (path != null) path,
      if (Platform.environment[envVar] != null) Platform.environment[envVar]!,
    ];
    var dir = Directory.current;
    for (int up = 0; up < 4; up++) {
      candidates.add('${dir.path}/native/stark_kernels/target/release/$fileName');
      dir = dir.parent;
    }
    StarkKernels? found;
    for (final c in candidates) {
      if (!File(c).existsSync()) continue;
      try {
        final lib = ffi.DynamicLibrary.open(c);
        final version = lib.lookupFunction<_VersionC, _VersionD>('sk_version')();
        if (version != abiVersion) continue;
        found = StarkKernels._(lib, c);
        break;
      } catch (_) {
        continue;
      }
    }
    if (path == null) {
      _tried = true;
      _loaded = found;
    }
    return found;
  }

  // ---- buffers ----
  static ffi.Pointer<ffi.Uint32> _upload(List<Uint32List> cols, int len) {
    final p = calloc<ffi.Uint32>(cols.length * len);
    final view = p.asTypedList(cols.length * len);
    for (int j = 0; j < cols.length; j++) {
      if (cols[j].length != len) throw ArgumentError('column $j has ${cols[j].length} entries, expected $len');
      view.setRange(j * len, (j + 1) * len, cols[j]);
    }
    return p;
  }

  static ffi.Pointer<ffi.Uint32> _upload1(Uint32List a) {
    final p = calloc<ffi.Uint32>(a.length);
    p.asTypedList(a.length).setAll(0, a);
    return p;
  }

  static List<Uint32List> _download(ffi.Pointer<ffi.Uint32> p, int k, int len) {
    final view = p.asTypedList(k * len);
    return [for (int j = 0; j < k; j++) Uint32List.fromList(view.sublist(j * len, (j + 1) * len))];
  }

  static Uint32List _download1(ffi.Pointer<ffi.Uint32> p, int len) => Uint32List.fromList(p.asTypedList(len));

  Uint8List sha256(List<int> data) {
    final p = calloc<ffi.Uint8>(data.length + 1);
    p.asTypedList(data.length + 1).setRange(0, data.length, data);
    final out = calloc<ffi.Uint8>(32);
    try {
      _sha(p, data.length, out);
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      calloc.free(p);
      calloc.free(out);
    }
  }

  // ---- ML-KEM-768 (FIPS 203), for the note-encryption KEM ----
  static const mlkem768SeedLength = 64, mlkem768PublicKeyLength = 1184, mlkem768CiphertextLength = 1088;

  static ffi.Pointer<ffi.Uint8> _bytes(List<int> b, int expected, String what) {
    if (b.length != expected) throw ArgumentError('$what is ${b.length} bytes, expected $expected');
    final p = calloc<ffi.Uint8>(expected);
    p.asTypedList(expected).setAll(0, b);
    return p;
  }

  /// The encapsulation key of the ML-KEM-768 pair generated from [seed]
  /// (64 bytes, d ‖ z). Keys are regenerated from the seed on every use.
  Uint8List mlkem768PublicKey(List<int> seed) {
    final s = _bytes(seed, mlkem768SeedLength, 'seed');
    final out = calloc<ffi.Uint8>(mlkem768PublicKeyLength);
    try {
      _kemPk(s, out);
      return Uint8List.fromList(out.asTypedList(mlkem768PublicKeyLength));
    } finally {
      calloc.free(s);
      calloc.free(out);
    }
  }

  /// Encapsulates to [pk] with the 32 random bytes [m]: (ciphertext, shared
  /// secret), or null when [pk] is not a valid encapsulation key.
  (Uint8List, Uint8List)? mlkem768Encaps(List<int> pk, List<int> m) {
    final p = _bytes(pk, mlkem768PublicKeyLength, 'public key'), mm = _bytes(m, 32, 'm');
    final ct = calloc<ffi.Uint8>(mlkem768CiphertextLength), ss = calloc<ffi.Uint8>(32);
    try {
      if (_kemEncaps(p, mm, ct, ss) != 0) return null;
      return (Uint8List.fromList(ct.asTypedList(mlkem768CiphertextLength)), Uint8List.fromList(ss.asTypedList(32)));
    } finally {
      calloc.free(p);
      calloc.free(mm);
      calloc.free(ct);
      calloc.free(ss);
    }
  }

  /// Decapsulates [ct] with the pair generated from [seed]. A malformed
  /// ciphertext yields a pseudorandom secret (implicit rejection).
  Uint8List mlkem768Decaps(List<int> seed, List<int> ct) {
    final s = _bytes(seed, mlkem768SeedLength, 'seed'), c = _bytes(ct, mlkem768CiphertextLength, 'ciphertext');
    final ss = calloc<ffi.Uint8>(32);
    try {
      _kemDecaps(s, c, ss);
      return Uint8List.fromList(ss.asTypedList(32));
    } finally {
      calloc.free(s);
      calloc.free(c);
      calloc.free(ss);
    }
  }

  @override
  List<Uint32List> interpolateColumns(List<Uint32List> vals, int m) {
    final n = 1 << (m + 1), k = vals.length;
    final inp = _upload(vals, n);
    final out = calloc<ffi.Uint32>(k * n);
    try {
      _interp(inp, k, m, out);
      return _download(out, k, n);
    } finally {
      calloc.free(inp);
      calloc.free(out);
    }
  }

  static int _coefLen(List<Uint32List> coefs, int m) {
    final len = coefs.first.length;
    if (len > 1 << (m + 1) || (len & (len - 1)) != 0) throw ArgumentError('coefficient length $len');
    return len;
  }

  @override
  List<Uint32List> evaluateColumns(List<Uint32List> coefs, int m) {
    final n = 1 << (m + 1), k = coefs.length, len = _coefLen(coefs, m);
    final inp = _upload(coefs, len);
    final out = calloc<ffi.Uint32>(k * n);
    try {
      _eval(inp, k, len, m, out);
      return _download(out, k, n);
    } finally {
      calloc.free(inp);
      calloc.free(out);
    }
  }

  /// One Poseidon2 permutation (for tests of the native port).
  List<int> poseidon2(List<int> state) {
    if (state.length != 16) throw ArgumentError('16 lanes');
    final sp = _upload1(Uint32List.fromList(state));
    final rc = _upload1(_rc);
    try {
      _permuteP2(sp, rc);
      return _download1(sp, 16);
    } finally {
      calloc.free(sp);
      calloc.free(rc);
    }
  }

  @override
  (List<Uint32List>, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash) {
    final mm = 1 << m, n = 2 * mm, k = coefs.length, len = _coefLen(coefs, m);
    if (hash is Sha256ProofHash) {
      final inp = _upload(coefs, len);
      final ev = calloc<ffi.Uint32>(k * n);
      final treeLen = FlatMerkleTree.byteLength(mm);
      final tree = calloc<ffi.Uint8>(treeLen);
      try {
        _commit(inp, k, len, m, ev, tree);
        return (_download(ev, k, n), FlatMerkleTree(Uint8List.fromList(tree.asTypedList(treeLen)), mm));
      } finally {
        calloc.free(inp);
        calloc.free(ev);
        calloc.free(tree);
      }
    }
    if (hash is Poseidon2ProofHash) {
      final inp = _upload(coefs, len);
      final rc = _upload1(_rc);
      final ev = calloc<ffi.Uint32>(k * n);
      final treeLen = FlatMerkleTree.laneLength(mm);
      final tree = calloc<ffi.Uint32>(treeLen);
      try {
        _commitP2(inp, k, len, m, rc, ev, tree);
        return (_download(ev, k, n), FlatMerkleTree(Uint32List.fromList(tree.asTypedList(treeLen)), mm, unit: 8));
      } finally {
        calloc.free(inp);
        calloc.free(rc);
        calloc.free(ev);
        calloc.free(tree);
      }
    }
    return _fallback.commitColumns(coefs, m, hash);
  }

  @override
  Uint32List deepQuotients(DeepConstants k, List<Uint32List> cols, int m, {Uint32List? into}) {
    final n = 1 << (m + 1), kk = cols.length;
    final consts = qFlat([k.c, k.A, k.B, k.dA, k.dB, k.dC, ...k.weights]);
    if (k.weights.length != kk) throw ArgumentError('${k.weights.length} weights for $kk columns');
    final cp = _upload1(consts);
    final inp = _upload(cols, n);
    final out = into == null ? calloc<ffi.Uint32>(4 * n) : _upload1(into);
    try {
      _deep(cp, inp, kk, m, into == null ? 0 : 1, out);
      final r = _download1(out, 4 * n);
      if (into != null) into.setAll(0, r);
      return into ?? r;
    } finally {
      calloc.free(cp);
      calloc.free(inp);
      calloc.free(out);
    }
  }

  @override
  Uint32List circleFold(Uint32List q, int m, QM31 alpha, {Uint32List? into}) {
    final mm = 1 << m;
    if (q.length != 8 * mm) throw ArgumentError('array length');
    final qp = _upload1(q);
    final ap = _upload1(qFlat([alpha]));
    final out = into == null ? calloc<ffi.Uint32>(4 * mm) : _upload1(into);
    try {
      _circleFold(qp, m, ap, into == null ? 0 : 1, out);
      final r = _download1(out, 4 * mm);
      if (into != null) into.setAll(0, r);
      return into ?? r;
    } finally {
      calloc.free(qp);
      calloc.free(ap);
      calloc.free(out);
    }
  }

  @override
  Uint32List lineFold(Uint32List cur, int logLen, QM31 alpha) {
    final len = 1 << logLen, h = len >> 1;
    if (cur.length != 4 * len) throw ArgumentError('layer length');
    final cp = _upload1(cur);
    final ap = _upload1(qFlat([alpha]));
    final out = calloc<ffi.Uint32>(4 * h);
    try {
      _lineFold(cp, logLen, ap, out);
      return _download1(out, 4 * h);
    } finally {
      calloc.free(cp);
      calloc.free(ap);
      calloc.free(out);
    }
  }

  @override
  MerkleCommitment merklePairs(Uint32List cur, int logLen, ProofHash hash) {
    final len = 1 << logLen, h = len >> 1;
    if (cur.length != 4 * len) throw ArgumentError('layer length');
    if (hash is Sha256ProofHash) {
      final cp = _upload1(cur);
      final treeLen = FlatMerkleTree.byteLength(h);
      final tree = calloc<ffi.Uint8>(treeLen);
      try {
        _merklePairs(cp, logLen, tree);
        return FlatMerkleTree(Uint8List.fromList(tree.asTypedList(treeLen)), h);
      } finally {
        calloc.free(cp);
        calloc.free(tree);
      }
    }
    if (hash is Poseidon2ProofHash) {
      final cp = _upload1(cur);
      final rc = _upload1(_rc);
      final treeLen = FlatMerkleTree.laneLength(h);
      final tree = calloc<ffi.Uint32>(treeLen);
      try {
        _merklePairsP2(cp, logLen, rc, tree);
        return FlatMerkleTree(Uint32List.fromList(tree.asTypedList(treeLen)), h, unit: 8);
      } finally {
        calloc.free(cp);
        calloc.free(rc);
        calloc.free(tree);
      }
    }
    return _fallback.merklePairs(cur, logLen, hash);
  }
}
