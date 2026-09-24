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
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:ffi/ffi.dart';
import 'circle_fft.dart';
import 'm31.dart';
import 'proof_hash.dart';
import '../script_gen/air.dart' show LogUpSpec;
import '../script_gen/air_ring.dart' show Program, ProgKind;
import '../script_gen/fiat_shamir_script_gen.dart' show TranscriptRef;
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
  /// i is `hash.leaf` of the 2k lanes `ev[j][i]`, `ev[j][M + i]`. The
  /// values stay where this implementation keeps them (see [Columns]).
  (Columns, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash);

  /// Value columns held by this implementation (a copy for the Dart
  /// kernels, native memory for the native ones).
  Columns storeColumns(List<Uint32List> cols);

  /// DEEP quotients of the value columns of [sets] (in order) on
  /// HalfCoset(m) ∪ conj at every position:
  /// `(c Σ w_j col_j - A y - B) / (dA x + dB y + dC)`. Added into [into]
  /// when given (and returned), else a fresh array.
  Uint32List deepQuotients(DeepConstants k, List<Columns> sets, int m, {Uint32List? into});

  /// The DEEP quotients of both groups summed, in one pass over the columns
  /// they share.
  ///
  /// Group B reads every column of [sets]; group C reads the first
  /// `c.weights.length` of them, which is how the prover opens the trace,
  /// aux and preprocessed columns at the shifted point while the
  /// composition blocks are opened only at z. Two separate calls read
  /// gigabytes twice for one pass of arithmetic. The default here is those
  /// two calls, for implementations without a fused kernel.
  Uint32List deepQuotientsPair(DeepConstants b, DeepConstants c, List<Columns> sets, int m) => twoPassDeep(this, b, c, sets, m);

  /// The fallback [deepQuotientsPair]: group B over everything, then group C
  /// accumulated over the sets its weights cover.
  static Uint32List twoPassDeep(ProverKernels k, DeepConstants b, DeepConstants c, List<Columns> sets, int m) {
    final out = k.deepQuotients(b, sets, m);
    final shared = <Columns>[];
    var taken = 0;
    for (final s in sets) {
      if (taken >= c.weights.length) break;
      shared.add(s);
      taken += s.count;
    }
    if (taken != c.weights.length) throw ArgumentError('group C reads $taken columns, not ${c.weights.length}');
    return k.deepQuotients(c, shared, m, into: out);
  }

  /// Circle fold of a twin-layout QM31 array on HalfCoset(m):
  /// `(q_i + q_{M+i}) + alpha (q_i - q_{M+i}) / y_i`; accumulates into [into].
  Uint32List circleFold(Uint32List q, int m, QM31 alpha, {Uint32List? into});

  /// Line fold of a layer of length 2^logLen over HalfCoset(logLen):
  /// `(f_i + f_{i+h}) + alpha (f_i - f_{i+h}) / x_i`.
  Uint32List lineFold(Uint32List cur, int logLen, QM31 alpha);

  /// Merkle commitment under [hash] of a layer of length 2^logLen whose
  /// leaf i is `hash.leaf` of the 8 limbs of `cur[i]`, `cur[i + h]`.
  MerkleCommitment merklePairs(Uint32List cur, int logLen, ProofHash hash);

  /// Composition values from the AIR's recorded constraint programs (see
  /// [CompositionJob]), as 4 limb columns over the composition domain, or
  /// null when this implementation has no such path (the prover then runs
  /// the AIR's constraints row by row in Dart).
  List<Uint32List>? composition(CompositionJob job) => null;

  /// Each coefficient column evaluated at the point (x, y).
  List<QM31> evalAt(List<Uint32List> coefs, QM31 x, QM31 y);

  /// The LogUp aux columns of [spec] over the main [rows] (n x numCols),
  /// the preprocessed columns [pre] and the challenges [chal]: the aux
  /// columns in the AIR's order and the accumulator's total, or null when
  /// this implementation has no such path.
  (List<Uint32List>, QM31)? logUpColumns(LogUpSpec spec, List<List<int>> rows, List<Uint32List> pre, List<QM31> chal, int numAuxCols) => null;

  /// The default: the native kernels when the library is built, else Dart.
  static ProverKernels get best => StarkKernels.tryLoad() ?? DartKernels();
}

/// Value columns on a domain (k columns of 2^(m+1) words, twin layout),
/// held wherever the kernels that produced them keep them: the Dart heap for
/// [DartKernels], native memory for [StarkKernels], where a node's columns
/// are gigabytes and the later kernels read them in place. [release] frees
/// them; reading after that is an error.
abstract class Columns {
  int get count;
  int get length;
  int at(int col, int i);

  /// Column [col] (a copy for native columns).
  Uint32List column(int col);
  void release();
  bool get isEmpty => count == 0;

  static final Columns empty = DartColumns(const []);
}

class DartColumns implements Columns {
  final List<Uint32List> cols;
  DartColumns(this.cols);
  @override
  int get count => cols.length;
  @override
  int get length => cols.isEmpty ? 0 : cols[0].length;
  @override
  int at(int col, int i) => cols[col][i];
  @override
  Uint32List column(int col) => cols[col];
  @override
  void release() {}
  @override
  bool get isEmpty => cols.isEmpty;
}

/// Columns in the native store, by id.
class NativeColumns implements Columns {
  final StarkKernels _k;
  final int id;
  @override
  final int count;
  @override
  final int length;
  bool _released = false;
  NativeColumns._(this._k, this.id, this.count, this.length);

  void _check() {
    if (_released) throw StateError('native columns $id were released');
  }

  @override
  int at(int col, int i) {
    _check();
    if (col < 0 || col >= count || i < 0 || i >= length) throw RangeError('column $col at $i of $count x $length');
    return _k._storeGet(id, col, i);
  }

  @override
  Uint32List column(int col) {
    _check();
    if (col < 0 || col >= count) throw RangeError('column $col of $count');
    final out = calloc<ffi.Uint32>(length);
    try {
      _k._storeRead(id, col, 0, length, out);
      return StarkKernels._download1(out, length);
    } finally {
      calloc.free(out);
    }
  }

  @override
  void release() {
    if (_released) return;
    _released = true;
    _k._storeFree(id);
  }

  @override
  bool get isEmpty => count == 0;
}

/// What the composition kernel needs: the main program (over M31) and the
/// aux program (over QM31, null without aux constraints) with their inputs
/// resolved to sources; the column values on the composition domain (trace,
/// aux and pre columns, then public columns; `nC` entries each); the
/// periodic columns on their own domain (2^logPC entries) with `idxPer[q]`
/// the periodic index of row q; the linear forms on the domain; `idxNext[q]`
/// the row of the next-row opening; the QM31 challenges; per constraint
/// (main outputs then aux outputs) its QM31 weight and the index of its
/// divisor-inverse column in [divs].
class CompositionJob {
  static const srcCur = 0, srcNext = 1, srcPer = 2, srcLin = 3, srcConst = 4, srcChal = 5;
  final Program main;
  final Program? aux;
  final Uint32List mainSrc, auxSrc; // (kind, index) per input
  final List<Uint32List> cols, per, lin, divs;
  final int logC, logPC;

  /// When > 0, [cols] are coefficient columns of this length (all equal)
  /// that the kernel evaluates on the composition domain itself; when 0
  /// the values on the domain are the columns of [values], in order.
  final int coefLen;
  final List<Columns> values;
  final Uint32List idxNext, idxPer;
  final List<QM31> chal;
  final List<QM31> weights;
  final Uint32List divSel;
  CompositionJob({
    required this.main,
    required this.aux,
    required this.mainSrc,
    required this.auxSrc,
    required this.cols,
    required this.per,
    required this.lin,
    required this.divs,
    required this.logC,
    required this.logPC,
    required this.idxNext,
    required this.idxPer,
    required this.chal,
    required this.weights,
    required this.divSel,
    this.coefLen = 0,
    this.values = const [],
  });

  /// Resolves [prog]'s input names against the layout: `cur{j}`/`next{j}`
  /// over [nAll] columns, `per{k}` (periodic for k < [nPer], else public
  /// column k - nPer at index nAll + ...), `lin{k}`, `pub{i}` as the
  /// constant [publics][i], `chal{k}`. Null for any other name.
  static Uint32List? resolve(Program prog, int nAll, int nPer, List<int> publics) {
    final out = Uint32List(2 * prog.numInputs);
    for (int i = 0; i < prog.numInputs; i++) {
      final name = prog.inputNames[i];
      final m = RegExp(r'^(cur|next|per|lin|pub|chal)(\d+)$').firstMatch(name);
      if (m == null) return null;
      final k = int.parse(m.group(2)!);
      final (kind, idx) = switch (m.group(1)) {
        'cur' => (srcCur, k),
        'next' => (srcNext, k),
        'per' => k < nPer ? (srcPer, k) : (srcCur, nAll + k - nPer),
        'lin' => (srcLin, k),
        'pub' => (srcConst, publics[k]),
        _ => (srcChal, k),
      };
      out[2 * i] = kind;
      out[2 * i + 1] = idx;
    }
    return out;
  }

  /// A program the M31 path can run: every constant is an embedded base
  /// value.
  static bool baseOnly(Program p) => p.ops.every((o) => o.kind != ProgKind.constant || (o.imm.c0.b == 0 && o.imm.c1.a == 0 && o.imm.c1.b == 0));

  static Uint32List encode(Program p) {
    final out = Uint32List(7 * p.ops.length);
    for (int i = 0; i < p.ops.length; i++) {
      final o = p.ops[i];
      out[7 * i] = o.kind.index;
      out[7 * i + 1] = o.a;
      out[7 * i + 2] = o.b;
      final l = o.imm.limbs;
      for (int k = 0; k < 4; k++) {
        out[7 * i + 3 + k] = l[k];
      }
    }
    return out;
  }
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

  @override
  List<Uint32List>? composition(CompositionJob job) => null;

  @override
  Uint32List deepQuotientsPair(DeepConstants b, DeepConstants c, List<Columns> sets, int m) =>
      ProverKernels.twoPassDeep(this, b, c, sets, m);

  @override
  List<QM31> evalAt(List<Uint32List> coefs, QM31 x, QM31 y) => [for (final c in coefs) CircleFft.evalAt(c, x, y)];

  @override
  (List<Uint32List>, QM31)? logUpColumns(LogUpSpec spec, List<List<int>> rows, List<Uint32List> pre, List<QM31> chal, int numAuxCols) => null;

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
  (Columns, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash) {
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
    return (DartColumns(ev), MerkleTree(leaves, node: hash.node));
  }

  @override
  Columns storeColumns(List<Uint32List> cols) => DartColumns(cols);

  @override
  Uint32List deepQuotients(DeepConstants k, List<Columns> sets, int m, {Uint32List? into}) {
    final cols = [for (final s in sets) for (int j = 0; j < s.count; j++) s.column(j)];
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
typedef _GpuAvailC = ffi.Uint32 Function();
typedef _GpuAvailD = int Function();
typedef _GpuEnableC = ffi.Uint32 Function(ffi.Uint32);
typedef _GpuEnableD = int Function(int);
typedef _InterpC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _InterpD = void Function(ffi.Pointer<ffi.Uint32>, int, int, ffi.Pointer<ffi.Uint32>);
typedef _EvalC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _EvalD = void Function(ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _CommitC = ffi.Uint64 Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint8>);
typedef _CommitD = int Function(ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint8>);
typedef _DeepC = ffi.Void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint64>, ffi.Size, ffi.Uint32, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _DeepD = void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint64>, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _GrindShaC = ffi.Uint64 Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Uint32);
typedef _GrindShaD = int Function(ffi.Pointer<ffi.Uint8>, int, int);
typedef _GrindP2C = ffi.Uint64 Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, ffi.Uint32);
typedef _GrindP2D = int Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, int);
typedef _CompTimingC = ffi.Void Function(ffi.Pointer<ffi.Uint64>);
typedef _CompTimingD = void Function(ffi.Pointer<ffi.Uint64>);
typedef _Deep2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint64>, ffi.Size, ffi.Size,
    ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _Deep2D = void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint64>, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _StorePutC = ffi.Uint64 Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size);
typedef _StorePutD = int Function(ffi.Pointer<ffi.Uint32>, int, int);
typedef _StoreFreeC = ffi.Void Function(ffi.Uint64);
typedef _StoreFreeD = void Function(int);
typedef _StoreGetC = ffi.Uint32 Function(ffi.Uint64, ffi.Size, ffi.Size);
typedef _StoreGetD = int Function(int, int, int);
typedef _StoreReadC = ffi.Void Function(ffi.Uint64, ffi.Size, ffi.Size, ffi.Size, ffi.Pointer<ffi.Uint32>);
typedef _StoreReadD = void Function(int, int, int, int, ffi.Pointer<ffi.Uint32>);
typedef _CircleFoldC = ffi.Void Function(
    ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>);
typedef _CircleFoldD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>);
typedef _LineFoldC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _LineFoldD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint8>);
typedef _MerklePairsD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint8>);
typedef _CommitP2C = ffi.Uint64 Function(
    ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Size, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _CommitP2D = int Function(ffi.Pointer<ffi.Uint32>, int, int, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsP2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Uint32, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _MerklePairsP2D = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _PermuteP2C = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _CompressPairsC = ffi.Void Function(ffi.Pointer<ffi.Uint32>, ffi.Size, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _CompressPairsD = void Function(ffi.Pointer<ffi.Uint32>, int, ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _PermuteP2D = void Function(ffi.Pointer<ffi.Uint32>, ffi.Pointer<ffi.Uint32>);
typedef _ShaC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Pointer<ffi.Uint8>);
typedef _ShaD = void Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>);
typedef _U32P = ffi.Pointer<ffi.Uint32>;
typedef _CompC = ffi.Void Function(_U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, ffi.Pointer<ffi.Uint64>, ffi.Size,
    _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P);
typedef _CompD = void Function(_U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, ffi.Pointer<ffi.Uint64>, int, _U32P,
    _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P);
typedef _EvalAtC = ffi.Void Function(_U32P, ffi.Size, ffi.Size, _U32P, _U32P, _U32P);
typedef _EvalAtD = void Function(_U32P, int, int, _U32P, _U32P, _U32P);
typedef _LogUpC = ffi.Void Function(_U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P);
typedef _LogUpD = void Function(_U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P, _U32P);
typedef _KemPkC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemPkD = void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemEncapsC = ffi.Uint32 Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemEncapsD = int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemDecapsC = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);
typedef _KemDecapsD = void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>);

/// The native kernels (`native/stark_kernels`, built with
/// `cargo build --release --manifest-path native/stark_kernels/Cargo.toml`).
///
/// Inputs are copied into native memory and results copied back, except
/// the committed value columns, which stay in the native column store
/// ([NativeColumns]) and are read there by the composition, DEEP and
/// opening steps. Every kernel is exact, so [tryLoad] returning null
/// (library not built) only costs speed.
class StarkKernels implements ProverKernels {
  static const abiVersion = 7;
  static const envVar = 'STARK_KERNELS_LIB';

  /// Set this to 1 (or true) to run the kernels that have a GPU path on the
  /// GPU. It is off unless asked for, and a machine that cannot run it says
  /// so in [gpuStatus] and proves on the CPU instead.
  static const gpuEnvVar = 'STARK_KERNELS_GPU';

  final ffi.DynamicLibrary _lib;
  final String path;
  late final _InterpD _interp = _lib.lookupFunction<_InterpC, _InterpD>('sk_interpolate_columns');
  late final _EvalD _eval = _lib.lookupFunction<_EvalC, _EvalD>('sk_evaluate_columns');
  late final _CommitD _commit = _lib.lookupFunction<_CommitC, _CommitD>('sk_commit_columns');
  late final _DeepD _deep = _lib.lookupFunction<_DeepC, _DeepD>('sk_deep_quotients');
  late final _Deep2D _deep2 = _lib.lookupFunction<_Deep2C, _Deep2D>('sk_deep_quotients2');
  late final _CompTimingD _compTiming = _lib.lookupFunction<_CompTimingC, _CompTimingD>('sk_composition_timing');
  late final _GrindShaD _grindSha = _lib.lookupFunction<_GrindShaC, _GrindShaD>('sk_grind_sha');
  late final _GrindP2D _grindP2 = _lib.lookupFunction<_GrindP2C, _GrindP2D>('sk_grind_p2');
  late final _CircleFoldD _circleFold = _lib.lookupFunction<_CircleFoldC, _CircleFoldD>('sk_circle_fold');
  late final _LineFoldD _lineFold = _lib.lookupFunction<_LineFoldC, _LineFoldD>('sk_line_fold');
  late final _MerklePairsD _merklePairs = _lib.lookupFunction<_MerklePairsC, _MerklePairsD>('sk_merkle_pairs');
  late final _ShaD _sha = _lib.lookupFunction<_ShaC, _ShaD>('sk_sha256');
  late final _CommitP2D _commitP2 = _lib.lookupFunction<_CommitP2C, _CommitP2D>('sk_commit_columns_p2');
  late final _MerklePairsP2D _merklePairsP2 = _lib.lookupFunction<_MerklePairsP2C, _MerklePairsP2D>('sk_merkle_pairs_p2');
  late final _PermuteP2D _permuteP2 = _lib.lookupFunction<_PermuteP2C, _PermuteP2D>('sk_poseidon2_permute');
  late final _CompressPairsD _compressPairs = _lib.lookupFunction<_CompressPairsC, _CompressPairsD>('sk_p2_compress_pairs');
  late final _CompD _comp = _lib.lookupFunction<_CompC, _CompD>('sk_composition');
  late final _EvalAtD _evalAt = _lib.lookupFunction<_EvalAtC, _EvalAtD>('sk_eval_at');
  late final _LogUpD _logUp = _lib.lookupFunction<_LogUpC, _LogUpD>('sk_logup_columns');
  late final _StorePutD _storePut = _lib.lookupFunction<_StorePutC, _StorePutD>('sk_store_put');
  late final _StoreFreeD _storeFree = _lib.lookupFunction<_StoreFreeC, _StoreFreeD>('sk_store_free');
  late final _StoreGetD _storeGet = _lib.lookupFunction<_StoreGetC, _StoreGetD>('sk_store_get');
  late final _StoreReadD _storeRead = _lib.lookupFunction<_StoreReadC, _StoreReadD>('sk_store_read');
  late final _KemPkD _kemPk = _lib.lookupFunction<_KemPkC, _KemPkD>('sk_mlkem768_public_key');
  late final _KemEncapsD _kemEncaps = _lib.lookupFunction<_KemEncapsC, _KemEncapsD>('sk_mlkem768_encaps');
  late final _KemDecapsD _kemDecaps = _lib.lookupFunction<_KemDecapsC, _KemDecapsD>('sk_mlkem768_decaps');
  late final _GpuAvailD _gpuAvail = _lib.lookupFunction<_GpuAvailC, _GpuAvailD>('sk_gpu_available');
  late final _GpuEnableD _gpuEnable = _lib.lookupFunction<_GpuEnableC, _GpuEnableD>('sk_gpu_enable');
  late final Uint32List _rc = Poseidon2ProofHash.roundConstants;
  final DartKernels _fallback = DartKernels();

  StarkKernels._(this._lib, this.path);

  bool _gpu = false;

  /// Whether the GPU backend is running.
  bool get gpuEnabled => _gpu;

  /// Why the GPU backend is or is not running, for a caller to print.
  String get gpuStatus {
    if (_gpu) return 'on';
    switch (_gpuAvail()) {
      case 1:
        return 'off (available; set $gpuEnvVar=1)';
      case 2:
        return 'unavailable: no Metal device';
      case 3:
        return 'unavailable: the shaders did not compile';
      default:
        return 'unavailable: built without the GPU backend';
    }
  }

  /// Asks the library to run the kernels that have a GPU path on the GPU.
  /// Returns whether it took; [gpuStatus] says why when it did not.
  bool enableGpu(bool on) => _gpu = _gpuEnable(on ? 1 : 0) == 1;

  @override
  String get name => _gpu ? 'native+metal' : 'native';

  /// How the last composition call split, in milliseconds: extending the
  /// columns onto the composition domain, and running the constraint
  /// program over them. The reuse path does no extension, so its first
  /// figure is zero.
  /// The smallest 4-byte nonce whose SHA256 of [state] and it begins with
  /// [zeroBytes] zero bytes, or -1 when the search found none.
  int grindSha(List<int> state, int zeroBytes) {
    final sp = calloc<ffi.Uint8>(state.length);
    try {
      sp.asTypedList(state.length).setAll(0, state);
      final n = _grindSha(sp, state.length, zeroBytes);
      return n == _notFound ? -1 : n;
    } finally {
      calloc.free(sp);
    }
  }

  /// The smallest lane nonce whose Poseidon2 compression with [state] has
  /// its low [bits] bits zero, or -1 when the search found none.
  int grindP2(List<int> state, int bits) {
    final sp = _upload1(Uint32List.fromList(state));
    final rc = _upload1(_rc);
    try {
      final n = _grindP2(sp, rc, bits);
      return n == _notFound ? -1 : n;
    } finally {
      calloc.free(sp);
      calloc.free(rc);
    }
  }

  static const _notFound = 0xFFFFFFFFFFFFFFFF;

  (double, double) get compositionSplit {
    final p = calloc<ffi.Uint64>(2);
    try {
      _compTiming(p);
      return (p[0] / 1000, p[1] / 1000);
    } finally {
      calloc.free(p);
    }
  }

  static StarkKernels? _loaded;
  static bool _tried = false;

  /// Where this package is on disk, from the running program's package
  /// config, or null when there is none (an AOT binary, a Flutter bundle).
  /// A package that depends on tstokenlib runs from its own directory, so
  /// the crate is not under its current directory or any parent of it.
  static String? _packageRoot() {
    var dir = Directory.current;
    for (int up = 0; up < 6; up++) {
      final f = File('${dir.path}/.dart_tool/package_config.json');
      if (f.existsSync()) {
        try {
          final config = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
          for (final p in (config['packages'] as List).cast<Map<String, dynamic>>()) {
            if (p['name'] != 'tstokenlib') continue;
            final root = Uri.parse(p['rootUri'] as String);
            final resolved = root.hasScheme ? root : f.parent.uri.resolveUri(root);
            return resolved.toFilePath().replaceAll(RegExp(r'/$'), '');
          }
        } catch (_) {
          return null;
        }
        return null;
      }
      dir = dir.parent;
    }
    return null;
  }

  /// The library file name for this platform.
  static String get fileName => Platform.isMacOS
      ? 'libstark_kernels.dylib'
      : Platform.isWindows
          ? 'stark_kernels.dll'
          : 'libstark_kernels.so';

  /// Where an installed program keeps the library: beside its executable,
  /// or in `../lib` from it. A compiled program has no source tree to search,
  /// so a package or tarball that ships the library puts it in one of these.
  /// Under `dart run` the executable is the Dart VM, and neither exists.
  static List<String> _besideExecutable() {
    final bin = File(Platform.resolvedExecutable).parent.path;
    return ['$bin/$fileName', '${File(bin).parent.path}/lib/$fileName'];
  }

  /// Loads the library from [path], `$STARK_KERNELS_LIB`, beside the running
  /// executable, or the crate's release directory under the current directory
  /// or its parents. Returns null when none is found or the ABI version
  /// differs. Cached.
  static StarkKernels? tryLoad({String? path}) {
    if (path == null && _tried) return _loaded;
    final candidates = <String>[
      if (path != null) path,
      if (Platform.environment[envVar] != null) Platform.environment[envVar]!,
      ..._besideExecutable(),
    ];
    var dir = Directory.current;
    for (int up = 0; up < 4; up++) {
      candidates.add('${dir.path}/native/stark_kernels/target/release/$fileName');
      dir = dir.parent;
    }
    // and beside tstokenlib itself, for a package that depends on it: the
    // crate lives in this repo, not in the caller's
    final own = _packageRoot();
    if (own != null) candidates.add('$own/native/stark_kernels/target/release/$fileName');
    StarkKernels? found;
    for (final c in candidates) {
      if (!File(c).existsSync()) continue;
      try {
        final lib = ffi.DynamicLibrary.open(c);
        final version = lib.lookupFunction<_VersionC, _VersionD>('sk_version')();
        if (version != abiVersion) continue;
        found = StarkKernels._(lib, c);
        final want = Platform.environment[gpuEnvVar];
        if (want == '1' || want == 'true') found.enableGpu(true);
        // grinding is a search over independent hashes, so the kernels do it
        // across cores; both flavours return the same nonce the Dart loop
        // would have counted up to
        final k = found;
        TranscriptRef.nativeGrind = (state, zeroBytes) => k.grindSha(state, zeroBytes);
        Poseidon2Transcript.nativeGrind = (state, bits) => k.grindP2(state, bits);
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
    return [for (int j = 0; j < k; j++) Uint32List(len)..setRange(0, len, view, j * len)];
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

  @override
  List<Uint32List> composition(CompositionJob job) {
    final nC = 1 << job.logC, nPC = 1 << job.logPC;
    final nOut = job.main.outputs.length + (job.aux?.outputs.length ?? 0);
    if (job.weights.length != nOut || job.divSel.length != nOut) throw ArgumentError('one weight and divisor per constraint');
    final desc = _upload1(Uint32List.fromList([
      job.logC, valueColumns(job), job.per.length, job.logPC, job.lin.length, job.divs.length,
      job.main.numInputs, job.main.ops.length, job.main.outputs.length,
      job.aux?.numInputs ?? 0, job.aux?.ops.length ?? 0, job.aux?.outputs.length ?? 0, job.chal.length, job.coefLen,
    ]));
    final mainOps = _upload1(CompositionJob.encode(job.main)), mainSrc = _upload1(job.mainSrc);
    final mainOut = _upload1(Uint32List.fromList(job.main.outputs));
    final auxOps = _upload1(job.aux == null ? Uint32List(0) : CompositionJob.encode(job.aux!)), auxSrc = _upload1(job.auxSrc);
    final auxOut = _upload1(Uint32List.fromList(job.aux?.outputs ?? const []));
    final chal = _upload1(Uint32List.fromList([for (final c in job.chal) ...c.limbs]));
    final cols = _upload(job.coefLen > 0 ? job.cols : const [], job.coefLen), per = _upload(job.per, nPC), lin = _upload(job.lin, nC), divs = _upload(job.divs, nC);
    final (sets, owned) = job.coefLen > 0 ? (const <NativeColumns>[], const <NativeColumns>[]) : _native(job.values);
    final setIds = _uploadIds(sets);
    final idxNext = _upload1(job.idxNext), idxPer = _upload1(job.idxPer);
    final weights = _upload1(Uint32List.fromList([for (final w in job.weights) ...w.limbs])), divSel = _upload1(job.divSel);
    final out = calloc<ffi.Uint32>(4 * nC);
    try {
      _comp(desc, mainOps, mainSrc, mainOut, auxOps, auxSrc, auxOut, chal, cols, setIds, sets.length, per, lin, idxNext, idxPer, weights, divSel, divs, out);
      final v = out.asTypedList(4 * nC);
      final limbs = List.generate(4, (_) => Uint32List(nC));
      for (int q = 0; q < nC; q++) {
        for (int k = 0; k < 4; k++) {
          limbs[k][q] = v[4 * q + k];
        }
      }
      return limbs;
    } finally {
      for (final p in [desc, mainOps, mainSrc, mainOut, auxOps, auxSrc, auxOut, chal, cols, per, lin, divs, idxNext, idxPer, weights, divSel, out]) {
        calloc.free(p);
      }
      calloc.free(setIds);
      for (final c in owned) {
        c.release();
      }
    }
  }

  /// The column count of the composition job's value sets.
  static int valueColumns(CompositionJob job) => job.coefLen > 0 ? job.cols.length : job.values.fold(0, (n, c) => n + c.count);

  /// [sets] as native columns: those already native as they are, the others
  /// copied into the store for the call (returned second, to release).
  (List<NativeColumns>, List<NativeColumns>) _native(List<Columns> sets) {
    final all = <NativeColumns>[], owned = <NativeColumns>[];
    for (final c in sets) {
      if (c.isEmpty) continue;
      if (c is NativeColumns) {
        c._check();
        all.add(c);
      } else {
        final n = storeColumns([for (int j = 0; j < c.count; j++) c.column(j)]) as NativeColumns;
        all.add(n);
        owned.add(n);
      }
    }
    return (all, owned);
  }

  static ffi.Pointer<ffi.Uint64> _uploadIds(List<NativeColumns> sets) {
    final p = calloc<ffi.Uint64>(sets.isEmpty ? 1 : sets.length);
    for (int i = 0; i < sets.length; i++) {
      p[i] = sets[i].id;
    }
    return p;
  }

  @override
  Columns storeColumns(List<Uint32List> cols) {
    if (cols.isEmpty) return Columns.empty;
    final n = cols[0].length;
    final inp = _upload(cols, n);
    try {
      return NativeColumns._(this, _storePut(inp, cols.length, n), cols.length, n);
    } finally {
      calloc.free(inp);
    }
  }

  @override
  List<QM31> evalAt(List<Uint32List> coefs, QM31 x, QM31 y) {
    if (coefs.isEmpty) return const [];
    final k = coefs.length, len = coefs[0].length;
    final c = _upload(coefs, len), px = _upload1(Uint32List.fromList(x.limbs)), py = _upload1(Uint32List.fromList(y.limbs));
    final out = calloc<ffi.Uint32>(4 * k);
    try {
      _evalAt(c, k, len, px, py, out);
      final v = out.asTypedList(4 * k);
      return [for (int j = 0; j < k; j++) QM31.fromLimbs(v[4 * j], v[4 * j + 1], v[4 * j + 2], v[4 * j + 3])];
    } finally {
      calloc.free(c);
      calloc.free(px);
      calloc.free(py);
      calloc.free(out);
    }
  }

  @override
  (List<Uint32List>, QM31)? logUpColumns(LogUpSpec spec, List<List<int>> rows, List<Uint32List> pre, List<QM31> chal, int numAuxCols) {
    final n = rows.length, nMain = rows[0].length, logN = CircleFft.log2(n);
    final prog = spec.program;
    // inputs: cur{j} (main cell), pre{c}, chal{k}; constants otherwise
    final src = Uint32List(2 * prog.numInputs);
    for (int i = 0; i < prog.numInputs; i++) {
      final m = RegExp(r'^(cur|pre|chal)(\d+)$').firstMatch(prog.inputNames[i]);
      if (m == null) return null;
      final k = int.parse(m.group(2)!);
      src[2 * i] = switch (m.group(1)) { 'cur' => 0, 'pre' => 1, _ => 5 };
      src[2 * i + 1] = k;
    }
    final flat = Uint32List(n * nMain);
    for (int r = 0; r < n; r++) {
      flat.setRange(r * nMain, (r + 1) * nMain, rows[r]);
    }
    final w = 4 * spec.helpers + 4;
    if (numAuxCols < w) throw ArgumentError('aux columns');
    final desc = _upload1(Uint32List.fromList([logN, nMain, pre.length, prog.numInputs, prog.ops.length, spec.helpers, chal.length, spec.gammaIndex, spec.deltaIndex]));
    final ops = _upload1(CompositionJob.encode(prog)), srcP = _upload1(src), outs = _upload1(Uint32List.fromList(prog.outputs));
    final ch = _upload1(Uint32List.fromList([for (final c in chal) ...c.limbs]));
    final rowsP = _upload1(flat), preP = _upload(pre, n);
    final out = calloc<ffi.Uint32>(w * n), total = calloc<ffi.Uint32>(4);
    try {
      _logUp(desc, ops, srcP, outs, ch, rowsP, preP, out, total);
      final v = out.asTypedList(w * n);
      final cols = List.generate(numAuxCols, (_) => Uint32List(n));
      for (int h = 0; h < spec.helpers; h++) {
        for (int k = 0; k < 4; k++) {
          cols[spec.helperOffsets[h] + k].setAll(0, v.sublist((4 * h + k) * n, (4 * h + k + 1) * n));
        }
      }
      for (int k = 0; k < 4; k++) {
        cols[spec.accOffset + k].setAll(0, v.sublist((4 * spec.helpers + k) * n, (4 * spec.helpers + k + 1) * n));
      }
      final t = total.asTypedList(4);
      return (cols, QM31.fromLimbs(t[0], t[1], t[2], t[3]));
    } finally {
      for (final p in [desc, ops, srcP, outs, ch, rowsP, preP, out, total]) {
        calloc.free(p);
      }
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

  /// Two-to-one Poseidon2 compressions of [pairs] (16 lanes each) on the
  /// calling thread: node i is the first 8 lanes of pair i permuted.
  Uint32List compressPairs(Uint32List pairs) {
    if (pairs.length % 16 != 0) throw ArgumentError('16 lanes a pair');
    final n = pairs.length ~/ 16;
    final pp = _upload1(pairs), rc = _upload1(_rc), out = calloc<ffi.Uint32>(8 * n + 1);
    try {
      _compressPairs(pp, n, rc, out);
      return _download1(out, 8 * n);
    } finally {
      calloc.free(pp);
      calloc.free(rc);
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
  (Columns, MerkleCommitment) commitColumns(List<Uint32List> coefs, int m, ProofHash hash) {
    final mm = 1 << m, n = 2 * mm, k = coefs.length, len = _coefLen(coefs, m);
    if (hash is Sha256ProofHash) {
      final inp = _upload(coefs, len);
      final treeLen = FlatMerkleTree.byteLength(mm);
      final tree = calloc<ffi.Uint8>(treeLen);
      try {
        final id = _commit(inp, k, len, m, tree);
        return (NativeColumns._(this, id, k, n), FlatMerkleTree(Uint8List.fromList(tree.asTypedList(treeLen)), mm));
      } finally {
        calloc.free(inp);
        calloc.free(tree);
      }
    }
    if (hash is Poseidon2ProofHash) {
      final inp = _upload(coefs, len);
      final rc = _upload1(_rc);
      final treeLen = FlatMerkleTree.laneLength(mm);
      final tree = calloc<ffi.Uint32>(treeLen);
      try {
        final id = _commitP2(inp, k, len, m, rc, tree);
        return (NativeColumns._(this, id, k, n), FlatMerkleTree(Uint32List.fromList(tree.asTypedList(treeLen)), mm, unit: 8));
      } finally {
        calloc.free(inp);
        calloc.free(rc);
        calloc.free(tree);
      }
    }
    return _fallback.commitColumns(coefs, m, hash);
  }

  @override
  Uint32List deepQuotients(DeepConstants k, List<Columns> sets, int m, {Uint32List? into}) {
    final n = 1 << (m + 1);
    final kk = sets.fold(0, (c, s) => c + s.count);
    if (k.weights.length != kk) throw ArgumentError('${k.weights.length} weights for $kk columns');
    for (final s in sets) {
      if (!s.isEmpty && s.length != n) throw ArgumentError('columns of ${s.length} values on a domain of $n');
    }
    final consts = qFlat([k.c, k.A, k.B, k.dA, k.dB, k.dC, ...k.weights]);
    final cp = _upload1(consts);
    final (native, owned) = _native(sets);
    final ids = _uploadIds(native);
    final out = into == null ? calloc<ffi.Uint32>(4 * n) : _upload1(into);
    try {
      _deep(cp, ids, native.length, m, into == null ? 0 : 1, out);
      final r = _download1(out, 4 * n);
      if (into != null) into.setAll(0, r);
      return into ?? r;
    } finally {
      calloc.free(cp);
      calloc.free(ids);
      calloc.free(out);
      for (final c in owned) {
        c.release();
      }
    }
  }

  @override
  Uint32List deepQuotientsPair(DeepConstants b, DeepConstants c, List<Columns> sets, int m) {
    final n = 1 << (m + 1);
    final kk = sets.fold(0, (t, s) => t + s.count);
    if (b.weights.length != kk) throw ArgumentError('${b.weights.length} weights for $kk columns');
    if (c.weights.length > kk) throw ArgumentError('group C reads more columns than group B');
    for (final s in sets) {
      if (!s.isEmpty && s.length != n) throw ArgumentError('columns of ${s.length} values on a domain of $n');
    }
    final bp = _upload1(qFlat([b.c, b.A, b.B, b.dA, b.dB, b.dC, ...b.weights]));
    final cp = _upload1(qFlat([c.c, c.A, c.B, c.dA, c.dB, c.dC, ...c.weights]));
    final (native, owned) = _native(sets);
    final ids = _uploadIds(native);
    final out = calloc<ffi.Uint32>(4 * n);
    try {
      _deep2(bp, cp, ids, native.length, c.weights.length, m, out);
      return _download1(out, 4 * n);
    } finally {
      calloc.free(bp);
      calloc.free(cp);
      calloc.free(ids);
      calloc.free(out);
      for (final col in owned) {
        col.release();
      }
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
