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
import 'm31.dart';
import 'proof_hash.dart';
import 'stark_prover_ref.dart' show StarkParams, StarkProof, QueryProof;
import '../script_gen/air.dart' show Air;

/// A malformed encoding: a wrong length, a lane outside the field, or a
/// proof whose lists do not match the shape it is being encoded against.
class ProofCodecException implements Exception {
  final String what;
  ProofCodecException(this.what);
  @override
  String toString() => 'proof codec: $what';
}

/// The column counts of the AIR a proof belongs to. The encoding carries no
/// lengths of its own, so a decoder needs these alongside the [StarkParams]
/// to know how long every list is; they are the same counts the verifier
/// checks the proof against, so a proof that decodes has already passed
/// those length checks.
class ProofShape {
  final int numCols, numAuxCols, numPreCols;
  const ProofShape({required this.numCols, this.numAuxCols = 0, this.numPreCols = 0});
  ProofShape.of(Air air) : numCols = air.numCols, numAuxCols = air.numAuxCols, numPreCols = air.numPreCols;

  int get totalCols => numCols + numAuxCols + numPreCols;

  @override
  bool operator ==(Object other) =>
      other is ProofShape && other.numCols == numCols && other.numAuxCols == numAuxCols && other.numPreCols == numPreCols;
  @override
  int get hashCode => Object.hash(numCols, numAuxCols, numPreCols);
  @override
  String toString() => 'ProofShape($numCols, aux $numAuxCols, pre $numPreCols)';
}

/// The canonical byte encoding of a [StarkProof], in either hash flavour.
///
/// A proof is a fixed-shape object once the parameters and the AIR's column
/// counts are known, so the encoding is a bare concatenation with no tags or
/// lengths: the values in the order the verifier reads them (roots, the z
/// hint, the out-of-domain values, the FRI roots, the final coefficients,
/// the grinding nonce, then per query its index, leaves, paths and
/// inverses). That order is the one `StarkVerifierGen.buildUnlock` already
/// pushes, so a proof crossing a process boundary and a proof going on chain
/// are laid out alike. Lanes are 4-byte little-endian M31 values and QM31
/// values are their four lanes; a digest is its bytes for SHA256 and its
/// eight lanes for Poseidon2, 32 bytes either way.
///
/// The public inputs are not part of the encoding: they belong to the
/// statement, and whoever decodes a proof must already hold the AIR to
/// verify it against.
class ProofCodec {
  final StarkParams P;
  final ProofShape shape;
  final ProofHash hash;
  const ProofCodec(this.P, this.shape, {this.hash = const Sha256ProofHash()});
  ProofCodec.forAir(StarkParams P, Air air, {ProofHash hash = const Sha256ProofHash()})
      : this(P, ProofShape.of(air), hash: hash);

  /// Bytes one digest entry occupies: 1 for SHA256's bytes, 4 for
  /// Poseidon2's lanes.
  int get _entry => hash.digestBytes ~/ hash.digestLen;

  bool get _hasAux => shape.numAuxCols > 0;
  bool get _hasPre => shape.numPreCols > 0;

  /// The exact length of every encoding under these parameters and shape.
  /// Decoding rejects anything else, which is what makes truncation and
  /// padding detectable without a framing header.
  int get bytes {
    final a = P.logTraceHalf, d = hash.digestBytes, K = P.compCols;
    var n = d * (2 + (_hasAux ? 1 : 0) + (_hasPre ? 1 : 0) + P.numLineFolds);
    n += 16 * (1 + 2 * shape.totalCols + K + P.finalDegree);
    n += hash.nonceBytes;
    var q = 4; // the query index
    q += 8 * K + a * d; // composition leaf (2K lanes) and path
    for (int l = 0; l < P.numLineFolds; l++) {
      q += 32 + (a - 1 - l) * d + 4; // the folded pair, its path, the x inverse
    }
    q += 8 * shape.numCols + a * d;
    if (_hasAux) q += 8 * shape.numAuxCols + a * d;
    if (_hasPre) q += 8 * shape.numPreCols + a * d;
    q += 4 + 64; // y_B inverse and the four DEEP denominators
    return n + P.numQueries * q;
  }

  // ---------------------------------------------------------------- encode

  Uint8List encode(StarkProof pf) {
    final w = _Writer(bytes);
    final a = P.logTraceHalf, ct = shape.totalCols, C = shape.numCols;
    final A = shape.numAuxCols, R = shape.numPreCols, K = P.compCols;
    void need(bool ok, String what) {
      if (!ok) throw ProofCodecException('cannot encode: $what');
    }

    need(pf.traceAtZ.length == ct && pf.traceAtZg.length == ct, 'out-of-domain value count');
    need(pf.compAtZ.length == K, 'composition value count');
    need(pf.friRoots.length == P.numLineFolds, 'FRI root count');
    need(pf.finalCoefs.length == P.finalDegree, 'final coefficient count');
    need(pf.queries.length == P.numQueries, 'query count');
    need(_hasAux == pf.auxRoot.isNotEmpty, 'aux round presence');
    need(_hasPre == pf.preRoot.isNotEmpty, 'preprocessed commitment presence');

    _digest(w, pf.traceRoot);
    if (_hasAux) _digest(w, pf.auxRoot);
    if (_hasPre) _digest(w, pf.preRoot);
    _digest(w, pf.compRoot);
    _q(w, pf.zHint);
    for (final v in pf.traceAtZ) {
      _q(w, v);
    }
    for (final v in pf.traceAtZg) {
      _q(w, v);
    }
    for (final v in pf.compAtZ) {
      _q(w, v);
    }
    for (final r in pf.friRoots) {
      _digest(w, r);
    }
    for (final c in pf.finalCoefs) {
      _q(w, c);
    }
    need(pf.nonce.length == hash.nonceBytes ~/ _entry, 'nonce length');
    for (final v in pf.nonce) {
      _entry == 1 ? w.byte(v) : _lane(w, v);
    }
    for (final qp in pf.queries) {
      need(qp.index >= 0 && qp.index < 1 << a, 'query index out of domain');
      w.u32(qp.index);
      need(qp.compLeaf.length == 2 * K, 'composition leaf');
      _lanes(w, qp.compLeaf);
      _path(w, qp.compPath, a, 'composition');
      need(qp.lineF0.length == P.numLineFolds && qp.lineF1.length == P.numLineFolds, 'line layer count');
      need(qp.linePaths.length == P.numLineFolds && qp.lineXInv.length == P.numLineFolds, 'line layer count');
      for (int l = 0; l < P.numLineFolds; l++) {
        _q(w, qp.lineF0[l]);
        _q(w, qp.lineF1[l]);
        _path(w, qp.linePaths[l], a - 1 - l, 'layer $l');
        _lane(w, qp.lineXInv[l]);
      }
      need(qp.traceLeaf.length == 2 * C, 'trace leaf');
      _lanes(w, qp.traceLeaf);
      _path(w, qp.tracePath, a, 'trace');
      if (_hasAux) {
        need(qp.auxLeaf.length == 2 * A, 'aux leaf');
        _lanes(w, qp.auxLeaf);
        _path(w, qp.auxPath, a, 'aux');
      }
      if (_hasPre) {
        need(qp.preLeaf.length == 2 * R, 'preprocessed leaf');
        _lanes(w, qp.preLeaf);
        _path(w, qp.prePath, a, 'preprocessed');
      }
      _lane(w, qp.yBInv);
      _q(w, qp.dBInvP);
      _q(w, qp.dBInvC);
      _q(w, qp.dCInvP);
      _q(w, qp.dCInvC);
    }
    if (w.at != w.length) throw StateError('encoder wrote ${w.at} of ${w.length} bytes');
    return w.done;
  }

  void _digest(_Writer w, List<int> d) {
    if (d.length != hash.digestLen) throw ProofCodecException('cannot encode: digest of ${d.length} entries');
    for (final v in d) {
      _entry == 1 ? w.byte(v) : _lane(w, v);
    }
  }

  void _path(_Writer w, List<List<int>> path, int depth, String what) {
    if (path.length != depth) throw ProofCodecException('cannot encode: $what path of ${path.length} levels, $depth expected');
    for (final s in path) {
      _digest(w, s);
    }
  }

  void _lane(_Writer w, int v) {
    if (v < 0 || v >= M31.p) throw ProofCodecException('cannot encode: lane $v out of range');
    w.u32(v);
  }

  void _lanes(_Writer w, List<int> vs) {
    for (final v in vs) {
      _lane(w, v);
    }
  }

  void _q(_Writer w, QM31 v) => _lanes(w, v.limbs);

  // ---------------------------------------------------------------- decode

  StarkProof decode(Uint8List b) {
    if (b.length != bytes) {
      throw ProofCodecException('${b.length} bytes, $bytes expected (${b.length < bytes ? 'truncated' : 'oversized'})');
    }
    final r = _Reader(b);
    final a = P.logTraceHalf, ct = shape.totalCols, C = shape.numCols;
    final A = shape.numAuxCols, R = shape.numPreCols, K = P.compCols;
    final traceRoot = _rDigest(r);
    final auxRoot = _hasAux ? _rDigest(r) : const <int>[];
    final preRoot = _hasPre ? _rDigest(r) : const <int>[];
    final compRoot = _rDigest(r);
    final zHint = _rQ(r);
    final traceAtZ = [for (int i = 0; i < ct; i++) _rQ(r)];
    final traceAtZg = [for (int i = 0; i < ct; i++) _rQ(r)];
    final compAtZ = [for (int i = 0; i < K; i++) _rQ(r)];
    final friRoots = [for (int l = 0; l < P.numLineFolds; l++) _rDigest(r)];
    final finalCoefs = [for (int i = 0; i < P.finalDegree; i++) _rQ(r)];
    final nonce = [for (int i = 0; i < hash.nonceBytes ~/ _entry; i++) _entry == 1 ? r.byte() : _rLane(r)];
    final queries = <QueryProof>[];
    for (int qi = 0; qi < P.numQueries; qi++) {
      final index = r.u32();
      if (index >= 1 << a) throw ProofCodecException('query $qi index $index outside the domain');
      final compLeaf = _rLanes(r, 2 * K);
      final compPath = _rPath(r, a);
      final lineF0 = <QM31>[], lineF1 = <QM31>[], linePaths = <List<List<int>>>[], lineXInv = <int>[];
      for (int l = 0; l < P.numLineFolds; l++) {
        lineF0.add(_rQ(r));
        lineF1.add(_rQ(r));
        linePaths.add(_rPath(r, a - 1 - l));
        lineXInv.add(_rLane(r));
      }
      final traceLeaf = _rLanes(r, 2 * C);
      final tracePath = _rPath(r, a);
      final auxLeaf = _hasAux ? _rLanes(r, 2 * A) : const <int>[];
      final auxPath = _hasAux ? _rPath(r, a) : const <List<int>>[];
      final preLeaf = _hasPre ? _rLanes(r, 2 * R) : const <int>[];
      final prePath = _hasPre ? _rPath(r, a) : const <List<int>>[];
      queries.add(QueryProof(
          index: index,
          compLeaf: compLeaf,
          compPath: compPath,
          lineF0: lineF0,
          lineF1: lineF1,
          linePaths: linePaths,
          lineXInv: lineXInv,
          traceLeaf: traceLeaf,
          tracePath: tracePath,
          auxLeaf: auxLeaf,
          auxPath: auxPath,
          preLeaf: preLeaf,
          prePath: prePath,
          yBInv: _rLane(r),
          dBInvP: _rQ(r),
          dBInvC: _rQ(r),
          dCInvP: _rQ(r),
          dCInvC: _rQ(r)));
    }
    return StarkProof(
        traceRoot: traceRoot,
        compRoot: compRoot,
        auxRoot: auxRoot,
        preRoot: preRoot,
        zHint: zHint,
        traceAtZ: traceAtZ,
        traceAtZg: traceAtZg,
        compAtZ: compAtZ,
        friRoots: friRoots,
        finalCoefs: finalCoefs,
        nonce: nonce,
        queries: queries);
  }

  List<int> _rDigest(_Reader r) => [for (int i = 0; i < hash.digestLen; i++) _entry == 1 ? r.byte() : _rLane(r)];
  List<List<int>> _rPath(_Reader r, int depth) => [for (int i = 0; i < depth; i++) _rDigest(r)];
  int _rLane(_Reader r) {
    final v = r.u32();
    if (v >= M31.p) throw ProofCodecException('lane $v out of range');
    return v;
  }

  List<int> _rLanes(_Reader r, int n) => [for (int i = 0; i < n; i++) _rLane(r)];
  QM31 _rQ(_Reader r) => QM31.fromLimbs(_rLane(r), _rLane(r), _rLane(r), _rLane(r));
}

/// A cursor writing little-endian values into a buffer of known size.
class _Writer {
  final ByteData _bd;
  int at = 0;
  _Writer(int n) : _bd = ByteData(n);
  int get length => _bd.lengthInBytes;
  void u32(int v) {
    _bd.setUint32(at, v, Endian.little);
    at += 4;
  }

  void byte(int v) {
    if (v < 0 || v > 255) throw ProofCodecException('cannot encode: byte $v out of range');
    _bd.setUint8(at, v);
    at += 1;
  }

  Uint8List get done => _bd.buffer.asUint8List(0, at);
}

/// The reading counterpart. Every length is known before reading starts, so
/// an overrun can only mean a bug; it is still checked rather than trusted.
class _Reader {
  final ByteData _bd;
  int at = 0;
  _Reader(Uint8List b) : _bd = ByteData.sublistView(b);
  void _room(int n) {
    if (at + n > _bd.lengthInBytes) throw ProofCodecException('ran past the end of the encoding');
  }

  int u32() {
    _room(4);
    final v = _bd.getUint32(at, Endian.little);
    at += 4;
    return v;
  }

  int byte() {
    _room(1);
    return _bd.getUint8(at++);
  }
}
