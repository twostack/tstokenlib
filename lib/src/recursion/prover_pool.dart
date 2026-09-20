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

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import '../crypto/m31.dart';
import '../crypto/proof_codec.dart';
import '../crypto/stark_prover.dart';
import '../crypto/stark_prover_ref.dart';
import '../crypto/stark_verifier_ref.dart';
import '../script_gen/pool_spend_air.dart';
import 'verifier_air.dart';
import 'verifier_program.dart';

/// One level-1 aggregation node, handed out whole.
///
/// Level 1 is the bulk of a round (sixteen 2^20 nodes, about 170 s of 342 s)
/// and every node is independent of the others and of the coordinator's
/// ledger state, so it is the part of the round that can be spread over the
/// coordinator's prover pool: the machines it operates, proving nodes in
/// parallel. A job is exactly what proving one node needs and nothing more:
/// the node's spend proofs and their public inputs, the level program's
/// identity (its parameters, whose [StarkParams.logTrace] fixes the program,
/// and its preprocessed root), the parameters the spends were proved with,
/// and the node digest the coordinator expects the node to be about. The
/// spend proofs and publics are zero-knowledge proofs over data the chain
/// publishes anyway, so a job discloses nothing a prover could not read from
/// a round transaction, which is what lets a prover outside the coordinator's
/// own machines join the pool later without a privacy cost.
class NodeJob {
  /// The parameters the [proofs] were proved with.
  final StarkParams spendParams;

  /// The level program's parameters; [StarkParams.logTrace] is its trace
  /// size, which together with the arity determines the compiled program.
  final StarkParams levelParams;

  /// The level program's preprocessed root, the other half of its identity:
  /// a prover that compiles a different program commits to a different root
  /// and the coordinator's verification fails.
  final List<int> levelPreRoot;

  /// The transfers of this node, in order.
  final List<PoolPublicInputs> publics;
  final List<StarkProof> proofs;

  /// The round's ring of roots, which the node checks every real spend's
  /// anchor against and absorbs into its digest.
  final List<List<int>> ring;

  /// The node's public input: the chain digest of the transfers' statement
  /// digests and the ring, which is what pins the returned proof to these
  /// transfers in this round.
  final List<int> digest;

  NodeJob({
    required this.spendParams,
    required this.levelParams,
    required this.levelPreRoot,
    required this.publics,
    required this.proofs,
    required this.ring,
    required this.digest,
  }) {
    if (publics.length != proofs.length || publics.isEmpty) throw ArgumentError('one spend proof per transfer');
    if (levelPreRoot.length != 8) throw ArgumentError('an 8-lane preprocessed root');
    if (ring.length != anchorRing.size || ring.any((r) => r.length != 8)) throw ArgumentError('a ring of ${anchorRing.size} roots');
    if (digest.length != 8) throw ArgumentError('an 8-lane node digest');
  }

  static const p2 = Poseidon2ProofHash();

  /// The anchor check every level-1 node makes (the pool's).
  static const anchorRing = AnchorRing.pool;

  int get arity => publics.length;

  /// The inner shapes the node verifies: one spend AIR per transfer.
  List<InnerShape> shapes() => [for (final p in publics) InnerShape(spendParams, PoolSpendAir.air(p))];

  /// The node digest these transfers imply. A prover checks it against
  /// [digest] before proving, so a job that does not describe itself is
  /// refused instead of producing a proof nobody wants.
  List<int> derivedDigest() =>
      VerifierProgram.nodeDigest([for (final s in shapes()) VerifierProgram.statementDigest(s.air, const [])], ring: ring);

  /// The compiled level program for this job. Compiling is about 0.3 s at
  /// production size and the preprocessed commitment behind it about 6 s, so
  /// a pool member serving many nodes compiles once and keeps the program
  /// for [LocalNodeProver].
  VerifierProgram compile() => VerifierProgram.compileAll(shapes(), levelParams.logTrace, ring: anchorRing);

  /// The AIR the node's proof is checked against.
  VerifierAir airOf(VerifierProgram program) => program.air(digest);

  /// The codec of one of the [proofs].
  ProofCodec get spendCodec => ProofCodec.forAir(spendParams, PoolSpendAir.air(publics.first), hash: p2);

  /// The codec of the proof a prover returns.
  ProofCodec nodeCodec(VerifierProgram program) => ProofCodec.forAir(levelParams, airOf(program), hash: p2);

  // ------------------------------------------------------------- encoding

  /// Lanes a job occupies before the spend proofs: the two parameter sets,
  /// the arity, the preprocessed root, the digest, the ring and the publics.
  static const _paramLanes = 7;
  int get _headerLanes => 1 + 2 * _paramLanes + 8 + 8 + 8 * anchorRing.size + arity * PoolPublicInputs.count;

  int get bytes => 4 * _headerLanes + arity * spendCodec.bytes;

  Uint8List encode() {
    final codec = spendCodec;
    final out = Uint8List(bytes);
    final bd = ByteData.sublistView(out);
    var at = 0;
    void u32(int v) {
      bd.setUint32(at, v, Endian.little);
      at += 4;
    }

    void lane(int v) {
      if (v < 0 || v >= M31.p) throw ProofCodecException('cannot encode job: lane $v out of range');
      u32(v);
    }

    void params(StarkParams p) {
      u32(p.logTrace);
      u32(p.logBlowup);
      u32(p.logExpand);
      u32(p.logFinal);
      u32(p.numQueries);
      u32(p.grindBytes);
      u32(p.zkRandomizers);
    }

    u32(arity);
    params(spendParams);
    params(levelParams);
    for (final v in levelPreRoot) {
      lane(v);
    }
    for (final v in digest) {
      lane(v);
    }
    for (final r in ring) {
      for (final v in r) {
        lane(v);
      }
    }
    for (final p in publics) {
      for (final v in p.toLanes()) {
        lane(v);
      }
    }
    for (final pf in proofs) {
      out.setRange(at, at + codec.bytes, codec.encode(pf));
      at += codec.bytes;
    }
    if (at != out.length) throw StateError('job encoder wrote $at of ${out.length} bytes');
    return out;
  }

  /// The inverse of [encode]. Every length follows from the arity and the
  /// parameters in the header, so a job that is not exactly one encoding is
  /// refused rather than read part way.
  static NodeJob decode(Uint8List b) {
    final bd = ByteData.sublistView(b);
    var at = 0;
    int u32() {
      if (at + 4 > b.length) throw ProofCodecException('job encoding ran past the end');
      final v = bd.getUint32(at, Endian.little);
      at += 4;
      return v;
    }

    int lane() {
      final v = u32();
      if (v >= M31.p) throw ProofCodecException('job lane $v out of range');
      return v;
    }

    StarkParams params() => StarkParams(
        logTrace: u32(),
        logBlowup: u32(),
        logExpand: u32(),
        logFinal: u32(),
        numQueries: u32(),
        grindBytes: u32(),
        zkRandomizers: u32());

    final arity = u32();
    if (arity < 1 || arity > 1024) throw ProofCodecException('job arity $arity');
    final spendParams = params(), levelParams = params();
    final preRoot = [for (int i = 0; i < 8; i++) lane()];
    final digest = [for (int i = 0; i < 8; i++) lane()];
    final ring = [for (int k = 0; k < anchorRing.size; k++) [for (int i = 0; i < 8; i++) lane()]];
    final publics = [
      for (int i = 0; i < arity; i++) PoolPublicInputs.fromLanes([for (int k = 0; k < PoolPublicInputs.count; k++) lane()])
    ];
    final codec = ProofCodec.forAir(spendParams, PoolSpendAir.air(publics.first), hash: p2);
    if (b.length != at + arity * codec.bytes) {
      throw ProofCodecException('job is ${b.length} bytes, ${at + arity * codec.bytes} expected');
    }
    final proofs = [
      for (int i = 0; i < arity; i++) codec.decode(Uint8List.sublistView(b, at + i * codec.bytes, at + (i + 1) * codec.bytes))
    ];
    return NodeJob(
        spendParams: spendParams,
        levelParams: levelParams,
        levelPreRoot: preRoot,
        publics: publics,
        proofs: proofs,
        ring: ring,
        digest: digest);
  }
}

/// Something that can prove a level-1 node. The local prover, a member of
/// the pool on another machine behind a transport, and the pool itself are
/// all the same interface, so the aggregation does not know which it is
/// talking to.
abstract class NodeProver {
  /// Proves [job], or throws. Asynchronous because a pool member on another
  /// machine is a round trip; the local implementation completes without
  /// yielding to the event loop for longer than the proof takes.
  Future<StarkProof> prove(NodeJob job);

  /// Whether this prover has already checked what it returns against the
  /// job's digest. The aggregation folds only proofs that verify, and repeats
  /// the check itself for a prover that does not make this promise; the local
  /// prover and the pool do, so the round pays for one verification per node
  /// rather than two.
  bool get verifies => false;
}

/// Proves a node here, with this machine's prover. This is what the
/// coordinator falls back to and what every pool member runs on its own
/// machine.
class LocalNodeProver implements NodeProver {
  /// The compiled level program. Supplying the coordinator's own saves
  /// recompiling per node; without one every job compiles its own.
  final VerifierProgram? program;
  final Random? rng;
  final ProverKernels? kernels;
  final bool verbose;
  LocalNodeProver({this.program, this.rng, this.kernels, this.verbose = false});

  static const p2 = Poseidon2ProofHash();

  @override
  bool get verifies => true;

  @override
  Future<StarkProof> prove(NodeJob job) async => proveNow(job);

  /// The synchronous body, for callers already off the coordinator's path.
  StarkProof proveNow(NodeJob job) {
    final derived = job.derivedDigest();
    for (int i = 0; i < 8; i++) {
      if (derived[i] != job.digest[i]) throw ArgumentError('the job\'s digest is not the one its transfers imply');
    }
    final prog = program ?? job.compile();
    final shapes = job.shapes();
    final rows = prog.witnessAll(job.proofs, shapes: shapes, ring: job.ring);
    return StarkProver.prove(job.levelParams, prog.air(job.digest), rows, rng: rng, hash: p2, kernels: kernels, verbose: verbose);
  }
}

/// What one node cost and where it was proved, for the round's accounting.
class NodeOutcome {
  /// The pool member the node went to, or null when it was proved locally
  /// straight away.
  final int? prover;

  /// Why the coordinator proved it itself: null when the member's proof was
  /// used, otherwise 'no provers', 'timeout', 'rejected' or 'failed'.
  final String? fallback;
  final Duration elapsed;
  NodeOutcome(this.prover, this.fallback, this.elapsed);
  bool get local => fallback != null;
  @override
  String toString() => '${local ? 'local ($fallback)' : 'prover $prover'} in ${elapsed.inMilliseconds} ms';
}

/// The coordinator's pool of level-1 provers: the machines it operates,
/// each a [NodeProver], with this machine as the fallback.
///
/// The sixteen level-1 nodes are independent, so with more machines in the
/// pool they prove in parallel and the round shortens by that much; with an
/// empty pool every node is proved here and the round is what it was. A
/// member is just another [NodeProver], so an in-process one and one behind
/// a network transport look the same here.
///
/// The pool is also the trust boundary, which is what lets a machine the
/// coordinator does not operate (a participant's server, say) be admitted to
/// it later: the pool re-derives the node's AIR from the job it sent and
/// verifies the returned proof against it with the reference verifier, so a
/// member cannot choose the statement its proof is about. Anything late,
/// wrong or broken is proved locally instead, which means a round completes
/// with no members, with faulty members, or with a mix.
class ProverPool implements NodeProver {
  final List<NodeProver> provers;
  final LocalNodeProver local;

  /// How long one node may take at a member before the coordinator gives up
  /// on it and proves it here. A late result is dropped: by then the local
  /// proof is the one being folded.
  final Duration timeout;

  /// The compiled level program, used both for verification and by [local].
  final VerifierProgram program;
  final bool verbose;

  /// One entry per node handed out, in the order [prove] was called.
  final outcomes = <NodeOutcome>[];

  int _next = 0;
  ProverPool({
    required this.program,
    this.provers = const [],
    LocalNodeProver? local,
    this.timeout = const Duration(minutes: 5),
    this.verbose = false,
  }) : local = local ?? LocalNodeProver(program: program);

  static const p2 = Poseidon2ProofHash();

  @override
  bool get verifies => true;

  int get localNodes => outcomes.where((o) => o.local).length;
  int get pooledNodes => outcomes.where((o) => !o.local).length;

  @override
  Future<StarkProof> prove(NodeJob job) async {
    final sw = Stopwatch()..start();
    int? prover;
    var fallback = 'no provers';
    if (provers.isNotEmpty) {
      prover = _next++ % provers.length;
      try {
        final pf = await provers[prover].prove(job).timeout(timeout);
        if (accepts(job, pf)) {
          outcomes.add(NodeOutcome(prover, null, sw.elapsed));
          if (verbose) print('  [pool] node from prover $prover in ${sw.elapsedMilliseconds} ms');
          return pf;
        }
        fallback = 'rejected';
      } on TimeoutException {
        fallback = 'timeout';
      } catch (_) {
        fallback = 'failed';
      }
    }
    final pf = local.proveNow(job);
    outcomes.add(NodeOutcome(prover, fallback, sw.elapsed));
    if (verbose) print('  [pool] node proved locally ($fallback) in ${sw.elapsedMilliseconds} ms');
    return pf;
  }

  /// Whether [proof] really proves [job]: the AIR is rebuilt here from the
  /// job's digest, so a proof of another node fails on the statement its
  /// transcript is bound to. Any error at all counts as a refusal, since a
  /// member's output is untrusted input even when the member is ours.
  bool accepts(NodeJob job, StarkProof proof) {
    try {
      return StarkVerifierRef(job.levelParams, job.airOf(program), hash: p2).check(proof) == null;
    } catch (_) {
      return false;
    }
  }
}
