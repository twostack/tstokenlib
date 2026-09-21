import 'dart:math';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'pool_verifier_test.dart' show VRound, ownerKey, strangerKey, pkhOf, refused;

// Test-size parameters, as the nullifier aggregation test proves at.
const spendP = StarkParams(
    logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
const p1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
const p2 = StarkParams(logTrace: 17, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
const rootP = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

/// A round V checks against a real root proof: the same transaction harness
/// as [VRound], with the proof's unlock under the tail instead of bare lanes.
class ProvedRound extends VRound {
  static late PoolAggregation agg;
  static late PoolVerifierGen gen;
  static late StarkProof proof;
  static late List<int> wide;

  /// The lanes the unlock claims, when a test makes them differ from [wide].
  List<int>? claimed;

  ProvedRound(
      {required List<List<int>> bundleHashes,
      required List<PoolWithdrawal> withdrawals,
      required List<PoolReceipt> receipts,
      required List<int> h0,
      required List<int> h1}) {
    this.bundleHashes = bundleHashes;
    this.withdrawals = withdrawals;
    this.receipts = receipts;
    this.h0 = h0;
    this.h1 = h1;
  }

  @override
  PoolVerifierGen get v => gen;

  @override
  List<int> belowTail() => StarkVerifierGen(rootP, agg.rootAir(claimed ?? wide)).buildUnlock(proof).buffer;
}

void main() {
  final rng = Random(61);
  List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));

  // the pool's commitment tree: six notes, padded to one whole subtree, so
  // the round appends at subtree index 1 and every spend anchors to its root
  final cmTree = NoteCommitmentTree();
  final keys = <(List<int>, List<int>, int, List<int>, List<int>, int)>[];
  for (int i = 0; i < 6; i++) {
    final sk = lanes(5), d = lanes(3), rho = lanes(3), rcm = lanes(4), value = 1000 + i;
    keys.add((sk, d, value, rho, rcm, cmTree.append(PoolHash.commit(PoolHash.pkd(sk, d), value, rho, rcm).$2)));
  }
  while (cmTree.size % NoteCommitmentTree.subtreeLeaves != 0) {
    cmTree.append(lanes(8));
  }
  SpendNote note(int i) {
    final (sk, d, value, rho, rcm, pos) = keys[i];
    final p = cmTree.path(pos);
    return SpendNote(sk: sk, d: d, value: value, rho: rho, rcm: rcm, siblings: p.siblings, position: p.position);
  }

  OutputNote out(int v) => OutputNote(pkd: lanes(8), value: v, rho: lanes(3), rcm: lanes(4));
  SpendNote dummy() => SpendNote.dummy(sk: lanes(5), rho: lanes(3));

  final rootBefore = cmTree.root;
  final ring = [rootBefore, lanes(8), lanes(8), lanes(8)];
  final bundleHashes = [for (int t = 0; t < 4; t++) PoolOutHash.bundleHash(lanes(20 + t).map((x) => x & 0xff).toList())];
  final w0 = PoolWithdrawal(pkhOf(ownerKey), BigInt.from(500)), w3 = PoolWithdrawal(pkhOf(strangerKey), BigInt.from(7));
  List<int> oh(int t, [PoolWithdrawal? w]) => PoolOutHash.transferLanes(bundleHashes[t], withdrawal: w);
  // 0 withdraws 500, 1 moves a note, 2 deposits 500 through receipt slot 0,
  // 3 withdraws 7
  final witnesses = [
    PoolSpendAir.witness(note(0), note(1), out(1500), out(1), 500, outHash: oh(0, w0)),
    PoolSpendAir.witness(note(2), dummy(), out(1002), out(0), 0, outHash: oh(1)),
    PoolSpendAir.witness(dummy(), dummy(), out(500), out(0), -500, outHash: oh(2), anchor: lanes(8)),
    PoolSpendAir.witness(note(3), note(4), out(2000), out(0), 7, outHash: oh(3, w3)),
  ];
  final publics = [for (final w in witnesses) w.publics];
  final nullifiers = NullifierTree();
  for (int i = 0; i < 5; i++) {
    nullifiers.insert(lanes(8));
  }
  final nfBefore = nullifiers.root;
  const balance0 = 100000;

  late ProvedRound Function() honest;

  setUpAll(() async {
    final sw = Stopwatch()..start();
    final agg = PoolAggregation(
        spendP: spendP,
        levelSpec: const [
          AggregationLevel(params: p1, logTrace: 15, arity: 2),
          AggregationLevel(params: p2, logTrace: 17, arity: 2),
        ],
        rootP: rootP,
        rootLog: 15,
        nullifierLevel: 1,
        receiptSlots: 2);
    final spendProofs = [
      for (int t = 0; t < 4; t++)
        StarkProver.prove(spendP, PoolSpendAir.air(publics[t]), witnesses[t].rows, rng: Random(1), hash: const Poseidon2ProofHash())
    ];
    final j = cmTree.nextSubtree, paths = <List<List<int>>>[];
    final spendLanes = [for (final p in publics) p.toLanes()];
    for (int s = 0; s < agg.tree.subtrees; s++) {
      paths.add(cmTree.subtreePath(j + s));
      cmTree.appendSubtree([for (final l in agg.tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final (proof, wide) = await agg.aggregate(publics, spendProofs,
        rootBefore: rootBefore,
        rootAfter: cmTree.root,
        index: j,
        paths: paths,
        ring: ring,
        nullifiers: nullifiers,
        receiptTransfers: const [2],
        rng: Random(3));
    print('  proved the round in ${sw.elapsedMilliseconds} ms');
    sw.reset();
    final stmt = PoolStatement.of(agg.tree);
    final gen = PoolVerifierGen(stmt,
        pp1Program: VRound.pp1Program,
        pp3Program: VRound.pp3Program,
        verifier: StarkVerifierGen(rootP, agg.rootAir(List.filled(stmt.numPublics, 0))));
    final body = gen.body();
    print('  V with the root verifier: body ${body.length} B, generated in ${sw.elapsedMilliseconds} ms');
    ProvedRound.agg = agg;
    ProvedRound.gen = gen;
    ProvedRound.proof = proof;
    ProvedRound.wide = wide;

    final nfAfter = wide.sublist(stmt.nullifierOffset + 8, stmt.nullifierOffset + 16);
    final hdr0 = PoolHeader(
        cmRoot: SlotScript.lanesBytes(rootBefore),
        nfRoot: SlotScript.lanesBytes(nfBefore),
        ring: [for (final r in ring) SlotScript.lanesBytes(r)],
        size: 32 * j,
        balance: BigInt.from(balance0),
        outHash: List.filled(32, 0x11));
    final hdr1 = hdr0.advance(
        cmRoot: SlotScript.lanesBytes(cmTree.root),
        nfRoot: SlotScript.lanesBytes(nfAfter),
        size: 32 * j + stmt.leavesAppended,
        balance: BigInt.from(balance0 - 500 + 500 - 7),
        outHash: PoolOutHash.roundOutHash(bundleHashes));
    honest = () => ProvedRound(
        bundleHashes: bundleHashes,
        withdrawals: [w0, w3],
        receipts: [PoolReceipt(SlotScript.lanesBytes(publics[2].cmOut1), BigInt.from(500))],
        h0: hdr0.encode(),
        h1: hdr1.encode());
  });

  test('V accepts a round of four proved transfers', () {
    final sw = Stopwatch()..start();
    honest().run();
    print('  V ran in ${sw.elapsedMilliseconds} ms');
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('a statement the proof does not prove is refused, though the tail would take it', () {
    // Claim another rootAfter, with header_{N+1} written to match, so every
    // check in the tail passes and only the proof is left to refuse it.
    final r = honest();
    final stmt = PoolStatement.of(ProvedRound.agg.tree);
    final claimed = [...ProvedRound.wide]..[stmt.roundOffset + 8] ^= 1;
    final after = SlotScript.lanesBytes(claimed.sublist(stmt.roundOffset + 8, stmt.roundOffset + 16));
    final lie = List<int>.from(r.h1)
      ..setRange(PoolHeader.cmRootOffset, PoolHeader.cmRootOffset + 32, after)
      ..setRange(PoolHeader.ringOffset, PoolHeader.ringOffset + 32, after);
    r
      ..claimed = claimed
      ..h1 = lie;
    refused(r);
    // the same claim on bare lanes passes the tail, so the refusal above is
    // the proof's
    final bare = _BareRound(claimed, r);
    bare.run();
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('a withdrawal paying someone else is refused with the real proof underneath', () {
    final r = honest();
    r.withdrawals = [PoolWithdrawal(pkhOf(strangerKey), BigInt.from(500)), r.withdrawals[1]];
    refused(r);
  }, timeout: const Timeout(Duration(minutes: 20)));
}

/// [like]'s round, run by the tail alone on the bare [lanes].
class _BareRound extends VRound {
  final List<int> lanes;
  _BareRound(this.lanes, VRound like) {
    bundleHashes = like.bundleHashes;
    withdrawals = like.withdrawals;
    receipts = like.receipts;
    h0 = like.h0;
    h1 = like.h1;
  }

  static final _gen = PoolVerifierGen(PoolStatement.of(ProvedRound.agg.tree),
      pp1Program: VRound.pp1Program, pp3Program: VRound.pp3Program);

  @override
  PoolVerifierGen get v => _gen;

  @override
  List<int> belowTail() => PoolVerifierGen.barePublics(lanes);
}
