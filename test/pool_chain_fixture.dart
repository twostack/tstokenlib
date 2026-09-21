import 'dart:math';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'pool_verifier_proof_test.dart' show spendP, p1, p2, rootP;


/// The proofs and headers of a pool's first two rounds, with the real V:
/// round 1 takes in a deposit of 500 through receipt slot 0 beside padding
/// transfers, and round 2 spends that note into a 200 note and a withdrawal
/// of 300 to [withdrawalPKH]. At test parameters (4 transfers, 2 receipt
/// slots) unless [production], which proves the 256-transfer throughput
/// plan with nullifiers and 8 receipt slots, as the pool runs it. Nothing here is a
/// transaction; `pool_round_v_test` builds the chain in memory and
/// `pool_localnet_test` builds it on a node, both from this.
class PoolChainFixture {
  final PoolAggregation agg;
  final PoolVerifierGen v;
  final List<int> body;
  final PoolHeader g, h1, h2;
  final PoolRoundProof proof, proof2;
  final List<int> bundles, bundles2;
  final PoolReceipt receipt;
  final PoolWithdrawal withdrawal;

  PoolChainFixture._(this.agg, this.v, this.body, this.g, this.h1, this.h2, this.proof, this.proof2,
      this.bundles, this.bundles2, this.receipt, this.withdrawal);

  static Future<PoolChainFixture> prove({required List<int> withdrawalPKH, bool production = false, bool verbose = false}) async {
    final rng = Random(71);
    List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));
    final agg = production
        ? PoolAggregation.throughput(nullifiers: true, receiptSlots: PoolReceipt.maxPerRound)
        : PoolAggregation(
        spendP: spendP,
        levelSpec: const [
          AggregationLevel(params: p1, logTrace: 15, arity: 2),
          AggregationLevel(params: p2, logTrace: 17, arity: 2),
        ],
        rootP: rootP,
        rootLog: 15,
        nullifierLevel: 1,
        receiptSlots: 2);
    final n = agg.transfers;
    final stmt = PoolStatement.of(agg.tree);
    final v = ShieldedPoolTool.poolVerifier(stmt,
        verifier: StarkVerifierGen(agg.rootP, agg.rootAir(List.filled(stmt.numPublics, 0))));

    final cmTree = NoteCommitmentTree();
    final nullifiers = NullifierTree();
    final g = PoolHeader.genesis(
        emptyCmRoot: SlotScript.lanesBytes(cmTree.root), emptyNfRoot: SlotScript.lanesBytes(nullifiers.root));
    final ring = List.filled(4, cmTree.root);

    SpendNote dummy() => SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    OutputNote out(int v) => OutputNote(pkd: lanes(8), value: v, rho: lanes(3), rcm: lanes(4));
    List<List<int>> bundlesOf(int round) =>
        [for (int t = 0; t < n; t++) List<int>.generate(40 + t % 64, (i) => (i * 7 + t + 31 * round) & 0xff)];

    /// Proves one round of [witnesses] against the pool's trees as they
    /// stand, and advances them.
    Future<(PoolRoundProof, List<PoolPublicInputs>)> prove(
        List<PoolSpendWitness> witnesses, List<List<int>> c, List<List<int>> ring, List<int> receiptTransfers) async {
      final publics = [for (final w in witnesses) w.publics];
      final sw = Stopwatch()..start();
      final spendProofs = [
        for (int t = 0; t < n; t++)
          StarkProver.prove(agg.spendP, PoolSpendAir.air(publics[t]), witnesses[t].rows, rng: Random(1), hash: const Poseidon2ProofHash())
      ];
      if (verbose) print('  $n spend proofs in ${sw.elapsedMilliseconds} ms');
      sw.reset();
      final rootBefore = cmTree.root;
      final j = cmTree.nextSubtree, paths = <List<List<int>>>[];
      final spendLanes = [for (final p in publics) p.toLanes()];
      for (int s = 0; s < agg.tree.subtrees; s++) {
        paths.add(cmTree.subtreePath(j + s));
        cmTree.appendSubtree([for (final l in agg.tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
      }
      final (rootProof, wide) = await agg.aggregate(publics, spendProofs,
          rootBefore: rootBefore,
          rootAfter: cmTree.root,
          index: j,
          paths: paths,
          ring: ring,
          nullifiers: nullifiers,
          receiptTransfers: receiptTransfers,
          rng: Random(3),
          verbose: verbose);
      if (verbose) print('  aggregated in ${sw.elapsedMilliseconds} ms');
      return (PoolRoundProof.root(rootP, agg.rootAir(wide), rootProof, c), publics);
    }

    // ---- round 1: a deposit of 500, whose note has a real owner, and three
    // padding transfers
    final sk = lanes(5), d = lanes(3), rho = lanes(3), rcm = lanes(4);
    final depositNote = OutputNote(pkd: PoolHash.pkd(sk, d), value: 500, rho: rho, rcm: rcm);
    final perTransfer = bundlesOf(1);
    final c = [for (final b in perTransfer) PoolOutHash.bundleHash(b)];
    final bundles = PoolOutHash.encodeBundles(perTransfer);
    final (proof, publics1) = await prove([
      PoolSpendAir.witness(dummy(), dummy(), depositNote, out(0), -500,
          outHash: PoolOutHash.transferLanes(c[0]), anchor: lanes(8)),
      for (int t = 1; t < n; t++)
        PoolSpendAir.witness(dummy(), dummy(), out(0), out(0), 0,
            outHash: PoolOutHash.transferLanes(c[t]), anchor: lanes(8)),
    ], c, ring, const [0]);
    final receipt = PoolReceipt(SlotScript.lanesBytes(publics1[0].cmOut1), BigInt.from(500));
    final h1 = g.advance(
        cmRoot: SlotScript.lanesBytes(cmTree.root),
        nfRoot: SlotScript.lanesBytes(nullifiers.root),
        size: stmt.leavesAppended,
        balance: g.balance + BigInt.from(500),
        outHash: PoolOutHash.roundOutHash(c));

    // ---- round 2: the deposit's note, the tree's first leaf, spent into a
    // 200 note and a withdrawal of 300, anchored to header 1's root
    if (publics1[0].cmOut1.toString() != PoolHash.commit(PoolHash.pkd(sk, d), 500, rho, rcm).$2.toString()) {
      throw StateError('round 1\'s first output is not the deposit note');
    }
    final path = cmTree.path(0);
    final spent = SpendNote(sk: sk, d: d, value: 500, rho: rho, rcm: rcm, siblings: path.siblings, position: path.position);
    final withdrawal = PoolWithdrawal(withdrawalPKH, BigInt.from(300));
    final perTransfer2 = bundlesOf(2);
    final c2 = [for (final b in perTransfer2) PoolOutHash.bundleHash(b)];
    final bundles2 = PoolOutHash.encodeBundles(perTransfer2);
    final (proof2, _) = await prove([
      PoolSpendAir.witness(spent, dummy(), out(200), out(0), 300,
          outHash: PoolOutHash.transferLanes(c2[0], withdrawal: withdrawal)),
      for (int t = 1; t < n; t++)
        PoolSpendAir.witness(dummy(), dummy(), out(0), out(0), 0,
            outHash: PoolOutHash.transferLanes(c2[t]), anchor: lanes(8)),
    ], c2, [for (final r in h1.ring) _lanesOf(r)], const []);
    final h2 = h1.advance(
        cmRoot: SlotScript.lanesBytes(cmTree.root),
        nfRoot: SlotScript.lanesBytes(nullifiers.root),
        size: 2 * stmt.leavesAppended,
        balance: h1.balance - BigInt.from(300),
        outHash: PoolOutHash.roundOutHash(c2));
    if (h2.nfRoot.toString() == h1.nfRoot.toString()) {
      throw StateError('round 2 spends a real note, so its nullifier goes in');
    }
    return PoolChainFixture._(agg, v, v.body(), g, h1, h2, proof, proof2, bundles, bundles2, receipt, withdrawal);
  }
}

List<int> _lanesOf(List<int> bytes) => [
      for (int i = 0; i < bytes.length; i += 4)
        bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)
    ];
