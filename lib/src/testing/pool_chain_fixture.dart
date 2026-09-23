import 'dart:math';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart' show StarkProof;
import 'package:tstokenlib/src/recursion/pool_aggregator.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/script_gen/stark_verifier_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_transfer.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart' show StarkParams;

/// The STARK parameters the test chain proves at: small enough to prove in
/// seconds, the same shape as production. A pool run on these is not sound;
/// they exist so the chain, the reader, the coordinator and a wallet can be
/// exercised end to end without a prover farm.
class PoolTestParams {
  static const spend = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  static const level1 = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  static const level2 = StarkParams(logTrace: 17, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
  static const root = StarkParams(logTrace: 15, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);
}

const spendP = PoolTestParams.spend;
const p1 = PoolTestParams.level1;
const p2 = PoolTestParams.level2;
const rootP = PoolTestParams.root;


/// The proofs and headers of a pool's first two rounds, with the real V:
/// round 1 takes in a deposit of 500 through receipt slot 0 beside padding
/// transfers, and round 2 spends that note into a 200 note and a withdrawal
/// of 300 to [withdrawalPKH]. At test parameters (4 transfers, 2 receipt
/// slots) unless [production], which proves the 256-transfer throughput
/// plan with nullifiers and 8 receipt slots, as the pool runs it. Nothing here is a
/// transaction; `pool_round_v_test` builds the chain in memory and
/// `pool_localnet_test` builds it on a node, both from this.
///
/// The notes are real: the deposit note and round 2's 200 change note go
/// to [wallet]'s address [walletD], every other real output to a
/// stranger's, and each real transfer carries the hybrid bundles of its two
/// outputs. Padding transfers pay [ShieldedTransfer.paddingNote] with an
/// empty bundle, as the coordinator's are. So the chain a reader and a
/// scanner are tested on is the one that is mined.
class PoolChainFixture {
  final PoolAggregation agg;
  final PoolVerifierGen v;
  final List<int> body;
  final PoolHeader g, h1, h2;
  final PoolRoundProof proof, proof2;
  final List<int> bundles, bundles2;
  final PoolReceipt receipt;
  final PoolWithdrawal withdrawal;

  /// Each round's transfers in round order. Round 1's first is the
  /// deposit, without the covenant outpoint it backs: that is built later,
  /// from [receipt].
  final List<ShieldedTransfer> transfers1, transfers2;

  /// The wallet the deposit and the change are paid to, and the address.
  final PoolWalletKeys wallet;
  final List<int> walletD;

  PoolChainFixture._(this.agg, this.v, this.body, this.g, this.h1, this.h2, this.proof, this.proof2,
      this.bundles, this.bundles2, this.receipt, this.withdrawal, this.transfers1, this.transfers2, this.wallet, this.walletD);

  /// The plan the fixture proves under: the 256-transfer throughput plan
  /// with nullifiers and 8 receipt slots at [production], else a 4-transfer
  /// plan at test parameters with 2 receipt slots. A coordinator run on the
  /// fixture's chain is configured with the same.
  static PoolAggregation plan({bool production = false}) => production
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

  /// With [aggregate] false the spend proofs are made and the trees
  /// advanced, but no round is aggregated: [proof] and [proof2] are bare
  /// and [transfers1] and [transfers2] are what a coordinator, which
  /// aggregates itself, takes in. That saves the two aggregations (about
  /// 12 minutes at production) when only the transfers are wanted.
  static Future<PoolChainFixture> prove(
      {required List<int> withdrawalPKH, bool production = false, bool verbose = false, bool aggregate = true}) async {
    final rng = Random(71);
    List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));
    final agg = plan(production: production);
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
    final wallet = PoolWalletKeys(lanes(5)), stranger = PoolWalletKeys(lanes(5));
    final walletD = PoolHash.diversifier(wallet.ivk, 0);
    final walletAddr = await NoteAddress.derive(wallet.ivk, walletD);
    final strangerAddr = await NoteAddress.at(stranger.ivk, 0);
    NotePlaintext plain(List<int> d, int v) => NotePlaintext(asset: PoolHash.bsvAsset, d: d, value: v, rho: lanes(3), rcm: lanes(4));

    /// A real transfer's two outputs, [v1] to the wallet and [v2] to the
    /// stranger, and the bundle carrying them, sent under [ovk].
    Future<(OutputNote, OutputNote, NotePlaintext, List<int>)> outputs(int v1, int v2, List<int> ovk) async {
      final p1 = plain(walletD, v1), p2 = plain(strangerAddr.d, v2);
      final bundle = [
        ...(await NoteEncryption.encrypt(p1, walletAddr, ovk, rng: rng)).bytes,
        ...(await NoteEncryption.encrypt(p2, strangerAddr, ovk, rng: rng)).bytes,
      ];
      return (p1.toOutputNote(walletAddr.pkd), p2.toOutputNote(strangerAddr.pkd), p1, bundle);
    }

    List<List<int>> bundlesOf(List<int> first) => [first, for (int t = 1; t < n; t++) const <int>[]];

    /// Proves one round of [witnesses] against the pool's trees as they
    /// stand, and advances them.
    Future<(PoolRoundProof, List<PoolPublicInputs>, List<StarkProof>)> prove(
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
      if (!aggregate) {
        // the aggregation is what inserts the nullifiers; do that by hand
        for (final p in publics) {
          if (p.real1) nullifiers.insert(p.nf1);
          if (p.real2) nullifiers.insert(p.nf2);
        }
        return (PoolRoundProof.bare(List.filled(stmt.numPublics, 0), c), publics, spendProofs);
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
      return (PoolRoundProof.root(agg.rootP, agg.rootAir(wide), rootProof, c), publics, spendProofs);
    }

    // ---- round 1: a deposit of 500, whose note is the wallet's, and
    // padding transfers
    final (depositNote, depositZero, depositPlain, depositBundle) = await outputs(500, 0, stranger.ovk);
    final perTransfer = bundlesOf(depositBundle);
    final c = [for (final b in perTransfer) PoolOutHash.bundleHash(b)];
    final bundles = PoolOutHash.encodeBundles(perTransfer);
    final (proof, publics1, spends1) = await prove([
      PoolSpendAir.witness(dummy(), dummy(), depositNote, depositZero, -500,
          outHash: PoolOutHash.transferLanes(c[0]), anchor: lanes(8)),
      for (int t = 1; t < n; t++) ShieldedTransfer.paddingWitness(rng: rng),
    ], c, ring, const [0]);
    final receipt = PoolReceipt(SlotScript.lanesBytes(publics1[0].cmOut1), BigInt.from(500));
    final h1 = g.advance(
        cmRoot: SlotScript.lanesBytes(cmTree.root),
        nfRoot: SlotScript.lanesBytes(nullifiers.root),
        size: stmt.leavesAppended,
        balance: g.balance + BigInt.from(500),
        outHash: PoolOutHash.roundOutHash(c));
    final transfers1 = [for (int t = 0; t < n; t++) ShieldedTransfer(publics1[t], spends1[t], perTransfer[t])];

    // ---- round 2: the deposit's note, the tree's first leaf, spent into a
    // 200 change note to the wallet and a withdrawal of 300, anchored to
    // header 1's root
    final walletPkd = walletAddr.pkd;
    if (publics1[0].cmOut1.toString() != depositPlain.cmUnder(walletPkd).toString()) {
      throw StateError('round 1\'s first output is not the deposit note');
    }
    final path = cmTree.path(0);
    final spent = SpendNote(
        sk: wallet.sk, d: walletD, value: 500, rho: depositPlain.rho, rcm: depositPlain.rcm, siblings: path.siblings, position: path.position);
    final withdrawal = PoolWithdrawal(withdrawalPKH, BigInt.from(300));
    final (changeNote, changeZero, _, changeBundle) = await outputs(200, 0, wallet.ovk);
    final perTransfer2 = bundlesOf(changeBundle);
    final c2 = [for (final b in perTransfer2) PoolOutHash.bundleHash(b)];
    final bundles2 = PoolOutHash.encodeBundles(perTransfer2);
    final (proof2, publics2, spends2) = await prove([
      PoolSpendAir.witness(spent, dummy(), changeNote, changeZero, 300,
          outHash: PoolOutHash.transferLanes(c2[0], withdrawal: withdrawal)),
      for (int t = 1; t < n; t++) ShieldedTransfer.paddingWitness(rng: rng),
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
    final transfers2 = [
      for (int t = 0; t < n; t++) ShieldedTransfer(publics2[t], spends2[t], perTransfer2[t], withdrawal: t == 0 ? withdrawal : null)
    ];
    for (final t in [...transfers1, ...transfers2]) {
      final why = t.refusal();
      if (why != null) throw StateError('the fixture built a transfer that refuses itself: $why');
    }
    return PoolChainFixture._(agg, v, v.body(), g, h1, h2, proof, proof2, bundles, bundles2, receipt, withdrawal, transfers1, transfers2,
        wallet, walletD);
  }
}

List<int> _lanesOf(List<int> bytes) => [
      for (int i = 0; i < bytes.length; i += 4)
        bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)
    ];
