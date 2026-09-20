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

import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import '../builder/pp1_sp_lock_builder.dart';
import '../builder/pp1_sp_unlock_builder.dart';
import '../crypto/note_commitment_tree.dart';
import '../crypto/note_encryption.dart';
import '../crypto/m31.dart';
import '../crypto/nullifier_set.dart';
import '../crypto/stark_prover.dart';
import '../crypto/stark_prover_ref.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_script_gen.dart';
import '../script_gen/slot_script_common.dart';
import '../script_gen/subtree_append_slot_gen.dart';
import '../script_gen/verifier_slot_gen.dart';
import '../recursion/prover_pool.dart';
import '../recursion/pool_aggregator.dart';

/// A transfer submitted to a round: a spend proof with its publics and the
/// serialised extra outputs (unshield payees, deposit change) it committed to.
class PoolTransfer {
  final PoolPublicInputs publics;
  final StarkProof proof;
  final Uint8List extraOutputs;
  /// The issuer's authorisation: a mint of a non-BSV asset or a transfer
  /// of a gated one needs it (the state script checks it).
  final IssuerAuth? auth;
  PoolTransfer(this.publics, this.proof, this.extraOutputs, {this.auth});

  bool get needsAuth => !PoolHash.isBsv(publics.asset) && (publics.publicOut < 0 || PoolHash.isGated(publics.asset));

  /// The one note every padding transfer pays its two outputs to: zero
  /// value, the zero address, zero randomness. Its commitment is a public
  /// constant, so a reader knows a padding transfer's leaves without any
  /// note data on chain (commitments are not public lanes in aggregated
  /// mode). Anyone can spend it, once, for nothing.
  static final paddingNote = OutputNote(
      pkd: List.filled(PoolHash.digestLanes, 0), value: 0, rho: List.filled(PoolHash.rhoLanes, 0), rcm: List.filled(PoolHash.rcmLanes, 0));
  static final List<int> paddingCm = paddingNote.cm;

  /// A padding transfer for an aggregated round: a spend of two dummies
  /// (fresh random keys and rho) into two copies of [paddingNote], nothing
  /// leaving the pool, no extra outputs. It is proved against the zero
  /// anchor: the ring check is waived when neither input is real, so it can
  /// be proved at any time and used in any round. Proving one costs a spend
  /// proof (about 1.5 s at production parameters).
  static PoolTransfer padding(StarkParams spendP, {Random? rng}) {
    final r = rng ?? Random.secure();
    List<int> lanes(int n) => List.generate(n, (_) => r.nextInt(M31.p));
    final a = SpendNote.dummy(sk: lanes(PoolHash.skLanes), rho: lanes(PoolHash.rhoLanes));
    final b = SpendNote.dummy(sk: lanes(PoolHash.skLanes), rho: lanes(PoolHash.rhoLanes));
    final w = PoolSpendAir.witness(a, b, paddingNote, paddingNote, 0,
        anchor: List.filled(8, 0), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    assert(w.publics.isPadding);
    final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: r, hash: const Poseidon2ProofHash());
    return PoolTransfer(w.publics, proof, Uint8List(0));
  }
}

/// The coordinator's stock of padding transfers. An aggregated round has a
/// fixed number of transfers, so a round with fewer real ones is filled from
/// here; [fill] proves ahead of time (between rounds) and [take] proves any
/// shortfall on the spot.
class PaddingSupply {
  final StarkParams spendP;
  final Random _rng;
  final List<PoolTransfer> _stock = [];
  PaddingSupply(this.spendP, {Random? rng}) : _rng = rng ?? Random.secure();

  int get stock => _stock.length;

  /// Proves until [target] padding transfers are in stock.
  void fill(int target) {
    while (_stock.length < target) {
      _stock.add(PoolTransfer.padding(spendP, rng: _rng));
    }
  }

  /// [n] padding transfers, from stock first.
  List<PoolTransfer> take(int n) {
    final out = <PoolTransfer>[];
    while (out.length < n && _stock.isNotEmpty) {
      out.add(_stock.removeLast());
    }
    while (out.length < n) {
      out.add(PoolTransfer.padding(spendP, rng: _rng));
    }
    return out;
  }
}

/// A signed transparent input added to a round (a deposit's funding).
class FundingInput {
  final Transaction tx;
  final int vout;
  final TransactionSigner signer;
  final SVPublicKey pubKey;
  FundingInput(this.tx, this.vout, this.signer, this.pubKey);
}

/// The pool as its wallets and coordinator track it: the header of the live
/// state output, its vault, the commitment tree and the nullifier set, and
/// the transaction holding it. Advanced by [ShieldedPoolTool.createRoundTxn].
class PoolLedger {
  PP1SpHeader header;
  int vault;
  Transaction tx; // the transaction whose vout 0 is the state
  final NoteCommitmentTree tree = NoteCommitmentTree();
  final NullifierSet nullifiers = NullifierSet();
  PoolLedger(this.header, this.vault, this.tx);

  List<int> get anchor => NullifierSet.toLanes(header.cmRoot);

  /// The header's ring of roots as lanes, [anchor] first.
  List<List<int>> get ringLanes => [for (final r in header.ring) NullifierSet.toLanes(r)];
}

/// Builds the PP1_SP transactions: issuance, genesis (the create), rounds.
///
/// All transactions are assembled directly (no change output of the tool's
/// own in a round: whatever the vault, the slots and the extra outputs leave
/// is the fee). Slots pay 1 satoshi each.
class ShieldedPoolTool {
  final PP1SpScriptGen gen;
  final NetworkType networkType;
  final int sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  ShieldedPoolTool(this.gen, {this.networkType = NetworkType.TEST});

  static const int stateVout = 0;
  int get k => gen.k;

  TransactionInput _input(Transaction tx, int vout, UnlockingScriptBuilder builder) =>
      TransactionInput(tx.id, vout, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: builder);

  static List<int> outpointBytes(TransactionInput i) => [
        ...hex.decode(i.prevTxnId).reversed,
        ...(ByteData(4)..setUint32(0, i.prevTxnOutputIndex, Endian.little)).buffer.asUint8List(),
      ];
  static List<int> prevoutsAfter(Transaction t, int from) => [for (final i in t.inputs.skip(from)) ...outpointBytes(i)];

  Uint8List _preimage(Transaction t, int input, SVScript lock, int sats, int type) =>
      Sighash().createSighashPreImage(t, type, input, lock, BigInt.from(sats))!;

  /// The issuance: output 0 is the issued state (1 sat), output 1 an
  /// `OP_RETURN` marker, output 2 the change. tokenId = [fundingTx]'s txid;
  /// output 0 of [fundingTx] is what the genesis will spend, so it must be
  /// the creator's and must stay unspent until then.
  Transaction createIssuanceTxn(Transaction fundingTx, int fundingVout, TransactionSigner signer, SVPublicKey fundingPub,
      Address changeAddress, List<int> rabinPubKeyHash,
      {int fee = 500, List<int>? metadata}) {
    if (fundingVout == 0) throw ArgumentError('output 0 of the funding transaction is reserved for the genesis');
    final header = PP1SpHeader.issued(tokenId: fundingTx.hash, rabinPubKeyHash: rabinPubKeyHash);
    final t = Transaction()
      ..version = 1
      ..nLockTime = 0;
    t.inputs.add(_input(fundingTx, fundingVout, P2PKHUnlockBuilder(fundingPub)));
    t.outputs.add(TransactionOutput(BigInt.one, gen.lock(header)));
    t.outputs.add(TransactionOutput(BigInt.zero, SVScript.fromByteArray([OpCodes.OP_RETURN, ...(metadata ?? const [4, 0x53, 0x50, 0x31, 0x00])])));
    final change = fundingTx.outputs[fundingVout].satoshis - BigInt.one - BigInt.from(fee);
    t.outputs.add(TransactionOutput(change, P2PKHLockBuilder.fromAddress(changeAddress).getScriptPubkey()));
    signer.sign(t, fundingTx.outputs[fundingVout], 0);
    return t;
  }

  /// The genesis: input 0 spends (tokenId, 0), input 1 the issued state;
  /// outputs are the live state with [vault] satoshis, K verifier slots, the
  /// append slot and the change. Returns the transaction and the ledger.
  (Transaction, PoolLedger) createGenesisTxn(Transaction issuanceTx, Transaction fundingTx, TransactionSigner signer,
      SVPublicKey fundingPub, Address changeAddress,
      {required List<int> rabinN,
      required List<int> rabinS,
      required int rabinPadding,
      required List<int> identityTxId,
      required List<int> ed25519PubKey,
      required int vault,
      int fee = 1000}) {
    final issued = PP1SpLockBuilder.fromScript(issuanceTx.outputs[stateVout].script).header;
    if (issued.phase != 0) throw ArgumentError('not an issued pool');
    final live = issued.live();
    final funding = fundingTx.outputs[0].satoshis.toInt();
    final change = funding + 1 - vault - gen.numSlots - fee;
    if (change < 0) throw ArgumentError('funding output 0 does not cover the vault, the slots and the fee');
    final extras = SlotScript.output(P2PKHLockBuilder.fromAddress(changeAddress).getScriptPubkey().buffer, value: change);
    final outs = gen.roundOutputs(live, vault, [for (int i = 0; i < gen.numResults; i++) VerifierSlotGen.emptyResultOutput()], [extras]);
    final unlock = PP1SpUnlockBuilder.create(gen,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: rabinPadding, identityTxId: identityTxId, ed25519PubKey: ed25519PubKey,
        vault: vault, extras: extras);
    final t = _assemble([
      _input(fundingTx, 0, P2PKHUnlockBuilder(fundingPub)),
      _input(issuanceTx, stateVout, unlock),
    ], outs);
    signer.sign(t, fundingTx.outputs[0], 0);
    unlock.preimage = _preimage(t, 1, issuanceTx.outputs[stateVout].script, 1, sigHashAll);
    return (t, PoolLedger(live, vault, t));
  }

  /// A round: input 0 the state, 1..K the verifier slots, K+1 the append
  /// slot (the parent's vouts K+2..2K+2), then any deposit [funding] inputs;
  /// outputs the new state, the K + 1 results, fresh slots and the transfers'
  /// extra outputs. Verifies nothing itself; advances [ledger].

  /// The outputs of [ledger]'s transaction a round spends, in input order.
  List<TransactionOutput> spentByRound(PoolLedger ledger) =>
      [ledger.tx.outputs[stateVout], for (final v in gen.slotVouts) ledger.tx.outputs[v]];

  /// An aggregated round (the generator's aggregated mode): up to
  /// [agg].transfers transfers, a short round filled from [padding], folded
  /// by [agg] into one root proof for the single verifier slot; the round
  /// transaction is input 0 the state, input 1 the slot, then the deposit
  /// [funding] inputs. With [level1] the aggregation's level-1 nodes are
  /// proved through that prover (the coordinator's [ProverPool]) instead of
  /// inline, which is why building a round is asynchronous.
  Future<Transaction> createAggregatedRoundTxn(PoolLedger ledger, List<PoolTransfer> transfers, PoolAggregation agg,
      {List<FundingInput> funding = const [],
      PaddingSupply? padding,
      Random? rng,
      NodeProver? level1,
      bool verbose = false}) async {
    if (!gen.aggregated) throw StateError('the generator is not in aggregated mode');
    if (agg.transfers != gen.n) throw StateError('the aggregation folds ${agg.transfers} transfers, the round holds ${gen.n}');
    if (transfers.length > gen.n) throw ArgumentError('a round holds at most ${gen.n} transfers');
    if (transfers.length < gen.n) {
      if (padding == null) throw ArgumentError('${transfers.length} of ${gen.n} transfers: a short round needs a padding supply');
      transfers = [...transfers, ...padding.take(gen.n - transfers.length)];
    }
    final parent = ledger.tx;
    final h = ledger.header;
    for (int i = 0; i < transfers.length; i++) {
      final want = PoolPublicInputs.outHashLanes(transfers[i].extraOutputs);
      for (int j = 0; j < 8; j++) {
        if (transfers[i].publics.outHash[j] != want[j]) throw ArgumentError('transfer $i: its publics do not commit to its extra outputs');
      }
      if (transfers[i].needsAuth && transfers[i].auth == null) throw ArgumentError('transfer $i needs the issuer\'s authorisation');
    }
    final full = <PP1SpTransfer>[
      for (final t in transfers)
        PP1SpTransfer(t.publics, t.extraOutputs, t.publics.real1 ? ledger.nullifiers.insert(NullifierSet.fromLanes(t.publics.nf1)) : null,
            t.publics.real2 ? ledger.nullifiers.insert(NullifierSet.fromLanes(t.publics.nf2)) : null,
            auth: t.auth)
    ];
    // the tree: whole subtrees of the transfers' commitments, in order
    final rootBefore = ledger.anchor;
    final j = ledger.tree.nextSubtree;
    final spendLanes = [for (final t in transfers) t.publics.toLanes()];
    final paths = <List<List<int>>>[];
    for (int s = 0; s < agg.tree.subtrees; s++) {
      paths.add(ledger.tree.subtreePath(j + s));
      ledger.tree.appendSubtree([for (final l in agg.tree.subtreeLeavesOf(spendLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }
    final rootAfter = ledger.tree.root;
    if (agg.tree.leavesAppended != gen.leavesAppended) throw StateError('the aggregation and the generator disagree on the leaves per round');
    var vault = ledger.vault;
    for (final t in transfers) {
      if (PoolHash.isBsv(t.publics.asset)) vault -= t.publics.publicOut;
    }
    if (vault < 0) throw ArgumentError('the round would overdraw the vault');
    final next = h.afterRound(rootAfter, ledger.nullifiers.root, leaves: gen.leavesAppended);
    final extras = [for (final t in transfers) if (t.extraOutputs.isNotEmpty) t.extraOutputs];

    final (rootProof, wide) = await agg.aggregate([for (final t in transfers) t.publics], [for (final t in transfers) t.proof],
        rootBefore: rootBefore,
        rootAfter: rootAfter,
        index: j,
        paths: paths,
        ring: ledger.ringLanes,
        rng: rng,
        level1: level1,
        verbose: verbose);
    final outs = gen.roundOutputs(next, vault, [VerifierSlotGen.resultOutput(wide)], extras);
    final stateUnlock = PP1SpUnlockBuilder.roundAggregated(gen,
        extraPrevouts: const [], transfers: full, roundLanes: wide.sublist(agg.tree.roundOffset));
    final slotUnlock = VerifierSlotUnlockBuilder.proofLanes(gen.verifierSlot, rootProof, wide);
    final t = _assemble([
      _input(parent, stateVout, stateUnlock),
      _input(parent, gen.slotVout0, slotUnlock),
      for (final f in funding) _input(f.tx, f.vout, P2PKHUnlockBuilder(f.pubKey)),
    ], outs);
    for (int i = 0; i < funding.length; i++) {
      funding[i].signer.sign(t, funding[i].tx.outputs[funding[i].vout], 2 + i);
    }
    stateUnlock
      ..extraPrevouts = prevoutsAfter(t, 2)
      ..preimage = _preimage(t, 0, parent.outputs[stateVout].script, ledger.vault, sigHashAll);
    slotUnlock
      ..prevoutsTail = prevoutsAfter(t, 1)
      ..preimage = _preimage(t, 1, parent.outputs[gen.slotVout0].script, 1, SlotScript.sighashSingle);
    ledger
      ..header = next
      ..vault = vault
      ..tx = t;
    return t;
  }
  Transaction createRoundTxn(PoolLedger ledger, List<PoolTransfer?> transfers, {List<FundingInput> funding = const []}) {
    if (transfers.length != k) throw ArgumentError('a round has $k transfer slots');
    final parent = ledger.tx;
    final h = ledger.header;
    for (int i = 0; i < k; i++) {
      final t = transfers[i];
      if (t == null) continue;
      final want = PoolPublicInputs.outHashLanes(t.extraOutputs);
      for (int j = 0; j < 8; j++) {
        if (t.publics.outHash[j] != want[j]) throw ArgumentError('transfer $i: its publics do not commit to its extra outputs');
      }
      if (t.needsAuth && t.auth == null) throw ArgumentError('transfer $i needs the issuer\'s authorisation');
    }
    // apply to the wallet model first: nullifier witnesses, subtree, roots
    final full = <PP1SpTransfer?>[];
    for (final t in transfers) {
      if (t == null) {
        full.add(null);
        continue;
      }
      // a dummy input's nullifier is not inserted (the proof's real flags say which)
      final nf1 = t.publics.real1 ? ledger.nullifiers.insert(NullifierSet.fromLanes(t.publics.nf1)) : null;
      final nf2 = t.publics.real2 ? ledger.nullifiers.insert(NullifierSet.fromLanes(t.publics.nf2)) : null;
      full.add(PP1SpTransfer(t.publics, t.extraOutputs, nf1, nf2, auth: t.auth));
    }
    final rootBefore = ledger.anchor;
    final j = ledger.tree.nextSubtree;
    final siblings = ledger.tree.subtreePath(j);
    final cms = roundLeaves([for (final t in transfers) t?.publics]);
    ledger.tree.appendSubtree(cms);
    final rootAfter = ledger.tree.root;
    final results = [
      for (final t in transfers) t == null ? VerifierSlotGen.emptyResultOutput() : VerifierSlotGen.resultOutput(t.publics.toLanes()),
      SubtreeAppendSlotGen.resultOutput(SubtreeAppendSlotGen.payload(rootBefore, rootAfter, j, cms)),
    ];
    var vault = ledger.vault;
    for (final t in transfers) {
      if (t != null && PoolHash.isBsv(t.publics.asset)) vault -= t.publics.publicOut;
    }
    if (vault < 0) throw ArgumentError('the round would overdraw the vault');
    final next = h.afterRound(rootAfter, ledger.nullifiers.root);
    final extras = [for (final t in transfers) if (t != null && t.extraOutputs.isNotEmpty) t.extraOutputs];
    final outs = gen.roundOutputs(next, vault, results, extras);

    final stateUnlock = PP1SpUnlockBuilder.round(gen, extraPrevouts: const [], rootAfter: rootAfter, transfers: full);
    final slotUnlocks = <VerifierSlotUnlockBuilder>[
      for (final t in transfers)
        t == null ? VerifierSlotUnlockBuilder.skip(gen.verifierSlot) : VerifierSlotUnlockBuilder.proof(gen.verifierSlot, t.proof, t.publics)
    ];
    final appendUnlock = AppendSlotUnlockBuilder(gen.appendSlot, index: j, rootBefore: rootBefore, siblings: siblings, cms: cms);
    final t = _assemble([
      _input(parent, stateVout, stateUnlock),
      for (int i = 0; i < k; i++) _input(parent, gen.slotVout0 + i, slotUnlocks[i]),
      _input(parent, gen.appendVout, appendUnlock),
      for (final f in funding) _input(f.tx, f.vout, P2PKHUnlockBuilder(f.pubKey)),
    ], outs);
    for (int i = 0; i < funding.length; i++) {
      funding[i].signer.sign(t, funding[i].tx.outputs[funding[i].vout], k + 2 + i);
    }
    // the preimages, now that inputs and outputs are fixed
    stateUnlock
      ..extraPrevouts = prevoutsAfter(t, k + 2)
      ..preimage = _preimage(t, 0, parent.outputs[stateVout].script, ledger.vault, sigHashAll);
    final tail = prevoutsAfter(t, 1);
    for (int i = 0; i < k; i++) {
      slotUnlocks[i]
        ..prevoutsTail = tail
        ..preimage = _preimage(t, 1 + i, parent.outputs[gen.slotVout0 + i].script, 1, SlotScript.sighashSingle);
    }
    appendUnlock
      ..prevoutsTail = tail
      ..preimage = _preimage(t, k + 1, parent.outputs[gen.appendVout].script, 1, SlotScript.sighashSingle);
    ledger
      ..header = next
      ..vault = vault
      ..tx = t;
    return t;
  }

  Transaction _assemble(List<TransactionInput> ins, List<Uint8List> outs) {
    final t = Transaction()
      ..version = 1
      ..nLockTime = 0;
    t.inputs.addAll(ins);
    t.outputs.addAll(outs.expand(outputsFromBytes));
    return t;
  }

  /// Every output serialised in [bytes], in order (a transfer's extras may
  /// hold several: its note-data output, then payouts).
  static List<TransactionOutput> outputsFromBytes(Uint8List bytes) {
    final out = <TransactionOutput>[];
    var at = 0;
    while (at < bytes.length) {
      final o = outputFromBytes(bytes, at);
      out.add(o);
      at += 8 + PP1SpScriptGen.varint(o.script.buffer.length).length + o.script.buffer.length;
    }
    return out;
  }

  static TransactionOutput outputFromBytes(Uint8List bytes, [int at = 0]) {
    final sats = ByteData.sublistView(bytes, at, at + 8).getUint64(0, Endian.little);
    var i = at + 8;
    int len;
    if (bytes[i] < 0xfd) {
      len = bytes[i];
      i += 1;
    } else if (bytes[i] == 0xfd) {
      len = bytes[i + 1] | (bytes[i + 2] << 8);
      i += 3;
    } else {
      len = ByteData.sublistView(bytes, i + 1, i + 5).getUint32(0, Endian.little);
      i += 5;
    }
    return TransactionOutput(BigInt.from(sats), SVScript.fromByteArray(bytes.sublist(i, i + len)));
  }

  /// The leaves a round appends, by slot: transfer t's commitments sit at
  /// leaves 2t and 2t+1 of the subtree (empty leaves for an idle slot), so
  /// a note's position is subtreeIndex * 32 + 2 * slot + which.
  static List<List<int>> roundLeaves(List<PoolPublicInputs?> transfers) =>
      [for (final t in transfers) ...(t == null ? [MerkleFrontier.emptyLeaf, MerkleFrontier.emptyLeaf] : [t.cmOut1, t.cmOut2])];

  /// Serialise a P2PKH payout as an extra output.
  static Uint8List payout(Address to, int sats) => SlotScript.output(P2PKHLockBuilder.fromAddress(to).getScriptPubkey().buffer, value: sats);

  /// A transfer's extra outputs: its note-data output (the ciphertexts of
  /// its output notes) first, then any payouts. The transfer's outHash
  /// commits to all of it.
  static Uint8List extras(List<NoteBundle> bundles, [List<Uint8List> payouts = const []]) =>
      Uint8List.fromList([if (bundles.isNotEmpty) ...NoteBundle.output(bundles), for (final p in payouts) ...p]);
}
