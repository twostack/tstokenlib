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

import 'package:dartsv/dartsv.dart';
import '../builder/pp1_sp_legacy_lock_builder.dart';
import '../crypto/nullifier_set.dart';
import '../crypto/note_commitment_tree.dart';
import '../crypto/note_encryption.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_legacy_script_gen.dart';
import '../script_gen/slot_script_common.dart';
import '../script_gen/subtree_append_slot_gen.dart';
import '../script_gen/verifier_slot_gen.dart';
import 'shielded_pool_legacy_tool.dart';

/// What one round did, as read from its transaction: the publics of every
/// used verifier slot (null for an idle one), the subtree index the round
/// filled, and the leaves it appended (transfer t's commitments at 2t and
/// 2t+1, empty leaves for an idle slot; see [ShieldedPoolLegacyTool.roundLeaves]).
class PoolRound {
  final Transaction tx;
  final List<PoolPublicInputs?> transfers;
  final int subtreeIndex;
  final List<List<int>> commitments;
  PoolRound(this.tx, this.transfers, this.subtreeIndex, this.commitments);

  /// The note ciphertexts the round carries (its transfers' note-data
  /// outputs, in output order). Wallets trial-decrypt them; each names the
  /// commitment it is for.
  List<NoteBundle> get noteBundles => [
        for (final o in tx.outputs) ...?NoteBundle.fromScript(o.script.buffer),
      ];
}

/// Rebuilds a [PoolLedger] from the pool's transactions as they appear on
/// chain: the genesis, then each round in order.
///
/// A wallet or coordinator that did not build the rounds itself needs the
/// commitment tree (to prove membership of its notes) and the nullifier set
/// (to build the insertion witnesses of its next spend). Both are a
/// function of the publics the rounds carried, and those are plain pushes
/// in the verifier slots' unlocking scripts, so nothing is decrypted or
/// verified here: the chain already verified the proofs. What the reader
/// does check is that its own model agrees with what the round committed
/// to (the append result and the new header), so a bug in either would be
/// caught at the first round rather than at the wallet's next spend.
class PoolChainReader {
  final PP1SpLegacyScriptGen gen;
  final PoolLedger ledger;
  final List<PoolRound> rounds = [];

  int get k => gen.k;

  PoolChainReader._(this.gen, this.ledger);

  /// Start from the genesis (the create): output 0 is the live state with
  /// an empty tree and an empty nullifier set.
  factory PoolChainReader.fromGenesis(PP1SpLegacyScriptGen gen, Transaction genesisTx) {
    final state = genesisTx.outputs[ShieldedPoolLegacyTool.stateVout];
    final header = PP1SpLegacyLockBuilder.fromScript(state.script).header;
    if (header.phase != 1) throw FormatException('output 0 is not a live pool state');
    if (header.size != 0) throw FormatException('not a genesis: the tree is not empty');
    final ledger = PoolLedger(header, state.satoshis.toInt(), genesisTx);
    if (!_bytesEqual(header.nfRoot, ledger.nullifiers.root) || !_bytesEqual(header.cmRoot, PP1SpLegacyHeader.emptyRootBytes)) {
      throw FormatException('not a genesis: roots are not the empty roots');
    }
    _checkSlots(gen, genesisTx);
    return PoolChainReader._(gen, ledger);
  }

  /// Apply the next round: [roundTx] must spend the ledger's state and
  /// slots. Advances [ledger] and returns what the round did.
  PoolRound apply(Transaction roundTx) {
    if (gen.aggregated) return _applyAggregated(roundTx);
    final parent = ledger.tx;
    _expectSpends(roundTx, 0, parent, ShieldedPoolLegacyTool.stateVout);
    for (int i = 0; i < k; i++) {
      _expectSpends(roundTx, 1 + i, parent, gen.slotVout0 + i);
    }
    _expectSpends(roundTx, k + 1, parent, gen.appendVout);
    if (roundTx.outputs.length < gen.appendVout + 1) throw FormatException('round has too few outputs');

    // the transfers: publics from the slot unlocks, cross-checked with the results
    final transfers = <PoolPublicInputs?>[];
    for (int i = 0; i < k; i++) {
      final publics = readSlot(roundTx.inputs[1 + i].script!);
      final result = roundTx.outputs[1 + i];
      final expected = publics == null ? VerifierSlotGen.emptyResultOutput() : VerifierSlotGen.resultOutput(publics.toLanes());
      if (!_bytesEqual(ShieldedPoolLegacyTool.outputFromBytes(expected).script.buffer, result.script.buffer) || result.satoshis != BigInt.zero) {
        throw FormatException('slot $i: result output does not match its unlocking script');
      }
      transfers.add(publics);
    }

    // apply to the model in slot order, as the state script did
    final rootBefore = ledger.anchor;
    final j = ledger.tree.nextSubtree;
    var vault = ledger.vault;
    for (final t in transfers) {
      if (t == null) continue;
      if (t.real1) ledger.nullifiers.insert(NullifierSet.fromLanes(t.nf1));
      if (t.real2) ledger.nullifiers.insert(NullifierSet.fromLanes(t.nf2));
      if (PoolHash.isBsv(t.asset)) vault -= t.publicOut;
    }
    final cms = ShieldedPoolLegacyTool.roundLeaves(transfers);
    ledger.tree.appendSubtree(cms);
    final rootAfter = ledger.tree.root;

    // the round's own commitments must agree with the model
    final appendResult = roundTx.outputs[k + 1].script.buffer;
    final payload = SubtreeAppendSlotGen.payload(rootBefore, rootAfter, j, cms);
    if (!_bytesEqual(ShieldedPoolLegacyTool.outputFromBytes(SubtreeAppendSlotGen.resultOutput(payload)).script.buffer, appendResult)) {
      throw StateError('the append result disagrees with the rebuilt tree');
    }
    final next = ledger.header.afterRound(rootAfter, ledger.nullifiers.root);
    final state = roundTx.outputs[ShieldedPoolLegacyTool.stateVout];
    if (!_bytesEqual(PP1SpLegacyLockBuilder.fromScript(state.script).header.bytes(), next.bytes())) {
      throw StateError('the new state header disagrees with the rebuilt ledger');
    }
    if (state.satoshis.toInt() != vault) throw StateError('the new vault disagrees with the publics');
    _checkSlots(gen, roundTx);

    ledger
      ..header = next
      ..vault = vault
      ..tx = roundTx;
    final round = PoolRound(roundTx, transfers, j, cms);
    rounds.add(round);
    return round;
  }

  /// An aggregated round: input 1 is the one slot, unlocked with every
  /// transfer's reduced lanes and the round lanes; the root proof also
  /// proved the tree update, so the model's new root must be the one in
  /// the lanes. The commitments are not lanes: each transfer's come from
  /// the note data its outHash attributes to it, or, for a padding
  /// transfer, are the padding constant; the rootAfter check is what makes
  /// that trustworthy, since the proof appended the true ones.
  PoolRound _applyAggregated(Transaction roundTx) {
    final parent = ledger.tx;
    final n = gen.n;
    _expectSpends(roundTx, 0, parent, ShieldedPoolLegacyTool.stateVout);
    _expectSpends(roundTx, 1, parent, gen.slotVout0);
    if (roundTx.outputs.length < gen.slotVout0 + 1) throw FormatException('round has too few outputs');
    final per = gen.lanesPerTransfer;
    final lanes = readSlotLanes(roundTx.inputs[1].script!, n * per + PP1SpLegacyScriptGen.roundLanes);
    if (lanes == null) throw FormatException('an aggregated round cannot skip its slot');
    final expected = VerifierSlotGen.resultOutput(lanes);
    final result = roundTx.outputs[1];
    if (!_bytesEqual(ShieldedPoolLegacyTool.outputFromBytes(expected).script.buffer, result.script.buffer) || result.satoshis != BigInt.zero) {
      throw FormatException('the result output does not match the slot\'s unlocking script');
    }
    final transfers = <PoolPublicInputs?>[];
    var cursor = gen.slotVout0 + 1; // the extra outputs follow the slot
    for (int t = 0; t < n; t++) {
      final reduced = lanes.sublist(t * per, (t + 1) * per);
      final bare = PoolPublicInputs.fromReducedLanes(reduced);
      final (extras, next) = _extrasOf(roundTx, cursor, bare.outHash, t);
      cursor = next;
      final bundles = extras.isEmpty ? null : NoteBundle.fromScript(extras.first.script.buffer);
      final List<int> cm1, cm2;
      if (bundles != null && bundles.length == 2) {
        cm1 = bundles[0].cm;
        cm2 = bundles[1].cm;
      } else if (bundles == null && bare.isPadding) {
        cm1 = cm2 = PoolTransfer.paddingCm;
      } else {
        throw FormatException('transfer $t: no note data to take its two commitments from');
      }
      transfers.add(PoolPublicInputs.fromReducedLanes(reduced, cm1: cm1, cm2: cm2));
    }
    final round = lanes.sublist(n * per);
    final rootBefore = ledger.anchor;
    if (!_sameInts(round.sublist(0, 8), rootBefore)) throw StateError('the round\'s rootBefore is not the pool\'s root');
    if (!_sameInts(round.sublist(24), [for (final r in ledger.ringLanes) ...r])) throw StateError('the round\'s ring is not the pool\'s');
    final j = ledger.tree.nextSubtree;
    if (round[16] != j) throw StateError('the round\'s subtree index disagrees with the rebuilt tree');
    var vault = ledger.vault;
    final cms = <List<int>>[];
    for (final t in transfers) {
      if (t!.real1) ledger.nullifiers.insert(NullifierSet.fromLanes(t.nf1));
      if (t.real2) ledger.nullifiers.insert(NullifierSet.fromLanes(t.nf2));
      if (PoolHash.isBsv(t.asset)) vault -= t.publicOut;
      cms.addAll([t.cmOut1, t.cmOut2]);
    }
    for (int s = 0; s < gen.leavesAppended ~/ NoteCommitmentTree.subtreeLeaves; s++) {
      ledger.tree.appendSubtree([
        for (int i = 0; i < NoteCommitmentTree.subtreeLeaves; i++)
          s * NoteCommitmentTree.subtreeLeaves + i < cms.length ? cms[s * NoteCommitmentTree.subtreeLeaves + i] : MerkleFrontier.emptyLeaf
      ]);
    }
    final rootAfter = ledger.tree.root;
    if (!_sameInts(round.sublist(8, 16), rootAfter)) throw StateError('the round\'s rootAfter disagrees with the rebuilt tree');
    final next = ledger.header.afterRound(rootAfter, ledger.nullifiers.root, leaves: gen.leavesAppended);
    final state = roundTx.outputs[ShieldedPoolLegacyTool.stateVout];
    if (!_bytesEqual(PP1SpLegacyLockBuilder.fromScript(state.script).header.bytes(), next.bytes())) {
      throw StateError('the new state header disagrees with the rebuilt ledger');
    }
    if (state.satoshis.toInt() != vault) throw StateError('the new vault disagrees with the publics');
    _checkSlots(gen, roundTx);
    ledger
      ..header = next
      ..vault = vault
      ..tx = roundTx;
    final r = PoolRound(roundTx, transfers, j, cms);
    rounds.add(r);
    return r;
  }

  static bool _sameInts(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// The publics a verifier slot was unlocked with, or null for a skip.
  /// A proof unlock is `<50 publics> <proof...> <preimage> <prevoutsTail> OP_1`;
  /// a skip is `<preimage> <prevoutsTail> OP_0`.
  static PoolPublicInputs? readSlot(SVScript unlock) {
    final lanes = readSlotLanes(unlock, PoolPublicInputs.count);
    return lanes == null ? null : PoolPublicInputs.fromLanes(lanes);
  }

  /// The outputs from [from] that are transfer [t]'s extra outputs: the
  /// shortest run whose serialisation hashes to its [outHash] (an empty run
  /// when the hash is the empty one's). Every transfer's extras follow the
  /// previous transfer's, so walking the transfers in order attributes
  /// every output.
  (List<TransactionOutput>, int) _extrasOf(Transaction tx, int from, List<int> outHash, int t) {
    final bytes = <int>[];
    var at = from;
    while (true) {
      if (_sameInts(PoolPublicInputs.outHashLanes(bytes), outHash)) return (tx.outputs.sublist(from, at), at);
      if (at >= tx.outputs.length) throw FormatException('transfer $t: no run of outputs hashes to its outHash');
      final o = tx.outputs[at];
      bytes.addAll(SlotScript.output(o.script.buffer, value: o.satoshis.toInt()));
      at++;
    }
  }

  /// The first [count] lanes a verifier slot was unlocked with, or null.
  static List<int>? readSlotLanes(SVScript unlock, int count) {
    final chunks = unlock.chunks;
    if (chunks.isEmpty) throw FormatException('empty slot unlock');
    final selector = chunks.last.opcodenum;
    if (selector == OpCodes.OP_0) return null;
    if (selector != OpCodes.OP_1) throw FormatException('slot selector is neither OP_0 nor OP_1');
    if (chunks.length < count + 3) throw FormatException('proof unlock too short');
    return [for (int i = 0; i < count; i++) scriptNum(chunks[i])];
  }

  /// A pushed script number as an int: OP_0, OP_1..OP_16, OP_1NEGATE or a
  /// minimally encoded little-endian sign-magnitude push.
  static int scriptNum(ScriptChunk c) {
    final op = c.opcodenum;
    if (op == OpCodes.OP_0) return 0;
    if (op >= OpCodes.OP_1 && op <= OpCodes.OP_16) return op - OpCodes.OP_1 + 1;
    if (op == OpCodes.OP_1NEGATE) return -1;
    if (op > OpCodes.OP_PUSHDATA4) throw FormatException('not a push');
    final b = c.buf ?? const [];
    if (b.isEmpty) return 0;
    if (b.length > 8) throw FormatException('script number too long');
    var v = 0;
    for (int i = b.length - 1; i >= 0; i--) {
      v = (v << 8) | (i == b.length - 1 ? b[i] & 0x7f : b[i]);
    }
    return (b.last & 0x80) != 0 ? -v : v;
  }

  static void _expectSpends(Transaction tx, int input, Transaction parent, int vout) {
    if (input >= tx.inputs.length) throw FormatException('round has no input $input');
    final i = tx.inputs[input];
    if (i.prevTxnId != parent.id || i.prevTxnOutputIndex != vout) {
      throw FormatException('input $input does not spend output $vout of the pool transaction');
    }
  }

  /// The fresh slots a pool transaction mints must be the generator's.
  static void _checkSlots(PP1SpLegacyScriptGen gen, Transaction tx) {
    if (gen.aggregated) {
      if (!_bytesEqual(tx.outputs[gen.slotVout0].script.buffer, gen.verifierBytes)) throw FormatException('output ${gen.slotVout0} is not the verifier slot');
      return;
    }
    for (int i = 0; i < gen.k; i++) {
      final s = tx.outputs[gen.slotVout0 + i].script.buffer;
      if (!_bytesEqual(s, gen.verifierBytes)) throw FormatException('output ${gen.slotVout0 + i} is not a verifier slot');
    }
    if (!_bytesEqual(tx.outputs[gen.appendVout].script.buffer, gen.appendBytes)) {
      throw FormatException('output ${gen.appendVout} is not the append slot');
    }
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
