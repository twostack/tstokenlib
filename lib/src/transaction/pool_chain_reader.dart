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
import '../builder/pp1_sp_lock_builder.dart';
import '../crypto/nullifier_set.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_script_gen.dart';
import '../script_gen/subtree_append_slot_gen.dart';
import '../script_gen/verifier_slot_gen.dart';
import 'shielded_pool_tool.dart';

/// What one round did, as read from its transaction: the publics of every
/// used verifier slot (null for an idle one), the subtree index the round
/// filled, and the leaves it appended (transfer t's commitments at 2t and
/// 2t+1, empty leaves for an idle slot; see [ShieldedPoolTool.roundLeaves]).
class PoolRound {
  final Transaction tx;
  final List<PoolPublicInputs?> transfers;
  final int subtreeIndex;
  final List<List<int>> commitments;
  PoolRound(this.tx, this.transfers, this.subtreeIndex, this.commitments);
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
  final PP1SpScriptGen gen;
  final PoolLedger ledger;
  final List<PoolRound> rounds = [];

  int get k => gen.k;

  PoolChainReader._(this.gen, this.ledger);

  /// Start from the genesis (the create): output 0 is the live state with
  /// an empty tree and an empty nullifier set.
  factory PoolChainReader.fromGenesis(PP1SpScriptGen gen, Transaction genesisTx) {
    final state = genesisTx.outputs[ShieldedPoolTool.stateVout];
    final header = PP1SpLockBuilder.fromScript(state.script).header;
    if (header.phase != 1) throw FormatException('output 0 is not a live pool state');
    if (header.size != 0) throw FormatException('not a genesis: the tree is not empty');
    final ledger = PoolLedger(header, state.satoshis.toInt(), genesisTx);
    if (!_bytesEqual(header.nfRoot, ledger.nullifiers.root) || !_bytesEqual(header.cmRoot, PP1SpHeader.emptyRootBytes)) {
      throw FormatException('not a genesis: roots are not the empty roots');
    }
    _checkSlots(gen, genesisTx);
    return PoolChainReader._(gen, ledger);
  }

  /// Apply the next round: [roundTx] must spend the ledger's state and
  /// slots. Advances [ledger] and returns what the round did.
  PoolRound apply(Transaction roundTx) {
    final parent = ledger.tx;
    _expectSpends(roundTx, 0, parent, ShieldedPoolTool.stateVout);
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
      if (!_bytesEqual(ShieldedPoolTool.outputFromBytes(expected).script.buffer, result.script.buffer) || result.satoshis != BigInt.zero) {
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
      vault -= t.publicOut;
    }
    final cms = ShieldedPoolTool.roundLeaves(transfers);
    ledger.tree.appendSubtree(cms);
    final rootAfter = ledger.tree.root;

    // the round's own commitments must agree with the model
    final appendResult = roundTx.outputs[k + 1].script.buffer;
    final payload = SubtreeAppendSlotGen.payload(rootBefore, rootAfter, j, cms);
    if (!_bytesEqual(ShieldedPoolTool.outputFromBytes(SubtreeAppendSlotGen.resultOutput(payload)).script.buffer, appendResult)) {
      throw StateError('the append result disagrees with the rebuilt tree');
    }
    final next = ledger.header.afterRound(rootAfter, ledger.nullifiers.root);
    final state = roundTx.outputs[ShieldedPoolTool.stateVout];
    if (!_bytesEqual(PP1SpLockBuilder.fromScript(state.script).header.bytes(), next.bytes())) {
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

  /// The publics a verifier slot was unlocked with, or null for a skip.
  /// A proof unlock is `<50 publics> <proof...> <preimage> <prevoutsTail> OP_1`;
  /// a skip is `<preimage> <prevoutsTail> OP_0`.
  static PoolPublicInputs? readSlot(SVScript unlock) {
    final chunks = unlock.chunks;
    if (chunks.isEmpty) throw FormatException('empty slot unlock');
    final selector = chunks.last.opcodenum;
    if (selector == OpCodes.OP_0) return null;
    if (selector != OpCodes.OP_1) throw FormatException('slot selector is neither OP_0 nor OP_1');
    if (chunks.length < PoolPublicInputs.count + 3) throw FormatException('proof unlock too short');
    return PoolPublicInputs.fromLanes([for (int i = 0; i < PoolPublicInputs.count; i++) scriptNum(chunks[i])]);
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
  static void _checkSlots(PP1SpScriptGen gen, Transaction tx) {
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
