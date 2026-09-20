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
import 'package:dartsv/dartsv.dart';
import '../crypto/stark_prover_ref.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pp1_sp_legacy_script_gen.dart';
import '../script_gen/subtree_append_slot_gen.dart';
import '../script_gen/verifier_slot_gen.dart';

enum ShieldedPoolLegacyAction { create, round }

/// Unlocking-script builder for the PP1_SP state input. The preimage is set
/// after the transaction's outputs are fixed (two-pass build).
class PP1SpLegacyUnlockBuilder extends UnlockingScriptBuilder {
  final PP1SpLegacyScriptGen gen;
  final ShieldedPoolLegacyAction action;
  Uint8List? preimage;

  // create
  List<int>? rabinN, rabinS, identityTxId, ed25519PubKey, extras;
  int? rabinPadding, vault;

  // round
  List<int>? extraPrevouts, rootAfter, roundLanes;
  List<PP1SpLegacyTransfer?>? transfers;

  PP1SpLegacyUnlockBuilder.create(this.gen,
      {required this.rabinN,
      required this.rabinS,
      required this.rabinPadding,
      required this.identityTxId,
      required this.ed25519PubKey,
      required this.vault,
      required this.extras})
      : action = ShieldedPoolLegacyAction.create;

  PP1SpLegacyUnlockBuilder.round(this.gen, {required this.extraPrevouts, required this.rootAfter, required this.transfers})
      : action = ShieldedPoolLegacyAction.round;

  /// An aggregated round: every transfer present, the round lanes from the
  /// root proof's wide statement.
  PP1SpLegacyUnlockBuilder.roundAggregated(this.gen, {required this.extraPrevouts, required this.transfers, required this.roundLanes})
      : action = ShieldedPoolLegacyAction.round;

  @override
  SVScript getScriptSig() {
    if (preimage == null) return SVScript();
    switch (action) {
      case ShieldedPoolLegacyAction.create:
        return gen.createUnlock(
            preimage: preimage!,
            rabinN: rabinN!,
            rabinS: rabinS!,
            rabinPadding: rabinPadding!,
            identityTxId: identityTxId!,
            ed25519PubKey: ed25519PubKey!,
            vault: vault!,
            extras: extras!);
      case ShieldedPoolLegacyAction.round:
        return gen.spendUnlock(
            preimage: preimage!, extraPrevouts: extraPrevouts!, rootAfter: rootAfter ?? const [], transfers: transfers!, roundLanes: roundLanes);
    }
  }

  @override
  void parse(SVScript script) {}
}

/// Unlocking-script builder for a verifier slot input: a proof, or a skip.
class VerifierSlotUnlockBuilder extends UnlockingScriptBuilder {
  final VerifierSlotGen gen;
  final StarkProof? proof;
  final List<int>? lanes;
  Uint8List? preimage;
  List<int>? prevoutsTail;

  VerifierSlotUnlockBuilder.proof(this.gen, this.proof, PoolPublicInputs publics) : lanes = publics.toLanes();
  VerifierSlotUnlockBuilder.proofLanes(this.gen, this.proof, this.lanes);
  VerifierSlotUnlockBuilder.skip(this.gen)
      : proof = null,
        lanes = null;

  @override
  SVScript getScriptSig() {
    if (preimage == null) return SVScript();
    return proof == null ? gen.unlockSkip(preimage!, prevoutsTail!) : gen.unlockProofLanes(proof!, lanes!, preimage!, prevoutsTail!);
  }

  @override
  void parse(SVScript script) {}
}

/// Unlocking-script builder for the append slot input.
class AppendSlotUnlockBuilder extends UnlockingScriptBuilder {
  final SubtreeAppendSlotGen gen;
  final int index;
  final List<int> rootBefore;
  final List<List<int>> siblings, cms;
  Uint8List? preimage;
  List<int>? prevoutsTail;

  AppendSlotUnlockBuilder(this.gen, {required this.index, required this.rootBefore, required this.siblings, required this.cms});

  @override
  SVScript getScriptSig() {
    if (preimage == null) return SVScript();
    return gen.unlock(preimage!, prevoutsTail!, index, rootBefore, siblings, cms);
  }

  @override
  void parse(SVScript script) {}
}
