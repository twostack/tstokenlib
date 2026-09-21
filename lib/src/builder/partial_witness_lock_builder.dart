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
import '../script_gen/witness_check_script_gen.dart';

/// Builds the locking script for the partial SHA256 witness output (index 3) of a token transaction.
///
/// This output enables partial SHA256 calculation in-script. The locking script
/// is dynamically generated using [WitnessCheckScriptGen], replacing the previous
/// ~100KB compiled sCrypt hex template with a hand-optimized ~62KB script.
///
/// Constructor Parameters:
///   ownerPKH - The Pubkey Hash of the current token owner (needed for burn)
class PartialWitnessLockBuilder extends LockingScriptBuilder {

  List<int>? _ownerPKH;
  List<int>? _nextSlot;

  /// Creates the PP3 of an ordinary token, which its owner can burn.
  ///
  /// [_ownerPKH] - 20-byte pubkey hash of the current token owner (needed for burn).
  PartialWitnessLockBuilder(List<int> ownerPKH) : _ownerPKH = ownerPKH {
    if (ownerPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner PKH must be 20 bytes");
    }
  }

  /// Creates the PP3 of a shielded pool round, which nobody can burn.
  ///
  /// [nextSlot] is the 36-byte outpoint of the verifier slot the spending
  /// round must also spend, at input 3.
  ///
  /// A separate constructor rather than an optional argument, because the two
  /// kinds must not mix: a pool's PP3 holds every depositor's balance, so an
  /// owner who could burn it would be an owner who could take it. There is no
  /// owner here to pass.
  PartialWitnessLockBuilder.forPool(List<int> nextSlot) : _nextSlot = nextSlot {
    if (nextSlot.length != 36) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "nextSlot must be a 36-byte outpoint");
    }
  }

  /// Reconstructs a [PartialWitnessLockBuilder] by parsing an existing script.
  PartialWitnessLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  /// The 36-byte verifier-slot outpoint a pool PP3 pins, or null for an
  /// ordinary token's.
  List<int>? get nextSlot => _nextSlot;

  /// The 20-byte pubkey hash of the owner who may burn this output, or null
  /// for a pool's, which has none.
  List<int>? get ownerPKH => _ownerPKH;

  /// Whether this is a pool PP3, which has no burn path.
  bool get isPool => _nextSlot != null;

  @override
  SVScript getScriptPubkey() {
    return WitnessCheckScriptGen.generate(
      ownerPKH: _ownerPKH,
      pp2OutputIndex: 2,  // NFT always uses PP2 at output index 2
      nextSlot: _nextSlot,
    );
  }

  @override
  void parse(SVScript script) {
    // The first push says which kind this is: 20 bytes is an owner, 36 is a
    // verifier slot. A pool PP3 carries no owner at all.
    var chunks = script.chunks;
    if (chunks.isEmpty || chunks[0].buf == null) return;
    var first = chunks[0].buf!.toList();
    if (first.length == 36) {
      _nextSlot = first;
    } else {
      _ownerPKH = first;
    }
  }
}
