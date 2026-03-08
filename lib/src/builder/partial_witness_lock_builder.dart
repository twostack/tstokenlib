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

  List<int> _ownerPKH;

  /// Creates a partial witness locking script builder.
  ///
  /// [_ownerPKH] - 20-byte pubkey hash of the current token owner (needed for burn).
  PartialWitnessLockBuilder(this._ownerPKH) {
    if (_ownerPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner PKH must be 20 bytes");
    }
  }

  /// Reconstructs a [PartialWitnessLockBuilder] by parsing an existing script.
  PartialWitnessLockBuilder.fromScript(SVScript script) :
      _ownerPKH = [],
      super.fromScript(script);

  /// The 20-byte pubkey hash of the current token owner.
  List<int> get ownerPKH => _ownerPKH;

  @override
  SVScript getScriptPubkey() {
    return WitnessCheckScriptGen.generate(
      ownerPKH: _ownerPKH,
      pp2OutputIndex: 2,  // NFT always uses PP2 at output index 2
    );
  }

  @override
  void parse(SVScript script) {
    var chunks = script.chunks;
    if (chunks.isNotEmpty && chunks[0].buf != null) {
      _ownerPKH = chunks[0].buf!.toList();
    }
  }
}
