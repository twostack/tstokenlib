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

/// Builds the locking script for the partial SHA256 witness output of a fungible token transaction.
///
/// This output enables partial SHA256 calculation in-script for fungible tokens,
/// extending the base partial witness with an additional PP2 output index parameter.
class PartialWitnessFtLockBuilder extends LockingScriptBuilder {

  List<int> _ownerPKH;
  int _pp2OutputIndex;

  /// Creates a partial witness FT locking script builder.
  ///
  /// [_ownerPKH] - 20-byte pubkey hash of the current token owner (needed for burn).
  /// [_pp2OutputIndex] - Output index of the PP2-FT output.
  PartialWitnessFtLockBuilder(this._ownerPKH, this._pp2OutputIndex) {
    if (_ownerPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner PKH must be 20 bytes");
    }
  }

  /// Reconstructs a [PartialWitnessFtLockBuilder] by parsing an existing script.
  PartialWitnessFtLockBuilder.fromScript(SVScript script) :
      _ownerPKH = [],
      _pp2OutputIndex = 0,
      super.fromScript(script);

  /// The 20-byte pubkey hash of the current token owner.
  List<int> get ownerPKH => _ownerPKH;

  /// The output index of the PP2-FT output.
  int get pp2OutputIndex => _pp2OutputIndex;

  @override
  SVScript getScriptPubkey() {
    return WitnessCheckScriptGen.generate(
      ownerPKH: _ownerPKH,
      pp2OutputIndex: _pp2OutputIndex,
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
