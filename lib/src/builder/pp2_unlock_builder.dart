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

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'pp1_nft_unlock_builder.dart';

/// Builds the unlocking script (scriptSig) for spending the PP2 witness bridge output.
///
/// Supports two modes: normal unlock (pushes the outpoint TxID with OP_0 selector)
/// and burn (pushes owner pubkey + signature with OP_1 selector).
class PP2UnlockBuilder extends UnlockingScriptBuilder {

  List<int>? _outpointTxId;
  SVPublicKey? _ownerPubKey;
  TokenAction? _action;

  /// Creates a PP2 unlock builder for a normal token transfer.
  ///
  /// [outpointTxId] - The transaction ID of the outpoint being spent.
  PP2UnlockBuilder(List<int> outpointTxId) : _outpointTxId = outpointTxId;

  /// Creates a PP2 unlock builder for burning (destroying) a token.
  PP2UnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = TokenAction.BURN;

  /// Reconstructs a [PP2UnlockBuilder] by parsing an existing script.
  PP2UnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  /// The transaction ID of the outpoint being spent.
  List<int>? get outpointTxId => _outpointTxId;

  @override
  SVScript getScriptSig() {
    if (_action == TokenAction.BURN) {
      if (signatures.isEmpty) return SVScript();
      var sigBytes = hex.decode(signatures.first.toTxFormat());
      var pkBytes = hex.decode(_ownerPubKey!.toHex());
      return ScriptBuilder()
          .addData(Uint8List.fromList(pkBytes))
          .addData(Uint8List.fromList(sigBytes))
          .opCode(OpCodes.OP_1) // function selector: burnToken=1
          .build();
    }

    if (_outpointTxId == null) return SVScript();
    return ScriptBuilder()
        .addData(Uint8List.fromList(_outpointTxId!))
        .opCode(OpCodes.OP_0) // function selector: unlock=0
        .build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;

    if (chunkList.isEmpty) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Empty PP2 ScriptSig");
    }

    _outpointTxId = chunkList[0].buf;
  }

}