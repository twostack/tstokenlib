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
import 'pp1_ft_unlock_builder.dart';

/// Builds the unlocking script for spending the partial SHA256 witness output
/// of a fungible token transaction.
///
/// Supports normal unlock (pushes preimage, partial hash, witness preimage, and
/// funding TxID with OP_0 selector) and burn (pushes owner pubkey + signature
/// with OP_1 selector).
class PartialWitnessFtUnlockBuilder extends UnlockingScriptBuilder {

  List<int>? _preImage;
  List<int>? _partialHash;
  List<int>? _partialWitnessPreImage;
  List<int>? _fundingTxId;
  SVPublicKey? _ownerPubKey;
  FungibleTokenAction? _action;

  /// Creates a partial witness FT unlock builder for a normal token transfer.
  ///
  /// [preImage] - The sighash preimage of this transaction.
  /// [partialHash] - The intermediate SHA256 hash state.
  /// [partialWitnessPreImage] - The remaining preimage bytes for the witness.
  /// [fundingTxId] - The transaction ID funding the witness.
  PartialWitnessFtUnlockBuilder(
    List<int> preImage,
    List<int> partialHash,
    List<int> partialWitnessPreImage,
    List<int> fundingTxId,
  ) : _preImage = preImage,
      _partialHash = partialHash,
      _partialWitnessPreImage = partialWitnessPreImage,
      _fundingTxId = fundingTxId;

  /// Creates a partial witness FT unlock builder for burning a token.
  PartialWitnessFtUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = FungibleTokenAction.BURN;

  /// Reconstructs a [PartialWitnessFtUnlockBuilder] by parsing an existing script.
  PartialWitnessFtUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  /// The sighash preimage of this transaction.
  List<int>? get preImage => _preImage;

  /// The intermediate SHA256 hash state.
  List<int>? get partialHash => _partialHash;

  /// The remaining preimage bytes for the witness partial SHA256.
  List<int>? get partialWitnessPreImage => _partialWitnessPreImage;

  /// The transaction ID funding the witness.
  List<int>? get fundingTxId => _fundingTxId;

  @override
  SVScript getScriptSig() {
    if (_action == FungibleTokenAction.BURN) {
      if (signatures.isEmpty) return SVScript();
      var sigBytes = hex.decode(signatures.first.toTxFormat());
      var pkBytes = hex.decode(_ownerPubKey!.toHex());
      return ScriptBuilder()
          .addData(Uint8List.fromList(pkBytes))
          .addData(Uint8List.fromList(sigBytes))
          .opCode(OpCodes.OP_1) // function selector: burnToken=1
          .build();
    }

    if (_preImage == null) return SVScript();

    var builder = ScriptBuilder()
        .addData(Uint8List.fromList(_preImage!))
        .addData(Uint8List.fromList(_partialHash!))
        .addData(Uint8List.fromList(_partialWitnessPreImage!))
        .addData(Uint8List.fromList(_fundingTxId!))
        .opCode(OpCodes.OP_0); // function selector: unlock=0

    var result = builder.build();
    return result;
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;

    if (chunkList.length < 4) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for PartialWitnessFt ScriptSig");
    }

    _preImage = chunkList[0].buf;
    _partialHash = chunkList[1].buf;
    _partialWitnessPreImage = chunkList[2].buf;
    _fundingTxId = chunkList[3].buf;
  }

}
