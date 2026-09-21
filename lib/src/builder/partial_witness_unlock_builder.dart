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

/// Builds the unlocking script for spending the partial SHA256 witness output (index 3).
///
/// Supports normal unlock (pushes preimage, partial hash, witness preimage, and
/// funding outpoint with OP_0 selector) and burn (pushes owner pubkey + signature
/// with OP_1 selector).
class PartialWitnessUnlockBuilder extends UnlockingScriptBuilder {

  List<int>? _preImage;
  List<int>? _partialHash;
  List<int>? _partialWitnessPreImage;
  List<int>? _fundingOutpoint;
  List<int>? _extraPrevouts;
  SVPublicKey? _ownerPubKey;
  TokenAction? _action;
  List<int>? _nextSlot;
  List<int>? _nextValue;

  /// Creates a partial witness unlock builder for a normal token transfer.
  ///
  /// [preImage] - The sighash preimage of this transaction.
  /// [partialHash] - The intermediate SHA256 hash state.
  /// [partialWitnessPreImage] - The remaining preimage bytes for the witness.
  /// [fundingOutpoint] - The 36-byte outpoint (txid + vout) funding the witness.
  PartialWitnessUnlockBuilder(
    List<int> preImage,
    List<int> partialHash,
    List<int> partialWitnessPreImage,
    List<int> fundingOutpoint,
  ) : _preImage = preImage,
      _partialHash = partialHash,
      _partialWitnessPreImage = partialWitnessPreImage,
      _fundingOutpoint = fundingOutpoint;

  /// Creates the unlock for a pool PP3, built with
  /// [PartialWitnessLockBuilder.forPool], which a round spends at input 3.
  ///
  /// [preImage] must be the SIGHASH_SINGLE|FORKID preimage for input 3 with
  /// the PP3 script as its scriptCode: a pool PP3 signs SINGLE so that its
  /// hashOutputs covers output 3 alone, and uses no OP_CODESEPARATOR so that
  /// it can read its own program.
  /// [extraPrevouts] - concatenated outpoints of the inputs after PP3, the
  /// deposit covenants; empty when there are none.
  /// [nextSlot] and [nextValue] describe the round's output 3, the PP3 that
  /// replaces this one: the slot it pins and the 8-byte little-endian value it
  /// holds. PP3's forward covenant rebuilds that output from its own program
  /// and these two, so they must be exactly what the round carries.
  ///
  /// No function selector is pushed: a pool PP3 has no burn path to select.
  PartialWitnessUnlockBuilder.forPool(
    List<int> preImage,
    List<int> partialHash,
    List<int> partialWitnessPreImage,
    List<int> fundingOutpoint, {
    required List<int> nextSlot,
    required List<int> nextValue,
    List<int> extraPrevouts = const <int>[],
  }) : _preImage = preImage,
      _partialHash = partialHash,
      _partialWitnessPreImage = partialWitnessPreImage,
      _fundingOutpoint = fundingOutpoint,
      _extraPrevouts = extraPrevouts,
      _nextSlot = nextSlot,
      _nextValue = nextValue {
    if (nextSlot.length != 36) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'nextSlot must be a 36-byte outpoint');
    }
    if (nextValue.length != 8) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'nextValue must be 8 bytes, little endian');
    }
  }

  /// Creates a partial witness unlock builder for burning a token.
  PartialWitnessUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = TokenAction.BURN;

  /// Reconstructs a [PartialWitnessUnlockBuilder] by parsing an existing script.
  PartialWitnessUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  /// The sighash preimage of this transaction.
  List<int>? get preImage => _preImage;

  /// The intermediate SHA256 hash state.
  List<int>? get partialHash => _partialHash;

  /// The remaining preimage bytes for the witness partial SHA256.
  List<int>? get partialWitnessPreImage => _partialWitnessPreImage;

  /// The 36-byte outpoint (txid + vout) funding the witness.
  List<int>? get fundingOutpoint => _fundingOutpoint;

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

    if (_preImage == null) return SVScript();

    var builder = ScriptBuilder();
    if (_extraPrevouts != null) {
      // A pool PP3: the successor's value and slot go first, so they land at
      // the bottom of the stack and sit untouched under the witness check
      // until the forward covenant needs them.
      builder
          .addData(Uint8List.fromList(_nextValue!))
          .addData(Uint8List.fromList(_nextSlot!));
    }
    builder
        .addData(Uint8List.fromList(_preImage!))
        .addData(Uint8List.fromList(_partialHash!))
        .addData(Uint8List.fromList(_partialWitnessPreImage!))
        .addData(Uint8List.fromList(_fundingOutpoint!));
    if (_extraPrevouts != null) {
      // A pool PP3. It has no burn path, so there is nothing to select
      // between and no selector is pushed; extraPrevouts is the last push.
      builder.addData(Uint8List.fromList(_extraPrevouts!));
    } else {
      builder.opCode(OpCodes.OP_0); // function selector: unlock=0
    }

    var result = builder.build();
    return result;
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;

    if (chunkList.length < 4) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for PartialWitness ScriptSig");
    }

    _preImage = chunkList[0].buf;
    _partialHash = chunkList[1].buf;
    _partialWitnessPreImage = chunkList[2].buf;
    _fundingOutpoint = chunkList[3].buf;
  }

}