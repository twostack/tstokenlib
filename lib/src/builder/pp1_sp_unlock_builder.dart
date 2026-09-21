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
import '../shielded_pool/pool_header.dart';

/// What a spend of a PP1_SP output is doing.
enum ShieldedPoolAction {
  /// TSL1 issuance: the pool's genesis.
  CREATE,

  /// One round of the pool: the inductive transfer that advances the header.
  ROUND,
}

/// Builds the unlocking script (scriptSig) for spending the PP1_SP output.
///
/// Dispatch selectors: OP_0 = create, OP_1 = round.
///
/// There is no burn. A pool's PP3 holds every depositor's money, so nothing
/// releases it on a signature alone; see [PP1SpScriptGen].
class PP1SpUnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  ShieldedPoolAction? action;
  List<int>? _fundingOutpoint;

  // Round-specific
  List<int>? _newOwnerPKH;
  List<int>? _newHeader;
  List<int>? _nextSlot;
  List<int>? _yInput;
  List<int>? _verifierBody;
  List<int>? _bundles;

  List<int>? _sigBytes;

  List<int>? get preImage => _preImage;

  /// Unlock for a round.
  ///
  /// [prevTokenTx] is the parent token transaction, whose bytes PP1 rebuilds to
  /// prove which ancestor this round spends.
  PP1SpUnlockBuilder(
      this._preImage,
      this._pp2Output,
      this._ownerPubKey,
      this._changePKH,
      this._changeAmount,
      this._tokenLHS,
      this._prevTokenTx,
      this._witnessPadding,
      this.action,
      this._fundingOutpoint,
      {List<int>? newOwnerPKH,
      List<int>? newHeader,
      List<int>? nextSlot,
      List<int>? yInput,
      List<int>? verifierBody,
      List<int>? bundles})
      : _newOwnerPKH = newOwnerPKH,
        _newHeader = newHeader,
        _nextSlot = nextSlot,
        _yInput = yInput,
        _verifierBody = verifierBody,
        _bundles = bundles;

  PP1SpUnlockBuilder.fromScript(SVScript script,
      {ShieldedPoolAction this.action = ShieldedPoolAction.ROUND})
      : super.fromScript(script);

  @override
  SVScript getScriptSig() {
    SVSignature? signature;
    if (signatures.isNotEmpty) {
      signature = signatures[0];
    }

    if (signature == null && action != ShieldedPoolAction.CREATE) {
      return ScriptBuilder().build();
    }

    if (signature != null) {
      _sigBytes = hex.decode(signature.toTxFormat());
    }

    var result = ScriptBuilder();

    switch (action!) {
      case ShieldedPoolAction.CREATE:
        // Stack: [tokenRawTx, preImage, fundingOutpoint, witnessPadding, OP_0]
        //
        // tokenRawTx is first so it lands at the bottom, leaving every other
        // stack index unchanged for the phases after the anchor check.
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_fundingOutpoint!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        result.opCode(OpCodes.OP_0);
        break;

      case ShieldedPoolAction.ROUND:
        // Stack: [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
        //         newOwnerPKH, newHeader, nextSlot, yInput, vBody, bundles,
        //         scriptLHS, parentRawTx, padding, OP_1]
        //
        // nextSlot, yInput and vBody describe the verifier slot that round N+2
        // will have to spend; PP1 certifies it holds this pool's verifier
        // carrying newHeader. bundles are the round's ciphertexts, published by
        // being in this witness and bound by newHeader.outHash.
        if (_newHeader == null || _newHeader!.length != PoolHeader.byteSize) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
              "A round needs a ${PoolHeader.byteSize}-byte header");
        }
        if (_newOwnerPKH == null || _newOwnerPKH!.length != 20) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
              "A round needs a 20-byte newOwnerPKH");
        }
        if (_nextSlot == null || _nextSlot!.length != 36) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
              "A round needs a 36-byte nextSlot outpoint");
        }
        if (_yInput == null || _verifierBody == null) {
          throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
              "A round needs the slot transaction's input and the verifier body");
        }
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(_sigBytes!));
        result.addData(Uint8List.fromList(_newOwnerPKH!));
        result.addData(Uint8List.fromList(_newHeader!));
        result.addData(Uint8List.fromList(_nextSlot!));
        result.addData(Uint8List.fromList(_yInput!));
        result.addData(Uint8List.fromList(_verifierBody!));
        result.addData(Uint8List.fromList(_bundles ?? const <int>[]));
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        result.opCode(OpCodes.OP_1);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;
    _preImage = chunkList[0].buf;
    _pp2Output = chunkList[1].buf;
    _ownerPubKey = SVPublicKey.fromBuffer(chunkList[2].buf ?? []);
    _changePKH = hex.encode(chunkList[3].buf ?? [00]);
    _changeAmount = castToBigInt(chunkList[4].buf ?? [], true);
    _sigBytes = chunkList[5].buf;
    _newOwnerPKH = chunkList[6].buf;
    _newHeader = chunkList[7].buf;
    _nextSlot = chunkList[8].buf;
    _yInput = chunkList[9].buf;
    _verifierBody = chunkList[10].buf;
    _bundles = chunkList[11].buf;
    _tokenLHS = chunkList[12].buf;
    _prevTokenTx = chunkList[13].buf;
    _witnessPadding = chunkList[14].buf;
  }

  List<int>? get pp2Output => _pp2Output;
  SVPublicKey? get ownerPubKey => _ownerPubKey;
  BigInt? get changeAmount => _changeAmount;
  List<int>? get tokenLHS => _tokenLHS;
  List<int>? get prevTokenTx => _prevTokenTx;
  List<int>? get witnessPadding => _witnessPadding;
  List<int>? get fundingOutpoint => _fundingOutpoint;
  String? get changePKH => _changePKH;
  List<int>? get sigBytes => _sigBytes;
  List<int>? get newOwnerPKH => _newOwnerPKH;
  List<int>? get newHeader => _newHeader;
  List<int>? get nextSlot => _nextSlot;
  List<int>? get yInput => _yInput;
  List<int>? get verifierBody => _verifierBody;
  List<int>? get bundles => _bundles;
}
