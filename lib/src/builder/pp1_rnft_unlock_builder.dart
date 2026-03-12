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

/// The type of action being performed on a restricted NFT token.
enum RestrictedTokenAction {
  /// Initial token creation.
  ISSUANCE,
  /// Transfer of token ownership.
  TRANSFER,
  /// Redeem the token (may or may not destroy it).
  REDEEM,
  /// Permanent destruction of a token.
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP1_RNFT output.
///
/// Supports four actions: issuance (OP_0), transfer (OP_1), redeem (OP_2), burn (OP_3).
class PP1RnftUnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  RestrictedTokenAction? action;
  List<int>? _witnessFundingTxId;

  // Rabin identity binding fields (used during issuance)
  List<int>? _rabinN;
  List<int>? _rabinS;
  int? _rabinPadding;
  List<int>? _identityTxId;
  List<int>? _ed25519PubKey;

  List<int>? _sigBytes;

  List<int>? get preImage => _preImage;

  /// Creates a PP1_RNFT unlock builder for a token transfer.
  PP1RnftUnlockBuilder(
      this._preImage,
      this._pp2Output,
      this._ownerPubKey,
      this._changePKH,
      this._changeAmount,
      this._tokenLHS,
      this._prevTokenTx,
      this._witnessPadding,
      this.action,
      this._witnessFundingTxId,
      {List<int>? rabinN,
       List<int>? rabinS,
       int? rabinPadding,
       List<int>? identityTxId,
       List<int>? ed25519PubKey})
      : _rabinN = rabinN,
        _rabinS = rabinS,
        _rabinPadding = rabinPadding,
        _identityTxId = identityTxId,
        _ed25519PubKey = ed25519PubKey;

  /// Creates a PP1_RNFT unlock builder for burning a token.
  PP1RnftUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        action = RestrictedTokenAction.BURN;

  /// Creates a PP1_RNFT unlock builder for redeeming a token.
  PP1RnftUnlockBuilder.forRedeem(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        action = RestrictedTokenAction.REDEEM;

  PP1RnftUnlockBuilder.fromScript(SVScript script, {RestrictedTokenAction this.action = RestrictedTokenAction.TRANSFER}): super.fromScript(script);

  @override
  SVScript getScriptSig() {
    SVSignature? signature = null;
    if (!signatures.isEmpty) {
      signature = signatures[0];
    }

    if (signature == null) {
      return ScriptBuilder().build();
    }

    var sigBytes = hex.decode(this.signatures.first.toTxFormat());
    var result = ScriptBuilder();

    if (action == RestrictedTokenAction.ISSUANCE) {
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._witnessFundingTxId!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.addData(Uint8List.fromList(this._rabinN!));
      result.addData(Uint8List.fromList(this._rabinS!));
      result.number(this._rabinPadding!);
      result.addData(Uint8List.fromList(this._identityTxId!));
      result.addData(Uint8List.fromList(this._ed25519PubKey!));
    } else if (action == RestrictedTokenAction.TRANSFER) {
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
    } else if (action == RestrictedTokenAction.REDEEM) {
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
    } else if (action == RestrictedTokenAction.BURN) {
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
    }

    switch (action!) {
      case RestrictedTokenAction.ISSUANCE:
        result.opCode(OpCodes.OP_0);
        break;
      case RestrictedTokenAction.TRANSFER:
        result.opCode(OpCodes.OP_1);
        break;
      case RestrictedTokenAction.REDEEM:
        result.opCode(OpCodes.OP_2);
        break;
      case RestrictedTokenAction.BURN:
        result.opCode(OpCodes.OP_3);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;
    this._preImage = chunkList[0].buf;
    this._pp2Output = chunkList[1].buf;
    this._ownerPubKey = SVPublicKey.fromBuffer(chunkList[2].buf ?? []);
    this._changePKH = hex.encode(chunkList[3].buf ?? [00]);
    this._changeAmount = castToBigInt(chunkList[4].buf ?? [], true);
    this._sigBytes = chunkList[5].buf;
    this._tokenLHS = chunkList[6].buf;
    this._prevTokenTx = chunkList[7].buf;
    this._witnessPadding = chunkList[8].buf;
  }

  List<int>? get pp2Output => _pp2Output;
  SVPublicKey? get ownerPubKey => _ownerPubKey;
  BigInt? get changeAmount => _changeAmount;
  List<int>? get tokenLHS => _tokenLHS;
  List<int>? get prevTokenTx => _prevTokenTx;
  List<int>? get witnessPadding => _witnessPadding;
  List<int>? get witnessFundingTxId => _witnessFundingTxId;
  String? get changePKH => _changePKH;
  List<int>? get sigBytes => _sigBytes;
}
