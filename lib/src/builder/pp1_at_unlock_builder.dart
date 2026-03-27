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

/// The type of action being performed on an appendable token.
enum AppendableTokenAction {
  /// Initial token creation (issuer signs).
  ISSUANCE,
  /// Add a stamp to the card (issuer signs).
  STAMP,
  /// Redeem the card reward (owner signs, threshold check).
  REDEEM,
  /// Transfer ownership to a new customer (owner signs).
  TRANSFER,
  /// Burn the token (owner signs).
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP1_AT output.
///
/// Dispatch selectors:
/// - OP_0 = issue, OP_1 = stamp, OP_2 = redeem, OP_3 = transfer, OP_4 = burn
class PP1AtUnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _pubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  AppendableTokenAction? action;
  List<int>? _fundingOutpoint;
  List<int>? _stampMetadata;

  // Rabin identity binding fields (used during issuance)
  List<int>? _rabinN;           // Rabin public key n, encoded as script number bytes
  List<int>? _rabinS;           // Rabin signature s, encoded as script number bytes
  int? _rabinPadding;           // Rabin signature padding (small integer)
  List<int>? _identityTxId;     // 32-byte identity anchor transaction ID
  List<int>? _ed25519PubKey;    // 32-byte ED25519 public key

  List<int>? _sigBytes;

  List<int>? get preImage => _preImage;

  /// Creates a PP1_AT unlock builder for issue or transfer.
  PP1AtUnlockBuilder(
      this._preImage,
      this._pp2Output,
      this._pubKey,
      this._changePKH,
      this._changeAmount,
      this._tokenLHS,
      this._prevTokenTx,
      this._witnessPadding,
      this.action,
      this._fundingOutpoint,
      {List<int>? stampMetadata,
       List<int>? rabinN,
       List<int>? rabinS,
       int? rabinPadding,
       List<int>? identityTxId,
       List<int>? ed25519PubKey})
      : _stampMetadata = stampMetadata,
        _rabinN = rabinN,
        _rabinS = rabinS,
        _rabinPadding = rabinPadding,
        _identityTxId = identityTxId,
        _ed25519PubKey = ed25519PubKey;

  /// Creates a PP1_AT unlock builder for burning a token.
  PP1AtUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _pubKey = ownerPubKey,
        action = AppendableTokenAction.BURN;

  /// Creates a PP1_AT unlock builder for redeeming a token.
  PP1AtUnlockBuilder.forRedeem(SVPublicKey ownerPubKey)
      : _pubKey = ownerPubKey,
        action = AppendableTokenAction.REDEEM;

  PP1AtUnlockBuilder.fromScript(SVScript script,
      {AppendableTokenAction this.action = AppendableTokenAction.TRANSFER})
      : super.fromScript(script);

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

    if (action == AppendableTokenAction.ISSUANCE) {
      // Stack: [preImage, fundingOutpoint(36B), padding, issuerPubKey, issuerSig,
      //         rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey]
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._fundingOutpoint!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.addData(Uint8List.fromList(hex.decode(this._pubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
      // Rabin identity binding data
      result.addData(Uint8List.fromList(this._rabinN!));
      result.addData(Uint8List.fromList(this._rabinS!));
      result.number(this._rabinPadding!);
      result.addData(Uint8List.fromList(this._identityTxId!));
      result.addData(Uint8List.fromList(this._ed25519PubKey!));
    } else if (action == AppendableTokenAction.STAMP) {
      // Stack: [preImage, pp2Out, issuerPK, changePkh, changeAmt, issuerSig,
      //         scriptLHS, parentRawTx, padding, stampMetadata]
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._pubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.addData(Uint8List.fromList(this._stampMetadata!));
    } else if (action == AppendableTokenAction.TRANSFER) {
      // Stack: [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
      //         scriptLHS, parentRawTx, padding]
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._pubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
    } else if (action == AppendableTokenAction.REDEEM) {
      result.addData(Uint8List.fromList(hex.decode(_pubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
    } else if (action == AppendableTokenAction.BURN) {
      result.addData(Uint8List.fromList(hex.decode(_pubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
    }

    switch (action!) {
      case AppendableTokenAction.ISSUANCE:
        result.opCode(OpCodes.OP_0);
        break;
      case AppendableTokenAction.STAMP:
        result.opCode(OpCodes.OP_1);
        break;
      case AppendableTokenAction.REDEEM:
        result.opCode(OpCodes.OP_2);
        break;
      case AppendableTokenAction.TRANSFER:
        result.opCode(OpCodes.OP_3);
        break;
      case AppendableTokenAction.BURN:
        result.opCode(OpCodes.OP_4);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;
    this._preImage = chunkList[0].buf;
    this._pp2Output = chunkList[1].buf;
    this._pubKey = SVPublicKey.fromBuffer(chunkList[2].buf ?? []);
    this._changePKH = hex.encode(chunkList[3].buf ?? [00]);
    this._changeAmount = castToBigInt(chunkList[4].buf ?? [], true);
    this._sigBytes = chunkList[5].buf;
    this._tokenLHS = chunkList[6].buf;
    this._prevTokenTx = chunkList[7].buf;
    this._witnessPadding = chunkList[8].buf;
  }

  List<int>? get pp2Output => _pp2Output;
  SVPublicKey? get pubKey => _pubKey;
  BigInt? get changeAmount => _changeAmount;
  List<int>? get tokenLHS => _tokenLHS;
  List<int>? get prevTokenTx => _prevTokenTx;
  List<int>? get witnessPadding => _witnessPadding;
  /// The 36-byte funding outpoint (txid + vout) for the witness transaction.
  List<int>? get fundingOutpoint => _fundingOutpoint;
  String? get changePKH => _changePKH;
  List<int>? get sigBytes => _sigBytes;
  List<int>? get stampMetadata => _stampMetadata;
}
