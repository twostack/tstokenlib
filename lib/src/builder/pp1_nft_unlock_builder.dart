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


/// The type of action being performed on a token.
enum TokenAction {
  /// Initial token creation.
  ISSUANCE,
  /// Transfer of token ownership.
  TRANSFER,
  /// Permanent destruction of a token.
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP1 inductive proof output.
///
/// Supports three token actions: issuance, transfer, and burn. Each action
/// produces a different scriptSig layout with the appropriate data pushes
/// and an OP_N function selector.
class PP1NftUnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  TokenAction? action;
  List<int>? _fundingOutpoint;

  // Rabin identity binding fields (used during issuance)
  List<int>? _rabinN;           // Rabin public key n, encoded as script number bytes
  List<int>? _rabinS;           // Rabin signature s, encoded as script number bytes
  int? _rabinPadding;           // Rabin signature padding (small integer)
  List<int>? _identityTxId;     // 32-byte identity anchor transaction ID
  List<int>? _ed25519PubKey;    // 32-byte ED25519 public key

  //these are populated upon parsing/reconstruction
  List<int>? _sigBytes;


  /// The sighash preimage used for in-script signature verification.
  List<int>? get preImage => _preImage;

  /// Creates a PP1 unlock builder for a token transfer.
  PP1NftUnlockBuilder(
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
      {List<int>? rabinN,
       List<int>? rabinS,
       int? rabinPadding,
       List<int>? identityTxId,
       List<int>? ed25519PubKey}
      ) : _rabinN = rabinN,
          _rabinS = rabinS,
          _rabinPadding = rabinPadding,
          _identityTxId = identityTxId,
          _ed25519PubKey = ed25519PubKey;


  /// Creates a PP1 unlock builder for burning (destroying) a token.
  PP1NftUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        action = TokenAction.BURN;

  /// Reconstructs a [PP1NftUnlockBuilder] by parsing an existing script.
  ///
  /// [action] defaults to [TokenAction.TRANSFER]; set to [TokenAction.ISSUANCE]
  /// when parsing the witness for the issuance transaction.
  PP1NftUnlockBuilder.fromScript(SVScript script, {TokenAction this.action = TokenAction.TRANSFER}): super.fromScript(script);

  @override
  SVScript getScriptSig() {

    SVSignature? signature  = null;
    if (!signatures.isEmpty) {
      signature = signatures[0];
    }

    if (signature == null) {
      return ScriptBuilder().build(); //return empty script; otherwise we will barf on early serialize (prior to signing)
    }

    var sigBytes = hex.decode(this.signatures.first.toTxFormat());

    var result = ScriptBuilder();

    if (action == TokenAction.ISSUANCE) {

      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._fundingOutpoint!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      // Rabin identity binding data
      result.addData(Uint8List.fromList(this._rabinN!));
      result.addData(Uint8List.fromList(this._rabinS!));
      result.number(this._rabinPadding!);
      result.addData(Uint8List.fromList(this._identityTxId!));
      result.addData(Uint8List.fromList(this._ed25519PubKey!));

    }else if (action == TokenAction.TRANSFER){

      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!))); //must be PKH
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));

    }else if (action == TokenAction.BURN) {
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));
    }

    switch (action!){
      case TokenAction.ISSUANCE :
        result.opCode(OpCodes.OP_0);
        break;
      case TokenAction.TRANSFER:
        result.opCode(OpCodes.OP_1);
        break;
      case TokenAction.BURN:
        result.opCode(OpCodes.OP_2);
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

  /// The serialized PP2 output script used during transfer verification.
  List<int>? get pp2Output => _pp2Output;

  /// The public key of the current token owner.
  SVPublicKey? get ownerPubKey => _ownerPubKey;

  /// The satoshi amount sent as change.
  BigInt? get changeAmount => _changeAmount;

  /// The left-hand side of the token transaction used in inductive proof.
  List<int>? get tokenLHS => _tokenLHS;

  /// The serialized previous token transaction.
  List<int>? get prevTokenTx => _prevTokenTx;

  /// Padding bytes for the witness partial SHA256 calculation.
  List<int>? get witnessPadding => _witnessPadding;

  /// The 36-byte funding outpoint (txid + vout) for the witness transaction.
  List<int>? get fundingOutpoint => _fundingOutpoint;

  /// The pubkey hash of the change output recipient.
  String? get changePKH => _changePKH;

  /// The raw signature bytes (populated when parsing an existing script).
  List<int>? get sigBytes => _sigBytes;
}
