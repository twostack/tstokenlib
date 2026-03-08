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

/// The type of action being performed on a fungible token.
enum FungibleTokenAction {
  /// Initial token minting.
  MINT,
  /// Transfer of token amount.
  TRANSFER,
  /// Split transfer to multiple recipients.
  SPLIT_TRANSFER,
  /// Merge multiple token UTXOs.
  MERGE,
  /// Permanent destruction of tokens.
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP5 fungible token output.
///
/// Supports five modes: MINT (OP_0), TRANSFER (OP_1), SPLIT_TRANSFER (OP_2),
/// MERGE (OP_3), and BURN (OP_4).
class PP5UnlockBuilder extends UnlockingScriptBuilder {

  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  List<int>? _witnessFundingTxId;
  FungibleTokenAction? _action;
  int? _recipientAmount;
  int? _tokenChangeAmount;
  List<int>? _recipientPKH;
  int? _myOutputIndex;
  int? _parentOutputCount;

  //these are populated upon parsing/reconstruction
  List<int>? _sigBytes;

  /// Creates a PP5 unlock builder for minting new tokens.
  ///
  /// [preImage] - The sighash preimage.
  /// [witnessFundingTxId] - The funding transaction ID.
  /// [witnessPadding] - Padding bytes for SHA256 calculation.
  PP5UnlockBuilder.forMint(
    List<int> preImage,
    List<int> witnessFundingTxId,
    List<int> witnessPadding,
  ) : _preImage = preImage,
      _witnessFundingTxId = witnessFundingTxId,
      _witnessPadding = witnessPadding,
      _action = FungibleTokenAction.MINT;

  /// Creates a PP5 unlock builder for a token transfer.
  PP5UnlockBuilder.forTransfer(
    List<int> preImage,
    List<int> pp2Output,
    SVPublicKey ownerPubKey,
    String changePKH,
    BigInt changeAmount,
    List<int> tokenLHS,
    List<int> prevTokenTx,
    List<int> witnessPadding,
    int parentOutputCount,
  ) : _preImage = preImage,
      _pp2Output = pp2Output,
      _ownerPubKey = ownerPubKey,
      _changePKH = changePKH,
      _changeAmount = changeAmount,
      _tokenLHS = tokenLHS,
      _prevTokenTx = prevTokenTx,
      _witnessPadding = witnessPadding,
      _parentOutputCount = parentOutputCount,
      _action = FungibleTokenAction.TRANSFER;

  /// Creates a PP5 unlock builder for a split transfer.
  PP5UnlockBuilder.forSplitTransfer(
    List<int> preImage,
    List<int> pp2RecipientOutput,
    List<int> pp2ChangeOutput,
    SVPublicKey ownerPubKey,
    String changePKH,
    BigInt changeAmount,
    List<int> tokenLHS,
    List<int> prevTokenTx,
    List<int> witnessPadding,
    int recipientAmount,
    int tokenChangeAmount,
    List<int> recipientPKH,
    int myOutputIndex,
    int parentOutputCount,
  ) : _preImage = preImage,
      _pp2Output = pp2RecipientOutput,
      _pp2ChangeOutput = pp2ChangeOutput,
      _ownerPubKey = ownerPubKey,
      _changePKH = changePKH,
      _changeAmount = changeAmount,
      _tokenLHS = tokenLHS,
      _prevTokenTx = prevTokenTx,
      _witnessPadding = witnessPadding,
      _recipientAmount = recipientAmount,
      _tokenChangeAmount = tokenChangeAmount,
      _recipientPKH = recipientPKH,
      _myOutputIndex = myOutputIndex,
      _parentOutputCount = parentOutputCount,
      _action = FungibleTokenAction.SPLIT_TRANSFER;

  List<int>? _pp2ChangeOutput;

  /// Creates a PP5 unlock builder for burning tokens.
  PP5UnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = FungibleTokenAction.BURN;

  /// Creates a PP5 unlock builder for merging token UTXOs.
  PP5UnlockBuilder.forMerge(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = FungibleTokenAction.MERGE;

  /// Reconstructs a [PP5UnlockBuilder] by parsing an existing script.
  PP5UnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  /// The sighash preimage.
  List<int>? get preImage => _preImage;

  /// The serialized PP2 output script.
  List<int>? get pp2Output => _pp2Output;

  /// The public key of the current token owner.
  SVPublicKey? get ownerPubKey => _ownerPubKey;

  /// The satoshi amount sent as change.
  BigInt? get changeAmount => _changeAmount;

  /// The left-hand side of the token transaction.
  List<int>? get tokenLHS => _tokenLHS;

  /// The serialized previous token transaction.
  List<int>? get prevTokenTx => _prevTokenTx;

  /// Padding bytes for the witness SHA256 calculation.
  List<int>? get witnessPadding => _witnessPadding;

  /// The funding transaction ID for the witness.
  List<int>? get witnessFundingTxId => _witnessFundingTxId;

  /// The pubkey hash of the change output recipient.
  String? get changePKH => _changePKH;

  /// The raw signature bytes (populated when parsing).
  List<int>? get sigBytes => _sigBytes;

  /// The fungible token action being performed.
  FungibleTokenAction? get action => _action;

  /// The amount being sent to the recipient (split transfer).
  int? get recipientAmount => _recipientAmount;

  /// The token change amount returned to sender (split transfer).
  int? get tokenChangeAmount => _tokenChangeAmount;

  /// The recipient's pubkey hash (split transfer).
  List<int>? get recipientPKH => _recipientPKH;

  /// The output index of this PP5 output (split transfer).
  int? get myOutputIndex => _myOutputIndex;

  /// The number of outputs in the parent transaction.
  int? get parentOutputCount => _parentOutputCount;

  @override
  SVScript getScriptSig() {

    SVSignature? signature = null;
    if (!signatures.isEmpty) {
      signature = signatures[0];
    }

    if (signature == null && _action != FungibleTokenAction.MINT) {
      return ScriptBuilder().build();
    }

    var result = ScriptBuilder();

    if (_action == FungibleTokenAction.MINT) {

      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._witnessFundingTxId!));
      result.addData(Uint8List.fromList(this._witnessPadding!));

    } else if (_action == FungibleTokenAction.TRANSFER) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.number(this._parentOutputCount!);

    } else if (_action == FungibleTokenAction.SPLIT_TRANSFER) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(this._pp2ChangeOutput ?? []));
      result.addData(Uint8List.fromList(hex.decode(this._ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.number(this._recipientAmount!);
      result.number(this._tokenChangeAmount!);
      result.addData(Uint8List.fromList(this._recipientPKH!));
      result.number(this._myOutputIndex!);
      result.number(this._parentOutputCount!);

    } else if (_action == FungibleTokenAction.MERGE) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));

    } else if (_action == FungibleTokenAction.BURN) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));

    }

    switch (_action!) {
      case FungibleTokenAction.MINT:
        result.opCode(OpCodes.OP_0);
        break;
      case FungibleTokenAction.TRANSFER:
        result.opCode(OpCodes.OP_1);
        break;
      case FungibleTokenAction.SPLIT_TRANSFER:
        result.opCode(OpCodes.OP_2);
        break;
      case FungibleTokenAction.MERGE:
        result.opCode(OpCodes.OP_3);
        break;
      case FungibleTokenAction.BURN:
        result.opCode(OpCodes.OP_4);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;

    if (chunkList.isEmpty) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Empty PP5 ScriptSig");
    }

    _preImage = chunkList[0].buf;
    _pp2Output = chunkList[1].buf;
    _ownerPubKey = SVPublicKey.fromBuffer(chunkList[2].buf ?? []);
    _changePKH = hex.encode(chunkList[3].buf ?? [00]);
    _changeAmount = castToBigInt(chunkList[4].buf ?? [], true);
    _sigBytes = chunkList[5].buf;
    _tokenLHS = chunkList[6].buf;
    _prevTokenTx = chunkList[7].buf;
    _witnessPadding = chunkList[8].buf;
  }
}
