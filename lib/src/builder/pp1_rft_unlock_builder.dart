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

/// The type of action being performed on a restricted fungible token.
enum RestrictedFungibleTokenAction {
  /// Initial token minting.
  MINT,
  /// Transfer of token amount.
  TRANSFER,
  /// Split transfer to multiple recipients.
  SPLIT_TRANSFER,
  /// Merge multiple token UTXOs.
  MERGE,
  /// Redeem the token.
  REDEEM,
  /// Permanent destruction of tokens.
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP1_RFT output.
///
/// Supports six modes: MINT (OP_0), TRANSFER (OP_1), SPLIT_TRANSFER (OP_2),
/// MERGE (OP_3), REDEEM (OP_4), and BURN (OP_5).
class PP1RftUnlockBuilder extends UnlockingScriptBuilder {

  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  List<int>? _fundingOutpoint;
  RestrictedFungibleTokenAction? _action;
  int? _recipientAmount;
  int? _tokenChangeAmount;
  List<int>? _recipientPKH;
  int? _myOutputIndex;
  int? _parentOutputCount;

  // Merge-specific fields
  List<int>? _prevTokenTxB;
  int? _parentOutputCountB;
  int? _parentPP1FtIndexA;
  int? _parentPP1FtIndexB;

  // Merkle whitelist fields (transfer + split)
  List<int>? _transferRecipientPKH;
  List<int>? _merkleProof;
  List<int>? _merkleSides;

  // Rabin identity binding fields (mint)
  List<int>? _rabinN;
  List<int>? _rabinS;
  int? _rabinPadding;
  List<int>? _identityTxId;
  List<int>? _ed25519PubKey;

  List<int>? _pp2ChangeOutput;
  List<int>? _sigBytes;

  /// Creates a PP1_RFT unlock builder for minting new tokens.
  PP1RftUnlockBuilder.forMint(
    List<int> preImage,
    List<int> fundingOutpoint,
    List<int> witnessPadding,
    {List<int>? rabinN,
     List<int>? rabinS,
     int? rabinPadding,
     List<int>? identityTxId,
     List<int>? ed25519PubKey}
  ) : _preImage = preImage,
      _fundingOutpoint = fundingOutpoint,
      _witnessPadding = witnessPadding,
      _rabinN = rabinN,
      _rabinS = rabinS,
      _rabinPadding = rabinPadding,
      _identityTxId = identityTxId,
      _ed25519PubKey = ed25519PubKey,
      _action = RestrictedFungibleTokenAction.MINT;

  /// Creates a PP1_RFT unlock builder for a token transfer.
  PP1RftUnlockBuilder.forTransfer(
    List<int> preImage,
    List<int> pp2Output,
    SVPublicKey ownerPubKey,
    String changePKH,
    BigInt changeAmount,
    List<int> tokenLHS,
    List<int> prevTokenTx,
    List<int> witnessPadding,
    int parentOutputCount,
    int parentPP1FtIndex,
    List<int> transferRecipientPKH,
    List<int> merkleProof,
    List<int> merkleSides,
  ) : _preImage = preImage,
      _pp2Output = pp2Output,
      _ownerPubKey = ownerPubKey,
      _changePKH = changePKH,
      _changeAmount = changeAmount,
      _tokenLHS = tokenLHS,
      _prevTokenTx = prevTokenTx,
      _witnessPadding = witnessPadding,
      _parentOutputCount = parentOutputCount,
      _parentPP1FtIndexA = parentPP1FtIndex,
      _transferRecipientPKH = transferRecipientPKH,
      _merkleProof = merkleProof,
      _merkleSides = merkleSides,
      _action = RestrictedFungibleTokenAction.TRANSFER;

  /// Creates a PP1_RFT unlock builder for a split transfer.
  PP1RftUnlockBuilder.forSplitTransfer(
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
    int parentPP1FtIndex,
    List<int> merkleProof,
    List<int> merkleSides,
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
      _parentPP1FtIndexA = parentPP1FtIndex,
      _merkleProof = merkleProof,
      _merkleSides = merkleSides,
      _action = RestrictedFungibleTokenAction.SPLIT_TRANSFER;

  /// Creates a PP1_RFT unlock builder for merging two token UTXOs.
  PP1RftUnlockBuilder.forMerge(
    List<int> preImage,
    List<int> pp2Output,
    SVPublicKey ownerPubKey,
    String changePKH,
    BigInt changeAmount,
    List<int> tokenLHS,
    List<int> prevTokenTxA,
    List<int> prevTokenTxB,
    List<int> witnessPadding,
    int parentOutputCountA,
    int parentOutputCountB,
    int parentPP1FtIndexA,
    int parentPP1FtIndexB,
  ) : _preImage = preImage,
      _pp2Output = pp2Output,
      _ownerPubKey = ownerPubKey,
      _changePKH = changePKH,
      _changeAmount = changeAmount,
      _tokenLHS = tokenLHS,
      _prevTokenTx = prevTokenTxA,
      _prevTokenTxB = prevTokenTxB,
      _witnessPadding = witnessPadding,
      _parentOutputCount = parentOutputCountA,
      _parentOutputCountB = parentOutputCountB,
      _parentPP1FtIndexA = parentPP1FtIndexA,
      _parentPP1FtIndexB = parentPP1FtIndexB,
      _action = RestrictedFungibleTokenAction.MERGE;

  /// Creates a PP1_RFT unlock builder for burning tokens.
  PP1RftUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = RestrictedFungibleTokenAction.BURN;

  /// Creates a PP1_RFT unlock builder for redeeming tokens.
  PP1RftUnlockBuilder.forRedeem(SVPublicKey ownerPubKey)
      : _ownerPubKey = ownerPubKey,
        _action = RestrictedFungibleTokenAction.REDEEM;

  /// Reconstructs from an existing script.
  PP1RftUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  List<int>? get preImage => _preImage;
  List<int>? get pp2Output => _pp2Output;
  SVPublicKey? get ownerPubKey => _ownerPubKey;
  BigInt? get changeAmount => _changeAmount;
  List<int>? get tokenLHS => _tokenLHS;
  List<int>? get prevTokenTx => _prevTokenTx;
  List<int>? get witnessPadding => _witnessPadding;
  List<int>? get fundingOutpoint => _fundingOutpoint;
  String? get changePKH => _changePKH;
  List<int>? get sigBytes => _sigBytes;
  RestrictedFungibleTokenAction? get action => _action;

  @override
  SVScript getScriptSig() {

    SVSignature? signature = null;
    if (!signatures.isEmpty) {
      signature = signatures[0];
    }

    if (signature == null && _action != RestrictedFungibleTokenAction.MINT) {
      return ScriptBuilder().build();
    }

    var result = ScriptBuilder();

    if (_action == RestrictedFungibleTokenAction.MINT) {

      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._fundingOutpoint!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.addData(Uint8List.fromList(this._rabinN!));
      result.addData(Uint8List.fromList(this._rabinS!));
      result.number(this._rabinPadding!);
      result.addData(Uint8List.fromList(this._identityTxId!));
      result.addData(Uint8List.fromList(this._ed25519PubKey!));

    } else if (_action == RestrictedFungibleTokenAction.TRANSFER) {

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
      result.number(this._parentPP1FtIndexA!);
      result.addData(Uint8List.fromList(_transferRecipientPKH!));
      result.addData(Uint8List.fromList(_merkleProof ?? []));
      result.addData(Uint8List.fromList(_merkleSides ?? []));

    } else if (_action == RestrictedFungibleTokenAction.SPLIT_TRANSFER) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));       // pp2RecipOut
      result.addData(Uint8List.fromList(this._pp2ChangeOutput!)); // pp2ChangeOut
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
      result.number(this._parentPP1FtIndexA!);
      result.addData(Uint8List.fromList(_merkleProof ?? []));
      result.addData(Uint8List.fromList(_merkleSides ?? []));

    } else if (_action == RestrictedFungibleTokenAction.MERGE) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._pp2Output!));
      result.addData(Uint8List.fromList(hex.decode(this._ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
      result.number(this._changeAmount!.toInt());
      result.addData(Uint8List.fromList(sigBytes));
      result.addData(Uint8List.fromList(this._tokenLHS!));
      result.addData(Uint8List.fromList(this._prevTokenTx!));
      result.addData(Uint8List.fromList(this._prevTokenTxB!));
      result.addData(Uint8List.fromList(this._witnessPadding!));
      result.number(this._parentOutputCount!);
      result.number(this._parentOutputCountB!);
      result.number(this._parentPP1FtIndexA!);
      result.number(this._parentPP1FtIndexB!);

    } else if (_action == RestrictedFungibleTokenAction.REDEEM) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));

    } else if (_action == RestrictedFungibleTokenAction.BURN) {

      var sigBytes = hex.decode(this.signatures.first.toTxFormat());
      result.addData(Uint8List.fromList(hex.decode(_ownerPubKey!.toHex())));
      result.addData(Uint8List.fromList(sigBytes));

    }

    switch (_action!) {
      case RestrictedFungibleTokenAction.MINT:
        result.opCode(OpCodes.OP_0);
        break;
      case RestrictedFungibleTokenAction.TRANSFER:
        result.opCode(OpCodes.OP_1);
        break;
      case RestrictedFungibleTokenAction.SPLIT_TRANSFER:
        result.opCode(OpCodes.OP_2);
        break;
      case RestrictedFungibleTokenAction.MERGE:
        result.opCode(OpCodes.OP_3);
        break;
      case RestrictedFungibleTokenAction.REDEEM:
        result.opCode(OpCodes.OP_4);
        break;
      case RestrictedFungibleTokenAction.BURN:
        result.opCode(OpCodes.OP_5);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;

    if (chunkList.isEmpty) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Empty PP1_RFT ScriptSig");
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
