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


enum TokenAction {
  ISSUANCE,
  TRANSFER,
  BURN
}

class PP1UnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _ownerPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  TokenAction? action;
  List<int>? _witnessFundingTxId;


  //these are populated upon parsing/reconstruction
  List<int>? _sigBytes;


  List<int>? get preImage => _preImage;

  PP1UnlockBuilder(
      this._preImage,
      this._pp2Output,
      this._ownerPubKey,
      this._changePKH,
      this._changeAmount,
      this._tokenLHS,
      this._prevTokenTx,
      this._witnessPadding,
      this.action,
      this._witnessFundingTxId
      );


  //Set issuanceWitness to true if this is the witness for the issuance transaction
  PP1UnlockBuilder.fromScript(SVScript script, {TokenAction this.action = TokenAction.TRANSFER}): super.fromScript(script);

  // PP1LockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST}) : super.fromScript(script);

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

    // var changePKH = Address.fromPubkeyHash( _changePKH!, NetworkType.TEST).toHex();
    var result = ScriptBuilder();

    if (action == TokenAction.ISSUANCE) {

      result.addData(Uint8List.fromList(this._preImage!));
      result.addData(Uint8List.fromList(this._witnessFundingTxId!));
      result.addData(Uint8List.fromList(this._witnessPadding!));

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

    }else {
      var signature = signatures[0];
      var sigBuffer = Uint8List.fromList(hex.decode(signature.toTxFormat()));
      var pkBuffer = Uint8List.fromList(hex.decode(_ownerPubKey!.toHex()));

      return ScriptBuilder()
          .addData(pkBuffer)
          .addData(sigBuffer)
          .build();
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

      // if (chunkList.length < 1000) { //arbitrary length check
      //   throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for PP1 ScriptPubkey");
      // }

      //check length of recipient address
      // if (chunkList[11].len != 20) {
      //   throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient Address has invalid length. Maybe not a PP1 script ? ");
      // }
      //
      // //check length of token id
      // if (chunkList[12].len != 32) {
      //   throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "TokenId has invalid length. Maybe not a PP1 script ? ");
      // }

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
