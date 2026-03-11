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

/// Builds the locking script for the PP2-FT output of a fungible token transaction.
///
/// PP2-FT is the witness bridge for fungible tokens. It extends PP2 with additional
/// output index parameters for the PP1_FT and PP2 outputs.
class PP2FtLockBuilder extends LockingScriptBuilder {

  String template = "0176017c018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c000000000000<outpoint><witnessChangePKH><witnessChangeAmount><ownerPKH><pp1FtOutputIndex><pp2OutputIndex>55795c7a755b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a54795b7a755a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a53795a7a75597a597a597a597a597a597a597a597a597a5279597a75587a587a587a587a587a587a587a587a78587a75577a577a577a577a577a577a577a76577a75567a567a567a567a567a567a6d6d6d607900876304020000000112795379546e8b80767682778c7f75007f777777777e0113795379546e8b80767682778c7f75007f777777777e0114795479546e8b80767682778c7f75007f777777777e597953797e52797e76a8a8010005ffffffff00546e8b80767682778c7f75007f7777777776767e787ea8a800011479011479855f79011a79011c797e0119797e01147e787e011a797e0118797e775f79588078768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5279817654805e795a797e57797e5c797e5979768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5158807e58797e5379a8a87e567954807e787e76a8a876517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8176011b79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810011c7901217901217985537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e777777777777777777777777ab76011b79ac77777777777777777777777777777777777777777777777777777777777777777777777777676079518763011279a9537988011179011379ac7777777777777777777777777777777777777767006868";

  List<int> _fundingOutpoint;
  List<int> _witnessChangePKH;
  int _changeAmount;
  List<int> _ownerPKH;
  int _pp1FtOutputIndex;
  int _pp2OutputIndex;

  /// Reconstructs a [PP2FtLockBuilder] by parsing an existing script.
  PP2FtLockBuilder.fromScript(SVScript script) :
      _fundingOutpoint = [],
      _witnessChangePKH = [],
      _changeAmount = 0,
      _ownerPKH = [],
      _pp1FtOutputIndex = 0,
      _pp2OutputIndex = 0,
      super.fromScript(script);

  /// Creates a PP2-FT locking script builder.
  ///
  /// [_fundingOutpoint] - 36-byte outpoint (txid + index) funding the witness transaction.
  /// [_witnessChangePKH] - 20-byte pubkey hash for the witness change output.
  /// [_changeAmount] - Satoshi amount locked by the witness change output.
  /// [_ownerPKH] - 20-byte pubkey hash of the current token owner (needed for burn).
  /// [_pp1FtOutputIndex] - Output index of the PP1_FT fungible token output.
  /// [_pp2OutputIndex] - Output index of the PP2-FT output.
  PP2FtLockBuilder(this._fundingOutpoint, this._witnessChangePKH, this._changeAmount, this._ownerPKH, this._pp1FtOutputIndex, this._pp2OutputIndex) {
    if (_fundingOutpoint.length != 36) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Funding outpoint must be 36 bytes (32-byte txid + 4-byte index)");
    }
    if (_witnessChangePKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Witness change PKH must be 20 bytes");
    }
    if (_changeAmount < 0) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Change amount must be non-negative");
    }
    if (_ownerPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner PKH must be 20 bytes");
    }
  }

  @override
  SVScript getScriptPubkey() {

    var scriptHex = template
        .replaceFirst("<outpoint>", ScriptBuilder().addData(Uint8List.fromList(_fundingOutpoint)).build().toHex())
        .replaceFirst("<witnessChangePKH>", ScriptBuilder().addData(Uint8List.fromList(_witnessChangePKH)).build().toHex())
        .replaceFirst("<witnessChangeAmount>", ScriptBuilder().number(_changeAmount).build().toHex())
        .replaceFirst("<ownerPKH>", ScriptBuilder().addData(Uint8List.fromList(_ownerPKH)).build().toHex())
        .replaceFirst("<pp1FtOutputIndex>", ScriptBuilder().number(_pp1FtOutputIndex).build().toHex())
        .replaceFirst("<pp2OutputIndex>", ScriptBuilder().number(_pp2OutputIndex).build().toHex());

        return SVScript.fromHex(scriptHex);
  }

  /// The 36-byte outpoint funding the witness transaction.
  List<int> get fundingOutpoint => _fundingOutpoint;

  /// The 20-byte pubkey hash for the witness change output.
  List<int> get witnessChangePKH => _witnessChangePKH;

  /// The satoshi amount locked by the witness change output.
  int get changeAmount => _changeAmount;

  /// The 20-byte pubkey hash of the current token owner.
  List<int> get ownerPKH => _ownerPKH;

  /// The output index of the PP1_FT fungible token output.
  int get pp1FtOutputIndex => _pp1FtOutputIndex;

  /// The output index of the PP2-FT output.
  int get pp2OutputIndex => _pp2OutputIndex;

  @override
  void parse(SVScript script) {
    var scriptHex = hex.encode(script.buffer);

    var prefixEnd = template.indexOf('<outpoint>');
    var prefix = template.substring(0, prefixEnd);

    if (!scriptHex.startsWith(prefix)) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script does not match PP2-FT template");
    }

    var paramBytes = hex.decode(scriptHex.substring(prefix.length));
    var offset = 0;

    // Read outpoint pushdata (expected: 0x24 = 36 bytes)
    var outpointLen = paramBytes[offset];
    offset++;
    _fundingOutpoint = paramBytes.sublist(offset, offset + outpointLen).toList();
    offset += outpointLen;

    // Read witnessChangePKH pushdata (expected: 0x14 = 20 bytes)
    var pkhLen = paramBytes[offset];
    offset++;
    _witnessChangePKH = paramBytes.sublist(offset, offset + pkhLen).toList();
    offset += pkhLen;

    // Read changeAmount (script number encoding)
    var amountByte = paramBytes[offset];
    if (amountByte == 0x00) {
      _changeAmount = 0;
    } else if (amountByte >= 0x51 && amountByte <= 0x60) {
      _changeAmount = amountByte - 0x50;
    } else {
      var numLen = amountByte;
      offset++;
      var numBytes = paramBytes.sublist(offset, offset + numLen);
      _changeAmount = castToBigInt(numBytes, true).toInt();
      offset += numLen;
    }
    offset++;

    // Read ownerPKH pushdata (expected: 0x14 = 20 bytes)
    var ownerPkhLen = paramBytes[offset];
    offset++;
    _ownerPKH = paramBytes.sublist(offset, offset + ownerPkhLen).toList();
    offset += ownerPkhLen;

    // Read pp1FtOutputIndex (script number encoding)
    var pp1FtByte = paramBytes[offset];
    if (pp1FtByte == 0x00) {
      _pp1FtOutputIndex = 0;
    } else if (pp1FtByte >= 0x51 && pp1FtByte <= 0x60) {
      _pp1FtOutputIndex = pp1FtByte - 0x50;
    } else {
      var numLen = pp1FtByte;
      offset++;
      var numBytes = paramBytes.sublist(offset, offset + numLen);
      _pp1FtOutputIndex = castToBigInt(numBytes, true).toInt();
      offset += numLen;
    }
    offset++;

    // Read pp2OutputIndex (script number encoding)
    var pp2Byte = paramBytes[offset];
    if (pp2Byte == 0x00) {
      _pp2OutputIndex = 0;
    } else if (pp2Byte >= 0x51 && pp2Byte <= 0x60) {
      _pp2OutputIndex = pp2Byte - 0x50;
    } else {
      var numLen = pp2Byte;
      offset++;
      var numBytes = paramBytes.sublist(offset, offset + numLen);
      _pp2OutputIndex = castToBigInt(numBytes, true).toInt();
      offset += numLen;
    }
  }
}
