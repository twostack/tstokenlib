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

/**
 * The PP2 Lock builder is positioned as the third output of the token transaction.
 * It's primary purpose is to bridge the connection between the Sha256 output in fourth position,
 * and the Inductive Proof in PP1 (second token output).
 * PP2 will assert that all the witness outpoints spend from this transaction. In order to
 * do so it will perform an in-script rebuild of it's Sighash PreImage.
 *
 * Constructor Parameters :
 *
 *  fundingOutpoint - The outpoint that will fund the Witness Transaction
 *  witnessChangePKH - The Pubkey Hash to which the Witness output will be locked
 *  changeAmount   - The satoshi amount locked by the Witness' output
 *  ownerPKH       - The Pubkey Hash of the current token owner (needed for burn)
 */
/// Builds the locking script for the PP2 output (index 2) of a token transaction.
///
/// PP2 is the witness bridge. It connects the partial SHA256 witness output (index 3)
/// to the inductive proof in PP1 (index 1) by asserting that all witness outpoints
/// spend from this transaction via an in-script sighash preimage rebuild.
class PP2LockBuilder extends LockingScriptBuilder{

  //DEBUG
  // String template = "0176017c018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000<outpoint><witnessChangePKH><witnessChangeAmount><ownerPKH>615379587a75577a577a577a577a577a577a577a5279577a75567a567a567a567a567a567a5179567a75557a557a557a557a557a0079557a75547a547a547a547a75757575615e79008763040200000060795154615179517951938000795179827751947f75007f77517a75517a75517a75617e0111795254615179517951938000795179827751947f75007f77517a75517a75517a75617e0112795254615179517951938000795179827751947f75007f77517a75517a75517a75617e577953797e52797e0079a8a84c510079011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a9517987695f79011179ac77777777777777777777777777777777776700686805ffffffff0054615179517951938000795179827751947f75007f77517a75517a75517a7561007951797e51797ea8a800011279011279855d7961011879011a797e0117797e01147e51797e0118797e0116797e517a75615d7958805179610079827700517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e527981007954805e795a797e57797e5c797e5979610079827700517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e5158807e58797e5379a8a87e567954807e51797e0079a8a80079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e810079011979210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810011a79011f79011f798561537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a7561ab0079011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a9517987695f79011179ac777777777777777777777777777777777767006868";

  //RELEASE
  String template = "0176017c018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000<outpoint><witnessChangePKH><witnessChangeAmount><ownerPKH>5379587a75577a577a577a577a577a577a577a5279577a75567a567a567a567a567a567a78567a757171557a76557a75547a547a547a547a6d6d5e790087630402000000607951546e8b80767682778c7f75007f777777777e01117952546e8b80767682778c7f75007f777777777e01127952546e8b80767682778c7f75007f777777777e577953797e52797e76a8a84c4e76011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a978885f79011179ac77777777777777777777777777777777776700686805ffffffff00546e8b80767682778c7f75007f7777777776767e787ea8a800011279011279855d79011879011a797e0117797e01147e787e0118797e0116797e775d79588078768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5279817654805e795a797e57797e5c797e5979768277007802fd009f6378516e8b80767682778c7f75007f77777777776778030000019f6301fd5279526e8b80767682778c7f75007f777777777e7767780500000000019f6301fe5279546e8b80767682778c7f75007f777777777e776778090000000000000000019f6301ff5279586e8b80767682778c7f75007f777777777e77686868687653797e7777777e5158807e58797e5379a8a87e567954807e787e76a8a876517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8176011979210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce0810011a79011f79011f7985537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e777777777777777777777777ab76011979ac7777777777777777777777777777777777777777777777777777777777777777777777675e795187636079a978885f79011179ac777777777777777777777777777777777767006868";

  List<int> _fundingOutpoint;
  List<int> _witnessChangePKH;
  int _changeAmount;
  List<int> _ownerPKH;

  /// Reconstructs a [PP2LockBuilder] by parsing an existing script.
  PP2LockBuilder.fromScript(SVScript script) :
      _fundingOutpoint = [],
      _witnessChangePKH = [],
      _changeAmount = 0,
      _ownerPKH = [],
      super.fromScript(script);

  /// Creates a PP2 locking script builder.
  ///
  /// [_fundingOutpoint] - 36-byte outpoint (txid + index) funding the witness transaction.
  /// [_witnessChangePKH] - 20-byte pubkey hash for the witness change output.
  /// [_changeAmount] - Satoshi amount locked by the witness change output.
  /// [_ownerPKH] - 20-byte pubkey hash of the current token owner (needed for burn).
  PP2LockBuilder(this._fundingOutpoint, this._witnessChangePKH, this._changeAmount, this._ownerPKH) {
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
        .replaceFirst("<ownerPKH>", ScriptBuilder().addData(Uint8List.fromList(_ownerPKH)).build().toHex());

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

  @override
  void parse(SVScript script) {
    var scriptHex = hex.encode(script.buffer);

    // The prefix before constructor params is the same for DEBUG and RELEASE templates
    var prefixEnd = template.indexOf('<outpoint>');
    var prefix = template.substring(0, prefixEnd);

    if (!scriptHex.startsWith(prefix)) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script does not match PP2 template");
    }

    // Parse constructor params from the script bytes after the prefix
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
  }
}