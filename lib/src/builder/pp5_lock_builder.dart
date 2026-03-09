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

import 'package:dartsv/dartsv.dart';
import '../script_gen/pp5_script_gen.dart';

/// Builds the locking script for the PP5 fungible token output.
///
/// PP5 holds the fungible token state: recipient, token ID, and amount.
class PP5LockBuilder extends LockingScriptBuilder {

  List<int> _recipientPKH;
  List<int> _tokenId;
  int _amount;

  /// Reconstructs a [PP5LockBuilder] by parsing an existing script.
  PP5LockBuilder.fromScript(SVScript script) :
      _recipientPKH = [],
      _tokenId = [],
      _amount = 0,
      super.fromScript(script);

  /// Creates a PP5 locking script builder.
  ///
  /// [_recipientPKH] - 20-byte pubkey hash of the token recipient.
  /// [_tokenId] - 32-byte token identifier.
  /// [_amount] - The fungible token amount (encoded as 8-byte LE sign-magnitude).
  PP5LockBuilder(this._recipientPKH, this._tokenId, this._amount) {
    if (_recipientPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient PKH must be 20 bytes");
    }
    if (_tokenId.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_amount < 0) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Amount must be non-negative");
    }
  }

  @override
  SVScript getScriptPubkey() {
    return PP5ScriptGen.generate(
      ownerPKH: _recipientPKH,
      tokenId: _tokenId,
      amount: _amount,
    );
  }

  /// The 20-byte pubkey hash of the token recipient.
  List<int> get recipientPKH => _recipientPKH;

  /// The 32-byte token identifier.
  List<int> get tokenId => _tokenId;

  /// The fungible token amount.
  int get amount => _amount;

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    // Hand-optimized PP5 layout:
    // Byte 0:     0x14 (pushdata 20)
    // Bytes 1-20: ownerPKH
    // Byte 21:    0x20 (pushdata 32)
    // Bytes 22-53: tokenId
    // Byte 54:    0x08 (pushdata 8)
    // Bytes 55-62: amount (8-byte LE)
    if (buf.length < PP5ScriptGen.amountDataEnd) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP5");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _recipientPKH = buf.sublist(PP5ScriptGen.pkhDataStart, PP5ScriptGen.pkhDataEnd).toList();
    _tokenId = buf.sublist(PP5ScriptGen.tokenIdDataStart, PP5ScriptGen.tokenIdDataEnd).toList();
    var amountBytesList = buf.sublist(PP5ScriptGen.amountDataStart, PP5ScriptGen.amountDataEnd);
    _amount = castToBigInt(amountBytesList, false, nMaxNumSize: 8).toInt();
  }
}
