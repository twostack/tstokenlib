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

import '../script_gen/pp1_rft_script_gen.dart';

/// Builds the locking script for the PP1_RFT (Restricted Fungible Token) output.
///
/// PP1_RFT extends PP1_FT with Rabin identity anchoring, transfer policy flags,
/// and optional Merkle tree whitelisting.
///
/// Constructor Params:
///   recipientPKH - 20-byte pubkey hash the token is locked to
///   tokenId - 32-byte unique token identifier
///   rabinPubKeyHash - 20-byte hash160 of the Rabin public key
///   flags - transfer policy flags (0-255)
///   amount - the fungible token amount
class PP1RftLockBuilder extends LockingScriptBuilder {

  List<int> _recipientPKH;
  List<int> _tokenId;
  List<int> _rabinPubKeyHash;
  int _flags;
  int _amount;

  /// Reconstructs a [PP1RftLockBuilder] by parsing an existing script.
  PP1RftLockBuilder.fromScript(SVScript script)
      : _recipientPKH = [],
        _tokenId = [],
        _rabinPubKeyHash = [],
        _flags = 0,
        _amount = 0,
        super.fromScript(script);

  /// Creates a PP1_RFT locking script builder.
  PP1RftLockBuilder(this._recipientPKH, this._tokenId, this._rabinPubKeyHash, this._flags, this._amount) {
    if (_recipientPKH.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient PKH must be 20 bytes");
    }
    if (_tokenId.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_rabinPubKeyHash.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Rabin pubkey hash must be 20 bytes");
    }
    if (_flags < 0 || _flags > 255) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Flags must be a single byte (0-255)");
    }
    if (_amount < 0) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Amount must be non-negative");
    }
  }

  @override
  SVScript getScriptPubkey() {
    return PP1RftScriptGen.generate(
      ownerPKH: _recipientPKH,
      tokenId: _tokenId,
      rabinPubKeyHash: _rabinPubKeyHash,
      flags: _flags,
      amount: _amount,
    );
  }

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    if (buf.length < PP1RftScriptGen.amountDataEnd) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_RFT");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _recipientPKH = buf.sublist(PP1RftScriptGen.pkhDataStart, PP1RftScriptGen.pkhDataEnd).toList();
    _tokenId = buf.sublist(PP1RftScriptGen.tokenIdDataStart, PP1RftScriptGen.tokenIdDataEnd).toList();
    _rabinPubKeyHash = buf.sublist(PP1RftScriptGen.rabinPKHDataStart, PP1RftScriptGen.rabinPKHDataEnd).toList();
    _flags = buf[PP1RftScriptGen.flagsDataStart]; // only low byte used
    var amountBytesList = buf.sublist(PP1RftScriptGen.amountDataStart, PP1RftScriptGen.amountDataEnd);
    _amount = castToBigInt(amountBytesList, false, nMaxNumSize: 8).toInt();
  }

  List<int> get recipientPKH => _recipientPKH;
  List<int> get tokenId => _tokenId;
  List<int> get rabinPubKeyHash => _rabinPubKeyHash;
  int get flags => _flags;
  int get amount => _amount;
}
