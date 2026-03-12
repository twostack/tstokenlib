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

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

import '../script_gen/pp1_rnft_script_gen.dart';

/// Builds the locking script for the PP1_RNFT (Restricted NFT) output.
///
/// PP1_RNFT extends PP1_NFT with transfer policy flags and optional composition.
///
/// Constructor Params:
///   recipientPKH - Address (pubkey hash) the token is locked to
///   tokenId - 32-byte unique token identifier
///   rabinPubKeyHash - 20-byte hash160 of the Rabin public key
///   flags - 1-byte transfer policy flags
///   companionTokenId - optional 32-byte companion token ID
class PP1RnftLockBuilder extends LockingScriptBuilder {
  Address? _recipientPKH;
  List<int>? _tokenId;
  List<int>? _rabinPubKeyHash;
  int _flags;
  List<int>? _companionTokenId;
  NetworkType? networkType;

  PP1RnftLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST})
      : _flags = 0, super.fromScript(script);

  PP1RnftLockBuilder(this._recipientPKH, this._tokenId, this._rabinPubKeyHash, this._flags, {List<int>? companionTokenId, this.networkType})
      : _companionTokenId = companionTokenId {
    if (_recipientPKH == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient address is required");
    }
    if (_tokenId == null || _tokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_rabinPubKeyHash == null || _rabinPubKeyHash!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Rabin pubkey hash must be 20 bytes");
    }
    if (_flags < 0 || _flags > 255) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Flags must be a single byte (0-255)");
    }
    if (_companionTokenId != null && _companionTokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Companion token ID must be 32 bytes");
    }
  }

  @override
  SVScript getScriptPubkey() {
    var recipientPKH = hex.decode(_recipientPKH?.address ?? "00");
    return PP1RnftScriptGen.generate(
      ownerPKH: recipientPKH,
      tokenId: _tokenId!,
      rabinPubKeyHash: _rabinPubKeyHash!,
      flags: _flags,
      companionTokenId: _companionTokenId,
    );
  }

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    // Use byte-offset parsing (like PP1FtLockBuilder) since flags are 4-byte LE
    // Header layout:
    //   Byte 0:     0x14 (pushdata 20)
    //   Bytes 1-20: ownerPKH
    //   Byte 21:    0x20 (pushdata 32)
    //   Bytes 22-53: tokenId
    //   Byte 54:    0x14 (pushdata 20)
    //   Bytes 55-74: rabinPubKeyHash
    //   Byte 75:    0x04 (pushdata 4)
    //   Bytes 76-79: flags (4-byte LE)
    //   Byte 80:    either script body start OR 0x20 (companion push)
    if (buf.length < PP1RnftScriptGen.flagsDataEnd) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_RNFT");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _recipientPKH = Address.fromPubkeyHash(
        hex.encode(buf.sublist(PP1RnftScriptGen.pkhDataStart, PP1RnftScriptGen.pkhDataEnd).toList()),
        networkType ?? NetworkType.TEST);
    _tokenId = buf.sublist(PP1RnftScriptGen.tokenIdDataStart, PP1RnftScriptGen.tokenIdDataEnd).toList();
    _rabinPubKeyHash = buf.sublist(PP1RnftScriptGen.rabinPKHDataStart, PP1RnftScriptGen.rabinPKHDataEnd).toList();
    _flags = buf[PP1RnftScriptGen.flagsDataStart]; // only low byte used

    // Check for companion: if byte at scriptBodyStartNoCompanion is 0x20 (pushdata 32)
    if (buf.length > PP1RnftScriptGen.scriptBodyStartNoCompanion &&
        buf[PP1RnftScriptGen.scriptBodyStartNoCompanion] == 0x20) {
      _companionTokenId = buf.sublist(
          PP1RnftScriptGen.companionIdDataStart,
          PP1RnftScriptGen.companionIdDataEnd).toList();
    }
  }

  List<int>? get tokenId => _tokenId;
  Address? get recipientAddress => _recipientPKH;
  List<int>? get rabinPubKeyHash => _rabinPubKeyHash;
  int get flags => _flags;
  List<int>? get companionTokenId => _companionTokenId;
  bool get hasCompanion => _companionTokenId != null;
}
