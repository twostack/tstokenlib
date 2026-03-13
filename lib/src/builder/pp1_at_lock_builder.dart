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

import '../script_gen/pp1_at_script_gen.dart';

/// Builds the locking script for the PP1_AT (Appendable Token) output.
///
/// PP1_AT is a loyalty/stamp card token with dual authority (issuer + owner),
/// append-only rolling hash, and threshold-based redemption.
///
/// Header layout (118 bytes):
/// ```
/// Byte 0:        0x14 (pushdata 20)
/// Bytes 1-20:    ownerPKH (customer)
/// Byte 21:       0x20 (pushdata 32)
/// Bytes 22-53:   tokenId
/// Byte 54:       0x14 (pushdata 20)
/// Bytes 55-74:   issuerPKH (shop)
/// Byte 75:       0x04 (pushdata 4)
/// Bytes 76-79:   stampCount (4-byte LE)
/// Byte 80:       0x04 (pushdata 4)
/// Bytes 81-84:   threshold (4-byte LE)
/// Byte 85:       0x20 (pushdata 32)
/// Bytes 86-117:  stampsHash (rolling SHA256)
/// Byte 118:      start of script body
/// ```
class PP1AtLockBuilder extends LockingScriptBuilder {
  Address? _recipientAddress;
  List<int>? _tokenId;
  List<int>? _issuerPKH;
  int _stampCount;
  int _threshold;
  List<int>? _stampsHash;
  NetworkType? networkType;

  PP1AtLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST})
      : _stampCount = 0, _threshold = 0, super.fromScript(script);

  PP1AtLockBuilder(this._recipientAddress, this._tokenId, this._issuerPKH,
      this._stampCount, this._threshold, this._stampsHash, {this.networkType}) {
    if (_recipientAddress == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient address is required");
    }
    if (_tokenId == null || _tokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_issuerPKH == null || _issuerPKH!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Issuer PKH must be 20 bytes");
    }
    if (_stampsHash == null || _stampsHash!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Stamps hash must be 32 bytes");
    }
  }

  @override
  SVScript getScriptPubkey() {
    var ownerPKH = hex.decode(_recipientAddress!.pubkeyHash160);
    return PP1AtScriptGen.generate(
      ownerPKH: ownerPKH,
      tokenId: _tokenId!,
      issuerPKH: _issuerPKH!,
      stampCount: _stampCount,
      threshold: _threshold,
      stampsHash: _stampsHash!,
    );
  }

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    if (buf.length < PP1AtScriptGen.scriptBodyStart) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_AT");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _recipientAddress = Address.fromPubkeyHash(
        hex.encode(buf.sublist(PP1AtScriptGen.pkhDataStart, PP1AtScriptGen.pkhDataEnd).toList()),
        networkType ?? NetworkType.TEST);
    _tokenId = buf.sublist(PP1AtScriptGen.tokenIdDataStart, PP1AtScriptGen.tokenIdDataEnd).toList();
    _issuerPKH = buf.sublist(PP1AtScriptGen.issuerPKHDataStart, PP1AtScriptGen.issuerPKHDataEnd).toList();

    // stampCount: 4-byte LE at bytes 76-79
    var scBytes = buf.sublist(PP1AtScriptGen.stampCountDataStart, PP1AtScriptGen.stampCountDataEnd).toList();
    _stampCount = scBytes[0] | (scBytes[1] << 8) | (scBytes[2] << 16) | (scBytes[3] << 24);

    // threshold: 4-byte LE at bytes 81-84
    var thBytes = buf.sublist(PP1AtScriptGen.thresholdDataStart, PP1AtScriptGen.thresholdDataEnd).toList();
    _threshold = thBytes[0] | (thBytes[1] << 8) | (thBytes[2] << 16) | (thBytes[3] << 24);

    _stampsHash = buf.sublist(PP1AtScriptGen.stampsHashDataStart, PP1AtScriptGen.stampsHashDataEnd).toList();
  }

  List<int>? get tokenId => _tokenId;
  Address? get recipientAddress => _recipientAddress;
  List<int>? get issuerPKH => _issuerPKH;
  int get stampCount => _stampCount;
  int get threshold => _threshold;
  List<int>? get stampsHash => _stampsHash;
}
