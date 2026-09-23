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

import '../script_gen/pp1_sp_script_gen.dart';
import '../shielded_pool/pool_header.dart';

/// Builds the locking script for the PP1_SP (shielded pool) output.
///
/// Header layout (563 bytes):
/// ```
/// [0:1]     0x14       [1:21]    ownerPKH         (20,  mutable)
/// [21:22]   0x20       [22:54]   tokenId          (32,  immutable)
/// [54:55]   0x20       [55:87]   verifierBodyHash (32,  immutable)
/// [87:89]   0x4c 0xec  [89:325]  genesisHeader    (236, immutable)
/// [325:327] 0x4c 0xec  [327:563] header           (236, mutable) — see PoolHeader
/// [563:]    script body (immutable)
/// ```
///
/// The genesis header is carried in full rather than as a commitment, so a
/// script parsed off the chain is enough to regenerate the next round's and to
/// check what state the pool opened on.
class PP1SpLockBuilder extends LockingScriptBuilder {
  Address? _ownerAddress;
  List<int>? _tokenId;
  List<int>? _verifierBodyHash;
  PoolHeader? _header;
  List<int>? _genesisHeader;
  NetworkType? networkType;

  PP1SpLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST})
      : super.fromScript(script);

  PP1SpLockBuilder(
      this._ownerAddress,
      this._tokenId,
      this._verifierBodyHash,
      this._header,
      this._genesisHeader,
      {this.networkType}) {
    if (_ownerAddress == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner address is required");
    }
    if (_tokenId == null || _tokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_verifierBodyHash == null || _verifierBodyHash!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
          "Verifier body hash must be a 32-byte SHA256");
    }
    if (_header == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Pool header is required");
    }
    if (_genesisHeader == null || _genesisHeader!.length != PoolHeader.byteSize) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
          "Genesis header must be ${PoolHeader.byteSize} bytes");
    }
  }

  @override
  SVScript getScriptPubkey() {
    var ownerPKH = hex.decode(_ownerAddress!.pubkeyHash160);
    return PP1SpScriptGen.generate(
      ownerPKH: ownerPKH,
      tokenId: _tokenId!,
      verifierBodyHash: _verifierBodyHash!,
      header: _header!.encode(),
      genesisHeader: _genesisHeader!,
    );
  }

  /// Reads the five fields at their fixed offsets.
  ///
  /// **This is not a security boundary.** It checks the pushes it needs in
  /// order to read, and nothing about the script body — so it reads a script
  /// carrying a PP1's first [PP1SpScriptGen.scriptBodyStart] bytes over a body
  /// that spends on a signature exactly as it reads a real PP1_SP, and returns
  /// the forger's chosen tokenId, owner and header as though the chain had
  /// enforced them. The whole induction lives in the body.
  ///
  /// Use it to build, or on a script this side wrote. **A reader of chain data
  /// must go through [PoolEvidence.readPP1]**, which regenerates the script
  /// from the fields it parsed and requires every byte to match. A forged
  /// round built this way was broadcast and mined on localnet for the price of
  /// two ordinary transactions; see the design record, "The one-hop lineage
  /// claim, attacked".
  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    if (buf.length < PP1SpScriptGen.scriptBodyStart) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_SP");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }
    // A header is 236 bytes, past the 75-byte direct-push limit, so each push
    // is OP_PUSHDATA1 followed by the length.
    for (var at in [PP1SpScriptGen.genesisPushStart, PP1SpScriptGen.headerPushStart]) {
      if (buf[at] != 0x4c || buf[at + 1] != PoolHeader.byteSize) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
            "Expected OP_PUSHDATA1 ${PoolHeader.byteSize} at byte $at");
      }
    }

    _ownerAddress = Address.fromPubkeyHash(
        hex.encode(buf.sublist(PP1SpScriptGen.pkhDataStart, PP1SpScriptGen.pkhDataEnd).toList()),
        networkType ?? NetworkType.TEST);
    _tokenId = buf.sublist(PP1SpScriptGen.tokenIdDataStart, PP1SpScriptGen.tokenIdDataEnd).toList();
    _verifierBodyHash = buf
        .sublist(PP1SpScriptGen.verifierBodyHashDataStart,
            PP1SpScriptGen.verifierBodyHashDataEnd)
        .toList();
    _genesisHeader =
        buf.sublist(PP1SpScriptGen.genesisDataStart, PP1SpScriptGen.genesisDataEnd).toList();
    _header = PoolHeader.decode(
        buf.sublist(PP1SpScriptGen.headerDataStart, PP1SpScriptGen.headerDataEnd).toList());
  }

  Address? get ownerAddress => _ownerAddress;
  List<int>? get tokenId => _tokenId;
  List<int>? get verifierBodyHash => _verifierBodyHash;
  PoolHeader? get header => _header;
  List<int>? get genesisHeader => _genesisHeader;
}
