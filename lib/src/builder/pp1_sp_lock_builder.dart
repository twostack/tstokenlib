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

/// Builds the locking script for the PP1_SP (State Machine Token) output.
///
/// Header layout (140 bytes):
/// ```
/// [0:1]     0x14  [1:21]    ownerPKH (mutable — "next expected actor")
/// [21:22]   0x20  [22:54]   tokenId (immutable)
/// [54:55]   0x14  [55:75]   operatorPKH (immutable)
/// [75:76]   0x14  [76:96]   counterpartyPKH (immutable)
/// [96:97]   0x01  [97:98]   currentState (mutable — 0x00-0x05)
/// [98:99]   0x01  [99:100]  checkpointCount (mutable)
/// [100:101] 0x20  [101:133] commitmentHash (mutable — rolling SHA256)
/// [133:134] 0x01  [134:135] transitionBitmask (immutable)
/// [135:136] 0x04  [136:140] timeoutDelta (immutable — 4-byte LE)
/// [140:]    script body (immutable)
/// ```
class PP1SpLockBuilder extends LockingScriptBuilder {
  Address? _ownerAddress;
  List<int>? _tokenId;
  List<int>? _operatorPKH;
  List<int>? _counterpartyPKH;
  List<int>? _rabinPubKeyHash;
  int _currentState;
  int _checkpointCount;
  List<int>? _commitmentHash;
  int _transitionBitmask;
  int _timeoutDelta;
  NetworkType? networkType;

  PP1SpLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST})
      : _currentState = 0, _checkpointCount = 0, _transitionBitmask = 0,
        _timeoutDelta = 0, super.fromScript(script);

  PP1SpLockBuilder(
      this._ownerAddress,
      this._tokenId,
      this._operatorPKH,
      this._counterpartyPKH,
      this._rabinPubKeyHash,
      this._currentState,
      this._checkpointCount,
      this._commitmentHash,
      this._transitionBitmask,
      this._timeoutDelta,
      {this.networkType}) {
    if (_ownerAddress == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Owner address is required");
    }
    if (_tokenId == null || _tokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes");
    }
    if (_operatorPKH == null || _operatorPKH!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Operator PKH must be 20 bytes");
    }
    if (_counterpartyPKH == null || _counterpartyPKH!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Counterparty PKH must be 20 bytes");
    }
    if (_rabinPubKeyHash == null || _rabinPubKeyHash!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Rabin pubkey hash must be 20 bytes");
    }
    if (_commitmentHash == null || _commitmentHash!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Commitment hash must be 32 bytes");
    }
  }

  @override
  SVScript getScriptPubkey() {
    var ownerPKH = hex.decode(_ownerAddress!.pubkeyHash160);
    return PP1SpScriptGen.generate(
      ownerPKH: ownerPKH,
      tokenId: _tokenId!,
      operatorPKH: _operatorPKH!,
      counterpartyPKH: _counterpartyPKH!,
      rabinPubKeyHash: _rabinPubKeyHash!,
      currentState: _currentState,
      checkpointCount: _checkpointCount,
      commitmentHash: _commitmentHash!,
      transitionBitmask: _transitionBitmask,
      timeoutDelta: _timeoutDelta,
    );
  }

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    if (buf.length < PP1SpScriptGen.scriptBodyStart) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_SP");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _ownerAddress = Address.fromPubkeyHash(
        hex.encode(buf.sublist(PP1SpScriptGen.pkhDataStart, PP1SpScriptGen.pkhDataEnd).toList()),
        networkType ?? NetworkType.TEST);
    _tokenId = buf.sublist(PP1SpScriptGen.tokenIdDataStart, PP1SpScriptGen.tokenIdDataEnd).toList();
    _operatorPKH = buf.sublist(PP1SpScriptGen.operatorPKHDataStart, PP1SpScriptGen.operatorPKHDataEnd).toList();
    _counterpartyPKH = buf.sublist(PP1SpScriptGen.counterpartyPKHDataStart, PP1SpScriptGen.counterpartyPKHDataEnd).toList();
    _rabinPubKeyHash = buf.sublist(PP1SpScriptGen.rabinPKHDataStart, PP1SpScriptGen.rabinPKHDataEnd).toList();
    _currentState = buf[PP1SpScriptGen.currentStateDataStart];
    _checkpointCount = buf[PP1SpScriptGen.checkpointCountDataStart];
    _commitmentHash = buf.sublist(PP1SpScriptGen.commitmentHashDataStart, PP1SpScriptGen.commitmentHashDataEnd).toList();
    _transitionBitmask = buf[PP1SpScriptGen.transitionBitmaskDataStart];

    var tdBytes = buf.sublist(PP1SpScriptGen.timeoutDeltaDataStart, PP1SpScriptGen.timeoutDeltaDataEnd).toList();
    _timeoutDelta = tdBytes[0] | (tdBytes[1] << 8) | (tdBytes[2] << 16) | (tdBytes[3] << 24);
  }

  Address? get ownerAddress => _ownerAddress;
  List<int>? get tokenId => _tokenId;
  List<int>? get operatorPKH => _operatorPKH;
  List<int>? get counterpartyPKH => _counterpartyPKH;
  List<int>? get rabinPubKeyHash => _rabinPubKeyHash;
  int get currentState => _currentState;
  int get checkpointCount => _checkpointCount;
  List<int>? get commitmentHash => _commitmentHash;
  int get transitionBitmask => _transitionBitmask;
  int get timeoutDelta => _timeoutDelta;
}
