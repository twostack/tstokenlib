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

import '../script_gen/pp1_sm_script_gen.dart';

/// Builds the locking script for the PP1_SM (State Machine Token) output.
///
/// Header layout (140 bytes):
/// ```
/// [0:1]     0x14  [1:21]    ownerPKH (mutable — "next expected actor")
/// [21:22]   0x20  [22:54]   tokenId (immutable)
/// [54:55]   0x14  [55:75]   merchantPKH (immutable)
/// [75:76]   0x14  [76:96]   customerPKH (immutable)
/// [96:97]   0x01  [97:98]   currentState (mutable — 0x00-0x05)
/// [98:99]   0x01  [99:100]  milestoneCount (mutable)
/// [100:101] 0x20  [101:133] commitmentHash (mutable — rolling SHA256)
/// [133:134] 0x01  [134:135] transitionBitmask (immutable)
/// [135:136] 0x04  [136:140] timeoutDelta (immutable — 4-byte LE)
/// [140:]    script body (immutable)
/// ```
class PP1SmLockBuilder extends LockingScriptBuilder {
  Address? _ownerAddress;
  List<int>? _tokenId;
  List<int>? _merchantPKH;
  List<int>? _customerPKH;
  List<int>? _rabinPubKeyHash;
  int _currentState;
  int _milestoneCount;
  List<int>? _commitmentHash;
  int _transitionBitmask;
  int _timeoutDelta;
  NetworkType? networkType;

  PP1SmLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST})
      : _currentState = 0, _milestoneCount = 0, _transitionBitmask = 0,
        _timeoutDelta = 0, super.fromScript(script);

  PP1SmLockBuilder(
      this._ownerAddress,
      this._tokenId,
      this._merchantPKH,
      this._customerPKH,
      this._rabinPubKeyHash,
      this._currentState,
      this._milestoneCount,
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
    if (_merchantPKH == null || _merchantPKH!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Merchant PKH must be 20 bytes");
    }
    if (_customerPKH == null || _customerPKH!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Customer PKH must be 20 bytes");
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
    return PP1SmScriptGen.generate(
      ownerPKH: ownerPKH,
      tokenId: _tokenId!,
      merchantPKH: _merchantPKH!,
      customerPKH: _customerPKH!,
      rabinPubKeyHash: _rabinPubKeyHash!,
      currentState: _currentState,
      milestoneCount: _milestoneCount,
      commitmentHash: _commitmentHash!,
      transitionBitmask: _transitionBitmask,
      timeoutDelta: _timeoutDelta,
    );
  }

  @override
  void parse(SVScript script) {
    var buf = script.buffer;

    if (buf.length < PP1SmScriptGen.scriptBodyStart) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script too short for PP1_SM");
    }
    if (buf[0] != 0x14) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Expected 0x14 pushdata at byte 0");
    }

    _ownerAddress = Address.fromPubkeyHash(
        hex.encode(buf.sublist(PP1SmScriptGen.pkhDataStart, PP1SmScriptGen.pkhDataEnd).toList()),
        networkType ?? NetworkType.TEST);
    _tokenId = buf.sublist(PP1SmScriptGen.tokenIdDataStart, PP1SmScriptGen.tokenIdDataEnd).toList();
    _merchantPKH = buf.sublist(PP1SmScriptGen.merchantPKHDataStart, PP1SmScriptGen.merchantPKHDataEnd).toList();
    _customerPKH = buf.sublist(PP1SmScriptGen.customerPKHDataStart, PP1SmScriptGen.customerPKHDataEnd).toList();
    _rabinPubKeyHash = buf.sublist(PP1SmScriptGen.rabinPKHDataStart, PP1SmScriptGen.rabinPKHDataEnd).toList();
    _currentState = buf[PP1SmScriptGen.currentStateDataStart];
    _milestoneCount = buf[PP1SmScriptGen.milestoneCountDataStart];
    _commitmentHash = buf.sublist(PP1SmScriptGen.commitmentHashDataStart, PP1SmScriptGen.commitmentHashDataEnd).toList();
    _transitionBitmask = buf[PP1SmScriptGen.transitionBitmaskDataStart];

    var tdBytes = buf.sublist(PP1SmScriptGen.timeoutDeltaDataStart, PP1SmScriptGen.timeoutDeltaDataEnd).toList();
    _timeoutDelta = tdBytes[0] | (tdBytes[1] << 8) | (tdBytes[2] << 16) | (tdBytes[3] << 24);
  }

  Address? get ownerAddress => _ownerAddress;
  List<int>? get tokenId => _tokenId;
  List<int>? get merchantPKH => _merchantPKH;
  List<int>? get customerPKH => _customerPKH;
  List<int>? get rabinPubKeyHash => _rabinPubKeyHash;
  int get currentState => _currentState;
  int get milestoneCount => _milestoneCount;
  List<int>? get commitmentHash => _commitmentHash;
  int get transitionBitmask => _transitionBitmask;
  int get timeoutDelta => _timeoutDelta;
}
