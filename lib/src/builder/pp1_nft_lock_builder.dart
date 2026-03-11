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

import '../script_gen/pp1_nft_script_gen.dart';

/// Builds the locking script for the PP1 output (index 1) of a token transaction.
///
/// PP1 is the inductive proof output. It proves by induction that the history
/// of token transfers has been performed correctly, providing double-spend
/// protection to the token.
///
/// Constructor Params:
///   recipientPKH - Address (pubkey hash) the token is locked to
///   tokenId - 32-byte unique token identifier
///   rabinPubKeyHash - 20-byte hash160 of the Rabin public key (identity anchor)
class PP1NftLockBuilder extends LockingScriptBuilder{

  Address? _recipientPKH;
  List<int>? _tokenId;
  List<int>? _rabinPubKeyHash;

  NetworkType? networkType;

  /// Reconstructs a [PP1NftLockBuilder] by parsing an existing script.
  PP1NftLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.TEST}) : super.fromScript(script);

  /// Creates a PP1 locking script builder.
  ///
  /// [_recipientPKH] - Address (pubkey hash) the token is locked to.
  /// [_tokenId] - 32-byte unique token ID (the TxID of the initial issuance funding input).
  /// [_rabinPubKeyHash] - 20-byte hash160 of the Rabin public key for identity anchoring.
  PP1NftLockBuilder(this._recipientPKH, this._tokenId, this._rabinPubKeyHash) {
    if (_recipientPKH == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient address is required for PP1 locking script");
    }
    if (_tokenId == null || _tokenId!.length != 32) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Token ID must be 32 bytes (transaction hash)");
    }
    if (_rabinPubKeyHash == null || _rabinPubKeyHash!.length != 20) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Rabin pubkey hash must be 20 bytes (hash160)");
    }
  }

  @override
  SVScript getScriptPubkey() {
    var recipientPKH = hex.decode(_recipientPKH?.address ?? "00");

    return PP1NftScriptGen.generate(
      ownerPKH: recipientPKH,
      tokenId: _tokenId!,
      rabinPubKeyHash: _rabinPubKeyHash!,
    );
  }


  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      // Hand-optimized script: chunks[0]=ownerPKH, [1]=tokenId, [2]=rabinPubKeyHash
      if (chunkList.length < 3) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for PP1 ScriptPubkey");
      }

      if (chunkList[0].len != 20) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Recipient Address has invalid length. Maybe not a PP1 script ? ");
      }

      if (chunkList[1].len != 32) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "TokenId has invalid length. Maybe not a PP1 script ? ");
      }

      if (chunkList[2].len != 20) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Rabin pubkey hash has invalid length. Maybe not a PP1 script ? ");
      }

      _tokenId = chunkList[1].buf;
      _rabinPubKeyHash = chunkList[2].buf;
      var addressBuf = chunkList[0].buf ?? [];
      _recipientPKH = Address.fromPubkeyHash(hex.encode(addressBuf), networkType ?? NetworkType.TEST );
    }
  }

 /// The 32-byte unique token identifier.
 List<int>? get tokenId => _tokenId;

 /// The address (pubkey hash) the token is locked to.
 Address? get recipientAddress => _recipientPKH;

 /// The 20-byte hash160 of the Rabin public key for identity anchoring.
 List<int>? get rabinPubKeyHash => _rabinPubKeyHash;

}
