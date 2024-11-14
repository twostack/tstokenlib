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

import 'package:dartsv/dartsv.dart';
import 'package:convert/convert.dart';

/* Data Size Calculations
The following space calculation is for the spending
scriptSig that would match this template.

| Input Fields                         | size (bytes)
|--------------------------------------| ----------
| TxId of Parent Txn                   | 32 bytes
| outputIndex in Parent Txn            | 4 bytes  (uint32)
| length of the script in next field   | 2 bytes (varint)
| scriptSig                            | 32 bytes (push txid )
| sequence number                      | 4 bytes (uint32

Txn Input => 32 + 4 + 2 + 32 + 4 = 74
Txn Output => 35
Total : 109 bytes (still short of the 128 byte limit)

0014650c4adb156f19e36a755c820d892cda108299c4775279a97888785379ac777777 => 35 bytes (this template)
76a914650c4adb156f19e36a755c820d892cda108299c488ac ==> 25 bytes (basic P2PKH template)
 */

/*
Modified P2PKH Locking script builder.
 */
class ModP2PKHLockBuilder extends LockingScriptBuilder {

  Address? address;
  List<int>? pubkeyHash;
  NetworkType? networkType;

  ModP2PKHLockBuilder.fromAddress(Address address){
    this.address = address;
    this.networkType = address.networkType;
    pubkeyHash = hex.decode(address.pubkeyHash160);
  }

  ModP2PKHLockBuilder.fromPublicKey(SVPublicKey publicKey, {this.networkType = NetworkType.MAIN}){
    this.address = publicKey.toAddress(networkType ?? NetworkType.MAIN);
    pubkeyHash = hex.decode(address!.pubkeyHash160);
  }

  ModP2PKHLockBuilder.fromScript(SVScript script, {this.networkType = NetworkType.MAIN}) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {

    if (this.pubkeyHash == null){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,"Missing pubkey hash value");
    }

    var builder = ScriptBuilder()
        .opCode(OpCodes.OP_SWAP)
        .opCode(OpCodes.OP_DUP)
        .opCode(OpCodes.OP_HASH160)
        .addData(Uint8List.fromList(pubkeyHash!))
        .opCode(OpCodes.OP_EQUALVERIFY)
        .opCode(OpCodes.OP_CHECKSIG);

    return builder.build();

  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 6) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptPubkey");
      }

      if (chunkList[3].len != 20) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Signature and Public Key values are malformed");
      }

      if (!(chunkList[0].opcodenum == OpCodes.OP_SWAP &&
          chunkList[1].opcodenum == OpCodes.OP_DUP &&
          chunkList[2].opcodenum == OpCodes.OP_HASH160 &&
          chunkList[4].opcodenum == OpCodes.OP_EQUALVERIFY &&
          chunkList[5].opcodenum == OpCodes.OP_CHECKSIG)) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Malformed P2PKH ScriptPubkey script. Mismatched OP_CODES.");
      }

      pubkeyHash = chunkList[3].buf;
      address = Address.fromPubkeyHash(hex.encode(pubkeyHash ?? []), networkType ?? NetworkType.MAIN);
    }
  }

}

class ModP2PKHUnlockBuilder extends UnlockingScriptBuilder {

  SVPublicKey? signerPubkey;

  ModP2PKHUnlockBuilder.fromScript(SVScript script) : super.fromScript(script);

  ModP2PKHUnlockBuilder(this.signerPubkey);

  @override
  SVScript getScriptSig() {
    if (signatures == null || signatures.isEmpty || signerPubkey == null) return SVScript();

    var signature = signatures[0];
    var sigBuffer = Uint8List.fromList(hex.decode(signature.toTxFormat()));
    var pkBuffer = Uint8List.fromList(hex.decode(signerPubkey!.toHex()));

    return ScriptBuilder()
        .addData(pkBuffer)
        .addData(sigBuffer)
        .build();
  }

  @override
  void parse(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 2) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptSig");
      }

      var sig = chunkList[1].buf;
      var pubKey = chunkList[0].buf;

      if (sig == null || pubKey == null){
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Either one of Signature of Pubkey was not provided (null value)");
      }

      signerPubkey = SVPublicKey.fromHex(hex.encode(pubKey));
      signatures.add(SVSignature.fromTxFormat(hex.encode(sig)));
    } else {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
    }
  }

  SVScript get scriptSig => getScriptSig();
}