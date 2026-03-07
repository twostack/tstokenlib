

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:collection/collection.dart';


class AIPLockBuilder extends LockingScriptBuilder {

  /*
 OP_RETURN
  19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut
  [Data]
  [Media Type]
  [Encoding]
  [Filename]
  |
  15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva
  [Signing Algorithm]
  [Signing Address]
  [Signature]
  [Field Index 0] // Optional. 0 based index means the OP_RETURN (0x6a) is signed itself
  [Field Index 1] // Optional.
    ...           // If the Field Indexes are omitted, then it's assumed that all fields to the left of the AUTHOR_IDENTITY prefix are signed.

   */

  final String PREFIX = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";
  String? SIGNING_ALGORITHM;
  String? publicKey;
  String? signature;

  AIPLockBuilder(this.publicKey, this.signature, {this.SIGNING_ALGORITHM = "ED25519"});

  AIPLockBuilder.fromScript(SVScript svScript) {
    parse(svScript);
  }

  @override
  SVScript getScriptPubkey() {

    if (publicKey == null || signature == null || SIGNING_ALGORITHM == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Missing public key or signature");
    }

    var builder = ScriptBuilder();

    builder
        .opFalse()
        .opCode(OpCodes.OP_RETURN)
        .addData(Uint8List.fromList(utf8.encode(PREFIX)))
        .addData(Uint8List.fromList(utf8.encode(SIGNING_ALGORITHM!)))
        .addData(Uint8List.fromList(hex.decode(publicKey!)))
        .addData(Uint8List.fromList(base64Decode(signature!)));

      return builder.build();
    }


  @override
  void parse(SVScript script) {

    //full length is 7, without the filename it's 6
    if (script == null || script.chunks.length < 6) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Not a valid AIP protocol script");
    }

    var chunks = script.chunks;

    if (chunks[0].opcodenum != OpCodes.OP_FALSE || chunks[1].opcodenum != OpCodes.OP_RETURN){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script MUST start with [OP_FALSE OP_RETURN]");
    }

    Function eq = const ListEquality().equals;

    if (!eq(chunks[2].buf, utf8.encode(PREFIX))){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Prefix does not match the MAP protocol prefix of : [$PREFIX] ");
    }

    SIGNING_ALGORITHM = hex.encode(chunks[3].buf ?? []);
    publicKey = hex.encode(chunks[4].buf ?? []);
    signature = hex.encode(chunks[5].buf ?? []);

  }

  static Future<AIPLockBuilder?> signLockingScript(LockingScriptBuilder locker, SignatureWand? wand) async {

    if (wand == null) return null;

    var builder = ScriptBuilder.fromScript(locker.getScriptPubkey());
    builder.addData(Uint8List.fromList(utf8.encode("|"))); //append pipe

    var signatureScript = builder.build();
    var message = signatureScript.toHex();

    var signature = await wand.sign(hex.decode(message));
    SimplePublicKey pubkey = (await wand.extractPublicKeyUsedForSignatures() as SimplePublicKey);

    var b64Sig = base64Encode(signature.bytes);
    var pubkeyHex = hex.encode(pubkey.bytes);

    return AIPLockBuilder(pubkeyHex, b64Sig);

  }


}