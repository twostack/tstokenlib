import 'dart:convert';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:collection/collection.dart';

class BLockBuilder extends LockingScriptBuilder {

  String PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";

  /* https://github.com/unwriter/B
  OP_RETURN
  19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut
  [Data]
  [Media Type]
  [Encoding]
  [Filename]
   */

  List<int>? data;
  String? mediaType;
  String? encoding;
  String? filename;

  BLockBuilder(this.data, this.mediaType, this.encoding, {this.filename});

  BLockBuilder.fromScript(SVScript script){
    parse(script);
  }

  @override
  SVScript getScriptPubkey() {
    var builder = ScriptBuilder();

    builder
        .opFalse()
        .opCode(OpCodes.OP_RETURN)
        .addData(Uint8List.fromList(utf8.encode(PREFIX)))
        .addData(Uint8List.fromList(data ?? <int>[]))
        .addData(Uint8List.fromList(utf8.encode(mediaType ?? "")))
        .addData(Uint8List.fromList(utf8.encode(encoding ?? "")));

    if (filename != null) {
      builder.addData(Uint8List.fromList(utf8.encode(filename ?? "")));
    }

    return builder.build();
  }

  @override
  void parse(SVScript script) {

    //full length is 7, without the filename it's 6
    if (script == null || script.chunks.length < 6) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Not a valid B protocol script");
    }

    var chunks = script.chunks;

    if (chunks[0].opcodenum != OpCodes.OP_FALSE || chunks[1].opcodenum != OpCodes.OP_RETURN){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script MUST start with [OP_FALSE OP_RETURN]");
    }

    Function eq = const ListEquality().equals;

    if (!eq(chunks[2].buf, utf8.encode(PREFIX))){
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Prefix does not match the MAP protocol prefix of : [$PREFIX] ");
    }

    //get the mediaType
    data = chunks[3].buf;
    mediaType = utf8.decode(chunks[4].buf ?? []);
    encoding = utf8.decode(chunks[5].buf ?? []);

    //grab the optional filename
    if (chunks.length == 7) {
      filename = utf8.decode(chunks[6].buf ?? []);
    }

  }

}
