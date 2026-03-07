import 'dart:convert';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:collection/collection.dart';

/// Builds an OP_FALSE OP_RETURN script following the B:// (Bitcoin Data) protocol.
///
/// B:// is used for on-chain data storage with fields for data, media type,
/// encoding, and an optional filename.
class BLockBuilder extends LockingScriptBuilder {

  /// The B:// protocol prefix address.
  String PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";

  /* https://github.com/unwriter/B
  OP_RETURN
  19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut
  [Data]
  [Media Type]
  [Encoding]
  [Filename]
   */

  /// The raw data bytes to store on-chain.
  List<int>? data;

  /// The MIME type of the data (e.g. "text/plain", "image/png").
  String? mediaType;

  /// The character encoding (e.g. "utf-8").
  String? encoding;

  /// An optional filename for the data.
  String? filename;

  /// Creates a B:// lock builder with the given data and metadata fields.
  BLockBuilder(this.data, this.mediaType, this.encoding, {this.filename});

  /// Reconstructs a [BLockBuilder] by parsing an existing B:// script.
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
