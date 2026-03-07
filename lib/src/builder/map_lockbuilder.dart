import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dartsv/dartsv.dart';

/// Builds an OP_FALSE OP_RETURN script following the Magic Attribute Protocol (MAP).
///
/// MAP stores key-value metadata on-chain using SET or DELETE operations.
class MapLockBuilder extends LockingScriptBuilder {

  /// The MAP protocol prefix address.
  final String PREFIX = "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5";

  Function eq = const ListEquality().equals;
  /* https://github.com/rohenaz/map
  <OP_RETURN | <input>>
  MAP
  <SET | DELETE>
  <key>
  <value>
   */
  /// The key-value pairs to store on-chain.
  Map<String, dynamic> map = {};

  /// Creates a MAP lock builder from an existing key-value [map].
  MapLockBuilder.fromMap(this.map);

  /// Reconstructs a [MapLockBuilder] by parsing an existing MAP script.
  MapLockBuilder.fromScript(SVScript script){
   parse(script);
  }

  @override
  SVScript getScriptPubkey() {

    ScriptBuilder builder = ScriptBuilder();
    builder
        .opFalse()
        .opCode(OpCodes.OP_RETURN)
        // .addData(Uint8List.fromList(utf8.encode("|")))
        .addData(Uint8List.fromList(utf8.encode(PREFIX)))
        .addData(Uint8List.fromList(utf8.encode("SET")));
        // .addData(Uint8List.fromList(utf8.encode("DELETE")));

    map.forEach((key, value) {
     builder.addData(Uint8List.fromList(utf8.encode(key)));
     builder.addData(Uint8List.fromList(utf8.encode(value)));
    });


    return builder.build();
  }

  @override
  void parse(SVScript script) {

      if (script == null || script.chunks.length < 4) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Not a valid MAP protocol script");
      }

      var chunks = script.chunks;

      if (chunks[0].opcodenum != OpCodes.OP_FALSE || chunks[1].opcodenum != OpCodes.OP_RETURN){
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script MUST start with [OP_FALSE OP_RETURN]");
      }

      Function eq = const ListEquality().equals;

      if (!eq(chunks[2].buf, utf8.encode(PREFIX))){
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Prefix does not match the MAP protocol prefix of : [1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5] ");
      }

      var pipeChunk = Uint8List.fromList(utf8.encode("|"));
      var pipeIndex = chunks.indexWhere((element) => eq(element.buf, pipeChunk));

      List mapSlice;
      if (pipeIndex == -1) {
        mapSlice = chunks.sublist(4, chunks.length);
      }else{
        mapSlice = chunks.sublist(4, pipeIndex);
      }

      if (mapSlice.length % 2 != 0) {
        throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unmatched/unbalanced map entries. Data structure cannot be parsed.");
      }

      for (var index = 0; index < mapSlice.length - 1; index = index + 2) {
        map[utf8.decode(mapSlice[index].buf ?? [])] = utf8.decode(mapSlice[index + 1].buf ?? []);
      }

  }


  /// Appends another [LockingScriptBuilder]'s output as a new pipe-delimited section.
  SVScript appendLocker(LockingScriptBuilder lockingScript){

    var mapScript = getScriptPubkey();

    var appendBuilder = ScriptBuilder.fromScript(mapScript);

    //add pipe to additional section
    appendBuilder.addData(Uint8List.fromList(utf8.encode("|")));

    var additionalSection = lockingScript.getScriptPubkey();

    //remove first two chunks (assumed to be OP_FALSe / OP_RETURN)
    if (additionalSection.chunks[0].opcodenum == OpCodes.OP_FALSE){
      additionalSection.chunks.removeAt(0);
    }

    if (additionalSection.chunks[0].opcodenum == OpCodes.OP_RETURN){
      additionalSection.chunks.removeAt(0);
    }

    //concat map script to bLock script
    for (ScriptChunk chunk in additionalSection.chunks){
      appendBuilder.addChunk(chunk);
    }

    return appendBuilder.build();

  }


}