import 'dart:convert';
import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:collection/collection.dart';

import 'aip_lockbuilder.dart';
import 'b_lockbuilder.dart';
import 'map_lockbuilder.dart';

/// Identifies which pipe-delimited section of a BMAP script is being parsed.
enum ChunkSection{
  /// The B:// data section.
  BCHUNK,
  /// The MAP metadata section.
  MAPCHUNK,
  /// The AIP identity/signature section.
  AIPCHUNK
}

/// Builds a composite OP_RETURN script combining B://, MAP, and optionally AIP protocols.
///
/// The BMAP format concatenates B:// data, MAP metadata, and AIP identity sections
/// separated by pipe (`|`) delimiters within a single OP_RETURN output.
class BmapLockBuilder extends LockingScriptBuilder {

  /// The raw B:// data bytes.
  List<int>? data;

  /// The MIME type of the B:// data.
  String? mediaType;

  /// The character encoding of the B:// data.
  String? encoding;

  /// An optional filename for the B:// data.
  String? filename;

  /// Key-value pairs for the MAP metadata section.
  Map<String, dynamic> map = {};

  /// The AIP signature (base64-encoded), or null if no AIP section.
  String? authorSignature;

  /// The AIP public key (hex-encoded), or null if no AIP section.
  String? authorPublicKey;

  /// The AIP signing algorithm (defaults to "ED25519").
  String? authorAlgorithm = "ED25519";

  Function eq = const ListEquality().equals;

  /// Reconstructs a [BmapLockBuilder] by parsing an existing BMAP script.
  BmapLockBuilder.fromScript(SVScript script){
    parse(script);
  }

  /// Creates a BMAP lock builder by composing B:// and MAP data.
  BmapLockBuilder(BLockBuilder bLocker, MapLockBuilder mapLocker){
    data = bLocker.data;
    mediaType = bLocker.mediaType;
    encoding = bLocker.encoding;
    filename = bLocker.filename;

    map = mapLocker.map;
  }

  @override
  SVScript getScriptPubkey() {
    var bLocker = BLockBuilder(data, mediaType, encoding, filename: filename);
    var mapLocker = MapLockBuilder.fromMap(map);

    var bLockScript = bLocker.getScriptPubkey();
    var bLockBuilder = ScriptBuilder.fromScript(bLockScript);

    //add pipe to B script
    bLockBuilder.addData(Uint8List.fromList(utf8.encode("|")));

    //strip [op_false op_return] from mapLockScript
    var mapLockScript = mapLocker.getScriptPubkey();
    mapLockScript.chunks.removeRange(0, 2);

    //concat map script to bLock script
    for (ScriptChunk chunk in mapLockScript.chunks){
      bLockBuilder.addChunk(chunk);
    }

    //concat AIP script to map script if we have data
    if ((authorPublicKey?.isNotEmpty ?? false) && (authorSignature?.isNotEmpty ?? false)) {
      var aipLocker = AIPLockBuilder(authorPublicKey, authorSignature, SIGNING_ALGORITHM: authorAlgorithm);
      var aipScript = aipLocker.getScriptPubkey();
      if (aipScript.chunks[0].opcodenum == OpCodes.OP_FALSE){
        aipScript.chunks.removeAt(0);
      }

      if (aipScript.chunks[0].opcodenum == OpCodes.OP_RETURN){
        aipScript.chunks.removeAt(0);
      }
      //add pipe behind MAP data
      bLockBuilder.addData(Uint8List.fromList(utf8.encode("|")));
      for (ScriptChunk chunk in aipScript.chunks) {
        bLockBuilder.addChunk(chunk);
      }
    }

    return bLockBuilder.build();
  }


  @override
  void parse(SVScript script) {

    var pipeScript= ScriptBuilder().addData(Uint8List.fromList(utf8.encode("|"))).build();
    //split along pipes
    var pipeChunk = pipeScript.chunks[0];

    var bLockChunks = <ScriptChunk>[];
    var mapChunks = <ScriptChunk>[];
    var aipChunks = <ScriptChunk>[];

    var currentChunk = ChunkSection.BCHUNK;
    for (ScriptChunk chunk in script.chunks) {
      if (currentChunk == ChunkSection.BCHUNK){
        if (!eq(chunk.buf, pipeChunk.buf)) {
          bLockChunks.add(chunk);
        }
      }else if (currentChunk == ChunkSection.MAPCHUNK){
        if (!eq(chunk.buf, pipeChunk.buf)) {
          mapChunks.add(chunk);
        }
      }else if (currentChunk == ChunkSection.AIPCHUNK){
        if (!eq(chunk.buf, pipeChunk.buf)) {
          aipChunks.add(chunk);
        }
      }

      if (eq(chunk.buf, pipeChunk.buf)){
        //transition to scanning next section
        switch (currentChunk){
          case  ChunkSection.BCHUNK: currentChunk = ChunkSection.MAPCHUNK; break;
          case  ChunkSection.MAPCHUNK: currentChunk = ChunkSection.AIPCHUNK; break;
          default:
            break;
        }
      }
    }

    //parse the bLock data
    //reconstruct our bLocker so B checks can be performed
    var bLockScript = SVScript.fromChunks(bLockChunks);
    var bLocker = BLockBuilder.fromScript(bLockScript);
    data = bLocker.data;
    mediaType = bLocker.mediaType;
    encoding = bLocker.encoding;
    filename = bLocker.filename;

    //parse the MAP data
    var mapScript = SVScript.fromChunks(mapChunks);

    //add back [op_false op_return]
    var falseReturnScript = ScriptBuilder().opFalse().opCode(OpCodes.OP_RETURN).build();
    falseReturnScript.chunks.addAll(mapScript.chunks);

    //reconstruct our mapLocker so MAP checks can be performed
    var mapLocker = MapLockBuilder.fromScript(falseReturnScript);

    map = mapLocker.map;

    if (aipChunks.isNotEmpty) {
      var aipScript = SVScript.fromChunks(aipChunks);
      //recreate the false/return script
      falseReturnScript = ScriptBuilder().opFalse().opCode(OpCodes.OP_RETURN).build();
      falseReturnScript.chunks.addAll(aipScript.chunks);

      //setup AIP locker
      var aipLocker = AIPLockBuilder.fromScript(falseReturnScript);

      authorAlgorithm = aipLocker.SIGNING_ALGORITHM;
      authorSignature = aipLocker.signature;
      authorPublicKey = aipLocker.publicKey;
    }
  }



  /// Appends another [LockingScriptBuilder]'s output as a new pipe-delimited section.
  SVScript appendLocker(LockingScriptBuilder lockingScript){

    var bmapScript = getScriptPubkey();

    var appendBuilder = ScriptBuilder.fromScript(bmapScript);

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