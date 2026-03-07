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

/// Builds an OP_FALSE OP_RETURN metadata output for token transactions.
/// The script starts with 0x00 0x6a (OP_FALSE OP_RETURN) followed by optional data pushes.
class MetadataLockBuilder extends LockingScriptBuilder {

  List<int>? _metadataBytes;

  /// Creates a metadata output with optional raw metadata bytes.
  /// If no metadata is provided, creates a bare OP_FALSE OP_RETURN script.
  MetadataLockBuilder({List<int>? metadataBytes}) : _metadataBytes = metadataBytes;

  /// Reconstructs a [MetadataLockBuilder] by parsing an existing OP_RETURN script.
  MetadataLockBuilder.fromScript(SVScript script) {
    parse(script);
  }

  /// The raw metadata bytes, or null if this is a bare OP_FALSE OP_RETURN.
  List<int>? get metadataBytes => _metadataBytes;

  @override
  SVScript getScriptPubkey() {
    var builder = ScriptBuilder()
        .opFalse()
        .opCode(OpCodes.OP_RETURN);

    if (_metadataBytes != null && _metadataBytes!.isNotEmpty) {
      builder.addData(Uint8List.fromList(_metadataBytes!));
    }

    return builder.build();
  }

  @override
  void parse(SVScript script) {
    var chunks = script.chunks;

    if (chunks.length < 2 ||
        chunks[0].opcodenum != OpCodes.OP_FALSE ||
        chunks[1].opcodenum != OpCodes.OP_RETURN) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
          "Not a valid metadata OP_RETURN script");
    }

    if (chunks.length > 2) {
      _metadataBytes = chunks[2].buf;
    }
  }
}
