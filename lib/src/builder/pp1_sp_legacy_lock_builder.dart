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

import 'package:dartsv/dartsv.dart';
import '../script_gen/pp1_sp_legacy_script_gen.dart';

/// Locking-script builder for the PP1_SP (shielded pool) state output.
///
/// The header ([PP1SpLegacyHeader], 226 bytes of pushes) is followed by the body
/// [PP1SpLegacyScriptGen.body], which depends on the STARK parameters and the
/// round size K and bakes in the hashes of the two slot scripts. Parsing a
/// script recovers the header; regenerating needs the generator.
class PP1SpLegacyLockBuilder extends LockingScriptBuilder {
  PP1SpLegacyScriptGen? _gen;
  PP1SpLegacyHeader? _header;

  PP1SpLegacyLockBuilder(PP1SpLegacyScriptGen gen, PP1SpLegacyHeader header)
      : _gen = gen,
        _header = header;

  PP1SpLegacyLockBuilder.fromScript(SVScript script) : super.fromScript(script);

  @override
  SVScript getScriptPubkey() {
    if (_gen != null) return _gen!.lock(_header!);
    return script!; // parsed from a script: hand it back unchanged
  }

  @override
  void parse(SVScript script) {
    final buf = script.buffer;
    if (buf.length < PP1SpLegacyHeader.bytesTotal) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, 'Script too short for PP1_SP');
    }
    _header = PP1SpLegacyHeader.parse(buf);
  }

  PP1SpLegacyHeader get header => _header!;

  /// The body after the header, as parsed.
  List<int> get body => script!.buffer.sublist(PP1SpLegacyHeader.bytesTotal);
}

/// Locking-script builder for a slot output (verifier or append): a constant
/// script per pool version.
class PP1SpLegacySlotLockBuilder extends LockingScriptBuilder {
  final SVScript _script;
  PP1SpLegacySlotLockBuilder(this._script);

  @override
  SVScript getScriptPubkey() => _script;

  @override
  void parse(SVScript script) {}
}
