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

class PP2UnlockBuilder extends UnlockingScriptBuilder {

  final List<int> _outpointTxId;

  PP2UnlockBuilder(this._outpointTxId);

  @override
  SVScript getScriptSig() {
    return ScriptBuilder()
        .addData(Uint8List.fromList(_outpointTxId))
        .build();
  }

  @override
  void parse(SVScript script) {
    // TODO: implement parse
  }

}