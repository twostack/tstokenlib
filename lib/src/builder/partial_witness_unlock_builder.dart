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

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

class PartialWitnessUnlockBuilder extends UnlockingScriptBuilder {

  final List<int> _preImage;
  final List<int> _partialHash;
  final List<int> _partialWitnessPreImage;
  final List<int> _fundingTxId;


  PartialWitnessUnlockBuilder(this._preImage, this._partialHash, this._partialWitnessPreImage, this._fundingTxId);

  @override
  SVScript getScriptSig() {

    var builder = ScriptBuilder()
        .addData(Uint8List.fromList(_preImage))
        .addData(Uint8List.fromList(_partialHash))
        .addData(Uint8List.fromList(_partialWitnessPreImage))
        .addData(Uint8List.fromList(_fundingTxId));

    var result = builder.build();
    return result;
  }

  @override
  void parse(SVScript script) {
    // TODO: implement parse
  }

}