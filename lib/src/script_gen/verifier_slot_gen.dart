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
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import '../crypto/stark_prover_ref.dart';
import 'air.dart';
import 'm31_script_gen.dart';
import 'pool_spend_air.dart';
import 'slot_script_common.dart';
import 'stark_verifier_gen.dart';

/// The PP1_SP verifier slot: a stateless, single-use sibling of the pool
/// state that verifies one spend proof and publishes the publics it verified.
///
/// Two paths, chosen by the selector on top of the unlocking script:
///   1 (proof): the STARK verifier runs on `[publics, proof, preimage,
///     prevoutsTail]`; the result output is `OP_RETURN SHA256(publics)`.
///   0 (skip): an unused slot; the result output is `OP_RETURN` alone.
/// Either way the slot signs SIGHASH_SINGLE over its own output index and
/// requires the state to be input 0 of the same parent, so a slot is spent
/// exactly once, in the state's round, and the state reads the result it
/// rebuilt itself.
class VerifierSlotGen {
  final StarkParams P;
  late final StarkVerifierGen _gen;
  SVScript? _lock;

  VerifierSlotGen(this.P) {
    _gen = StarkVerifierGen(P, PoolSpendAir.air(PoolPublicInputs.zero()))
      ..unlockAbove = const ['preimage', 'prevoutsTail']
      ..prologue = (e) {
        _bind(e, withPublics: true);
      }
      ..epilogue = (e) {
        e.dropAllExcept(['sig']);
      };
  }

  static Uint8List publicsHash(List<int> lanes) =>
      Uint8List.fromList(crypto.sha256.convert(SlotScript.lanesBytes(lanes)).bytes);

  static Uint8List resultOutput(List<int> publicLanes) => SlotScript.resultOutput32(publicsHash(publicLanes));
  static Uint8List emptyResultOutput() => SlotScript.emptyResultOutput();

  /// The result output, then the checks and the signature, leaving `sig`.
  void _bind(StackEmitter e, {required bool withPublics}) {
    if (withPublics) {
      SlotScript.lanesToBytes(e, [for (int k = 0; k < PoolPublicInputs.count; k++) Air.publicName(k)], as: 'pb');
      SlotScript.op(e, OpCodes.OP_SHA256, pops: 1, pushes: 1);
      e.pushData([...List.filled(8, 0), 34, OpCodes.OP_RETURN, 32]);
      e.swap();
      SlotScript.cat(e, as: 'out');
    } else {
      e.pushData([...List.filled(8, 0), 1, OpCodes.OP_RETURN], as: 'out');
    }
    SlotScript.emitPreimageFields(e, 'preimage');
    e.roll('out');
    SlotScript.emitOutputBound(e);
    SlotScript.emitStateCoSpent(e, 'prevoutsTail');
    e.roll('preimage');
    SlotScript.emitSignature(e, SlotScript.sighashSingle);
  }

  SVScript lock() {
    if (_lock != null) return _lock!;
    final proof = _gen.generate().buffer;
    final sb = ScriptBuilder();
    final e = StackEmitter(sb, initial: const ['preimage', 'prevoutsTail']);
    _bind(e, withPublics: false);
    e.dropAllExcept(['sig']);
    final skip = sb.build().buffer;
    return _lock = SVScript.fromByteArray([
      OpCodes.OP_IF, ...proof, OpCodes.OP_ELSE, ...skip, OpCodes.OP_ENDIF,
      ...SlotScript.checkSigTail(),
    ]);
  }

  SVScript unlockProof(StarkProof proof, PoolPublicInputs publics, Uint8List preimage, List<int> prevoutsTail) {
    final base = StarkVerifierGen(P, PoolSpendAir.air(publics)).buildUnlock(proof);
    final b = ScriptBuilder();
    b.addData(preimage);
    b.addData(Uint8List.fromList(prevoutsTail));
    b.opCode(OpCodes.OP_1);
    return SVScript.fromByteArray([...base.buffer, ...b.build().buffer]);
  }

  SVScript unlockSkip(Uint8List preimage, List<int> prevoutsTail) {
    final b = ScriptBuilder();
    b.addData(preimage);
    b.addData(Uint8List.fromList(prevoutsTail));
    b.opCode(OpCodes.OP_0);
    return b.build();
  }
}
