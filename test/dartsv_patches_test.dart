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
import 'package:test/test.dart';

/// Regression tests for the local dartsv patches the shielded pool relies on.
///
/// They live here rather than in dartsv because dartsv's own test runner
/// cannot load any test file on this machine: the Dart SDK bundled with the
/// Flutter install no longer ships `frontend_server.dart.snapshot`, which the
/// runner asks for when it compiles that package. Raising dartsv's SDK
/// constraint, its `test` constraint (1.24.6 through 1.31.1, including the
/// exact 1.30.0 this repository runs on) and clearing its kernel cache all
/// leave the failure unchanged, so it is the toolchain and not the package.
/// See the dartsv section of README.md.
///
/// Each test states what unpatched dartsv does, so the value of the patch is
/// on the record even though the unpatched code is no longer reachable here.
void main() {
  group('dartsv patch: FindAndDelete is linear', () {
    // Unpatched `removeAllInstancesOf` allocated a fresh script-sized
    // ByteDataWriter buffer for every opcode it copied, so a script of a few
    // hundred KB (an ordinary size for a verifier slot) allocated tens of GB
    // and exhausted the heap. The patched version writes once into one buffer.

    test('removes every instance of a chunk and keeps the rest', () {
      // OP_1 <0xaa 0xbb> OP_2 <0xaa 0xbb> OP_3, removing the push of aabb
      final chunk = [2, 0xaa, 0xbb];
      final script = [OpCodes.OP_1, ...chunk, OpCodes.OP_2, ...chunk, OpCodes.OP_3];
      final out = SVScript.removeAllInstancesOf(script, chunk);
      expect(out, [OpCodes.OP_1, OpCodes.OP_2, OpCodes.OP_3]);
    });

    test('leaves a script alone when the chunk does not occur', () {
      final script = [OpCodes.OP_1, 2, 0xaa, 0xbb, OpCodes.OP_2];
      expect(SVScript.removeAllInstancesOf(script, [2, 0xcc, 0xdd]), script);
    });

    test('an empty chunk removes nothing', () {
      final script = [OpCodes.OP_1, 2, 0xaa, 0xbb];
      expect(SVScript.removeAllInstancesOf(script, []), script);
    });

    test('does not mistake a byte inside a push for the chunk', () {
      // the push data contains OP_2's byte value; removing OP_2 must not cut it
      final script = [3, 0xaa, OpCodes.OP_2, 0xbb, OpCodes.OP_2];
      expect(SVScript.removeAllInstancesOf(script, [OpCodes.OP_2]), [3, 0xaa, OpCodes.OP_2, 0xbb]);
    });

    test('handles PUSHDATA1, PUSHDATA2 and PUSHDATA4 headers', () {
      final p1 = [OpCodes.OP_PUSHDATA1, 2, 0x11, 0x22];
      final p2 = [OpCodes.OP_PUSHDATA2, 2, 0, 0x33, 0x44];
      final p4 = [OpCodes.OP_PUSHDATA4, 2, 0, 0, 0, 0x55, 0x66];
      final script = [...p1, ...p2, ...p4];
      expect(SVScript.removeAllInstancesOf(script, p2), [...p1, ...p4]);
      expect(SVScript.removeAllInstancesOf(script, p4), [...p1, ...p2]);
    });

    test('a signature-sized push in a large script is removed without exhausting the heap', () {
      // the shape that used to blow up: a 400 KB script (a verifier slot is
      // larger still) holding one 71-byte signature push. Unpatched this
      // allocated about 400 KB per opcode across ~200,000 opcodes.
      final sig = [71, ...List<int>.filled(71, 0x30)];
      final filler = <int>[];
      while (filler.length < 400 * 1024) {
        filler.addAll([2, 0xde, 0xad]);
      }
      final script = [...filler, ...sig, ...filler];
      final sw = Stopwatch()..start();
      final out = SVScript.removeAllInstancesOf(script, sig);
      expect(out.length, script.length - sig.length);
      expect(out, [...filler, ...filler]);
      expect(sw.elapsed, lessThan(const Duration(seconds: 5)), reason: 'FindAndDelete must stay linear');
    });
  });

  group('dartsv patch: error diagnostics', () {
    test('ScriptException.toString names the error and the cause', () {
      final e = ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, 'mismatch at lane 3');
      // unpatched this was Dart's default "Instance of 'ScriptException'"
      expect(e.toString(), contains('mismatch at lane 3'));
      expect(e.toString(), contains('EQUALVERIFY'));
      expect(e.toString(), isNot(contains("Instance of")));
    });

    test('OP_EQUALVERIFY reports both operands in hex', () {
      // <0xaabb> <0xaabc> OP_EQUALVERIFY: unequal, so it must throw with the
      // two values spelled out. Unpatched the message named neither.
      final unlock = SVScript.fromByteArray(Uint8List.fromList([2, 0xaa, 0xbb, 2, 0xaa, 0xbc]));
      final lock = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_EQUALVERIFY, OpCodes.OP_1]));
      final tx = _spending(unlock);
      try {
        Interpreter().correctlySpends(unlock, lock, tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
        fail('OP_EQUALVERIFY on unequal data should throw');
      } on ScriptException catch (e) {
        expect(e.error, ScriptError.SCRIPT_ERR_EQUALVERIFY);
        expect(e.cause, contains('aabb'));
        expect(e.cause, contains('aabc'));
      }
    });
  });

  group('dartsv patch: the pre-Genesis stack limit does not apply after Genesis', () {
    // MAX_STACK_SIZE (1000 items) is pre-Genesis consensus; after Genesis BSV
    // bounds stack memory by policy instead. The pool's verifier scripts hold
    // far more than 1000 items, so unpatched dartsv rejected every one of them
    // with SCRIPT_ERR_STACK_SIZE.
    SVScript pushes(int n) => SVScript.fromByteArray(Uint8List.fromList([for (int i = 0; i < n; i++) OpCodes.OP_1]));

    test('more than 1000 stack items are allowed with UTXO_AFTER_GENESIS', () {
      final unlock = pushes(1500);
      final lock = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_DEPTH, 2, 0xdc, 0x05, OpCodes.OP_EQUAL]));
      final tx = _spending(unlock);
      Interpreter().correctlySpends(unlock, lock, tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    });

    test('the limit still applies without UTXO_AFTER_GENESIS', () {
      final unlock = pushes(1500);
      final lock = SVScript.fromByteArray(Uint8List.fromList([OpCodes.OP_DEPTH, OpCodes.OP_DROP, OpCodes.OP_1]));
      final tx = _spending(unlock);
      expect(
          () => Interpreter().correctlySpends(unlock, lock, tx, 0, <VerifyFlag>{}, Coin.valueOf(BigInt.from(1000))),
          throwsA(isA<ScriptException>().having((e) => e.error, 'error', ScriptError.SCRIPT_ERR_STACK_SIZE)));
    });
  });
}

/// A transaction spending one input with [unlock].
Transaction _spending(SVScript unlock) {
  final t = Transaction()
    ..version = 1
    ..nLockTime = 0;
  t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(unlock)));
  t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return t;
}
