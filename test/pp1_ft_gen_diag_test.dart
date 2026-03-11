import 'package:test/test.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/script_gen/pp1_ft_script_gen.dart';
import 'package:tstokenlib/src/script_gen/opcode_helpers.dart';
import 'dart:typed_data';

void main() {
  test('readVarint output order', () {
    // Test that emitReadVarint returns [value, rest] with rest on top
    // Push data: varint 3, then "abc"
    var b = ScriptBuilder();
    b.addData(Uint8List.fromList([0x03, 0x61, 0x62, 0x63]));
    PP1FtScriptGen.emitReadVarint(b);
    // Should have: [3, "abc"] with "abc" on top
    // Drop rest, check value == 3
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_EQUAL);
    
    var scriptPubKey = b.build();
    var scriptSig = ScriptBuilder().build();
    
    var interp = Interpreter();
    var tx = Transaction();
    tx.addOutput(TransactionOutput(BigInt.from(1000), scriptPubKey));
    tx.addInput(TransactionInput('a' * 64, 0, 0xFFFFFFFF));
    
    expect(() {
      interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
        {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    }, returnsNormally, reason: 'readVarint value should be 3');
  });
  
  test('readVarint rest content', () {
    // Verify rest is correct
    var b = ScriptBuilder();
    b.addData(Uint8List.fromList([0x03, 0x61, 0x62, 0x63]));
    PP1FtScriptGen.emitReadVarint(b);
    // Should have: [3, "abc"]
    // Swap to get rest on bottom, value on top
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_DROP);  // drop value
    // rest should be "abc" (3 bytes)
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_EQUAL);
    
    var scriptPubKey = b.build();
    var scriptSig = ScriptBuilder().build();
    var interp = Interpreter();
    var tx = Transaction();
    tx.addOutput(TransactionOutput(BigInt.from(1000), scriptPubKey));
    tx.addInput(TransactionInput('a' * 64, 0, 0xFFFFFFFF));
    
    expect(() {
      interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
        {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    }, returnsNormally, reason: 'readVarint rest should be 3 bytes');
  });
  
  test('readVarint with FD marker', () {
    // varint 0xFD 0x00 0x01 = 256 in LE
    var data = [0xFD, 0x00, 0x01];
    var rest = List.filled(256, 0xAA);
    var b = ScriptBuilder();
    b.addData(Uint8List.fromList(data + rest));
    PP1FtScriptGen.emitReadVarint(b);
    // Should have: [256, rest(256 bytes)]
    b.opCode(OpCodes.OP_DROP);  // drop rest
    OpcodeHelpers.pushInt(b, 256);
    b.opCode(OpCodes.OP_EQUAL);
    
    var scriptPubKey = b.build();
    var scriptSig = ScriptBuilder().build();
    var interp = Interpreter();
    var tx = Transaction();
    tx.addOutput(TransactionOutput(BigInt.from(1000), scriptPubKey));
    tx.addInput(TransactionInput('a' * 64, 0, 0xFFFFFFFF));
    
    expect(() {
      interp.correctlySpends(scriptSig, scriptPubKey, tx, 0,
        {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));
    }, returnsNormally, reason: 'readVarint FD marker should give 256');
  });
}
