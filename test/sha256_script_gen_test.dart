import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/script_gen/sha256_script_gen.dart';
import 'package:tstokenlib/src/script_gen/opcode_helpers.dart';
import 'package:tstokenlib/src/transaction/partial_sha256.dart';
import 'package:convert/convert.dart';

/// Converts a 32-bit unsigned int to a 4-byte big-endian Uint8List.
Uint8List _uint32ToBE(int value) {
  var buf = ByteData(4);
  buf.setUint32(0, value & 0xFFFFFFFF, Endian.big);
  return buf.buffer.asUint8List();
}

/// Converts a 32-bit unsigned int to a 4-byte little-endian Uint8List.
Uint8List _uint32ToLE(int value) {
  var buf = ByteData(4);
  buf.setUint32(0, value & 0xFFFFFFFF, Endian.little);
  return buf.buffer.asUint8List();
}

Transaction _createDummyTx(SVScript scriptSig) {
  var tx = Transaction();
  tx.version = 1;
  tx.nLockTime = 0;
  var input = TransactionInput(
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    0,
    TransactionInput.MAX_SEQ_NUMBER,
    scriptBuilder: DefaultUnlockBuilder.fromScript(scriptSig),
  );
  tx.inputs.add(input);
  tx.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return tx;
}

Set<VerifyFlag> get _genesisFlags => {VerifyFlag.UTXO_AFTER_GENESIS};

void _verifyScript(SVScript scriptSig, SVScript scriptPubKey) {
  var interp = Interpreter();
  var tx = _createDummyTx(scriptSig);
  interp.correctlySpends(
    scriptSig, scriptPubKey, tx, 0, _genesisFlags, Coin.valueOf(BigInt.from(1000)),
  );
}

void main() {
  group('K constants blob', () {
    test('has correct length', () {
      expect(Sha256ScriptGen.kConstantsBlob.length, equals(256));
    });

    test('matches PartialSha256.K values in BE format', () {
      var blob = Sha256ScriptGen.kConstantsBlob;
      var bd = ByteData.sublistView(blob);
      for (int i = 0; i < 64; i++) {
        int fromBlob = bd.getUint32(i * 4, Endian.big);
        int expected = PartialSha256.K[i] & 0xFFFFFFFF;
        expect(fromBlob, equals(expected),
            reason: 'K[$i] mismatch: got $fromBlob, expected $expected');
      }
    });
  });

  group('Byte reversal', () {
    test('reverseBytes4 swaps endianness correctly', () {
      var input = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      var expected = Uint8List.fromList([0x04, 0x03, 0x02, 0x01]);

      var lockBuilder = ScriptBuilder();
      OpcodeHelpers.reverseBytes4(lockBuilder);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(input);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });
  });

  group('32-bit addition (BE)', () {
    test('adds two BE values correctly', () {
      // 0x10000001 + 0x20000002 = 0x30000003
      var a = _uint32ToBE(0x10000001);
      var bVal = _uint32ToBE(0x20000002);
      var expected = _uint32ToBE(0x30000003);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitAdd32BE(lockBuilder);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(a);
      unlockBuilder.addData(bVal);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });

    test('truncates overflow correctly', () {
      // 0xFFFFFFFF + 1 = 0x00000000
      var a = _uint32ToBE(0xFFFFFFFF);
      var bVal = _uint32ToBE(0x00000001);
      var expected = _uint32ToBE(0x00000000);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitAdd32BE(lockBuilder);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(a);
      unlockBuilder.addData(bVal);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });
  });

  group('σ0 (small sigma 0)', () {
    test('matches PartialSha256.smallSig0 for test vectors', () {
      var testValues = [0x00000001, 0x80000000, 0x12345678, 0xDEADBEEF, 0xFFFFFFFF];

      for (var val in testValues) {
        int expected = PartialSha256.smallSig0(val) & 0xFFFFFFFF;
        var inputBE = _uint32ToBE(val);
        var expectedBE = _uint32ToBE(expected);

        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitSmallSigma0(lockBuilder);
        lockBuilder.addData(expectedBE);
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(inputBE);

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('σ1 (small sigma 1)', () {
    test('matches PartialSha256.smallSig1 for test vectors', () {
      var testValues = [0x00000001, 0x80000000, 0x12345678, 0xDEADBEEF, 0xFFFFFFFF];

      for (var val in testValues) {
        int expected = PartialSha256.smallSig1(val) & 0xFFFFFFFF;
        var inputBE = _uint32ToBE(val);
        var expectedBE = _uint32ToBE(expected);

        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitSmallSigma1(lockBuilder);
        lockBuilder.addData(expectedBE);
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(inputBE);

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('Σ0 (big sigma 0)', () {
    test('matches PartialSha256.bigSig0 for test vectors', () {
      var testValues = [0x00000001, 0x80000000, 0x12345678, 0x6A09E667, 0xFFFFFFFF];

      for (var val in testValues) {
        int expected = PartialSha256.bigSig0(val) & 0xFFFFFFFF;
        var inputBE = _uint32ToBE(val);
        var expectedBE = _uint32ToBE(expected);

        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitBigSigma0(lockBuilder);
        lockBuilder.addData(expectedBE);
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(inputBE);

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('Σ1 (big sigma 1)', () {
    test('matches PartialSha256.bigSig1 for test vectors', () {
      var testValues = [0x00000001, 0x80000000, 0x12345678, 0x510E527F, 0xFFFFFFFF];

      for (var val in testValues) {
        int expected = PartialSha256.bigSig1(val) & 0xFFFFFFFF;
        var inputBE = _uint32ToBE(val);
        var expectedBE = _uint32ToBE(expected);

        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitBigSigma1(lockBuilder);
        lockBuilder.addData(expectedBE);
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(inputBE);

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('Ch (choice)', () {
    test('matches PartialSha256.ch for test vectors', () {
      var testCases = [
        [0xFFFFFFFF, 0xAAAAAAAA, 0x55555555],
        [0x00000000, 0xAAAAAAAA, 0x55555555],
        [0x12345678, 0x9ABCDEF0, 0xFEDCBA98],
        [0x510E527F, 0x9B05688C, 0x1F83D9AB],
      ];

      for (var tc in testCases) {
        int e = tc[0], f = tc[1], g = tc[2];
        int expected = PartialSha256.ch(e, f, g) & 0xFFFFFFFF;

        // emitCh expects stack: g f e (e on top), all 4-byte
        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitCh(lockBuilder);
        lockBuilder.addData(_uint32ToBE(expected));
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(_uint32ToBE(g));
        unlockBuilder.addData(_uint32ToBE(f));
        unlockBuilder.addData(_uint32ToBE(e));

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('Maj (majority)', () {
    test('matches PartialSha256.maj for test vectors', () {
      var testCases = [
        [0xFFFFFFFF, 0xAAAAAAAA, 0x55555555],
        [0x00000000, 0xAAAAAAAA, 0x55555555],
        [0x12345678, 0x9ABCDEF0, 0xFEDCBA98],
        [0x6A09E667, 0xBB67AE85, 0x3C6EF372],
      ];

      for (var tc in testCases) {
        int a = tc[0], bVal = tc[1], c = tc[2];
        int expected = PartialSha256.maj(a, bVal, c) & 0xFFFFFFFF;

        // emitMaj expects stack: c b a (a on top)
        var lockBuilder = ScriptBuilder();
        Sha256ScriptGen.emitMaj(lockBuilder);
        lockBuilder.addData(_uint32ToBE(expected));
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
        lockBuilder.opCode(OpCodes.OP_1);

        var unlockBuilder = ScriptBuilder();
        unlockBuilder.addData(_uint32ToBE(c));
        unlockBuilder.addData(_uint32ToBE(bVal));
        unlockBuilder.addData(_uint32ToBE(a));

        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      }
    });
  });

  group('Blob extraction', () {
    test('extracts correct word from blob', () {
      var blob = Uint8List(16);
      for (int i = 0; i < 4; i++) {
        var word = _uint32ToBE(0x11111111 * (i + 1));
        blob.setRange(i * 4, (i + 1) * 4, word);
      }

      var expected = _uint32ToBE(0x33333333);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitExtractWord(lockBuilder, 8);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(blob);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });

    test('extractWordKeep preserves blob', () {
      var blob = Uint8List(16);
      for (int i = 0; i < 4; i++) {
        var word = _uint32ToBE(0x11111111 * (i + 1));
        blob.setRange(i * 4, (i + 1) * 4, word);
      }

      var expectedWord = _uint32ToBE(0x22222222);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitExtractWordKeep(lockBuilder, 4);
      lockBuilder.addData(expectedWord);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.addData(blob);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(blob);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });
  });

  group('32-bit addition (LE)', () {
    test('adds two LE values correctly', () {
      var a = _uint32ToLE(0x10000001);
      var bVal = _uint32ToLE(0x20000002);
      var expected = _uint32ToLE(0x30000003);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitAdd32LE(lockBuilder);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(a);
      unlockBuilder.addData(bVal);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });

    test('truncates overflow correctly (LE)', () {
      var a = _uint32ToLE(0xFFFFFFFF);
      var bVal = _uint32ToLE(0x00000001);
      var expected = _uint32ToLE(0x00000000);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitAdd32LE(lockBuilder);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(a);
      unlockBuilder.addData(bVal);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });
  });

  group('addNBE', () {
    test('adds 4 BE values correctly', () {
      // 0x10000000 + 0x20000000 + 0x30000000 + 0x01000000 = 0x61000000
      var v0 = _uint32ToBE(0x10000000);
      var v1 = _uint32ToBE(0x20000000);
      var v2 = _uint32ToBE(0x30000000);
      var v3 = _uint32ToBE(0x01000000);
      var expected = _uint32ToBE(0x61000000);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitAddNBE(lockBuilder, 4);
      lockBuilder.addData(expected);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(v0);
      unlockBuilder.addData(v1);
      unlockBuilder.addData(v2);
      unlockBuilder.addData(v3);

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });
  });

  group('Message schedule', () {
    test('blob concatenation produces correct 64-byte blob', () {
      // Test that 16 words concatenate in the right order
      // New convention: W[0] on top, W[15] at bottom
      var words = <Uint8List>[];
      for (int i = 0; i < 16; i++) {
        words.add(_uint32ToBE(i + 1));  // W[0]=1, W[1]=2, ..., W[15]=16
      }

      // Expected blob: W[0]||W[1]||...||W[15]
      var expectedBlob = Uint8List(64);
      for (int i = 0; i < 16; i++) {
        expectedBlob.setRange(i * 4, (i + 1) * 4, words[i]);
      }

      // Build: push W[15]..W[0] (W[0] on top), concatenate with SWAP+CAT
      var lockBuilder = ScriptBuilder();
      for (int i = 1; i < 16; i++) {
        lockBuilder.opCode(OpCodes.OP_SWAP);
        lockBuilder.opCode(OpCodes.OP_CAT);
      }
      lockBuilder.addData(expectedBlob);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      // Push in reverse order so W[0] ends up on top
      var unlockBuilder = ScriptBuilder();
      for (int i = 15; i >= 0; i--) {
        unlockBuilder.addData(words[i]);
      }

      _verifyScript(unlockBuilder.build(), lockBuilder.build());
    });

    test('single expansion step t=16 inline', () {
      // Manually inline ONE step of the expansion loop
      var w = List<int>.filled(16, 0);
      w[0] = 0x80000000;

      var initialBlob = Uint8List(64);
      for (int i = 0; i < 16; i++) {
        initialBlob.setRange(i * 4, (i + 1) * 4, _uint32ToBE(w[i]));
      }

      // Compute expected W[16]
      int expected = (PartialSha256.smallSig1(w[14]) +
                      w[9] +
                      PartialSha256.smallSig0(w[1]) +
                      w[0]) & 0xFFFFFFFF;

      // Push blob directly, then do ONE step of expansion
      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(initialBlob);

      var lockBuilder = ScriptBuilder();
      int t = 16;
      // σ0(W[t-15])
      Sha256ScriptGen.emitExtractWordKeep(lockBuilder, (t - 15) * 4);
      Sha256ScriptGen.emitSmallSigma0(lockBuilder);
      lockBuilder.opCode(OpCodes.OP_TOALTSTACK);
      // σ1(W[t-2])
      Sha256ScriptGen.emitExtractWordKeep(lockBuilder, (t - 2) * 4);
      Sha256ScriptGen.emitSmallSigma1(lockBuilder);
      // W[t-7]
      lockBuilder.opCode(OpCodes.OP_OVER);
      Sha256ScriptGen.emitExtractWord(lockBuilder, (t - 7) * 4);
      // W[t-16]
      lockBuilder.opCode(OpCodes.OP_2); lockBuilder.opCode(OpCodes.OP_PICK);
      Sha256ScriptGen.emitExtractWord(lockBuilder, (t - 16) * 4);
      // σ0 from altstack
      lockBuilder.opCode(OpCodes.OP_FROMALTSTACK);
      // Sum 4
      Sha256ScriptGen.emitAddNBE(lockBuilder, 4);
      // Append to blob
      lockBuilder.opCode(OpCodes.OP_CAT);
      // Now blob is 68 bytes. Extract W[16] at offset 64.
      Sha256ScriptGen.emitExtractWord(lockBuilder, 64);
      lockBuilder.addData(_uint32ToBE(expected));
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      try {
        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      } catch (e) {
        print('Error: $e');
        rethrow;
      }
    });

    test('full message schedule produces correct W blob', () {
      var w = List<int>.filled(64, 0);
      w[0] = 0x80000000;
      for (int t = 16; t < 64; t++) {
        w[t] = (PartialSha256.smallSig1(w[t - 2]) +
                w[t - 7] +
                PartialSha256.smallSig0(w[t - 15]) +
                w[t - 16]) & 0xFFFFFFFF;
      }

      // Push in reverse order so W[0] is on top
      var unlockBuilder = ScriptBuilder();
      for (int i = 15; i >= 0; i--) {
        unlockBuilder.addData(_uint32ToBE(w[i]));
      }

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitMessageScheduleBlob(lockBuilder);
      // Verify a few key words from the 256-byte blob
      // Check W[16], W[31], W[47], W[63]
      for (var idx in [16, 31, 47, 63]) {
        lockBuilder.opCode(OpCodes.OP_DUP);
        Sha256ScriptGen.emitExtractWord(lockBuilder, idx * 4);
        lockBuilder.addData(_uint32ToBE(w[idx]));
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      }
      // Check total blob size = 256
      lockBuilder.opCode(OpCodes.OP_SIZE);
      lockBuilder.opCode(OpCodes.OP_NIP);
      OpcodeHelpers.pushInt(lockBuilder, 256);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      try {
        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      } catch (e) {
        print('Error: $e');
        rethrow;
      }
    });

  });

  group('Full SHA256 block', () {
    test('single compression round produces correct state (LE)', () {
      // Use SHA256("") IV and first block W values
      var iv = PartialSha256.STD_INIT_VECTOR;
      var w = List<int>.filled(64, 0);
      w[0] = 0x80000000;
      for (int t = 16; t < 64; t++) {
        w[t] = (PartialSha256.smallSig1(w[t - 2]) + w[t - 7] +
                PartialSha256.smallSig0(w[t - 15]) + w[t - 16]) & 0xFFFFFFFF;
      }

      // Compute expected state after round 0 using Int32List (same as reference)
      var TEMP = Int32List.fromList(iv);
      int t1_32 = TEMP[7] + PartialSha256.bigSig1(TEMP[4]) +
                PartialSha256.ch(TEMP[4], TEMP[5], TEMP[6]) +
                PartialSha256.K[0] + w[0];
      int t2_32 = PartialSha256.bigSig0(TEMP[0]) +
                PartialSha256.maj(TEMP[0], TEMP[1], TEMP[2]);
      TEMP.setRange(1, TEMP.length, TEMP);
      TEMP[4] += t1_32;
      TEMP[0] = t1_32 + t2_32;

      print('Expected state after round 0:');
      for (int i = 0; i < 8; i++) {
        print('  H[$i] = 0x${(TEMP[i] & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0')}');
      }

      // Build W blob (BE) and K blob (BE)
      var wBlob = Uint8List(256);
      for (int i = 0; i < 64; i++) {
        var bd = ByteData.sublistView(wBlob, i * 4, (i + 1) * 4);
        bd.setUint32(0, w[i] & 0xFFFFFFFF, Endian.big);
      }
      var kBlob = Sha256ScriptGen.kConstantsBlob;

      // Unlock: push state as LE words (h...a, a on top)
      var unlockBuilder = ScriptBuilder();
      for (int i = 7; i >= 0; i--) {
        unlockBuilder.addData(_uint32ToLE(iv[i] & 0xFFFFFFFF));
      }

      // Lock: set up altstack and run one round
      var lockBuilder = ScriptBuilder();
      lockBuilder.addData(wBlob);
      lockBuilder.opCode(OpCodes.OP_TOALTSTACK);  // W
      lockBuilder.addData(kBlob);
      lockBuilder.opCode(OpCodes.OP_TOALTSTACK);  // K

      Sha256ScriptGen.emitCompressionRound(lockBuilder, 0);

      // Discard K and W
      lockBuilder.opCode(OpCodes.OP_FROMALTSTACK); lockBuilder.opCode(OpCodes.OP_DROP);
      lockBuilder.opCode(OpCodes.OP_FROMALTSTACK); lockBuilder.opCode(OpCodes.OP_DROP);

      // Verify: a'(top)...h'(bottom) as LE against TEMP[0]...TEMP[7]
      for (int i = 0; i < 8; i++) {
        lockBuilder.addData(_uint32ToLE(TEMP[i] & 0xFFFFFFFF));
        lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      }
      lockBuilder.opCode(OpCodes.OP_1);

      try {
        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      } catch (e) {
        print('Single round error: $e');
        rethrow;
      }
    });

    test('emitOneBlock matches PartialSha256.hashOneBlock for SHA256("")', () {
      // SHA256("") first block: 0x80000000 followed by zeros, length=0
      var block = Uint8List(64);
      block[0] = 0x80;  // BE: 0x80 at first byte = 0x80000000 as first word
      // rest is zeros, including length field (0 bits)

      // Use standard initial vector
      var iv = PartialSha256.STD_INIT_VECTOR;
      var midstate = Uint8List(32);
      var bd = ByteData.sublistView(midstate);
      for (int i = 0; i < 8; i++) {
        bd.setUint32(i * 4, iv[i] & 0xFFFFFFFF, Endian.big);
      }

      // Compute expected hash using Dart reference
      var blockWords = PartialSha256.uint8ListToInt32List(block);
      var expectedHash = PartialSha256.hashOneBlock(blockWords, iv);

      // Build scripts: unlock pushes midstate then block
      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(midstate);
      unlockBuilder.addData(block);

      // Lock: emitOneBlock, then compare
      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitOneBlock(lockBuilder);
      lockBuilder.addData(expectedHash);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      var scriptSig = unlockBuilder.build();
      var scriptPubKey = lockBuilder.build();
      print('Full block scriptPubKey size: ${scriptPubKey.buffer!.length} bytes');

      try {
        _verifyScript(scriptSig, scriptPubKey);
      } catch (e) {
        print('Error: $e');
        rethrow;
      }
    });

    test('emitOneBlock with non-trivial data', () {
      // SHA256("abc") — first block is: 0x61626380 0x00...00 0x00000018
      var block = Uint8List(64);
      block[0] = 0x61; block[1] = 0x62; block[2] = 0x63; block[3] = 0x80;
      // length = 24 bits = 0x18
      block[63] = 0x18;

      var iv = PartialSha256.STD_INIT_VECTOR;
      var midstate = Uint8List(32);
      var bd = ByteData.sublistView(midstate);
      for (int i = 0; i < 8; i++) {
        bd.setUint32(i * 4, iv[i] & 0xFFFFFFFF, Endian.big);
      }

      var blockWords = PartialSha256.uint8ListToInt32List(block);
      var expectedHash = PartialSha256.hashOneBlock(blockWords, iv);
      // SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
      print('Expected SHA256("abc"): ${expectedHash.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');

      var unlockBuilder = ScriptBuilder();
      unlockBuilder.addData(midstate);
      unlockBuilder.addData(block);

      var lockBuilder = ScriptBuilder();
      Sha256ScriptGen.emitOneBlock(lockBuilder);
      lockBuilder.addData(expectedHash);
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      try {
        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      } catch (e) {
        print('Error: $e');
        rethrow;
      }
    });

    test('produces correct W[16] via emitMessageScheduleBlob limited', () {
      // Test with W0-on-top convention
      var w = List<int>.filled(16, 0);
      w[0] = 0x80000000;

      int expected = (PartialSha256.smallSig1(w[14]) +
                      w[9] +
                      PartialSha256.smallSig0(w[1]) +
                      w[0]) & 0xFFFFFFFF;

      // Push in reverse order so W[0] is on top
      var unlockBuilder = ScriptBuilder();
      for (int i = 15; i >= 0; i--) {
        unlockBuilder.addData(_uint32ToBE(w[i]));
      }

      // Locking script: concat with SWAP+CAT (new convention)
      var lockBuilder = ScriptBuilder();
      for (int i = 1; i < 16; i++) {
        lockBuilder.opCode(OpCodes.OP_SWAP);
        lockBuilder.opCode(OpCodes.OP_CAT);
      }

      // Do just 1 expansion step (t=16)
      int t = 16;
      Sha256ScriptGen.emitExtractWordKeep(lockBuilder, (t - 15) * 4);
      Sha256ScriptGen.emitSmallSigma0(lockBuilder);
      lockBuilder.opCode(OpCodes.OP_TOALTSTACK);
      Sha256ScriptGen.emitExtractWordKeep(lockBuilder, (t - 2) * 4);
      Sha256ScriptGen.emitSmallSigma1(lockBuilder);
      lockBuilder.opCode(OpCodes.OP_OVER);
      Sha256ScriptGen.emitExtractWord(lockBuilder, (t - 7) * 4);
      lockBuilder.opCode(OpCodes.OP_2); lockBuilder.opCode(OpCodes.OP_PICK);
      Sha256ScriptGen.emitExtractWord(lockBuilder, (t - 16) * 4);
      lockBuilder.opCode(OpCodes.OP_FROMALTSTACK);
      Sha256ScriptGen.emitAddNBE(lockBuilder, 4);
      lockBuilder.opCode(OpCodes.OP_CAT);

      Sha256ScriptGen.emitExtractWord(lockBuilder, 64);
      lockBuilder.addData(_uint32ToBE(expected));
      lockBuilder.opCode(OpCodes.OP_EQUALVERIFY);
      lockBuilder.opCode(OpCodes.OP_1);

      try {
        _verifyScript(unlockBuilder.build(), lockBuilder.build());
      } catch (e) {
        print('Error: $e');
        rethrow;
      }
    });
  });
}
