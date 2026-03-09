import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

var aliceWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey alicePrivateKey = SVPrivateKey.fromWIF(aliceWif);
SVPublicKey alicePubKey = alicePrivateKey.publicKey;
var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
var alicePubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

Transaction getBobFundingTx() {
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

Transaction getAliceFundingTx() {
  var rawTx =
      "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";
  return Transaction.fromHex(rawTx);
}

/// Rebuild an SVScript from chunks, replacing one chunk's data.
SVScript tamperChunkData(SVScript original, int chunkIndex, Uint8List newData) {
  var chunks = original.chunks;
  var b = ScriptBuilder();
  for (int i = 0; i < chunks.length; i++) {
    if (i == chunkIndex) {
      b.addData(newData);
    } else {
      var chunk = chunks[i];
      if (chunk.buf != null && chunk.buf!.isNotEmpty) {
        b.addData(Uint8List.fromList(chunk.buf!));
      } else {
        b.opCode(chunk.opcodenum);
      }
    }
  }
  return b.build();
}

/// Rebuild an SVScript from chunks, replacing one chunk's number value.
SVScript tamperChunkNumber(SVScript original, int chunkIndex, int newValue) {
  var chunks = original.chunks;
  var b = ScriptBuilder();
  for (int i = 0; i < chunks.length; i++) {
    if (i == chunkIndex) {
      b.number(newValue);
    } else {
      var chunk = chunks[i];
      if (chunk.buf != null && chunk.buf!.isNotEmpty) {
        b.addData(Uint8List.fromList(chunk.buf!));
      } else {
        b.opCode(chunk.opcodenum);
      }
    }
  }
  return b.build();
}

var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

void main() {
  // =========================================================================
  // Shared setup: mint → witness → transfer (used by transfer and burn tests)
  // =========================================================================
  late Transaction mintTx;
  late Transaction mintWitnessTx;
  late Transaction transferTx;
  late Transaction transferWitnessTx;
  late Transaction burnTx;
  late FungibleTokenTool service;

  setUpAll(() async {
    service = FungibleTokenTool();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

    // Step 1: Bob mints 1000 tokens
    var bobFundingTx = getBobFundingTx();
    mintTx = await service.createFungibleMintTxn(
      bobFundingTx, bobFundingSigner, bobPub, bobAddress,
      bobFundingTx.hash, 1000,
    );

    var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
    var tokenId = pp5Lock.tokenId;

    // Step 2: Create mint witness
    mintWitnessTx = service.createFungibleWitnessTxn(
      bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
      FungibleTokenAction.MINT,
    );

    // Step 3: Bob transfers to Alice
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx();
    transferTx = service.createFungibleTransferTxn(
      mintWitnessTx, mintTx, bobPub, aliceAddress,
      transferFundingTx, bobFundingSigner, bobPub,
      aliceFundingTx.hash, tokenId, 1000,
    );

    // Step 4: Create transfer witness (Alice proves she received)
    transferWitnessTx = service.createFungibleWitnessTxn(
      aliceFundingSigner, aliceFundingTx, transferTx, alicePubKey, bobPubkeyHash,
      FungibleTokenAction.TRANSFER,
      parentTokenTxBytes: hex.decode(mintTx.serialize()),
      parentOutputCount: 5,
    );

    // Step 5: Alice burns
    var burnFundingTx = getAliceFundingTx();
    burnTx = service.createFungibleBurnTxn(
      transferTx, aliceFundingSigner, alicePubKey,
      burnFundingTx, aliceFundingSigner, alicePubKey,
    );
  });

  // =========================================================================
  // Sanity checks: valid transactions pass
  // =========================================================================
  group('Sanity: valid transactions pass', () {
    test('burn spending verifies', () {
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            burnTx.inputs[1].script!, transferTx.outputs[1].script,
            burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        returnsNormally,
        reason: 'Valid burn should pass');
    });

    test('transfer witness spending verifies', () {
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            transferWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        returnsNormally,
        reason: 'Valid transfer witness should pass');
    });

    test('mint witness spending verifies', () {
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            mintWitnessTx.inputs[1].script!, mintTx.outputs[1].script,
            mintWitnessTx, 1, verifyFlags, Coin.valueOf(mintTx.outputs[1].satoshis)),
        returnsNormally,
        reason: 'Valid mint witness should pass');
    });
  });

  // =========================================================================
  // Burn negative tests
  // =========================================================================
  // Burn scriptSig chunks: [0: ownerPubKey, 1: ownerSig, 2: OP_4(selector)]
  group('Burn negative tests', () {
    test('rejects wrong ownerPubKey (hash160 mismatch)',
        timeout: Timeout(Duration(minutes: 1)), () {
      var validScriptSig = burnTx.inputs[1].script!;
      // Replace Alice's pubkey with Bob's pubkey
      var wrongPubKey = Uint8List.fromList(hex.decode(bobPub.toHex()));
      var tamperedSig = tamperChunkData(validScriptSig, 0, wrongPubKey);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerPubKey should fail hash160 check');
    });

    test('rejects wrong ownerSig',
        timeout: Timeout(Duration(minutes: 1)), () {
      var validScriptSig = burnTx.inputs[1].script!;
      // Replace signature with garbage (same length)
      var origSig = validScriptSig.chunks[1].buf!;
      var wrongSig = Uint8List.fromList(List.filled(origSig.length, 0xAA));
      var tamperedSig = tamperChunkData(validScriptSig, 1, wrongSig);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerSig should fail checkSig');
    });

    test('rejects random garbage pubkey',
        timeout: Timeout(Duration(minutes: 1)), () {
      var validScriptSig = burnTx.inputs[1].script!;
      // Use random 33 bytes that aren't a valid pubkey
      var garbagePubKey = Uint8List.fromList(List.filled(33, 0xDE));
      var tamperedSig = tamperChunkData(validScriptSig, 0, garbagePubKey);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Garbage pubkey should fail');
    });
  });

  // =========================================================================
  // Transfer negative tests
  // =========================================================================
  // Transfer scriptSig chunks:
  //   [0: preImage, 1: pp2Output, 2: ownerPubKey, 3: changePKH,
  //    4: changeAmount, 5: ownerSig, 6: tokenLHS, 7: prevTokenTx,
  //    8: witnessPadding, 9: parentOutputCount, 10: parentPP5Index, 11: OP_1]
  group('Transfer negative tests', () {
    test('rejects wrong ownerPubKey (hash160 mismatch)',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      // Replace Alice's pubkey with Bob's
      var wrongPubKey = Uint8List.fromList(hex.decode(bobPub.toHex()));
      var tamperedSig = tamperChunkData(validScriptSig, 2, wrongPubKey);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerPubKey should fail hash160 check');
    });

    test('rejects wrong ownerSig',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      var origSig = validScriptSig.chunks[5].buf!;
      var wrongSig = Uint8List.fromList(List.filled(origSig.length, 0xBB));
      var tamperedSig = tamperChunkData(validScriptSig, 5, wrongSig);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerSig should fail checkSig');
    });

    test('rejects wrong parentRawTx (different tx)',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      // Use a different tx as parentRawTx (the funding tx instead of the real parent)
      var wrongParentTx = Uint8List.fromList(hex.decode(getBobFundingTx().serialize()));
      var tamperedSig = tamperChunkData(validScriptSig, 7, wrongParentTx);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentRawTx should fail outpoint verification');
    });

    test('rejects tampered parentRawTx (flipped byte)',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      var origParent = Uint8List.fromList(validScriptSig.chunks[7].buf!);
      // Flip one byte in the middle of the parent tx
      origParent[origParent.length ~/ 2] ^= 0xFF;
      var tamperedSig = tamperChunkData(validScriptSig, 7, origParent);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Tampered parentRawTx should fail verification');
    });

    test('rejects wrong pp2Output',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      var origPP2 = Uint8List.fromList(validScriptSig.chunks[1].buf!);
      // Tamper with the PP2 output bytes
      origPP2[10] ^= 0xFF;
      var tamperedSig = tamperChunkData(validScriptSig, 1, origPP2);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong pp2Output should fail PP2 validation');
    });

    test('rejects wrong parentOutputCount',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      // parentOutputCount is chunk 9; change from 5 to 6
      var tamperedSig = tamperChunkNumber(validScriptSig, 9, 6);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentOutputCount should fail');
    });

    test('rejects wrong parentPP5Index',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = transferWitnessTx.inputs[1].script!;
      // parentPP5Index is chunk 10; change from 1 to 2
      var tamperedSig = tamperChunkNumber(validScriptSig, 10, 2);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, transferTx.outputs[1].script,
            transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentPP5Index should fail');
    });
  });

  // =========================================================================
  // Mint negative tests
  // =========================================================================
  // Mint scriptSig chunks: [0: preImage, 1: fundingTxId, 2: padding, 3: OP_0]
  group('Mint negative tests', () {
    test('rejects wrong fundingTxId',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mintWitnessTx.inputs[1].script!;
      // Replace fundingTxId with a different hash
      var wrongFundingId = Uint8List.fromList(List.filled(32, 0xAA));
      var tamperedSig = tamperChunkData(validScriptSig, 1, wrongFundingId);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mintTx.outputs[1].script,
            mintWitnessTx, 1, verifyFlags, Coin.valueOf(mintTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong fundingTxId should fail hashPrevouts check');
    });
  });

  // =========================================================================
  // Split negative tests
  // =========================================================================
  // Split scriptSig chunks:
  //   [0: preImage, 1: pp2RecipOutput, 2: pp2ChangeOutput, 3: ownerPubKey,
  //    4: changePKH, 5: changeAmount, 6: ownerSig, 7: tokenLHS,
  //    8: prevTokenTx, 9: witnessPadding, 10: recipientAmount,
  //    11: tokenChangeAmount, 12: recipientPKH, 13: myOutputIndex,
  //    14: parentOutputCount, 15: parentPP5Index, 16: OP_2]
  group('Split negative tests', () {
    late Transaction splitTx;
    late Transaction splitWitnessTx;

    setUpAll(() {
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

      // Use the shared mintTx and mintWitnessTx from outer setUpAll
      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      // Create split: 700 to Alice, 300 change to Bob
      var splitFundingTx = getBobFundingTx();
      var aliceWitnessFundingTx = getAliceFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 700,
        splitFundingTx, bobFundingSigner, bobPub,
        aliceWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, 1000,
      );

      // Create split witness (recipient, pp5Idx=1)
      splitWitnessTx = service.createFungibleWitnessTxn(
        aliceFundingSigner, aliceWitnessFundingTx, splitTx,
        alicePubKey, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
      );
    });

    test('sanity: valid split witness passes', () {
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            splitWitnessTx.inputs[1].script!, splitTx.outputs[1].script,
            splitWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
        returnsNormally,
        reason: 'Valid split witness should pass');
    });

    test('rejects wrong ownerPubKey',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = splitWitnessTx.inputs[1].script!;
      var wrongPubKey = Uint8List.fromList(hex.decode(bobPub.toHex()));
      var tamperedSig = tamperChunkData(validScriptSig, 3, wrongPubKey);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, splitTx.outputs[1].script,
            splitWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerPubKey should fail in split');
    });

    test('rejects wrong parentRawTx',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = splitWitnessTx.inputs[1].script!;
      var wrongParentTx = Uint8List.fromList(hex.decode(getBobFundingTx().serialize()));
      var tamperedSig = tamperChunkData(validScriptSig, 8, wrongParentTx);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, splitTx.outputs[1].script,
            splitWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentRawTx should fail in split');
    });

    test('rejects wrong recipientAmount (breaks balance conservation)',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = splitWitnessTx.inputs[1].script!;
      // Change recipientAmount from 700 to 800 (800+300 != 1000)
      var tamperedSig = tamperChunkNumber(validScriptSig, 10, 800);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, splitTx.outputs[1].script,
            splitWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong recipientAmount should fail balance conservation');
    });

    test('rejects wrong tokenChangeAmount (breaks balance conservation)',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = splitWitnessTx.inputs[1].script!;
      // Change tokenChangeAmount from 300 to 200 (700+200 != 1000)
      var tamperedSig = tamperChunkNumber(validScriptSig, 11, 200);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, splitTx.outputs[1].script,
            splitWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong tokenChangeAmount should fail balance conservation');
    });
  });

  // =========================================================================
  // Merge negative tests
  // =========================================================================
  // Merge scriptSig chunks:
  //   [0: preImage, 1: pp2Output, 2: ownerPubKey, 3: changePKH,
  //    4: changeAmount, 5: ownerSig, 6: tokenLHS, 7: prevTokenTxA,
  //    8: prevTokenTxB, 9: witnessPadding, 10: parentOutputCountA,
  //    11: parentOutputCountB, 12: parentPP5IndexA, 13: parentPP5IndexB,
  //    14: OP_3(selector)]
  group('Merge negative tests', () {
    late Transaction splitTx;
    late Transaction mergeTx;
    late Transaction mergeWitnessTx;

    setUpAll(() async {
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      // Split: 600 to Bob, 400 change to Bob
      var splitFundingTx = getBobFundingTx();
      var recipientWitnessFundingTx = getBobFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, bobAddress, 600,
        splitFundingTx, bobFundingSigner, bobPub,
        recipientWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, 1000,
      );

      // Witnesses for both triplets
      var recipientWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, recipientWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 1,
      );

      var changeWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, changeWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 4,
      );

      // Merge 600 + 400 = 1000
      var mergeFundingTx = getBobFundingTx();
      var mergeWitnessFundingTx = getBobFundingTx();

      mergeTx = service.createFungibleMergeTxn(
        recipientWitnessTx, splitTx,
        changeWitnessTx, splitTx,
        bobPub,
        bobFundingSigner,
        mergeFundingTx, bobFundingSigner, bobPub,
        mergeWitnessFundingTx.hash,
        tokenId, 1000,
        prevTripletBaseIndexA: 1,
        prevTripletBaseIndexB: 4,
      );

      // Create merge witness
      var splitTxBytes = hex.decode(splitTx.serialize());
      mergeWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, mergeWitnessFundingTx, mergeTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MERGE,
        parentTokenTxBytes: splitTxBytes,
        parentTokenTxBytesB: splitTxBytes,
        parentOutputCount: 8,
        parentOutputCountB: 8,
        parentPP5IndexA: 1,
        parentPP5IndexB: 4,
        tripletBaseIndex: 1,
      );
    });

    test('sanity: valid merge witness passes', () {
      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            mergeWitnessTx.inputs[1].script!, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        returnsNormally,
        reason: 'Valid merge witness should pass');
    });

    test('rejects wrong ownerPubKey',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var wrongPubKey = Uint8List.fromList(hex.decode(alicePubKey.toHex()));
      var tamperedSig = tamperChunkData(validScriptSig, 2, wrongPubKey);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerPubKey should fail hash160 check');
    });

    test('rejects wrong ownerSig',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var origSig = validScriptSig.chunks[5].buf!;
      var wrongSig = Uint8List.fromList(List.filled(origSig.length, 0xCC));
      var tamperedSig = tamperChunkData(validScriptSig, 5, wrongSig);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong ownerSig should fail checkSig');
    });

    test('rejects wrong parentRawTxA',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var wrongParentTx = Uint8List.fromList(hex.decode(getBobFundingTx().serialize()));
      var tamperedSig = tamperChunkData(validScriptSig, 7, wrongParentTx);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentRawTxA should fail');
    });

    test('rejects wrong parentRawTxB',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var wrongParentTx = Uint8List.fromList(hex.decode(getBobFundingTx().serialize()));
      var tamperedSig = tamperChunkData(validScriptSig, 8, wrongParentTx);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentRawTxB should fail');
    });

    test('rejects wrong pp2Output',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var origPP2 = Uint8List.fromList(validScriptSig.chunks[1].buf!);
      origPP2[10] ^= 0xFF;
      var tamperedSig = tamperChunkData(validScriptSig, 1, origPP2);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong pp2Output should fail PP2 validation');
    });

    test('rejects wrong parentOutputCountA',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var tamperedSig = tamperChunkNumber(validScriptSig, 10, 3);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentOutputCountA should fail');
    });

    test('rejects wrong parentPP5IndexA',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var tamperedSig = tamperChunkNumber(validScriptSig, 12, 3);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentPP5IndexA should fail');
    });

    test('rejects wrong parentPP5IndexB',
        timeout: Timeout(Duration(minutes: 2)), () {
      var validScriptSig = mergeWitnessTx.inputs[1].script!;
      var tamperedSig = tamperChunkNumber(validScriptSig, 13, 2);

      var interp = Interpreter();
      expect(
        () => interp.correctlySpends(
            tamperedSig, mergeTx.outputs[1].script,
            mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
        throwsA(isA<ScriptException>()),
        reason: 'Wrong parentPP5IndexB should fail');
    });
  });
}
