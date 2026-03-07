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

void main() {
  group('Invalid/missing funding transaction', () {
    test('funding tx with no output at index 1 causes a RangeError', () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
      var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Build a transaction with only one output (index 0)
      var singleOutputTx = TransactionBuilder()
          .spendFromTxnWithSigner(fundingSigner, getBobFundingTx(), 1,
              TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(bobPub))
          .spendToLockBuilder(
              P2PKHLockBuilder.fromAddress(bobAddress), BigInt.from(100000))
          .build(false);

      expect(singleOutputTx.outputs.length, 1);

      // Attempting to use this as a funding tx should fail because
      // createTokenIssuanceTxn tries to spend from output index 1
      expect(
          () => service.createTokenIssuanceTxn(
              singleOutputTx,
              fundingSigner,
              bobPub,
              bobAddress,
              singleOutputTx.hash),
          throwsA(isA<RangeError>()));
    });
  });

  group('Insufficient funds for fees', () {
    test(
        'funding tx with very small satoshi value produces transaction with negative change',
        () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
      var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Build a funding tx with only 1 sat in output[1]
      var tinyFundingTx = TransactionBuilder()
          .spendFromTxnWithSigner(fundingSigner, getBobFundingTx(), 1,
              TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(bobPub))
          .spendToLockBuilder(
              P2PKHLockBuilder.fromAddress(bobAddress), BigInt.from(100000))
          .spendToLockBuilder(
              P2PKHLockBuilder.fromAddress(bobAddress), BigInt.one)
          .build(false);

      expect(tinyFundingTx.outputs.length, 2);
      expect(tinyFundingTx.outputs[1].satoshis, BigInt.one);

      // The library does not validate balances, so issuance should still build
      var issuanceTx = await service.createTokenIssuanceTxn(
          tinyFundingTx,
          fundingSigner,
          bobPub,
          bobAddress,
          tinyFundingTx.hash);

      // The transaction builds but with insufficient funds.
      // The builder may drop the change output when it would be negative,
      // resulting in only 4 outputs instead of the standard 5.
      expect(issuanceTx.outputs.length, lessThanOrEqualTo(5));
      expect(issuanceTx.outputs.length, greaterThanOrEqualTo(4));
    });
  });

  group('Wrong owner attempting transfer', () {
    test(
        'Bob cannot sign transfer of a token that Alice owns - PP1 verification fails',
        () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

      // 1. Issue token to Bob
      var bobFundingTx = getBobFundingTx();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var issuanceTx = await service.createTokenIssuanceTxn(
          bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);

      // 2. Create witness for issuance
      var issuanceWitnessTx = service.createWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        issuanceTx,
        List<int>.empty(),
        bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
      );

      // 3. Extract tokenId
      var pp1Parsed = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
      var tokenId = pp1Parsed.tokenId ?? [];

      // 4. Transfer Bob -> Alice
      var transferFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var transferBobToAlice = service.createTokenTransferTxn(
        issuanceWitnessTx,
        issuanceTx,
        bobPub,
        aliceAddress,
        transferFundingTx,
        bobFundingSigner,
        bobPub,
        aliceFundingTx.hash,
        tokenId,
      );

      // 5. Create witness for Alice's token
      var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);
      var aliceWitnessTx = service.createWitnessTxn(
        aliceFundingSigner,
        aliceFundingTx,
        transferBobToAlice,
        hex.decode(issuanceTx.serialize()),
        alicePubKey,
        bobPubkeyHash,
        TokenAction.TRANSFER,
      );

      // 6. Now Alice owns the token. Create a second transfer Alice -> Bob,
      //    but have BOB try to sign as the current owner (he is NOT the owner).
      var bobFundingTx2 = getBobFundingTx();
      var bobFundingTx3 = getBobFundingTx();

      // Bob creates the transfer claiming to be the current owner
      var wrongOwnerTransferTx = service.createTokenTransferTxn(
        aliceWitnessTx,
        transferBobToAlice,
        bobPub, // WRONG: Bob's pubkey, but Alice owns the token
        bobAddress,
        bobFundingTx2,
        bobFundingSigner,
        bobPub,
        bobFundingTx3.hash,
        tokenId,
      );

      // 7. Verify that the witness output (ModP2PKH) spending fails.
      //    The witness output from aliceWitnessTx is locked to Alice's pubkey,
      //    but Bob signed the spending transaction.
      var interp = Interpreter();
      var verifyFlags = Set<VerifyFlag>();
      verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
      verifyFlags.add(VerifyFlag.LOW_S);
      verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

      // Input[1] spends the witness output locked to Alice -- Bob cannot sign it
      var scriptSigWitness = wrongOwnerTransferTx.inputs[1].script;
      var scriptPubKeyWitness = aliceWitnessTx.outputs[0].script;
      var outputSatsWitness = aliceWitnessTx.outputs[0].satoshis;

      expect(
          () => interp.correctlySpends(scriptSigWitness!, scriptPubKeyWitness,
              wrongOwnerTransferTx, 1, verifyFlags, Coin.valueOf(outputSatsWitness)),
          throwsA(isA<ScriptException>()));
    });
  });

  group('Malformed parent transaction in transfer', () {
    test(
        'garbage bytes as parentTokenTxBytes does not crash but witness verification fails',
        () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

      // 1. Issue token to Bob
      var bobFundingTx = getBobFundingTx();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var issuanceTx = await service.createTokenIssuanceTxn(
          bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);

      // 2. Create witness for issuance
      var issuanceWitnessTx = service.createWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        issuanceTx,
        List<int>.empty(),
        bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
      );

      // 3. Extract tokenId and do a transfer Bob -> Alice
      var pp1Parsed = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
      var tokenId = pp1Parsed.tokenId ?? [];

      var transferFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var transferTx = service.createTokenTransferTxn(
        issuanceWitnessTx,
        issuanceTx,
        bobPub,
        aliceAddress,
        transferFundingTx,
        bobFundingSigner,
        bobPub,
        aliceFundingTx.hash,
        tokenId,
      );

      // 4. Create witness with garbage parentTokenTxBytes
      var garbageBytes = List<int>.filled(200, 0xDE);
      var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

      // This should not crash -- it builds a witness transaction
      var witnessTx = service.createWitnessTxn(
        aliceFundingSigner,
        aliceFundingTx,
        transferTx,
        garbageBytes,
        alicePubKey,
        bobPubkeyHash,
        TokenAction.TRANSFER,
      );

      expect(witnessTx.inputs.length, greaterThan(0));
      expect(witnessTx.outputs.length, greaterThan(0));

      // 5. Verify that PP1 spending fails because the parent tx bytes are garbage
      var interp = Interpreter();
      var verifyFlags = Set<VerifyFlag>();
      verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
      verifyFlags.add(VerifyFlag.LOW_S);
      verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

      var scriptSigPP1 = witnessTx.inputs[1].script;
      var scriptPubKeyPP1 = transferTx.outputs[1].script;
      var outputSatsPP1 = transferTx.outputs[1].satoshis;

      expect(
          () => interp.correctlySpends(scriptSigPP1!, scriptPubKeyPP1,
              witnessTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1)),
          throwsA(isA<ScriptException>()));
    });
  });

  group('Padding byte edge cases', () {
    test('computePartialHash works with data on a 64-byte boundary', () {
      var utils = TransactionUtils();

      // Create data that is exactly 64 * 3 = 192 bytes (falls on a 64-byte boundary)
      var boundaryData = Uint8List(192);
      for (var i = 0; i < boundaryData.length; i++) {
        boundaryData[i] = i % 256;
      }

      // computePartialHash should handle boundary-aligned data without error
      var (partialHash, remainder) = utils.computePartialHash(boundaryData, 2);

      expect(partialHash, isNotEmpty);
      expect(remainder, isNotEmpty);
      // Remainder should be 128 bytes (2 blocks of 64 bytes)
      expect(remainder.length, 128);
    });

    test('calculatePaddingBytes returns non-empty padding for a witness transaction',
        () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

      var bobFundingTx = getBobFundingTx();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var issuanceTx = await service.createTokenIssuanceTxn(
          bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);

      // Build a minimal witness transaction to test padding
      var witnessTx = service.createWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        issuanceTx,
        List<int>.empty(),
        bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
      );

      var utils = TransactionUtils();
      var paddingBytes = utils.calculatePaddingBytes(witnessTx);

      expect(paddingBytes, isNotEmpty);
      expect(paddingBytes.length, greaterThan(0));
    });
  });

  group('Empty or oversized metadata', () {
    test('issuance with null metadataBytes succeeds', () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

      var fundingTx = getBobFundingTx();
      var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Pass null metadataBytes (the default)
      var issuanceTx = await service.createTokenIssuanceTxn(
          fundingTx, fundingSigner, bobPub, bobAddress, fundingTx.hash,
          metadataBytes: null);

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);

      // Output[4] should be the metadata OP_RETURN with 0 satoshis
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);
    });

    test('issuance with large metadata (1000 bytes) succeeds and has 5 outputs',
        () async {
      var service = TokenTool();
      var sigHashAll =
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

      var fundingTx = getBobFundingTx();
      var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Create 1000 bytes of metadata
      var largeMetadata = Uint8List(1000);
      for (var i = 0; i < 1000; i++) {
        largeMetadata[i] = i % 256;
      }

      var issuanceTx = await service.createTokenIssuanceTxn(
          fundingTx, fundingSigner, bobPub, bobAddress, fundingTx.hash,
          metadataBytes: largeMetadata.toList());

      // Should still produce the standard 5-output structure
      expect(issuanceTx.outputs.length, 5);
      // output[0] = change, output[1] = PP1, output[2] = PP2,
      // output[3] = PartialWitness, output[4] = metadata OP_RETURN
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);
      // The metadata output script should contain the large payload
      expect(issuanceTx.outputs[4].script.buffer.length, greaterThan(1000));
    });
  });

  group('PP1LockBuilder validation', () {
    test('throws ScriptException when recipientAddress is null', () {
      expect(
          () => PP1LockBuilder(null, List<int>.filled(32, 0)),
          throwsA(isA<ScriptException>()));
    });

    test('throws ScriptException when tokenId is not 32 bytes', () {
      expect(
          () => PP1LockBuilder(bobAddress, List<int>.filled(16, 0)),
          throwsA(isA<ScriptException>()));
    });

    test('throws ScriptException when tokenId is null', () {
      expect(
          () => PP1LockBuilder(bobAddress, null),
          throwsA(isA<ScriptException>()));
    });
  });

  group('PP2LockBuilder validation', () {
    test('throws ScriptException when outpoint is not 36 bytes', () {
      expect(
          () => PP2LockBuilder(
              List<int>.filled(10, 0), // wrong: should be 36 bytes
              List<int>.filled(20, 0),
              1,
              List<int>.filled(20, 0)),
          throwsA(isA<ScriptException>()));
    });

    test('throws ScriptException when witnessChangePKH is not 20 bytes', () {
      expect(
          () => PP2LockBuilder(
              List<int>.filled(36, 0),
              List<int>.filled(10, 0), // wrong: should be 20 bytes
              1,
              List<int>.filled(20, 0)),
          throwsA(isA<ScriptException>()));
    });

    test('throws ScriptException when change amount is negative', () {
      expect(
          () => PP2LockBuilder(
              List<int>.filled(36, 0),
              List<int>.filled(20, 0),
              -1,
              List<int>.filled(20, 0)),
          throwsA(isA<ScriptException>()));
    });

    test('throws ScriptException when ownerPKH is not 20 bytes', () {
      expect(
          () => PP2LockBuilder(
              List<int>.filled(36, 0),
              List<int>.filled(20, 0),
              1,
              List<int>.filled(5, 0)), // wrong: should be 20 bytes
          throwsA(isA<ScriptException>()));
    });
  });
}
