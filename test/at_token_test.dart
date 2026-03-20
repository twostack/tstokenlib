import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/pp1_at_script_gen.dart';

// Dummy Rabin PKH for tests that don't need real Rabin verification
var testRabinPubKeyHash = List<int>.filled(20, 0x99);

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

// "Issuer" / shop identity — uses Alice keys
var aliceWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey alicePrivateKey = SVPrivateKey.fromWIF(aliceWif);
SVPublicKey alicePubKey = alicePrivateKey.publicKey;
var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
var alicePubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

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

  // Rabin keypair for witness tests (generated once)
  late RabinKeyPair rabinKeyPair;
  late List<int> rabinPubKeyHash;
  late List<int> dummyIdentityTxId;
  late List<int> dummyEd25519PubKey;

  setUpAll(() {
    rabinKeyPair = Rabin.generateKeyPair(1024);
    var rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
    rabinPubKeyHash = hash160(rabinNBytes);
    dummyIdentityTxId = List<int>.generate(32, (i) => i + 1);
    dummyEd25519PubKey = List<int>.generate(32, (i) => i + 0x41);
  });

  group('AT lock builder parse roundtrip', () {
    test('139-byte header roundtrip', () {
      var ownerPKH = hex.decode(bobPubkeyHash);
      var tokenId = List<int>.filled(32, 0xAA);
      var issuerPKH = hex.decode(alicePubkeyHash);
      var rabinPKH = List<int>.filled(20, 0x99);
      var stampCount = 0;
      var threshold = 10;
      var stampsHash = List<int>.filled(32, 0x00);

      var builder = PP1AtLockBuilder(bobAddress, tokenId, issuerPKH, rabinPKH, stampCount, threshold, stampsHash);
      var script = builder.getScriptPubkey();

      var parsed = PP1AtLockBuilder.fromScript(script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.issuerPKH, issuerPKH);
      expect(parsed.rabinPubKeyHash, rabinPKH);
      expect(parsed.stampCount, stampCount);
      expect(parsed.threshold, threshold);
      expect(parsed.stampsHash, stampsHash);
      expect(hex.encode(hex.decode(parsed.recipientAddress!.address)), bobPubkeyHash);
    });

    test('139-byte header with non-zero stampCount roundtrip', () {
      var tokenId = List<int>.filled(32, 0xBB);
      var issuerPKH = hex.decode(alicePubkeyHash);
      var rabinPKH = List<int>.filled(20, 0x99);
      var stampCount = 7;
      var threshold = 10;
      var stampsHash = List<int>.generate(32, (i) => i + 1);

      var builder = PP1AtLockBuilder(bobAddress, tokenId, issuerPKH, rabinPKH, stampCount, threshold, stampsHash);
      var script = builder.getScriptPubkey();

      var parsed = PP1AtLockBuilder.fromScript(script);
      expect(parsed.stampCount, 7);
      expect(parsed.threshold, 10);
      expect(parsed.stampsHash, stampsHash);
      expect(parsed.rabinPubKeyHash, rabinPKH);
    });
  });

  group('AT issuance transaction', () {
    test('creates 5-output issuance', () {
      var service = AppendableTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var issuerPKH = hex.decode(alicePubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);
      expect(issuanceTx.outputs[0].satoshis > BigInt.zero, true);
      expect(issuanceTx.outputs[1].satoshis, BigInt.one);
      expect(issuanceTx.outputs[2].satoshis, BigInt.one);
      expect(issuanceTx.outputs[3].satoshis, BigInt.one);
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP1_AT output contains correct initial fields', () {
      var service = AppendableTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var issuerPKH = hex.decode(alicePubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      var pp1Lock = PP1AtLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.tokenId, bobFundingTx.hash, reason: 'tokenId should be funding tx hash');
      expect(pp1Lock.issuerPKH, issuerPKH, reason: 'issuerPKH should match');
      expect(pp1Lock.rabinPubKeyHash, rabinPubKeyHash, reason: 'rabinPubKeyHash should match');
      expect(pp1Lock.stampCount, 0, reason: 'initial stampCount should be 0');
      expect(pp1Lock.threshold, 10, reason: 'threshold should be 10');
      expect(pp1Lock.stampsHash, List<int>.filled(32, 0), reason: 'initial stampsHash should be zeros');
    });
  });

  group('AT burn', () {
    test('burn succeeds with owner signature', () {
      var service = AppendableTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var issuerPKH = hex.decode(alicePubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      var aliceFundingTx = getAliceFundingTx();
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var burnTx = service.createBurnTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        aliceFundingTx, aliceSigner, alicePubKey,
      );

      // Verify PP1_AT burn (output[1])
      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, scriptPubKey, burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });
  });

  group('AT redeem', () {
    test('redeem fails with 0 stamps and threshold 10', () {
      var service = AppendableTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var issuerPKH = hex.decode(alicePubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      var aliceFundingTx = getAliceFundingTx();
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var redeemTx = service.createRedeemTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        aliceFundingTx, aliceSigner, alicePubKey,
      );

      var scriptSig = redeemTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;
      var interp = Interpreter();
      expect(
          () => interp.correctlySpends(scriptSig, scriptPubKey, redeemTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()),
          reason: 'Redeem should fail: stampCount(0) < threshold(10)');
    });

    test('redeem succeeds when stampCount >= threshold', () {
      // Build a fake parent tx with PP1_AT at output[1] where stampCount=10, threshold=10
      var tokenId = List<int>.filled(32, 0xAA);
      var issuerPKH = hex.decode(alicePubkeyHash);
      var stampsHash = List<int>.filled(32, 0x11);

      var pp1Script = PP1AtScriptGen.generate(
        ownerPKH: hex.decode(bobPubkeyHash),
        tokenId: tokenId,
        issuerPKH: issuerPKH,
        rabinPubKeyHash: testRabinPubKeyHash,
        stampCount: 10,
        threshold: 10,
        stampsHash: stampsHash,
      );

      var bobSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(bobSigner, getBobFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(bobPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(bobAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      // Spend PP1_AT (output[1]) with redeem
      var redeemUnlocker = PP1AtUnlockBuilder.forRedeem(bobPub);
      var aliceFundingTx = getAliceFundingTx();
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var redeemTx = TransactionBuilder()
          .spendFromTxnWithSigner(aliceSigner, aliceFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(alicePubKey))
          .spendFromTxnWithSigner(bobSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, redeemUnlocker)
          .sendChangeToPKH(bobAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = redeemTx.inputs[1].script!;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, parentTx.outputs[1].script, redeemTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });

    test('redeem succeeds when stampCount > threshold', () {
      var tokenId = List<int>.filled(32, 0xAA);
      var issuerPKH = hex.decode(alicePubkeyHash);
      var stampsHash = List<int>.filled(32, 0x11);

      var pp1Script = PP1AtScriptGen.generate(
        ownerPKH: hex.decode(bobPubkeyHash),
        tokenId: tokenId,
        issuerPKH: issuerPKH,
        rabinPubKeyHash: testRabinPubKeyHash,
        stampCount: 15,
        threshold: 10,
        stampsHash: stampsHash,
      );

      var bobSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(bobSigner, getBobFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(bobPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(bobAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      var redeemUnlocker = PP1AtUnlockBuilder.forRedeem(bobPub);
      var aliceFundingTx = getAliceFundingTx();
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var redeemTx = TransactionBuilder()
          .spendFromTxnWithSigner(aliceSigner, aliceFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(alicePubKey))
          .spendFromTxnWithSigner(bobSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, redeemUnlocker)
          .sendChangeToPKH(bobAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = redeemTx.inputs[1].script!;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, parentTx.outputs[1].script, redeemTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });
  });

  group('AT issue witness', () {
    test('issue witness verifies with issuer signature and Rabin identity', () {
      var service = AppendableTokenTool();
      var issuerPKH = hex.decode(alicePubkeyHash);

      // Create issuance transaction (Bob is customer, Alice is issuer)
      var bobFundingTx = getBobFundingTx();
      var bobSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingTx = getAliceFundingTx();

      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobSigner, bobPub, bobAddress,
        aliceFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      // Create witness with issuer (Alice) signing + Rabin identity binding
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var witnessTx = service.createWitnessTxn(
        aliceSigner,
        aliceFundingTx,
        issuanceTx,
        hex.decode(bobFundingTx.serialize()),
        alicePubKey,
        alicePubkeyHash,
        AppendableTokenAction.ISSUANCE,
        rabinKeyPair: rabinKeyPair,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Verify PP1_AT issue (input[1])
      var scriptSig = witnessTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, scriptPubKey, witnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });
  });

  group('AT transfer witness', () {
    test('full issue → witness → transfer → witness → burn cycle', () {
      var service = AppendableTokenTool();
      var bobSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var interp = Interpreter();
      var issuerPKH = hex.decode(alicePubkeyHash);

      // Step 1: Issue AT (Bob is owner, Alice is issuer)
      var bobFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobSigner, bobPub, bobAddress,
        aliceFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );
      var tokenId = bobFundingTx.hash;

      // Step 2: Issue witness (Alice signs as issuer + Rabin identity)
      var issueWitnessTx = service.createWitnessTxn(
        aliceSigner, aliceFundingTx, issuanceTx,
        hex.decode(bobFundingTx.serialize()),
        alicePubKey, alicePubkeyHash,
        AppendableTokenAction.ISSUANCE,
        rabinKeyPair: rabinKeyPair,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Verify issue witness PP1_AT
      interp.correctlySpends(
          issueWitnessTx.inputs[1].script!, issuanceTx.outputs[1].script,
          issueWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one));

      // Step 3: Bob transfers to Alice
      var transferFundingTx = getBobFundingTx();
      var aliceWitnessFundingTx = getAliceFundingTx();
      var transferTx = service.createTokenTransferTxn(
        issueWitnessTx, issuanceTx, bobPub, aliceAddress,
        transferFundingTx, bobSigner, bobPub,
        aliceWitnessFundingTx.hash, tokenId,
      );
      expect(transferTx.outputs.length, 5);

      // Verify PP1_AT in transfer has correct recipient
      var transferPP1 = PP1AtLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(hex.encode(hex.decode(transferPP1.recipientAddress!.address)), alicePubkeyHash);

      // Verify PP3/PartialWitness spending in transfer
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, issuanceTx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(issuanceTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in transfer should verify');

      // Step 4: Transfer witness (Alice, new owner, signs)
      // changePKH is Bob's (current owner) since transfer sends change to current owner
      var transferWitnessTx = service.createWitnessTxn(
        aliceSigner, aliceWitnessFundingTx, transferTx,
        hex.decode(issuanceTx.serialize()),
        alicePubKey, bobPubkeyHash,
        AppendableTokenAction.TRANSFER,
      );

      // Verify PP1_AT transferToken spending in witness
      var scriptSigPP1 = transferWitnessTx.inputs[1].script!;
      var scriptPubKeyPP1 = transferTx.outputs[1].script;
      expect(
          () => interp.correctlySpends(scriptSigPP1, scriptPubKeyPP1,
              transferWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'PP1_AT transferToken spending should verify');

      // Verify clean stack
      var stackInterp = Interpreter();
      var stack = InterpreterStack<List<int>>();
      stackInterp.executeScript(transferWitnessTx, 1, scriptSigPP1, stack, BigInt.one, verifyFlags);
      stackInterp.executeScript(transferWitnessTx, 1, scriptPubKeyPP1, stack, BigInt.one, verifyFlags);
      expect(stack.length, 1, reason: 'PP1_AT transfer witness must leave clean stack');

      // Step 5: Alice burns the token
      var burnFundingTx = getAliceFundingTx();
      var burnTx = service.createBurnTokenTxn(
        transferTx, aliceSigner, alicePubKey,
        burnFundingTx, aliceSigner, alicePubKey,
      );

      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, transferTx.outputs[1].script,
              burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'PP1_AT burn after transfer should verify');
    });
  });

  group('AT stamp witness', () {
    test('issue → witness → stamp → stamp witness verifies', () {
      var service = AppendableTokenTool();
      var bobSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var interp = Interpreter();
      var issuerPKH = hex.decode(alicePubkeyHash);

      // Step 1: Issue AT (Bob is owner, Alice is issuer, threshold=10)
      var bobFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var issuanceTx = service.createTokenIssuanceTxn(
        bobFundingTx, bobSigner, bobPub, bobAddress,
        aliceFundingTx.hash, issuerPKH, rabinPubKeyHash, 10,
      );

      // Step 2: Issue witness (Alice signs as issuer + Rabin identity)
      var issueWitnessTx = service.createWitnessTxn(
        aliceSigner, aliceFundingTx, issuanceTx,
        hex.decode(bobFundingTx.serialize()),
        alicePubKey, alicePubkeyHash,
        AppendableTokenAction.ISSUANCE,
        rabinKeyPair: rabinKeyPair,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Step 3: Alice stamps the token
      var stampMetadata = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);
      var stampFundingTx = getAliceFundingTx();
      var stampWitnessFundingTx = getAliceFundingTx();
      var stampTx = service.createTokenStampTxn(
        issueWitnessTx, issuanceTx, alicePubKey,
        stampFundingTx, aliceSigner, alicePubKey,
        stampWitnessFundingTx.hash, stampMetadata,
      );
      expect(stampTx.outputs.length, 5);

      // Verify PP1_AT in stamp has updated stampCount and stampsHash
      var stampPP1 = PP1AtLockBuilder.fromScript(stampTx.outputs[1].script);
      expect(stampPP1.stampCount, 1, reason: 'stampCount should be incremented to 1');

      // Verify rolling hash computed correctly
      var expectedNewStamp = crypto.sha256.convert(stampMetadata).bytes;
      var parentStampsHash = List<int>.filled(32, 0); // initial
      var expectedNewHash = crypto.sha256.convert([...parentStampsHash, ...expectedNewStamp]).bytes;
      expect(stampPP1.stampsHash, expectedNewHash, reason: 'stampsHash should match rolling hash');

      // Owner should be unchanged
      expect(hex.encode(hex.decode(stampPP1.recipientAddress!.address)), bobPubkeyHash);

      // Verify PP3/PartialWitness spending in stamp
      expect(
          () => interp.correctlySpends(
              stampTx.inputs[2].script!, issuanceTx.outputs[3].script,
              stampTx, 2, verifyFlags, Coin.valueOf(issuanceTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in stamp should verify');

      // Step 4: Stamp witness (Alice, issuer, signs)
      var stampWitnessTx = service.createWitnessTxn(
        aliceSigner, stampWitnessFundingTx, stampTx,
        hex.decode(issuanceTx.serialize()),
        alicePubKey, alicePubkeyHash,
        AppendableTokenAction.STAMP,
        stampMetadata: stampMetadata,
      );

      // Verify PP1_AT stampToken spending in witness
      expect(
          () => interp.correctlySpends(
              stampWitnessTx.inputs[1].script!, stampTx.outputs[1].script,
              stampWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'PP1_AT stampToken spending should verify');
    });
  });
}
