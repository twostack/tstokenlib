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

// Dummy 20-byte Rabin pubkey hash for testing (used for burn/redeem-only tests)
var testRabinPubKeyHash = List<int>.filled(20, 0xAB);

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

  group('RNFT issuance transaction', () {
    test('creates 5-output issuance with flags=0x00 (free transfer)', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x00,
      );

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);

      // Output[0]: Change (P2PKH)
      expect(issuanceTx.outputs[0].satoshis > BigInt.zero, true,
          reason: 'Change output should have satoshis');

      // Output[1]: PP1_RNFT (1 sat)
      expect(issuanceTx.outputs[1].satoshis, BigInt.one);

      // Output[2]: PP2 (1 sat)
      expect(issuanceTx.outputs[2].satoshis, BigInt.one);

      // Output[3]: PartialWitness (1 sat)
      expect(issuanceTx.outputs[3].satoshis, BigInt.one);

      // Output[4]: Metadata (0 sat)
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP1_RNFT output contains correct fields', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x01,
      );

      var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.tokenId, bobFundingTx.hash, reason: 'tokenId should be funding tx hash');
      expect(pp1Lock.flags, 0x01, reason: 'flags should be 0x01 (self-transfer only)');
      expect(pp1Lock.rabinPubKeyHash, testRabinPubKeyHash, reason: 'rabinPubKeyHash should match');
      expect(pp1Lock.hasCompanion, false, reason: 'no companion token');
    });

    test('PP1_RNFT with companion token', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var companionId = List<int>.filled(32, 0xCC);

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x08,
        companionTokenId: companionId,
      );

      var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.flags, 0x08, reason: 'flags should be 0x08 (composition required)');
      expect(pp1Lock.hasCompanion, true, reason: 'should have companion token');
      expect(pp1Lock.companionTokenId, companionId, reason: 'companion ID should match');
    });
  });

  group('RNFT lock builder parse roundtrip', () {
    test('77-byte header (no companion) roundtrip', () {
      var ownerPKH = hex.decode(bobPubkeyHash);
      var tokenId = List<int>.filled(32, 0xAA);
      var rabinPKH = testRabinPubKeyHash;
      var flags = 0x03;

      var builder = PP1RnftLockBuilder(bobAddress, tokenId, rabinPKH, flags);
      var script = builder.getScriptPubkey();

      var parsed = PP1RnftLockBuilder.fromScript(script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.rabinPubKeyHash, rabinPKH);
      expect(parsed.flags, flags);
      expect(parsed.hasCompanion, false);
      expect(hex.encode(hex.decode(parsed.recipientAddress!.address)), bobPubkeyHash);
    });

    test('110-byte header (with companion) roundtrip', () {
      var tokenId = List<int>.filled(32, 0xBB);
      var rabinPKH = testRabinPubKeyHash;
      var companionId = List<int>.filled(32, 0xDD);
      var flags = 0x09;

      var builder = PP1RnftLockBuilder(bobAddress, tokenId, rabinPKH, flags, companionTokenId: companionId);
      var script = builder.getScriptPubkey();

      var parsed = PP1RnftLockBuilder.fromScript(script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.rabinPubKeyHash, rabinPKH);
      expect(parsed.flags, flags);
      expect(parsed.hasCompanion, true);
      expect(parsed.companionTokenId, companionId);
    });
  });

  group('RNFT burn transaction', () {
    test('burn RNFT with flags=0x00 using Interpreter.correctlySpends', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      // Issue token
      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x00,
      );

      // Burn token
      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      // Verify PP1_RNFT burn spends correctly
      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });

    test('burn RNFT with flags=0x01 (self-transfer only) - burn still works', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x01,
      );

      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });

    test('burn RNFT with flags=0x02 (non-transferable) - burn still works', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x02,
      );

      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });
  });

  group('RNFT redeem transaction', () {
    test('redeem RNFT with Interpreter.correctlySpends', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x04, // one-time redeem
      );

      var redeemFundingTx = getBobFundingTx();
      var redeemTx = service.createRedeemTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        redeemFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = redeemTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, redeemTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });
  });

  group('RNFT all flag values', () {
    for (var flags in [0x00, 0x01, 0x02, 0x04, 0x05, 0x06]) {
      test('issue and burn with flags=0x${flags.toRadixString(16).padLeft(2, "0")}', () async {
        var service = RestrictedTokenTool();
        var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
        var bobFundingTx = getBobFundingTx();

        var issuanceTx = await service.createTokenIssuanceTxn(
          bobFundingTx, bobFundingSigner, bobPub, bobAddress,
          bobFundingTx.hash, testRabinPubKeyHash, flags,
        );

        // Verify issuance creates 5 outputs
        expect(issuanceTx.outputs.length, 5);

        // Parse back the PP1_RNFT
        var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
        expect(pp1Lock.flags, flags);

        // Burn should always work regardless of flags
        var burnFundingTx = getBobFundingTx();
        var burnTx = service.createBurnTokenTxn(
          issuanceTx, bobFundingSigner, bobPub,
          burnFundingTx, bobFundingSigner, bobPub,
        );

        var scriptSig = burnTx.inputs[1].script!;
        var scriptPubKey = issuanceTx.outputs[1].script;

        var interp = Interpreter();
        interp.correctlySpends(
          scriptSig, scriptPubKey, burnTx, 1,
          verifyFlags,
          Coin.valueOf(BigInt.from(1)),
        );
      });
    }
  });

  group('RNFT with companion token header', () {
    test('issue and burn with companion token (110-byte header)', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();
      var companionId = List<int>.filled(32, 0xEE);

      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x08,
        companionTokenId: companionId,
      );

      expect(issuanceTx.outputs.length, 5);

      var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.flags, 0x08);
      expect(pp1Lock.hasCompanion, true);
      expect(pp1Lock.companionTokenId, companionId);

      // Burn
      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        issuanceTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });
  });

  group('RNFT issue witness', () {
    test('issue witness with Rabin identity binding verifies PP1_RNFT', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      // Issue with real Rabin pubkey hash
      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00,
      );

      // Compute Rabin signature over sha256(identityTxId || ed25519PubKey)
      var concat = [...dummyIdentityTxId, ...dummyEd25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, rabinKeyPair.p, rabinKeyPair.q);
      var rabinN = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
      var rabinS = Rabin.bigIntToScriptNum(sig.s).toList();

      // Create issue witness
      var witnessFundingTx = getBobFundingTx();
      var witnessTx = service.createWitnessTxn(
        bobFundingSigner, witnessFundingTx, issuanceTx,
        hex.decode(bobFundingTx.serialize()), // parentTokenTxBytes (funding tx for issuance)
        bobPub, bobPubkeyHash,
        RestrictedTokenAction.ISSUANCE,
        rabinN: rabinN,
        rabinS: rabinS,
        rabinPadding: sig.padding,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      expect(witnessTx.outputs.length, 1);

      var interp = Interpreter();
      expect(
          () => interp.correctlySpends(
              witnessTx.inputs[1].script!, issuanceTx.outputs[1].script,
              witnessTx, 1, verifyFlags, Coin.valueOf(issuanceTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RNFT issueToken should verify');
    });
  });

  group('RNFT transfer transaction', () {
    test('full issue → witness → transfer → witness → burn cycle', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Step 1: Issue RNFT to Bob (flags=0x00, free transfer)
      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00,
      );
      var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId!;

      // Step 2: Issue witness (Rabin identity binding)
      var concat = [...dummyIdentityTxId, ...dummyEd25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, rabinKeyPair.p, rabinKeyPair.q);
      var rabinN = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
      var rabinS = Rabin.bigIntToScriptNum(sig.s).toList();

      var witnessFundingTx = getBobFundingTx();
      var issueWitnessTx = service.createWitnessTxn(
        bobFundingSigner, witnessFundingTx, issuanceTx,
        hex.decode(bobFundingTx.serialize()),
        bobPub, bobPubkeyHash,
        RestrictedTokenAction.ISSUANCE,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: sig.padding,
        identityTxId: dummyIdentityTxId, ed25519PubKey: dummyEd25519PubKey,
      );

      // Step 3: Bob transfers RNFT to Alice
      var transferFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var transferTx = service.createTokenTransferTxn(
        issueWitnessTx, issuanceTx, bobPub, aliceAddress,
        transferFundingTx, bobFundingSigner, bobPub,
        aliceFundingTx.hash, tokenId,
      );
      expect(transferTx.outputs.length, 5);

      // Verify PP1_RNFT in transfer has correct recipient
      var transferPP1 = PP1RnftLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(hex.encode(hex.decode(transferPP1.recipientAddress!.address)), alicePubkeyHash);

      // Verify PP3/PartialWitness spending in transfer
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, issuanceTx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(issuanceTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in transfer should verify');

      // Step 4: Alice's transfer witness (exercises transferToken inductive proof)
      var aliceWitnessFundingTx = getAliceFundingTx();
      var transferWitnessTx = service.createWitnessTxn(
        aliceFundingSigner, aliceWitnessFundingTx, transferTx,
        hex.decode(issuanceTx.serialize()), // parentTokenTxBytes
        alicePubKey, bobPubkeyHash,
        RestrictedTokenAction.TRANSFER,
      );
      expect(transferWitnessTx.outputs.length, 1);

      // Verify PP1_RNFT transferToken spending in witness
      expect(
          () => interp.correctlySpends(
              transferWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
              transferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RNFT transferToken spending should verify');

      // Step 5: Alice burns the token
      var burnFundingTx = getAliceFundingTx();
      var burnTx = service.createBurnTokenTxn(
        transferTx, aliceFundingSigner, alicePubKey,
        burnFundingTx, aliceFundingSigner, alicePubKey,
      );

      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, transferTx.outputs[1].script,
              burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RNFT burn after transfer should verify');
    });

    test('self-transfer-only policy (flags=0x01) allows self-transfer', () async {
      var service = RestrictedTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Issue with flags=0x01 (self-transfer only)
      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x01,
      );
      var pp1Lock = PP1RnftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId!;

      // Issue witness
      var concat = [...dummyIdentityTxId, ...dummyEd25519PubKey];
      var messageHash = Rabin.sha256ToScriptInt(concat);
      var sig = Rabin.sign(messageHash, rabinKeyPair.p, rabinKeyPair.q);
      var rabinN = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
      var rabinS = Rabin.bigIntToScriptNum(sig.s).toList();

      var witnessFundingTx = getBobFundingTx();
      var issueWitnessTx = service.createWitnessTxn(
        bobFundingSigner, witnessFundingTx, issuanceTx,
        hex.decode(bobFundingTx.serialize()),
        bobPub, bobPubkeyHash,
        RestrictedTokenAction.ISSUANCE,
        rabinN: rabinN, rabinS: rabinS, rabinPadding: sig.padding,
        identityTxId: dummyIdentityTxId, ed25519PubKey: dummyEd25519PubKey,
      );

      // Self-transfer: Bob → Bob
      var transferFundingTx = getBobFundingTx();
      var bobWitnessFundingTx = getBobFundingTx();
      var transferTx = service.createTokenTransferTxn(
        issueWitnessTx, issuanceTx, bobPub, bobAddress,
        transferFundingTx, bobFundingSigner, bobPub,
        bobWitnessFundingTx.hash, tokenId,
      );

      // Transfer witness (exercises transferToken with self-only policy)
      var transferWitnessTx = service.createWitnessTxn(
        bobFundingSigner, bobWitnessFundingTx, transferTx,
        hex.decode(issuanceTx.serialize()),
        bobPub, bobPubkeyHash,
        RestrictedTokenAction.TRANSFER,
      );

      var scriptSigPP1 = transferWitnessTx.inputs[1].script!;
      var scriptPubKeyPP1 = transferTx.outputs[1].script;
      var pp1Sats = transferTx.outputs[1].satoshis;
      expect(
          () => interp.correctlySpends(scriptSigPP1, scriptPubKeyPP1,
              transferWitnessTx, 1, verifyFlags, Coin.valueOf(pp1Sats)),
          returnsNormally,
          reason: 'PP1_RNFT self-transfer with flags=0x01 should verify');

      // Verify clean stack
      var stackInterp = Interpreter();
      var stack = InterpreterStack<List<int>>();
      stackInterp.executeScript(transferWitnessTx, 1, scriptSigPP1, stack, pp1Sats, verifyFlags);
      stackInterp.executeScript(transferWitnessTx, 1, scriptPubKeyPP1, stack, pp1Sats, verifyFlags);
      expect(stack.length, 1, reason: 'PP1_RNFT transfer witness must leave clean stack');
    });
  });
}
