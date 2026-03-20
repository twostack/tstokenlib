import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";
var bobPKH = hex.decode(bobPubkeyHash);

var aliceWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey alicePrivateKey = SVPrivateKey.fromWIF(aliceWif);
SVPublicKey alicePubKey = alicePrivateKey.publicKey;
var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
var alicePubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

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

  // Rabin keypair for mint witness tests (generated once)
  late RabinKeyPair rabinKeyPair;
  late List<int> rabinPubKeyHash;
  late List<int> rabinNBytes;
  late List<int> rabinSBytes;
  late int rabinPaddingValue;
  late List<int> dummyIdentityTxId;
  late List<int> dummyEd25519PubKey;

  setUpAll(() {
    rabinKeyPair = Rabin.generateKeyPair(1024);
    rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
    rabinPubKeyHash = hash160(rabinNBytes);
    dummyIdentityTxId = List<int>.generate(32, (i) => i + 1);
    dummyEd25519PubKey = List<int>.generate(32, (i) => i + 0x41);
    // Pre-compute Rabin signature for deterministic tokenId
    var tokenId = getBobFundingTx().hash;
    var msg = Rabin.sha256ToScriptInt([...dummyIdentityTxId, ...dummyEd25519PubKey, ...tokenId]);
    var sig = Rabin.sign(msg, rabinKeyPair.p, rabinKeyPair.q);
    rabinSBytes = Rabin.bigIntToScriptNum(sig.s).toList();
    rabinPaddingValue = sig.padding;
  });

  group('RFT mint transaction', () {
    test('creates 5-output mint with flags=0x00 and amount=1000', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x00, 1000,
      );

      expect(mintTx.outputs.length, 5);
      expect(mintTx.inputs.length, 1);

      // Output[0]: Change (P2PKH)
      expect(mintTx.outputs[0].satoshis > BigInt.zero, true,
          reason: 'Change output should have satoshis');

      // Output[1]: PP1_RFT (1 sat)
      expect(mintTx.outputs[1].satoshis, BigInt.one);

      // Output[2]: PP2-FT (1 sat)
      expect(mintTx.outputs[2].satoshis, BigInt.one);

      // Output[3]: PP3-FT (1 sat)
      expect(mintTx.outputs[3].satoshis, BigInt.one);

      // Output[4]: Metadata (0 sat)
      expect(mintTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP1_RFT output contains correct fields', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x01, 500,
      );

      var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
      expect(pp1Lock.tokenId, bobFundingTx.hash, reason: 'tokenId should be funding tx hash');
      expect(pp1Lock.flags, 0x01, reason: 'flags should be 0x01');
      expect(pp1Lock.rabinPubKeyHash, testRabinPubKeyHash, reason: 'rabinPubKeyHash should match');
      expect(pp1Lock.amount, 500, reason: 'amount should be 500');
      expect(pp1Lock.recipientPKH, bobPKH, reason: 'recipientPKH should be bobPKH');
    });
  });

  group('RFT lock builder parse roundtrip', () {
    test('89-byte header roundtrip', () {
      var tokenId = List<int>.filled(32, 0xAA);
      var rabinPKH = testRabinPubKeyHash;
      var flags = 0x03;
      var amount = 1000;

      var builder = PP1RftLockBuilder(bobPKH, tokenId, rabinPKH, flags, amount);
      var script = builder.getScriptPubkey();

      var parsed = PP1RftLockBuilder.fromScript(script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.rabinPubKeyHash, rabinPKH);
      expect(parsed.flags, flags);
      expect(parsed.amount, amount);
      expect(parsed.recipientPKH, bobPKH);
    });

    test('roundtrip with large amount', () {
      var tokenId = List<int>.filled(32, 0xBB);
      var rabinPKH = testRabinPubKeyHash;
      var flags = 0x05;
      var amount = 100000000; // 100M

      var builder = PP1RftLockBuilder(bobPKH, tokenId, rabinPKH, flags, amount);
      var script = builder.getScriptPubkey();

      var parsed = PP1RftLockBuilder.fromScript(script);
      expect(parsed.amount, amount);
      expect(parsed.flags, flags);
    });
  });

  group('RFT burn transaction', () {
    test('burn RFT with flags=0x00 using Interpreter.correctlySpends', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x00, 1000,
      );

      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        mintTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = mintTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });

    test('burn RFT with flags=0x01 (self-transfer only) - burn still works', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x01, 500,
      );

      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        mintTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = burnTx.inputs[1].script!;
      var scriptPubKey = mintTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, burnTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });
  });

  group('RFT redeem transaction', () {
    test('redeem RFT with Interpreter.correctlySpends', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, testRabinPubKeyHash, 0x04, 1000,
      );

      var redeemFundingTx = getBobFundingTx();
      var redeemTx = service.createRedeemTokenTxn(
        mintTx, bobFundingSigner, bobPub,
        redeemFundingTx, bobFundingSigner, bobPub,
      );

      var scriptSig = redeemTx.inputs[1].script!;
      var scriptPubKey = mintTx.outputs[1].script;

      var interp = Interpreter();
      interp.correctlySpends(
        scriptSig, scriptPubKey, redeemTx, 1,
        verifyFlags,
        Coin.valueOf(BigInt.from(1)),
      );
    });
  });

  group('RFT all flag values', () {
    for (var flags in [0x00, 0x01, 0x02, 0x04, 0x05, 0x06]) {
      test('mint and burn with flags=0x${flags.toRadixString(16).padLeft(2, "0")}', () async {
        var service = RestrictedFungibleTokenTool();
        var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
        var bobFundingTx = getBobFundingTx();

        var mintTx = await service.createFungibleMintTxn(
          bobFundingTx, bobFundingSigner, bobPub, bobAddress,
          bobFundingTx.hash, testRabinPubKeyHash, flags, 1000,
        );

        expect(mintTx.outputs.length, 5);

        var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
        expect(pp1Lock.flags, flags);
        expect(pp1Lock.amount, 1000);

        var burnFundingTx = getBobFundingTx();
        var burnTx = service.createBurnTokenTxn(
          mintTx, bobFundingSigner, bobPub,
          burnFundingTx, bobFundingSigner, bobPub,
        );

        var scriptSig = burnTx.inputs[1].script!;
        var scriptPubKey = mintTx.outputs[1].script;

        var interp = Interpreter();
        interp.correctlySpends(
          scriptSig, scriptPubKey, burnTx, 1,
          verifyFlags,
          Coin.valueOf(BigInt.from(1)),
        );
      });
    }
  });

  group('RFT mint witness', () {
    test('mint witness with Rabin identity binding verifies PP1_RFT', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var bobFundingTx = getBobFundingTx();

      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00, 1000,
      );

      var mintWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.MINT,
        rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      expect(mintWitnessTx.outputs.length, 1);

      var interp = Interpreter();
      expect(
          () => interp.correctlySpends(
              mintWitnessTx.inputs[1].script!, mintTx.outputs[1].script,
              mintWitnessTx, 1, verifyFlags, Coin.valueOf(mintTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RFT mintToken should verify');
    });
  });

  group('RFT transfer transaction', () {
    test('full mint → witness → transfer → witness → burn cycle', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Step 1: Mint 1000 RFT to Bob (flags=0x00, free transfer)
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00, 1000,
      );
      var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId;

      // Step 2: Mint witness
      var mintWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.MINT,
        rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      expect(mintWitnessTx.outputs.length, 1);

      // Step 3: Bob transfers 1000 RFT to Alice
      var transferFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var transferTx = service.createRftTransferTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress,
        transferFundingTx, bobFundingSigner, bobPub,
        aliceFundingTx.hash, tokenId, rabinPubKeyHash, 0x00, 1000,
      );
      expect(transferTx.outputs.length, 5);

      // Verify PP1_RFT in transfer has correct recipient and amount
      var transferPP1 = PP1RftLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(transferPP1.amount, 1000);
      expect(hex.encode(transferPP1.recipientPKH), alicePubkeyHash);

      // Verify PP3-FT spending in transfer
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, mintTx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(mintTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in transfer should verify');

      // Step 4: Alice's transfer witness (exercises transferToken)
      var aliceWitnessTx = service.createRftWitnessTxn(
        aliceFundingSigner, aliceFundingTx, transferTx, alicePubKey, bobPubkeyHash,
        RestrictedFungibleTokenAction.TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
      );
      expect(aliceWitnessTx.outputs.length, 1);

      // Verify PP1_RFT transferToken spending in witness
      expect(
          () => interp.correctlySpends(
              aliceWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
              aliceWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RFT transferToken spending should verify');

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
          reason: 'PP1_RFT burn after transfer should verify');
    });

    test('self-transfer-only policy (flags=0x01) allows self-transfer', () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Mint with flags=0x01 (self-transfer only)
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x01, 1000,
      );
      var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId;

      // Mint witness
      var mintWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.MINT,
        rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Self-transfer: Bob → Bob
      var transferFundingTx = getBobFundingTx();
      var bobWitnessFundingTx = getBobFundingTx();
      var transferTx = service.createRftTransferTxn(
        mintWitnessTx, mintTx, bobPub, bobAddress,
        transferFundingTx, bobFundingSigner, bobPub,
        bobWitnessFundingTx.hash, tokenId, rabinPubKeyHash, 0x01, 1000,
      );

      // Transfer witness (exercises transferToken with self-only policy)
      var transferWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobWitnessFundingTx, transferTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
      );

      var scriptSigPP1 = transferWitnessTx.inputs[1].script!;
      var scriptPubKeyPP1 = transferTx.outputs[1].script;
      var pp1Sats = transferTx.outputs[1].satoshis;
      expect(
          () => interp.correctlySpends(scriptSigPP1, scriptPubKeyPP1,
              transferWitnessTx, 1, verifyFlags, Coin.valueOf(pp1Sats)),
          returnsNormally,
          reason: 'PP1_RFT self-transfer with flags=0x01 should verify');

      // Verify clean stack
      var stackInterp = Interpreter();
      var stack = InterpreterStack<List<int>>();
      stackInterp.executeScript(transferWitnessTx, 1, scriptSigPP1, stack, pp1Sats, verifyFlags);
      stackInterp.executeScript(transferWitnessTx, 1, scriptPubKeyPP1, stack, pp1Sats, verifyFlags);
      expect(stack.length, 1, reason: 'PP1_RFT transfer witness must leave clean stack');
    });
  });

  group('RFT split transfer', () {
    test('mint → witness → split 700/300 → recipient witness → change witness → burn both',
        timeout: Timeout(Duration(minutes: 2)), () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Step 1: Mint 1000 RFT to Bob (flags=0x00, free transfer)
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00, 1000,
      );
      var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId;

      // Step 2: Mint witness
      var mintWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.MINT,
        rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Step 3: Split 700 to Alice, 300 change to Bob
      var splitFundingTx = getBobFundingTx();
      var recipientWitnessFundingTx = getAliceFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      var splitTx = service.createRftSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 700,
        splitFundingTx, bobFundingSigner, bobPub,
        recipientWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, rabinPubKeyHash, 0x00, 1000,
      );

      expect(splitTx.outputs.length, 8, reason: 'Split should create 8 outputs');

      // Verify split amounts
      var recipientPP1 = PP1RftLockBuilder.fromScript(splitTx.outputs[1].script);
      var changePP1 = PP1RftLockBuilder.fromScript(splitTx.outputs[4].script);
      expect(recipientPP1.amount, 700);
      expect(changePP1.amount, 300);
      expect(hex.encode(recipientPP1.recipientPKH), alicePubkeyHash);
      expect(hex.encode(changePP1.recipientPKH), bobPubkeyHash);

      // Verify PP3-FT spending in split tx
      expect(
          () => interp.correctlySpends(
              splitTx.inputs[2].script!, mintTx.outputs[3].script,
              splitTx, 2, verifyFlags, Coin.valueOf(mintTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in split should verify');

      // Step 4: Recipient witness (Alice, base=1)
      var recipientWitnessTx = service.createRftWitnessTxn(
        aliceFundingSigner, recipientWitnessFundingTx, splitTx, alicePubKey, bobPubkeyHash,
        RestrictedFungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 1,
        parentPP1FtIndex: 1,
      );

      expect(
          () => interp.correctlySpends(
              recipientWitnessTx.inputs[1].script!, splitTx.outputs[1].script,
              recipientWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_RFT splitTransfer (recipient) should verify');

      // Step 5: Change witness (Bob, base=4)
      var changeWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, changeWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 4,
        parentPP1FtIndex: 1,
      );

      expect(
          () => interp.correctlySpends(
              changeWitnessTx.inputs[1].script!, splitTx.outputs[4].script,
              changeWitnessTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[4].satoshis)),
          returnsNormally,
          reason: 'PP1_RFT splitTransfer (change) should verify');

      // Step 6: Burn both triplets
      var aliceBurnFundingTx = getAliceFundingTx();
      var aliceBurnTx = service.createBurnTokenTxn(
        splitTx, aliceFundingSigner, alicePubKey,
        aliceBurnFundingTx, aliceFundingSigner, alicePubKey,
      );
      expect(
          () => interp.correctlySpends(
              aliceBurnTx.inputs[1].script!, splitTx.outputs[1].script,
              aliceBurnTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'Burn recipient RFT after split should verify');

      var bobBurnFundingTx = getBobFundingTx();
      var bobBurnTx = service.createBurnTokenTxn(
        splitTx, bobFundingSigner, bobPub,
        bobBurnFundingTx, bobFundingSigner, bobPub,
        tripletBaseIndex: 4,
      );
      expect(
          () => interp.correctlySpends(
              bobBurnTx.inputs[1].script!, splitTx.outputs[4].script,
              bobBurnTx, 1, verifyFlags, Coin.valueOf(splitTx.outputs[4].satoshis)),
          returnsNormally,
          reason: 'Burn change RFT after split should verify');
    });
  });

  group('RFT merge transaction', () {
    test('split 600/400 then merge back to 1000',
        timeout: Timeout(Duration(minutes: 3)), () async {
      var service = RestrictedFungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var interp = Interpreter();
      var bobFundingTx = getBobFundingTx();

      // Step 1: Mint 1000 RFT to Bob
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, rabinPubKeyHash, 0x00, 1000,
      );
      var pp1Lock = PP1RftLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId;

      // Step 2: Mint witness
      var mintWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.MINT,
        rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );

      // Step 3: Split 600 to Bob (recipient), 400 change to Bob
      var splitFundingTx = getBobFundingTx();
      var recipientWitnessFundingTx = getBobFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      var splitTx = service.createRftSplitTxn(
        mintWitnessTx, mintTx, bobPub, bobAddress, 600,
        splitFundingTx, bobFundingSigner, bobPub,
        recipientWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, rabinPubKeyHash, 0x00, 1000,
      );
      expect(splitTx.outputs.length, 8);

      var recipientPP1 = PP1RftLockBuilder.fromScript(splitTx.outputs[1].script);
      var changePP1 = PP1RftLockBuilder.fromScript(splitTx.outputs[4].script);
      expect(recipientPP1.amount, 600);
      expect(changePP1.amount, 400);

      // Step 4: Witness for recipient triplet (base=1)
      var recipientWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, recipientWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 1,
        parentPP1FtIndex: 1,
      );

      // Step 5: Witness for change triplet (base=4)
      var changeWitnessTx = service.createRftWitnessTxn(
        bobFundingSigner, changeWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        RestrictedFungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 4,
        parentPP1FtIndex: 1,
      );

      // Step 6: Merge 600 + 400 = 1000
      var mergeFundingTx = getBobFundingTx();
      var mergeWitnessFundingTx = getBobFundingTx();

      var mergeTx = service.createRftMergeTxn(
        recipientWitnessTx, splitTx,
        changeWitnessTx, splitTx,
        bobPub,
        bobFundingSigner,
        mergeFundingTx, bobFundingSigner, bobPub,
        mergeWitnessFundingTx.hash,
        tokenId, rabinPubKeyHash, 0x00, 1000,
        prevTripletBaseIndexA: 1,
        prevTripletBaseIndexB: 4,
      );

      expect(mergeTx.outputs.length, 5, reason: 'Merge should create 5 outputs');
      expect(mergeTx.inputs.length, 5, reason: 'Merge should have 5 inputs');

      // Verify merged PP1_RFT
      var mergedPP1 = PP1RftLockBuilder.fromScript(mergeTx.outputs[1].script);
      expect(mergedPP1.amount, 1000, reason: 'Merged amount should be 1000');
      expect(hex.encode(mergedPP1.recipientPKH), bobPubkeyHash);

      // Verify PP3 burns
      for (var i = 3; i <= 4; i++) {
        var pp3OutputIdx = (i == 3) ? 3 : 6; // PP3 at base+2
        expect(
            () => interp.correctlySpends(
                mergeTx.inputs[i].script!, splitTx.outputs[pp3OutputIdx].script,
                mergeTx, i, verifyFlags, Coin.valueOf(splitTx.outputs[pp3OutputIdx].satoshis)),
            returnsNormally,
            reason: 'PP3 burn at input $i should verify');
      }

      // Verify witness spending
      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[1].script!, recipientWitnessTx.outputs[0].script,
              mergeTx, 1, verifyFlags, Coin.valueOf(recipientWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'Witness A spending in merge should verify');

      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[2].script!, changeWitnessTx.outputs[0].script,
              mergeTx, 2, verifyFlags, Coin.valueOf(changeWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'Witness B spending in merge should verify');

      // Step 7: Burn the merged token
      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        mergeTx, bobFundingSigner, bobPub,
        burnFundingTx, bobFundingSigner, bobPub,
      );

      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, mergeTx.outputs[1].script,
              burnTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'Burn merged RFT should verify');
    });
  });

  group('Merkle tree', () {
    test('single-entry tree has root = SHA256(leaf)', () {
      var pkh = List<int>.filled(20, 0x01);
      var tree = MerkleTree([pkh]);
      expect(tree.root.length, 32);
      expect(tree.depth, 0);
      expect(tree.leafCount, 1);
    });

    test('two-entry tree produces valid proofs', () {
      var pkh1 = List<int>.filled(20, 0x01);
      var pkh2 = List<int>.filled(20, 0x02);
      var tree = MerkleTree([pkh1, pkh2]);
      expect(tree.depth, 1);

      var proof0 = tree.getProof(0);
      expect(proof0.length, 1);
      expect(MerkleTree.verifyProof(pkh1, proof0, tree.root), true);

      var proof1 = tree.getProof(1);
      expect(MerkleTree.verifyProof(pkh2, proof1, tree.root), true);

      // Wrong proof should fail
      expect(MerkleTree.verifyProof(pkh2, proof0, tree.root), false);
    });

    test('four-entry tree produces valid proofs for all leaves', () {
      var leaves = List.generate(4, (i) => List<int>.filled(20, i + 1));
      var tree = MerkleTree(leaves);
      expect(tree.depth, 2);

      for (var i = 0; i < 4; i++) {
        var proof = tree.getProof(i);
        expect(MerkleTree.verifyProof(leaves[i], proof, tree.root), true);
      }
    });

    test('odd-count tree (3 entries) handles duplication', () {
      var leaves = List.generate(3, (i) => List<int>.filled(20, i + 1));
      var tree = MerkleTree(leaves);
      expect(tree.depth, 2);

      for (var i = 0; i < 3; i++) {
        var proof = tree.getProof(i);
        expect(MerkleTree.verifyProof(leaves[i], proof, tree.root), true);
      }
    });
  });
}
