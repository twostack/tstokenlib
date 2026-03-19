import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';

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

late List<int> rabinPubKeyHash;
late List<int> rabinNBytes;
late List<int> rabinSBytes;
late int rabinPaddingValue;
late List<int> dummyIdentityTxId;
late List<int> dummyEd25519PubKey;

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
  setUpAll(() {
    var kp = Rabin.generateKeyPair(1024);
    rabinNBytes = Rabin.bigIntToScriptNum(kp.n).toList();
    rabinPubKeyHash = hash160(rabinNBytes);
    dummyIdentityTxId = List<int>.generate(32, (i) => i + 1);
    dummyEd25519PubKey = List<int>.generate(32, (i) => i + 0x41);
    var messageBytes = [...dummyIdentityTxId, ...dummyEd25519PubKey];
    var messageHash = Rabin.sha256ToScriptInt(messageBytes);
    var sig = Rabin.sign(messageHash, kp.p, kp.q);
    rabinSBytes = Rabin.bigIntToScriptNum(sig.s).toList();
    rabinPaddingValue = sig.padding;
  });

  group('Full lifecycle: issue -> transfer -> transfer -> burn', () {
    test('Bob issues, transfers to Alice, Alice transfers back to Bob, Bob burns',
        timeout: Timeout(Duration(minutes: 2)), () async {
      var service = TokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);

      // --- Step 1: Bob issues a token ---
      var bobFundingTx = getBobFundingTx();
      var issuanceTx = await service.createTokenIssuanceTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash, rabinPubKeyHash,
      );
      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);

      // Extract tokenId from issuance PP1
      var pp1Lock = PP1NftLockBuilder.fromScript(issuanceTx.outputs[1].script);
      var tokenId = pp1Lock.tokenId ?? [];
      expect(tokenId.isNotEmpty, true);

      // --- Step 2: Create issuance witness for Bob ---
      var issuanceWitnessTx = service.createWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        issuanceTx,
        List<int>.empty(), // no parent for issuance
        bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      expect(issuanceWitnessTx.outputs.length, 1);

      // --- Step 3: Bob transfers to Alice ---
      var transferFundingTx1 = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var firstTransferTx = service.createTokenTransferTxn(
        issuanceWitnessTx,
        issuanceTx,
        bobPub,
        aliceAddress,
        transferFundingTx1,
        bobFundingSigner,
        bobPub,
        aliceFundingTx.hash, // recipient's witness funding txid
        tokenId,
      );
      expect(firstTransferTx.outputs.length, 5);

      // --- Step 4: Create transfer witness for Alice ---
      var aliceWitnessTx = service.createWitnessTxn(
        aliceFundingSigner,
        aliceFundingTx,
        firstTransferTx,
        hex.decode(issuanceTx.serialize()), // parentTokenTxBytes
        alicePubKey,
        bobPubkeyHash, // tokenChangePKH = previous owner
        TokenAction.TRANSFER,
      );
      expect(aliceWitnessTx.outputs.length, 1);

      // --- Step 5: Alice transfers back to Bob ---
      var transferFundingTx2 = getAliceFundingTx();
      var bobFundingTx2 = getBobFundingTx();
      var secondTransferTx = service.createTokenTransferTxn(
        aliceWitnessTx,
        firstTransferTx,
        alicePubKey,
        bobAddress,
        transferFundingTx2,
        aliceFundingSigner,
        alicePubKey,
        bobFundingTx2.hash, // recipient's witness funding txid
        tokenId,
      );
      expect(secondTransferTx.outputs.length, 5);

      // --- Step 6: Create transfer witness for Bob ---
      var bobWitnessTx = service.createWitnessTxn(
        bobFundingSigner,
        bobFundingTx2,
        secondTransferTx,
        hex.decode(firstTransferTx.serialize()), // parentTokenTxBytes
        bobPub,
        alicePubkeyHash, // tokenChangePKH = previous owner (Alice)
        TokenAction.TRANSFER,
      );
      expect(bobWitnessTx.outputs.length, 1);

      // --- Step 7: Bob burns the token ---
      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createBurnTokenTxn(
        secondTransferTx,
        bobFundingSigner,
        bobPub,
        burnFundingTx,
        bobFundingSigner,
        bobPub,
      );

      // Burn tx should have only 1 output (change)
      expect(burnTx.outputs.length, 1);
      // 4 inputs: funding, PP1, PP2, PartialWitness
      expect(burnTx.inputs.length, 4);

      // --- Step 8: Verify burn spending (PP1, PP2, PartialWitness) ---
      var interp = Interpreter();
      var verifyFlags = Set<VerifyFlag>();
      verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
      verifyFlags.add(VerifyFlag.LOW_S);
      verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);
      verifyFlags.add(VerifyFlag.MINIMALDATA);

      // Verify PP1 burn spending (input[1] spends secondTransferTx output[1])
      var scriptSigPP1 = burnTx.inputs[1].script;
      var scriptPubKeyPP1 = secondTransferTx.outputs[1].script;
      var outputSatsPP1 = secondTransferTx.outputs[1].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigPP1!, scriptPubKeyPP1, burnTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1)),
          returnsNormally);

      // Verify PP2 burn spending (input[2] spends secondTransferTx output[2])
      var scriptSigPP2 = burnTx.inputs[2].script;
      var scriptPubKeyPP2 = secondTransferTx.outputs[2].script;
      var outputSatsPP2 = secondTransferTx.outputs[2].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigPP2!, scriptPubKeyPP2, burnTx, 2, verifyFlags, Coin.valueOf(outputSatsPP2)),
          returnsNormally);

      // Verify PartialWitness burn spending (input[3] spends secondTransferTx output[3])
      var scriptSigPW = burnTx.inputs[3].script;
      var scriptPubKeyPW = secondTransferTx.outputs[3].script;
      var outputSatsPW = secondTransferTx.outputs[3].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigPW!, scriptPubKeyPW, burnTx, 3, verifyFlags, Coin.valueOf(outputSatsPW)),
          returnsNormally);

      // --- Step 9: Verify intermediate script spending works ---
      // Verify the first transfer spends the issuance witness (ModP2PKH) correctly
      var scriptSigWitness1 = firstTransferTx.inputs[1].script;
      var scriptPubKeyWitness1 = issuanceWitnessTx.outputs[0].script;
      var outputSatsWitness1 = issuanceWitnessTx.outputs[0].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigWitness1!, scriptPubKeyWitness1, firstTransferTx, 1, verifyFlags, Coin.valueOf(outputSatsWitness1)),
          returnsNormally);

      // Verify the first transfer spends the PartialWitness (PP3) from issuance
      var scriptSigPP3_1 = firstTransferTx.inputs[2].script;
      var scriptPubKeyPP3_1 = issuanceTx.outputs[3].script;
      var outputSatsPP3_1 = issuanceTx.outputs[3].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigPP3_1!, scriptPubKeyPP3_1, firstTransferTx, 2, verifyFlags, Coin.valueOf(outputSatsPP3_1)),
          returnsNormally);

      // Verify the second transfer spends Alice's witness (ModP2PKH) correctly
      var scriptSigWitness2 = secondTransferTx.inputs[1].script;
      var scriptPubKeyWitness2 = aliceWitnessTx.outputs[0].script;
      var outputSatsWitness2 = aliceWitnessTx.outputs[0].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigWitness2!, scriptPubKeyWitness2, secondTransferTx, 1, verifyFlags, Coin.valueOf(outputSatsWitness2)),
          returnsNormally);

      // Verify the second transfer spends the PartialWitness (PP3) from first transfer
      var scriptSigPP3_2 = secondTransferTx.inputs[2].script;
      var scriptPubKeyPP3_2 = firstTransferTx.outputs[3].script;
      var outputSatsPP3_2 = firstTransferTx.outputs[3].satoshis;
      expect(
          () => interp.correctlySpends(
              scriptSigPP3_2!, scriptPubKeyPP3_2, secondTransferTx, 2, verifyFlags, Coin.valueOf(outputSatsPP3_2)),
          returnsNormally);
    });
  });

  group('Mainnet vs testnet configuration', () {
    test('TokenTool can be constructed with both network types', () {
      var testnetTool = TokenTool(networkType: NetworkType.TEST);
      var mainnetTool = TokenTool(networkType: NetworkType.MAIN);
      expect(testnetTool.networkType, NetworkType.TEST);
      expect(mainnetTool.networkType, NetworkType.MAIN);
    });

    test('createTokenIssuanceTxn works with testnet configuration', () async {
      var service = TokenTool(networkType: NetworkType.TEST);
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var fundingTx = getBobFundingTx();
      var testnetAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);

      var issuanceTx = await service.createTokenIssuanceTxn(
        fundingTx, bobFundingSigner, bobPub, testnetAddress, fundingTx.hash, rabinPubKeyHash,
      );

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);
    });

    test('createTokenIssuanceTxn works with mainnet configuration', () async {
      var service = TokenTool(networkType: NetworkType.MAIN);
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var fundingTx = getBobFundingTx();
      var mainnetAddress = Address.fromPublicKey(bobPub, NetworkType.MAIN);

      var issuanceTx = await service.createTokenIssuanceTxn(
        fundingTx, bobFundingSigner, bobPub, mainnetAddress, fundingTx.hash, rabinPubKeyHash,
      );

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);
    });
  });

  group('Fee calculation across different transaction sizes', () {
    test('custom fee of 200 sats produces different change than default', () async {
      var defaultService = TokenTool(); // defaultFee = 135
      var customService = TokenTool(defaultFee: BigInt.from(200));
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      // Issue tokens with both services
      var fundingTx1 = getBobFundingTx();
      var issuanceTx1 = await defaultService.createTokenIssuanceTxn(
        fundingTx1, bobFundingSigner, bobPub, bobAddress, fundingTx1.hash, rabinPubKeyHash,
      );
      var witnessTx1 = defaultService.createWitnessTxn(
        bobFundingSigner, fundingTx1, issuanceTx1,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock1 = PP1NftLockBuilder.fromScript(issuanceTx1.outputs[1].script);
      var tokenId1 = pp1Lock1.tokenId ?? [];
      var transferFundingTx1 = getBobFundingTx();
      var aliceFundingTx1 = getAliceFundingTx();
      var transferTx1 = defaultService.createTokenTransferTxn(
        witnessTx1, issuanceTx1, bobPub, aliceAddress,
        transferFundingTx1, bobFundingSigner, bobPub,
        aliceFundingTx1.hash, tokenId1,
      );

      var fundingTx2 = getBobFundingTx();
      var issuanceTx2 = await customService.createTokenIssuanceTxn(
        fundingTx2, bobFundingSigner, bobPub, bobAddress, fundingTx2.hash, rabinPubKeyHash,
      );
      var witnessTx2 = customService.createWitnessTxn(
        bobFundingSigner, fundingTx2, issuanceTx2,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock2 = PP1NftLockBuilder.fromScript(issuanceTx2.outputs[1].script);
      var tokenId2 = pp1Lock2.tokenId ?? [];
      var transferFundingTx2 = getBobFundingTx();
      var aliceFundingTx2 = getAliceFundingTx();
      var transferTx2 = customService.createTokenTransferTxn(
        witnessTx2, issuanceTx2, bobPub, aliceAddress,
        transferFundingTx2, bobFundingSigner, bobPub,
        aliceFundingTx2.hash, tokenId2,
      );

      // Change output is output[0] in transfer tx
      var changeDefault = transferTx1.outputs[0].satoshis;
      var changeCustom = transferTx2.outputs[0].satoshis;

      // Higher fee means less change
      expect(changeCustom < changeDefault, true,
          reason: 'Fee of 200 should leave less change than default fee of 135');
      expect(changeDefault - changeCustom, BigInt.from(65),
          reason: 'Difference should be 200 - 135 = 65 sats');
    });

    test('fee of 50 sats leaves more change than default', () async {
      var defaultService = TokenTool(); // defaultFee = 135
      var lowFeeService = TokenTool(defaultFee: BigInt.from(50));
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      var fundingTx1 = getBobFundingTx();
      var issuanceTx1 = await defaultService.createTokenIssuanceTxn(
        fundingTx1, bobFundingSigner, bobPub, bobAddress, fundingTx1.hash, rabinPubKeyHash,
      );
      var witnessTx1 = defaultService.createWitnessTxn(
        bobFundingSigner, fundingTx1, issuanceTx1,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock1 = PP1NftLockBuilder.fromScript(issuanceTx1.outputs[1].script);
      var tokenId1 = pp1Lock1.tokenId ?? [];
      var transferFundingTx1 = getBobFundingTx();
      var aliceFundingTx1 = getAliceFundingTx();
      var transferTx1 = defaultService.createTokenTransferTxn(
        witnessTx1, issuanceTx1, bobPub, aliceAddress,
        transferFundingTx1, bobFundingSigner, bobPub,
        aliceFundingTx1.hash, tokenId1,
      );

      var fundingTx2 = getBobFundingTx();
      var issuanceTx2 = await lowFeeService.createTokenIssuanceTxn(
        fundingTx2, bobFundingSigner, bobPub, bobAddress, fundingTx2.hash, rabinPubKeyHash,
      );
      var witnessTx2 = lowFeeService.createWitnessTxn(
        bobFundingSigner, fundingTx2, issuanceTx2,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock2 = PP1NftLockBuilder.fromScript(issuanceTx2.outputs[1].script);
      var tokenId2 = pp1Lock2.tokenId ?? [];
      var transferFundingTx2 = getBobFundingTx();
      var aliceFundingTx2 = getAliceFundingTx();
      var transferTx2 = lowFeeService.createTokenTransferTxn(
        witnessTx2, issuanceTx2, bobPub, aliceAddress,
        transferFundingTx2, bobFundingSigner, bobPub,
        aliceFundingTx2.hash, tokenId2,
      );

      var changeDefault = transferTx1.outputs[0].satoshis;
      var changeLow = transferTx2.outputs[0].satoshis;

      // Lower fee means more change
      expect(changeLow > changeDefault, true,
          reason: 'Fee of 50 should leave more change than default fee of 135');
      expect(changeLow - changeDefault, BigInt.from(85),
          reason: 'Difference should be 135 - 50 = 85 sats');
    });

    test('fee of 500 sats leaves significantly less change', () async {
      var defaultService = TokenTool(); // defaultFee = 135
      var highFeeService = TokenTool(defaultFee: BigInt.from(500));
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      var fundingTx1 = getBobFundingTx();
      var issuanceTx1 = await defaultService.createTokenIssuanceTxn(
        fundingTx1, bobFundingSigner, bobPub, bobAddress, fundingTx1.hash, rabinPubKeyHash,
      );
      var witnessTx1 = defaultService.createWitnessTxn(
        bobFundingSigner, fundingTx1, issuanceTx1,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock1 = PP1NftLockBuilder.fromScript(issuanceTx1.outputs[1].script);
      var tokenId1 = pp1Lock1.tokenId ?? [];
      var transferFundingTx1 = getBobFundingTx();
      var aliceFundingTx1 = getAliceFundingTx();
      var transferTx1 = defaultService.createTokenTransferTxn(
        witnessTx1, issuanceTx1, bobPub, aliceAddress,
        transferFundingTx1, bobFundingSigner, bobPub,
        aliceFundingTx1.hash, tokenId1,
      );

      var fundingTx2 = getBobFundingTx();
      var issuanceTx2 = await highFeeService.createTokenIssuanceTxn(
        fundingTx2, bobFundingSigner, bobPub, bobAddress, fundingTx2.hash, rabinPubKeyHash,
      );
      var witnessTx2 = highFeeService.createWitnessTxn(
        bobFundingSigner, fundingTx2, issuanceTx2,
        List<int>.empty(), bobPub,
        Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
        TokenAction.ISSUANCE,
        rabinN: rabinNBytes,
        rabinS: rabinSBytes,
        rabinPadding: rabinPaddingValue,
        identityTxId: dummyIdentityTxId,
        ed25519PubKey: dummyEd25519PubKey,
      );
      var pp1Lock2 = PP1NftLockBuilder.fromScript(issuanceTx2.outputs[1].script);
      var tokenId2 = pp1Lock2.tokenId ?? [];
      var transferFundingTx2 = getBobFundingTx();
      var aliceFundingTx2 = getAliceFundingTx();
      var transferTx2 = highFeeService.createTokenTransferTxn(
        witnessTx2, issuanceTx2, bobPub, aliceAddress,
        transferFundingTx2, bobFundingSigner, bobPub,
        aliceFundingTx2.hash, tokenId2,
      );

      var changeDefault = transferTx1.outputs[0].satoshis;
      var changeHigh = transferTx2.outputs[0].satoshis;

      // Much higher fee means much less change
      expect(changeHigh < changeDefault, true,
          reason: 'Fee of 500 should leave less change than default fee of 135');
      expect(changeDefault - changeHigh, BigInt.from(365),
          reason: 'Difference should be 500 - 135 = 365 sats');
    });
  });
}
