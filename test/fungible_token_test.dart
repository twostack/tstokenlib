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

void main() {
  group('Fungible token mint transaction', () {
    test('creates 5-output mint transaction with correct structure', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      expect(mintTx.outputs.length, 5);
      expect(mintTx.inputs.length, 1);

      // Output[0]: Change (P2PKH)
      expect(mintTx.outputs[0].satoshis > BigInt.zero, true,
          reason: 'Change output should have satoshis');

      // Output[1]: PP5 (1 sat)
      expect(mintTx.outputs[1].satoshis, BigInt.one);

      // Output[2]: PP2-FT (1 sat)
      expect(mintTx.outputs[2].satoshis, BigInt.one);

      // Output[3]: PP3-FT (1 sat)
      expect(mintTx.outputs[3].satoshis, BigInt.one);

      // Output[4]: Metadata (0 sat)
      expect(mintTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP5 output contains correct amount and tokenId', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 5000,
      );

      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      expect(pp5Lock.amount, 5000, reason: 'PP5 amount should be 5000');
      expect(pp5Lock.tokenId, bobFundingTx.hash,
          reason: 'tokenId should be funding tx hash');
      expect(hex.encode(pp5Lock.recipientPKH), bobPubkeyHash,
          reason: 'recipientPKH should be Bob');
    });

    test('PP2-FT output has correct indices (1,2)', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 100,
      );

      var pp2Lock = PP2FtLockBuilder.fromScript(mintTx.outputs[2].script);
      expect(pp2Lock.pp5OutputIndex, 1);
      expect(pp2Lock.pp2OutputIndex, 2);
    });
  });

  group('Full lifecycle: mint -> witness -> transfer -> witness -> burn', () {
    test('Bob mints 1000 tokens, transfers to Alice, Alice burns',
        timeout: Timeout(Duration(minutes: 2)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

      // --- Step 1: Bob mints 1000 tokens ---
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      expect(mintTx.outputs.length, 5);

      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      // --- Step 2: Create mint witness for Bob ---
      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        mintTx,
        bobPub,
        bobPubkeyHash,
        FungibleTokenAction.MINT,
      );
      expect(mintWitnessTx.outputs.length, 1);

      // --- Step 3: Bob transfers 1000 tokens to Alice ---
      var transferFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var transferTx = service.createFungibleTransferTxn(
        mintWitnessTx,
        mintTx,
        bobPub,
        aliceAddress,
        transferFundingTx,
        bobFundingSigner,
        bobPub,
        aliceFundingTx.hash,
        tokenId,
        1000,
      );
      expect(transferTx.outputs.length, 5);

      // Verify PP5 in transfer has correct recipient and amount
      var transferPP5 = PP5LockBuilder.fromScript(transferTx.outputs[1].script);
      expect(transferPP5.amount, 1000);
      expect(hex.encode(transferPP5.recipientPKH), alicePubkeyHash);

      // --- Step 4: Create transfer witness for Alice ---
      var aliceWitnessTx = service.createFungibleWitnessTxn(
        aliceFundingSigner,
        aliceFundingTx,
        transferTx,
        alicePubKey,
        bobPubkeyHash,
        FungibleTokenAction.TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
      );
      expect(aliceWitnessTx.outputs.length, 1);

      // --- Step 5: Alice burns the token ---
      var burnFundingTx = getAliceFundingTx();
      var burnTx = service.createFungibleBurnTxn(
        transferTx,
        aliceFundingSigner,
        alicePubKey,
        burnFundingTx,
        aliceFundingSigner,
        alicePubKey,
      );

      expect(burnTx.outputs.length, 1);
      expect(burnTx.inputs.length, 4); // funding, PP5, PP2-FT, PP3-FT

      // --- Step 6: Verify burn spending with interpreter ---
      var interp = Interpreter();
      var verifyFlags = Set<VerifyFlag>();
      verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
      verifyFlags.add(VerifyFlag.LOW_S);
      verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

      // Verify PP5 burn spending (input[1] spends transferTx output[1])
      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, transferTx.outputs[1].script,
              burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP5 burn spending should verify');

      // Verify PP2-FT burn spending (input[2] spends transferTx output[2])
      expect(
          () => interp.correctlySpends(
              burnTx.inputs[2].script!, transferTx.outputs[2].script,
              burnTx, 2, verifyFlags, Coin.valueOf(transferTx.outputs[2].satoshis)),
          returnsNormally,
          reason: 'PP2-FT burn spending should verify');

      // Verify PP3-FT burn spending (input[3] spends transferTx output[3])
      expect(
          () => interp.correctlySpends(
              burnTx.inputs[3].script!, transferTx.outputs[3].script,
              burnTx, 3, verifyFlags, Coin.valueOf(transferTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT burn spending should verify');

      // --- Step 7: Verify PP3-FT spending in the transfer tx ---
      // Transfer tx input[2] spends mintTx output[3] (PP3-FT)
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, mintTx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(mintTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in transfer should verify');

      // Transfer tx input[1] spends mintWitnessTx output[0] (ModP2PKH)
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[1].script!, mintWitnessTx.outputs[0].script,
              transferTx, 1, verifyFlags, Coin.valueOf(mintWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH witness spending in transfer should verify');
    });
  });

  group('Burn directly after mint', () {
    test('Bob mints then burns immediately',
        timeout: Timeout(Duration(minutes: 1)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 500,
      );

      var burnFundingTx = getBobFundingTx();
      var burnTx = service.createFungibleBurnTxn(
        mintTx,
        bobFundingSigner,
        bobPub,
        burnFundingTx,
        bobFundingSigner,
        bobPub,
      );

      expect(burnTx.outputs.length, 1);
      expect(burnTx.inputs.length, 4);

      // Verify all burn spending
      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      for (var i = 1; i <= 3; i++) {
        expect(
            () => interp.correctlySpends(
                burnTx.inputs[i].script!, mintTx.outputs[i].script,
                burnTx, i, verifyFlags, Coin.valueOf(mintTx.outputs[i].satoshis)),
            returnsNormally,
            reason: 'Burn spending at input $i should verify');
      }
    });
  });

  group('Split transaction structure', () {
    test('mint -> witness -> split creates 8-output transaction',
        timeout: Timeout(Duration(minutes: 2)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Mint 1000 tokens
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      // Create mint witness
      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner,
        bobFundingTx,
        mintTx,
        bobPub,
        bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      // Split: 700 to Alice, 300 change to Bob
      var splitFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var changeFundingTx = getBobFundingTx();

      var splitTx = service.createFungibleSplitTxn(
        mintWitnessTx,
        mintTx,
        bobPub,
        aliceAddress,
        700,
        splitFundingTx,
        bobFundingSigner,
        bobPub,
        aliceFundingTx.hash,
        changeFundingTx.hash,
        tokenId,
        1000,
      );

      expect(splitTx.outputs.length, 8, reason: 'Split should create 8 outputs');
      expect(splitTx.inputs.length, 3);

      // Verify output structure
      // [0] Change (P2PKH)
      expect(splitTx.outputs[0].satoshis > BigInt.zero, true);

      // [1] PP5 recipient (700 tokens to Alice)
      var recipientPP5 = PP5LockBuilder.fromScript(splitTx.outputs[1].script);
      expect(recipientPP5.amount, 700, reason: 'Recipient should get 700');
      expect(hex.encode(recipientPP5.recipientPKH), alicePubkeyHash);
      expect(splitTx.outputs[1].satoshis, BigInt.one);

      // [2] PP2-FT recipient (indices 1,2)
      var recipientPP2 = PP2FtLockBuilder.fromScript(splitTx.outputs[2].script);
      expect(recipientPP2.pp5OutputIndex, 1);
      expect(recipientPP2.pp2OutputIndex, 2);
      expect(splitTx.outputs[2].satoshis, BigInt.one);

      // [3] PP3-FT recipient
      expect(splitTx.outputs[3].satoshis, BigInt.one);

      // [4] PP5 change (300 tokens to Bob)
      var changePP5 = PP5LockBuilder.fromScript(splitTx.outputs[4].script);
      expect(changePP5.amount, 300, reason: 'Change should be 300');
      expect(hex.encode(changePP5.recipientPKH), bobPubkeyHash);
      expect(splitTx.outputs[4].satoshis, BigInt.one);

      // [5] PP2-FT change (indices 4,5)
      var changePP2 = PP2FtLockBuilder.fromScript(splitTx.outputs[5].script);
      expect(changePP2.pp5OutputIndex, 4);
      expect(changePP2.pp2OutputIndex, 5);
      expect(splitTx.outputs[5].satoshis, BigInt.one);

      // [6] PP3-FT change
      expect(splitTx.outputs[6].satoshis, BigInt.one);

      // [7] Metadata (0 sat)
      expect(splitTx.outputs[7].satoshis, BigInt.zero);

      // Verify balance conservation
      expect(recipientPP5.amount + changePP5.amount, 1000,
          reason: 'Total should equal original amount');

      // Verify PP3-FT spending in the split tx (input[2] spends mintTx output[3])
      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      expect(
          () => interp.correctlySpends(
              splitTx.inputs[2].script!, mintTx.outputs[3].script,
              splitTx, 2, verifyFlags, Coin.valueOf(mintTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in split should verify');

      // Verify ModP2PKH spending in the split tx (input[1] spends mintWitnessTx output[0])
      expect(
          () => interp.correctlySpends(
              splitTx.inputs[1].script!, mintWitnessTx.outputs[0].script,
              splitTx, 1, verifyFlags, Coin.valueOf(mintWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH witness spending in split should verify');
    });

    test('split with minimum amounts (1 and 999)', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      var splitFundingTx = getBobFundingTx();
      var aliceFundingTx = getAliceFundingTx();
      var changeFundingTx = getBobFundingTx();

      var splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 1,
        splitFundingTx, bobFundingSigner, bobPub,
        aliceFundingTx.hash, changeFundingTx.hash, tokenId, 1000,
      );

      var recipientPP5 = PP5LockBuilder.fromScript(splitTx.outputs[1].script);
      var changePP5 = PP5LockBuilder.fromScript(splitTx.outputs[4].script);
      expect(recipientPP5.amount, 1);
      expect(changePP5.amount, 999);
      expect(recipientPP5.amount + changePP5.amount, 1000);
    });
  });

  group('Burn after split', () {
    test('burn recipient triplet after split',
        timeout: Timeout(Duration(minutes: 1)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

      // Mint and witness
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      // Split: 600 to Alice, 400 to Bob
      var splitFundingTx = getBobFundingTx();
      var splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 600,
        splitFundingTx, bobFundingSigner, bobPub,
        getAliceFundingTx().hash, getBobFundingTx().hash, tokenId, 1000,
      );

      // Burn Alice's recipient triplet (indices 1,2,3)
      var aliceBurnFundingTx = getAliceFundingTx();
      var burnTx = service.createFungibleBurnTxn(
        splitTx, aliceFundingSigner, alicePubKey,
        aliceBurnFundingTx, aliceFundingSigner, alicePubKey,
        tripletBaseIndex: 1,
      );

      expect(burnTx.outputs.length, 1);
      expect(burnTx.inputs.length, 4);

      // Verify burn spending
      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      for (var i = 1; i <= 3; i++) {
        expect(
            () => interp.correctlySpends(
                burnTx.inputs[i].script!, splitTx.outputs[i].script,
                burnTx, i, verifyFlags, Coin.valueOf(splitTx.outputs[i].satoshis)),
            returnsNormally,
            reason: 'Burn spending at input $i (recipient triplet) should verify');
      }
    });

    test('burn change triplet after split',
        timeout: Timeout(Duration(minutes: 1)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

      // Mint, witness, split
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp5Lock.tokenId;

      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      var splitFundingTx = getBobFundingTx();
      var splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 600,
        splitFundingTx, bobFundingSigner, bobPub,
        getAliceFundingTx().hash, getBobFundingTx().hash, tokenId, 1000,
      );

      // Burn Bob's change triplet (indices 4,5,6)
      var bobBurnFundingTx = getBobFundingTx();
      var burnTx = service.createFungibleBurnTxn(
        splitTx, bobFundingSigner, bobPub,
        bobBurnFundingTx, bobFundingSigner, bobPub,
        tripletBaseIndex: 4,
      );

      expect(burnTx.outputs.length, 1);
      expect(burnTx.inputs.length, 4);

      // Verify burn spending at change triplet indices (4,5,6)
      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      for (var i = 1; i <= 3; i++) {
        var outputIdx = 3 + i; // maps to outputs 4,5,6
        expect(
            () => interp.correctlySpends(
                burnTx.inputs[i].script!, splitTx.outputs[outputIdx].script,
                burnTx, i, verifyFlags, Coin.valueOf(splitTx.outputs[outputIdx].satoshis)),
            returnsNormally,
            reason: 'Burn spending at input $i (change triplet output[$outputIdx]) should verify');
      }
    });
  });

  group('FungibleTokenTool configuration', () {
    test('can be constructed with both network types', () {
      var testnetTool = FungibleTokenTool(networkType: NetworkType.TEST);
      var mainnetTool = FungibleTokenTool(networkType: NetworkType.MAIN);
      expect(testnetTool.networkType, NetworkType.TEST);
      expect(mainnetTool.networkType, NetworkType.MAIN);
    });

    test('default fee is 135 sats', () {
      var tool = FungibleTokenTool();
      expect(tool.defaultFee, BigInt.from(135));
    });

    test('custom fee is respected', () {
      var tool = FungibleTokenTool(defaultFee: BigInt.from(500));
      expect(tool.defaultFee, BigInt.from(500));
    });
  });
}
