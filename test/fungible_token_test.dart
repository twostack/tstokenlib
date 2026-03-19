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
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

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

      // Output[1]: PP1_FT (1 sat)
      expect(mintTx.outputs[1].satoshis, BigInt.one);

      // Output[2]: PP2-FT (1 sat)
      expect(mintTx.outputs[2].satoshis, BigInt.one);

      // Output[3]: PP3-FT (1 sat)
      expect(mintTx.outputs[3].satoshis, BigInt.one);

      // Output[4]: Metadata (0 sat)
      expect(mintTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP1_FT output contains correct amount and tokenId', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 5000,
      );

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      expect(pp1FtLock.amount, 5000, reason: 'PP1_FT amount should be 5000');
      expect(pp1FtLock.tokenId, bobFundingTx.hash,
          reason: 'tokenId should be funding tx hash');
      expect(hex.encode(pp1FtLock.recipientPKH), bobPubkeyHash,
          reason: 'recipientPKH should be Bob');
    });

    test('PP2-FT output has correct indices (1,2)', () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 100,
      );

      var pp2Lock = PP2FtLockBuilder.fromScript(mintTx.outputs[2].script);
      expect(pp2Lock.pp1FtOutputIndex, 1);
      expect(pp2Lock.pp2OutputIndex, 2);
    });
  });

  group('Full lifecycle: mint -> witness -> transfer -> witness -> burn', () {
    test('Bob mints 1000 tokens, transfers to Alice, Alice burns',
        timeout: Timeout(Duration(minutes: 2)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);

      // --- Step 1: Bob mints 1000 tokens ---
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      expect(mintTx.outputs.length, 5);

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

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

      // Verify PP1_FT in transfer has correct recipient and amount
      var transferPP1_FT = PP1FtLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(transferPP1_FT.amount, 1000);
      expect(hex.encode(transferPP1_FT.recipientPKH), alicePubkeyHash);

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
      expect(burnTx.inputs.length, 4); // funding, PP1_FT, PP2-FT, PP3-FT

      // --- Step 6: Verify burn spending with interpreter ---
      var interp = Interpreter();
      var verifyFlags = Set<VerifyFlag>();
      verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
      verifyFlags.add(VerifyFlag.LOW_S);
      verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);
      verifyFlags.add(VerifyFlag.MINIMALDATA);

      // Verify PP1_FT burn spending (input[1] spends transferTx output[1])
      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, transferTx.outputs[1].script,
              burnTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_FT burn spending should verify');

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
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

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
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      // Mint 1000 tokens
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

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

      // [1] PP1_FT recipient (700 tokens to Alice)
      var recipientPP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[1].script);
      expect(recipientPP1_FT.amount, 700, reason: 'Recipient should get 700');
      expect(hex.encode(recipientPP1_FT.recipientPKH), alicePubkeyHash);
      expect(splitTx.outputs[1].satoshis, BigInt.one);

      // [2] PP2-FT recipient (indices 1,2)
      var recipientPP2 = PP2FtLockBuilder.fromScript(splitTx.outputs[2].script);
      expect(recipientPP2.pp1FtOutputIndex, 1);
      expect(recipientPP2.pp2OutputIndex, 2);
      expect(splitTx.outputs[2].satoshis, BigInt.one);

      // [3] PP3-FT recipient
      expect(splitTx.outputs[3].satoshis, BigInt.one);

      // [4] PP1_FT change (300 tokens to Bob)
      var changePP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[4].script);
      expect(changePP1_FT.amount, 300, reason: 'Change should be 300');
      expect(hex.encode(changePP1_FT.recipientPKH), bobPubkeyHash);
      expect(splitTx.outputs[4].satoshis, BigInt.one);

      // [5] PP2-FT change (indices 4,5)
      var changePP2 = PP2FtLockBuilder.fromScript(splitTx.outputs[5].script);
      expect(changePP2.pp1FtOutputIndex, 4);
      expect(changePP2.pp2OutputIndex, 5);
      expect(splitTx.outputs[5].satoshis, BigInt.one);

      // [6] PP3-FT change
      expect(splitTx.outputs[6].satoshis, BigInt.one);

      // [7] Metadata (0 sat)
      expect(splitTx.outputs[7].satoshis, BigInt.zero);

      // Verify balance conservation
      expect(recipientPP1_FT.amount + changePP1_FT.amount, 1000,
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
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

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

      var recipientPP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[1].script);
      var changePP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[4].script);
      expect(recipientPP1_FT.amount, 1);
      expect(changePP1_FT.amount, 999);
      expect(recipientPP1_FT.amount + changePP1_FT.amount, 1000);
    });
  });

  group('Burn after split', () {
    test('burn recipient triplet after split',
        timeout: Timeout(Duration(minutes: 1)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);

      // Mint and witness
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

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
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      // Mint, witness, split
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );
      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

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

  group('Merge transaction: split then merge', () {
    test('split 600/400 then merge back to 1000',
        timeout: Timeout(Duration(minutes: 3)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);

      // --- Step 1: Mint 1000 tokens ---
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

      // --- Step 2: Mint witness ---
      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      // --- Step 3: Split: 600 to Bob (recipient), 400 change to Bob ---
      var splitFundingTx = getBobFundingTx();
      var recipientWitnessFundingTx = getBobFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      var splitTx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, bobAddress, 600,
        splitFundingTx, bobFundingSigner, bobPub,
        recipientWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, 1000,
      );

      expect(splitTx.outputs.length, 8);

      // Verify split amounts
      var recipientPP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[1].script);
      var changePP1_FT = PP1FtLockBuilder.fromScript(splitTx.outputs[4].script);
      expect(recipientPP1_FT.amount, 600);
      expect(changePP1_FT.amount, 400);

      // --- Step 4: Witness for recipient triplet (base index 1) ---
      var recipientWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, recipientWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 1,
      );

      // --- Step 5: Witness for change triplet (base index 4) ---
      var changeWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, changeWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 4,
      );

      // --- Step 6: Merge 600 + 400 = 1000 ---
      var mergeFundingTx = getBobFundingTx();
      var mergeWitnessFundingTx = getBobFundingTx();

      var mergeTx = service.createFungibleMergeTxn(
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

      // Verify merge tx structure
      expect(mergeTx.outputs.length, 5, reason: 'Merge should create 5 outputs');
      expect(mergeTx.inputs.length, 5, reason: 'Merge should have 5 inputs');

      // Verify merged PP1_FT amount
      var mergedPP1_FT = PP1FtLockBuilder.fromScript(mergeTx.outputs[1].script);
      expect(mergedPP1_FT.amount, 1000, reason: 'Merged amount should be 1000');
      expect(hex.encode(mergedPP1_FT.recipientPKH), bobPubkeyHash);

      // Verify PP2-FT indices
      var mergedPP2 = PP2FtLockBuilder.fromScript(mergeTx.outputs[2].script);
      expect(mergedPP2.pp1FtOutputIndex, 1);
      expect(mergedPP2.pp2OutputIndex, 2);

      // Verify output satoshi values
      expect(mergeTx.outputs[1].satoshis, BigInt.one); // PP1_FT
      expect(mergeTx.outputs[2].satoshis, BigInt.one); // PP2-FT
      expect(mergeTx.outputs[3].satoshis, BigInt.one); // PP3-FT
      expect(mergeTx.outputs[4].satoshis, BigInt.zero); // Metadata

      // --- Step 7: Verify script execution ---
      // Input ordering: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      // Verify ModP2PKH witness A spending (input[1] spends recipientWitnessTx output[0])
      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[1].script!, recipientWitnessTx.outputs[0].script,
              mergeTx, 1, verifyFlags, Coin.valueOf(recipientWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH witness A spending in merge should verify');

      // Verify ModP2PKH witness B spending (input[2] spends changeWitnessTx output[0])
      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[2].script!, changeWitnessTx.outputs[0].script,
              mergeTx, 2, verifyFlags, Coin.valueOf(changeWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH witness B spending in merge should verify');

      // Verify PP3-FT-A burn spending (input[3] spends splitTx output[3])
      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[3].script!, splitTx.outputs[3].script,
              mergeTx, 3, verifyFlags, Coin.valueOf(splitTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT-A burn spending in merge should verify');

      // Verify PP3-FT-B burn spending (input[4] spends splitTx output[6])
      expect(
          () => interp.correctlySpends(
              mergeTx.inputs[4].script!, splitTx.outputs[6].script,
              mergeTx, 4, verifyFlags, Coin.valueOf(splitTx.outputs[6].satoshis)),
          returnsNormally,
          reason: 'PP3-FT-B burn spending in merge should verify');

      // --- Step 8: Create merge witness (exercises PP1_FT.mergeToken) ---
      var splitTxBytes = hex.decode(splitTx.serialize());
      var mergeWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, mergeWitnessFundingTx, mergeTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MERGE,
        parentTokenTxBytes: splitTxBytes,
        parentTokenTxBytesB: splitTxBytes,
        parentOutputCount: 8,
        parentOutputCountB: 8,
        parentPP1FtIndexA: 1,
        parentPP1FtIndexB: 4,
        tripletBaseIndex: 1,
      );
      expect(mergeWitnessTx.outputs.length, 1);

      // Verify PP1_FT spending in merge witness (input[1] spends mergeTx output[1])
      expect(
          () => interp.correctlySpends(
              mergeWitnessTx.inputs[1].script!, mergeTx.outputs[1].script,
              mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_FT mergeToken spending in witness should verify');

      // --- Step 9: Transfer merged tokens to Alice (proves merged UTXOs are spendable) ---
      var transferFundingTx = getBobFundingTx();
      var aliceWitnessFundingTx = getAliceFundingTx();

      var transferTx = service.createFungibleTransferTxn(
        mergeWitnessTx, mergeTx, bobPub, aliceAddress,
        transferFundingTx, bobFundingSigner, bobPub,
        aliceWitnessFundingTx.hash, tokenId, 1000,
      );

      expect(transferTx.outputs.length, 5);

      // Verify transferred PP1_FT has correct amount and recipient
      var transferPP1_FT = PP1FtLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(transferPP1_FT.amount, 1000, reason: 'Transferred amount should be 1000');
      expect(hex.encode(transferPP1_FT.recipientPKH), alicePubkeyHash,
          reason: 'Recipient should be Alice');

      // Verify PP3-FT spending in transfer (input[2] spends mergeTx output[3])
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, mergeTx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(mergeTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in post-merge transfer should verify');

      // Verify ModP2PKH witness spending (input[1] spends mergeWitnessTx output[0])
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[1].script!, mergeWitnessTx.outputs[0].script,
              transferTx, 1, verifyFlags, Coin.valueOf(mergeWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH spending in post-merge transfer should verify');

      // --- Step 10: Witness for Alice's transfer (exercises PP1_FT.transferToken on merged output) ---
      // tokenChangePKH must be Bob's PKH because the transfer tx's satoshi change goes to Bob (the sender)
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);
      var aliceWitnessTx = service.createFungibleWitnessTxn(
        aliceFundingSigner, aliceWitnessFundingTx, transferTx,
        alicePubKey, bobPubkeyHash,
        FungibleTokenAction.TRANSFER,
        parentTokenTxBytes: hex.decode(mergeTx.serialize()),
        parentOutputCount: 5,
      );
      expect(aliceWitnessTx.outputs.length, 1);

      // Verify PP1_FT spending in Alice's witness (input[1] spends transferTx output[1])
      expect(
          () => interp.correctlySpends(
              aliceWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
              aliceWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_FT transferToken spending after merge should verify');
    });
  });

  group('Split after split: spending change triplet', () {
    test('split change triplet (parentPP1FtIndex=4) then verify witnesses',
        timeout: Timeout(Duration(minutes: 3)), () async {
      var service = FungibleTokenTool();
      var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
      var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);

      // --- Step 1: Mint 1000 tokens ---
      var bobFundingTx = getBobFundingTx();
      var mintTx = await service.createFungibleMintTxn(
        bobFundingTx, bobFundingSigner, bobPub, bobAddress,
        bobFundingTx.hash, 1000,
      );

      var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
      var tokenId = pp1FtLock.tokenId;

      // --- Step 2: Mint witness ---
      var mintWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
        FungibleTokenAction.MINT,
      );

      // --- Step 3: First split: 700 to Alice, 300 change to Bob ---
      var split1FundingTx = getBobFundingTx();
      var aliceWitnessFundingTx = getAliceFundingTx();
      var changeWitnessFundingTx = getBobFundingTx();

      var split1Tx = service.createFungibleSplitTxn(
        mintWitnessTx, mintTx, bobPub, aliceAddress, 700,
        split1FundingTx, bobFundingSigner, bobPub,
        aliceWitnessFundingTx.hash, changeWitnessFundingTx.hash,
        tokenId, 1000,
      );

      expect(split1Tx.outputs.length, 8);
      var recipientPP1_FT = PP1FtLockBuilder.fromScript(split1Tx.outputs[1].script);
      var changePP1_FT = PP1FtLockBuilder.fromScript(split1Tx.outputs[4].script);
      expect(recipientPP1_FT.amount, 700);
      expect(changePP1_FT.amount, 300);
      expect(hex.encode(recipientPP1_FT.recipientPKH), alicePubkeyHash);
      expect(hex.encode(changePP1_FT.recipientPKH), bobPubkeyHash);

      // --- Step 4: Witness for change triplet (base index 4) ---
      var changeWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, changeWitnessFundingTx, split1Tx, bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(mintTx.serialize()),
        parentOutputCount: 5,
        tripletBaseIndex: 4,
      );

      // --- Step 5: Second split of change: 200 to Alice, 100 change to Bob ---
      // This exercises prevTripletBaseIndex=4 (spending from change triplet)
      var split2FundingTx = getBobFundingTx();
      var alice2WitnessFundingTx = getAliceFundingTx();
      var change2WitnessFundingTx = getBobFundingTx();

      var split2Tx = service.createFungibleSplitTxn(
        changeWitnessTx, split1Tx, bobPub, aliceAddress, 200,
        split2FundingTx, bobFundingSigner, bobPub,
        alice2WitnessFundingTx.hash, change2WitnessFundingTx.hash,
        tokenId, 300,
        prevTripletBaseIndex: 4,
      );

      expect(split2Tx.outputs.length, 8, reason: 'Second split should create 8 outputs');
      expect(split2Tx.inputs.length, 3);

      // Verify second split amounts
      var split2RecipientPP1_FT = PP1FtLockBuilder.fromScript(split2Tx.outputs[1].script);
      var split2ChangePP1_FT = PP1FtLockBuilder.fromScript(split2Tx.outputs[4].script);
      expect(split2RecipientPP1_FT.amount, 200, reason: 'Recipient should get 200');
      expect(split2ChangePP1_FT.amount, 100, reason: 'Change should be 100');
      expect(hex.encode(split2RecipientPP1_FT.recipientPKH), alicePubkeyHash);
      expect(hex.encode(split2ChangePP1_FT.recipientPKH), bobPubkeyHash);

      // Verify balance conservation
      expect(split2RecipientPP1_FT.amount + split2ChangePP1_FT.amount, 300,
          reason: 'Total should equal change amount from first split');

      var interp = Interpreter();
      var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

      // Verify PP3-FT spending in second split (input[2] spends split1Tx output[6] — change PP3)
      expect(
          () => interp.correctlySpends(
              split2Tx.inputs[2].script!, split1Tx.outputs[6].script,
              split2Tx, 2, verifyFlags, Coin.valueOf(split1Tx.outputs[6].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending from change triplet in second split should verify');

      // Verify ModP2PKH spending (input[1] spends changeWitnessTx output[0])
      expect(
          () => interp.correctlySpends(
              split2Tx.inputs[1].script!, changeWitnessTx.outputs[0].script,
              split2Tx, 1, verifyFlags, Coin.valueOf(changeWitnessTx.outputs[0].satoshis)),
          returnsNormally,
          reason: 'ModP2PKH witness spending in second split should verify');

      // --- Step 6: Witness for second split recipient (base=1, parentPP1FtIndex=4) ---
      // Parent is split1Tx (8 outputs), PP1_FT was at index 4 (change triplet)
      var alice2WitnessTx = service.createFungibleWitnessTxn(
        aliceFundingSigner, alice2WitnessFundingTx, split2Tx,
        alicePubKey, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(split1Tx.serialize()),
        parentOutputCount: 8,
        tripletBaseIndex: 1,
        parentPP1FtIndexA: 4,
      );
      expect(alice2WitnessTx.outputs.length, 1);

      // Verify PP1_FT splitTransfer spending in recipient witness
      expect(
          () => interp.correctlySpends(
              alice2WitnessTx.inputs[1].script!, split2Tx.outputs[1].script,
              alice2WitnessTx, 1, verifyFlags, Coin.valueOf(split2Tx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_FT splitTransfer (recipient) with parentPP1FtIndex=4 should verify');

      // --- Step 7: Witness for second split change (base=4, parentPP1FtIndex=4) ---
      var change2WitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, change2WitnessFundingTx, split2Tx,
        bobPub, bobPubkeyHash,
        FungibleTokenAction.SPLIT_TRANSFER,
        parentTokenTxBytes: hex.decode(split1Tx.serialize()),
        parentOutputCount: 8,
        tripletBaseIndex: 4,
        parentPP1FtIndexA: 4,
      );
      expect(change2WitnessTx.outputs.length, 1);

      // Verify PP1_FT splitTransfer spending in change witness
      expect(
          () => interp.correctlySpends(
              change2WitnessTx.inputs[1].script!, split2Tx.outputs[4].script,
              change2WitnessTx, 1, verifyFlags, Coin.valueOf(split2Tx.outputs[4].satoshis)),
          returnsNormally,
          reason: 'PP1_FT splitTransfer (change) with parentPP1FtIndex=4 should verify');

      // --- Step 8: Transfer Alice's 200 tokens to Bob (exercises transferToken with parentPP1FtIndex=4) ---
      // Alice's 200-token recipient triplet came from split2Tx (base=1)
      // But the parent of that triplet is split1Tx where PP1_FT was at index 4
      var transferFundingTx = getAliceFundingTx();
      var bobTransferWitnessFundingTx = getBobFundingTx();

      var transferTx = service.createFungibleTransferTxn(
        alice2WitnessTx, split2Tx, alicePubKey, bobAddress,
        transferFundingTx, aliceFundingSigner, alicePubKey,
        bobTransferWitnessFundingTx.hash, tokenId, 200,
      );

      expect(transferTx.outputs.length, 5);
      var transferPP1_FT = PP1FtLockBuilder.fromScript(transferTx.outputs[1].script);
      expect(transferPP1_FT.amount, 200, reason: 'Transferred amount should be 200');
      expect(hex.encode(transferPP1_FT.recipientPKH), bobPubkeyHash,
          reason: 'Recipient should be Bob');

      // Verify PP3-FT spending in transfer (input[2] spends split2Tx output[3])
      expect(
          () => interp.correctlySpends(
              transferTx.inputs[2].script!, split2Tx.outputs[3].script,
              transferTx, 2, verifyFlags, Coin.valueOf(split2Tx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PP3-FT spending in transfer-after-split should verify');

      // --- Step 9: Witness for Bob's transfer (exercises transferToken, parent=split2Tx) ---
      var bobTransferWitnessTx = service.createFungibleWitnessTxn(
        bobFundingSigner, bobTransferWitnessFundingTx, transferTx,
        bobPub, alicePubkeyHash,
        FungibleTokenAction.TRANSFER,
        parentTokenTxBytes: hex.decode(split2Tx.serialize()),
        parentOutputCount: 8,
      );
      expect(bobTransferWitnessTx.outputs.length, 1);

      // Verify PP1_FT transferToken spending in witness
      expect(
          () => interp.correctlySpends(
              bobTransferWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
              bobTransferWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis)),
          returnsNormally,
          reason: 'PP1_FT transferToken after split-change transfer should verify');
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
