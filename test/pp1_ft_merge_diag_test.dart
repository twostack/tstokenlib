import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'pp1_ft_transfer_diag_test.dart' show ScriptTracer;

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

late RabinKeyPair rabinKeyPair;
late List<int> rabinPubKeyHash;
var dummyIdentityTxId = List<int>.generate(32, (i) => i + 1);
var dummyEd25519PubKey = List<int>.generate(32, (i) => i + 0x41);

void main() {
  test('Diagnostic: merge-then-transfer with trace',
      timeout: Timeout(Duration(minutes: 3)), () async {
    var service = FungibleTokenTool();
    var bobFundingSigner = DefaultTransactionSigner(sigHashAll, bobPrivateKey);
    var aliceFundingSigner = DefaultTransactionSigner(sigHashAll, alicePrivateKey);

    rabinKeyPair = Rabin.generateKeyPair(1024);
    var rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
    rabinPubKeyHash = hash160(rabinNBytes);
    var rabinTokenId = getBobFundingTx().hash;
    var msg = Rabin.sha256ToScriptInt([...dummyIdentityTxId, ...dummyEd25519PubKey, ...rabinTokenId]);
    var sig = Rabin.sign(msg, rabinKeyPair.p, rabinKeyPair.q);
    var rabinSBytes = Rabin.bigIntToScriptNum(sig.s).toList();
    var rabinPaddingValue = sig.padding;

    // Step 1: Mint 1000 tokens
    var bobFundingTx = getBobFundingTx();
    var mintTx = await service.createFungibleMintTxn(
      bobFundingTx, bobFundingSigner, bobPub, bobAddress,
      bobFundingTx.hash, rabinPubKeyHash, 1000,
    );
    var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
    var tokenId = pp1FtLock.tokenId;

    // Step 2: Mint witness
    var mintWitnessTx = service.createFungibleWitnessTxn(
      bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
      FungibleTokenAction.MINT,
      rabinN: rabinNBytes, rabinS: rabinSBytes, rabinPadding: rabinPaddingValue,
      identityTxId: dummyIdentityTxId,
      ed25519PubKey: dummyEd25519PubKey,
    );

    // Step 3: Split 600/400
    var split1FundingTx = getBobFundingTx();
    var aliceWitnessFundingTx = getAliceFundingTx();
    var changeWitnessFundingTx = getBobFundingTx();

    var splitTx = service.createFungibleSplitTxn(
      mintWitnessTx, mintTx, bobPub, aliceAddress, 600,
      split1FundingTx, bobFundingSigner, bobPub,
      aliceWitnessFundingTx.hash, changeWitnessFundingTx.hash,
      tokenId, 1000,
    );

    // Step 4: Witnesses for split
    var recipientWitnessTx = service.createFungibleWitnessTxn(
      aliceFundingSigner, aliceWitnessFundingTx, splitTx,
      alicePubKey, bobPubkeyHash,
      FungibleTokenAction.SPLIT_TRANSFER,
      parentTokenTxBytes: hex.decode(mintTx.serialize()),
      parentOutputCount: 5,
    );

    var changeWitnessTx = service.createFungibleWitnessTxn(
      bobFundingSigner, changeWitnessFundingTx, splitTx, bobPub, bobPubkeyHash,
      FungibleTokenAction.SPLIT_TRANSFER,
      parentTokenTxBytes: hex.decode(mintTx.serialize()),
      parentOutputCount: 5,
      tripletBaseIndex: 4,
    );

    // Step 5: Merge
    var mergeFundingTx = getBobFundingTx();
    var mergeWitnessFundingTx = getBobFundingTx();

    var mergeTx = service.createFungibleMergeTxn(
      recipientWitnessTx, splitTx, changeWitnessTx, splitTx,
      bobPub, bobFundingSigner, mergeFundingTx, bobFundingSigner, bobPub,
      mergeWitnessFundingTx.hash, tokenId, 1000,
      prevTripletBaseIndexA: 1, prevTripletBaseIndexB: 4,
    );

    print('mergeTx outputs: ${mergeTx.outputs.length}');
    print('mergeTx inputs: ${mergeTx.inputs.length}');
    for (int i = 0; i < mergeTx.outputs.length; i++) {
      print('  mergeTx output[$i]: script=${mergeTx.outputs[i].script.buffer.length}B, sats=${mergeTx.outputs[i].satoshis}');
    }

    // Step 6: Merge witness (uses mergeToken placeholder — just OP_1)
    var mergeWitnessTx = service.createFungibleWitnessTxn(
      bobFundingSigner, mergeWitnessFundingTx, mergeTx, bobPub, bobPubkeyHash,
      FungibleTokenAction.MERGE,
      parentTokenTxBytes: hex.decode(splitTx.serialize()),
      parentTokenTxBytesB: hex.decode(splitTx.serialize()),
      parentOutputCount: 8,
      parentOutputCountB: 8,
      parentPP1FtIndexA: 1,
      parentPP1FtIndexB: 4,
      tripletBaseIndex: 1,
    );

    // Step 7: Transfer merged tokens to Alice
    var transferFundingTx = getBobFundingTx();
    var aliceTransferWitnessFundingTx = getAliceFundingTx();

    var transferTx = service.createFungibleTransferTxn(
      mergeWitnessTx, mergeTx, bobPub, aliceAddress,
      transferFundingTx, bobFundingSigner, bobPub,
      aliceTransferWitnessFundingTx.hash, tokenId, 1000,
    );

    print('transferTx outputs: ${transferTx.outputs.length}');
    print('transferTx inputs: ${transferTx.inputs.length}');

    // Step 8: Transfer witness
    var aliceTransferWitnessTx = service.createFungibleWitnessTxn(
      aliceFundingSigner, aliceTransferWitnessFundingTx, transferTx,
      alicePubKey, bobPubkeyHash,
      FungibleTokenAction.TRANSFER,
      parentTokenTxBytes: hex.decode(mergeTx.serialize()),
      parentOutputCount: 5,
    );

    // Step 9: Verify with trace
    var interp = Interpreter();
    var tracer = ScriptTracer(capacity: 50);
    interp.traceCallback = tracer.record;
    var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

    var scriptSigPP1 = aliceTransferWitnessTx.inputs[1].script!;
    var scriptPubKeyPP1 = transferTx.outputs[1].script;
    var pp1Sats = transferTx.outputs[1].satoshis;

    try {
      interp.correctlySpends(scriptSigPP1, scriptPubKeyPP1,
          aliceTransferWitnessTx, 1, verifyFlags, Coin.valueOf(pp1Sats));
      print('PP1_FT transferToken after merge PASSED');
    } catch (e) {
      print('PP1_FT transferToken after merge FAILED: $e');
      tracer.dump();
    }

    // Verify clean stack
    var stackInterp = Interpreter();
    var stack = InterpreterStack<List<int>>();
    stackInterp.executeScript(aliceTransferWitnessTx, 1, scriptSigPP1, stack, pp1Sats, verifyFlags);
    stackInterp.executeScript(aliceTransferWitnessTx, 1, scriptPubKeyPP1, stack, pp1Sats, verifyFlags);
    expect(stack.length, 1, reason: 'PP1_FT transfer witness (merge) must leave clean stack');
  });
}
