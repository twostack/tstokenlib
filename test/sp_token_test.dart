import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/script_gen/witness_check_script_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';

// The pool coordinator.
var operatorWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey operatorPrivateKey = SVPrivateKey.fromWIF(operatorWif);
var operatorPub = operatorPrivateKey.publicKey;
Address operatorAddress = Address.fromPublicKey(operatorPub, NetworkType.TEST);
var operatorPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

// An outsider, used for the counterfeit cases.
var counterpartyWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey counterpartyPrivateKey = SVPrivateKey.fromWIF(counterpartyWif);
SVPublicKey counterpartyPub = counterpartyPrivateKey.publicKey;
var counterpartyAddress = Address.fromPublicKey(counterpartyPub, NetworkType.TEST);
var counterpartyPubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

Transaction getOperatorFundingTx() {
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

/// A second operator-owned funding UTXO. A pool coordinator signs its own
/// witnesses, so the witness funding input carries its key too. Bumping the
/// version gives a distinct txid over the same outputs.
Transaction getOperatorFundingTx2() {
  var rawTx =
      "0300000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

Transaction getCounterpartyFundingTx() {
  var rawTx =
      "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";
  return Transaction.fromHex(rawTx);
}

/// The empty-tree roots are Poseidon2 values that come from the pool's
/// configuration. Nothing in PP1 interprets them, so fixed bytes are enough.
var emptyCmRoot = List<int>.generate(32, (i) => 0xA0 + i % 16);
var emptyNfRoot = List<int>.generate(32, (i) => 0xB0 + i % 16);

PoolHeader genesisHeader() =>
    PoolHeader.genesis(emptyCmRoot: emptyCmRoot, emptyNfRoot: emptyNfRoot);

PoolHeader nextHeader(PoolHeader from) => from.advance(
      cmRoot: List<int>.generate(32, (i) => 0xC0 + i % 16),
      nfRoot: List<int>.generate(32, (i) => 0xD0 + i % 16),
      size: 7,
      balance: BigInt.from(123456789),
      outHash: List<int>.generate(32, (i) => 0xE0 + i % 16),
    );

/// A stand-in for the real verifier program: it drops the header it was built
/// with and succeeds. PP1 only ever checks its hash and the header push in
/// front of it, so the shape is what matters here, not what it proves.
final verifierBody = Uint8List.fromList([OpCodes.OP_DROP, OpCodes.OP_1]);
final decoyBody = Uint8List.fromList([OpCodes.OP_DROP, OpCodes.OP_DROP, OpCodes.OP_1]);
final verifierBodyHash = crypto.sha256.convert(verifierBody).bytes;

TransactionInput slotFunding(int n) =>
    TransactionInput(hex.encode(List.filled(32, n)), 0, 0xffffffff);

List<int> outpoint(List<int> txId, int vout) {
  var o = Uint8List(36);
  o.setAll(0, txId);
  o.buffer.asByteData().setUint32(32, vout, Endian.little);
  return o;
}

void main() {

  group('Pool header codec', () {
    test('encodes to 236 bytes and decodes back', () {
      var h = nextHeader(genesisHeader());
      var encoded = h.encode();
      expect(encoded.length, PoolHeader.byteSize);
      expect(encoded.length, 236);

      var back = PoolHeader.decode(encoded);
      expect(back.cmRoot, h.cmRoot);
      expect(back.nfRoot, h.nfRoot);
      expect(back.ring, h.ring);
      expect(back.size, h.size);
      expect(back.balance, h.balance);
      expect(back.outHash, h.outHash);
    });

    test('balance survives a value past 32 bits', () {
      var big = BigInt.two.pow(63) + BigInt.from(12345);
      var h = genesisHeader().advance(
          cmRoot: emptyCmRoot, nfRoot: emptyNfRoot, size: 0,
          balance: big, outHash: List<int>.filled(32, 0));
      expect(PoolHeader.decode(h.encode()).balance, big);
    });

    test('advance rotates the ring newest first and drops the oldest', () {
      var g = genesisHeader();
      var h1 = nextHeader(g);
      expect(h1.ring[0], h1.cmRoot);
      expect(h1.ring[1], g.ring[0]);
      expect(h1.ring.length, PoolHeader.ringEntries);
    });

    test('genesis has no leaves, no bundles and only its dust', () {
      var g = genesisHeader();
      expect(g.size, 0);
      // balance is the value PP3 actually holds, not a bookkeeping figure, and
      // PP1 checks the two are equal on every round. Opening at zero would
      // either make that invariant false or leave an unspendable output.
      expect(g.balance, BigInt.one);
      expect(g.outHash, List<int>.filled(32, 0));
      expect(g.ring.every((r) => _same(r, emptyCmRoot)), true,
          reason: 'round 1 spend proofs need a legitimate anchor');
    });

    test('rejects a wrong-length field', () {
      expect(() => PoolHeader(cmRoot: [1, 2, 3], nfRoot: emptyNfRoot,
          ring: List.generate(4, (_) => emptyCmRoot), size: 0,
          balance: BigInt.zero, outHash: List.filled(32, 0)),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP lock builder parse roundtrip', () {
    test('563-byte header roundtrip', () {
      var tokenId = List<int>.filled(32, 0xAA);
      var g = genesisHeader();
      var h = nextHeader(g);

      var script = PP1SpLockBuilder(
              operatorAddress, tokenId, verifierBodyHash, h, g.encode())
          .getScriptPubkey();

      var parsed = PP1SpLockBuilder.fromScript(script);
      expect(parsed.ownerAddress!.pubkeyHash160, operatorPubkeyHash);
      expect(parsed.tokenId, tokenId);
      expect(parsed.verifierBodyHash, verifierBodyHash);
      expect(parsed.header!.encode(), h.encode());
      expect(parsed.genesisHeader, g.encode());
    });

    test('script header byte offsets match constants', () {
      var g = genesisHeader();
      var script = PP1SpLockBuilder(operatorAddress, List<int>.filled(32, 0xCC),
              verifierBodyHash, g, g.encode())
          .getScriptPubkey();
      var buf = script.buffer;

      expect(buf[0], 0x14);                             // ownerPKH push
      expect(buf[PP1SpScriptGen.tokenIdDataStart - 1], 0x20);  // tokenId push
      expect(buf[PP1SpScriptGen.verifierBodyHashDataStart - 1], 0x20);
      // 236 bytes is past the 75-byte direct-push limit, so the header push is
      // OP_PUSHDATA1 followed by its length. That is why headerDataStart is 56
      // and not 55.
      expect(buf[PP1SpScriptGen.genesisPushStart], 0x4c);
      expect(buf[PP1SpScriptGen.genesisPushStart + 1], PoolHeader.byteSize);
      expect(buf[PP1SpScriptGen.headerPushStart], 0x4c);
      expect(buf[PP1SpScriptGen.headerPushStart + 1], PoolHeader.byteSize);
      expect(PP1SpScriptGen.genesisDataStart, 89);
      expect(PP1SpScriptGen.headerDataStart, 327);
      expect(PP1SpScriptGen.headerDataEnd, 563);
      expect(PP1SpScriptGen.scriptBodyStart, 563);

      expect(buf.sublist(PP1SpScriptGen.genesisDataStart, PP1SpScriptGen.genesisDataEnd),
          g.encode());
      expect(buf.sublist(PP1SpScriptGen.headerDataStart, PP1SpScriptGen.headerDataEnd),
          g.encode());
    });

    test('the genesis header is readable straight off the script', () {
      // It is carried in full rather than as a commitment, so a depositor can
      // check what state the pool opened on without being handed a preimage.
      var g = genesisHeader();
      var script = PP1SpLockBuilder(operatorAddress, List<int>.filled(32, 0xCC),
              verifierBodyHash, nextHeader(g), g.encode())
          .getScriptPubkey();
      expect(PP1SpLockBuilder.fromScript(script).genesisHeader, g.encode());
    });

    test('validation rejects a wrong-length tokenId', () {
      var g = genesisHeader();
      expect(() => PP1SpLockBuilder(
              operatorAddress, [1, 2, 3], verifierBodyHash, g, g.encode()),
          throwsA(isA<ScriptException>()));
    });

    test('validation rejects a wrong-length genesis header', () {
      var g = genesisHeader();
      expect(() => PP1SpLockBuilder(operatorAddress, List<int>.filled(32, 0),
              verifierBodyHash, g, [1, 2]),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SP script generation', () {
    test('generate produces a header of exactly scriptBodyStart bytes', () {
      var g = genesisHeader();
      var script = PP1SpScriptGen.generate(
        ownerPKH: hex.decode(operatorPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        verifierBodyHash: verifierBodyHash,
        header: g.encode(),
        genesisHeader: g.encode(),
      );

      var buf = script.buffer;
      expect(buf.length > PP1SpScriptGen.scriptBodyStart, true);
      expect(buf[0], 0x14);
      expect(buf.sublist(1, 21), hex.decode(operatorPubkeyHash));
    });

    test('every pool shares one script body', () {
      // The genesis header is a header field, not part of the body, so a single
      // template serves every pool.
      var g1 = genesisHeader();
      var g2 = PoolHeader.genesis(
          emptyCmRoot: List<int>.filled(32, 0x01), emptyNfRoot: emptyNfRoot);
      var tokenId = List<int>.filled(32, 0xAA);

      var a = PP1SpScriptGen.generate(
          ownerPKH: hex.decode(operatorPubkeyHash), tokenId: tokenId,
          verifierBodyHash: verifierBodyHash,
          header: g1.encode(), genesisHeader: g1.encode()).buffer;
      var b = PP1SpScriptGen.generate(
          ownerPKH: hex.decode(counterpartyPubkeyHash), tokenId: tokenId,
          verifierBodyHash: crypto.sha256.convert(decoyBody).bytes,
          header: g2.encode(), genesisHeader: g2.encode()).buffer;

      expect(a.length, b.length);
      expect(_same(a.sublist(PP1SpScriptGen.scriptBodyStart),
                   b.sublist(PP1SpScriptGen.scriptBodyStart)), true);
    });

    test('rejects a header that is not 236 bytes', () {
      var g = genesisHeader();
      expect(() => PP1SpScriptGen.generate(
          ownerPKH: hex.decode(operatorPubkeyHash),
          tokenId: List<int>.filled(32, 0xAA),
          verifierBodyHash: verifierBodyHash,
          header: [1, 2, 3], genesisHeader: g.encode()),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP issuance transaction', () {
    test('creates a 5-output issuance carrying the genesis header', () {
      var service = ShieldedPoolTool();
      var operatorSigner = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      var fundingTx = getOperatorFundingTx();
      var g = genesisHeader();

      var y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var issuanceTx = service.createTokenIssuanceTxn(
          fundingTx, operatorSigner, operatorPub, operatorAddress,
          verifierBodyHash, g, y0.outpoint, getOperatorFundingTx2().hash,
          slotTx: y0.tx);

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 2,
          reason: 'the funding that fixes tokenId, and Y_0\'s anchor');
      expect(issuanceTx.inputs[1].prevTxnId, y0.tx.id);
      expect(issuanceTx.inputs[1].prevTxnOutputIndex, 1);
      expect(issuanceTx.outputs[0].satoshis > BigInt.zero, true);
      expect(issuanceTx.outputs[1].satoshis, BigInt.one);
      expect(issuanceTx.outputs[2].satoshis, BigInt.one);
      expect(issuanceTx.outputs[3].satoshis, g.balance,
          reason: 'PP3 holds the pool balance, which at genesis is the dust');
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);

      var pp1Lock = PP1SpLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.tokenId, fundingTx.hash);
      expect(pp1Lock.ownerAddress!.pubkeyHash160, operatorPubkeyHash);
      expect(pp1Lock.verifierBodyHash, verifierBodyHash);
      expect(pp1Lock.header!.encode(), g.encode());
    });

    test('refuses to fund issuance from any output but 1', () {
      var service = ShieldedPoolTool();
      var g = genesisHeader();
      var y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      expect(() => service.createTokenIssuanceTxn(
              getOperatorFundingTx(),
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              operatorPub, operatorAddress, verifierBodyHash, g, y0.outpoint,
              getOperatorFundingTx2().hash, fundingVout: 0, slotTx: y0.tx),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP create witness', () {
    test('create witness verifies', () {
      var service = ShieldedPoolTool();
      var fundA = getOperatorFundingTx();
      var fundB = getOperatorFundingTx2();
      var signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);

      var g = genesisHeader();
      var y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var issuanceTx = service.createTokenIssuanceTxn(fundA, signer, operatorPub,
          operatorAddress, verifierBodyHash, g, y0.outpoint, fundB.hash, slotTx: y0.tx);

      var witnessTx = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE,
          slotParts: y0.parts, verifierBody: verifierBody);

      Interpreter().correctlySpends(witnessTx.inputs[1].script!,
          issuanceTx.outputs[1].script, witnessTx, 1, verifyFlags,
          Coin.valueOf(BigInt.one));
    });

    test('rejects an issuance that opens on a state other than genesis', () {
      // Without this, a coordinator could issue a pool whose commitment tree
      // already holds notes nobody deposited for. The first spend against that
      // tree would then drain a PP3 that never received the money.
      var service = ShieldedPoolTool();
      var fundA = getOperatorFundingTx();
      var fundB = getOperatorFundingTx2();
      var signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      var g = genesisHeader();
      var stuffed = nextHeader(g);
      // A genuine genesis slot and anchor, so the header is the only thing
      // wrong with this issuance.
      var y0 = genesisSlot(g);

      var issuanceTx = (TransactionBuilder()
            ..spendFromTxnWithSigner(signer, fundA, 1,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(operatorPub))
            ..spendFromTxnWithSigner(signer, y0.tx, 1,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(operatorPub))
            ..withFeePerKb(100)
            ..spendToLockBuilder(
                PP1SpLockBuilder(operatorAddress, fundA.hash, verifierBodyHash,
                    stuffed, g.encode()),
                BigInt.one)
            ..spendToLockBuilder(
                PP2LockBuilder(outpoint(fundB.hash, 1),
                    hex.decode(operatorPubkeyHash), 1, hex.decode(operatorPubkeyHash)),
                BigInt.one)
            ..spendToLockBuilder(
                PartialWitnessLockBuilder.forPool(y0.outpoint), BigInt.one)
            ..spendToLockBuilder(MetadataLockBuilder(), BigInt.zero)
            ..sendChangeToPKH(operatorAddress))
          .build(false);

      var witnessTx = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE,
          slotParts: y0.parts, verifierBody: verifierBody);

      expect(
          () => Interpreter().correctlySpends(witnessTx.inputs[1].script!,
              issuanceTx.outputs[1].script, witnessTx, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SP create certifies the genesis slot', () {
    // The round branch certifies the slot the next round spends, so before
    // this nothing ever looked at Y_0, the slot round 1 spends. A decoy Y_0
    // let round 1 run unverified with a header_1 of the coordinator's
    // choosing, and every later V would then verify faithfully from it
    // (tool/scratch/genesis_slot_probe.dart). Each issuance below is built
    // with the tool's own guard waived, as a coordinator bypassing the tool
    // would, so the refusal is witness 0's.
    var service = ShieldedPoolTool();
    var fundA = getOperatorFundingTx();
    var fundB = getOperatorFundingTx2();
    var signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
    var g = genesisHeader();
    var owner = hex.decode(operatorPubkeyHash);

    ({Transaction tx, List<int> outpoint, List<int> parts}) slot(
            {PoolHeader? header, List<int>? body, List<int>? signerPKH, int n = 0x10}) =>
        service.buildSlotTxn(
            header: header ?? g, verifierBody: body ?? verifierBody,
            fundingInput: slotFunding(n), anchorPKH: owner,
            signerPKH: signerPKH ?? owner);

    void create(({Transaction tx, List<int> outpoint, List<int> parts}) y,
        {List<int>? body, Transaction? spentAnchorOf, bool spendAnchor = true}) {
      var issuance = service.createTokenIssuanceTxn(fundA, signer, operatorPub,
          operatorAddress, verifierBodyHash, g, y.outpoint, fundB.hash,
          slotTx: spentAnchorOf ?? y.tx, uncheckedSlot: true,
          spendAnchor: spendAnchor);
      var witness = service.createWitnessTxn(signer, fundB, issuance,
          hex.decode(fundA.serialize()), operatorPub, operatorPubkeyHash,
          ShieldedPoolAction.CREATE,
          slotParts: y.parts, verifierBody: body ?? verifierBody);
      Interpreter().correctlySpends(witness.inputs[1].script!,
          issuance.outputs[1].script, witness, 1, verifyFlags,
          Coin.valueOf(BigInt.one));
    }

    test('accepts the genuine genesis slot', () {
      create(slot());
    });

    test('rejects a genesis slot holding a decoy', () {
      // Claimed honestly, the decoy fails the body hash.
      expect(() => create(slot(body: decoyBody), body: decoyBody),
          throwsA(isA<ScriptException>()));
    });

    test('rejects claiming the verifier is in a genesis slot holding a decoy', () {
      expect(() => create(slot(body: decoyBody)), throwsA(isA<ScriptException>()));
    });

    test('rejects a genesis slot built for another header', () {
      expect(() => create(slot(header: nextHeader(g))), throwsA(isA<ScriptException>()));
    });

    test('rejects a genesis slot answering to a key other than the owner', () {
      expect(() => create(slot(signerPKH: hex.decode(counterpartyPubkeyHash))),
          throwsA(isA<ScriptException>()));
    });

    test('rejects an issuance that does not spend the genesis slot\'s anchor', () {
      expect(() => create(slot(), spendAnchor: false), throwsA(isA<ScriptException>()));
    });

    test('rejects an issuance spending another transaction\'s output 1', () {
      expect(() => create(slot(), spentAnchorOf: slot(n: 0x11).tx),
          throwsA(isA<ScriptException>()));
    });

    test('a Y funded from a real output is signed, and witness 0 still certifies it', () {
      // A mined Y has to unlock its funding. The signature changes Y's input,
      // which PP1 rebuilds from `parts`, so this checks the signed input is
      // what PP1 hashes, and that the scriptSig stays under PP1's 253 bytes.
      var coins = Transaction()
        ..addInput(slotFunding(0x12))
        ..addOutput(TransactionOutput(BigInt.from(5000), P2PKHLockBuilder.fromAddress(operatorAddress).getScriptPubkey()));
      var y = service.buildSlotTxn(header: g, verifierBody: verifierBody,
          fundingTx: coins, fundingVout: 0, fundingSigner: signer, fundingPubKey: operatorPub,
          anchorPKH: owner, signerPKH: owner);
      Interpreter().correctlySpends(y.tx.inputs[0].script!, coins.outputs[0].script, y.tx, 0,
          verifyFlags, Coin.valueOf(coins.outputs[0].satoshis));
      expect(y.tx.inputs[0].script!.buffer.length, lessThan(253));
      create(y);
      expect(() => service.buildSlotTxn(header: g, verifierBody: verifierBody,
              fundingTx: coins, fundingInput: slotFunding(0x12), anchorPKH: owner, signerPKH: owner),
          throwsArgumentError);
    });

    test('the tool refuses a genesis slot witness 0 would refuse', () {
      var decoy = slot(body: decoyBody);
      expect(() => service.createTokenIssuanceTxn(fundA, signer, operatorPub,
              operatorAddress, verifierBodyHash, g, decoy.outpoint, fundB.hash,
              slotTx: decoy.tx),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP create anchors the base case', () {
    // The issuance branch never used to inspect the token transaction's own
    // inputs, so tokenId was bound to nothing on chain and anyone could mint a
    // second pool carrying the same tokenId. Both cases below were ACCEPTED
    // before the anchor check existed.

    Transaction counterfeit(List<int> tokenId, Address owner,
        Transaction funding, SVPrivateKey fundingKey) {
      var g = genesisHeader();
      var ownerPKH = hex.decode(owner.pubkeyHash160);
      return (TransactionBuilder()
            ..spendFromTxnWithSigner(
                DefaultTransactionSigner(sigHashAll, fundingKey), funding, 1,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(fundingKey.publicKey))
            ..withFeePerKb(100)
            ..spendToLockBuilder(
                PP1SpLockBuilder(owner, tokenId, verifierBodyHash, g, g.encode()),
                BigInt.one)
            ..spendToLockBuilder(
                PP2LockBuilder(outpoint(getOperatorFundingTx().hash, 1),
                    ownerPKH, 1, ownerPKH),
                BigInt.one)
            ..spendToLockBuilder(PartialWitnessLockBuilder(ownerPKH), BigInt.one)
            ..spendToLockBuilder(MetadataLockBuilder(), BigInt.zero)
            ..sendChangeToPKH(owner))
          .build(false);
    }

    void expectCreateRejected(Transaction issuance) {
      var service = ShieldedPoolTool();
      var witness = service.createWitnessTxn(
        DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
        getOperatorFundingTx2(), issuance,
        hex.decode(getOperatorFundingTx().serialize()), operatorPub,
        operatorPubkeyHash, ShieldedPoolAction.CREATE,
        slotParts: genesisSlot(genesisHeader()).parts, verifierBody: verifierBody,
      );
      expect(
          () => Interpreter().correctlySpends(witness.inputs[1].script!,
              issuance.outputs[1].script, witness, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    }

    test('rejects a second pool carrying an existing tokenId', () {
      // A PP1 script byte-identical to the genuine issuance, funded by an
      // unrelated UTXO. This is the conclusive case: the only thing that can be
      // failing is the funding outpoint.
      expectCreateRejected(counterfeit(getOperatorFundingTx().hash,
          operatorAddress, getCounterpartyFundingTx(), counterpartyPrivateKey));
    });

    test('rejects a counterfeit that names the attacker as owner', () {
      expectCreateRejected(counterfeit(getOperatorFundingTx().hash,
          counterpartyAddress, getCounterpartyFundingTx(), counterpartyPrivateKey));
    });
  });

  group('SP round', () {
    late ShieldedPoolTool service;
    late Transaction fundA, fundB, issuanceTx, createWitness;
    late DefaultTransactionSigner signer;
    late PoolHeader g, h1;
    late ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1;
    late List<int> bundles;

    setUp(() {
      service = ShieldedPoolTool();
      fundA = getOperatorFundingTx();
      fundB = getOperatorFundingTx2();
      signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      g = genesisHeader();
      bundles = PoolOutHash.encodeBundles([[1, 2, 3], [4, 5]]);
      // outHash binds the round's ciphertexts, so the header the round carries
      // has to be built around the bundles that ride in its witness.
      var base = nextHeader(g);
      h1 = PoolHeader(
          cmRoot: base.cmRoot, nfRoot: base.nfRoot, ring: base.ring,
          size: base.size, balance: BigInt.from(500000),
          outHash: PoolOutHash.roundOutHashOf(PoolOutHash.decodeBundles(bundles)));

      y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      y1 = service.buildSlotTxn(
          header: h1, verifierBody: verifierBody, fundingInput: slotFunding(0x11),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));

      issuanceTx = service.createTokenIssuanceTxn(fundA, signer, operatorPub,
          operatorAddress, verifierBodyHash, g, y0.outpoint, fundB.hash, slotTx: y0.tx);
      createWitness = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE,
          slotParts: y0.parts, verifierBody: verifierBody);
    });

    // [unchecked] waives the build-time slot check, which the negative cases
    // below need: they pin a slot PP1 will refuse on purpose, and the whole
    // point is to watch the witness refuse it.
    Transaction round(PoolHeader header, List<int> slot,
            {bool unchecked = false, Transaction? slotTx}) =>
        service.createRoundTxn(
            createWitness, issuanceTx, y0.tx, operatorPub, fundA, signer,
            operatorPub, fundB.hash, header, slot,
            nextSlotTx: slotTx ?? y1.tx,
            uncheckedNextSlot: unchecked);

    Transaction roundWitness(Transaction roundTx, {
      required PoolHeader claimedHeader,
      required List<int> claimedSlot,
      required List<int> slotParts,
      required List<int> vBody,
      required List<int> claimedBundles,
    }) =>
        service.createWitnessTxn(
            signer, fundB, roundTx, hex.decode(issuanceTx.serialize()),
            operatorPub, operatorPubkeyHash, ShieldedPoolAction.ROUND,
            newOwnerPKH: hex.decode(operatorPubkeyHash),
            newHeader: claimedHeader.encode(), nextSlot: claimedSlot,
            slotParts: slotParts, verifierBody: vBody, bundles: claimedBundles);

    void spendPP1(Transaction roundTx, Transaction witness) =>
        Interpreter().correctlySpends(witness.inputs[1].script!,
            roundTx.outputs[1].script, witness, 1, verifyFlags,
            Coin.valueOf(BigInt.one));

    Transaction honestWitness(Transaction roundTx) => roundWitness(roundTx,
        claimedHeader: h1, claimedSlot: y1.outpoint, slotParts: y1.parts,
        vBody: verifierBody, claimedBundles: bundles);

    test('issue, create witness, round, round witness', () {
      var roundTx = round(h1, y1.outpoint);
      expect(roundTx.inputs.length, 5,
          reason: 'funding, the previous witness, the verifier slot, PP3, and '
              'the next slot\'s anchor');
      expect(roundTx.inputs[4].prevTxnId, y1.tx.id);
      expect(roundTx.inputs[4].prevTxnOutputIndex, 1);
      expect(roundTx.outputs.length, 5);

      // The spend of the parent PP3 is what carries the induction forward, and
      // what refuses to happen unless the verifier slot is an input.
      Interpreter().correctlySpends(roundTx.inputs[3].script!,
          issuanceTx.outputs[3].script, roundTx, 3, verifyFlags,
          Coin.valueOf(BigInt.one));

      spendPP1(roundTx, honestWitness(roundTx));
    });

    test('PP3 holds the pool balance and names the next slot', () {
      var roundTx = round(h1, y1.outpoint);
      expect(roundTx.outputs[3].satoshis, h1.balance);
      expect(
          roundTx.outputs[3].script.buffer.sublist(
              PP1SpScriptGen.pp3NextSlotStart, PP1SpScriptGen.pp3NextSlotEnd),
          y1.outpoint);
    });

    test('the round carries the new header forward', () {
      var after = PP1SpLockBuilder.fromScript(round(h1, y1.outpoint).outputs[1].script);
      expect(after.header!.encode(), h1.encode());
      expect(after.header!.balance, h1.balance);
      expect(after.tokenId, fundA.hash, reason: 'tokenId is immutable');
      expect(after.verifierBodyHash, verifierBodyHash, reason: 'so is the verifier');
      expect(after.genesisHeader, g.encode(), reason: 'and so is the genesis');
    });

    test('the round leaves the body byte-identical to its parent', () {
      // PP1 rebuilds the next script as parent[0:1] + newPKH + parent[21:327] +
      // newHeader + parent[563:]. Anything else changing would make the round
      // unspendable.
      var parent = issuanceTx.outputs[1].script.buffer;
      var child = round(h1, y1.outpoint).outputs[1].script.buffer;
      expect(child.length, parent.length);
      expect(_same(child.sublist(PP1SpScriptGen.scriptBodyStart),
                   parent.sublist(PP1SpScriptGen.scriptBodyStart)), true);
      expect(_same(child.sublist(PP1SpScriptGen.immutableMidStart,
                                 PP1SpScriptGen.headerDataStart),
                   parent.sublist(PP1SpScriptGen.immutableMidStart,
                                  PP1SpScriptGen.headerDataStart)), true);
    });

    test('rejects a witness that claims a header the round did not build', () {
      // PP1 rebuilds the round from the pushed header and matches the result
      // against its own outpoint's txid, so a claimed header that the token
      // transaction does not actually carry cannot be made to hash correctly.
      var roundTx = round(h1, y1.outpoint);
      var lie = h1.advance(
          cmRoot: List<int>.filled(32, 0x77), nfRoot: List<int>.filled(32, 0x88),
          size: 999, balance: BigInt.from(1), outHash: List<int>.filled(32, 0x99));
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: lie, claimedSlot: y1.outpoint, slotParts: y1.parts,
              vBody: verifierBody, claimedBundles: bundles)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects bundles that do not hash to outHash', () {
      // The bundles are what lets a recipient find and open their note. They
      // ride in the witness rather than an output because of where TSL1 pays
      // for bytes; this is what stops the coordinator publishing something
      // other than what the round committed to.
      var roundTx = round(h1, y1.outpoint);
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: h1, claimedSlot: y1.outpoint, slotParts: y1.parts,
              vBody: verifierBody, claimedBundles: PoolOutHash.encodeBundles([[9, 9, 9]]))),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a slot whose verifier was built for another header', () {
      // The decisive case for the whole design. The slot really does hold this
      // pool's verifier, with the right body, spendable and everything; it was
      // simply initialised with the genesis header instead of this round's. If
      // PP1 checked only the body hash it would pass, and round N+2 would then
      // be verified against a state that is not the one it follows.
      var stale = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x12),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var roundTx = round(h1, stale.outpoint, unchecked: true, slotTx: stale.tx);
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: h1, claimedSlot: stale.outpoint,
              slotParts: stale.parts, vBody: verifierBody, claimedBundles: bundles)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a slot holding something that is not the verifier', () {
      var decoy = service.buildSlotTxn(
          header: h1, verifierBody: decoyBody, fundingInput: slotFunding(0x13),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var roundTx = round(h1, decoy.outpoint, unchecked: true, slotTx: decoy.tx);
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: h1, claimedSlot: decoy.outpoint,
              slotParts: decoy.parts, vBody: decoyBody, claimedBundles: bundles)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects claiming the verifier is in a slot that holds a decoy', () {
      var decoy = service.buildSlotTxn(
          header: h1, verifierBody: decoyBody, fundingInput: slotFunding(0x13),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var roundTx = round(h1, decoy.outpoint, unchecked: true, slotTx: decoy.tx);
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: h1, claimedSlot: decoy.outpoint,
              slotParts: decoy.parts, vBody: verifierBody, claimedBundles: bundles)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a round whose PP3 names a slot other than the certified one', () {
      // Certifying one slot and pinning another would leave round N+2 free to
      // spend an uncertified one.
      var decoy = service.buildSlotTxn(
          header: h1, verifierBody: decoyBody, fundingInput: slotFunding(0x13),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      var roundTx = round(h1, decoy.outpoint, unchecked: true, slotTx: decoy.tx);
      expect(() => spendPP1(roundTx, roundWitness(roundTx,
              claimedHeader: h1, claimedSlot: y1.outpoint, slotParts: y1.parts,
              vBody: verifierBody, claimedBundles: bundles)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a witness signed by someone other than the owner', () {
      var roundTx = round(h1, y1.outpoint);
      var outsider = DefaultTransactionSigner(sigHashAll, counterpartyPrivateKey);
      var witness = service.createWitnessTxn(
          outsider, getCounterpartyFundingTx(), roundTx,
          hex.decode(issuanceTx.serialize()), counterpartyPub,
          counterpartyPubkeyHash, ShieldedPoolAction.ROUND,
          newOwnerPKH: hex.decode(operatorPubkeyHash), newHeader: h1.encode(),
          nextSlot: y1.outpoint, slotParts: y1.parts, verifierBody: verifierBody,
          bundles: bundles);
      expect(() => spendPP1(roundTx, witness), throwsA(isA<ScriptException>()));
    });

    test('rejects a selector that names no branch', () {
      var roundTx = round(h1, y1.outpoint);
      var witness = honestWitness(roundTx);
      // Replace the trailing OP_1 with OP_2, which used to select "confirm".
      var raw = Uint8List.fromList(witness.inputs[1].script!.buffer);
      expect(raw[raw.length - 1], OpCodes.OP_1);
      raw[raw.length - 1] = OpCodes.OP_2;
      expect(
          () => Interpreter().correctlySpends(SVScript.fromByteArray(raw),
              roundTx.outputs[1].script, witness, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    });

    test('two consecutive rounds chain', () {
      // One round from genesis is not enough to exercise the chain. PP3 holds
      // the pool balance, so the sighash preimage for spending it carries that
      // value, and the genesis balance of 1 hid a hardcoded satoshi in the tool
      // until a second round was built against a funded PP3.
      var round1 = round(h1, y1.outpoint);
      var witness1 = honestWitness(round1);
      spendPP1(round1, witness1);

      var bundles2 = PoolOutHash.encodeBundles([[7, 7, 7, 7]]);
      var base2 = h1.advance(
          cmRoot: List<int>.generate(32, (i) => 0xE0 + i % 16),
          nfRoot: List<int>.generate(32, (i) => 0xF0 + i % 16),
          size: 9, balance: BigInt.from(900000), outHash: List<int>.filled(32, 0));
      var h2 = PoolHeader(
          cmRoot: base2.cmRoot, nfRoot: base2.nfRoot, ring: base2.ring,
          size: base2.size, balance: base2.balance,
          outHash: PoolOutHash.roundOutHashOf(PoolOutHash.decodeBundles(bundles2)));
      var y2 = service.buildSlotTxn(
          header: h2, verifierBody: verifierBody, fundingInput: slotFunding(0x12),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));

      var round2 = service.createRoundTxn(witness1, round1, y1.tx, operatorPub,
          fundA, signer, operatorPub, fundB.hash, h2, y2.outpoint,
          nextSlotTx: y2.tx);

      // Round 1's PP3 held 500000 satoshis, not dust, and round 2 has to spend it.
      expect(round1.outputs[3].satoshis, h1.balance);
      Interpreter().correctlySpends(round2.inputs[3].script!,
          round1.outputs[3].script, round2, 3, verifyFlags,
          Coin.valueOf(h1.balance));

      var witness2 = service.createWitnessTxn(
          signer, fundB, round2, hex.decode(round1.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.ROUND,
          newOwnerPKH: hex.decode(operatorPubkeyHash), newHeader: h2.encode(),
          nextSlot: y2.outpoint, slotParts: y2.parts, verifierBody: verifierBody,
          bundles: bundles2);
      Interpreter().correctlySpends(witness2.inputs[1].script!,
          round2.outputs[1].script, witness2, 1, verifyFlags,
          Coin.valueOf(BigInt.one));

      expect(PP1SpLockBuilder.fromScript(round2.outputs[1].script).header!.encode(),
          h2.encode());
    });

    test('the tool refuses a round that brings its own verifier slot', () {
      var stray = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x14),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      expect(() => service.createRoundTxn(createWitness, issuanceTx, stray.tx,
              operatorPub, fundA, signer, operatorPub, fundB.hash, h1,
              y1.outpoint, nextSlotTx: y1.tx),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP PP3 pins the verifier slot', () {
    // The pool's verification must be impossible to skip. PP1 cannot enforce
    // that, because it runs in the witness, after the round is already mined
    // and its withdrawals paid. PP3 can: it refuses to be spent unless the
    // verifier slot it names is also an input of the spending round.
    late Transaction opFunding, cpFunding, tokenTx, witnessTx, slotTx;
    late SVScript pp3Script;
    late List<int> partialHash, remainder;

    setUp(() {
      opFunding = getOperatorFundingTx();
      cpFunding = getCounterpartyFundingTx();
      var y0 = genesisSlot(genesisHeader());
      slotTx = y0.tx;
      var service = ShieldedPoolTool();
      tokenTx = service.createTokenIssuanceTxn(
        opFunding, DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
        operatorPub, operatorAddress, verifierBodyHash, genesisHeader(),
        y0.outpoint, cpFunding.hash, slotTx: y0.tx,
      );
      pp3Script = tokenTx.outputs[3].script;
      witnessTx = service.createWitnessTxn(
        DefaultTransactionSigner(sigHashAll, counterpartyPrivateKey),
        cpFunding, tokenTx, hex.decode(opFunding.serialize()), counterpartyPub,
        counterpartyPubkeyHash, ShieldedPoolAction.CREATE,
        slotParts: y0.parts, verifierBody: verifierBody,
      );
      var parts = TransactionUtils()
          .computePartialHash(hex.decode(witnessTx.serialize()), 2);
      partialHash = parts.$1;
      remainder = parts.$2;
    });

    var newSlot = outpoint(List<int>.filled(32, 0x77), 0);
    var pp3In = PP1SpScriptGen.poolPP3Input;
    var pp3Sighash = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_SINGLE.value;

    List<int> le8(BigInt v) {
      var o = Uint8List(8);
      o.buffer.asByteData().setUint64(0, v.toInt(), Endian.little);
      return o;
    }

    /// A round spending the issuance's PP3, built by hand so that every part
    /// the covenant looks at can be got wrong on purpose.
    ///
    /// [output3] is what the round actually carries at output 3, and
    /// [claimedSlot] and [claimedValue] are what the unlock says it carries.
    /// Honest rounds make them agree. [unlockOverride] replaces the unlocking
    /// script outright, for attacks the builder refuses to construct.
    ///
    /// [anchor] is the outpoint spent at input 4, (newSlot's txid, 1) by
    /// default, or none with [withAnchor] false; [depositFirst] puts a
    /// deposit at input 4 and the anchor after it.
    Transaction round({
      bool withSlot = true,
      bool withAnchor = true,
      List<int>? anchor,
      bool depositFirst = false,
      TransactionOutput? output3,
      bool successorAt4 = false,
      List<int>? claimedSlot,
      List<int>? claimedValue,
      List<int>? fakePartialHash,
      SVScript Function(List<int> preImage)? unlockOverride,
    }) {
      var successor = TransactionOutput(BigInt.from(777),
          PartialWitnessLockBuilder.forPool(newSlot).getScriptPubkey());
      var carried = output3 ?? successor;
      var pay = P2PKHLockBuilder.fromAddress(operatorAddress).getScriptPubkey();

      var tx = Transaction()
        ..version = 1
        ..nLockTime = 0
        ..addInput(TransactionInput(opFunding.id, 1, 0xffffffff))
        ..addInput(TransactionInput(witnessTx.id, 0, 0xffffffff));
      if (withSlot) tx.addInput(TransactionInput(slotTx.id, 0, 0xffffffff));
      tx.addInput(TransactionInput(tokenTx.id, 3, 0xffffffff));
      var a = anchor ?? outpoint(newSlot.sublist(0, 32), 1);
      var anchorIn = TransactionInput(
          hex.encode(a.sublist(0, 32).reversed.toList()),
          Uint8List.fromList(a.sublist(32)).buffer.asByteData().getUint32(0, Endian.little),
          0xffffffff);
      var deposit = TransactionInput(cpFunding.id, 0, 0xffffffff);
      if (depositFirst) tx.addInput(deposit);
      if (withAnchor) tx.addInput(anchorIn);
      tx
        ..addOutput(TransactionOutput(BigInt.from(1000), pay))
        ..addOutput(TransactionOutput(BigInt.one, pay))
        ..addOutput(TransactionOutput(BigInt.one, pay));
      if (successorAt4) {
        tx
          ..addOutput(TransactionOutput(BigInt.one, pay))
          ..addOutput(carried);
      } else {
        tx.addOutput(carried);
      }

      var at = withSlot ? pp3In : pp3In - 1;
      var pre = Sighash().createSighashPreImage(tx, pp3Sighash, at, pp3Script, BigInt.one)!;
      tx.inputs[at].script = unlockOverride != null
          ? unlockOverride(pre)
          : PartialWitnessUnlockBuilder.forPool(
                  pre, fakePartialHash ?? partialHash, remainder,
                  outpoint(opFunding.hash, 1),
                  nextSlot: claimedSlot ?? newSlot,
                  nextValue: claimedValue ?? le8(successor.satoshis))
              .getScriptSig();
      return tx;
    }

    void spendPP3(Transaction tx) {
      var at = tx.inputs.indexWhere(
          (i) => i.prevTxnId == tokenTx.id && i.prevTxnOutputIndex == 3);
      Interpreter().correctlySpends(tx.inputs[at].script!, pp3Script, tx, at,
          verifyFlags, Coin.valueOf(BigInt.one));
    }

    test('accepts a round that spends the named slot at input 2', () {
      spendPP3(round());
    });

    test('rejects a round that skips verification', () {
      expect(() => spendPP3(round(withSlot: false)), throwsA(isA<ScriptException>()));
    });

    // The anchor. Output 3 pins Y_{N+1}:0, which the round after this one
    // spends; spending Y_{N+1}:1 here is what stops this round being mined
    // while Y_{N+1} never is, which would leave the next round nothing to
    // spend and the pool frozen.
    test('rejects a round that does not spend the anchor', () {
      expect(() => spendPP3(round(withAnchor: false)), throwsA(isA<ScriptException>()));
    });

    test('rejects an anchor from a transaction other than the pinned slot', () {
      expect(() => spendPP3(round(anchor: outpoint(List<int>.filled(32, 0x78), 1))),
          throwsA(isA<ScriptException>()));
    });

    test('rejects spending the pinned slot\'s output 0 as the anchor', () {
      // Output 0 is V, which the next round has to spend. Spending it here
      // would satisfy "depends on Y" and leave the next round nothing.
      expect(() => spendPP3(round(anchor: newSlot)), throwsA(isA<ScriptException>()));
    });

    test('rejects the anchor anywhere but input 4', () {
      expect(() => spendPP3(round(depositFirst: true)), throwsA(isA<ScriptException>()));
    });

    test('still requires the witness', () {
      // The covenant is added to the witness check, not substituted for it. A
      // partial hash that does not lead to this round's witness gives the
      // wrong witness txid, and input 1 no longer matches.
      expect(() => spendPP3(round(fakePartialHash: List<int>.filled(32, 0x13))),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a round whose output 3 is a burnable PP3', () {
      // The attack the covenant exists for: carry the pool balance forward in
      // a PP3 that still has the token archetype's burn path, then burn it.
      var burnable = TransactionOutput(BigInt.from(777),
          PartialWitnessLockBuilder(hex.decode(operatorPubkeyHash)).getScriptPubkey());
      expect(() => spendPP3(round(output3: burnable)), throwsA(isA<ScriptException>()));
    });

    test('rejects a round that pays the balance out at output 3', () {
      var theft = TransactionOutput(BigInt.from(777),
          P2PKHLockBuilder.fromAddress(operatorAddress).getScriptPubkey());
      expect(() => spendPP3(round(output3: theft)), throwsA(isA<ScriptException>()));
    });

    test('rejects the successor anywhere but output 3', () {
      // SIGHASH_SINGLE ties the covenant to the output at PP3's own index, so
      // the real PP3 cannot be parked elsewhere with something weaker at 3.
      var pay = TransactionOutput(BigInt.from(777),
          P2PKHLockBuilder.fromAddress(operatorAddress).getScriptPubkey());
      expect(() => spendPP3(round(output3: pay, successorAt4: true)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects an unlock that misstates the slot output 3 pins', () {
      expect(() => spendPP3(round(claimedSlot: outpoint(List<int>.filled(32, 0x78), 0))),
          throwsA(isA<ScriptException>()));
    });

    test('leaves the value to V', () {
      // The new balance is the proof's to say, so the covenant takes whatever
      // value output 3 holds as long as the unlock states it truthfully. This
      // test pins that down so nobody mistakes the covenant for the money gate.
      var dust = TransactionOutput(BigInt.one,
          PartialWitnessLockBuilder.forPool(newSlot).getScriptPubkey());
      spendPP3(round(output3: dust, claimedValue: le8(BigInt.one)));
      expect(() => spendPP3(round(output3: dust, claimedValue: le8(BigInt.from(777)))),
          throwsA(isA<ScriptException>()));
    });

    test('rejects an anyone-can-spend prefix smuggled in through the value', () {
      // The covenant compares bytes, and an output's serialization fixes where
      // its script starts only through the varint. So a spender who could push
      // more than 8 bytes of "value" could move the varint into it and put
      // OP_1 OP_RETURN in front of the real program: same bytes, same hash,
      // and the output parses as one anyone can spend.
      var code = pp3Script.buffer;
      var body = code.sublist(37);
      var prefix = [0x51, 0x6a];                  // OP_1 OP_RETURN
      var codeVarint = [0xfd, code.length & 0xff, code.length >> 8];
      var evil = [...prefix, ...codeVarint, 0x24, ...newSlot, ...body];
      var evilVarint = [0xfd, evil.length & 0xff, evil.length >> 8];
      var evilOut = TransactionOutput(BigInt.from(777),
          SVScript.fromByteArray(Uint8List.fromList(evil)));
      var smuggled = [...le8(BigInt.from(777)), ...evilVarint, ...prefix];

      // Confirm the attack is real: what the covenant would hash is exactly
      // the serialized output, so only the length check stands in the way.
      expect(_same([...smuggled, ...codeVarint, 0x24, ...newSlot, ...body],
                   evilOut.serialize()), true);

      SVScript unlock(List<int> pre) => ScriptBuilder()
          .addData(Uint8List.fromList(smuggled))
          .addData(Uint8List.fromList(newSlot))
          .addData(Uint8List.fromList(pre))
          .addData(Uint8List.fromList(partialHash))
          .addData(Uint8List.fromList(remainder))
          .addData(Uint8List.fromList(outpoint(opFunding.hash, 1)))
          .addData(Uint8List.fromList(const <int>[]))
          .build();
      expect(() => spendPP3(round(output3: evilOut, unlockOverride: unlock)),
          throwsA(isA<ScriptException>()));
    });

    test('cannot be burned, not even by the coordinator', () {
      // An ordinary token's PP3 has a burn path, and for a token that is a
      // feature. A pool's PP3 holds every depositor's balance and its owner is
      // the coordinator, so a burn path there would let the coordinator take
      // the pool on a signature. Before 2026-09-21 it did.
      var sweep = TransactionBuilder()
          .spendFromTxnWithSigner(
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              opFunding, 1, TransactionInput.MAX_SEQ_NUMBER,
              P2PKHUnlockBuilder(operatorPub))
          .spendFromTxnWithSigner(
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER,
              PartialWitnessUnlockBuilder.forBurn(operatorPub))
          .sendChangeToPKH(operatorAddress)
          .withFee(BigInt.from(500))
          .build(false);
      expect(
          () => Interpreter().correctlySpends(sweep.inputs[1].script!,
              pp3Script, sweep, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));

      // And the same sweep does work on an ordinary token's PP3, which is what
      // makes the rejection above mean something.
      var tokenPP3 = PartialWitnessLockBuilder(hex.decode(operatorPubkeyHash))
          .getScriptPubkey();
      var tokenTxWithOwnerPP3 = Transaction.fromHex(tokenTx.serialize());
      tokenTxWithOwnerPP3.outputs[3] = TransactionOutput(BigInt.one, tokenPP3);
      var sweepOwned = TransactionBuilder()
          .spendFromTxnWithSigner(
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              opFunding, 1, TransactionInput.MAX_SEQ_NUMBER,
              P2PKHUnlockBuilder(operatorPub))
          .spendFromTxnWithSigner(
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              tokenTxWithOwnerPP3, 3, TransactionInput.MAX_SEQ_NUMBER,
              PartialWitnessUnlockBuilder.forBurn(operatorPub))
          .sendChangeToPKH(operatorAddress)
          .withFee(BigInt.from(500))
          .build(false);
      Interpreter().correctlySpends(sweepOwned.inputs[1].script!, tokenPP3,
          sweepOwned, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });

    test('carries no owner, so a key rotation leaves its code untouched', () {
      var slot = outpoint(slotTx.hash, 0);
      expect(pp3Script.buffer.sublist(0, 1), [0x24],
          reason: 'the first push is the slot, not an owner');
      var owned = PartialWitnessLockBuilder.forPool(slot).getScriptPubkey().buffer;
      expect(_same(owned, pp3Script.buffer), true,
          reason: 'nothing about the coordinator is in the script');
      expect(PartialWitnessLockBuilder.fromScript(pp3Script).ownerPKH, isNull);
      expect(PartialWitnessLockBuilder.fromScript(pp3Script).nextSlot, slot);
    });

    test('an owner and a slot cannot be combined', () {
      // The two kinds of PP3 must not mix: an output with a verifier slot is a
      // pool's, and a pool's PP3 with an owner would be one the owner can burn.
      expect(
          () => WitnessCheckScriptGen.generate(
              ownerPKH: hex.decode(operatorPubkeyHash),
              nextSlot: outpoint(slotTx.hash, 0)),
          throwsA(isA<ScriptException>()));
      expect(() => WitnessCheckScriptGen.generate(),
          throwsA(isA<ScriptException>()));
    });

    test('nextSlot appears exactly once, so the rebuild can substitute it', () {
      // PP1 rebuilds PP3 as a fixed-window substitution. A second copy of
      // nextSlot buried in the body would be left stale by that rebuild.
      var slot = outpoint(slotTx.hash, 0);
      var occurrences = 0;
      for (var i = 0; i + 36 <= pp3Script.buffer.length; i++) {
        var match = true;
        for (var j = 0; j < 36; j++) {
          if (pp3Script.buffer[i + j] != slot[j]) { match = false; break; }
        }
        if (match) occurrences++;
      }
      expect(occurrences, 1);
      expect(pp3Script.buffer[PP1SpScriptGen.pp3NextSlotStart - 1], 0x24,
          reason: '36-byte push opcode');
    });

    test('in-script rebuild reproduces the builder output exactly', () {
      var oldSlot = outpoint(List<int>.filled(32, 0x10), 0);
      var newSlot = outpoint(List<int>.filled(32, 0x90), 7);
      var parent = PartialWitnessLockBuilder.forPool(oldSlot).getScriptPubkey();
      var want = PartialWitnessLockBuilder.forPool(newSlot).getScriptPubkey();

      var sig = ScriptBuilder()
          .addData(Uint8List.fromList(parent.buffer))
          .addData(Uint8List.fromList(newSlot))
          .build();
      var b = ScriptBuilder();
      PP1SpScriptGen.emitRebuildPP3WithNextSlot(b);
      b.addData(Uint8List.fromList(want.buffer));
      b.opCode(OpCodes.OP_EQUAL);

      var tx = Transaction()
        ..addInput(TransactionInput('00' * 32, 0, 0xffffffff))
        ..addOutput(TransactionOutput(BigInt.one, SVScript()));
      Interpreter().correctlySpends(sig, b.build(), tx, 0,
          {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.one));
    });
  });

  group('SP the pinned slot must hold the verifier', () {
    // PP3 proves only that *something* at the pinned outpoint was spent. An
    // OP_TRUE would satisfy it while skipping verification entirely, and a
    // verifier holding some other round's state would verify the next round's
    // proof against the wrong publics. PP1 closes both by rebuilding the slot
    // transaction and matching its txid, then rebuilding V from the header it
    // must embed and the body it must run.
    var header = nextHeader(genesisHeader());
    var other = genesisHeader();

    var owner = hex.decode(operatorPubkeyHash);
    SVScript verifier(PoolHeader h, List<int> body, {List<int>? signer}) =>
        SVScript.fromByteArray(Uint8List.fromList([0x4c, PoolHeader.byteSize,
            ...h.encode(), 0x14, ...(signer ?? owner), ...body]));

    var anchorPKH = hex.decode(operatorPubkeyHash);
    var anchor = TransactionOutput(BigInt.one, ShieldedPoolTool.anchorScript(anchorPKH));

    Transaction slotTx(SVScript carried, {bool anchorFirst = false}) {
      var y = Transaction()
        ..version = 1
        ..nLockTime = 0
        ..addInput(TransactionInput('11' * 32, 3, 0xffffffff));
      var v = TransactionOutput(BigInt.one, carried);
      for (var o in anchorFirst ? [anchor, v] : [v, anchor]) {
        y.addOutput(o);
      }
      return y;
    }

    // newOwner is what the round branch passes as V's signer: the owner the
    // certified round hands over to.
    void runCheck(List<int> yHash, List<int> parts, List<int> claimedBody,
        PoolHeader claimedHeader, {int vout = 0, List<int>? newOwner}) {
      var slot = Uint8List(36)..setAll(0, yHash);
      slot.buffer.asByteData().setUint32(32, vout, Endian.little);
      var sig = ScriptBuilder()
          .addData(Uint8List.fromList(parts))
          .addData(Uint8List.fromList(claimedBody))
          .addData(Uint8List.fromList(verifierBodyHash))
          .addData(Uint8List.fromList(claimedHeader.encode()))
          .addData(Uint8List.fromList(newOwner ?? owner))
          .addData(slot)
          .build();
      var b = ScriptBuilder();
      PP1SpScriptGen.emitVerifySlotIsVerifier(b);
      b.opCode(OpCodes.OP_1);
      var tx = Transaction()
        ..addInput(TransactionInput('00' * 32, 0, 0xffffffff))
        ..addOutput(TransactionOutput(BigInt.one, SVScript()));
      Interpreter().correctlySpends(sig, b.build(), tx, 0,
          {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.one));
    }

    void check({
      required SVScript carried,
      required List<int> claimedBody,
      required PoolHeader claimedHeader,
      int vout = 0,
      bool anchorFirst = false,
    }) {
      var y = slotTx(carried, anchorFirst: anchorFirst);
      runCheck(y.hash, [...y.inputs[0].serialize(), ...anchorPKH],
          claimedBody, claimedHeader, vout: vout);
    }

    test('accepts a slot that holds the verifier for this header', () {
      check(carried: verifier(header, verifierBody), claimedBody: verifierBody,
          claimedHeader: header);
    });

    test('rejects a V that answers to a key other than the new owner', () {
      // The coordinator building Y could otherwise name any key, including,
      // in a handover, their own after they have handed the pool on.
      var y = slotTx(verifier(header, verifierBody,
          signer: hex.decode(counterpartyPubkeyHash)));
      expect(() => runCheck(y.hash, [...y.inputs[0].serialize(), ...anchorPKH],
              verifierBody, header),
          throwsA(isA<ScriptException>()));
    });

    test('accepts a V that answers to the owner a handover names', () {
      var next = hex.decode(counterpartyPubkeyHash);
      var y = slotTx(verifier(header, verifierBody, signer: next));
      runCheck(y.hash, [...y.inputs[0].serialize(), ...anchorPKH],
          verifierBody, header, newOwner: next);
    });

    test('rejects a slot holding something else', () {
      check2() => check(carried: verifier(header, decoyBody),
          claimedBody: decoyBody, claimedHeader: header);
      expect(check2, throwsA(isA<ScriptException>()));
    });

    test('rejects claiming the verifier is there when it is not', () {
      // The txid binds the claim, so the decoy cannot be passed off as the
      // verifier even though the hash of what is claimed would check out.
      expect(() => check(carried: verifier(header, decoyBody),
              claimedBody: verifierBody, claimedHeader: header),
          throwsA(isA<ScriptException>()));
    });

    test('rejects the right verifier carrying the wrong header', () {
      expect(() => check(carried: verifier(other, verifierBody),
              claimedBody: verifierBody, claimedHeader: header),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a pin that names any output but 0', () {
      expect(() => check(carried: verifier(header, verifierBody),
              claimedBody: verifierBody, claimedHeader: header, vout: 1),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a Y with the anchor at output 0 and V at output 1', () {
      // The round spends output 1 as the anchor, so this Y would have the
      // round spend V and leave the round after it an anchor to "verify" with.
      expect(() => check(carried: verifier(header, verifierBody),
              claimedBody: verifierBody, claimedHeader: header, anchorFirst: true),
          throwsA(isA<ScriptException>()));
    });

    // The two attacks below build a Y whose bytes are exactly what PP1
    // rebuilds from the parts it is given, but which parses as a different
    // transaction: one input whose length byte does not match the bytes PP1
    // took to be that input. Each real Y has a single output an attacker can
    // spend without a proof, and hashes to what the pin names. What refuses
    // them is PP1's check that yInput is exactly as long as its own scriptSig
    // length says, with a one-byte length.
    List<int> vOut() {
      var v = verifier(header, verifierBody).buffer;
      var len = v.length < 0xfd ? [v.length] : [0xfd, v.length & 0xff, v.length >> 8];
      return [1, 0, 0, 0, 0, 0, 0, 0, ...len, ...v];
    }

    List<int> rebuilt(List<int> yInput, List<int> pkh) => [
          1, 0, 0, 0, 1, ...yInput, 2, ...vOut(),
          1, 0, 0, 0, 0, 0, 0, 0, 0x19, 0x76, 0xa9, 0x14, ...pkh, 0x88, 0xac,
          0, 0, 0, 0,
        ];

    List<int> hash256(List<int> b) =>
        crypto.sha256.convert(crypto.sha256.convert(b).bytes).bytes;

    test('rejects a Y input whose length claims more than it carries', () {
      // The scriptSig swallows V and the start of the anchor, and the parse
      // resumes inside the anchor's key hash: a sequence, one output, and the
      // script OP_1 OP_1 OP_EQUALVERIFY OP_CHECKSIG, whose last two opcodes
      // are the anchor's own. Anyone can spend it with their own signature.
      var prevout = [...List.filled(32, 0x11), 3, 0, 0, 0];
      // The scriptSig is one PUSHDATA2 over everything it swallows, so it is
      // push-only, as consensus requires of a scriptSig.
      var pushed = 1 + vOut().length + 12 + 4;
      var swallowed = 3 + pushed;
      var yInput = [...prevout, 0xfd, swallowed & 0xff, swallowed >> 8,
          0x4d, pushed & 0xff, pushed >> 8];
      var pkh = [0xaa, 0xaa, 0xaa, 0xaa, 0xff, 0xff, 0xff, 0xff, 0x01,
          1, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x51, 0x51];
      var raw = rebuilt(yInput, pkh);
      var real = Transaction.fromHex(hex.encode(raw));
      expect(real.inputs.length, 1);
      expect(real.outputs.length, 1);
      expect(real.outputs[0].script.buffer, [0x51, 0x51, 0x88, 0xac]);
      expect(() => runCheck(hash256(raw), [...yInput, ...pkh], verifierBody, header),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a Y input whose length claims less than it carries', () {
      // The scriptSig ends early and the rest of yInput is a sequence, one
      // output, and an OP_1 OP_RETURN script whose push length covers V and
      // the anchor. OP_RETURN ends execution with true on the stack, so the
      // one output is anyone-can-spend.
      var prevout = [...List.filled(32, 0x11), 3, 0, 0, 0];
      var n = 2 + 1 + vOut().length + 34;
      var yInput = [...prevout, 0x01, 0x51, 0xff, 0xff, 0xff, 0xff, 0x01,
          1, 0, 0, 0, 0, 0, 0, 0, 0xfd, n & 0xff, n >> 8, 0x51, 0x6a];
      var raw = rebuilt(yInput, anchorPKH);
      var real = Transaction.fromHex(hex.encode(raw));
      expect(real.inputs.length, 1);
      expect(real.outputs.length, 1);
      expect(real.outputs[0].script.buffer.sublist(0, 2), [0x51, 0x6a]);
      expect(() => runCheck(hash256(raw), [...yInput, ...anchorPKH], verifierBody, header),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SP V answers only to its signer', () {
    // PP3 pins the slot one way: the round that moves the money must spend
    // Y:0. Nothing pins it the other way, so without this a stranger who
    // copied the round's proof out of the mempool could spend Y:0 in a
    // transaction of their own, and the round would have nothing left to
    // spend. The key in V's second push is what refuses them. The body here
    // is only the signer check the real V runs, so that the mechanism is
    // tested before the rest of V exists:
    //   [sig, pubkey, header, signerPKH]  NIP OVER HASH160 EQUALVERIFY CHECKSIG
    var toyBody = Uint8List.fromList([OpCodes.OP_NIP, OpCodes.OP_OVER,
        OpCodes.OP_HASH160, OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG]);
    var service = ShieldedPoolTool();
    var y = service.buildSlotTxn(
        header: genesisHeader(), verifierBody: toyBody,
        fundingInput: slotFunding(0x30),
        anchorPKH: hex.decode(operatorPubkeyHash),
        signerPKH: hex.decode(operatorPubkeyHash));

    Transaction spendY(TransactionSigner signer, SVPublicKey pub, Address payTo) =>
        TransactionBuilder()
            .spendFromTxnWithSigner(signer, y.tx, 0,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(pub))
            .spendToLockBuilder(P2PKHLockBuilder.fromAddress(payTo), BigInt.one)
            .build(false);

    void spend(Transaction tx) => Interpreter().correctlySpends(
        tx.inputs[0].script!, y.tx.outputs[0].script, tx, 0, verifyFlags,
        Coin.valueOf(BigInt.one));

    var ownerSigner = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);

    test('accepts a spend the owner signed', () {
      spend(spendY(ownerSigner, operatorPub, operatorAddress));
    });

    test('rejects a stranger signing with their own key', () {
      var stranger = DefaultTransactionSigner(sigHashAll, counterpartyPrivateKey);
      expect(() => spend(spendY(stranger, counterpartyPub, counterpartyAddress)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects the owner\'s signature copied into another transaction', () {
      // What a front-runner actually has: the honest round's unlocking
      // script, taken from the mempool. SIGHASH_ALL commits the signature to
      // the whole round, so moved into a transaction of their own it fails.
      var honest = spendY(ownerSigner, operatorPub, operatorAddress);
      var copied = honest.inputs[0].script!;
      Transaction payingTo(Address a) => TransactionBuilder()
          .spendFromTxn(y.tx, 0, TransactionInput.MAX_SEQ_NUMBER,
              DefaultUnlockBuilder.fromScript(copied))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(a), BigInt.one)
          .build(false);
      // Replayed into an identical transaction it still verifies, so the
      // refusal below is the signature's commitment and not the harness.
      spend(payingTo(operatorAddress));
      expect(() => spend(payingTo(counterpartyAddress)),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SP the round must spend the slot its parent pinned', () {
    // A second, independent binding of the same fact PP3 enforces at mining
    // time. The outpoint is read out of the round's own left-hand side, which
    // the inductive proof has already tied to the round's txid.
    var pinned = outpoint(List<int>.filled(32, 0x55), 0);

    SVScript parentPP3(List<int> slot) =>
        PartialWitnessLockBuilder.forPool(slot).getScriptPubkey();

    /// version + input count + four inputs, which is the shape getTxLHS gives,
    /// with [slotOutpoint] at the pool's slot input and filler everywhere else.
    /// The filler after the slot matters: it is PP3's position, so a reader
    /// that looked one input too far would land on it and fail.
    List<int> lhsWithSlot(List<int> slotOutpoint) {
      var out = <int>[0x01, 0x00, 0x00, 0x00, 0x04];
      for (var i = 0; i < 4; i++) {
        out
          ..addAll(i == PP1SpScriptGen.poolSlotInput
              ? slotOutpoint
              : List<int>.filled(36, i))
          ..add(0x02)                      // a two-byte unlocking script
          ..addAll([0x51, 0x51])
          ..addAll([0xff, 0xff, 0xff, 0xff]);
      }
      return out;
    }

    void check(List<int> pinnedSlot, List<int> spentSlot) {
      var sig = ScriptBuilder()
          .addData(Uint8List.fromList(parentPP3(pinnedSlot).buffer))
          .addData(Uint8List.fromList(lhsWithSlot(spentSlot)))
          .build();
      var b = ScriptBuilder();
      PP1SpScriptGen.emitVerifySpentPinnedSlot(b);
      b.opCode(OpCodes.OP_1);
      var tx = Transaction()
        ..addInput(TransactionInput('00' * 32, 0, 0xffffffff))
        ..addOutput(TransactionOutput(BigInt.one, SVScript()));
      Interpreter().correctlySpends(sig, b.build(), tx, 0,
          {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.one));
    }

    test('accepts a round whose input 2 is the pinned slot', () {
      check(pinned, pinned);
    });

    test('rejects a round that brought its own verifier slot', () {
      expect(() => check(pinned, outpoint(List<int>.filled(32, 0x66), 0)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects the pinned txid at a different output index', () {
      expect(() => check(pinned, outpoint(List<int>.filled(32, 0x55), 1)),
          throwsA(isA<ScriptException>()));
    });
  });

  // =========================================================================
  // The variable output tail
  // =========================================================================
  //
  // Every other TSL1 archetype writes a literal output count of 5, and that
  // literal is what makes it impossible for a round to carry a second PP1 with
  // the same tokenId and fork the chain through the sanctioned path. A pool
  // has to pay withdrawals and acknowledge deposits, so the count has to move.
  // These tests are about what replaces the literal: not a length the spender
  // supplies, but a shape PP1 rebuilds and refuses to deviate from.
  group('SP the variable output tail', () {
    late ShieldedPoolTool service;
    late Transaction fundA, fundB, issuanceTx, createWitness;
    late DefaultTransactionSigner signer;
    late PoolHeader g, h1;
    late ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1;
    late List<int> bundles;

    setUp(() {
      service = ShieldedPoolTool();
      fundA = getOperatorFundingTx();
      fundB = getOperatorFundingTx2();
      signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      g = genesisHeader();
      bundles = PoolOutHash.encodeBundles([[1, 2, 3], [4, 5]]);
      var base = nextHeader(g);
      h1 = PoolHeader(
          cmRoot: base.cmRoot, nfRoot: base.nfRoot, ring: base.ring,
          size: base.size, balance: BigInt.from(500000),
          outHash: PoolOutHash.roundOutHashOf(PoolOutHash.decodeBundles(bundles)));

      y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      y1 = service.buildSlotTxn(
          header: h1, verifierBody: verifierBody, fundingInput: slotFunding(0x11),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));

      issuanceTx = service.createTokenIssuanceTxn(fundA, signer, operatorPub,
          operatorAddress, verifierBodyHash, g, y0.outpoint, fundB.hash, slotTx: y0.tx);
      createWitness = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE,
          slotParts: y0.parts, verifierBody: verifierBody);
    });

    Transaction round(
            {List<PoolWithdrawal>? withdrawals, List<PoolReceipt>? receipts}) =>
        service.createRoundTxn(createWitness, issuanceTx, y0.tx, operatorPub,
            fundA, signer, operatorPub, fundB.hash, h1, y1.outpoint,
            nextSlotTx: y1.tx, withdrawals: withdrawals, receipts: receipts);

    Transaction witnessFor(Transaction roundTx,
            {List<PoolWithdrawal>? withdrawals, List<PoolReceipt>? receipts}) =>
        service.createWitnessTxn(
            signer, fundB, roundTx, hex.decode(issuanceTx.serialize()),
            operatorPub, operatorPubkeyHash, ShieldedPoolAction.ROUND,
            newOwnerPKH: hex.decode(operatorPubkeyHash),
            newHeader: h1.encode(), nextSlot: y1.outpoint, slotParts: y1.parts,
            verifierBody: verifierBody, bundles: bundles,
            withdrawals: withdrawals, receipts: receipts);

    void spendPP1(Transaction roundTx, Transaction witness) =>
        Interpreter().correctlySpends(witness.inputs[1].script!,
            roundTx.outputs[1].script, witness, 1, verifyFlags,
            Coin.valueOf(BigInt.one));

    PoolWithdrawal payout(int n, int sats) =>
        PoolWithdrawal(List<int>.filled(20, n), BigInt.from(sats));
    PoolReceipt deposit(int n, int sats) =>
        PoolReceipt(List<int>.filled(32, n), BigInt.from(sats));

    test('a round with no tail is still the five TSL1 outputs', () {
      var roundTx = round();
      expect(roundTx.outputs.length, 5);
      spendPP1(roundTx, witnessFor(roundTx));
    });

    test('a withdrawal is a P2PKH output the witness accepts', () {
      var w = [payout(1, 1000)];
      var roundTx = round(withdrawals: w);
      expect(roundTx.outputs.length, 6);
      expect(roundTx.outputs[5].satoshis, BigInt.from(1000));
      expect(roundTx.outputs[5].script.buffer,
          [0x76, 0xa9, 0x14, ...List<int>.filled(20, 1), 0x88, 0xac]);
      spendPP1(roundTx, witnessFor(roundTx, withdrawals: w));
    });

    test('a receipt is a zero-value OP_FALSE OP_RETURN the witness accepts', () {
      var r = [deposit(0xAA, 100000)];
      var roundTx = round(receipts: r);
      expect(roundTx.outputs.length, 6);
      expect(roundTx.outputs[5].satoshis, BigInt.zero);
      expect(roundTx.outputs[5].script.buffer.sublist(0, 3), [0x00, 0x6a, 0x20]);
      expect(roundTx.outputs[5].script.buffer.length, 44,
          reason: 'the amount is eight raw bytes, so the shape never varies');
      spendPP1(roundTx, witnessFor(roundTx, receipts: r));
    });

    test('receipts come before withdrawals', () {
      // Not cosmetic. A deposit covenant proves its receipt with
      // SIGHASH_SINGLE, which ties output index to input index, and a
      // depositor cannot know how many withdrawals the round will carry.
      var w = [payout(1, 1000), payout(2, 2500)];
      var r = [deposit(0xAA, 100000)];
      var roundTx = round(withdrawals: w, receipts: r);
      expect(roundTx.outputs.length, 8);
      expect(roundTx.outputs[5].script.buffer.sublist(0, 2), [0x00, 0x6a]);
      expect(roundTx.outputs[6].script.buffer.sublist(0, 3), [0x76, 0xa9, 0x14]);
      expect(roundTx.outputs[7].script.buffer.sublist(0, 3), [0x76, 0xa9, 0x14]);
      spendPP1(roundTx, witnessFor(roundTx, withdrawals: w, receipts: r));
    });

    test('the output count survives passing 252', () {
      // The count is a varint, and every fixed-count archetype gets away with
      // one byte. 5 + 256 does not fit in one byte.
      var w = [for (var i = 0; i < PoolWithdrawal.maxPerRound; i++) payout(i % 251, 100 + i)];
      var roundTx = round(withdrawals: w);
      expect(roundTx.outputs.length, 261);
      spendPP1(roundTx, witnessFor(roundTx, withdrawals: w));
    });

    test('rejects a witness that names a payee the round did not pay', () {
      var roundTx = round(withdrawals: [payout(1, 1000)]);
      expect(() => spendPP1(roundTx, witnessFor(roundTx, withdrawals: [payout(9, 1000)])),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a witness that names an amount the round did not pay', () {
      var roundTx = round(withdrawals: [payout(1, 1000)]);
      expect(() => spendPP1(roundTx, witnessFor(roundTx, withdrawals: [payout(1, 999)])),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a witness that leaves a paid withdrawal out', () {
      var roundTx = round(withdrawals: [payout(1, 1000), payout(2, 2000)]);
      expect(() => spendPP1(roundTx, witnessFor(roundTx, withdrawals: [payout(1, 1000)])),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a round carrying a second PP1_SP in the tail', () {
      // This is the property the fixed count of five was defending. A round
      // with two PP1 outputs for the same tokenId forks the chain through the
      // path the protocol sanctions, so it has to die in the witness whatever
      // the witness claims the extra output is.
      for (var claim in <List<PoolWithdrawal>>[[], [payout(1, 1)]]) {
        var forged = round();
        forged.addOutput(TransactionOutput(BigInt.one, forged.outputs[1].script));
        expect(() => spendPP1(forged, witnessFor(forged, withdrawals: claim)),
            throwsA(isA<ScriptException>()),
            reason: 'claimed as ${claim.length} withdrawal(s)');
      }
    });

    test('rejects more records than the unrolled tail has steps', () {
      // The maxima are not a pushed number anyone checks. They are the point
      // at which the script runs out of steps, and leftover bytes are the same
      // thing as a count nobody checked.
      var w = [for (var i = 0; i < PoolWithdrawal.maxPerRound; i++) payout(i % 251, 100 + i)];
      var roundTx = round(withdrawals: w);
      expect(
          () => spendPP1(roundTx, witnessFor(roundTx, withdrawals: [...w, payout(7, 5)])),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a blob that is not whole records', () {
      // The builder will not make one, so rewrite the push in the finished
      // witness. The withdrawals blob is the first push of a round unlock.
      var roundTx = round(withdrawals: [payout(1, 1000)]);
      var witness = witnessFor(roundTx, withdrawals: [payout(1, 1000)]);
      var raw = witness.inputs[1].script!.buffer.toList();
      expect(raw[0], PoolWithdrawal.recordSize,
          reason: 'the first push is one 28-byte withdrawal record');
      raw[0] = PoolWithdrawal.recordSize - 1;
      raw.removeAt(PoolWithdrawal.recordSize);
      expect(
          () => Interpreter().correctlySpends(
              SVScript.fromByteArray(Uint8List.fromList(raw)),
              roundTx.outputs[1].script, witness, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    });

    test('the tool refuses a tail the script has no steps for', () {
      expect(
          () => round(withdrawals: [
                for (var i = 0; i <= PoolWithdrawal.maxPerRound; i++) payout(i % 251, 100)
              ]),
          throwsA(isA<ArgumentError>()));
      expect(
          () => round(receipts: [
                for (var i = 0; i <= PoolReceipt.maxPerRound; i++) deposit(i, 100)
              ]),
          throwsA(isA<ArgumentError>()));
    });
  });

  // =========================================================================
  // Refusing a slot before the round is mined
  // =========================================================================
  //
  // PP1's certification of the next slot happens in the witness, which is
  // built after the round is already mined. That is too late to help: a round
  // pinning a slot PP1 will refuse can never produce a witness, its PP3 can
  // then never be spent, and the pool balance is frozen permanently. So the
  // same checks run in Dart before anything is broadcast, and the only way
  // past them is to say so.
  group('SP the tool refuses a slot that would freeze the pool', () {
    late ShieldedPoolTool service;
    late Transaction fundA, fundB, issuanceTx, createWitness;
    late DefaultTransactionSigner signer;
    late PoolHeader g, h1;
    late ({Transaction tx, List<int> outpoint, List<int> parts}) y0, y1;

    setUp(() {
      service = ShieldedPoolTool();
      fundA = getOperatorFundingTx();
      fundB = getOperatorFundingTx2();
      signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      g = genesisHeader();
      h1 = nextHeader(g);
      y0 = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      y1 = service.buildSlotTxn(
          header: h1, verifierBody: verifierBody, fundingInput: slotFunding(0x11),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      issuanceTx = service.createTokenIssuanceTxn(fundA, signer, operatorPub,
          operatorAddress, verifierBodyHash, g, y0.outpoint, fundB.hash, slotTx: y0.tx);
      createWitness = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE,
          slotParts: y0.parts, verifierBody: verifierBody);
    });

    Transaction round(List<int> slot, {Transaction? slotTx, bool unchecked = false}) =>
        service.createRoundTxn(createWitness, issuanceTx, y0.tx, operatorPub,
            fundA, signer, operatorPub, fundB.hash, h1, slot,
            nextSlotTx: slotTx, uncheckedNextSlot: unchecked);

    test('accepts the slot built for this round', () {
      expect(round(y1.outpoint, slotTx: y1.tx).outputs.length, 5);
    });

    test('refuses a round that names no slot transaction', () {
      // The round spends the slot transaction's anchor, so there is no way to
      // build it without one, checked or not.
      expect(() => round(y1.outpoint), throwsA(isA<ArgumentError>()));
      expect(() => round(y1.outpoint, unchecked: true), throwsA(isA<ArgumentError>()));
    });

    test('spends the anchor of the slot it pins at input 4', () {
      var r = round(y1.outpoint, slotTx: y1.tx);
      expect(r.inputs[4].prevTxnId, y1.tx.id);
      expect(r.inputs[4].prevTxnOutputIndex, 1);
    });

    test('refuses a verifier built for another header', () {
      // The decisive case. This is a genuine, spendable copy of the pool's
      // verifier that was never told the state it is supposed to check, so a
      // body hash alone would pass it.
      var wrong = service.buildSlotTxn(
          header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x12),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      expect(() => round(wrong.outpoint, slotTx: wrong.tx),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses a verifier that is not this pool\'s', () {
      var decoy = service.buildSlotTxn(
          header: h1, verifierBody: decoyBody, fundingInput: slotFunding(0x13),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      expect(() => round(decoy.outpoint, slotTx: decoy.tx),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses a Y with a third output', () {
      // V then the anchor, and nothing else, is what forces V to be output 0.
      var extra = Transaction()
        ..version = 1
        ..nLockTime = 0
        ..addInput(slotFunding(0x14))
        ..addOutput(y1.tx.outputs[0])
        ..addOutput(y1.tx.outputs[1])
        ..addOutput(TransactionOutput(BigInt.one,
            P2PKHLockBuilder.fromAddress(operatorAddress).getScriptPubkey()));
      expect(() => round(outpoint(extra.hash, 0), slotTx: extra),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses a Y with the anchor at output 0', () {
      var swapped = Transaction()
        ..version = 1
        ..nLockTime = 0
        ..addInput(slotFunding(0x14))
        ..addOutput(y1.tx.outputs[1])
        ..addOutput(y1.tx.outputs[0]);
      expect(() => round(outpoint(swapped.hash, 0), slotTx: swapped),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses a Y whose output 1 is not the anchor', () {
      var wrong = Transaction()
        ..version = 1
        ..nLockTime = 0
        ..addInput(slotFunding(0x14))
        ..addOutput(y1.tx.outputs[0])
        ..addOutput(TransactionOutput(BigInt.one, SVScript.fromByteArray(
            Uint8List.fromList([OpCodes.OP_1]))));
      expect(() => round(outpoint(wrong.hash, 0), slotTx: wrong),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses an outpoint naming any output but 0', () {
      expect(() => round(outpoint(y1.tx.hash, 1), slotTx: y1.tx),
          throwsA(isA<ArgumentError>()));
    });

    test('refuses an outpoint that is not the slot transaction supplied', () {
      var other = service.buildSlotTxn(
          header: h1, verifierBody: verifierBody, fundingInput: slotFunding(0x15),
          anchorPKH: hex.decode(operatorPubkeyHash),
          signerPKH: hex.decode(operatorPubkeyHash));
      expect(() => round(other.outpoint, slotTx: y1.tx),
          throwsA(isA<ArgumentError>()));
    });
  });
}

/// The genesis slot every fixture pool opens with: V for [g], answering to
/// the operator, with the operator's anchor.
({Transaction tx, List<int> outpoint, List<int> parts}) genesisSlot(PoolHeader g) =>
    ShieldedPoolTool().buildSlotTxn(
        header: g, verifierBody: verifierBody, fundingInput: slotFunding(0x10),
        anchorPKH: hex.decode(operatorPubkeyHash),
        signerPKH: hex.decode(operatorPubkeyHash));

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
