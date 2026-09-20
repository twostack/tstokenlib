import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';

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

    test('genesis has no leaves, no money and no bundles', () {
      var g = genesisHeader();
      expect(g.size, 0);
      expect(g.balance, BigInt.zero);
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
    test('530-byte header roundtrip', () {
      var tokenId = List<int>.filled(32, 0xAA);
      var g = genesisHeader();
      var h = nextHeader(g);

      var script = PP1SpLockBuilder(operatorAddress, tokenId, h, g.encode())
          .getScriptPubkey();

      var parsed = PP1SpLockBuilder.fromScript(script);
      expect(parsed.ownerAddress!.pubkeyHash160, operatorPubkeyHash);
      expect(parsed.tokenId, tokenId);
      expect(parsed.header!.encode(), h.encode());
      expect(parsed.genesisHeader, g.encode());
    });

    test('script header byte offsets match constants', () {
      var g = genesisHeader();
      var script = PP1SpLockBuilder(
              operatorAddress, List<int>.filled(32, 0xCC), g, g.encode())
          .getScriptPubkey();
      var buf = script.buffer;

      expect(buf[0], 0x14);                             // ownerPKH push
      expect(buf[PP1SpScriptGen.tokenIdDataStart - 1], 0x20);  // tokenId push
      // 236 bytes is past the 75-byte direct-push limit, so the header push is
      // OP_PUSHDATA1 followed by its length. That is why headerDataStart is 56
      // and not 55.
      expect(buf[PP1SpScriptGen.genesisPushStart], 0x4c);
      expect(buf[PP1SpScriptGen.genesisPushStart + 1], PoolHeader.byteSize);
      expect(buf[PP1SpScriptGen.headerPushStart], 0x4c);
      expect(buf[PP1SpScriptGen.headerPushStart + 1], PoolHeader.byteSize);
      expect(PP1SpScriptGen.genesisDataStart, 56);
      expect(PP1SpScriptGen.headerDataStart, 294);
      expect(PP1SpScriptGen.headerDataEnd, 530);
      expect(PP1SpScriptGen.scriptBodyStart, 530);

      expect(buf.sublist(PP1SpScriptGen.genesisDataStart, PP1SpScriptGen.genesisDataEnd),
          g.encode());
      expect(buf.sublist(PP1SpScriptGen.headerDataStart, PP1SpScriptGen.headerDataEnd),
          g.encode());
    });

    test('the genesis header is readable straight off the script', () {
      // It is carried in full rather than as a commitment, so a depositor can
      // check what state the pool opened on without being handed a preimage.
      var g = genesisHeader();
      var script = PP1SpLockBuilder(
              operatorAddress, List<int>.filled(32, 0xCC), nextHeader(g), g.encode())
          .getScriptPubkey();
      expect(PP1SpLockBuilder.fromScript(script).genesisHeader, g.encode());
    });

    test('validation rejects a wrong-length tokenId', () {
      var g = genesisHeader();
      expect(() => PP1SpLockBuilder(operatorAddress, [1, 2, 3], g, g.encode()),
          throwsA(isA<ScriptException>()));
    });

    test('validation rejects a wrong-length genesis header', () {
      var g = genesisHeader();
      expect(() => PP1SpLockBuilder(operatorAddress, List<int>.filled(32, 0), g, [1, 2]),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SP script generation', () {
    test('generate produces a header of exactly scriptBodyStart bytes', () {
      var g = genesisHeader();
      var script = PP1SpScriptGen.generate(
        ownerPKH: hex.decode(operatorPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
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
          header: g1.encode(), genesisHeader: g1.encode()).buffer;
      var b = PP1SpScriptGen.generate(
          ownerPKH: hex.decode(counterpartyPubkeyHash), tokenId: tokenId,
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

      var issuanceTx = service.createTokenIssuanceTxn(
          fundingTx, operatorSigner, operatorPub, operatorAddress, g,
          getOperatorFundingTx2().hash);

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);
      expect(issuanceTx.outputs[0].satoshis > BigInt.zero, true);
      expect(issuanceTx.outputs[1].satoshis, BigInt.one);
      expect(issuanceTx.outputs[2].satoshis, BigInt.one);
      expect(issuanceTx.outputs[3].satoshis, BigInt.one);
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);

      var pp1Lock = PP1SpLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.tokenId, fundingTx.hash);
      expect(pp1Lock.ownerAddress!.pubkeyHash160, operatorPubkeyHash);
      expect(pp1Lock.header!.encode(), g.encode());
    });

    test('refuses to fund issuance from any output but 1', () {
      var service = ShieldedPoolTool();
      expect(() => service.createTokenIssuanceTxn(
              getOperatorFundingTx(),
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
              operatorPub, operatorAddress, genesisHeader(),
              getOperatorFundingTx2().hash, fundingVout: 0),
          throwsA(isA<ArgumentError>()));
    });
  });

  group('SP create witness', () {
    test('create witness verifies', () {
      var service = ShieldedPoolTool();
      var fundA = getOperatorFundingTx();
      var fundB = getOperatorFundingTx2();
      var signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);

      var issuanceTx = service.createTokenIssuanceTxn(
          fundA, signer, operatorPub, operatorAddress, genesisHeader(), fundB.hash);

      var witnessTx = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE);

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

      var issuanceTx = (TransactionBuilder()
            ..spendFromTxnWithSigner(signer, fundA, 1,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(operatorPub))
            ..withFeePerKb(100)
            ..spendToLockBuilder(
                PP1SpLockBuilder(operatorAddress, fundA.hash, stuffed, g.encode()),
                BigInt.one)
            ..spendToLockBuilder(
                PP2LockBuilder(outpoint(fundB.hash, 1),
                    hex.decode(operatorPubkeyHash), 1, hex.decode(operatorPubkeyHash)),
                BigInt.one)
            ..spendToLockBuilder(
                PartialWitnessLockBuilder(hex.decode(operatorPubkeyHash)), BigInt.one)
            ..spendToLockBuilder(MetadataLockBuilder(), BigInt.zero)
            ..sendChangeToPKH(operatorAddress))
          .build(false);

      var witnessTx = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE);

      expect(
          () => Interpreter().correctlySpends(witnessTx.inputs[1].script!,
              issuanceTx.outputs[1].script, witnessTx, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
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
                PP1SpLockBuilder(owner, tokenId, g, g.encode()), BigInt.one)
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

    setUp(() {
      service = ShieldedPoolTool();
      fundA = getOperatorFundingTx();
      fundB = getOperatorFundingTx2();
      signer = DefaultTransactionSigner(sigHashAll, operatorPrivateKey);
      g = genesisHeader();
      h1 = nextHeader(g);

      issuanceTx = service.createTokenIssuanceTxn(
          fundA, signer, operatorPub, operatorAddress, g, fundB.hash);
      createWitness = service.createWitnessTxn(
          signer, fundB, issuanceTx, hex.decode(fundA.serialize()),
          operatorPub, operatorPubkeyHash, ShieldedPoolAction.CREATE);
    });

    Transaction round(PoolHeader header) => service.createRoundTxn(
        createWitness, issuanceTx, operatorPub, fundA, signer, operatorPub,
        fundB.hash, header);

    Transaction roundWitness(Transaction roundTx, PoolHeader claimed) =>
        service.createWitnessTxn(
            signer, fundB, roundTx, hex.decode(issuanceTx.serialize()),
            operatorPub, operatorPubkeyHash, ShieldedPoolAction.ROUND,
            newOwnerPKH: hex.decode(operatorPubkeyHash),
            newHeader: claimed.encode());

    test('issue, create witness, round, round witness', () {
      var roundTx = round(h1);
      expect(roundTx.outputs.length, 5);

      // The spend of the parent PP3 is what carries the induction forward.
      Interpreter().correctlySpends(roundTx.inputs[2].script!,
          issuanceTx.outputs[3].script, roundTx, 2, verifyFlags,
          Coin.valueOf(BigInt.one));

      var witness = roundWitness(roundTx, h1);
      Interpreter().correctlySpends(witness.inputs[1].script!,
          roundTx.outputs[1].script, witness, 1, verifyFlags,
          Coin.valueOf(BigInt.one));
    });

    test('the round carries the new header forward', () {
      var after = PP1SpLockBuilder.fromScript(round(h1).outputs[1].script);
      expect(after.header!.encode(), h1.encode());
      expect(after.header!.balance, BigInt.from(123456789));
      expect(after.header!.size, 7);
      expect(after.tokenId, fundA.hash, reason: 'tokenId is immutable');
    });

    test('the round leaves the body byte-identical to its parent', () {
      // PP1 rebuilds the next script as parent[0:1] + newPKH + parent[21:56] +
      // newHeader + parent[292:]. Anything else changing would make the round
      // unspendable.
      var parent = issuanceTx.outputs[1].script.buffer;
      var child = round(h1).outputs[1].script.buffer;
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
      var roundTx = round(h1);
      var lie = h1.advance(
          cmRoot: List<int>.filled(32, 0x77), nfRoot: List<int>.filled(32, 0x88),
          size: 999, balance: BigInt.from(1), outHash: List<int>.filled(32, 0x99));

      var witness = roundWitness(roundTx, lie);
      expect(
          () => Interpreter().correctlySpends(witness.inputs[1].script!,
              roundTx.outputs[1].script, witness, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a witness signed by someone other than the owner', () {
      var roundTx = round(h1);
      var outsider = DefaultTransactionSigner(sigHashAll, counterpartyPrivateKey);
      var witness = service.createWitnessTxn(
          outsider, getCounterpartyFundingTx(), roundTx,
          hex.decode(issuanceTx.serialize()), counterpartyPub,
          counterpartyPubkeyHash, ShieldedPoolAction.ROUND,
          newOwnerPKH: hex.decode(operatorPubkeyHash), newHeader: h1.encode());
      expect(
          () => Interpreter().correctlySpends(witness.inputs[1].script!,
              roundTx.outputs[1].script, witness, 1, verifyFlags,
              Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()));
    });

    test('rejects a selector that names no branch', () {
      var roundTx = round(h1);
      var witness = roundWitness(roundTx, h1);
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
      slotTx = cpFunding; // only its outpoint matters to PP3
      var service = ShieldedPoolTool();
      tokenTx = service.createTokenIssuanceTxn(
        opFunding, DefaultTransactionSigner(sigHashAll, operatorPrivateKey),
        operatorPub, operatorAddress, genesisHeader(), cpFunding.hash,
        nextSlot: outpoint(slotTx.hash, 0),
      );
      pp3Script = tokenTx.outputs[3].script;
      witnessTx = service.createWitnessTxn(
        DefaultTransactionSigner(sigHashAll, counterpartyPrivateKey),
        cpFunding, tokenTx, hex.decode(opFunding.serialize()), counterpartyPub,
        counterpartyPubkeyHash, ShieldedPoolAction.CREATE,
      );
      var parts = TransactionUtils()
          .computePartialHash(hex.decode(witnessTx.serialize()), 2);
      partialHash = parts.$1;
      remainder = parts.$2;
    });

    Transaction round({required bool withSlot}) {
      var empty = DefaultUnlockBuilder.fromScript(ScriptBuilder.createEmpty());
      var b = TransactionBuilder()
          .spendFromTxnWithSigner(
              DefaultTransactionSigner(sigHashAll, operatorPrivateKey), opFunding, 1,
              TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(operatorPub))
          .spendFromTxn(witnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, empty)
          .spendFromTxn(tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, empty);
      if (withSlot) {
        b.spendFromTxn(slotTx, 0, TransactionInput.MAX_SEQ_NUMBER, empty);
      }
      var tx = b
          .spendToPKH(operatorAddress, BigInt.from(1000))
          .withFee(BigInt.from(500))
          .build(false);
      var pre = Sighash().createSighashPreImage(tx, sigHashAll, 2, pp3Script, BigInt.one);
      tx.inputs[2].script = PartialWitnessUnlockBuilder(
              pre!, partialHash, remainder, outpoint(opFunding.hash, 1),
              extraPrevouts: const <int>[])
          .getScriptSig();
      return tx;
    }

    void spendPP3(Transaction tx) => Interpreter().correctlySpends(
        tx.inputs[2].script!, pp3Script, tx, 2, verifyFlags, Coin.valueOf(BigInt.one));

    test('accepts a round that spends the named slot at input 3', () {
      spendPP3(round(withSlot: true));
    });

    test('rejects a round that skips verification', () {
      expect(() => spendPP3(round(withSlot: false)), throwsA(isA<ScriptException>()));
    });

    test('costs 46 bytes over a plain PP3', () {
      var plain = PartialWitnessLockBuilder(hex.decode(operatorPubkeyHash)).getScriptPubkey();
      expect(pp3Script.buffer.length - plain.buffer.length, 46);
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
      expect(pp3Script.buffer[21], 0x24);   // 36-byte push opcode
    });

    test('in-script rebuild reproduces the builder output exactly', () {
      var oldPKH = hex.decode(operatorPubkeyHash);
      var newPKH = hex.decode(counterpartyPubkeyHash);
      var oldSlot = outpoint(List<int>.filled(32, 0x10), 0);
      var newSlot = outpoint(List<int>.filled(32, 0x90), 7);
      var parent = PartialWitnessLockBuilder(oldPKH, nextSlot: oldSlot).getScriptPubkey();
      var want = PartialWitnessLockBuilder(newPKH, nextSlot: newSlot).getScriptPubkey();

      var sig = ScriptBuilder()
          .addData(Uint8List.fromList(parent.buffer))
          .addData(Uint8List.fromList(newPKH))
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
    // OP_TRUE would satisfy it while skipping verification entirely. PP1 closes
    // that by rebuilding the slot transaction and matching its txid, then
    // hashing the script it carries.
    var verifier = ScriptBuilder().opCode(OpCodes.OP_NOP).opCode(OpCodes.OP_1).build();
    var decoy = ScriptBuilder().opCode(OpCodes.OP_1).build();
    var bodyHash = crypto.sha256.convert(verifier.buffer).bytes;

    Transaction slotTx(SVScript carried) => Transaction()
      ..version = 1
      ..nLockTime = 0
      ..addInput(TransactionInput('11' * 32, 3, 0xffffffff))
      ..addOutput(TransactionOutput(BigInt.one, carried));

    void check({required SVScript carried, required SVScript claimed, int vout = 0}) {
      var y = slotTx(carried);
      var slot = Uint8List(36)..setAll(0, y.hash);
      slot.buffer.asByteData().setUint32(32, vout, Endian.little);
      var sig = ScriptBuilder()
          .addData(Uint8List.fromList(y.inputs[0].serialize()))
          .addData(Uint8List.fromList(claimed.buffer))
          .addData(slot)
          .build();
      var b = ScriptBuilder();
      PP1SpScriptGen.emitVerifySlotIsVerifier(b, bodyHash: bodyHash);
      b.opCode(OpCodes.OP_1);
      var tx = Transaction()
        ..addInput(TransactionInput('00' * 32, 0, 0xffffffff))
        ..addOutput(TransactionOutput(BigInt.one, SVScript()));
      Interpreter().correctlySpends(sig, b.build(), tx, 0,
          {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.one));
    }

    test('accepts a slot that really holds the verifier', () {
      check(carried: verifier, claimed: verifier);
    });

    test('rejects a slot holding something else', () {
      expect(() => check(carried: decoy, claimed: decoy), throwsA(isA<ScriptException>()));
    });

    test('rejects claiming the verifier is there when it is not', () {
      // The txid binds the claim, so the decoy cannot be passed off as the
      // verifier even though the hash of what is claimed would check out.
      expect(() => check(carried: decoy, claimed: verifier), throwsA(isA<ScriptException>()));
    });

    test('rejects a pin that names any output but 0', () {
      expect(() => check(carried: verifier, claimed: verifier, vout: 1),
          throwsA(isA<ScriptException>()));
    });
  });
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
