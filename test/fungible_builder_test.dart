import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

void main() {
  group('PP1FtLockBuilder round-trip', () {
    test('build then parse recovers recipientPKH, tokenId, and amount', () {
      var recipientPKH = hex.decode(bobPubkeyHash).toList();
      var tokenId = List<int>.generate(32, (i) => i + 0xA0);
      var amount = 1000;

      var builder = PP1FtLockBuilder(recipientPKH, tokenId, amount);
      var script = builder.getScriptPubkey();

      var parsed = PP1FtLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.recipientPKH, recipientPKH), true,
          reason: 'recipientPKH mismatch after round-trip');
      expect(ListEquality().equals(parsed.tokenId, tokenId), true,
          reason: 'tokenId mismatch after round-trip');
      expect(parsed.amount, amount, reason: 'amount mismatch after round-trip');
    });

    test('round-trip with amount = 1', () {
      var recipientPKH = hex.decode(bobPubkeyHash).toList();
      var tokenId = List<int>.generate(32, (i) => i);
      var amount = 1;

      var builder = PP1FtLockBuilder(recipientPKH, tokenId, amount);
      var script = builder.getScriptPubkey();

      var parsed = PP1FtLockBuilder.fromScript(script);

      expect(parsed.amount, 1);
    });

    test('round-trip with large amount', () {
      var recipientPKH = hex.decode(bobPubkeyHash).toList();
      var tokenId = List<int>.generate(32, (i) => 0xFF);
      var amount = 21000000 * 100000000; // 21M * 1e8

      var builder = PP1FtLockBuilder(recipientPKH, tokenId, amount);
      var script = builder.getScriptPubkey();

      var parsed = PP1FtLockBuilder.fromScript(script);

      expect(parsed.amount, amount, reason: 'large amount mismatch');
    });

    test('rejects PKH with wrong length', () {
      var badPKH = List<int>.generate(19, (i) => i);
      var tokenId = List<int>.generate(32, (i) => i);
      expect(() => PP1FtLockBuilder(badPKH, tokenId, 100), throwsException);
    });

    test('rejects tokenId with wrong length', () {
      var pkh = hex.decode(bobPubkeyHash).toList();
      var badTokenId = List<int>.generate(31, (i) => i);
      expect(() => PP1FtLockBuilder(pkh, badTokenId, 100), throwsException);
    });

    test('rejects negative amount', () {
      var pkh = hex.decode(bobPubkeyHash).toList();
      var tokenId = List<int>.generate(32, (i) => i);
      expect(() => PP1FtLockBuilder(pkh, tokenId, -1), throwsException);
    });
  });

  group('PP2FtLockBuilder round-trip', () {
    test('build then parse recovers all fields', () {
      var fundingOutpoint = List<int>.generate(36, (i) => i + 0x10);
      var witnessChangePKH = hex.decode(bobPubkeyHash).toList();
      var changeAmount = 1;
      var ownerPKH = hex.decode(bobPubkeyHash).toList();
      var pp1FtOutputIndex = 1;
      var pp2OutputIndex = 2;

      var builder = PP2FtLockBuilder(
          fundingOutpoint, witnessChangePKH, changeAmount, ownerPKH,
          pp1FtOutputIndex, pp2OutputIndex);
      var script = builder.getScriptPubkey();

      var parsed = PP2FtLockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.fundingOutpoint, fundingOutpoint), true,
          reason: 'fundingOutpoint mismatch');
      expect(ListEquality().equals(parsed.witnessChangePKH, witnessChangePKH), true,
          reason: 'witnessChangePKH mismatch');
      expect(parsed.changeAmount, changeAmount, reason: 'changeAmount mismatch');
      expect(ListEquality().equals(parsed.ownerPKH, ownerPKH), true,
          reason: 'ownerPKH mismatch');
      expect(parsed.pp1FtOutputIndex, pp1FtOutputIndex, reason: 'pp1FtOutputIndex mismatch');
      expect(parsed.pp2OutputIndex, pp2OutputIndex, reason: 'pp2OutputIndex mismatch');
    });

    test('round-trip with change triplet indices (4,5)', () {
      var fundingOutpoint = List<int>.generate(36, (i) => i);
      var witnessChangePKH = hex.decode(bobPubkeyHash).toList();
      var ownerPKH = hex.decode(bobPubkeyHash).toList();

      var builder = PP2FtLockBuilder(
          fundingOutpoint, witnessChangePKH, 1, ownerPKH, 4, 5);
      var script = builder.getScriptPubkey();

      var parsed = PP2FtLockBuilder.fromScript(script);

      expect(parsed.pp1FtOutputIndex, 4);
      expect(parsed.pp2OutputIndex, 5);
    });

    test('rejects outpoint with wrong length', () {
      var badOutpoint = List<int>.generate(35, (i) => i);
      var pkh = hex.decode(bobPubkeyHash).toList();
      expect(() => PP2FtLockBuilder(badOutpoint, pkh, 1, pkh, 1, 2), throwsException);
    });

    test('rejects PKH with wrong length', () {
      var outpoint = List<int>.generate(36, (i) => i);
      var badPKH = List<int>.generate(19, (i) => i);
      var goodPKH = hex.decode(bobPubkeyHash).toList();
      expect(() => PP2FtLockBuilder(outpoint, badPKH, 1, goodPKH, 1, 2), throwsException);
    });
  });

  group('PP1FtUnlockBuilder script construction', () {
    test('MINT action produces OP_0 selector', () {
      var preImage = List<int>.generate(100, (i) => i);
      var witnessFundingTxId = List<int>.generate(32, (i) => i + 0x50);
      var padding = Uint8List(5);

      var builder = PP1FtUnlockBuilder.forMint(preImage, witnessFundingTxId, padding);
      var script = builder.getScriptSig();
      var chunks = script.chunks;

      // Last chunk should be OP_0
      expect(chunks.last.opcodenum, OpCodes.OP_0,
          reason: 'MINT should end with OP_0');
      // Should have 4 chunks: preImage, witnessFundingTxId, padding, OP_0
      expect(chunks.length, 4);
    });

    test('BURN action produces OP_4 selector with pubkey and sig', () {
      var builder = PP1FtUnlockBuilder.forBurn(bobPub);

      // Need to sign to get a script sig
      var signer = TransactionSigner(
          SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value,
          bobPrivateKey);

      // Build a minimal transaction to get a signature
      var fundingTx = Transaction.fromHex(
          "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000");

      var tx = TransactionBuilder()
          .spendFromTxnWithSigner(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, builder)
          .spendToLockBuilder(ModP2PKHLockBuilder.fromAddress(bobAddress), BigInt.one)
          .build(false);

      var script = tx.inputs[0].script!;
      var chunks = script.chunks;

      // Last chunk should be OP_4
      expect(chunks.last.opcodenum, OpCodes.OP_4,
          reason: 'BURN should end with OP_4');
      // Should have 3 chunks: pubkey, sig, OP_4
      expect(chunks.length, 3);
    });
  });

  group('PP2FtUnlockBuilder script construction', () {
    test('normal unlock produces OP_0 selector with txid', () {
      var txId = List<int>.generate(32, (i) => i + 0x20);
      var builder = PP2FtUnlockBuilder(txId);
      var script = builder.getScriptSig();
      var chunks = script.chunks;

      expect(chunks.length, 2);
      expect(chunks.last.opcodenum, OpCodes.OP_0,
          reason: 'Normal unlock should end with OP_0');
      expect(ListEquality().equals(chunks[0].buf, txId), true,
          reason: 'First chunk should be txId');
    });

    test('parse recovers outpointTxId', () {
      var txId = List<int>.generate(32, (i) => i + 0x30);
      var builder = PP2FtUnlockBuilder(txId);
      var script = builder.getScriptSig();

      var parsed = PP2FtUnlockBuilder.fromScript(script);
      expect(ListEquality().equals(parsed.outpointTxId, txId), true,
          reason: 'outpointTxId mismatch after parse');
    });
  });

  group('PartialWitnessFtUnlockBuilder script construction', () {
    test('normal unlock produces OP_0 selector', () {
      var preImage = List<int>.generate(50, (i) => i);
      var partialHash = List<int>.generate(32, (i) => i + 0x10);
      var partialWitnessPreImage = List<int>.generate(128, (i) => i + 0x20);
      var fundingTxId = List<int>.generate(32, (i) => i + 0x30);

      var builder = PartialWitnessFtUnlockBuilder(
          preImage, partialHash, partialWitnessPreImage, fundingTxId);
      var script = builder.getScriptSig();
      var chunks = script.chunks;

      // 5 chunks: preImage, partialHash, witnessPreImage, fundingTxId, OP_0
      expect(chunks.length, 5);
      expect(chunks.last.opcodenum, OpCodes.OP_0);
    });

    test('parse recovers all fields', () {
      var preImage = List<int>.generate(50, (i) => i);
      var partialHash = List<int>.generate(32, (i) => i + 0x10);
      var partialWitnessPreImage = List<int>.generate(128, (i) => i + 0x20);
      var fundingTxId = List<int>.generate(32, (i) => i + 0x30);

      var builder = PartialWitnessFtUnlockBuilder(
          preImage, partialHash, partialWitnessPreImage, fundingTxId);
      var script = builder.getScriptSig();

      var parsed = PartialWitnessFtUnlockBuilder.fromScript(script);

      expect(ListEquality().equals(parsed.preImage, preImage), true);
      expect(ListEquality().equals(parsed.partialHash, partialHash), true);
      expect(ListEquality().equals(parsed.partialWitnessPreImage, partialWitnessPreImage), true);
      expect(ListEquality().equals(parsed.fundingTxId, fundingTxId), true);
    });
  });
}
