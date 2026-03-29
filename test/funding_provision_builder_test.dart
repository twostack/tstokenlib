import 'dart:typed_data';

import 'package:dartsv/dartsv.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

/// Create a synthetic funding transaction with a P2PKH output at [vout]
/// carrying [sats] satoshis locked to [address].
Transaction createFundingTx(
    SVPrivateKey key, SVPublicKey pubKey, Address address, int sats,
    {int vout = 0}) {
  // Build a fake coinbase-like TX with the desired output
  final builder = TransactionBuilder();

  // Dummy input (simulates a prior funding source)
  final dummyTxId = HEX.encode(List.filled(32, 0x01));
  final dummyScript = P2PKHLockBuilder.fromAddress(address).getScriptPubkey();
  final outpoint = TransactionOutpoint(
    dummyTxId,
    0,
    BigInt.from(sats + 10000), // enough to cover the output + fee
    dummyScript,
  );
  final sigHashAll =
      SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
  final txSigner = DefaultTransactionSigner(sigHashAll, key);
  builder.spendFromOutpointWithSigner(txSigner, outpoint,
      TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(pubKey));

  // If vout > 0, add dust outputs before the target
  for (var i = 0; i < vout; i++) {
    builder.spendToLockBuilder(
        P2PKHLockBuilder.fromAddress(address), BigInt.from(546));
  }
  builder.spendToLockBuilder(
      P2PKHLockBuilder.fromAddress(address), BigInt.from(sats));

  builder.withFeePerKb(1);
  builder.withOption(TransactionOption.DISABLE_DUST_OUTPUTS);
  return builder.build(false);
}

void main() {
  final privateKey = SVPrivateKey.fromWIF(
      'cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final publicKey = privateKey.publicKey;
  final address = Address.fromPublicKey(publicKey, NetworkType.TEST);
  final sigHashAll =
      SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
  final signer = DefaultTransactionSigner(sigHashAll, privateKey);

  group('FundingProvisionBuilder', () {
    test('single lifecycle step produces 4 TXs (1 split + 3 earmarks)', () {
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 500000, vout: 0);
      final results = FundingProvisionBuilder.provision(
        fundingTx, 0, signer, publicKey, signer, publicKey,
        address, 1, 100,
      );

      expect(results.length, equals(4));

      // First TX is the split
      expect(results[0].role, equals('split'));
      expect(results[0].purpose, isNull);
      expect(results[0].fundingVout, equals(-1));

      // Remaining 3 are earmarks
      expect(results[1].role, equals('earmark'));
      expect(results[1].purpose, equals('issuance-witness'));
      expect(results[1].fundingVout, equals(1));

      expect(results[2].role, equals('earmark'));
      expect(results[2].purpose, equals('transfer'));
      expect(results[2].fundingVout, equals(1));

      expect(results[3].role, equals('earmark'));
      expect(results[3].purpose, equals('transfer-witness'));
      expect(results[3].fundingVout, equals(1));
    });

    test('multi-step (2 steps) produces 7 TXs (1 split + 6 earmarks)', () {
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 1000000, vout: 0);
      final results = FundingProvisionBuilder.provision(
        fundingTx, 0, signer, publicKey, signer, publicKey,
        address, 2, 100,
      );

      expect(results.length, equals(7));
      expect(results[0].role, equals('split'));

      // 6 earmarks: 2 sets of (issuance-witness, transfer, transfer-witness)
      final earmarks = results.skip(1).toList();
      expect(earmarks.length, equals(6));
      expect(earmarks[0].purpose, equals('issuance-witness'));
      expect(earmarks[1].purpose, equals('transfer'));
      expect(earmarks[2].purpose, equals('transfer-witness'));
      expect(earmarks[3].purpose, equals('issuance-witness'));
      expect(earmarks[4].purpose, equals('transfer'));
      expect(earmarks[5].purpose, equals('transfer-witness'));
    });

    test('earmark inputs reference split TX outputs', () {
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 500000, vout: 0);
      final results = FundingProvisionBuilder.provision(
        fundingTx, 0, signer, publicKey, signer, publicKey,
        address, 1, 100,
      );

      final splitTxid = results[0].txid;

      // Each earmark TX should spend from the split TX
      for (var i = 1; i < results.length; i++) {
        final earmarkTx = Transaction.fromHex(results[i].rawHex);
        expect(earmarkTx.inputs[0].prevTxnId, equals(splitTxid),
            reason: 'Earmark $i should spend from split TX');
      }
    });

    test('earmark vout=1 matches declared fundingSats', () {
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 500000, vout: 0);
      final results = FundingProvisionBuilder.provision(
        fundingTx, 0, signer, publicKey, signer, publicKey,
        address, 1, 100,
      );

      for (var i = 1; i < results.length; i++) {
        final earmarkTx = Transaction.fromHex(results[i].rawHex);
        expect(earmarkTx.outputs.length, equals(2),
            reason: 'Earmark TX should have 2 outputs');
        expect(earmarkTx.outputs[1].satoshis.toInt(),
            equals(results[i].fundingSats),
            reason: 'vout=1 sats should match declared fundingSats');
      }
    });

    test('split TX has correct output count', () {
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 500000, vout: 0);
      final results = FundingProvisionBuilder.provision(
        fundingTx, 0, signer, publicKey, signer, publicKey,
        address, 1, 100,
      );

      final splitTx = Transaction.fromHex(results[0].rawHex);
      // 3 earmark outputs + 1 change = 4
      expect(splitTx.outputs.length, equals(4));
    });

    test('insufficient funds throws ArgumentError', () {
      // Only 100 sats — way too small
      final fundingTx =
          createFundingTx(privateKey, publicKey, address, 100, vout: 0);
      expect(
        () => FundingProvisionBuilder.provision(
          fundingTx, 0, signer, publicKey, signer, publicKey,
          address, 1, 100,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('computeFee uses ceiling division', () {
      // 226 bytes * 100 sats/KB = 22600 / 1000 = 22.6 → ceil = 23
      expect(FundingProvisionBuilder.computeFee(226, 100), equals(23));
      // 1000 bytes * 1 sat/KB = 1000 / 1000 = 1.0 → exactly 1
      expect(FundingProvisionBuilder.computeFee(1000, 1), equals(1));
      // Minimum fee is 1
      expect(FundingProvisionBuilder.computeFee(1, 1), equals(1));
    });
  });
}
