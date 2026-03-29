import 'package:dartsv/dartsv.dart';

import 'provisioned_funding_tx.dart';

/// Builds a two-level fan-out of funding transactions from a single large UTXO.
///
/// Level 1 (split TX): fans the input into N earmark outputs + change.
/// Level 2 (earmark TXs): each earmark output produces a 2-output TX with
/// the target funding amount at vout=1 (satisfying PP1/PP3 hardcoded constraints).
///
/// All transactions are built in memory using chained spending — dartsv
/// computes txids deterministically from serialization, so TX-B can reference
/// TX-A before either is broadcast.
class FundingProvisionBuilder {
  // P2PKH transaction size constants (bytes)
  static const int txOverhead = 10;      // 4 version + 1 inputCount + 1 outputCount + 4 locktime
  static const int p2pkhInput = 148;     // 32 txid + 4 vout + 1 scriptLen + 107 scriptSig + 4 seq
  static const int p2pkhOutput = 34;     // 8 value + 1 scriptLen + 25 scriptPubKey
  static const int dustLimit = 546;      // BSV dust limit for P2PKH

  // Token transaction size estimates (bytes, verified on-chain)
  static const int issuanceWitnessSize = 3400;
  static const int transferSize = 66600;
  static const int transferWitnessSize = 70000;

  // Locked output amounts (sats)
  static const int witnessLocked = 1;    // ModP2PKH output
  static const int tokenTxLocked = 3;    // PP1 + PP2 + PP3

  FundingProvisionBuilder._();

  /// Provision funding for one or more token lifecycle steps.
  ///
  /// Each lifecycle step (issue + witness + transfer + witness) requires
  /// 3 earmark TXs. The issuance itself has no vout constraint and uses
  /// the split TX change.
  ///
  /// [fundingTx] is the transaction providing the input UTXO.
  /// [fundingVout] is the output index of the funding UTXO.
  /// [fundingSigner] signs the split TX input (key that owns the funding UTXO).
  /// [changeSigner] signs earmark TX inputs (key that owns [changeAddress]).
  /// [changeAddress] is the destination for change and dust outputs.
  /// [lifecycleSteps] is the number of issue+witness+transfer+witness cycles.
  /// [feeRateSatsPerKb] is the target fee rate in satoshis per kilobyte.
  ///
  /// Returns an ordered list of transactions for sequential broadcast
  /// (split first, then earmarks).
  static List<ProvisionedFundingTx> provision(
    Transaction fundingTx,
    int fundingVout,
    TransactionSigner fundingSigner,
    SVPublicKey fundingPubKey,
    TransactionSigner changeSigner,
    SVPublicKey changePubKey,
    Address changeAddress,
    int lifecycleSteps,
    int feeRateSatsPerKb,
  ) {
    if (lifecycleSteps < 1) {
      throw ArgumentError('lifecycleSteps must be >= 1');
    }

    final issuanceWitnessFunding =
        computeFee(issuanceWitnessSize, feeRateSatsPerKb) + witnessLocked;
    final transferFunding =
        computeFee(transferSize, feeRateSatsPerKb) + tokenTxLocked;
    final transferWitnessFunding =
        computeFee(transferWitnessSize, feeRateSatsPerKb) + witnessLocked;

    final earmarkTxSize = txOverhead + p2pkhInput + 2 * p2pkhOutput;
    final earmarkFee = computeFee(earmarkTxSize, feeRateSatsPerKb);

    final splitOutIssuanceWitness =
        issuanceWitnessFunding + dustLimit + earmarkFee;
    final splitOutTransfer = transferFunding + dustLimit + earmarkFee;
    final splitOutTransferWitness =
        transferWitnessFunding + dustLimit + earmarkFee;

    final earmarkCount = 3 * lifecycleSteps;
    final splitOutputCount = earmarkCount + 1; // earmarks + change
    final splitTxSize = txOverhead + p2pkhInput + splitOutputCount * p2pkhOutput;
    final splitFee = computeFee(splitTxSize, feeRateSatsPerKb);

    final totalEarmarkSats = lifecycleSteps *
        (splitOutIssuanceWitness + splitOutTransfer + splitOutTransferWitness);
    final inputSats = fundingTx.outputs[fundingVout].satoshis.toInt();
    final changeSats = inputSats - totalEarmarkSats - splitFee;

    if (changeSats < dustLimit) {
      throw ArgumentError(
          'Insufficient funds: need ${totalEarmarkSats + splitFee + dustLimit}'
          ' sats but input has $inputSats');
    }

    return _buildTree(
      fundingTx, fundingVout, fundingSigner, fundingPubKey,
      changeSigner, changePubKey, changeAddress, lifecycleSteps,
      earmarkFee, splitFee, changeSats,
      splitOutIssuanceWitness, splitOutTransfer, splitOutTransferWitness,
      issuanceWitnessFunding, transferFunding, transferWitnessFunding,
    );
  }

  static List<ProvisionedFundingTx> _buildTree(
    Transaction fundingTx,
    int fundingVout,
    TransactionSigner fundingSigner,
    SVPublicKey fundingPubKey,
    TransactionSigner changeSigner,
    SVPublicKey changePubKey,
    Address changeAddress,
    int lifecycleSteps,
    int earmarkFee,
    int splitFee,
    int changeSats,
    int splitOutIssuanceWitness,
    int splitOutTransfer,
    int splitOutTransferWitness,
    int issuanceWitnessFunding,
    int transferFunding,
    int transferWitnessFunding,
  ) {
    final changeLock = P2PKHLockBuilder.fromAddress(changeAddress);

    // Level 1: Split TX
    final splitBuilder = TransactionBuilder()
        .spendFromTxnWithSigner(fundingSigner, fundingTx, fundingVout,
            TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(fundingPubKey));

    for (var step = 0; step < lifecycleSteps; step++) {
      splitBuilder.spendToLockBuilder(
          P2PKHLockBuilder.fromAddress(changeAddress),
          BigInt.from(splitOutIssuanceWitness));
      splitBuilder.spendToLockBuilder(
          P2PKHLockBuilder.fromAddress(changeAddress),
          BigInt.from(splitOutTransfer));
      splitBuilder.spendToLockBuilder(
          P2PKHLockBuilder.fromAddress(changeAddress),
          BigInt.from(splitOutTransferWitness));
    }
    splitBuilder.spendToLockBuilder(changeLock, BigInt.from(changeSats));

    final splitTx = splitBuilder.build(false);

    final results = <ProvisionedFundingTx>[
      ProvisionedFundingTx(
        txid: splitTx.id,
        rawHex: splitTx.serialize(),
        feeSats: splitFee,
        role: 'split',
        purpose: null,
        fundingVout: -1,
        fundingSats: -1,
      ),
    ];

    // Level 2: Earmark TXs
    const purposes = ['issuance-witness', 'transfer', 'transfer-witness'];
    final targets = [issuanceWitnessFunding, transferFunding, transferWitnessFunding];

    for (var step = 0; step < lifecycleSteps; step++) {
      for (var p = 0; p < 3; p++) {
        final splitOutputIndex = step * 3 + p;
        final targetSats = targets[p];
        final splitOutputSats =
            splitTx.outputs[splitOutputIndex].satoshis.toInt();
        final dustSats = splitOutputSats - targetSats - earmarkFee;

        // Fresh unlocker per TX — TransactionBuilder mutates during build
        final earmarkBuilder = TransactionBuilder()
            .spendFromTxnWithSigner(changeSigner, splitTx, splitOutputIndex,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(changePubKey));

        earmarkBuilder.spendToLockBuilder(
            P2PKHLockBuilder.fromAddress(changeAddress),
            BigInt.from(dustSats));
        earmarkBuilder.spendToLockBuilder(
            P2PKHLockBuilder.fromAddress(changeAddress),
            BigInt.from(targetSats));

        final earmarkTx = earmarkBuilder.build(false);

        results.add(ProvisionedFundingTx(
          txid: earmarkTx.id,
          rawHex: earmarkTx.serialize(),
          feeSats: earmarkFee,
          role: 'earmark',
          purpose: purposes[p],
          fundingVout: 1,
          fundingSats: targetSats,
        ));
      }
    }

    return results;
  }

  /// Compute fee in satoshis for a given transaction size and fee rate.
  /// Uses ceiling division: `(txSizeBytes * feeRate + 999) ~/ 1000`.
  static int computeFee(int txSizeBytes, int feeRateSatsPerKb) {
    final fee = (txSizeBytes * feeRateSatsPerKb + 999) ~/ 1000;
    return fee < 1 ? 1 : fee;
  }
}
