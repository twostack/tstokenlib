/// A single transaction in a funding provision batch.
///
/// Structurally identical to libspiffy's `ProvisionedTransaction` but
/// defined in tstokenlib to avoid cross-library dependency. Plugin
/// implementations trivially map between the two.
class ProvisionedFundingTx {
  /// Transaction ID (hex).
  final String txid;

  /// Raw transaction hex.
  final String rawHex;

  /// Fee paid by this transaction in satoshis.
  final int feeSats;

  /// Role in the provision tree: "split" (level 1) or "earmark" (level 2).
  final String role;

  /// Earmark purpose. Null for split TX.
  /// Values: "issuance-witness", "transfer", "transfer-witness".
  final String? purpose;

  /// Output index where earmarked sats sit.
  /// Always 1 for earmarks (protocol constraint), -1 for split.
  final int fundingVout;

  /// Satoshis at [fundingVout]. -1 for split.
  final int fundingSats;

  const ProvisionedFundingTx({
    required this.txid,
    required this.rawHex,
    required this.feeSats,
    required this.role,
    this.purpose,
    required this.fundingVout,
    required this.fundingSats,
  });
}
