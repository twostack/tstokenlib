## 1.4.0

- Update dartsv dependency to ^3.0.0 (abstract TransactionSigner support)

## 1.3.0
On-chain Identity Anchoring & Hand-optimized Scripts

- **Mandatory Rabin identity anchoring for NFT issuance**: PP1 now verifies a Rabin signature
  (`s² mod n == sha256(identityTxId || ed25519PubKey) + padding`) during issuance, enforcing
  that only the holder of the identity key can mint tokens. The `rabinPubKeyHash` is a new
  required parameter on `createTokenIssuanceTxn` and `PP1NftLockBuilder`.
- **Hand-optimized PP1 script**: Replaced the ~11KB compiled sCrypt template with a 2.5KB
  hand-optimized Bitcoin Script (~4.5x reduction).
- **Hand-optimized PP1_FT script**: Replaced the ~56KB compiled sCrypt template with an 8.2KB
  hand-optimized Bitcoin Script (~6.7x reduction).
- **Rabin cryptographic utilities**: New `Rabin` class with key generation, signing, and
  verification (`lib/src/crypto/rabin.dart`).
- **Fungible token support**: `FungibleTokenTool` with full lifecycle — mint, transfer, split,
  merge, and burn operations.
- **Issuer identity anchoring**: `IdentityAnchorBuilder` and `IdentityVerification` for
  linking tokens to ED25519-signed issuer identities.
- **Configurable fees**: `TokenTool` and `FungibleTokenTool` accept `defaultFee` and
  `networkType` constructor parameters.

## 1.0.0

- Initial version.
