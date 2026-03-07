# TSL1 Token Library — Production Readiness Roadmap

This document outlines the gaps between the current alpha implementation and a production-ready release, organized into four phases.

---

## Phase 1: Stabilize

Goal: Clean up the existing codebase so it is safe, predictable, and ready for feature work.

### 1.1 Remove Debug Output
- [x] Remove all `print()` statements from `lib/src/transaction/token_tool.dart`
- [x] Remove all `print()` statements from `lib/src/transaction/utils.dart`
- [x] Remove `printPreImage()` debug utility and unused `readVarIntNum()`

### 1.2 Parameterize Hardcoded Values
- [x] Replace hardcoded `NetworkType.TEST` in `token_tool.dart` with a configurable `networkType` constructor parameter
- [x] Replace hardcoded fee of 135 satoshis with configurable `defaultFee` constructor parameter
- [x] Document magic numbers (SHA256 block size constant in `utils.dart`)

### 1.3 Input Validation
- [x] Validate `PP1LockBuilder` constructor (recipient address required, token ID must be 32 bytes)
- [x] Validate `PP2LockBuilder` constructor (outpoint 36 bytes, PKH 20 bytes, non-negative amount)
- [x] Fail fast with descriptive `ScriptException` errors rather than producing invalid scripts silently

### 1.4 Export New Builders
- [x] Add exports to `lib/tstokenlib.dart` for:
  - `aip_lockbuilder.dart`
  - `b_lockbuilder.dart`
  - `bmap_lockbuilder.dart`
  - `map_lockbuilder.dart`
  - `hodl_lockbuilder.dart`
  - `hodl_unlockbuilder.dart`
  - `mod_p2pkh_builder.dart`

### 1.5 Code Cleanup
- [x] Remove commented-out code in `pp1_unlock_builder.dart` and `token_tool.dart`
- [x] Fix double-slash typo in `tstokenlib.dart` export path (`src/transaction//partial_sha256.dart`)

---

## Phase 2: Complete Core Protocol

Goal: Implement the missing protocol features required for real-world token usage.

### 2.1 Token Metadata
- [ ] Define a `TokenMetadata` data class with fields: name, symbol, description, decimals, total supply, icon URI
- [ ] Define a serialization format for on-chain metadata storage (consider using B/MAP protocols already partially implemented)
- [ ] Attach metadata to the issuance transaction (likely as an additional OP_RETURN output)
- [ ] Implement metadata parsing from existing token transactions

### 2.2 Issuer Identity
- [ ] Implement issuer identity anchoring in PP1 (address the TODO at `pp1_lock_builder.dart:83`)
- [ ] Integrate AIP (Author Identity Protocol) signing into the issuance flow
- [ ] Add issuer public key verification during token transfer validation
- [ ] Consider supporting Paymail-based identity resolution

### 2.3 Token Burn
- [ ] Implement `burnToken()` in `TokenTool` using the existing `TokenAction.BURN` enum value
- [ ] Wire up the `burnToken()` public function in `tsl1_PP1.scrypt` through the unlock builder
- [ ] Add validation that only the current token owner can burn

### 2.4 Implement `parse()` Methods
- [ ] `PP2LockBuilder.parse()` — reconstruct builder state from an existing PP2 locking script
- [ ] `PartialWitnessLockBuilder.parse()` — reconstruct from existing partial witness script
- [ ] `HodlLockBuilder.parse()` — reconstruct from existing HODL script
- [ ] These are essential for reading token state from on-chain transactions

---

## Phase 3: Test Coverage

Goal: Build confidence that the protocol implementation is correct and handles edge cases.

### 3.1 Core Protocol Tests
- [ ] Token issuance — valid issuance produces correct 4-output structure
- [ ] Token transfer — single transfer with witness validation
- [ ] Token transfer chain — multiple successive transfers (A -> B -> C)
- [ ] Token burn — owner can burn, non-owner cannot
- [ ] Witness transaction — correct partial SHA256 computation across various tx sizes

### 3.2 Error & Edge Case Tests
- [ ] Invalid/missing funding transaction
- [ ] Insufficient funds for fees
- [ ] Wrong owner attempting transfer
- [ ] Malformed parent transaction in transfer validation
- [ ] Padding byte edge cases (transactions at exact 64-byte boundaries)
- [ ] Empty or oversized metadata

### 3.3 Builder Tests
- [ ] PP1LockBuilder — lock/parse round-trip
- [ ] PP2LockBuilder — lock/parse round-trip
- [ ] PartialWitnessLockBuilder — lock/parse round-trip
- [ ] ModP2PKHLockBuilder — lock/parse round-trip, verify swapped sig/pubkey order
- [ ] AIPLockBuilder — signing and verification
- [ ] BLockBuilder — data attachment
- [ ] BMAPLockBuilder — structured data mapping
- [ ] MapLockBuilder — key-value storage
- [ ] HodlLockBuilder/UnlockBuilder — time-lock enforcement

### 3.4 Integration Tests
- [ ] Full lifecycle: issue -> transfer -> transfer -> burn
- [ ] Mainnet vs testnet configuration
- [ ] Fee calculation across different transaction sizes

---

## Phase 4: Documentation & Release Prep

Goal: Make the library usable by external developers.

### 4.1 API Documentation
- [ ] Add Dartdoc comments to all public classes and methods in `TokenTool`
- [ ] Add Dartdoc comments to all builder classes
- [ ] Add Dartdoc comments to utility functions
- [ ] Generate and host API reference docs

### 4.2 Architecture Guide
- [ ] Document the 4-output transaction structure (Change, PP1, PP2, PP3)
- [ ] Explain the inductive proof mechanism and why no back-to-genesis tracing is needed
- [ ] Explain the partial SHA256 witness mechanism
- [ ] Document the relationship between token, witness, and funding transactions
- [ ] Include transaction flow diagrams

### 4.3 Usage Guide
- [ ] Expand README with complete examples for: issuance, transfer, burn
- [ ] Add example project in `example/` directory
- [ ] Document error handling and common failure modes
- [ ] Add troubleshooting section

### 4.4 Security Review
- [ ] Audit all script template hex strings against compiled sCrypt output
- [ ] Review sighash preimage handling for correctness
- [ ] Verify no private key material is logged or leaked
- [ ] Document security model and threat assumptions
- [ ] External review of sCrypt contract logic

### 4.5 Release
- [ ] Remove "NOT PRODUCTION READY" warning from README
- [ ] Update version to 1.0.0
- [ ] Publish to pub.dev
- [ ] Tag release in git

---

## Key Files Reference

| File | Role |
|------|------|
| `lib/src/transaction/token_tool.dart` | Core token operations API |
| `lib/src/transaction/utils.dart` | Transaction utilities, padding, partial hash |
| `lib/src/transaction/partial_sha256.dart` | Single-block SHA256 implementation |
| `lib/src/builder/pp1_lock_builder.dart` | PP1 inductive proof locking script |
| `lib/src/builder/pp1_unlock_builder.dart` | PP1 unlocking script (issue/transfer/burn) |
| `lib/src/builder/pp2_lock_builder.dart` | PP2 witness bridge locking script |
| `lib/src/builder/pp2_unlock_builder.dart` | PP2 unlocking script |
| `lib/src/builder/partial_witness_lock_builder.dart` | PP3 partial SHA256 locking script |
| `lib/src/builder/partial_witness_unlock_builder.dart` | PP3 unlocking script |
| `scrypt/contracts/tsl1_PP1.scrypt` | sCrypt: inductive proof contract |
| `scrypt/contracts/tsl1_PP2.scrypt` | sCrypt: witness validation contract |
| `scrypt/contracts/tsl1_partial_witness.scrypt` | sCrypt: partial SHA256 contract |