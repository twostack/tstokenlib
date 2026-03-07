# TSL1 Token Library -- Security Review

**Date:** 2026-03-08
**Scope:** Defensive security audit of `tstokenlib` Dart library
**Reviewed files:**
- `lib/src/transaction/token_tool.dart`
- `lib/src/transaction/utils.dart`
- `lib/src/transaction/partial_sha256.dart`
- `lib/src/transaction/identity_verification.dart`
- `lib/src/builder/pp1_lock_builder.dart`
- `lib/src/builder/pp1_unlock_builder.dart`
- `lib/src/builder/pp2_lock_builder.dart`
- `lib/src/builder/pp2_unlock_builder.dart`
- `lib/src/builder/partial_witness_lock_builder.dart`
- `lib/src/builder/mod_p2pkh_builder.dart`
- `lib/tstokenlib.dart` (public API surface)
- All `lib/**/*.dart` files searched for `print()` statements
- All `test/**/*.dart` files searched for `print()` statements

---

## Findings

### F-01: Debug Script Template Active in Production Code

**Severity:** High

**Location:** `lib/src/builder/pp2_lock_builder.dart` (lines 38-42), `lib/src/builder/partial_witness_lock_builder.dart` (lines 45-49), `lib/src/builder/pp1_lock_builder.dart` (line 45)

**Description:** All three lock builders (PP1, PP2, PartialWitness) have their `template` field set to the DEBUG-compiled sCrypt hex. The RELEASE template is present but commented out. The debug template includes sCrypt debug opcodes (e.g., `OP_RETURN`-based error reporting) that make the scripts larger and potentially expose internal contract logic to anyone inspecting the blockchain.

The `template` field is a mutable, non-final instance variable (`String template = "..."`), meaning any code with a reference to a builder instance could overwrite the template at runtime.

**Recommendation:**
1. Switch to the RELEASE template before any mainnet deployment.
2. Make `template` a `static const` or `final` field to prevent runtime mutation.
3. Consider a compile-time or environment-based toggle rather than code comments.

---

### F-02: No Input Validation in TokenTool Public API Methods

**Severity:** Medium

**Location:** `lib/src/transaction/token_tool.dart` -- all four public methods (`createWitnessTxn`, `createTokenIssuanceTxn`, `createTokenTransferTxn`, `createBurnTokenTxn`)

**Description:** None of the public API methods perform any validation on their inputs before use. Examples:
- `createWitnessTxn` does not verify that `tokenTx` has the expected number of outputs (at least 3), that `parentTokenTxBytes` is non-empty, or that `tokenChangePKH` is a valid 20-byte hex string.
- `createTokenIssuanceTxn` does not validate that `witnessFundingTxId` is exactly 32 bytes.
- `createTokenTransferTxn` does not validate that `prevTokenTx` has at least 5 outputs (it accesses `outputs[4]` directly), or that `tokenId` is 32 bytes.
- `createBurnTokenTxn` does not validate output count on `tokenTx`.

Invalid inputs will cause unguarded index-out-of-range exceptions or produce malformed transactions that fail on-chain, but with no clear error message indicating the root cause.

**Recommendation:** Add guard clauses at the top of each public method to validate:
- Transaction output counts match the expected structure.
- Byte arrays (txids, PKHs) have the correct lengths (32 bytes for txids, 20 bytes for PKHs).
- Required parameters are non-null and non-empty.

---

### F-03: Template Substitution Uses String Replacement on Hex

**Severity:** Low

**Location:** `lib/src/builder/pp1_lock_builder.dart` (lines 73-75), `lib/src/builder/pp2_lock_builder.dart` (lines 74-78), `lib/src/builder/partial_witness_lock_builder.dart` (line 55)

**Description:** Script construction uses `String.replaceFirst()` on placeholder tokens (e.g., `<recipientPKH>`, `<tokenId>`, `<outpoint>`) within a hex-encoded script template. The replacement values are produced by `ScriptBuilder().addData(...)`, which correctly applies Bitcoin pushdata encoding (length prefix + raw bytes), so the substitution itself is structurally safe -- it is not susceptible to injection because:
1. The placeholders are unique angle-bracket strings that cannot appear in valid hex output.
2. The replacement values go through `ScriptBuilder`, which enforces pushdata formatting.

However, if a placeholder string were to accidentally appear in the compiled hex (astronomically unlikely but theoretically possible in a different template), the `replaceFirst` approach could produce a corrupted script.

**Recommendation:** No immediate action required. The current approach is functionally safe. For defense in depth, consider building the script by byte-level concatenation (prefix bytes + pushdata + suffix bytes) rather than string replacement, which would eliminate the theoretical risk entirely.

---

### F-04: Sighash Type Correctly Configured but Not Validated

**Severity:** Info

**Location:** `lib/src/transaction/token_tool.dart` (line 56)

**Description:** The sighash type is set to `SIGHASH_ALL | SIGHASH_FORKID`, which is the correct and standard sighash type for BSV transactions. It is stored as an instance variable `sigHashAll` (not `final`), so it could theoretically be modified after construction, though this would require direct field access by the caller.

The sighash type is consistently used across all preimage computations (`createSighashPreImage` calls on lines 93 and 244).

**Recommendation:** Make `sigHashAll` a `final` field to prevent accidental mutation.

---

### F-05: Private Key Material Handling

**Severity:** Info (Positive Finding)

**Location:** `lib/src/transaction/token_tool.dart`, all builder files

**Description:** The library correctly avoids handling raw private keys. All signing is done through the `TransactionSigner` abstraction (passed in by the caller). The `SVPublicKey` type is used for public key references, and no private key (`SVPrivateKey`) is imported, stored, or logged anywhere in the `lib/` source tree.

The `SignatureWand` used for ED25519 identity signing (line 179 of `token_tool.dart`) is also an abstraction that does not expose the underlying key material.

No `print()` statements exist anywhere in `lib/`. All `print()` calls are confined to `test/` files, where they log transaction IDs and script bytes -- not private keys or signatures.

**Recommendation:** No action required. This is good practice.

---

### F-06: Test Files Contain Debug Print Statements

**Severity:** Low

**Location:** `test/plugpoint_spending_test.dart` (approximately 30 print statements), `test/partial_sha256_test.dart`, `test/mod_p2pkh_test.dart`

**Description:** Test files contain numerous `print()` calls that output transaction IDs, serialized transactions, script hex bytes, and output details. While these are in test code (not shipped in the library), they could expose transaction structure details in CI logs or during collaborative development.

None of the print statements output private keys or raw signatures. The data logged is limited to public transaction data (txids, serialized transactions, script bytes).

**Recommendation:** Replace `print()` calls in tests with a logging framework or remove them. Consider using `expect()` assertions instead of printing values for manual inspection.

---

### F-07: Silent Error Swallowing in Identity Verification

**Severity:** Low

**Location:** `lib/src/transaction/identity_verification.dart` (lines 24, 56, 105)

**Description:** Three `catch (_)` blocks silently swallow all exceptions:
- `extractIdentityFromMetadata` returns null values on any parse error.
- `verifyIssuanceIdentity` returns `false` on any verification error.
- `verifyIdentityAnchor` returns `false` on any verification error.

While returning `false` for failed verification is reasonable (fail-closed), swallowing all exceptions without any logging or error reporting makes debugging difficult. A malformed identity anchor or corrupted data would be indistinguishable from a legitimately invalid identity.

**Recommendation:** Log or report the exception type/message at debug level before returning `false`/null. This preserves the fail-closed behavior while enabling diagnostics.

---

### F-08: PP1 Parse Validation Uses Arbitrary Chunk Count Check

**Severity:** Low

**Location:** `lib/src/builder/pp1_lock_builder.dart` (line 86)

**Description:** The `parse()` method checks `chunkList.length < 1000` and throws if the script has fewer than 1000 chunks. This is a rough heuristic rather than a precise structural validation. If the compiled sCrypt template changes in a way that alters chunk count, this check could break or allow malformed scripts through.

**Recommendation:** Replace the arbitrary `1000` threshold with the actual expected chunk count of the PP1 template, or validate the script prefix/structure instead of relying on chunk count alone.

---

### F-09: Partial SHA256 Implementation Correctness

**Severity:** Info

**Location:** `lib/src/transaction/partial_sha256.dart`

**Description:** The `PartialSha256` class implements SHA256 block-level hashing manually. The implementation follows the standard SHA256 algorithm (FIPS 180-4) with correct:
- Round constants (K array, 64 entries)
- Initial hash values (H0)
- Message schedule expansion (W array)
- Compression function (ch, maj, sigma functions)
- Padding scheme (append 0x80 bit, length in bits at end)

The `rotateRight` and `ushr` functions correctly handle unsigned right shift in Dart's signed integer environment.

One concern: Dart's `int` type is 64-bit on native platforms but 53-bit on web (JavaScript). The SHA256 implementation relies on 32-bit overflow behavior. The use of `Int32List` for working arrays ensures correct 32-bit wrapping on native platforms, but intermediate arithmetic (e.g., `t1`, `t2` in `hashOneBlock`) is performed with regular `int` before being stored back into `Int32List`. On native Dart this works correctly due to 64-bit int precision with implicit truncation on Int32List storage.

**Recommendation:** Add a comment documenting that this implementation is intended for native Dart only (not dart2js/web). If web support is ever needed, explicit masking to 32 bits would be required.

---

### F-10: `_subscriptAfterCodeSep` Method is Unused

**Severity:** Info

**Location:** `lib/src/transaction/token_tool.dart` (lines 300-328)

**Description:** The private method `_subscriptAfterCodeSep` is defined but never called from any code path. It appears to be dead code, possibly leftover from an earlier iteration. While it has no security impact as dead code, its presence could cause confusion.

**Recommendation:** Remove or document this method's intended purpose. If it is planned for future use, add a TODO comment.

---

### F-11: Hardcoded Public Keys in Script Templates

**Severity:** Info

**Location:** `lib/src/builder/pp2_lock_builder.dart` (template string), `lib/src/builder/pp1_lock_builder.dart` (template string)

**Description:** The script templates contain hardcoded public keys and hash values that are baked into the compiled sCrypt output. For example, in the PP2 template: `210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc8` and `206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081`. These appear to be ECDSA curve parameters (generator point, order) used for in-script signature verification, not arbitrary keys.

These values are part of the compiled sCrypt contract and are correct for the secp256k1 curve used in Bitcoin. They are not "secret" but their presence should be understood by anyone maintaining the code.

**Recommendation:** Add a comment in each builder identifying what these hardcoded values represent (e.g., "secp256k1 generator point G" and "curve order n").

---

### F-12: Issuance Identity Anchor Signature Not Verified at Parse Time

**Severity:** Medium

**Location:** `lib/src/builder/pp1_lock_builder.dart` (lines 100-101)

**Description:** There is an explicit TODO comment: `//TODO: Add signature validation for issuance identity anchor`. The `parse()` method for PP1 extracts the recipient PKH and token ID from a script but does not validate the identity anchor signature. This means that when reconstructing a PP1 script from on-chain data, the identity linkage is not verified.

The `IdentityVerification` class provides separate verification methods, but they are not integrated into the parsing pipeline.

**Recommendation:** Implement the TODO or document that identity verification must be performed separately by the caller using `IdentityVerification.verifyIssuanceIdentity()`.

---

## Security Model & Threat Assumptions

### What the Protocol Trusts

1. **Bitcoin Script Interpreter (Miners):** The protocol's security fundamentally relies on miners correctly executing Bitcoin Script. The on-chain scripts (PP1, PP2, PartialWitness) enforce the token rules. If the script interpreter has bugs or miners selectively refuse valid transactions, the protocol breaks.

2. **SHA256 Preimage Resistance:** The partial SHA256 witness mechanism relies on SHA256's collision resistance and preimage resistance. The partial hash computation assumes that providing a valid intermediate hash state and remaining blocks is equivalent to proving knowledge of the full preimage.

3. **ECDSA/secp256k1 Signature Security:** Token ownership is enforced via standard P2PKH-like signature checks (modified P2PKH in `ModP2PKHLockBuilder`). The security of token ownership transfer depends on the hardness of ECDSA signature forgery.

4. **ED25519 Signature Security (Identity):** The issuer identity anchoring system uses ED25519 signatures. Trust in issuer identity depends on the issuer's ED25519 private key remaining secret.

5. **Transaction Immutability:** Once a transaction is mined, the protocol assumes it cannot be reversed (sufficient confirmations). The inductive proof chain (PP1) would be invalidated by a blockchain reorganization that removes a link in the chain.

6. **Sighash Preimage Integrity:** PP2's in-script preimage reconstruction relies on the correctness of the sighash preimage format as defined by the BSV protocol (BIP143-style). Any protocol-level changes to sighash computation would break the proof mechanism.

### What the Protocol Does NOT Trust

1. **Token Holders:** Token holders cannot forge transfers because they must produce valid signatures that satisfy the locking scripts. The inductive proof (PP1) ensures that a holder can only transfer a token they legitimately received.

2. **Network Peers:** Transaction data is verified on-chain via script execution. The library does not rely on any off-chain attestation or peer honesty.

3. **Arbitrary Input Data:** The on-chain scripts validate all critical data (txid linkage, output structure, signature validity). The library-side validation is a convenience layer; the scripts are the ultimate enforcement mechanism.

### Known Limitations

1. **No SPV Verification:** The library does not perform SPV (Simplified Payment Verification) of parent transactions. It trusts that the `Transaction` objects passed to the API represent mined (or to-be-mined) transactions. A caller could pass fabricated transactions to the library and produce structurally valid but semantically invalid token transactions.

2. **Single Token per Transaction:** The protocol appears to support one token per transaction chain. There is no batching or multi-token support in the current structure.

3. **Fixed Output Structure:** The protocol requires a rigid output layout (output[0]=change, output[1]=PP1, output[2]=PP2, output[3]=PartialWitness, output[4]=metadata). Any deviation breaks the proof chain. This is enforced by the on-chain scripts but not validated by the library before transaction construction.

4. **Funding Output Index Assumption:** The library consistently assumes funding UTXOs are at output index 1 (e.g., `spendFromTxnWithSigner(..., fundingTx, 1, ...)`). This is a protocol convention, not validated.

5. **Debug Templates in Use:** As noted in F-01, the active script templates are debug versions. These produce larger transactions (higher fees) and may contain debug-only code paths.

6. **No Replay Protection Across Chains:** If the same UTXO set exists on a fork, token transactions could potentially be replayed. The `SIGHASH_FORKID` flag provides some protection, but only between chains with different fork IDs.

7. **Metadata Immutability:** Token metadata (output[4]) is carried forward verbatim during transfers (`prevTokenTx.outputs[4].script`). There is no mechanism to update metadata after issuance, which is by design but limits flexibility.

---

## Summary

| ID    | Severity | Summary                                              |
|-------|----------|------------------------------------------------------|
| F-01  | High     | Debug script templates active; should use RELEASE     |
| F-02  | Medium   | No input validation on public API methods             |
| F-12  | Medium   | Identity anchor signature verification not implemented at parse time |
| F-03  | Low      | Template substitution via string replacement (safe but fragile) |
| F-06  | Low      | Debug print statements in test files                  |
| F-07  | Low      | Silent exception swallowing in identity verification  |
| F-08  | Low      | Arbitrary chunk count threshold in PP1 parse          |
| F-04  | Info     | Sighash type field is non-final                       |
| F-05  | Info     | Private key handling is correct (positive finding)    |
| F-09  | Info     | Partial SHA256 implementation is native-only          |
| F-10  | Info     | Dead code: `_subscriptAfterCodeSep` method            |
| F-11  | Info     | Hardcoded curve parameters in templates need comments |

No critical vulnerabilities were identified. The most actionable finding is F-01 (switch to RELEASE templates before mainnet deployment). The on-chain scripts provide the primary security enforcement; the library is a construction aid, not a validation layer.
