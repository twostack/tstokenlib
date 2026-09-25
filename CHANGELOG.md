## 2.2.0

- **Deposits admitted before their round.** `ShieldedCoordinator` takes an optional `admitDeposit` hook, and has asynchronous entry points `receiveBytes`, `receive` and `admit`. A deposit that passes every check, the proof last, holds its place in the pending round while the caller admits it (for instance by broadcasting the covenant and waiting for the network to see it). It is accepted once admitted and refused, naming the caller's reason, otherwise. A round closed meanwhile waits for the admission and builds without a refused deposit. Without the hook nothing changes. (Also in 2.0.2, for the 2.0.x line.)
- **Fix: a round whose transfers all expired stayed in flight.** Every later deposit was then refused as targeting a round being built. Such a round now leaves the in-flight list, and a closed round that drops entries rebuilds its nullifier, covenant and withdrawal shadow from the entries it keeps.

## 2.1.0

- **The native kernels come with the package.** A build hook
  (`hook/build.dart`) bundles `libstark_kernels` into every program that
  depends on tstokenlib. For macOS (arm64, x64), iOS (device and simulator),
  Linux (x64, arm64, glibc 2.17 and later), Android (arm64, arm, x64) and
  Windows (x64, arm64) it downloads the library CI built from the crate's exact
  source and checks its SHA-256. Anywhere else, or when the crate has been
  edited, it builds with cargo. If it can do neither, the build fails with a
  message naming the options rather than proving in Dart without saying so.
  Before this release a consumer from pub.dev had no kernels unless they built
  them and set `STARK_KERNELS_LIB`, and `NoteKem` refused outright.
- **The `stark_kernels` user-define** chooses how: `auto` (the default),
  `source` (always cargo, never download) or `skip`.
- **Metal on Apple Silicon.** The macOS arm64 library, prebuilt or built by the
  hook, includes the Metal backend. It stays off until `STARK_KERNELS_GPU=1`.
- **`StarkKernels.tryLoad` finds the bundled copy** after `STARK_KERNELS_LIB`
  and before the other places it already searched. `STARK_KERNELS_LIB` still
  wins.
- **Requires Dart 3.10**, the first release where build hooks are stable.

## 2.0.1

- **The native kernels are found beside an installed program.** `StarkKernels.tryLoad` now also looks in the running executable's directory and in `../lib` from it, after `STARK_KERNELS_LIB` and before the source-tree search. A program compiled with `dart compile exe` has no source tree to search, so a package or tarball that ships `libstark_kernels` next to its binary (or in a `lib/` beside its `bin/`) now loads it with no environment variable. `STARK_KERNELS_LIB` still wins.

## 2.0.0

The TSL1_SP shielded pool, a seventh archetype, plus fixes to the existing six.
Major because the State Machine archetype's public names changed; every other
change is additive.

### Breaking

- **State Machine archetype renamed to domain-neutral terms.** `merchant` is now
  `operator`, `customer` is `counterparty`, `custReward` is `counterpartyShare`,
  `merchPay` is `operatorShare`, `merchRefund` is `operatorRecovery`, and
  `milestone` is `checkpoint` (including the public `milestoneCount` getter,
  now `checkpointCount`). **The byte layout is unchanged and no script
  behaviour changed**, so tokens issued under 1.4.0 keep working; only names in
  Dart moved. Aligns with tstokenlib4j for cross-language consistency.

### Added: the TSL1_SP shielded pool

A private-payments archetype: notes in a Merkle commitment tree, spends proved
by a Circle-STARK verified *in Bitcoin Script*, and rounds that aggregate many
transfers into one on-chain proof.

- **The pool as a TSL1 primitive.** `PP1_SP` carries the pool's own header and
  its recursion terminates at a once-spendable genesis outpoint, so a pool chain
  cannot be cloned. `PP3` pins the verifier slot its successor must spend and
  enforces it at mining time.
- **In-script STARK verification.** `V`, the verifier slot script, gates the
  pool's money. Deposits enter under a covenant; withdrawals leave as P2PKH.
- **Recursive aggregation.** A round's transfers fold into one root proof
  through a verifier AIR that verifies Poseidon2-flavour proofs. A 256-transfer
  round was measured end to end at 356 s on one machine.
- **Note encryption.** X25519 + ML-KEM-768 hybrid, with per-asset issuer roles,
  asset ids in the commitment, and viewing keys derived in-circuit.
- **Ledger, reader and scanner.** `ShieldedLedger`, `ShieldedChainReader`,
  `ShieldedNoteScanner`, `NoteCommitmentTree`. `ShieldedLedger.readLeaves` gives
  a wallet a round's leaves, positions and nullifiers from the two transactions
  alone, with no ledger state.
- **A coordinator.** `ShieldedCoordinator` assembles, proves and publishes
  rounds, with a prover pool for level-1 nodes.
- **A wallet protocol, version 3.** `PoolSubmission`, `PoolReply`,
  `PoolDescriptor`, `PoolAnnouncement`, the catch-up request and reply, and
  `PoolRoundMined`. Every message is versioned, bounded before it is read, and
  refused by name rather than thrown on. Transport-free: the bytes are the
  contract.
- **Native prover kernels.** An optional Rust crate (`native/stark_kernels`)
  behind a `ProverKernels` interface, with an experimental Metal backend. **A
  pure-Dart fallback is used when it is absent**, so the package works from
  pub.dev with no Rust toolchain; point `STARK_KERNELS_LIB` at a built library
  to use the accelerator.

### Added: for integrators

- `SigningCallback` and `SignerAdapter` for callback-based signing, so a host
  can keep its keys outside the library.
- `FundingProvisionBuilder`.
- **`fundingVout` on all six Tool classes.** Funding inputs and outpoints no
  longer hardcode output index 1. The parameter defaults to `1`, so existing
  callers are unaffected.
- `witnessChangePKH` on the Appendable archetype's `createTokenIssuanceTxn`.
- In-script Merkle proof verification for the PP1_RFT whitelist.

### Fixed

- **Identity anchor signing produced invalid scriptSigs.** Anchored issuance was
  affected.
- **Script number offset tracking in the PP2 and PP2-FT parsers.**
- **PP2_FT carried a wrong `fullSubscript`**; the correct 85-byte constant is
  now embedded, and all pipeline artifacts regenerated.
- Fee rate set to 100 sats/kB, the BSV standard relay fee.

### Dependencies

- `dartsv` is now `^3.1.0` (FindAndDelete and the post-Genesis stack limit).
- **`hex` is now a declared dependency.** It was used directly by
  `signer_adapter.dart` and arrived transitively through dartsv, which
  `dart pub publish` refuses.

### Packaging

- `.pubignore` now excludes the Rust crate's `target/` directory, development
  tooling and planning artifacts. A `.pubignore` replaces `.gitignore` for
  publishing, so anything git hides has to be named there too; 41 MB of build
  artifacts were reaching the archive without it.

### Known limits

- ARC caps a scriptSig at 1,636,802 bytes, and a production-parameter pool
  witness is larger, so production witnesses do not pass through ARC. Testnet
  runs at test parameters.
- The base case anchors `tokenId` to a spent outpoint in PP1_SP only. NFT, FT,
  RFT, RNFT, AT and SM still do not, which is a protocol decision; see
  `docs/developer-guides/INTEGRATING_TSTOKENLIB_SP.md`.

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
