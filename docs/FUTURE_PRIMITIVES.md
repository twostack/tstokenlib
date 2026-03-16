# Future Primitives

Seven capability gaps were identified in the [Use Case Landscape](USE_CASE_LANDSCAPE.md) that no current or designed TSL1 archetype covers. This document specifies each gap, the use cases it blocks, candidate approaches, and the work required to close it.

**Status key:** Archetypes referenced below have different implementation statuses:
- **Implemented:** PP1_NFT, PP1_FT — code exists in the codebase
- **Designed:** PP1_RNFT, PP1_RFT, PP1_AT, PP1_SM — fully specified but not yet implemented

---

## 1. Time-Bounded Validity

### The Gap

No implemented or designed archetype supports tokens that are valid only within a time window. Tokens are either permanent (until burned) or one-time-use (until redeemed). There is no middle ground — a token that activates on a start date, remains valid for a period, and then automatically becomes invalid.

### Use Cases Blocked

- Subscription tokens (monthly access passes)
- Season passes (valid for a season, then expire)
- Session tokens (valid for minutes/hours)
- Time-limited permits (construction permits, temporary licenses)
- Trial periods (30-day free trial tokens)

### Candidate Approach: `validFrom` / `validUntil` Fields

Add two 4-byte fields to the token header:

```
validFrom    (4 bytes, LE uint32)  — Unix timestamp or block height
validUntil   (4 bytes, LE uint32)  — Unix timestamp or block height
```

**Enforcement mechanism:**

On every spend operation, the script extracts `nLockTime` from the sighash preimage and verifies:

```
validFrom <= nLockTime <= validUntil
```

This constrains the spending transaction to a specific time window. The miner enforces `nLockTime` (transaction cannot be mined before that time), and the script enforces the upper bound.

**Limitations:**
- `nLockTime` is a *minimum* — miners won't mine the tx before that time, but the script must independently check the upper bound
- The upper bound check relies on the spender setting `nLockTime` honestly. However, a spender who sets `nLockTime` in the future will delay their own transaction, and one who sets it in the past will fail the `validFrom` check. The window is self-enforcing as long as `nLockTime` must satisfy *both* bounds
- Cannot enforce sub-block granularity (Bitcoin timestamps have ~2 hour variance)

**Work required:**
- Extend PP1_RNFT header with `validFrom` and `validUntil` fields (+10 bytes including pushdata prefixes)
- Add time-window check to all non-burn operations
- Update inductive proof slice offsets
- Estimated effort: moderate — mechanical extension of existing patterns

### Alternative: Periodic Re-Issuance

For subscriptions, the issuer mints a new token each period (monthly pass). No protocol change needed — the application layer manages renewal. Less elegant but works today.

---

## 2. On-Chain Randomness

### The Gap

Bitcoin Script is fully deterministic. Given the same inputs, it always produces the same output. There is no native source of randomness, which means tokens cannot make random selections, generate random outcomes, or fairly assign items from a pool.

### Use Cases Blocked

- Loot boxes / Mystery items (random item assignment)
- Lottery / Raffle (random winner selection)
- Random committee selection (jury duty, audit sampling)
- Procedurally generated game items

### Candidate Approach: Commit-Reveal with Block Hash

A two-phase protocol where randomness is derived from a future block hash that neither party can predict at commitment time.

**Phase 1 — Commit:** The participant commits to a secret value `s` by publishing `H(s)` in a transaction. This is a standard hash commitment.

**Phase 2 — Reveal:** After N blocks, the participant reveals `s`. The random outcome is derived from:

```
outcome = SHA256(s || blockHash_at_commit_height+N) mod range
```

The block hash is not directly available in Bitcoin Script, but it can be supplied in the scriptSig and verified against the sighash preimage's `hashPrevouts` if the reveal transaction spends a UTXO created at the target block height.

**Limitations:**
- Miners can withhold blocks to influence the outcome (miner extractable value)
- Requires two transactions (commit + reveal), adding latency and cost
- Block hash is not natively accessible in Script — needs creative workarounds or an oracle

**Alternative: SPV Block Header Access (Oracle-Free)**

sCrypt demonstrated that block headers can be verified in Script without oracles by checking the header hash against the difficulty target. The block nonce can serve as a pseudo-random source, though miners can manipulate nonces at no extra cost. Using the block *hash* is more resistant but still miner-influenceable. See [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md) Section 5 for the full SPV mechanism.

**Alternative: Oracle-Fed Randomness**

A trusted randomness oracle (e.g., drand, NIST beacon) publishes Rabin-signed random values. The token script verifies the oracle's Rabin signature over the random value (~hundreds of bytes of script, vs ~10 MB for ECDSA verification). This is simpler but introduces a trust assumption. See [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md) for the Rabin vs ECDSA analysis.

**Work required:**
- Design a commit-reveal protocol compatible with the TSL1 output structure
- Implement block hash extraction (if feasible) or oracle signature verification
- Define a new token type or SM variant that supports two-phase reveal
- Estimated effort: high — research-grade problem, not a mechanical extension

---

## 3. Oracle Integration

### The Gap

TSL1 tokens can only verify information that is available within the transaction itself (signatures, preimages, embedded state). They cannot access external data — prices, weather, sports scores, delivery confirmations — without a trusted party attesting to that data on-chain.

### Use Cases Blocked

- Prediction markets (outcome attestation)
- Insurance triggers (weather events, flight delays)
- Environmental impact bonds (measured outcomes)
- Derivatives (price feeds for settlement)
- IoT-triggered state transitions (temperature breach, location verification)

### Candidate Approach: Oracle as Stamping Authority

Model the oracle as a special-purpose signer within the existing dual-authority pattern:

**For AT (Appendable Token):** The oracle is the `issuerPKH`. Oracle attestations are stamps. Each stamp carries the attested data in its metadata. The token accumulates oracle attestations just like loyalty stamps.

**For SM (State Machine):** The oracle is a required co-signer for specific state transitions. When the oracle signs a transition, it attests that the off-chain condition has been met. The oracle's PKH is embedded as an immutable field in the SM header.

```
Proposed SM extension:

Byte 140:     0x14 (pushdata 20)
Bytes 141-160: oraclePKH (immutable)
Byte 161:     start of script body
```

Oracle-gated transitions require verification of the oracle's signature in addition to the normal party signatures. For Rabin-based oracles, this is a compact `sig^2 mod n == H(data) mod n` check (~hundreds of bytes). For ECDSA-based oracles, the oracle can co-sign the transaction using native `OP_CHECKSIG` (avoiding the ~10 MB cost of on-chain ECDSA verification). See [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md) for the full analysis of signature scheme trade-offs.

**Trust model:** The oracle is trusted to attest honestly. This is an explicit, bounded trust assumption — the oracle can attest falsely, but it cannot steal funds, change the token's rules, or act without the other parties' signatures. The oracle's identity is immutably recorded in the token, providing accountability.

**Decentralized oracles:** For higher assurance, require M-of-N oracle attestations. This maps to the N-of-M multi-sig gap (see [Section 4](#4-n-of-m-multi-signature)).

**Work required:**
- Add optional `oraclePKH` field to SM and AT headers
- Add oracle CHECKSIG to specific transitions (configurable via bitmask)
- Define oracle attestation data format (timestamp + value + signature)
- Estimated effort: moderate — the dual-authority pattern in AT already demonstrates the mechanism. Extending SM is straightforward.

---

## 4. N-of-M Multi-Signature

### The Gap

Current archetypes support at most 2 required signers (merchant + customer in SM, issuer + owner in AT). Some use cases require 3 or more parties to approve an action, or a threshold subset of a larger group.

### Use Cases Blocked

- DAO governance (3-of-5 board approval)
- Multi-party escrow (2-of-3 arbiter model)
- Board approvals (majority vote to release funds)
- Consortium operations (multi-bank trade finance)

### Candidate Approach A: Sequential CHECKSIG Chain

Extend the SM pattern to support N sequential `OP_CHECKSIG` operations, each verified against an immutable PKH embedded in the header.

```
Proposed header extension:

signerCount  (1 byte)  — number of required signers (N)
signerPKH_1  (20 bytes)
signerPKH_2  (20 bytes)
...
signerPKH_N  (20 bytes)
```

The script loops through N CHECKSIG verifications. Each signer's PKH is at a known offset.

**Limitation:** The header grows by 21 bytes per signer (pushdata + PKH). For 5 signers, that's 105 bytes — acceptable. For 20 signers, the header becomes unwieldy.

### Candidate Approach B: Merkle Tree of Signers

For large signer sets, embed a `signerMerkleRoot` instead of individual PKHs. The scriptSig supplies the signer's PKH, their Merkle proof, and their signature. The script verifies:

1. The PKH is a leaf in the Merkle tree (proof against `signerMerkleRoot`)
2. The signature is valid for that PKH

This mirrors the merchant whitelist pattern from PP1_RFT, applied to signers instead of recipients.

**For M-of-N threshold:** The script counts valid signer attestations and requires `count >= M`. Each signer provides their PKH, Merkle proof, and signature. The script verifies each and increments a counter.

**Limitation:** M sequential Merkle proof verifications are expensive in Script. Each proof is O(log N) hash operations. For M=3, N=5, this is manageable. For M=10, N=20, it becomes a significant script size cost.

**Work required:**
- Design a flexible signer verification module (sequential or Merkle-based)
- Integrate with SM as a guard condition variant
- Define threshold encoding in the header (M value, N signers or Merkle root)
- Estimated effort: moderate to high — the Merkle proof pattern exists in RFT, but threshold counting adds complexity

---

## 5. Periodic State Transitions

### The Gap

The designed PP1_SM supports linear state progression (INIT → ACTIVE → ... → SETTLED). It does not support cycles or recurring transitions — states that repeat on a schedule, like monthly payments, quarterly reporting, or annual renewals.

### Use Cases Blocked

- Bond coupon payments (semi-annual interest)
- Subscription renewals (monthly billing)
- Rent payments (monthly, with deposit return at end)
- Periodic compliance reporting (quarterly attestations)
- Recurring service agreements

### Candidate Approach A: Cycle-Capable State Machine (PP1_CSM)

Extend the designed PP1_SM to allow specific transitions to loop back to a previous state, with a cycle counter:

```
Proposed additional fields:

cycleCount     (2 bytes)  — number of completed cycles
maxCycles      (2 bytes)  — maximum cycles before terminal state (immutable)
```

The transition bitmask gains a "cycle" bit that permits a transition from a later state back to an earlier one, incrementing `cycleCount`. When `cycleCount >= maxCycles`, the cycle transition is disabled and only the terminal path remains.

**Example — Rental agreement:**

```
INIT → ACTIVE → PAYMENT_DUE → PAYMENT_RECEIVED → PAYMENT_DUE (cycle)
                                                 → LEASE_END (when cycleCount >= 12)
```

**Limitation:** Cycles re-introduce the possibility of indefinite chains. The `maxCycles` field bounds this, but long chains create large transaction histories. The inductive proof only checks one step back, so chain length is not a verification cost — but it is a liveness concern (each cycle requires a transaction).

### Candidate Approach B: Repeated Issuance (No Protocol Change)

The issuer creates a new SM token for each period. A 12-month lease becomes 12 sequential SM tokens, each covering one month. The application layer links them via metadata.

**Trade-off:** No protocol change needed, but loses the continuous audit trail and atomic relationship between periods. A tenant could have month 6 settled but month 7 disputed, with no on-chain link between them.

### Candidate Approach C: AT with Periodic Stamps

Model each period as a stamp in an AT token. The issuer stamps "payment received" each month. After 12 stamps (threshold), the deposit is returned.

**Trade-off:** Works well for simple recurring attestations. Does not support the full state machine flexibility (e.g., different actions depending on whether payment is on time vs. late).

**Work required:**
- Approach A: Add `cycleCount`/`maxCycles` to SM, modify transition validation to allow backward edges, update bitmask encoding. Moderate effort.
- Approach B: No protocol work. Application-layer convention only.
- Approach C: Already possible with existing AT design. No protocol work.

---

## 6. Fungible + Appendable Hybrid

### The Gap

AT has an append-only event log (stamps) but no fungible balance. FT has a fungible balance but no event log. Some use cases need both — a token that carries a monetary value *and* accumulates a history of events.

### Use Cases Blocked

- Financial instruments with transaction history (bonds that track coupon payments and carry face value)
- Loyalty programs with point balances (not just stamp counts, but actual redeemable point values that can be partially spent)
- Insurance policies (premium balance + claim history)
- Escrow with audit trail (locked amount + event log of milestones/disputes)

### Candidate Approach: PP1_FAT (Fungible Appendable Token)

Combine the FT and AT headers:

```
ownerPKH      (20 bytes, mutable)
tokenId       (32 bytes, immutable)
issuerPKH     (20 bytes, immutable)
amount        (8 bytes, mutable)       — from FT
stampCount    (2 bytes, mutable)       — from AT
threshold     (2 bytes, immutable)     — from AT
stampsHash    (32 bytes, mutable)      — from AT
```

**Operations would combine both families:**

| Operation | Effect |
|---|---|
| Mint | Set initial amount, stampCount=0 |
| Transfer | Move full amount to new owner (amount preserved) |
| Split | Divide amount (stamps/history not split — stays with one output) |
| Stamp | Issuer adds stamp, amount unchanged |
| Redeem | Customer redeems if stampCount >= threshold, amount distributed |
| Burn | Destroy token |

**Key question:** When splitting, does the stamp history go with the recipient or stay with the sender? The simplest answer: stamps are not splittable. The original token keeps the full history. The split-off portion starts with a fresh stamp history. This mirrors how a loyalty card works — you can't split your stamp progress.

**Work required:**
- Design combined header layout (estimated ~120 bytes)
- Merge FT conservation logic with AT stamp verification
- Define split semantics for the stamp fields
- Estimated effort: moderate — both component patterns are well-understood. The complexity is in the split edge case.

---

## 7. Conditional Transfer Restrictions

### The Gap

The designed PP1_RNFT has a static transfer policy set at issuance: freely transferable, self-transfer-only, or non-transferable. These policies cannot change based on conditions — time, external state, or properties of the recipient.

### Use Cases Blocked

- Vesting tokens (non-transferable until a date, then freely transferable)
- KYC-gated transfers (transferable only to recipients with a verified identity token)
- Graduated access (non-transferable during probation, transferable after)
- Embargo compliance (transferable except to blacklisted parties)

### Candidate Approach A: Time-Gated Transfer

Combine the time-bounded validity mechanism (Gap 1) with the transfer policy:

```
Transfer policy encoding:

00 = freely transferable
01 = self-transfer only
10 = non-transferable
11 = time-gated (non-transferable before validFrom, freely transferable after)
```

When the transfer policy is `11`, the script checks `nLockTime >= validFrom` before permitting a transfer. This reuses the same nLockTime extraction logic from the timeout mechanism.

### Candidate Approach B: Composition-Gated Transfer

Require the recipient to prove they hold a specific companion token (e.g., a KYC attestation RNFT) in order to receive a transfer. This extends the composition mechanism already designed for PP1_RNFT:

- The sender's token has `compositionRequired = true` and `companionTokenId` set to the KYC token type
- On transfer, the *recipient's* KYC token must be co-spent (self-transferred) in the same transaction
- The script verifies the recipient's KYC token outpoint in `hashPrevouts`

**Limitation:** This checks that the recipient *holds* the companion token at the time of transfer. It does not prevent the recipient from later burning or losing the companion token.

### Candidate Approach C: Blacklist via Merkle Proof of Exclusion

For embargo/sanctions compliance, maintain a Merkle tree of *excluded* PKHs. On transfer, the recipient provides a Merkle proof of *non-inclusion* — proving their PKH is not in the blacklist.

**Limitation:** Merkle proofs of non-inclusion require sorted trees and are more complex than inclusion proofs. This is feasible but significantly increases script complexity.

**Work required:**
- Approach A: Extend RNFT flags to support time-gated policy, add validFrom field. Low effort — combines two existing mechanisms.
- Approach B: Extend composition to check recipient's companion token (currently composition checks the spender's companion). Moderate effort — requires verifying an *output* companion token rather than an *input*.
- Approach C: Implement sorted Merkle tree with non-inclusion proofs. High effort — new cryptographic primitive in Script.

---

## Priority Assessment

| Gap | Extends | Impact | Effort | Recommendation |
|---|---|---|---|---|
| **Time-bounded validity** | PP1_RNFT (designed) | High (5+ use cases) | Low-moderate | **Priority 1** — Mechanical extension. Unblocks subscriptions, permits, session tokens. |
| **Oracle integration** | PP1_AT, PP1_SM (designed) | High (5+ use cases) | Moderate | **Priority 2** — Builds on designed AT/SM dual-authority. Unblocks prediction markets, insurance, IoT. |
| **N-of-M multi-sig** | PP1_SM (designed) | Medium (4 use cases) | Moderate-high | **Priority 3** — Merkle signer tree reuses RFT pattern. Unblocks DAO governance, consortium operations. |
| **Periodic transitions** | PP1_SM (designed) | Medium (5 use cases) | Low (use AT) to Moderate (build CSM) | **Priority 4** — AT covers most cases today. Full CSM only needed for complex recurring workflows. |
| **Conditional transfers** | PP1_RNFT (designed) | Medium (4 use cases) | Low (time-gated) to High (blacklist) | **Priority 5** — Time-gated variant is low-hanging fruit. Composition-gated adds KYC compliance. |
| **Fungible + Appendable** | PP1_FT + PP1_AT (new hybrid) | Low-medium (4 use cases) | Moderate | **Priority 6** — Niche. Most use cases can be approximated by composing separate FT and AT tokens. |
| **On-chain randomness** | New protocol | Low (3 use cases) | High | **Priority 7** — Research-grade. Commit-reveal is complex and miner-gameable. Oracle randomness is simpler but trust-dependent. Defer unless a specific product demands it. |

---

## Dependency Graph

Some gaps depend on or benefit from others being closed first:

```
Time-bounded validity ──────────────────────────────────┐
        │                                               │
        ▼                                               ▼
Conditional transfers (time-gated)          Periodic transitions (expiry per cycle)
        │
        ▼
Conditional transfers (composition-gated) ◄── requires RNFT composition (already designed)

Oracle integration
        │
        ├──► On-chain randomness (oracle-fed variant)
        │
        └──► N-of-M multi-sig (decentralized oracle = M-of-N attestors)

Fungible + Appendable ◄── independent, no dependencies
```

Closing **time-bounded validity** first has the highest cascading benefit — it partially addresses conditional transfers and periodic transitions at minimal cost.
