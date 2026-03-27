# PP1_SM Enhancement: 3-Party Authority and Script-Enforced Settlement

## Motivation

The Honey Rewards scandal (December 2024) exposed a structural flaw in affiliate and loyalty ecosystems: **attribution is controlled by opaque intermediaries who can silently redirect value flows.** PayPal's Honey browser extension replaced creators' affiliate cookies with its own at the point of sale, stealing commissions from the parties who actually drove the customer. Over 20 class-action lawsuits followed, and Honey lost 8 million users.

The root cause: there is no cryptographic binding between the party who generated the referral and the commission that results from it. The entire chain — referral attribution, customer journey progression, milestone verification, and reward distribution — relies on server-side databases and browser cookies that any intermediary can tamper with.

PP1_SM was designed to fix this for the 2-party case (merchant + customer). The funnel's immutable terms, dual-signature milestones, atomic settlement, and commitment hash chain already prevent the merchant from cheating the customer (or vice versa).

But the 2-party protocol does not protect the **referrer** — the third party whose contribution Honey-style attacks specifically target. Section 9 of [FUNNEL_STATE_MACHINE.md](FUNNEL_STATE_MACHINE.md) sketched a token-composition approach. This document specifies the preferred approach: extending PP1_SM itself to natively support a third authority key and script-enforced settlement ratios.

## Design Principles

1. **The referrer's binding must be on-chain.** If the referrer is only in metadata or a second token orchestrated by the application layer, a malicious intermediary can still tamper with attribution. The whole point is that no party — including the platform operator — can alter the referral binding after the fact.

2. **Settlement ratios must be script-enforced.** If the merchant constructs the settlement transaction and the script doesn't verify the payout split, the merchant can cheat the referrer. This is the exact attack vector the funnel exists to prevent.

3. **Backward-compatible.** Existing 2-party funnels must continue to work. The referrer extension is optional — activated by a flag and the presence of additional header fields.

4. **No new archetype.** PP1_SM is not a fundamentally different token type when extended with a referrer. It remains a finite-state automaton with multi-party authority, commitment chain, timeout, and atomic settlement. The enhancement adds one more authority key, one more settlement output, and script-level payout verification.

## Gap Analysis: Current PP1_SM vs Funnel Requirements

| Requirement | Current PP1_SM | Gap |
|-------------|---------------|-----|
| 2-party authority (merchant + customer) | Supported (merchantPKH + customerPKH) | None |
| 3-party authority (+ referrer) | Not supported | **referrerPKH field missing; no 3-sig verification path** |
| State machine transitions | 6 states, 7 operations, bitmask-gated | None |
| Milestone accumulation | milestoneCount + commitmentHash | None (functionally equivalent to AT's stampCount + stampsHash) |
| Milestone threshold guard | milestoneCount > 0 checked at Convert | **No configurable threshold; only checks > 0** |
| Commitment hash chain | Rolling SHA256 of signer sigs + event data | None |
| Timeout enforcement | nLockTime-gated with absolute deadline | None |
| Atomic settlement (2-party) | P2PKH outputs to customerPKH + merchantPKH, verified against immutable header | None |
| Atomic settlement (3-party) | Only 2 payout outputs | **No referrer payout output; no 3-output settlement topology** |
| Script-enforced payout ratios | Amounts passed in scriptSig, not verified against committed terms | **Merchant can set arbitrary amounts** |
| Schnorr commitment hiding | Not used; plain SHA256 hash chain | **Low-entropy milestone data is not hidden** (see Note below) |

**Note on Schnorr commitments:** The sCrypt funnel design uses Schnorr-based commitments for the hiding property. PP1_SM uses plain `SHA256(prevHash || SHA256(sig || eventData))`. For most funnel use cases (boolean milestones: visited, purchased, attended), the SHA256 chain is sufficient — the signature component provides entropy. For sensitive data (purchase amounts, specific products), the hiding property matters. This enhancement does not address the Schnorr question — it is tracked separately as a future cryptographic improvement. The SHA256 chain is adequate for the v1 referral extension.

## Enhancement Specification

### Extended Byte Layout

The enhanced header adds 3 fields after the existing `timeoutDelta`:

```
Offset  Len  Prefix  Field               Mutability   NEW?
------  ---  ------  -----               ----------   ----
0       1    0x14    [pushdata 20]        fixed
1       20   —       ownerPKH            mutable
21      1    0x20    [pushdata 32]        fixed
22      32   —       tokenId             immutable
54      1    0x14    [pushdata 20]        fixed
55      20   —       merchantPKH         immutable
75      1    0x14    [pushdata 20]        fixed
76      20   —       customerPKH         immutable
96      1    0x01    [pushdata 1]         fixed
97      1    —       currentState        mutable
98      1    0x01    [pushdata 1]         fixed
99      1    —       milestoneCount      mutable
100     1    0x20    [pushdata 32]        fixed
101     32   —       commitmentHash      mutable
133     1    0x01    [pushdata 1]         fixed
134     1    —       transitionBitmask   immutable
135     1    0x04    [pushdata 4]         fixed
136     4    —       timeoutDelta        immutable
─── existing header ends at byte 140 ───
140     1    0x01    [pushdata 1]         fixed        NEW
141     1    —       extensionFlags      immutable     NEW
142     1    0x14    [pushdata 20]        fixed        NEW (conditional)
143     20   —       referrerPKH         immutable     NEW (conditional)
163     1    0x01    [pushdata 1]         fixed        NEW (conditional)
164     1    —       milestoneThreshold  immutable     NEW (conditional)
165     1    0x02    [pushdata 2]         fixed        NEW (conditional)
166     2    —       commissionBPS       immutable     NEW (conditional)
168     —    —       [script body]        immutable
```

### extensionFlags (1 byte, immutable)

```
Bit 0:  hasReferrer
          0 = 2-party mode (no referrer fields present; header is 142 bytes)
          1 = 3-party mode (referrerPKH, milestoneThreshold, commissionBPS present; header is 168 bytes)
Bit 1:  enforceSettlementRatios
          0 = settlement amounts are unconstrained (backward-compatible)
          1 = settlement amounts verified against commissionBPS (requires hasReferrer)
Bits 2-7: reserved (must be 0)
```

**When `hasReferrer = 0`:** The header is 142 bytes (140 original + 2 for extensionFlags). The `referrerPKH`, `milestoneThreshold`, and `commissionBPS` fields are absent. The script body branches on `extensionFlags` to determine header parsing. All existing 2-party behavior is preserved.

**When `hasReferrer = 1`:** The header is 168 bytes. All three new fields are present.

### referrerPKH (20 bytes, immutable, conditional)

The referrer's public key hash. Bound to the funnel at issuance. Cannot be changed after the fact — this is the anti-Honey property.

### milestoneThreshold (1 byte, immutable, conditional)

Minimum `milestoneCount` required before the Convert transition is allowed. Replaces the current hardcoded `milestoneCount > 0` check with a configurable threshold. Mirrors PP1_AT's `threshold` concept.

Value 0x00 = no threshold (Convert allowed at any milestoneCount > 0, same as current behavior).
Value 0x01-0xFF = Convert requires `milestoneCount >= milestoneThreshold`.

### commissionBPS (2 bytes, little-endian, immutable, conditional)

Referrer commission rate in basis points (0-10000, representing 0.00%-100.00%). Used by the settlement script to verify the referrer's payout output.

Value 0 = referrer participates but receives no automatic commission (commission handled off-chain or via metadata).
Value 1-10000 = script enforces `referrerPayout >= (totalSettlement * commissionBPS) / 10000`.

## Modified Operations

### Issuance (OP_0: CreateFunnel)

**Change:** The scriptSig supplies the new fields. The script initializes them as immutable header bytes.

**New guard conditions:**
- If `hasReferrer = 1`: verify `referrerPKH != 0x00...00` (must be a real key)
- If `enforceSettlementRatios = 1`: verify `hasReferrer = 1` (cannot enforce ratios without a referrer)

### Enroll (OP_1)

**Change:** When `hasReferrer = 1`, the Enroll operation additionally verifies the referrer's consent.

**Option A — Referrer signature in Enroll:**

The referrer provides a signature in the scriptSig alongside the merchant's:

```
preImage, pp2Output, merchantPubKey, merchantSig,
referrerPubKey, referrerSig,
eventData, scriptLHS, parentRawTx, padding, OP_1
```

New guard conditions:
- `HASH160(referrerPubKey) == referrerPKH`
- `CHECKSIG(referrerSig, referrerPubKey)`

This proves the referrer consents to being bound to this funnel. The referrer's signature is included in the commitment hash update: `SHA256(prevHash || SHA256(merchantSig || referrerSig || eventData))`.

**Option B — Token composition (from Section 9 of FUNNEL_STATE_MACHINE.md):**

The referrer's PP1_RNFT identity token is co-spent in the same transaction. The PP1_SM script verifies the referrer's token outpoint in `hashPrevouts`. This approach requires the referrer to hold a specific token type, but doesn't require them to be online to sign at enrollment time if their identity token is pre-authorized.

**Recommendation:** Option A (direct signature) is simpler, requires no additional token, and directly proves the referrer's consent. Option B (composition) is more flexible for offline/delegated scenarios. Both can be supported — the `extensionFlags` could use bit 2 to select the mechanism.

### Confirm (OP_2)

**Change:** When `hasReferrer = 1`, the Confirm operation checks `milestoneThreshold` to guard the Convert transition.

No change to signature requirements — Confirm remains merchant + customer dual-sig. The referrer does not sign milestones (they are between the merchant and customer).

**New guard condition for the PROGRESSING → CONVERTING transition path:**
- If `milestoneThreshold > 0`: verify `milestoneCount >= milestoneThreshold`

(Note: this check is on Convert (OP_3), not Confirm. Confirm's only threshold-related concern is incrementing milestoneCount.)

### Convert (OP_3)

**Change:** When `milestoneThreshold > 0`, add guard:
- `milestoneCount >= milestoneThreshold`

This replaces the current `milestoneCount > 0` check. When `milestoneThreshold = 0`, the behavior is identical to today.

### Settle (OP_4)

This is the critical change.

**3-Party Settlement Topology (8 outputs):**

```
Output 0: Change (P2PKH to funding source)
Output 1: Customer reward (P2PKH to customerPKH)
Output 2: Merchant payment (P2PKH to merchantPKH)
Output 3: Referrer commission (P2PKH to referrerPKH)
Output 4: PP1_SM final state (1 sat, currentState = SETTLED)
Output 5: PP2_SM (witness bridge)
Output 6: PP3_SM (partial SHA256 witness)
Output 7: Metadata (OP_RETURN with settlement record)
```

**Script-enforced payout verification (when `enforceSettlementRatios = 1`):**

The scriptSig supplies:
```
preImage, pp2Output, merchantPubKey, merchantSig,
customerRewardAmount, merchantPaymentAmount, referrerCommissionAmount,
settlementData, scriptLHS, parentRawTx, padding, OP_4
```

New guard conditions:
1. All existing Settle guards (state == CONVERTING, merchant sig, bitmask bit 4)
2. `customerRewardAmount > 0` AND `merchantPaymentAmount > 0` AND `referrerCommissionAmount > 0`
3. **Commission enforcement:**
   ```
   totalSettlement = customerRewardAmount + merchantPaymentAmount + referrerCommissionAmount
   expectedMinCommission = (totalSettlement * commissionBPS) / 10000
   VERIFY referrerCommissionAmount >= expectedMinCommission
   ```
4. Output[1] is P2PKH locked to `customerPKH` with `customerRewardAmount` satoshis
5. Output[2] is P2PKH locked to `merchantPKH` with `merchantPaymentAmount` satoshis
6. Output[3] is P2PKH locked to `referrerPKH` with `referrerCommissionAmount` satoshis
7. Full transaction reconstruction with 8-output varint

**P2PKH output verification:**

All three payout outputs are constructed by the script using PKH values from the **immutable header fields** — `customerPKH`, `merchantPKH`, `referrerPKH`. The merchant cannot redirect any party's payout to a different address because the addresses are embedded in the immutable portion of the script that the inductive proof carries forward from issuance.

**Integer arithmetic in Script:**

The commission calculation `(totalSettlement * commissionBPS) / 10000` uses Bitcoin Script's `OP_MUL` and `OP_DIV` opcodes. Both are available in BSV's restored instruction set. The calculation is:

```
// Stack: customerRewardAmount, merchantPaymentAmount, referrerCommissionAmount, commissionBPS
// Compute total
OP_3 OP_PICK                    // copy customerRewardAmount
OP_3 OP_PICK                    // copy merchantPaymentAmount
OP_ADD
OP_3 OP_PICK                    // copy referrerCommissionAmount
OP_ADD                          // totalSettlement on stack

// Compute minimum commission
commissionBPS OP_MUL            // totalSettlement * commissionBPS
10000 OP_DIV                    // / 10000 = expectedMinCommission

// Verify
referrerCommissionAmount
OP_GREATERTHANOREQUAL OP_VERIFY
```

**Rounding:** `OP_DIV` truncates toward zero. The `>=` check means the referrer can receive more than the minimum (e.g., the merchant can round up), but never less.

### Timeout (OP_5)

**Change:** When `hasReferrer = 1`, the timeout topology becomes 7 outputs (adding the referrer gets nothing on timeout — only the merchant recovers):

```
Output 0: Change
Output 1: Merchant refund (P2PKH to merchantPKH)
Output 2: PP1_SM final state (EXPIRED)
Output 3: PP2_SM
Output 4: PP3_SM
Output 5: Metadata
```

No change to the timeout logic itself. The referrer has no claim on locked funds when the funnel expires — this is consistent with the design: the referrer earns commission only on successful conversion.

### Burn (OP_6)

**No change.** Burn operates on terminal states only and simply reclaims the dust sats.

## Modified Transition Table

| From | To | Selector | Bitmask Bit | Required Signers (2-party) | Required Signers (3-party) |
|------|----|----------|-------------|---------------------------|---------------------------|
| — | INIT | OP_0 | — | merchant | merchant |
| INIT | ACTIVE | OP_1 | 0 | merchant | merchant + referrer |
| ACTIVE | PROGRESSING | OP_2 | 1 | merchant + customer | merchant + customer |
| PROGRESSING | PROGRESSING | OP_2 | 2 | merchant + customer | merchant + customer |
| PROGRESSING | CONVERTING | OP_3 | 3 | merchant + customer | merchant + customer (+ threshold check) |
| CONVERTING | SETTLED | OP_4 | 4 | merchant | merchant (+ commission enforcement) |
| any (< 0x04) | EXPIRED | OP_5 | 5 | merchant + nLockTime | merchant + nLockTime |
| SETTLED/EXPIRED | — (burn) | OP_6 | — | owner | owner |

## Inductive Proof Update

### Extended Mutable/Immutable Regions

**2-party mode (extensionFlags bit 0 = 0, 142-byte header):**

```
Region 1:  bytes [1:21]     ownerPKH          (mutable)
Region 2:  bytes [97:98]    currentState      (mutable)
Region 3:  bytes [99:100]   milestoneCount    (mutable)
Region 4:  bytes [101:133]  commitmentHash    (mutable)

Immutable slices:
  bytes [0:1]       ownerPKH pushdata
  bytes [21:97]     tokenId + merchantPKH + customerPKH + state pushdata
  bytes [98:99]     milestoneCount pushdata
  bytes [100:101]   commitmentHash pushdata
  bytes [133:142]   transitionBitmask + timeoutDelta + extensionFlags
  bytes [142:]      script body
```

**3-party mode (extensionFlags bit 0 = 1, 168-byte header):**

```
Region 1:  bytes [1:21]     ownerPKH          (mutable)
Region 2:  bytes [97:98]    currentState      (mutable)
Region 3:  bytes [99:100]   milestoneCount    (mutable)
Region 4:  bytes [101:133]  commitmentHash    (mutable)

Immutable slices:
  bytes [0:1]       ownerPKH pushdata
  bytes [21:97]     tokenId + merchantPKH + customerPKH + state pushdata
  bytes [98:99]     milestoneCount pushdata
  bytes [100:101]   commitmentHash pushdata
  bytes [133:168]   transitionBitmask + timeoutDelta + extensionFlags
                    + referrerPKH + milestoneThreshold + commissionBPS
  bytes [168:]      script body
```

The new fields (`referrerPKH`, `milestoneThreshold`, `commissionBPS`) are in the immutable tail — they are carried forward by the inductive proof without substitution, exactly like `transitionBitmask` and `timeoutDelta`.

## Script Size Impact

| Component | Current PP1_SM | Enhanced PP1_SM (2-party) | Enhanced PP1_SM (3-party) |
|-----------|---------------|--------------------------|--------------------------|
| Header | 140 B | 142 B (+2) | 168 B (+28) |
| extensionFlags dispatch | — | ~50 B | ~50 B |
| Referrer signature check (Enroll) | — | — | ~80 B |
| milestoneThreshold guard (Convert) | — | ~30 B | ~30 B |
| Commission calculation (Settle) | — | — | ~100 B |
| 3rd P2PKH output verification (Settle) | — | — | ~120 B |
| 8-output reconstruction (Settle) | — | — | ~150 B (replaces 7-output) |
| **Total estimated delta** | — | **~80 B** | **~530 B** |
| **Total estimated script** | **12-15 KB** | **~12-15 KB** | **~13-16 KB** |

The 3-party extension adds approximately 530 bytes to the script body — a modest increase relative to the 12-15 KB baseline. The PP3 witness (~37.5 KB) is unchanged.

## Implementation Plan

### Phase 1: Header extension + extensionFlags dispatch

- Add `extensionFlags` to the byte layout (1 byte, always present)
- Script body branches on `extensionFlags` bit 0 to determine header parsing (142 vs 168 bytes)
- Existing 2-party tests continue to pass with `extensionFlags = 0x00`
- No behavioral change for 2-party funnels

**tstokenlib impact:**
- `PP1SmLockBuilder`: add `extensionFlags` field, conditional `referrerPKH` / `milestoneThreshold` / `commissionBPS` fields
- `PP1SmTemplate`: update byte offset parsing for both modes
- Template JSON: new `pp1_sm.json` template with extensionFlags

**tstokenlib4j impact:**
- `StateMachineTool`: add optional parameters for 3-party fields
- `PP1SmLockBuilder`: mirror Dart changes
- `PP1SmUnlockBuilder`: add referrer signature slot for Enroll

### Phase 2: 3-party Enroll

- Add referrer signature verification to Enroll path (when `hasReferrer = 1`)
- Referrer's signature included in commitment hash update
- Test: issue 3-party funnel, enroll with referrer sig, verify commitment chain

### Phase 3: milestoneThreshold guard

- Add threshold check to Convert path
- Test: funnel with `milestoneThreshold = 5`, verify Convert fails at 4, succeeds at 5

### Phase 4: Script-enforced settlement

- Extend Settle to 8-output topology (when `hasReferrer = 1`)
- Add commission calculation and verification
- Add P2PKH output construction for referrerPKH
- Test: settle with correct commission, verify script accepts
- Test: settle with underpaid referrer, verify script rejects
- Test: settle with correct amounts but wrong referrer address, verify script rejects

### Phase 5: Integration with Monocelo

- `StateMachineTool` (tstokenlib4j) exposes 3-party operations
- Monocelo's `SmStrategy` calls the extended tool
- `TokenService.settleToken()` accepts commission split or calculates from `commissionBPS`
- Workflow engine's Settle Token node passes through to the extended service

## Relationship to Token Composition Approach (Section 9)

The token composition approach (referrer holds a PP1_RNFT that is co-spent at enrollment) remains valid as an alternative mechanism. The key difference:

| Property | This Enhancement (native 3-party) | Token Composition |
|----------|----------------------------------|-------------------|
| Referrer binding | On-chain in PP1_SM header | On-chain via separate PP1_RNFT |
| Settlement enforcement | PP1_SM script verifies all 3 outputs | Application must build atomic tx spending both tokens |
| Referrer online at enrollment? | Yes (must sign) | Not necessarily (RNFT can be pre-authorized) |
| Additional token required? | No | Yes (PP1_RNFT identity token) |
| Script complexity | Higher (3-sig path, commission math) | Lower per-token, but coordination complexity |
| Trust model | Fully trustless — script enforces everything | Trustless for individual tokens; atomic settlement depends on tx builder |

**When to use which:**

- **Native 3-party (this enhancement):** Default for funnels where the referrer is known at issuance and all parties can sign at the appropriate steps. Strongest security guarantee.
- **Token composition:** Useful when the referrer relationship is more complex (multiple referrers, delegated referrals, referrer not known at funnel creation) or when the referrer holds a persistent identity token used across many funnels.

Both approaches can coexist. A future `extensionFlags` bit could select between them.

## Relationship to Generic State Machine Compiler

The [Generic State Machine Roadmap](GENERIC_STATE_MACHINE_ROADMAP.md) describes a compiler that accepts arbitrary state machine definitions and emits Bitcoin Script. This enhancement is compatible with that roadmap:

- The `extensionFlags`, `referrerPKH`, `milestoneThreshold`, and `commissionBPS` fields become part of the HeaderLayoutEngine's field catalog
- The 3-party signature requirement becomes a configurable auth rule in the transition table
- The commission calculation becomes a guard condition type (`CommissionGuard`)
- The 8-output settlement becomes a topology variant selectable per-transition

The enhancement can be implemented now as a hand-coded extension to PP1_SM. When the generic compiler is ready, the 3-party funnel becomes a definition that the compiler can emit — the hand-coded version serves as the reference implementation and test oracle.
