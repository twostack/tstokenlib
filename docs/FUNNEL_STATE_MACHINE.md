# PP1_SM: Funnel State Machine Token Specification

A UTXO state machine token that implements the customer-centric funnel as the first concrete instantiation of the automata research, built on TSL1's proven inductive proof primitives.

PP1_SM is a **funnel-specific** state machine — its states (INIT, ACTIVE, PROGRESSING, CONVERTING, SETTLED, EXPIRED), roles (merchant, customer), and transition guards are hardcoded for the customer acquisition funnel. It is not a general-purpose parameterizable state machine. Future use cases requiring different state graphs (e.g., supply chain, escrow, governance) would follow the same architectural pattern (inductive proof, commitment hash chain, timeout mechanism) but define their own state encodings and transition tables as separate PP1 contract variants.

This specification covers the 2-party core protocol (customer + merchant). A 3-party extension (adding referrer via token composition) is sketched in [Section 9](#9-3-party-extension-future).

---

## Table of Contents

1. [Automata-to-Bitcoin Mapping](#1-automata-to-bitcoin-mapping)
2. [PP1_SM Byte Layout](#2-pp1_sm-byte-layout)
3. [State Encoding and Transition Graph](#3-state-encoding-and-transition-graph)
4. [Operations](#4-operations)
5. [Timeout Mechanism](#5-timeout-mechanism)
6. [Inductive Proof](#6-inductive-proof)
7. [Commitment Hash Chain](#7-commitment-hash-chain)
8. [Design Decisions](#8-design-decisions)
9. [3-Party Extension (Future)](#9-3-party-extension-future)
10. [Script Size Estimate](#10-script-size-estimate)

---

## 1. Automata-to-Bitcoin Mapping

The automata research defines a formal framework for computation chains on a dual-stack Forth-like machine. PP1_SM is a concrete instantiation of that framework. Every abstract concept maps to a specific Bitcoin/TSL1 primitive.

| Automata Concept | Bitcoin/TSL1 Primitive | PP1_SM Realization |
|---|---|---|
| **State** (q in Q) | Mutable byte in PP1 script header | `currentState` field (1 byte, offset 97) |
| **Input symbol** (sigma in Sigma) | Function selector opcode in scriptSig | OP_0 through OP_6, each triggers a guarded transition |
| **Transition function** (delta) | Script IF/ELSE dispatch branches | Checks `(currentState, selector)` against allowed transitions |
| **Accept states** (F) | Terminal state values | SETTLED (0x04) and EXPIRED (0x05) — only burn allowed |
| **Dual-stack machine** | Bitcoin Script main stack + altstack | Constructor params on altstack; operations use main stack |
| **Monopole chain** | PP1 inductive proof | Each spend verifies parent's output structure and carries state forward |
| **Dipole pair** | PP1 + PP3 cooperation | PP1_SM verifies parent token tx; PP3_SM verifies witness tx |
| **Commitment chain** | Rolling SHA256 hash | `commitmentHash = SHA256(prev \|\| SHA256(sig \|\| eventData))` |
| **Perpetual machine** | Self-replicating UTXO | PP1_SM recreates itself at output[1] with updated mutable fields |
| **Monotonic clock** | nLockTime in sighash preimage | Timeout transitions require `nLockTime >= timeoutDelta` |
| **Termination guarantee** | No cycles from terminal states | SETTLED and EXPIRED have no outgoing transitions except burn |
| **Boolean output** | Script succeeds or fails | Every execution path ends TRUE (valid spend) or FALSE (reject) |
| **Guard condition** | CHECKSIG + field validation | Each transition requires specific signatures + state predicates |
| **Context awareness** | Function selector dispatch | OP_n selectors determine which operation executes (monopole pattern) |

---

## 2. PP1_SM Byte Layout

The script header follows the established TSL1 pattern: pushdata prefix byte, then data, for each field.

```
Offset  Len  Prefix  Field               Mutability
------  ---  ------  -----               ----------
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
140     —    —       [script body]        immutable
```

**Total header: 140 bytes.**

### Field Descriptions

**ownerPKH** (20 bytes, mutable) — The party expected to act next. Set to `merchantPKH` at issuance (merchant creates funnel). Updated to `customerPKH` on enrollment. For dual-sign operations, the script checks both `merchantPKH` and `customerPKH` directly from their immutable fields, bypassing `ownerPKH`.

**tokenId** (32 bytes, immutable) — `SHA256d(fundingTx)` set at issuance. Unique identifier for this funnel instance.

**merchantPKH** (20 bytes, immutable) — The merchant who created the funnel. Required signer for Enroll, Confirm, Convert, Settle, and Timeout.

**customerPKH** (20 bytes, immutable) — The customer enrolled in the funnel. Required co-signer for Confirm and Convert.

**currentState** (1 byte, mutable) — The finite automaton's current state. Values:

| Value | State | Description |
|-------|-------|-------------|
| 0x00 | INIT | Funnel created, customer not yet enrolled |
| 0x01 | ACTIVE | Customer enrolled, funnel is live |
| 0x02 | PROGRESSING | At least one milestone confirmed |
| 0x03 | CONVERTING | Conversion event triggered, awaiting settlement |
| 0x04 | SETTLED | Terminal: rewards distributed |
| 0x05 | EXPIRED | Terminal: timeout reached, merchant reclaimed funds |

**milestoneCount** (1 byte, mutable) — Number of confirmed milestones. Incremented on each Confirm operation. Maximum 255.

**commitmentHash** (32 bytes, mutable) — Rolling SHA256 of all funnel events. Updated on every state transition. See [Section 7](#7-commitment-hash-chain).

**transitionBitmask** (1 byte, immutable) — Enables/disables transitions at issuance time:

```
Bit 0: INIT → ACTIVE       (Enroll)
Bit 1: ACTIVE → PROGRESSING (first Confirm)
Bit 2: PROGRESSING → PROGRESSING (subsequent Confirm, self-loop)
Bit 3: PROGRESSING → CONVERTING  (Convert)
Bit 4: CONVERTING → SETTLED      (Settle)
Bit 5: any non-terminal → EXPIRED (Timeout)
Bits 6-7: reserved (must be 0)
```

A standard funnel uses `0x3F` (all transitions enabled). A single-milestone funnel could use `0x3B` (bit 2 cleared, no self-loop on PROGRESSING).

**timeoutDelta** (4 bytes, immutable) — Absolute deadline as a Unix timestamp (or block height). After this time, the merchant can invoke the Timeout operation to reclaim funds. Set at issuance.

### Inductive Proof Slice Offsets

For script rebuild, the mutable regions are:

```
Region 1:  bytes [1:21]    ownerPKH          (substitute)
Region 2:  bytes [97:98]   currentState      (substitute)
Region 3:  bytes [99:100]  milestoneCount    (substitute)
Region 4:  bytes [101:133] commitmentHash    (substitute)

Immutable slices between regions:
  bytes [0:1]      ownerPKH pushdata prefix
  bytes [21:97]    tokenId + merchantPKH + customerPKH + currentState pushdata
  bytes [98:99]    milestoneCount pushdata
  bytes [100:101]  commitmentHash pushdata
  bytes [133:]     transitionBitmask + timeoutDelta + script body
```

---

## 3. State Encoding and Transition Graph

### State Diagram

```
                     Enroll              Confirm (first)
          INIT ───────────────► ACTIVE ──────────────────► PROGRESSING
         (0x00)   merchant      (0x01)  merchant+customer   (0x02)
           │       signs                    sign               │  ▲
           │                                                   │  │
           │                                                   │  │ Confirm
           │                                                   │  │ (repeat)
           │                                                   └──┘
           │                                                   │
           │                                      Convert      │
           │                                  merchant+customer │
           │                                                   ▼
           │                                             CONVERTING
           │                                               (0x03)
           │                                                   │
           │                                       Settle      │
           │                                      merchant     │
           │                                                   ▼
           │                                              SETTLED
           │                                               (0x04)
           │                                            [terminal]
           │
           │
           ├──── Timeout (nLockTime gated, merchant signs) ──► EXPIRED
           │     from INIT, ACTIVE, PROGRESSING, CONVERTING     (0x05)
                                                             [terminal]
```

### Transition Table

| From | To | Selector | Bitmask Bit | Required Signers |
|------|----|----------|-------------|------------------|
| — | INIT | OP_0 | — | merchant (issuance) |
| INIT | ACTIVE | OP_1 | 0 | merchant |
| ACTIVE | PROGRESSING | OP_2 | 1 | merchant + customer |
| PROGRESSING | PROGRESSING | OP_2 | 2 | merchant + customer |
| PROGRESSING | CONVERTING | OP_3 | 3 | merchant + customer |
| CONVERTING | SETTLED | OP_4 | 4 | merchant |
| any (< 0x04) | EXPIRED | OP_5 | 5 | merchant + nLockTime gate |
| SETTLED/EXPIRED | — (burn) | OP_6 | — | owner |

---

## 4. Operations

### 4.1 OP_0: CreateFunnel

**From → To:** N/A → INIT (issuance, no parent)

**ScriptSig:**
```
preImage, fundingTxId, padding, OP_0
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)` — verify sighash preimage authenticity
2. hashPrevOuts verification (3 outpoints: funding, PP1_SM, PP2_SM)
3. `currentState == 0x00`
4. `milestoneCount == 0x00`
5. `commitmentHash == 0x00...00` (32 zero bytes)
6. `ownerPKH == merchantPKH` (merchant creates and initially owns)

**Mutable fields set:** ownerPKH = merchantPKH, currentState = 0, milestoneCount = 0, commitmentHash = zeros

**Transaction topology:** Standard 5-output

```
Output 0: Change (P2PKH to funding source)
Output 1: PP1_SM (funnel token, 1 sat)
Output 2: PP2_SM (witness bridge, 1 sat)
Output 3: PP3_SM (partial SHA256 witness, 1 sat)
Output 4: Metadata (OP_RETURN)
```

---

### 4.2 OP_1: Enroll

**From → To:** INIT (0x00) → ACTIVE (0x01)

**ScriptSig:**
```
preImage, pp2Output, merchantPubKey, merchantSig,
eventData, scriptLHS, parentRawTx, padding, OP_1
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)`
2. `currentState == 0x00`
3. `HASH160(merchantPubKey) == merchantPKH`
4. `CHECKSIG(merchantSig, merchantPubKey)` — merchant authorizes enrollment
5. Transition bitmask bit 0 is set
6. Inductive proof: parent PP1_SM script body unchanged (see [Section 6](#6-inductive-proof))
7. Output PP1_SM: `ownerPKH = customerPKH`, `currentState = 0x01`, `milestoneCount = 0`
8. `newCommitmentHash = SHA256(prevCommitmentHash || SHA256(merchantSig || eventData))`
9. PP2_SM output validation
10. Full transaction reconstruction: `SHA256d(rebuiltTx) == outpointTxId`

**Immutable fields verified unchanged:** tokenId, merchantPKH, customerPKH, transitionBitmask, timeoutDelta, script body

**Transaction topology:** Standard 5-output

---

### 4.3 OP_2: Confirm

**From → To:** ACTIVE (0x01) → PROGRESSING (0x02), or PROGRESSING (0x02) → PROGRESSING (0x02)

**ScriptSig:**
```
preImage, pp2Output, merchantPubKey, merchantSig,
customerPubKey, customerSig, milestoneData,
scriptLHS, parentRawTx, padding, OP_2
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)`
2. `currentState == 0x01 || currentState == 0x02`
3. **Dual signature:**
   - `HASH160(merchantPubKey) == merchantPKH` AND `CHECKSIG(merchantSig, merchantPubKey)`
   - `HASH160(customerPubKey) == customerPKH` AND `CHECKSIG(customerSig, customerPubKey)`
4. If `currentState == 0x01`: bitmask bit 1 set. If `currentState == 0x02`: bitmask bit 2 set.
5. Output PP1_SM: `currentState = 0x02`, `milestoneCount = parentMilestoneCount + 1`
6. `newCommitmentHash = SHA256(prevHash || SHA256(merchantSig || customerSig || milestoneData))`
7. Inductive proof: all immutable fields preserved
8. Full transaction reconstruction

**Transaction topology:** Standard 5-output

**Dual CHECKSIG note:** Both signatures use `SIGHASH_ALL | SIGHASH_FORKID` (0x41) over the same sighash preimage. The script verifies each sequentially — `OP_CHECKSIG` consumes the signature, so merchantSig is verified first, then customerSig.

---

### 4.4 OP_3: Convert

**From → To:** PROGRESSING (0x02) → CONVERTING (0x03)

**ScriptSig:**
```
preImage, pp2Output, merchantPubKey, merchantSig,
customerPubKey, customerSig, conversionData,
scriptLHS, parentRawTx, padding, OP_3
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)`
2. `currentState == 0x02`
3. Dual signature (merchant + customer)
4. `milestoneCount > 0` — at least one milestone must be confirmed
5. Bitmask bit 3 set
6. Output PP1_SM: `currentState = 0x03`, `milestoneCount` unchanged
7. `newCommitmentHash = SHA256(prevHash || SHA256(merchantSig || customerSig || conversionData))`
8. Inductive proof + full tx reconstruction

**Transaction topology:** Standard 5-output

---

### 4.5 OP_4: Settle

**From → To:** CONVERTING (0x03) → SETTLED (0x04, terminal)

**ScriptSig:**
```
preImage, pp2Output, merchantPubKey, merchantSig,
customerRewardAmount, merchantPaymentAmount, settlementData,
scriptLHS, parentRawTx, padding, OP_4
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)`
2. `currentState == 0x03`
3. `HASH160(merchantPubKey) == merchantPKH` AND `CHECKSIG(merchantSig, merchantPubKey)`
4. Bitmask bit 4 set
5. `customerRewardAmount > 0` AND `merchantPaymentAmount > 0`
6. Output[1] is P2PKH locked to `customerPKH` with `customerRewardAmount` satoshis
7. Output[2] is P2PKH locked to `merchantPKH` with `merchantPaymentAmount` satoshis
8. Output[3] PP1_SM: `currentState = 0x04`
9. `newCommitmentHash = SHA256(prevHash || SHA256(merchantSig || settlementData))`
10. Full tx reconstruction with 7-output varint

**Transaction topology:** Settlement 7-output

```
Output 0: Change (P2PKH to funding source)
Output 1: Customer reward (P2PKH to customerPKH)
Output 2: Merchant payment (P2PKH to merchantPKH)
Output 3: PP1_SM final state (1 sat, currentState = SETTLED)
Output 4: PP2_SM (witness bridge)
Output 5: PP3_SM (partial SHA256 witness)
Output 6: Metadata (OP_RETURN with settlement record)
```

**P2PKH output verification in script:**

The script constructs the expected customer reward output and merchant payment output by:
1. Building the standard P2PKH template: `OP_DUP OP_HASH160 <PKH> OP_EQUALVERIFY OP_CHECKSIG`
2. Substituting `customerPKH` (from the immutable script header) for output[1]
3. Substituting `merchantPKH` (from the immutable script header) for output[2]
4. Serializing each output as: `amount(8 LE) || varint(scriptLen) || script`
5. Including these in the full transaction reconstruction
6. Verifying `SHA256d(rebuiltTx) == outpointTxId` from the sighash preimage

Because the PKHs come from the immutable script header (not from the scriptSig), the merchant cannot redirect rewards to a different address.

---

### 4.6 OP_5: Timeout

**From → To:** any non-terminal (< 0x04) → EXPIRED (0x05, terminal)

**ScriptSig:**
```
preImage, pp2Output, merchantPubKey, merchantSig,
scriptLHS, parentRawTx, padding, OP_5
```

**Guard conditions:**
1. `checkPreimageOCS(preImage)`
2. `currentState < 0x04` — not already terminal
3. `HASH160(merchantPubKey) == merchantPKH` AND `CHECKSIG(merchantSig, merchantPubKey)`
4. Bitmask bit 5 set
5. **nLockTime gate:** see [Section 5](#5-timeout-mechanism)
6. Output[1] is P2PKH locked to `merchantPKH` (merchant reclaims funds)
7. Output[2] PP1_SM: `currentState = 0x05`
8. Full tx reconstruction with 6-output varint

**Transaction topology:** Timeout 6-output

```
Output 0: Change (P2PKH to funding source)
Output 1: Merchant refund (P2PKH to merchantPKH)
Output 2: PP1_SM final state (1 sat, currentState = EXPIRED)
Output 3: PP2_SM (witness bridge)
Output 4: PP3_SM (partial SHA256 witness)
Output 5: Metadata (OP_RETURN with timeout record)
```

---

### 4.7 OP_6: Burn

**From → To:** SETTLED (0x04) or EXPIRED (0x05) → destroyed

**ScriptSig:**
```
ownerPubKey, ownerSig, OP_6
```

**Guard conditions:**
1. `currentState >= 0x04` — must be terminal
2. `HASH160(ownerPubKey) == ownerPKH`
3. `CHECKSIG(ownerSig, ownerPubKey)`

**Transaction topology:**

```
Output 0: Change (P2PKH — all dust reclaimed)
```

No PP1_SM, PP2_SM, or PP3_SM outputs. The token ceases to exist.

---

## 5. Timeout Mechanism

### nLockTime Extraction from Sighash Preimage

The sighash preimage (BIP-143) includes `nLockTime` at bytes `len-8` to `len-4`. The script extracts it:

```
// preImage is on the stack
DUP
SIZE NIP                    // preImage length
8 SUB                       // offset to nLockTime
SPLIT                       // [prefix, last8]
4 SPLIT                     // [prefix, nLockTime(4LE), sighashType(4)]
DROP NIP                    // [nLockTime(4LE)]

// Convert 4-byte LE to unsigned script number
// Append 0x00 to prevent sign-bit interpretation
b'00' CAT BIN2NUM           // [nLockTime as script number]
```

### Deadline Comparison

The script compares the extracted `nLockTime` against the embedded `timeoutDelta`:

```
// timeoutDelta already on stack (extracted from altstack during constructor)
// nLockTime already on stack (extracted above)

// Verify: timeoutDelta <= nLockTime
LESSTHANOREQUAL
VERIFY
```

### nSequence Enforcement

For `nLockTime` to be enforced by miners, `nSequence` on all inputs must be less than `0xFFFFFFFF`. The script verifies this from the preimage:

```
// nSequence is at bytes len-44 to len-40 in the preimage
// Extract and verify < 0xFFFFFFFF
```

This ensures the spending transaction cannot be mined before the timeout deadline, providing both script-level and miner-level enforcement.

### Why Absolute Deadlines

The `timeoutDelta` field stores an **absolute** Unix timestamp (or block height), not a relative offset. This is because:

1. The sighash preimage of the *current* transaction does not contain the *parent* transaction's nLockTime or block timestamp.
2. There is no way in Script to determine when the token entered a particular state.
3. An absolute deadline, set at issuance, is the simplest correct approach.

For use cases requiring per-state deadlines, the application layer can issue multiple funnel tokens with staggered absolute deadlines, or use `OP_CHECKLOCKTIMEVERIFY` if the script design permits.

---

## 6. Inductive Proof

### Parent State Extraction

On every non-issuance operation, the scriptSig supplies `parentRawTx` (the raw bytes of the parent token transaction). The script:

1. Parses `parentRawTx` to extract the PP1_SM output at index 1 (or the appropriate index for settlement/timeout topologies).
2. Reads the parent PP1_SM locking script from that output.
3. Extracts mutable fields by byte offset:
   - `parentOwnerPKH` from bytes [1:21]
   - `parentCurrentState` from byte [97]
   - `parentMilestoneCount` from byte [99]
   - `parentCommitmentHash` from bytes [101:133]
4. Extracts immutable fields and verifies they match the current script:
   - `parentTokenId` at bytes [22:54] must equal current tokenId
   - `parentMerchantPKH` at bytes [55:75] must equal current merchantPKH
   - `parentCustomerPKH` at bytes [76:96] must equal current customerPKH

### Script Rebuild

The inductive proof reconstructs the expected PP1_SM script from the parent template with substituted mutable fields:

```
rebuiltScript = parentScript[0:1]       // ownerPKH pushdata (0x14)
              + newOwnerPKH             // 20 bytes (substituted)
              + parentScript[21:97]     // tokenId, merchantPKH, customerPKH,
                                        //   currentState pushdata (all immutable)
              + num2bin(newState, 1)     // currentState (substituted)
              + parentScript[98:99]     // milestoneCount pushdata
              + num2bin(newMilestoneCount, 1)  // milestoneCount (substituted)
              + parentScript[100:101]   // commitmentHash pushdata
              + newCommitmentHash       // 32 bytes (substituted)
              + parentScript[133:]      // transitionBitmask + timeoutDelta
                                        //   + entire script body (immutable)
```

The script verifies:
```
SHA256(rebuiltScript) == SHA256(currentScriptCode)
```

This single check guarantees:
- tokenId, merchantPKH, customerPKH are unchanged (embedded in the immutable slice [21:97])
- transitionBitmask and timeoutDelta are unchanged (embedded in the immutable suffix [133:])
- The entire script body (dispatch logic, guard conditions) is unchanged
- Only ownerPKH, currentState, milestoneCount, and commitmentHash were updated

### PP2_SM Validation

PP2_SM follows the same structure as the existing PP2 for NFTs/FTs. Key byte offsets shift to account for the PP1_SM header size. The PP2_SM constructor params:

```
fundingOutpoint    (36 bytes)
witnessChangePKH   (20 bytes)
changeAmount       (1 byte, OP_1)
ownerPKH           (20 bytes)
pp1OutputIndex     (1 byte)
pp2OutputIndex     (1 byte)
```

The PP1_SM script validates PP2_SM by:
1. Extracting the PP2_SM output from the parent transaction
2. Verifying the constructor params match (fundingOutpoint, ownerPKH)
3. Verifying the PP2_SM script body is the expected template

### PP3_SM Configuration

PP3_SM uses the dynamically generated partial SHA256 witness verifier (`WitnessCheckScriptGen`). The `pp2OutputIndex` adjusts for varying topologies:

| Topology | pp2OutputIndex |
|----------|---------------|
| Standard (5-output) | 2 |
| Timeout (6-output) | 3 |
| Settlement (7-output) | 4 |

### Input Structure

**Issuance (CreateFunnel):**
```
Input 0: Funding UTXO (P2PKH)
```

**Subsequent transitions (Enroll, Confirm, Convert, Settle, Timeout):**
```
Input 0: Funding UTXO (P2PKH)
Input 1: Previous witness output (ModP2PKH)
Input 2: Previous PP3_SM output
```

**Burn (terminal):**
```
Input 0: PP1_SM UTXO (the token itself)
```

---

## 7. Commitment Hash Chain

Every state transition appends to an auditable event log compressed into a constant-size rolling hash. This mirrors the PP1_AT `stampsHash` pattern.

### Hash Chain Construction

```
Genesis (issuance):
  commitmentHash₀ = 0x00...00  (32 zero bytes)

Transition n (any operation except burn):
  eventDigest = SHA256(signerSig₁ || [signerSig₂] || eventData)
  commitmentHashₙ = SHA256(commitmentHashₙ₋₁ || eventDigest)
```

Where:
- `signerSig₁` is the primary signer's signature (always the merchant)
- `signerSig₂` is the secondary signer's signature (customer, when dual-sign required)
- `eventData` is operation-specific data supplied in the scriptSig

### Verification in Script

The script verifies the commitment hash update on every transition:

```
// On stack: prevCommitmentHash, signerSig, eventData, newCommitmentHash

// Compute expected eventDigest
signerSig eventData CAT
SHA256                          // eventDigest

// Compute expected new hash
prevCommitmentHash SWAP CAT
SHA256                          // expectedNewHash

// Verify against the claimed new hash
newCommitmentHash
EQUALVERIFY
```

### Properties

**Binding:** Each commitment incorporates the previous hash, creating a tamper-evident chain. Altering any past event invalidates all subsequent hashes.

**Compact:** The hash is always 32 bytes regardless of chain length. A funnel with 100 milestones has the same on-chain footprint as one with 1.

**Auditable:** Off-chain, any party who recorded the individual `(signerSig, eventData)` pairs can reconstruct and verify the full chain.

**Non-repudiable:** Each event includes the signer's ECDSA signature, which is bound to the specific sighash preimage of that transaction. The signature cannot be reused or transplanted to a different context.

---

## 8. Design Decisions

### 8.1 Absolute vs. Relative Timeouts

**Decision:** Absolute deadline stored in `timeoutDelta`.

**Rationale:** The sighash preimage of the current transaction does not contain the parent transaction's nLockTime or the timestamp at which the token entered a state. Relative deadlines would require information not available in Script. An absolute deadline set at issuance is the simplest correct approach.

**Trade-off:** Less flexible (can't have per-state deadlines on-chain), but correct and implementable. Per-state deadlines can be managed at the application layer by issuing tokens with appropriate absolute deadlines.

### 8.2 Sequential CHECKSIG vs. CHECKMULTISIG

**Decision:** Two sequential `OP_CHECKSIG` calls for dual-sign operations.

**Rationale:** `OP_CHECKMULTISIG` has a known dummy-element bug (requires an extra `OP_0` on the stack). Two sequential `OP_CHECKSIG` operations are cleaner, easier to audit, and each independently returns TRUE/FALSE. Both signatures are over the same sighash preimage (`SIGHASH_ALL | SIGHASH_FORKID`, 0x41).

### 8.3 Transition Bitmask vs. Fully Configurable Graph

**Decision:** 1-byte bitmask enables/disables 6 pre-defined transitions. The graph structure itself is hardcoded in the immutable script body.

**Rationale:** A fully configurable transition graph would require encoding |Q|^2 possible transitions and per-transition signer requirements. This is impractical in Script. The bitmask allows selective disabling at issuance (e.g., disable the PROGRESSING self-loop for single-milestone funnels) while keeping the script body generic.

### 8.4 Atomic Settlement

**Decision:** Settlement creates explicit P2PKH outputs for customer reward and merchant payment within the same transaction that transitions to SETTLED.

**Rationale:** If settlement and state transition were separate transactions, the state could transition without rewards being paid. Atomic settlement guarantees that the SETTLED state is only reached when rewards are actually distributed. The PP1_SM script constructs expected P2PKH outputs using the immutable `customerPKH` and `merchantPKH` from the script header, preventing the merchant from redirecting rewards.

### 8.5 ownerPKH Semantics

**Decision:** `ownerPKH` tracks the "currently expected actor", not permanent ownership.

**Rationale:** Different operations require different signers. The witness transaction (PP3 flow) proves that the `ownerPKH` holder controls the token. By updating `ownerPKH` to reflect who should act next, the witness mechanism works without modification:

| After Operation | ownerPKH set to | Next expected actor |
|----------------|-----------------|---------------------|
| CreateFunnel | merchantPKH | Merchant (to enroll customer) |
| Enroll | customerPKH | Customer (to progress through milestones) |
| Confirm | customerPKH | Customer (for next milestone or conversion) |
| Convert | merchantPKH | Merchant (to settle) |

For dual-sign operations, the script checks `merchantPKH` and `customerPKH` directly from the immutable fields, not from `ownerPKH`.

---

## 9. 3-Party Extension (Future)

The 2-party core can be extended to include a referrer via **token composition**, using the PP1_RNFT archetype from [TOKEN_ARCHETYPES.md](TOKEN_ARCHETYPES.md).

### Approach

The referrer holds a **PP1_RNFT identity token** (self-transfer-only, composition-capable):

```
PP1_RNFT flags = 0b00000001  (self-transfer only)
```

The funnel token (PP1_SM) is extended with:
- An additional immutable field: `referrerPKH` (20 bytes)
- A `hasReferrer` flag bit in `transitionBitmask`

### Referral Activation

During Enroll (OP_1), if `hasReferrer` is set:
1. The referrer's PP1_RNFT identity token must be co-spent in the same transaction
2. The PP1_SM script verifies the referrer's token outpoint appears in `hashPrevouts`
3. The referrer's identity token is self-transferred (recreated with same owner)
4. This proves the referrer exists and consents to the referral

### Commission Distribution

During Settle (OP_4), the topology extends to 8 outputs:

```
Output 0: Change
Output 1: Customer reward (P2PKH to customerPKH)
Output 2: Merchant payment (P2PKH to merchantPKH)
Output 3: Referrer commission (P2PKH to referrerPKH)
Output 4: PP1_SM final state (SETTLED)
Output 5: PP2_SM
Output 6: PP3_SM
Output 7: Metadata
```

Commission calculation can be a fixed amount embedded at issuance, or computed from the settlement data.

### Timeout with Referrer

Timeout operates identically to the 2-party case — the referrer has no claim on the locked funds. Only the merchant recovers on timeout.

---

## 10. Script Size Estimate

| Component | Estimated Size |
|---|---|
| Header (140 bytes) | 140 B |
| Dispatch table (7 selectors) | ~100 B |
| Burn path (simple CHECKSIG) | ~30 B |
| Issuance path (hashPrevOuts + checkPreimage) | ~500 B |
| Enroll path (single-sig + inductive proof) | ~1.5 KB |
| Confirm path (dual-sig + rolling hash + inductive proof) | ~2.0 KB |
| Convert path (dual-sig + inductive proof) | ~1.8 KB |
| Settle path (single-sig + 7-output rebuild + P2PKH construction) | ~2.5 KB |
| Timeout path (single-sig + nLockTime extraction + 6-output rebuild) | ~2.0 KB |
| checkPreimageOCS (ECDSA trick for sighash verification) | ~1.5 KB |
| Shared utilities (readOutpoint, rebuild helpers) | ~1.0 KB |
| **Total estimated PP1_SM script** | **~12-15 KB** |

### Comparison

| Token Type | Script Size | Operations |
|---|---|---|
| PP1_NFT (current) | ~11 KB (hand-optimized) | 3 (issue, transfer, burn) |
| PP1_FT (current) | ~14 KB (hand-optimized) | 5 (mint, transfer, split, merge, burn) |
| **PP1_SM (estimated)** | **~12-15 KB** | **7 (create, enroll, confirm, convert, settle, timeout, burn)** |
| PP3 witness (all types) | ~37.5 KB | 1 (witness verification) |

The PP3_SM partial SHA256 witness verifier (~37.5 KB) remains the dominant script size, consistent with all other TSL1 token types. The PP1_SM script body is comparable to existing tokens despite having more operations, because many operations share the same inductive proof and transaction reconstruction logic.
