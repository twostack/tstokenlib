# TSL1 Token Archetypes

Four new token archetypes that extend the TSL1 protocol to cover a broad range of real-world use cases beyond basic NFTs and fungible tokens.

| Archetype | Base | Key Addition | Use Cases |
|-----------|------|-------------|-----------|
| [Restricted NFT (PP1_RNFT)](#1-restricted-nft-pp1_rnft) | PP1_NFT | Configurable transfer/composition/lifetime policies | Voucher, Identity, Auth/RBAC, Voting |
| [Restricted FT (PP1_RFT)](#2-restricted-ft-pp1_rft) | PP1_FT | Merkle-based merchant whitelist | School Money, Community Money, Digital Cash |
| [Appendable Token (PP1_AT)](#3-appendable-token-pp1_at) | New | Append-only stamps + threshold unlock | Loyalty/Rewards Card, Gamification |
| [State Machine (PP1_SM)](#4-state-machine-pp1_sm) | New | Finite automaton with dual-sig transitions, timeout, settlement | Customer Funnel, Escrow, Service Agreements |

All four inherit the TSL1 **inductive proof** architecture (PP1 mechanism), **partial SHA256 witness** (PP3), and **metadata persistence** (OP_RETURN output). No back-to-genesis tracing is required.

---

## 1. Restricted NFT (PP1_RNFT)

A parameterized extension of PP1_NFT that adds configurable constraints via a flags byte and optional companion token requirement.

### 1.1 Byte Layout

```
Byte 0:       0x14 (pushdata 20)
Bytes 1-20:   ownerPKH             — current holder
Byte 21:      0x20 (pushdata 32)
Bytes 22-53:  tokenId              — unique identifier (immutable)
Byte 54:      0x14 (pushdata 20)
Bytes 55-74:  rabinPubKeyHash      — identity anchor (immutable, see note below)
Byte 75:      0x01 (pushdata 1)
Byte 76:      flags                — constraint configuration
```

**Why Rabin, not ECDSA:** Identity anchoring requires verifying a signature over arbitrary data in Script. On-chain ECDSA verification produces ~10 MB of script (two scalar multiplications on secp256k1), while Rabin verification requires only a single modular squaring (~hundreds of bytes). This makes Rabin the only practical choice for tokens that must fit within reasonable script sizes. See [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md) for the full analysis.

If bit 3 of flags is set (composition required):

```
Byte 77:      0x20 (pushdata 32)
Bytes 78-109: companionTokenId     — required companion token (immutable)
Byte 110:     start of script body
```

Otherwise:

```
Byte 77:      start of script body
```

### 1.2 Flags Byte

```
Bit 0-1:  Transfer policy
            00 = freely transferable
            01 = self-transfer only (ownership proof without change of hands)
            10 = non-transferable (transfer operation disabled entirely)
Bit 2:    One-time-use
            0 = persistent (survives redemption)
            1 = burn-on-redeem (destroyed when redeemed)
Bit 3:    Composition required
            0 = standalone token
            1 = companionTokenId field present; spending requires
                the companion token to be consumed in the same transaction
Bits 4-7: Reserved (must be 0)
```

### 1.3 Operations

| Selector | Operation | Description |
|----------|-----------|-------------|
| `OP_0` | **Issue** | Create token. Embeds ownerPKH, tokenId, rabinPKH, flags, and optionally companionTokenId. Rabin identity anchoring as per PP1_NFT. |
| `OP_1` | **Transfer** | Change owner. Gated by transfer policy (see below). |
| `OP_2` | **Burn** | Destroy token. Owner signs with CHECKSIG. |
| `OP_3` | **Redeem** | Exercise the token's entitlement. If one-time-use flag is set, the token is burned atomically. |

#### Transfer Policy Enforcement

The script extracts bits 0-1 from the flags byte and branches:

- **`00` (free):** Standard PP1_NFT transfer — new ownerPKH can be any value.
- **`01` (self-only):** Script verifies `newOwnerPKH == currentOwnerPKH`. The token is spent and recreated with the same owner. Useful for proving ownership in a composed transaction without relinquishing the token.
- **`10` (non-transferable):** Script immediately fails with `OP_FALSE OP_RETURN` if OP_1 is invoked. The token cannot change hands.

#### Composition Mechanism

When bit 3 is set, the Transfer and Redeem operations require the companion token to be spent in the same transaction. Verification:

1. The scriptSig supplies the companion token's **outpoint** (32-byte txid + 4-byte vout).
2. The script computes `SHA256d(ownOutpoint || companionOutpoint || ...)` and verifies it equals **hashPrevouts** from the sighash preimage.
3. This proves the companion token is an input to the same transaction.
4. The companion token (typically an identity/auth token with self-transfer-only policy) is spent and recreated in the same transaction, proving the spender controls both tokens.

### 1.4 Use Case Mapping

#### Vouchers

```
flags = 0b00000101  (non-transferable + one-time-use)
```

- Issued by merchant to customer
- Cannot be given away (non-transferable)
- Redeemed once, then destroyed (burn-on-redeem)
- No composition required — the voucher is self-contained

**Lifecycle:**
```
Issue → [hold] → Redeem (burns token)
```

#### Identity Token

```
flags = 0b00000001  (self-transfer only)
```

- Proves the holder's identity on-chain
- Can be "refreshed" via self-transfer (proves liveness / current ownership)
- Cannot be given to someone else
- Persists indefinitely

**Lifecycle:**
```
Issue → [self-transfer to prove ownership] → ... → Burn (optional)
```

#### Authentication + Authorization (RBAC)

**Authorization token** (role token):
```
flags = 0b00000001  (self-transfer only)
```
Represents a role (e.g., "voter", "admin", "auditor"). Held by the user, self-transferred to prove role membership.

**Authentication token** (action token):
```
flags = 0b00001101  (non-transferable + one-time-use + composition required)
companionTokenId = <authorization token's tokenId>
```
Represents a specific action (e.g., "cast vote", "approve transaction"). Requires the role token to be co-spent.

**Lifecycle:**
```
Auth token issued → Redeem (composed with role token in same tx) → Auth token burned
Role token: self-transferred in the same tx, remains alive
```

#### Voting

**Ballot token** (the election):
```
flags = 0b00000001  (self-transfer only)
```
Represents a specific ballot/election. Self-transferred when composed with a vote.

**Voting token** (right to vote):
```
flags = 0b00001101  (non-transferable + one-time-use + composition required)
companionTokenId = <ballot tokenId>
```
One-time-use. Must be composed with the ballot token to cast a vote. Burned after use, preventing double-voting.

**Lifecycle:**
```
Voting token issued to eligible voter
  → Redeem (composed with ballot token) → Voting token burned
Ballot token: self-transferred in same tx, accumulates votes in metadata
```

---

## 2. Restricted FT (PP1_RFT)

A parameterized extension of PP1_FT that adds a Merkle-tree-based recipient whitelist, restricting where tokens can be spent.

### 2.1 Byte Layout

```
Byte 0:       0x14 (pushdata 20)
Bytes 1-20:   ownerPKH             — current holder
Byte 21:      0x20 (pushdata 32)
Bytes 22-53:  tokenId              — unique identifier (immutable)
Byte 54:      0x08 (pushdata 8)
Bytes 55-62:  amount               — token balance (8-byte LE, high bit clear)
Byte 63:      0x20 (pushdata 32)
Bytes 64-95:  merkleRoot           — root of authorized-recipient Merkle tree (immutable)
Byte 96:      0x01 (pushdata 1)
Byte 97:      flags                — constraint configuration
Byte 98:      start of script body
```

### 2.2 Flags Byte

```
Bit 0:    Whitelist enforced
            0 = unrestricted (anyone can receive)
            1 = transfers restricted to whitelisted recipients
Bit 1:    Issuer-redeemable
            0 = standard (no settlement path)
            1 = merchants can redeem tokens back to issuer for fiat settlement
Bits 2-7: Reserved (must be 0)
```

### 2.3 Merkle Whitelist Mechanism

The Merkle tree is constructed off-chain by the issuer:

```
Leaf construction:
  leaf = SHA256(merchantPKH)

Tree construction (binary Merkle tree):
  node = SHA256(left_child || right_child)

Root embedded in locking script:
  merkleRoot = tree root hash (32 bytes)
```

#### Proof Verification in Script

When a transfer or split requires whitelist validation, the scriptSig supplies:

1. `recipientPKH` — the intended recipient's public key hash
2. `proofLength` — number of levels in the Merkle proof
3. `proof[]` — array of (sibling_hash, direction_bit) pairs

The script verifies:

```
hash = SHA256(recipientPKH)
for i in 0..proofLength-1:
  sibling = proof[i].hash       (32 bytes from scriptSig)
  direction = proof[i].bit      (0 = sibling is left, 1 = sibling is right)
  if direction == 0:
    hash = SHA256(sibling || hash)
  else:
    hash = SHA256(hash || sibling)
EQUALVERIFY hash == merkleRoot
```

#### Whitelist Exemptions

Not all operations check the whitelist:

| Operation | Whitelist Check | Reason |
|-----------|----------------|--------|
| Mint | No | Issuer distributes freely to any recipient |
| Transfer | **Yes** — on recipient | Restricts where tokens flow |
| Split (recipient) | **Yes** — on recipient | Same as transfer |
| Split (change) | No | Change returns to current owner (self) |
| Merge | No | Combining own UTXOs, no new recipient |
| Burn | No | Destroying tokens, no recipient |
| Redeem | Special | Merchant→issuer path (see §2.5) |

### 2.4 Operations

| Selector | Operation | Description |
|----------|-----------|-------------|
| `OP_0` | **Mint** | Issuer creates tokens with amount, merkleRoot, flags. No whitelist check. |
| `OP_1` | **Transfer** | Send full amount to new owner. Whitelist check on recipient if flag set. |
| `OP_2` | **Split** | Divide amount. Whitelist check on recipient; change exempt. Conservation: `recipientAmt + changeAmt == parentAmt`. |
| `OP_3` | **Merge** | Combine two UTXOs. `amountA + amountB == mergedAmount`. No whitelist check. |
| `OP_4` | **Burn** | Destroy tokens. Owner signs. |
| `OP_5` | **Redeem** | Merchant sends tokens to issuer for fiat settlement (if issuer-redeemable flag set). |

### 2.5 Redemption / Settlement Path

When the issuer-redeemable flag (bit 1) is set, merchants can return tokens to the issuer for off-chain fiat settlement:

1. Merchant holds tokens received from customers.
2. Merchant invokes **Redeem** (OP_5), which transfers the tokens to a special **issuer burn address** (the issuer's PKH embedded in the token or derived from the Rabin identity).
3. The issuer collects redeemed tokens and settles with the merchant off-chain.
4. Optionally, redeemed tokens are burned by the issuer to remove them from circulation.

This models the **Rivo-style** digital cash flow:
```
Issuer ──mint──▶ Customer ──spend──▶ Merchant ──redeem──▶ Issuer ──settle──▶ Merchant (fiat)
```

### 2.6 Updating the Whitelist

The merkleRoot is **immutable** within a token's lifetime. To update the set of authorized merchants:

1. Issuer constructs a new Merkle tree with the updated merchant set.
2. Issuer mints new tokens with the updated merkleRoot.
3. Existing tokens with the old merkleRoot continue to work with the old merchant set until burned or redeemed.

For use cases requiring frequent whitelist changes, the issuer can implement a **rolling issuance** strategy: mint tokens with short-lived validity (enforced via nLocktime or metadata) and periodically re-issue with updated roots.

### 2.7 Use Case Mapping

#### School Money (Events)

```
merkleRoot = MerkleTree([stallA_PKH, stallB_PKH, stallC_PKH, ...]).root
flags = 0b00000001  (whitelist enforced, not redeemable)
```

- School mints tokens and distributes to students
- Students can only spend at event stalls (whitelisted)
- Stalls cannot redeem for fiat — tokens are purely internal
- Splitting allowed for making change

**Lifecycle:**
```
School mints → Distribute to students → Students spend at stalls → Stalls hold tokens
```

#### School Money (Cafeteria)

```
merkleRoot = MerkleTree([cafeteria_PKH]).root
flags = 0b00000001  (whitelist enforced)
```

Same as events but with a single-entry whitelist (the cafeteria).

#### Non-Custodial Digital Cash

```
merkleRoot = MerkleTree([merchantA_PKH, merchantB_PKH, ...]).root
flags = 0b00000011  (whitelist enforced + issuer-redeemable)
```

- Issuer (e.g., Rivo) mints tokens when customer tops up
- Customer spends at participating merchants (whitelisted)
- Merchants redeem tokens back to issuer for fiat settlement
- Full split/merge support for making change

**Lifecycle:**
```
Customer tops up → Issuer mints to customer → Customer spends at merchant
  → Merchant redeems to issuer → Issuer settles fiat to merchant
```

#### Community Currency (Bazaars, Fairs, Cleanup Vouchers)

```
merkleRoot = MerkleTree([vendor1_PKH, vendor2_PKH, ...]).root
flags = 0b00000001  (whitelist enforced)
```

- Community org mints tokens as rewards (e.g., cleanup participation)
- Tokens spendable only at community vendors/events
- Optionally redeemable if backed by a settlement fund

---

## 3. Appendable Token (PP1_AT)

A new token type with an append-only state log and threshold-based redemption. Designed for loyalty programs where value accrues over time through repeated interactions.

### 3.1 Byte Layout

```
Byte 0:        0x14 (pushdata 20)
Bytes 1-20:    ownerPKH             — customer holding the loyalty card
Byte 21:       0x20 (pushdata 32)
Bytes 22-53:   tokenId              — unique card identifier (immutable)
Byte 54:       0x14 (pushdata 20)
Bytes 55-74:   issuerPKH            — shop's public key hash (immutable)
Byte 75:       0x02 (pushdata 2)
Bytes 76-77:   stampCount           — current number of stamps (2-byte LE, mutable)
Byte 78:       0x02 (pushdata 2)
Bytes 79-80:   threshold            — stamps required to unlock redemption (immutable)
Byte 81:       0x20 (pushdata 32)
Bytes 82-113:  stampsHash           — rolling hash of all accumulated stamps (mutable)
Byte 114:      start of script body
```

### 3.2 Dual-Authority Model

The appendable token uses a **dual-authority** model where different operations require different signers:

| Operation | Required Signer | Why |
|-----------|----------------|-----|
| Issue | Issuer | Shop creates the loyalty card |
| Stamp | Issuer | Only the shop can award stamps (prevents self-minting points) |
| Redeem | Customer | Customer chooses when to redeem earned rewards |
| Transfer | Customer | Customer transfers card (if allowed) |
| Burn | Customer | Customer destroys card |

### 3.3 Rolling Stamp Hash

To keep the locking script a **constant size** regardless of how many stamps have been accumulated, stamps are compressed into a rolling SHA256 hash chain:

```
Initial state (0 stamps):
  stampsHash = 0x0000...0000  (32 zero bytes)

After stamp 1:
  stamp₁ = SHA256(issuerSig₁ || metadata₁)
  stampsHash₁ = SHA256(stampsHash₀ || stamp₁)

After stamp 2:
  stamp₂ = SHA256(issuerSig₂ || metadata₂)
  stampsHash₂ = SHA256(stampsHash₁ || stamp₂)

General formula:
  stampₙ = SHA256(issuerSigₙ || metadataₙ)
  stampsHashₙ = SHA256(stampsHashₙ₋₁ || stampₙ)
```

The metadata field can carry purchase-specific data (e.g., receipt hash, purchase amount, timestamp) providing an auditable trail without bloating the script.

### 3.4 Operations

| Selector | Operation | Description |
|----------|-----------|-------------|
| `OP_0` | **Issue** | Shop creates loyalty card for customer. Sets ownerPKH, issuerPKH, threshold. stampCount=0, stampsHash=zeros. |
| `OP_1` | **Stamp** | Issuer adds a stamp. See §3.5. |
| `OP_2` | **Redeem** | Customer redeems reward. Requires stampCount >= threshold. See §3.6. |
| `OP_3` | **Transfer** | Change ownerPKH. Can be disabled by the script for non-transferable cards. |
| `OP_4` | **Burn** | Customer destroys card. Owner signs with CHECKSIG. |

### 3.5 Stamp Operation (OP_1)

The issuer awards a stamp to the customer's loyalty card.

**ScriptSig supplies:**
- `preImage` — sighash preimage
- `issuerPubKey` — issuer's public key
- `issuerSig` — issuer's ECDSA signature
- `stampMetadata` — arbitrary data for this stamp (receipt hash, amount, etc.)
- Standard PP2/PP3 witness data

**Script verification:**
1. `HASH160(issuerPubKey) == issuerPKH` — verify issuer identity
2. `CHECKSIG(issuerSig, issuerPubKey)` — verify issuer authorization
3. Compute `newStamp = SHA256(issuerSig || stampMetadata)`
4. Compute `newStampsHash = SHA256(currentStampsHash || newStamp)`
5. Verify `newStampCount == currentStampCount + 1`
6. Rebuild PP1_AT with updated stampCount and stampsHash
7. Verify outputs via sighash preimage (inductive proof)

**Inductive proof carries forward:**
- tokenId (unchanged)
- issuerPKH (unchanged)
- threshold (unchanged)
- ownerPKH (unchanged — stamp doesn't change ownership)
- stampCount (incremented by 1)
- stampsHash (updated via rolling hash)

### 3.6 Redeem Operation (OP_2)

The customer redeems their accumulated stamps for a reward.

**ScriptSig supplies:**
- `preImage` — sighash preimage
- `ownerPubKey` — customer's public key
- `ownerSig` — customer's ECDSA signature

**Script verification:**
1. `HASH160(ownerPubKey) == ownerPKH` — verify customer identity
2. `CHECKSIG(ownerSig, ownerPubKey)` — verify customer authorization
3. `stampCount >= threshold` — verify enough stamps accumulated
4. **Burn variant:** token is destroyed (no PP1_AT output created)
5. **Reset variant:** stampCount reset to 0, stampsHash reset to zeros, token continues

The choice between burn and reset can be controlled by an additional flag bit, or by convention (the issuer decides at issuance time whether the card is single-use or reusable).

### 3.7 Use Case Mapping

#### Loyalty / Rewards Card

```
issuerPKH = shop's PKH
threshold = 10  (buy 10, get 1 free)
```

- Shop issues loyalty card to customer
- Each purchase: shop stamps the card (OP_1) with receipt metadata
- After 10 stamps: customer redeems (OP_2) for a reward
- Card can reset (reusable) or burn (single-use reward)

**Lifecycle:**
```
Issue (stampCount=0, threshold=10)
  → Stamp (stampCount=1) → Stamp (stampCount=2) → ... → Stamp (stampCount=10)
  → Redeem (stampCount >= threshold) → [burn or reset to 0]
```

#### Gamification

```
issuerPKH = game server's PKH
threshold = varies per achievement
```

- Game server issues achievement tokens to players
- Completing challenges earns stamps (game server signs)
- Reaching thresholds unlocks rewards, badges, or in-game items
- Stamp metadata carries challenge-specific proof (score hash, completion proof)

**Lifecycle:**
```
Issue achievement card (threshold=5)
  → Complete challenge 1 (stamp) → Complete challenge 2 (stamp) → ...
  → Threshold reached → Redeem (claim reward)
```

---

## 4. State Machine (PP1_SM)

A finite-state automaton token with dual-authority transitions, a rolling commitment hash chain, timeout mechanism, and atomic settlement. Fully specified in [FUNNEL_STATE_MACHINE.md](FUNNEL_STATE_MACHINE.md).

PP1_SM is the first concrete instantiation of the automata-to-Bitcoin mapping. The current specification implements a **customer acquisition funnel** (merchant + customer roles). Future SM variants would follow the same architectural pattern with different state graphs and role assignments.

### 4.1 Summary

| Property | Value |
|----------|-------|
| Header size | 140 bytes |
| States | 6 (INIT, ACTIVE, PROGRESSING, CONVERTING, SETTLED, EXPIRED) |
| Operations | 7 (CreateFunnel, Enroll, Confirm, Convert, Settle, Timeout, Burn) |
| Roles | Merchant (immutable PKH) + Customer (immutable PKH) |
| Mutable fields | ownerPKH, currentState, milestoneCount, commitmentHash |
| Immutable fields | tokenId, merchantPKH, customerPKH, transitionBitmask, timeoutDelta |
| Key mechanisms | Transition bitmask, nLockTime timeout, atomic P2PKH settlement, commitment hash chain |

### 4.2 Use Case Mapping

#### Customer Acquisition Funnel

The primary use case. A merchant creates a funnel, enrolls a customer, confirms milestones (engagement events), triggers conversion, and settles rewards atomically.

```
CreateFunnel → Enroll → Confirm (×N) → Convert → Settle
                                                    ├─► Customer reward (P2PKH)
                                                    └─► Merchant payment (P2PKH)
```

Timeout from any non-terminal state returns funds to the merchant.

#### Future SM Variants

The PP1_SM architecture (inductive proof, commitment chain, timeout, bitmask-gated transitions) is designed to be reused for other state machine use cases — escrow workflows, service agreements, supply chain tracking — each as a separate contract with its own state encoding. See [FUTURE_PRIMITIVES.md](FUTURE_PRIMITIVES.md) for planned extensions including periodic transitions (PP1_CSM) and oracle-gated transitions.

---

## 5. Comparison Matrix

### Use Cases × Archetypes

| Use Case | Archetype | Transfer | Split | Whitelist | Composition | Stamps | One-Time | State Machine |
|----------|-----------|----------|-------|-----------|-------------|--------|----------|---------------|
| Voucher | RNFT | No | — | — | — | — | Yes | — |
| Identity | RNFT | Self | — | — | — | — | No | — |
| RBAC (role) | RNFT | Self | — | — | — | — | No | — |
| RBAC (action) | RNFT | No | — | — | Yes | — | Yes | — |
| Voting (ballot) | RNFT | Self | — | — | — | — | No | — |
| Voting (vote) | RNFT | No | — | — | Yes | — | Yes | — |
| School Money | RFT | Yes | Yes | Stalls | — | — | No | — |
| Community Money | RFT | Yes | Yes | Vendors | — | — | No | — |
| Digital Cash | RFT | Yes | Yes | Merchants | — | — | No | — |
| Loyalty Card | AT | Optional | — | — | — | Yes | Optional | — |
| Gamification | AT | Optional | — | — | — | Yes | Optional | — |
| Customer Funnel | SM | — | — | — | Optional | — | — | 6 states |

### Constraints × Archetypes

| Constraint | PP1_NFT | PP1_FT | PP1_RNFT | PP1_RFT | PP1_AT | PP1_SM |
|------------|---------|--------|----------|---------|--------|--------|
| Unique identity | Yes | — | Yes | — | Yes | Yes |
| Fungible amount | — | Yes | — | Yes | — | — |
| Transfer policy | Free | Free | Configurable | Free | Configurable | — |
| Split/Merge | — | Yes | — | Yes | — | — |
| Recipient whitelist | — | — | — | Merkle tree | — | — |
| Token composition | — | — | Optional | — | — | Optional (3-party) |
| One-time-use | — | — | Optional | — | Optional | — |
| Appendable state | — | — | — | — | Rolling hash | Commitment chain |
| Threshold unlock | — | — | — | — | Yes | — |
| Dual authority | — | — | — | — | Yes | Yes (merchant+customer) |
| Rabin identity | Yes | — | Yes | — | — | — |
| Finite state machine | — | — | — | — | — | 6 states, bitmask-gated |
| Timeout mechanism | — | — | — | — | — | nLockTime-gated |
| Atomic settlement | — | — | — | — | — | P2PKH outputs |

---

## 6. Architectural Notes

### 6.1 Transaction Topology

All four archetypes preserve the standard TSL1 output structure:

```
Output 0: Change (P2PKH)
Output 1: PP1_* (token locking script)
Output 2: PP2_* (witness bridge)
Output 3: PP3_* (partial SHA256 witness)
Output 4: Metadata (OP_RETURN)
```

Split operations (PP1_RFT only) extend to 8 outputs:
```
Outputs 1-3: Recipient triplet (PP1_RFT, PP2_RFT, PP3_RFT)
Outputs 4-6: Change triplet (PP1_RFT, PP2_RFT, PP3_RFT)
Output 7:    Metadata
```

Composition (PP1_RNFT) adds companion token inputs but does not change the output count — the companion token's outputs are handled by its own script.

PP1_SM uses variable output topologies depending on the operation: 5-output (standard), 6-output (timeout), or 7-output (settlement). See [FUNNEL_STATE_MACHINE.md](FUNNEL_STATE_MACHINE.md) for details.

### 6.2 Script Size Estimates

| Token Type | Header (bytes) | Script Body (approx.) | Total |
|------------|---------------|----------------------|-------|
| PP1_NFT (current) | 75 | ~37.5 KB | ~37.5 KB |
| PP1_FT (current) | 63 | ~40 KB | ~40 KB |
| PP1_RNFT (no companion) | 77 | ~39 KB | ~39 KB |
| PP1_RNFT (with companion) | 110 | ~41 KB | ~41 KB |
| PP1_RFT | 98 | ~44 KB | ~44 KB |
| PP1_AT | 114 | ~42 KB | ~42 KB |
| PP1_SM | 140 | ~12-15 KB | ~12-15 KB |

The Merkle proof verification (PP1_RFT) and stamp hash chain (PP1_AT) add modest overhead to the script body. PP1_SM is smaller than the other archetypes because its PP1 script body handles dispatch and guards only — the dominant SHA256 cost is in the separate PP3_SM witness (~37.5 KB). The dominant cost for all types remains the SHA256 computation in the PP3 witness.

### 6.3 Immutability Guarantees

Fields carried forward via the inductive proof:

| Field | PP1_RNFT | PP1_RFT | PP1_AT | PP1_SM |
|-------|----------|---------|--------|--------|
| tokenId | Immutable | Immutable | Immutable | Immutable |
| rabinPubKeyHash | Immutable | — | — | — |
| flags | Immutable | Immutable | — | — |
| companionTokenId | Immutable | — | — | — |
| merkleRoot | — | Immutable | — | — |
| issuerPKH | — | — | Immutable | — |
| threshold | — | — | Immutable | — |
| merchantPKH | — | — | — | Immutable |
| customerPKH | — | — | — | Immutable |
| transitionBitmask | — | — | — | Immutable |
| timeoutDelta | — | — | — | Immutable |
| ownerPKH | Mutable (transfer) | Mutable (transfer) | Mutable (transfer) | Mutable (next actor) |
| amount | — | Mutable (conserved) | — | — |
| stampCount | — | — | Mutable (+1 per stamp) | — |
| stampsHash | — | — | Mutable (rolling hash) | — |
| currentState | — | — | — | Mutable (transition) |
| milestoneCount | — | — | — | Mutable (+1 per confirm) |
| commitmentHash | — | — | — | Mutable (rolling hash) |
