# TSL1 System Architecture Roadmap

A phased plan to take TSL1 from a protocol-layer library to a complete end-to-end platform that businesses can use to issue, operate, and integrate tokens into day-to-day operations.

---

## Current State

TSL1 today is a **protocol library** (tstokenlib). It provides:

- Hand-optimized locking scripts for NFT and FT tokens
- Dart-based script generators, lock/unlock builders, and lifecycle APIs
- Full local test coverage via the dartsv script interpreter
- Specifications for four new archetypes (RNFT, RFT, AT, SM)

Everything above the protocol layer — wallets, coordination, business integration, user-facing tools — does not yet exist.

---

## Target State

A business can:

1. Pick a token archetype from a template library
2. Configure it for their use case (loyalty program, funnel, school money, etc.)
3. Issue tokens to customers/participants via POS, web, or mobile
4. Operate the token lifecycle (stamp, confirm, settle, timeout) through their existing business systems
5. Let customers view and manage their tokens through a simple interface
6. Audit the full history of any token independently

---

## Phases

### Phase 1: Protocol Completion

**Goal:** All six token archetypes implemented, tested, and verified at the script level.

#### 1.1 Implement PP1_RNFT (Restricted NFT)

- Script generator: `pp1_rnft_script_gen.dart`
- Lock builder: `pp1_rnft_lock_builder.dart`
- Unlock builder: `pp1_rnft_unlock_builder.dart`
- Operations: Issue, Transfer (policy-gated), Burn, Redeem
- Composition mechanism (companionTokenId in hashPrevouts)
- Interpreter-verified tests for all flag combinations

#### 1.2 Implement PP1_RFT (Restricted FT)

- Script generator: `pp1_rft_script_gen.dart`
- Lock/unlock builders
- Merkle proof verification in Script
- Operations: Mint, Transfer (whitelist-checked), Split, Merge, Burn, Redeem
- Tests with varying Merkle tree sizes (1, 8, 64 leaves)

#### 1.3 Implement PP1_AT (Appendable Token)

- Script generator: `pp1_at_script_gen.dart`
- Lock/unlock builders
- Dual-authority signing (issuer stamps, owner redeems)
- Rolling SHA256 stamp hash
- Threshold-based unlock
- Tests for stamp accumulation and redemption

#### 1.4 Implement PP1_SM (State Machine)

- Script generator: `pp1_sm_script_gen.dart`
- Lock/unlock builders
- 7-operation dispatch (CreateFunnel through Burn)
- Dual CHECKSIG for co-signed transitions
- nLockTime-based timeout extraction and enforcement using sighash preimage inspection (OP_PUSH_TX pattern). BSV does not have OP_CHECKLOCKTIMEVERIFY (reverted to OP_NOP2) or OP_CHECKSEQUENCEVERIFY (reverted to OP_NOP3). Instead, the locking script extracts nLockTime (4 bytes) and nSequence from the sighash preimage directly, then validates in naked script: (1) nLockTime >= the pre-set expiry value, and (2) nSequence < 0xFFFFFFFF (non-final), ensuring the transaction cannot be mined before the timeout. nLockTime values below 500,000,000 are interpreted as block height; at or above 500,000,000 as Unix timestamp. nSequence serves only as a finality signal — BSV does not implement BIP68 relative lock time
- Settlement topology (7-output with P2PKH reward/payment outputs)
- Timeout topology (6-output with merchant refund)
- Tests for every state transition, including timeout and settlement

#### 1.5 Transaction tool APIs

- `RestrictedTokenTool` — high-level API for RNFT operations
- `RestrictedFungibleTokenTool` — high-level API for RFT operations
- `AppendableTokenTool` — high-level API for AT operations
- `StateMachineTokenTool` — high-level API for SM operations
- Consistent API surface matching existing `TokenTool` and `FungibleTokenTool`

**Depends on:** Nothing. Uses existing tstokenlib patterns and dartsv interpreter.

---

### Phase 2: Wallet Infrastructure

**Goal:** A token-aware wallet SDK that can hold, track, sign, and co-sign across all six token types.

#### 2.1 UTXO Manager

Standard BSV wallets track individual UTXOs. Token wallets must track **triplets** (PP1 + PP2 + PP3) as a single logical unit.

- Token UTXO discovery — identify triplets in a wallet's UTXO set by recognising PP1 script header patterns
- Triplet lifecycle tracking — link PP1, PP2, PP3 outputs of the same token transaction as a single entity
- State extraction — parse the PP1 header to expose current state, owner, amount, milestone count, etc.
- Dust management — track the 1-satoshi UTXOs that carry token state and fund their spending

#### 2.2 Signing Engine

- Single-sign operations — produce a complete scriptSig for operations requiring only one party (issue, burn, timeout)
- Co-sign support — produce a partial signature for operations requiring multiple parties (confirm, convert). The partial signature is transmitted to the counterparty for assembly
- Sighash computation — compute the sighash preimage for a proposed transaction, compatible with checkPreimageOCS
- Key management — HD key derivation, per-token key isolation, key rotation support

#### 2.3 Transaction Builder

- Template-driven transaction construction — given a token type, operation, and parameters, produce the correct input/output structure (5-output, 6-output, 7-output, or burn topology)
- Fee estimation — calculate the mining fee for the assembled transaction, accounting for the large script sizes (PP1 ~12-15 KB, PP3 ~37.5 KB)
- Funding UTXO selection — choose an appropriate funding input to cover the token outputs (3 sats for the triplet) plus mining fees
- nLockTime/nSequence management — for timeout operations, set nLockTime to the token's expiry (block height or Unix timestamp) and ensure at least one input has nSequence < 0xFFFFFFFF to activate the timelock. For all non-timeout operations, set nSequence to 0xFFFFFFFF (final) so nLockTime is ignored
- Witness transaction builder — construct the witness spending transaction for the PP3 flow

#### 2.4 Wallet SDK

- Dart package exposing the UTXO manager, signing engine, and transaction builder as a cohesive API
- Platform targets: server-side Dart (for merchant back-ends), Flutter (for mobile wallets)
- Encrypted key storage with platform-appropriate secure storage (Keychain on iOS, Keystore on Android, file-based for server)

**Depends on:** Phase 1 (token scripts and lifecycle APIs).

---

### Phase 3: Coordination Layer

**Goal:** A protocol and service for multi-party transaction assembly — proposing, reviewing, co-signing, and broadcasting token transactions.

#### 3.1 Transaction Proposal Protocol

Define a message format for proposing a token operation to a counterparty:

- **Proposal message:** Contains the partially-assembled transaction (inputs, outputs, the proposer's signature), the token ID, the operation being requested, and human-readable metadata (e.g., "Merchant XYZ is confirming milestone 3 of your funnel")
- **Response message:** Contains the counterparty's signature (approval) or a rejection with reason
- **Completion message:** The fully-assembled, signed transaction, ready for broadcast

This is analogous to BIP-270 (Payment Protocol) but extended for stateful, multi-party token workflows.

#### 3.2 Messaging Transport

The proposal protocol needs a transport layer. Candidates:

- **Direct P2P** — Peer-to-peer connection between wallets (WebSocket, libp2p). No intermediary. Requires both parties online simultaneously.
- **Relay server** — A lightweight store-and-forward service. The proposer posts the proposal; the counterparty retrieves it when they come online. Tolerates asynchronous workflows.
- **On-chain messaging** — Encode proposals as OP_RETURN transactions. Expensive but requires no infrastructure. Suitable for low-frequency, high-value operations.

The relay server is the pragmatic first choice. It handles the common case (merchant proposes, customer approves on their phone minutes/hours later) without requiring both parties online simultaneously.

#### 3.3 Discovery & Addressing

How does a merchant's system find a customer's wallet?

- **Payment handles** — Human-readable identifiers (email, phone, username) that resolve to a wallet endpoint. Similar to Paymail.
- **QR codes / Deep links** — For in-person interactions (POS). Encode the proposal URL or wallet address in a scannable format.
- **NFC** — Tap-to-connect for mobile-to-POS interactions.

#### 3.4 Notification Service

- Push notifications when a token operation requires the user's action (co-sign a milestone, approve a settlement)
- Timeout warnings — "Your funnel expires in 48 hours"
- State change alerts — "You received a loyalty stamp (7/10)"
- Delivery via push notification (mobile), webhook (server), or email (fallback)

**Depends on:** Phase 2 (wallet SDK for signing and transaction building).

---

### Phase 4: Token Lifecycle Service

**Goal:** A hosted service (or self-hosted package) that manages token operations at business scale — issuance, state tracking, batch operations, and template management.

#### 4.1 Template Library

Pre-configured token archetypes for common business use cases:

| Template | Archetype | Pre-set Parameters |
|---|---|---|
| Loyalty Card (10-stamp) | AT | threshold=10, non-transferable |
| Loyalty Card (custom) | AT | configurable threshold and transferability |
| Standard Funnel | SM | all transitions enabled, 30-day timeout |
| Single-Milestone Funnel | SM | no PROGRESSING self-loop, 7-day timeout |
| Gift Voucher | RNFT | non-transferable, one-time-use |
| Transferable Gift Card | RNFT | transferable, one-time-use |
| School Event Money | RFT | whitelist-enforced, not redeemable |
| Digital Cash | RFT | whitelist-enforced, issuer-redeemable |
| Identity Token | RNFT | self-transfer-only, persistent |
| Voting Token | RNFT | non-transferable, one-time-use, composition-required |
| Certificate | RNFT | non-transferable, persistent |
| Chain of Custody | AT | no threshold (stamp-only), non-transferable |

Templates expose only the parameters the business needs to configure (reward amount, expiry date, merchant list) and hide the protocol details (bitmasks, byte layouts, script generation).

#### 4.2 Token Registry

A database tracking every token the business has issued or participates in:

- Token ID, type, current state, owner, creation date, last activity
- Indexed by business-relevant dimensions: campaign, customer, product, status
- Queryable: "all funnels in PROGRESSING state with 3+ milestones", "all loyalty cards within 2 stamps of threshold", "all tokens expiring this week"
- Populated by monitoring the blockchain for transactions involving the business's tokens

#### 4.3 Batch Operations

- **Batch mint** — issue thousands of tokens (school money distribution, airdrop, event ticketing) in a series of transactions, tracked as a single campaign
- **Batch settle** — settle all completed funnels at end of day
- **Batch timeout** — reclaim funds from all expired tokens
- **Batch stamp** — stamp loyalty cards for all customers who made a purchase today

#### 4.4 Webhook & Event System

Emit business events when token state changes:

```
token.created      — a new token was issued
token.enrolled     — a customer joined a funnel
token.stamped      — a loyalty stamp was added
token.milestone    — a funnel milestone was confirmed
token.converted    — a funnel reached conversion
token.settled      — rewards were distributed
token.expired      — a token timed out
token.burned       — a token was destroyed
```

Businesses subscribe to these events to trigger downstream actions in their own systems (update CRM, send email, log to accounting).

**Depends on:** Phase 2 (wallet SDK), Phase 3 (coordination layer for multi-party operations).

---

### Phase 5: Business Integration

**Goal:** Connectors that plug the token lifecycle into the systems businesses already use.

#### 5.1 REST API

A standard HTTP API that wraps the Token Lifecycle Service:

```
POST   /tokens                  — create a token from a template
GET    /tokens/{id}             — get token state and history
POST   /tokens/{id}/stamp       — stamp a loyalty card
POST   /tokens/{id}/confirm     — confirm a funnel milestone
POST   /tokens/{id}/settle      — settle a completed funnel
POST   /tokens/{id}/timeout     — reclaim an expired token
GET    /tokens?state=ACTIVE     — query tokens by state
POST   /campaigns               — create a batch issuance campaign
```

Authentication, rate limiting, and API key management for business clients.

#### 5.2 Point-of-Sale SDK

A lightweight SDK for POS integration:

- **Scan-to-stamp** — customer presents QR code at checkout, POS triggers a loyalty stamp
- **Scan-to-redeem** — customer presents voucher QR code, POS verifies and burns the token
- **Scan-to-enrol** — customer scans a funnel QR code at the merchant's location
- **Checkout integration** — apply restricted FT tokens (school money, digital cash) as payment, with automatic change calculation via split

Target platforms: Android POS terminals, iOS (Square/Clover-style), web-based POS.

#### 5.3 E-Commerce Plugins

- **Shopify app** — issue loyalty stamps on purchase, apply vouchers at checkout, track funnel conversions
- **WooCommerce plugin** — same functionality for WordPress-based stores
- **Custom checkout widget** — embeddable JavaScript widget for any web checkout. "Pay with school money", "Apply voucher", "Earn 1 loyalty stamp with this purchase"

#### 5.4 Accounting & Compliance Export

- Settlement transactions mapped to double-entry accounting records (debit/credit)
- Token issuance recorded as contingent liability (reward obligation)
- Reward distribution recorded as expense
- CSV/PDF export for auditors
- Tax reporting support (jurisdiction-dependent)

**Depends on:** Phase 4 (token lifecycle service and event system).

---

### Phase 6: Explorer & Audit Tools

**Goal:** Transparency and verification tools for all participants.

#### 6.1 Token Explorer (Web)

A web application for inspecting token state and history:

- Search by token ID, transaction ID, or participant address
- Visual state timeline — show every state transition with timestamp, signers, and event data
- State diagram overlay — highlight the current state on the token type's transition graph
- Commitment chain visualization — display the rolling hash chain with expandable event details
- Raw transaction view for technical users

#### 6.2 Customer Dashboard

A consumer-facing interface (mobile app or web):

- **My Tokens** — list of all tokens the user holds, grouped by type (loyalty cards, vouchers, funnel enrollments)
- **Progress indicators** — "7 of 10 stamps", "Funnel 60% complete", "Balance: 45 school tokens"
- **Action prompts** — "You have a settlement waiting for approval", "Your voucher expires in 3 days"
- **History** — timeline of all token events the user participated in
- **No blockchain jargon** — plain language throughout. "Stamps", "Points", "Balance", "Voucher" — not "UTXOs", "scriptSig", "PP1"

#### 6.3 Verification Tool

A standalone tool (CLI or web) that any party can use to independently verify a token's history:

- Input: token ID + claimed event history (list of event data for each transition)
- Process: reconstruct the commitment hash chain from the claimed events, compare against the on-chain commitment hash
- Output: "Verified — all 7 events match the on-chain hash" or "Mismatch at event 4 — claimed event does not match the chain"

This is the audit tool. It requires no trust in any party — it uses only the on-chain data and the claimed event log.

#### 6.4 Analytics Dashboard (Merchant)

Aggregate views for business operators:

- **Funnel analytics** — conversion rates, average time to conversion, dropout by stage, settlement volumes
- **Loyalty analytics** — stamps per customer, redemption rates, average time to threshold
- **Restricted FT analytics** — velocity (how fast tokens circulate), merchant breakdown (which stalls/vendors receive the most), redemption rates
- **Campaign comparison** — compare performance across campaigns, time periods, customer segments

**Depends on:** Blockchain indexer (reads on-chain data). Can be built in parallel with Phases 2-5.

---

## Phase Summary

| Phase | Deliverable | Depends On | Outcome |
|---|---|---|---|
| **1** | Protocol completion | — | All 6 token types implemented and tested |
| **2** | Wallet SDK | Phase 1 | Hold, sign, co-sign tokens programmatically |
| **3** | Coordination layer | Phase 2 | Multi-party transaction assembly and messaging |
| **4** | Token lifecycle service | Phase 2, 3 | Business-scale issuance, tracking, batch ops |
| **5** | Business integration | Phase 4 | POS, e-commerce, API, accounting connectors |
| **6** | Explorer & audit | Blockchain indexer | Transparency, dashboards, verification tools |

```
Phase 1          Phase 2          Phase 3          Phase 4          Phase 5
Protocol    ───► Wallet SDK  ───► Coordination ───► Lifecycle   ───► Integration
Completion       (hold, sign)     (propose,         Service          (POS, API,
(6 token                          co-sign,          (templates,       e-commerce,
 types)                           notify)            batch ops,       accounting)
                                                    events)
                                       │
                                       │         Phase 6
                                       └───────► Explorer & Audit
                                                 (can start early,
                                                  parallel build)
```

---

## Technical Stack Considerations

| Layer | Recommended Stack | Rationale |
|---|---|---|
| **Protocol** (scripts, builders) | Dart | Existing tstokenlib codebase, dartsv dependency |
| **Wallet SDK** | Dart / Flutter | Shares protocol layer, targets both server and mobile |
| **Coordination relay** | Any (Go, Node, Rust) | Stateless store-and-forward. Language choice driven by ops preference |
| **Token lifecycle service** | Dart (server) | Shares wallet SDK and protocol code. Single language stack |
| **REST API** | Dart (shelf/dart_frog) or Node | Dart keeps the stack unified. Node if the team prefers wider ecosystem |
| **Business plugins** | JavaScript (Shopify/WooCommerce) | Platform-mandated. Thin wrappers calling the REST API |
| **Explorer & dashboards** | Web (React/Vue/Svelte) + indexer | Standard web stack. Indexer can be any language with blockchain RPC access |
| **Mobile customer app** | Flutter | Shares Dart codebase with wallet SDK and protocol layer |

The Dart-through-Flutter stack gives maximum code reuse: the same protocol library, wallet SDK, and lifecycle logic runs on server, mobile, and (via dart2js) web.
