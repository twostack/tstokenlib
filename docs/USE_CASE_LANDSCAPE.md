# TSL1 Use Case Landscape

A comprehensive assessment of use cases across the TSL1 token archetypes, covering both currently identified applications and speculative future directions.

## Token Archetypes

| Symbol | Type | Status | Description |
|--------|------|--------|-------------|
| **NFT** | PP1_NFT | Implemented | Unique, transferable, burnable |
| **FT** | PP1_FT | Implemented | Fungible, splittable, mergeable |
| **RNFT** | PP1_RNFT | Designed | Restricted NFT — configurable transfer/composition/lifetime policies |
| **RFT** | PP1_RFT | Designed | Restricted FT — Merkle-based merchant whitelist |
| **AT** | PP1_AT | Designed | Appendable Token — stamp accumulation, threshold unlock, dual-authority |
| **SM** | PP1_SM | Designed | State Machine — general-purpose multi-party stateful workflows |

---

## 1. Commerce & Payments

| Use Case | Archetype | Notes |
|---|---|---|
| **Digital cash** (Rivo-style) | RFT | Merchant whitelist, issuer-redeemable, splittable |
| **Gift cards** | RNFT | Non-transferable (or transferable), one-time-use, burns on redemption |
| **Vouchers / Coupons** | RNFT | Non-transferable, one-time-use, merchant-specific |
| **Loyalty / Rewards cards** | AT | Stamp accumulation, threshold unlock, dual-authority |
| **Subscription tokens** | ??? | Needs time-gated access — valid for a period, then expires. Closest to RNFT with an embedded expiry, but none of our types have periodic renewal |
| **Layaway / Installment plans** | SM | State machine: deposit → partial payments → final payment → goods released. Timeout returns partial payments. Very close to the funnel model |
| **Escrow** | SM | 2-party or 3-party (with arbiter). Funds locked until conditions met or timeout. Settlement is atomic |
| **Invoice factoring** | SM | Seller issues invoice token → factor buys at discount → debtor pays factor at maturity. State machine with timeout and multi-party settlement |
| **Prepaid utility tokens** | RFT | School money variant — restricted to a single utility provider (electricity, water, transit) |
| **Split payments** | FT | Already supported — FT split operation divides amount between parties |
| **Tipping / Micro-donations** | FT | Standard FT transfer, possibly with merchant whitelist (RFT) for cause-specific donations |
| **Cashback tokens** | AT | Merchant stamps purchases, customer redeems when threshold met. Identical to loyalty |

---

## 2. Marketing & Engagement

| Use Case | Archetype | Notes |
|---|---|---|
| **Customer funnel tracking** | SM | The [funnel state machine specification](FUNNEL_STATE_MACHINE.md) |
| **Affiliate / Referral tracking** | SM + RNFT | SM for the funnel, RNFT identity token for the referrer (composition) |
| **Engagement rewards** (click, visit, share) | AT | Each engagement is a stamp. Threshold unlock for reward |
| **Contest / Sweepstakes entry** | RNFT | Non-transferable, one-time-use. Issuance = entry. Burn = claim prize |
| **Proof of attendance** (POAP) | RNFT | Non-transferable, persistent. Self-transfer-only for proof of holding |
| **Brand ambassador credentials** | RNFT | Self-transfer-only identity token. Composed with campaign tokens |
| **Bounty programs** | SM | Task posted → claimed → submitted → reviewed → paid. State machine with timeout |
| **Airdrop claims** | RNFT | One-time-use, non-transferable. Issued to eligible addresses, burned on claim |

---

## 3. Identity & Access Control

| Use Case | Archetype | Notes |
|---|---|---|
| **On-chain identity** | RNFT | Self-transfer-only, persistent, Rabin identity anchor |
| **RBAC (role-based access)** | RNFT | Role token (self-transfer) + action token (one-time-use, composed) |
| **KYC / AML attestation** | RNFT | Non-transferable. Issuer (bank, exchange) attests. Self-transfer proves current validity |
| **Membership cards** | AT or RNFT | RNFT if binary (member/not-member). AT if tiered (stamp-based progression to gold/platinum) |
| **API keys / Access tokens** | RNFT | Non-transferable, possibly with expiry. Self-transfer = authentication handshake |
| **Delegated authority** | RNFT | Transferable (to delegate). One-time-use or persistent depending on scope. Composed with principal's identity token |
| **Multi-sig governance** | ??? | Needs N-of-M signature threshold. Current archetypes support 1 or 2 signers. A governance token might need 3-of-5. Possible SM extension or new primitive |
| **Session tokens** | ??? | Short-lived, auto-expiring. Closest to RNFT with timeout, but we don't have time-bounded NFTs yet |

---

## 4. Voting & Governance

| Use Case | Archetype | Notes |
|---|---|---|
| **One-person-one-vote** | RNFT | Non-transferable, one-time-use, composed with ballot token |
| **Weighted voting** (shareholder) | FT + RNFT | FT amount = vote weight. RNFT ballot for composition. Split to vote on multiple proposals |
| **Proxy voting** | RNFT | Transferable (once). Original holder transfers vote to proxy. One-time-use prevents re-delegation |
| **Quadratic voting** | ??? | Needs on-chain sqrt computation or pre-committed vote cost table. FT for credits, but the quadratic pricing rule needs custom script logic |
| **DAO treasury management** | SM | Proposal → vote → threshold → execute. State machine with multi-party signing and timeout |
| **Constitutional amendments** | SM | Proposal → deliberation → supermajority vote → ratification. Multi-stage SM with higher signature thresholds |

---

## 5. Education

| Use Case | Archetype | Notes |
|---|---|---|
| **School money** (events, cafeteria) | RFT | Merchant-whitelisted fungible token |
| **Course completion certificates** | RNFT | Non-transferable, persistent. Issuer = institution |
| **Diplomas / Degrees** | RNFT | Non-transferable, persistent, Rabin-anchored to institution identity |
| **Skill badges** | AT | Appendable — each skill assessment adds a stamp. Threshold = certification level |
| **Student ID** | RNFT | Self-transfer-only identity. Composed with access tokens for facilities |
| **Academic credits** | FT | Fungible, splittable (transfer credits between institutions). Possibly RFT with institution whitelist |
| **Exam tokens** | RNFT | One-time-use, non-transferable. Burns on submission. Prevents re-takes |

---

## 6. Gaming & Entertainment

| Use Case | Archetype | Notes |
|---|---|---|
| **In-game currency** | RFT | Restricted to game ecosystem (merchant whitelist = in-game vendors) |
| **Achievement badges** | AT | Stamp-based progression. Threshold unlocks next tier |
| **Loot / Inventory items** | NFT | Standard NFT — unique, transferable between players |
| **Soulbound items** | RNFT | Non-transferable NFT. Earned, not traded |
| **Tournament entry** | RNFT | One-time-use, non-transferable. Burns on participation |
| **Season passes** | ??? | Time-bounded access. Needs expiry mechanism not currently in any archetype |
| **Collectible cards (trading)** | NFT | Standard NFT — unique, freely transferable |
| **Collectible cards (non-trading)** | RNFT | Non-transferable variant for earned/soulbound collectibles |
| **Betting / Prediction markets** | SM | Bet placed → event occurs → oracle attests → settlement. Needs oracle integration (new primitive) |
| **Loot boxes / Mystery items** | ??? | Needs commit-reveal randomness. No current archetype supports on-chain randomness |

---

## 7. Supply Chain & Provenance

| Use Case | Archetype | Notes |
|---|---|---|
| **Chain of custody** | AT | Each handler stamps the token. Rolling hash = tamper-evident audit trail |
| **Provenance / Authenticity** | NFT + AT | NFT for the item identity. AT for the accumulating history of custody transfers |
| **Quality certifications** | RNFT | Non-transferable, issued by certifying authority. Self-transfer = re-certification |
| **Shipping / Bill of lading** | SM | Created → in transit → customs → delivered. Multi-party (shipper, carrier, receiver, customs) |
| **Fair trade / Organic certification** | RNFT | Non-transferable, issuer = certifying body. Rabin-anchored |
| **Warehouse receipts** | NFT | Unique, transferable. Represents claim on stored goods |
| **Cold chain monitoring** | AT | IoT device stamps temperature readings. If threshold violated, token flagged |
| **Conflict mineral tracking** | AT | Each supply chain node stamps provenance data. Threshold = minimum attestations for compliance |

---

## 8. Real Estate & Property

| Use Case | Archetype | Notes |
|---|---|---|
| **Deed / Title tokens** | NFT | Unique, transferable. Represents property ownership |
| **Fractional ownership** | FT | Fungible shares in a property. Split/merge for trading |
| **Rental agreements** | SM | Lease signed → deposit locked → monthly payments → lease ends → deposit returned. Timeout = eviction process |
| **Property access keys** | RNFT | Non-transferable (tenant-bound) or transferable (landlord delegates). Self-transfer = prove occupancy |
| **Building permits** | RNFT | Non-transferable, one-time-use. Issued by authority, consumed on inspection |

---

## 9. Healthcare

| Use Case | Archetype | Notes |
|---|---|---|
| **Prescription tokens** | RNFT | Non-transferable, one-time-use (or N-use with milestone count). Pharmacy whitelist via composition |
| **Patient consent** | RNFT | Non-transferable, self-transfer-only. Self-transfer = re-affirmation of consent |
| **Insurance claim processing** | SM | Claim filed → evidence submitted → reviewed → approved/denied → paid. Multi-party (patient, provider, insurer) |
| **Vaccination records** | AT | Each vaccination is a stamp from the healthcare provider. Persistent, non-transferable |
| **Clinical trial participation** | SM | Enrolled → screening → active → follow-up → complete. Milestones stamped by trial coordinator |
| **Organ donor registry** | RNFT | Non-transferable, self-transfer-only. Persistent opt-in |

---

## 10. Legal & Compliance

| Use Case | Archetype | Notes |
|---|---|---|
| **Power of attorney** | RNFT | Transferable (to delegate). One-time-use or persistent depending on scope. Composed with principal's identity token |
| **Notarization** | AT | Notary stamps the document token. Single stamp = notarized. Non-transferable |
| **Contract execution** | SM | Draft → countersigned → active → fulfilled → closed. Multi-party state machine |
| **Regulatory compliance attestation** | RNFT | Non-transferable, issuer = regulator. Periodic re-certification via new issuance |
| **Non-disclosure agreements** | SM | Proposed → signed by both parties → active → expired/terminated |
| **Lien / Encumbrance** | RNFT | Non-transferable, attached to a property NFT via composition. Burned on satisfaction |

---

## 11. Government & Public Sector

| Use Case | Archetype | Notes |
|---|---|---|
| **Voting** (elections) | RNFT | Non-transferable, one-time-use, composed with ballot |
| **Permits / Licenses** | RNFT | Non-transferable, possibly time-bounded. Issuer = government agency |
| **Benefit distribution** (welfare, UBI) | RFT | Restricted to approved vendors (groceries, housing). Splittable for partial use |
| **Tax receipts** | RNFT | Non-transferable, persistent. Proof of payment |
| **Public grant tracking** | SM | Applied → approved → milestone payments → audit → closed. Funnel pattern with government as merchant |
| **Land registry** | NFT | Unique parcel token, transferable on sale |
| **Refugee / Displaced person ID** | RNFT | Non-transferable identity. Issuer = UNHCR or government. Critical for stateless populations |

---

## 12. Energy & Environment

| Use Case | Archetype | Notes |
|---|---|---|
| **Carbon credits** | FT | Fungible, tradeable, burnable (retirement = burn) |
| **Renewable energy certificates** | NFT or FT | NFT if each certificate is unique (tracked to specific generation event). FT if fungible by type |
| **Utility prepayment** | RFT | Restricted to specific utility provider. Splittable |
| **Emissions allowances** | FT | Tradeable permits. Cap-and-trade implemented via fixed supply FT |
| **Environmental impact bonds** | SM | Funded → project executed → impact measured → returns distributed. Multi-stage with oracle attestation |

---

## 13. Financial Instruments

| Use Case | Archetype | Notes |
|---|---|---|
| **Bonds / Fixed income** | SM | Issued → coupon payments (periodic) → maturity → redemption. Needs periodic state transitions |
| **Options / Derivatives** | SM | Created → active → exercised/expired. Timeout = expiry. Settlement = atomic payout |
| **Crowdfunding** | SM | Campaign created → contributions → threshold met → funds released. Timeout = refund |
| **Micro-lending** | SM | Loan offered → accepted → disbursed → repayments → settled. Timeout = default |
| **Trade finance (letters of credit)** | SM | Issued → goods shipped → documents presented → payment released. Multi-party (buyer, seller, banks) |
| **Tokenized securities** | FT + RNFT | FT for the shares. RNFT for the shareholder identity (KYC). Composition ensures only verified holders trade |

---

## Gaps: Primitives Not Yet Covered

| Gap | Use Cases Affected | What's Needed |
|---|---|---|
| **Time-bounded validity** | Subscriptions, season passes, session tokens, permits | An expiry mechanism — either a `validUntil` field checked via nLockTime, or periodic re-issuance |
| **On-chain randomness** | Loot boxes, lottery, random assignment | Commit-reveal scheme or oracle-fed randomness. Fundamentally hard on a deterministic VM |
| **Oracle integration** | Prediction markets, insurance triggers, environmental bonds, derivatives | A trusted data feed that can attest to off-chain events. Could be modeled as a special stamp from an oracle-PKH in AT or SM |
| **N-of-M multi-sig** (N > 2) | DAO governance, multi-party escrow, board approvals | Current archetypes support 1 or 2 signers. A governance variant needs threshold signatures |
| **Periodic state transitions** | Bond coupons, subscription renewals, rent payments | SM supports linear progression but not recurring/cyclical transitions. Would need a cycle-capable state machine or repeated issuance |
| **Fungible + Appendable hybrid** | Tokens with both a balance and an event log | AT has stamps but no amount. FT has amount but no stamps. A hybrid would serve financial instruments with both value and history |
| **Conditional transfer restrictions** | Tokens transferable only after a date, or only if holder passes KYC | RNFT has static transfer policy. Dynamic conditions (time-gated, predicate-gated) need richer flag logic |

---

## Coverage Summary

| Archetype | Use Cases | Primary Domains |
|---|---|---|
| **PP1_NFT** | ~5 | Property, collectibles, warehouse receipts |
| **PP1_FT** | ~8 | Payments, carbon credits, split payments, academic credits |
| **PP1_RNFT** | ~25 | Identity, access, voting, vouchers, certificates, permits, credentials |
| **PP1_RFT** | ~8 | School money, digital cash, utility prepayment, benefit distribution, in-game currency |
| **PP1_AT** | ~12 | Loyalty, supply chain, engagement, skill badges, vaccination records |
| **PP1_SM** | ~18 | Funnels, escrow, lending, insurance, contracts, shipping, crowdfunding |
| **??? (new)** | ~8 | Subscriptions, randomness, oracles, N-of-M governance, periodic payments |

The six archetypes (NFT, FT, RNFT, RFT, AT, SM) cover roughly **75-80 use cases** across 13 domains. The remaining ~8 use cases cluster around a small set of missing primitives — **time-bounded validity** and **oracle integration** being the most impactful gaps to close.
