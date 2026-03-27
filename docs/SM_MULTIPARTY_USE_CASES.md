# PP1_SM Multi-Party Use Cases

Detailed specifications for state machine token use cases that leverage multi-party authority, script-enforced settlement, and the generic SM compiler. Each use case identifies the trust failure it solves, defines the state graph, maps party roles to signature requirements, and notes what capabilities are needed from the SM platform.

These use cases build on the [3-party enhancement](state-machine-enhancement.md) and the [generic state machine compiler roadmap](GENERIC_STATE_MACHINE_ROADMAP.md). The [customer acquisition funnel](FUNNEL_STATE_MACHINE.md) is the first instantiation; the use cases below are future instantiations of the same architecture.

---

## Table of Contents

### Part I: B2B Coordination
1. [Milestone-Based Freelance Escrow](#1-milestone-based-freelance-escrow)
2. [Conditional Donation / Impact Funding](#2-conditional-donation--impact-funding)
3. [Music Royalty Split](#3-music-royalty-split)
4. [Supply Chain Provenance](#4-supply-chain-provenance)
5. [Prediction Market / Conditional Bet](#5-prediction-market--conditional-bet)
6. [Construction Contract](#6-construction-contract)
7. [Academic Credential Issuance](#7-academic-credential-issuance)

### Part II: Consumer — Entertainment & Gaming
8. [Provably Fair Loot Box / Gacha](#8-provably-fair-loot-box--gacha)
9. [Esports Tournament Escrow](#9-esports-tournament-escrow)
10. [Battle Pass / Season Pass Value Guarantee](#10-battle-pass--season-pass-value-guarantee)
11. [Player-vs-Player Wager with Anti-Cheat Oracle](#11-player-vs-player-wager-with-anti-cheat-oracle)
12. [Collaborative Content Revenue Share](#12-collaborative-content-revenue-share)
13. [Film/Show Crowdfunding with Milestone Delivery](#13-filmshow-crowdfunding-with-milestone-delivery)
14. [Live Event Ticket with Anti-Scalping and Artist Royalty](#14-live-event-ticket-with-anti-scalping-and-artist-royalty)
15. [Interactive Storytelling / Choose-Your-Adventure NFT](#15-interactive-storytelling--choose-your-adventure-nft)

### Summary
16. [Capability Requirements Matrix (Updated)](#16-capability-requirements-matrix-updated)

---

## 1. Milestone-Based Freelance Escrow

### Trust failure

Freelance platforms take 20-30% fees to intermediate trust. Clients withhold payment after delivery. Freelancers deliver substandard work after being paid upfront. Disputes are resolved by the platform — which has misaligned incentives (they want transaction volume, not fair outcomes). The platform is the single point of trust failure, and both parties are captive to its rulings.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Client** | `clientPKH` (immutable) | Funds the escrow. Co-signs milestone acceptance. |
| **Freelancer** | `freelancerPKH` (immutable) | Delivers work. Submits milestone evidence. |
| **Arbiter** | `arbiterPKH` (immutable) | Resolves disputes. Only active if the DISPUTED state is reached. Fee locked at creation via `commissionBPS`. |

### State graph

```
                  Client funds
CREATED ──────────────────────► FUNDED
                                  │
                     Freelancer   │
                     + Client     │
                     dual-sig     │
                                  ▼
                             MILESTONE_1
                                  │
                     (repeat)     │  Client + Freelancer
                                  │  dual-sig per milestone
                                  ▼
                             MILESTONE_N
                                  │
                     Freelancer   │
                     submits      │
                                  ▼
                             DELIVERED
                               │   │
              Client accepts   │   │  Client disputes
              (Client sig)     │   │  (Client sig)
                               ▼   ▼
                          ACCEPTED  DISPUTED
                               │       │
                  Client sig   │       │  Arbiter sig
                               │       │  (determines split)
                               ▼       ▼
                             SETTLED ◄──┘
                          [3 outputs]
                     Client: remainder/refund
                     Freelancer: earned amount
                     Arbiter: fee (commissionBPS)

    ─── from FUNDED, MILESTONE_*, DELIVERED ───
                               │
                  Timeout       │  (nLockTime gated)
                  Client sig   │
                               ▼
                            EXPIRED
                     Client recovers funds
```

### Transition table

| From | To | Required signers | Notes |
|------|----|-----------------|-------|
| CREATED | FUNDED | Client | Client locks funds |
| FUNDED | MILESTONE_1 | Client + Freelancer | First deliverable accepted |
| MILESTONE_N | MILESTONE_N+1 | Client + Freelancer | Subsequent deliverables |
| MILESTONE_N | DELIVERED | Freelancer | Freelancer claims completion |
| DELIVERED | ACCEPTED | Client | Client confirms satisfaction |
| DELIVERED | DISPUTED | Client | Client raises dispute |
| DISPUTED | SETTLED | Arbiter | Arbiter determines fair split |
| ACCEPTED | SETTLED | Client | Final settlement |
| Any non-terminal | EXPIRED | Client + nLockTime | Deadline passed, client recovers |

### Settlement enforcement

- **Normal path (ACCEPTED → SETTLED):** Freelancer receives full contracted amount. Client receives any excess funds. No arbiter fee.
- **Dispute path (DISPUTED → SETTLED):** Arbiter determines the split (e.g., 70% freelancer / 30% client based on partial delivery). Arbiter receives their `commissionBPS` fee from the total. The split amounts are passed in the arbiter's scriptSig and verified against the commitment chain (the arbiter's signed attestation of fair split is hashed into commitmentHash).
- **Timeout path:** Client recovers all locked funds. Freelancer receives nothing. Arbiter receives nothing.

### Commitment chain usage

Each milestone's commitment hash includes `SHA256(clientSig || freelancerSig || deliverableHash)` — a hash of the actual deliverable (document, code commit, design file). This creates a tamper-evident record of what was delivered and accepted. In a dispute, the arbiter can verify the full delivery history by replaying the commitment chain.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | [state-machine-enhancement.md](state-machine-enhancement.md) |
| Conditional arbiter activation (only in DISPUTED path) | Generic compiler: per-transition signer configuration |
| Settlement split determined at settle-time (not at creation) | Needs flexible settlement — arbiter passes amounts, script verifies they sum to total |
| milestoneThreshold | Enhancement spec (optional — client may accept after any number of milestones) |

---

## 2. Conditional Donation / Impact Funding

### Trust failure

Donors give money to causes with no verifiable proof that funds were used as promised. NGOs self-report impact metrics with no independent verification. Auditors are hired and paid by the NGO itself — a structural conflict of interest. The result: donor fatigue, misallocated aid, and scandals (e.g., Wounded Warrior Project spending 40% on overhead while reporting 80%+ program efficiency).

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Donor** | `donorPKH` (immutable) | Funds the pledge. Recovers funds on timeout. |
| **NGO** | `ngoPKH` (immutable) | Executes the project. Submits milestone evidence. |
| **Auditor** | `auditorPKH` (immutable) | Independent verifier. Co-signs milestones. Fee locked via `commissionBPS`. |

### State graph

```
                  Donor funds
PLEDGED ──────────────────────► FUNDED
                                  │
                     NGO submits  │
                     evidence,    │
                     Auditor      │
                     co-signs     │
                                  ▼
                             MILESTONE_1
                                  │
                     (repeat)     │  NGO + Auditor dual-sig
                                  │
                                  ▼
                             MILESTONE_N
                                  │
                     milestoneCount │
                     >= threshold   │
                                    ▼
                          IMPACT_VERIFIED
                                  │
                     NGO sig      │
                                  ▼
                              SETTLED
                          [3 outputs]
                     NGO: project funds (pro-rata)
                     Auditor: verification fee
                     Donor: any remainder

    ─── from FUNDED, MILESTONE_* ───
                               │
                  Timeout       │
                  Donor sig     │
                               ▼
                            EXPIRED
                     Donor recovers all funds
```

### Key design properties

**Pro-rata settlement:** The settlement amount scales with `milestoneCount / milestoneThreshold`. If the donor pledged 1,000,000 sats for 5 milestones and only 3 are verified before settlement, the NGO receives 600,000 sats. The script enforces: `ngoPayment <= (totalFunds * milestoneCount) / milestoneThreshold`.

**Donor does NOT sign milestones.** The donor trusts the auditor, not the NGO. This is the critical difference from the freelance escrow — the donor is a passive funder, not an active participant. Milestone verification is Auditor + NGO dual-sig.

**Auditor independence.** The auditor's PKH is locked at creation by the donor — the NGO cannot swap in a friendly auditor. The auditor's fee (`commissionBPS`) is also locked at creation, preventing fee inflation.

### Commitment chain usage

Each milestone hash includes evidence data: `SHA256(auditorSig || ngoSig || SHA256(evidencePayload))`. The evidence payload might be hashes of photos, GPS coordinates, enrollment lists, or financial records. The auditor's signature over this data is an on-chain attestation that they verified the evidence. They cannot later deny having verified it.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| Pro-rata settlement based on milestoneCount | Needs arithmetic: `(total * count) / threshold` in settlement script |
| Donor-passive milestones (NGO + Auditor sign, Donor does not) | Generic compiler: per-transition signer configuration |
| milestoneThreshold | Enhancement spec |

---

## 3. Music Royalty Split

### Trust failure

Music royalty accounting is notoriously opaque. Labels report sales figures that artists can't independently verify. Producers get credited inconsistently. Distributors take variable cuts. Settlement cycles are 30-90 days. Everyone is trusting everyone else's spreadsheet, and disputes take years to resolve (Taylor Swift re-recording her catalogue is a high-profile example of how broken the system is).

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Artist** | `artistPKH` (immutable) | Creates the work. Receives primary royalty share. |
| **Producer** | `producerPKH` (immutable) | Contributes to production. Receives production share. |
| **Distributor** | `distributorPKH` (immutable) | Sells/streams the work. Reports revenue. Receives distribution fee. |

### State graph

```
                     All 3 parties sign
CREATED ──────────────────────────────► TERMS_LOCKED
                                            │
                     Artist + Producer      │
                     dual-sig               │
                                            ▼
                                       RECORDING
                                            │
                     Artist + Producer      │
                     dual-sig               │
                                            ▼
                                        RELEASED
                                            │
                     Distributor stamps     │
                     revenue events         │
                                            ▼
                                     ┌► EARNING ◄┐
                                     │      │     │
                                     │      │     │ Distributor stamps
                                     │      │     │ (self-loop: revenue events)
                                     │      │     │
                                     │      ▼     │
                                     │  SETTLED ──┘
                                     │  [3 outputs]
                                     │  Artist: artistShare
                                     │  Producer: producerShare
                                     │  Distributor: distributorShare
                                     │
                                     └── (re-enter EARNING for next period)
```

### Key design properties

**Re-entrant settlement.** Unlike the customer funnel (where SETTLED is terminal), royalty tokens cycle: EARNING → SETTLED → EARNING → SETTLED → ... Each settlement distributes accumulated revenue for the period. The token persists across settlement cycles.

**Distributor as stamper.** Revenue events (each sale, stream, sync license placement) are stamped by the distributor with the revenue data hashed into the commitment chain. The artist and producer can independently audit the chain to verify reported revenue matches their own tracking.

**Immutable splits.** The royalty percentages are locked at TERMS_LOCKED. The artist's 60%, producer's 25%, and distributor's 15% (or whatever they negotiated) cannot be changed for the lifetime of the token. This prevents the label-era pattern of unilateral term changes.

**3-party signing at TERMS_LOCKED only.** After terms are locked, the distributor operates independently (stamps revenue), and settlement requires only one party to trigger (any of the three). Day-to-day operations don't require all parties to be online simultaneously.

### Commitment chain usage

Each revenue stamp: `SHA256(distributorSig || revenueData)` where `revenueData` contains stream counts, sale amounts, source identifiers, and timestamps. The rolling hash creates an auditable revenue history. At any point, the artist can request the full event log and verify it produces the current `commitmentHash`.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Re-entrant settlement (SETTLED → EARNING cycle)** | **Not yet specified.** Current SM treats SETTLED as terminal. Needs the periodic transitions variant (PP1_CSM from the generic compiler roadmap). |
| Per-transition signer configuration (3-party at TERMS_LOCKED, 1-party at SETTLE) | Generic compiler |
| Immutable commission splits (3-way) | Enhancement spec extends to 3-way; generic compiler parameterizes N-way |

---

## 4. Supply Chain Provenance

### Trust failure

Counterfeit goods, mislabeled origins, broken cold chains. Every party in the supply chain claims the product was handled correctly. When something goes wrong — contaminated food, counterfeit pharmaceuticals, failed aircraft parts — nobody can prove where the chain broke. Liability is determined by lawyers arguing over spreadsheets, not by verifiable evidence.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Manufacturer** | `mfrPKH` (immutable) | Produces goods. Creates the provenance token. |
| **Inspector** | `inspectorPKH` (immutable) | Independent QC. Signs quality gates. |
| **Shipper** | `shipperPKH` (immutable) | Transports goods. Commits to handling conditions. |
| **Buyer** | `buyerPKH` (immutable) | Receives goods. Accepts or rejects. |

### State graph

```
                  Manufacturer
MANUFACTURED ────────────────► QC_SUBMITTED
                                    │
                     Inspector      │
                     signs          │
                                    ▼
                               QC_PASSED
                                    │
                     Shipper        │
                     accepts        │
                     custody        │
                                    ▼
                              IN_TRANSIT
                                    │
                     Shipper stamps │  (self-loop: checkpoint stamps
                     checkpoints    │   with GPS, temp, handling data)
                                    │
                     Inspector      │
                     verifies docs  │
                                    ▼
                          CUSTOMS_CLEARED
                                    │
                     Shipper +      │
                     Buyer          │
                     dual-sig       │
                     (handoff)      │
                                    ▼
                              DELIVERED
                               │     │
              Buyer accepts    │     │  Buyer rejects
              (Buyer sig)      │     │  (Buyer sig)
                               ▼     ▼
                          ACCEPTED  REJECTED
                               │       │
                               │       │  [determine fault from
                               │       │   commitment chain:
                               │       │   last valid milestone
                               │       │   identifies responsible party]
                               ▼       ▼
                             SETTLED ◄──┘
                          [4 outputs]
                     Manufacturer: product payment
                     Shipper: freight payment
                     Inspector: inspection fee
                     Buyer: refund (if rejected)

    ─── from any non-terminal state ───
                               │
                  Timeout       │
                  Manufacturer  │
                               ▼
                            EXPIRED
```

### Key design properties

**4-party authority.** This is the first use case requiring more than 3 signers. Each transition has a different signer configuration — the inspector signs QC gates, the shipper signs transit events, the buyer signs acceptance. No single party controls the full chain.

**Checkpoint stamps during transit.** The IN_TRANSIT state supports self-loop transitions (like PROGRESSING in the funnel). Each checkpoint stamp includes IoT sensor data: GPS coordinates, temperature readings, humidity, shock indicators. The shipper commits to these conditions by signing them into the commitment chain.

**Fault attribution via commitment chain.** If the buyer rejects the goods, the dispute resolution path examines the commitment chain to identify where the failure occurred. If the last valid checkpoint shows correct conditions but QC was signed off on a defective batch, the manufacturer is liable. If checkpoint data shows a temperature breach during transit, the shipper is liable. The commitment chain is the evidence — no external investigation needed.

**Multi-party settlement.** SETTLED distributes to up to 4 parties. The split depends on the path taken (ACCEPTED vs REJECTED) and potentially on fault attribution.

### Commitment chain usage

Each stage appends: `SHA256(signerSig || stageData)` where stageData includes:
- QC_PASSED: inspection report hash, test results, batch numbers
- IN_TRANSIT checkpoints: GPS, temperature, timestamp, handler ID
- CUSTOMS_CLEARED: document hashes, clearance codes
- DELIVERED: receiving inspection notes, condition assessment

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| **4-party authority** | **Not yet specified.** Enhancement spec adds 3rd party. Generic compiler needed for 4+. |
| Per-transition signer configuration | Generic compiler |
| Self-loop with stamps (IN_TRANSIT checkpoints) | Already in funnel spec (PROGRESSING self-loop) |
| Conditional settlement (different splits for ACCEPTED vs REJECTED) | Generic compiler: per-terminal-state settlement topology |
| 4-way settlement outputs | Generic compiler: variable output count |

---

## 5. Prediction Market / Conditional Bet

### Trust failure

Prediction market platforms are custodial. They hold both sides' funds and determine outcomes. They can be shut down by regulators (Polymarket's US restrictions), manipulated by insiders, or go bankrupt with user funds (FTX collapse wiped out users of FTX-hosted prediction markets). The oracle problem — who attests to the real-world outcome — is compounded by the custody problem.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Party A** | `partyAPKH` (immutable) | Takes one side of the bet. Stakes funds. |
| **Party B** | `partyBPKH` (immutable) | Takes the other side. Stakes matching funds. |
| **Oracle** | `oraclePKH` (immutable) | Reports the real-world outcome. Fee locked via `commissionBPS`. |

### State graph

```
                  Party A proposes,
                  stakes funds
PROPOSED ──────────────────────────► FUNDED
                                       │
                     Party B matches   │
                     stake             │
                                       ▼
                                    ACTIVE
                                       │
                     Oracle signs      │
                     outcome           │
                                       ▼
                                   RESOLVED
                                       │
                     (automatic        │
                      from outcome)    │
                                       ▼
                                    SETTLED
                                 [3 outputs]
                            Winner: both stakes - oracle fee
                            Loser: nothing
                            Oracle: commissionBPS fee

    ─── from FUNDED, ACTIVE ───
                               │
                  Timeout       │  (event didn't occur by deadline)
                               ▼
                            EXPIRED
                     Both parties refunded equally
                     Oracle: nothing (didn't resolve)
```

### Key design properties

**Oracle identity is immutable.** The oracle is named at bet creation. They cannot be swapped after stakes are placed. If the oracle resolves dishonestly, their on-chain history (across all bets they've oracled) is permanently stained — the commitment chain proves what they attested to.

**Outcome-determined settlement.** The oracle's resolution includes the outcome in eventData (hashed into commitmentHash). The settlement script uses this to determine the winner. The oracle reports the outcome; the script determines the payout. The oracle cannot direct funds to a specific party — only attest to what happened.

**Equal refund on timeout.** If the oracle fails to resolve by the deadline (the event didn't happen, or the oracle disappeared), both parties are refunded equally. The oracle receives no fee. This incentivizes the oracle to resolve promptly.

**No platform custody.** Both stakes are locked in the UTXO from FUNDED onwards. No intermediary holds the funds at any point. The script is the custodian.

### Multi-oracle variant

For high-stakes bets, replace the single oracle with M-of-N oracles. The ACTIVE → RESOLVED transition requires threshold signatures: e.g., 3-of-5 independent oracles must agree on the outcome. This requires:

- N oracle PKHs in the header (immutable)
- Threshold parameter M (immutable)
- The resolution scriptSig supplies M signatures
- The script verifies each signature against the oracle PKH set and counts valid signatures

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| Outcome-determined settlement split | Generic compiler: conditional settlement logic based on eventData |
| **M-of-N threshold signatures** | **Not yet specified.** Needed for multi-oracle variant. |
| Equal refund on timeout (both parties, not just one) | Generic compiler: multi-output timeout topology |

---

## 6. Construction Contract

### Trust failure

Construction disputes are among the most expensive and common commercial conflicts. Owners withhold final payment claiming defects. Contractors walk away from half-finished projects after receiving progress payments. Change orders are disputed retroactively. Mechanics liens clog courts for years. The root cause: there is no neutral, tamper-proof record of what was built, what was inspected, and what was agreed.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Owner** | `ownerPKH` (immutable) | Funds the project. Accepts or disputes completion. |
| **Contractor** | `contractorPKH` (immutable) | Builds the project. Submits phase completion evidence. |
| **Inspector** | `inspectorPKH` (immutable) | Independent building inspector. Signs off on phase completion. Fee locked at creation. |

### State graph

```
                     Owner funds
CONTRACT_SIGNED ─────────────────► PHASE_1_ACTIVE
                                        │
                        Contractor      │
                        submits,        │
                        Inspector       │
                        co-signs        │
                                        ▼
                                  PHASE_1_INSPECTED ──────► PHASE_2_ACTIVE
                                        │                        │
                                        │  (deficiency)          │ ...repeat...
                                        ▼                        ▼
                                  DEFICIENCY_NOTED        PHASE_N_INSPECTED
                                        │                        │
                        All 3 sign      │           Inspector    │
                        remediation     │           signs        │
                        plan            │                        ▼
                                        │              FINAL_INSPECTION
                                        │                   │    │
                                        │      Owner accepts │    │ Owner disputes
                                        │                   ▼    ▼
                                        │              ACCEPTED  DISPUTED
                                        │                   │       │
                                        │                   │  Inspector
                                        │                   │  determines
                                        │                   ▼       ▼
                                        └──────────────► SETTLED ◄──┘
                                                      [3 outputs]
                                                 Owner: holdback/refund
                                                 Contractor: earned amount
                                                 Inspector: fee

    ─── from any non-terminal ───
                               │
                  Timeout       │
                  Owner sig     │
                               ▼
                            EXPIRED
                     Owner recovers remaining funds
                     Contractor keeps already-settled phases
```

### Key design properties

**Phase-based progress payments.** Each inspected phase can trigger a partial settlement. The contractor receives payment for completed phases, while remaining funds stay locked for future phases. This requires the re-entrant settlement capability (settle partial amount, continue to next phase).

**Inspector as the critical third party.** The inspector's signature on each phase is the trigger for progress payment. The owner can't withhold payment for a phase the inspector has verified. The contractor can't claim a phase is complete without the inspector's attestation.

**Deficiency handling.** If the inspector finds deficiencies, the token enters DEFICIENCY_NOTED. Returning to the normal path requires all three parties to sign the remediation plan — this prevents unilateral "deficiency" claims by the owner to delay payment, and prevents the contractor from ignoring legitimate deficiencies.

**Holdback enforcement.** A percentage of each progress payment can be held back (retained) until final inspection. The `commissionBPS` field repurposed as holdback percentage. The holdback is released at FINAL_INSPECTION → SETTLED.

### Commitment chain usage

Each phase inspection: `SHA256(inspectorSig || contractorSig || phaseData)` where phaseData includes inspection report hashes, photo documentation, material certifications, and code compliance references. The commitment chain becomes a complete, tamper-evident construction record — valuable for warranty claims, insurance, and future renovations.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Re-entrant partial settlement** | **Not yet specified.** Need to settle partial amounts while keeping token active for next phase. Related to periodic transitions (PP1_CSM). |
| Deficiency state requiring all-party remediation sign-off | Generic compiler: per-transition signer configuration |
| milestoneThreshold (minimum phases before final settlement) | Enhancement spec |
| Complex state graph (10+ states with branching) | Generic compiler |

---

## 7. Academic Credential Issuance

### Trust failure

Credential fraud is a multi-billion-dollar problem. Diploma mills issue fake degrees. Employers spend billions on background checks that still miss forgeries. When institutions lose accreditation, graduates are left with worthless credentials and no way to prove their education was legitimate at the time they received it. Credential verification is slow (weeks for transcript requests), fragmented (each institution has its own system), and brittle (if the institution closes, records may be lost).

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Student** | `studentPKH` (immutable) | Completes coursework. Holds the credential. |
| **Institution** | `institutionPKH` (immutable) | Delivers education. Stamps course completions. Issues the credential. |
| **Accreditor** | `accreditorPKH` (immutable) | Independent accreditation body. Co-signs the final credential, attesting that the institution was accredited during the student's enrollment. |

### State graph

```
                     Institution
                     enrolls student
ENROLLED ──────────────────────────► COURSEWORK
                                        │
                     Institution        │  (self-loop:
                     stamps courses     │   each course is a
                                        │   milestone stamp)
                                        │
                     milestoneCount     │
                     >= threshold       │
                                        ▼
                                REQUIREMENTS_MET
                                        │
                     Institution        │
                     signs              │
                                        ▼
                              CREDENTIAL_ISSUED
                                        │
                     Accreditor         │
                     co-signs           │
                                        ▼
                                    VERIFIED
                                   [terminal]
```

### Key design properties

**No funds, no settlement.** This is the first SM use case where the token settles **trust**, not **money**. There are no satoshi payouts at the terminal state. The VERIFIED state with its commitment chain IS the credential. The "value" is the cryptographic proof of the student's achievement, co-signed by the institution and the accreditor.

**Accreditor signature is temporally bound.** If the accreditor later revokes the institution's accreditation, existing VERIFIED credentials remain valid — the accreditor's signature is in the immutable commitment chain, proving the institution was accredited at the time of graduation. New enrollments would not receive the accreditor's signature. This solves the "retroactive invalidation" problem that plagues traditional accreditation.

**Course stamps are AT-style accumulation.** Each course completion is a milestone stamp from the institution: `SHA256(institutionSig || courseData)` where courseData includes course code, grade, credit hours, and semester. The `milestoneThreshold` = required credit hours for graduation.

**The credential is self-verifying.** Any employer or third party can verify the credential by:
1. Checking the token is in VERIFIED state
2. Verifying `accreditorPKH` matches a known accreditation body
3. Replaying the commitment chain to verify the course history
4. No need to contact the institution or the accreditor — the proof is on-chain

**No timeout.** Unlike financial use cases, there is no timeout/expiry. Education doesn't expire. The token persists permanently. (A variant could add timeout for programs with maximum completion deadlines.)

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **No-value terminal state (no settlement outputs)** | **Not yet specified.** Current SM assumes settlement distributes satoshis. Need a "finalize without payout" terminal path. |
| milestoneThreshold | Enhancement spec |
| Self-loop with stamps (course completions) | Already in funnel spec (PROGRESSING self-loop) |
| Permanent token (no timeout) | Set timeoutDelta to max value, or add a "no timeout" flag |

---

---

# Part II: Consumer — Entertainment & Gaming

The use cases above target B2B coordination problems. The use cases below target the **consumer** landscape — gaming, entertainment, and the creator economy — where the same multi-party SM properties (immutable terms, atomic settlement, commitment chains) solve trust failures that affect millions of end users.

---

## 8. Provably Fair Loot Box / Gacha

### Trust failure

Game publishers set loot box odds opaquely. EA's Star Wars Battlefront II scandal revealed drop rates as low as 0.06% for legendary items while marketing implied much higher chances. Belgium and the Netherlands banned loot boxes as gambling. China requires odds disclosure, but publishers comply with misleading fine print. Players spend billions on systems where the house sets and can silently change the odds mid-event.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Player** | `playerPKH` (immutable) | Purchases loot box. Triggers reveal. Receives item. |
| **Publisher** | `publisherPKH` (immutable) | Commits odds table. Reveals seed. Issues item. |
| **Odds Auditor** | `auditorPKH` (immutable) | Independent verifier. Attests that committed odds match advertised rates. Fee via `commissionBPS`. |

### State graph

```
                  Player pays
LISTED ──────────────────────► PURCHASED
                                   │
                  Publisher has     │
                  already committed │
                  odds + seed      │
                                   ▼
                            ODDS_COMMITTED
                                   │
                  Auditor co-signs │  (attests odds match
                  (Auditor sig)    │   advertised rates)
                                   ▼
                              CERTIFIED
                                   │
                  Player triggers  │
                  reveal           │
                  (Player sig)     │
                                   ▼
                               OPENED
                                   │
                  Publisher reveals │  seed (preimage of
                  (Publisher sig)   │  commitment). Item
                                   │  determined by:
                                   │  SHA256(seed || playerPKH || nonce)
                                   ▼
                           ITEM_REVEALED
                                   │
                  (automatic)      │
                                   ▼
                              SETTLED
                           [3 outputs]
                     Player: item token (NFT/RNFT)
                     Publisher: payment
                     Auditor: fee

    ─── from PURCHASED, CERTIFIED ───
                               │
                  Timeout       │  (Publisher fails to reveal)
                  Player sig   │
                               ▼
                            EXPIRED
                     Player refunded in full
```

### Key design properties

**Odds are committed before purchase.** The publisher creates the loot box token with `commitmentHash = SHA256(oddsTable || seed)`. The odds table and seed are locked before any player pays. The publisher cannot change them retroactively.

**Auditor attests to odds.** The Odds Auditor is an independent party (a gaming commission, an audit firm, or a DAO) whose PKH is immutable. They verify the odds table matches the advertised rates and co-sign. The publisher can't swap in a friendly auditor — the identity is locked at creation.

**Deterministic item selection.** The item is determined by `SHA256(seed || playerPKH || nonce)` — a function of the committed seed and the player's identity. This is deterministic and verifiable: once the seed is revealed, anyone can confirm the item was fairly selected.

**Timeout protects the player.** If the publisher refuses to reveal the seed (because the result would be a rare item they don't want to give away), the timeout returns the player's payment. The publisher can't stall indefinitely.

**Item issuance in settlement.** The settlement transaction mints a new token (PP1_NFT or PP1_RNFT) as one of its outputs, atomically delivering the item to the player. The player receives the item or gets a refund — never neither.

### Commitment chain usage

The full chain records: `SHA256(publisherSig || oddsTableHash)` at creation, `SHA256(auditorSig || certificationData)` at certification, `SHA256(playerSig || openRequest)` at opening, `SHA256(publisherSig || seed || itemId)` at reveal. Any regulator can replay this chain to verify exactly what odds were in effect, that they were independently certified, and that the item selection was deterministic.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Commit-reveal pattern** (odds + seed) | **New.** Publish commitment at creation, verify preimage at reveal. Script checks `SHA256(revealedSeed) == committedHash`. |
| **Token issuance in settlement** (NFT as output) | **New.** Settlement outputs include PP1_NFT/RNFT locking scripts, not just P2PKH. Cross-archetype atomic operation. |
| Timeout with full refund | Already supported |

---

## 9. Esports Tournament Escrow

### Trust failure

Esports tournament organizers regularly disappear with prize pools. In 2023 alone, multiple Dota 2 and CS2 tournament organizers failed to pay winners. Players travel internationally, compete for weeks, and have no guarantee the prize money exists or will be distributed fairly. Even legitimate organizations delay payments for months through "verification" and "processing." The fundamental problem: players compete on the organizer's promise, not on provable funds.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Organizer** | `organizerPKH` (immutable) | Creates tournament. Locks full prize pool. |
| **Player/Team** | `playerPKH` (committed at registration) | Competes. Receives prize on placement. |
| **Referee** | `refereePKH` (immutable) | Signs match results. Independent of organizer. |

### State graph

```
                  Organizer locks
                  full prize pool
ANNOUNCED ───────────────────────► FUNDED
                                      │
                  Players register    │
                  (entry fees added)  │
                                      ▼
                                 REGISTERED
                                      │
                  Referee stamps      │
                  match results       │
                                      ▼
                               ┌► BRACKET ◄┐
                               │     │      │
                               │     │      │ Referee stamps
                               │     │      │ each match result
                               └─────┘      │
                                     │
                  Final match        │
                  result stamped     │
                                     ▼
                                  FINALS
                                     │
                  Organizer or       │
                  Referee triggers   │
                                     ▼
                                  SETTLED
                              [4+ outputs]
                     1st place: prize share
                     2nd place: prize share
                     3rd place: prize share
                     Organizer: operational fee
                     Referee: officiating fee

    ─── from FUNDED, REGISTERED, BRACKET ───
                               │
                  Timeout       │  (tournament abandoned)
                               ▼
                            EXPIRED
                     Entry fees returned to players
                     Prize pool returned to organizer
```

### Key design properties

**Prize pool is provably locked.** The full prize pool is locked in the UTXO at FUNDED, before any player registers. Players can verify the funds exist on-chain. No more "prize pool TBD" or "prize pool subject to sponsorship."

**Match results are referee-signed.** Each match result is a milestone stamp: `SHA256(refereeSig || matchData)` where matchData includes player IDs, scores, map/game details, and timestamps. The commitment chain is a permanent, tamper-evident record of every match.

**Immutable prize distribution.** The settlement ratios (e.g., 1st: 50%, 2nd: 30%, 3rd: 15%, Ref: 5%) are committed at creation. The organizer can't reduce prizes after the event — the script enforces the split.

**Multi-output settlement.** Settlement distributes to 4+ parties (podium finishers + organizer + referee). This requires the generic compiler's variable output count.

**Timeout returns entry fees.** If the tournament is abandoned, timeout refunds entry fees to registered players. The prize pool (organizer's funds) returns to the organizer. Nobody's money is stuck.

### Commitment chain usage

The bracket history is fully committed: every match result, every score, signed by the referee. Post-tournament, anyone can replay the chain to verify the bracket was correctly resolved. Match-fixing becomes provably detectable — if a referee signs an implausible result, their attestation is permanently in the chain.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Multi-output settlement (4+ parties)** | Generic compiler: variable output count |
| **Multi-output timeout (refund to multiple registered players)** | Generic compiler |
| Self-loop with stamps (match results) | Already in funnel spec (PROGRESSING self-loop) |
| Dynamic party registration (players join after creation) | **New consideration.** Player PKHs aren't known at creation. Need a registration phase that commits player identities. |

---

## 10. Battle Pass / Season Pass Value Guarantee

### Trust failure

Players pay $10-20 for a battle pass with promised rewards at various tiers. The publisher controls what's in the pass, can change rewards mid-season, can make progression impossibly slow to push players toward paid tier skips, and can devalue items after the season ends. Players have no recourse — they already paid, and the publisher's terms of service allow unlimited changes.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Player** | `playerPKH` (immutable) | Purchases battle pass. Progresses through tiers. |
| **Publisher** | `publisherPKH` (immutable) | Commits reward table. Stamps tier progression. Issues rewards. |

### State graph

```
                  Player purchases
PURCHASED ──────────────────────► TIER_0
                                    │
                  Publisher stamps  │
                  progression      │
                  (XP, challenges) │
                                    ▼
                               ┌► TIER_N ◄┐
                               │     │     │
                               │     │     │ Publisher stamps
                               │     │     │ next tier reached
                               └─────┘     │
                                     │
                  milestoneCount     │
                  >= threshold       │
                  (all tiers)        │
                                     ▼
                                MAX_TIER
                                     │
                  (automatic)        │
                                     ▼
                                  SETTLED
                           [2 outputs]
                     Player: all reward tokens
                     Publisher: payment retained

    ─── Season end timeout ───
                               │
                  Pro-rata      │
                  settlement    │
                               ▼
                         SEASON_ENDED
                     Player: rewards earned up to current tier
                     Publisher: payment for delivered tiers
                     Unearned rewards: not issued
```

### Key design properties

**Reward table is committed and immutable.** At PURCHASED, the full reward table is hashed into `commitmentHash`: what item at each tier, the item's properties, the total number of tiers. The publisher cannot swap a legendary skin for a common item mid-season.

**Tier progression is publisher-stamped.** Each tier reached is a milestone stamp. The publisher signs the progression data (XP earned, challenges completed). This creates an auditable record — if players dispute the progression speed, the stamp frequency and XP data are in the commitment chain.

**Pro-rata settlement on season end.** If the season ends (timeout) before the player reaches max tier, settlement issues the rewards they've earned. `milestoneCount / milestoneThreshold` determines how many reward items are issued. The player isn't cheated out of tiers they've already reached.

**Reward items issued as tokens.** Each tier reward is a PP1_NFT or PP1_RNFT minted in the settlement transaction. The player receives actual on-chain items, not database entries that disappear when the game shuts down.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 2-party authority | PP1_SM v1 |
| milestoneThreshold | Enhancement spec |
| Pro-rata settlement based on milestoneCount | Generic compiler |
| **Token issuance in settlement** (multiple NFTs/RNFTs as outputs) | **New.** Multiple token minting outputs in a single settlement. |
| **Pro-rata timeout settlement** | **New.** Timeout distributes partial rewards, not just refunds. |

---

## 11. Player-vs-Player Wager with Anti-Cheat Oracle

### Trust failure

PvP wagering platforms (betting on your own gameplay) have no way to verify the match was played fairly. Aim-botters, lag-switchers, and account boosters corrupt results. The platform either ignores cheating (bad for honest players who lose their stake) or adjudicates disputes manually (slow, expensive, inconsistent, and vulnerable to social engineering). The platform itself may even be complicit — prioritizing high-volume players who cheat over honest players who complain.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Player A** | `playerAPKH` (immutable) | Takes the challenge. Stakes funds. |
| **Player B** | `playerBPKH` (immutable) | Accepts the challenge. Stakes matching funds. |
| **Anti-Cheat Oracle** | `oraclePKH` (immutable) | Analyzes match data. Attests to fair play or flags cheating. Fee via `commissionBPS`. |

### State graph

```
                  Player A stakes
CHALLENGED ─────────────────────► ACCEPTED
                                      │
                  Player B matches    │
                  stake               │
                                      ▼
                                   STAKED
                                      │
                  Match played        │
                  (off-chain)         │
                                      ▼
                             RESULT_SUBMITTED
                                   │     │
                  Oracle: clean    │     │  Oracle: suspicious
                  (Oracle sig)     │     │  (Oracle sig)
                                   ▼     ▼
                              VERIFIED  FLAGGED
                                   │       │
                  (automatic)      │       │  (automatic)
                                   ▼       ▼
                              SETTLED   VOIDED
                           [3 outputs]  [2 outputs]
                     Winner: both stakes  Player A: stake returned
                       minus oracle fee   Player B: stake returned
                     Loser: nothing       Oracle: no fee
                     Oracle: fee

    ─── from ACCEPTED, STAKED ───
                               │
                  Timeout       │  (match never played)
                               ▼
                            EXPIRED
                     Both players refunded equally
```

### Key design properties

**Oracle identity is immutable.** The anti-cheat oracle is named at wager creation. The platform can't swap in a different analysis system mid-match to favor a specific player or protect a high-value customer.

**VOID path protects honest players.** If the Oracle detects cheating (statistical anomalies, known cheat signatures, replay inconsistencies), the match is voided and both stakes are returned. The cheater doesn't profit from cheating — they just waste their time. The honest player doesn't lose their stake to a cheater.

**Oracle earns nothing on VOID.** The Oracle receives their fee only on VERIFIED (clean) matches. If they void the match, they get nothing. This incentivizes the Oracle to only flag genuine cheating — false positives cost them revenue.

**No platform custody.** Both stakes are locked in the UTXO from STAKED onwards. The platform never touches the funds. Settlement is script-enforced based on the Oracle's attestation.

### Commitment chain usage

The Oracle's analysis is signed into the commitment chain: `SHA256(oracleSig || matchAnalysisHash)` where matchAnalysisHash covers replay data, statistical metrics, anti-cheat telemetry hashes. If a player disputes the Oracle's verdict, the chain proves exactly what data the Oracle analyzed and what conclusion they reached.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **VOID/CANCEL terminal state** (mutual equal refund) | **New.** A terminal state where both parties are refunded equally. Neither wins, neither loses. Oracle receives nothing. |
| Outcome-determined settlement path | Generic compiler: conditional branching to different terminal states |
| Equal refund on timeout | Generic compiler: multi-output timeout topology |

---

## 12. Collaborative Content Revenue Share

### Trust failure

Content platforms (YouTube, TikTok, Twitch) control revenue distribution for collaborative content. When two creators collaborate, the platform decides how to split ad revenue — often attributing 100% to whoever uploaded the video. Co-creators, editors, thumbnail artists, and music producers who contributed to viral content receive nothing unless the uploader voluntarily shares revenue through the platform's (often limited) split features. The platform has no incentive to solve this — they want simple, fast payments, not fair multi-party attribution. This is the Honey scandal applied to content creation: the intermediary controls attribution and payout.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Primary Creator** | `primaryPKH` (immutable) | Creates and uploads content. Receives primary share. |
| **Collaborator** | `collabPKH` (immutable) | Contributes to content (editing, music, art, co-hosting). Receives collaboration share. |
| **Platform** | `platformPKH` (immutable) | Distributes content. Reports revenue. Receives platform fee. |

### State graph

```
                     Primary + Collaborator
                     propose terms
PROPOSED ──────────────────────────────────► TERMS_ACCEPTED
                                                  │
                     All 3 parties sign           │
                     (triple-sig)                 │
                                                  ▼
                                           CONTENT_LIVE
                                                  │
                     Platform stamps              │
                     revenue events               │
                                                  ▼
                                           ┌► EARNING ◄┐
                                           │      │     │
                                           │      │     │ Platform stamps
                                           │      │     │ (ad revenue, sponsorship,
                                           │      │     │  merch sales, sync licenses)
                                           │      │     │
                                           │      ▼     │
                                           │  SETTLED ──┘
                                           │  [3 outputs]
                                           │  Primary: primaryShare
                                           │  Collaborator: collabShare
                                           │  Platform: platformFee
                                           │
                                           └── (re-enter EARNING
                                                for next period)

    ─── from CONTENT_LIVE, EARNING ───
                               │
                  Timeout       │  (no revenue reported
                               │   within deadline)
                               ▼
                     INACTIVE (token persists,
                     can re-activate on new revenue)
```

### Key design properties

**Immutable revenue splits.** Primary 50%, Collaborator 35%, Platform 15% (or whatever they negotiate). Locked at TERMS_ACCEPTED via triple-sig. The platform can't quietly reduce the collaborator's share or "forget" to include them.

**Platform as stamper, not arbiter.** The platform reports revenue by stamping events into the commitment chain. Each stamp includes: revenue amount, source (ad network, sponsor, merch), time period, and content identifier. Creators can audit the chain against their own analytics to verify the platform's reports.

**Re-entrant periodic settlement.** EARNING → SETTLED → EARNING cycles. Each settlement distributes accumulated revenue for the period. The token persists across settlement cycles for the lifetime of the content.

**Anti-Honey property for creators.** This directly addresses the same trust failure as the Honey scandal but from the creator's perspective. Instead of an intermediary stealing attribution at the point of sale, the intermediary (platform) is forced to distribute revenue according to pre-committed terms. The platform can't quietly re-attribute a viral video's revenue to their own house account.

### Commitment chain usage

Each revenue stamp: `SHA256(platformSig || revenueData)` where revenueData includes: `{ amount, source, period, contentId, impressions, cpm }`. The rolling hash creates an auditable revenue history that creators can independently verify against platform analytics dashboards.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Re-entrant settlement** (periodic) | PP1_CSM periodic variant (roadmap) |
| Per-transition signer configuration (triple-sig at TERMS_ACCEPTED, single-sig stamps) | Generic compiler |
| commissionBPS (3-way split) | Enhancement spec |

---

## 13. Film/Show Crowdfunding with Milestone Delivery

### Trust failure

Entertainment crowdfunding has a catastrophic delivery rate. Kickstarter's own data shows ~35% of funded projects fail to deliver rewards. High-profile disasters — Star Citizen raising $600M+ with no release date, the Coolest Cooler delivering to only a fraction of backers, countless documentary campaigns that produced nothing — have eroded trust in the model. Backers have no recourse once the campaign closes. Their money is gone, and the creator's only obligation is moral, not contractual or technical.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Backer** | `backerPKH` (immutable) | Funds the project. Recovers funds on timeout. Receives access token on delivery. |
| **Production Team** | `productionPKH` (immutable) | Executes the project. Submits milestone evidence. Receives phased funding. |
| **Completion Bond** | `bondPKH` (immutable) | Independent guarantor (completion bond companies already exist in Hollywood). Verifies milestone delivery. Fee via `commissionBPS`. |

### State graph

```
                  Backer funds
CAMPAIGN ──────────────────────► FUNDED
                                    │
                  Production +      │
                  Bond co-sign      │
                  each phase        │
                                    ▼
                            PRE_PRODUCTION
                                    │
                  Bond verifies     │  → release 20% of budget
                  deliverables      │
                                    ▼
                              PRODUCTION
                                    │
                  Bond verifies     │  → release 50% of budget
                  principal         │
                  photography       │
                                    ▼
                           POST_PRODUCTION
                                    │
                  Bond verifies     │  → release 30% of budget
                  final cut         │
                                    ▼
                              DELIVERED
                                    │
                  (automatic)       │
                                    ▼
                               SETTLED
                            [3 outputs]
                     Backer: content access token (RNFT)
                     Production: final payment
                     Bond: completion fee

    ─── from any phase ───
                               │
                  Timeout       │
                  Backer sig   │
                               ▼
                            EXPIRED
                     Remaining (unreleased) funds
                     returned to backer.
                     Already-released phase payments
                     are NOT clawed back.
```

### Key design properties

**Phased fund release with independent verification.** The production team doesn't receive all funds upfront. Each phase requires the Completion Bond company to verify deliverables before funds are released. This is how Hollywood already works for studio films — the SM token brings the same discipline to crowdfunding.

**Backer receives a content access token.** At DELIVERED → SETTLED, the backer receives a PP1_RNFT (non-transferable, or transferable with restrictions) that serves as their access credential — a "ticket" to the finished film, show, or content. This is minted atomically in the settlement transaction.

**Timeout returns unreleased funds.** If production stalls (the team disappears, the project is abandoned), the timeout returns funds that haven't been released yet. Crucially, already-released phase payments are NOT clawed back — the Completion Bond verified those deliverables, so the production team legitimately earned that portion.

**Budget commitment is immutable.** The budget breakdown (20/50/30 or whatever split), the milestone definitions, and the Completion Bond's fee are all locked at creation. The production team can't come back mid-project asking for more money from the escrow (they can fundraise separately, but this token's terms are fixed).

### Commitment chain usage

Each phase verification: `SHA256(bondSig || productionSig || phaseData)` where phaseData includes deliverable hashes (rough cuts, casting announcements, location permits, final masters). The commitment chain becomes a verifiable production history — valuable for the backer's confidence, for the production team's portfolio, and for any disputes about what was delivered.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Re-entrant partial settlement** (phased fund release) | PP1_CSM periodic variant (roadmap) |
| **Token issuance in settlement** (RNFT access token) | **New.** Same as loot box — settlement mints a new token. |
| milestoneThreshold | Enhancement spec |
| Partial timeout (return unreleased funds only) | Generic compiler: settlement amount based on remaining balance |

---

## 14. Live Event Ticket with Anti-Scalping and Artist Royalty

### Trust failure

Ticketmaster and its parent company Live Nation operate a near-monopoly on live event ticketing. The Taylor Swift Eras Tour debacle revealed systematic problems: "dynamic pricing" raised tickets from $49 face value to $5,000+ through Ticketmaster's own "platinum" program. Scalper bots buy at face value and resell at massive markups. Artists receive none of the secondary market revenue. Fans are gouged, and the system that's supposed to serve them extracts maximum rent from their enthusiasm. A 2024 DOJ antitrust suit against Live Nation confirmed the structural problems.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Fan** | `fanPKH` (mutable — changes on resale) | Purchases ticket. Attends event. |
| **Organizer** | `organizerPKH` (immutable) | Creates event. Receives venue/operations share. |
| **Artist** | `artistPKH` (immutable) | Performs. Receives performance fee and resale royalties. |

### State graph

```
                  Organizer lists
LISTED ──────────────────────► PURCHASED
                                  │
                     Fan buys     │
                     at face      │
                     value        │
                                  ▼
                               HELD
                              │    │
             Fan attends      │    │  Fan resells
             (Venue sig)      │    │
                              │    │  [price cap enforced]
                              │    │  [artist royalty paid]
                              ▼    ▼
                         ADMITTED  RESOLD
                              │       │
                              │       │  New buyer pays
                              │       │  (same constraints apply)
                              │       ▼
                              │   RE_PURCHASED
                              │       │
                              │       │  (new fan holds ticket,
                              │       │   can attend or resell again)
                              │       ▼
                              │    HELD (new fan)
                              │       │
                              ▼       ▼
                           SETTLED ◄──┘  (on admission)
                        [3 outputs]
                   Artist: performance fee + resale royalties
                   Organizer: venue/operations share
                   Fan: attended event (ticket consumed)

    ─── from HELD ───
                               │
                  Timeout       │  (event date passed,
                  Organizer    │   fan didn't attend)
                               ▼
                            EXPIRED
                     Refund policy enforced
                     (full, partial, or none —
                      set at creation)
```

### Key design properties

**Price cap is script-enforced.** The maximum resale price is an immutable field set at creation. The script verifies: `resalePrice <= maxResalePrice`. No bot, no scalper, no platform can sell above this cap — the transaction literally won't validate. This is not a Terms of Service that scalpers ignore; it's a mathematical constraint.

**Artist royalty on every resale.** Each HELD → RESOLD transition pays the artist a percentage of the resale price. The royalty rate is immutable (set at creation via `commissionBPS`). This happens atomically in the resale transaction — the artist doesn't need to track secondary sales or trust a platform to report them.

**Resale is a state transition, not a separate market.** The ticket token's HELD → RESOLD → RE_PURCHASED flow is built into the state machine. There's no separate "secondary market" with different rules. Every transfer is subject to the same immutable constraints: price cap and artist royalty.

**Venue admission is a state transition.** The venue's entry system signs the HELD → ADMITTED transition. This proves attendance (useful for refund policies, fan engagement programs, and artist analytics). It also makes the ticket non-reusable — once ADMITTED, it can't be resold.

### Commitment chain usage

Each transaction (purchase, resale, admission) is recorded: `SHA256(signerSig || transactionData)`. The chain records the full ticket history: original purchase price, every resale price, the royalty paid to the artist on each resale, and the final admission. Artists get transparent analytics on their ticket economics.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority (Fan + Organizer + Artist) | Enhancement spec |
| **Price cap enforcement** (`maxAmount` field checked in transfer/resale script) | **New.** An immutable field that caps the value in a settlement or transfer output. |
| **Resale royalty on transfer** (percentage to a committed PKH on every ownership change) | **New.** Each transfer automatically pays a percentage to the artist. Similar to commissionBPS but applied on transfer, not just final settlement. |
| Re-entrant state (HELD → RESOLD → RE_PURCHASED → HELD cycle) | Generic compiler |
| Mutable ownerPKH (fan changes on resale) | Already in PP1_SM v1 (ownerPKH is mutable) |

---

## 15. Interactive Storytelling / Choose-Your-Adventure NFT

### Trust failure

Interactive media promises player agency — "your choices matter." But the publisher controls the narrative. Choices feel meaningful but outcomes are often predetermined or cosmetically different. When publishers monetize choices (pay-to-unlock story branches), there's no guarantee the "premium" branches are substantively different, that the promised endings actually exist, or that the publisher won't change the story post-launch. Players pay for the promise of agency in a system designed to extract revenue, not deliver meaningful narrative variation.

### Parties

| Role | Key | Responsibilities |
|------|-----|-----------------|
| **Player** | `playerPKH` (immutable) | Makes narrative choices. Holds the resulting story artifact. |
| **Story Creator** | `creatorPKH` (immutable) | Commits the narrative tree. Delivers chapter content. |
| **Narrative Oracle** | `oraclePKH` (immutable) | Generates or delivers chapter content based on choices. Can be a deterministic AI or a human author. Signs each chapter into the commitment chain. |

### State graph

```
                     Creator commits
                     narrative tree hash
PROLOGUE ──────────────────────────────► CHAPTER_1
                                            │
                     Player chooses         │
                     (Player sig +          │
                      choice identifier)    │
                                            ▼
                                    CHOICE_1A ─or─ CHOICE_1B
                                         │              │
                     Oracle delivers     │              │  Oracle delivers
                     chapter content     │              │  chapter content
                     (Oracle sig)        │              │  (Oracle sig)
                                         ▼              ▼
                                      CHAPTER_2A    CHAPTER_2B
                                         │              │
                                         │    ...       │    ...
                                         │  (branching  │  (branching
                                         │   continues) │   continues)
                                         ▼              ▼
                                     ENDING_X       ENDING_Y
                                    [terminal]      [terminal]
                                   Player holds    Player holds
                                   unique path     unique path
                                   NFT             NFT
```

### Key design properties

**Narrative tree is committed before play begins.** The full branching story — every possible path and ending — is hashed into the `commitmentHash` at creation. The story exists before any player starts. This is verifiable: the creator publishes the Merkle root of all story branches. After the experience, the player can verify their path was one of the pre-committed branches, not generated ad-hoc.

**Each choice is a state transition.** The player signs their choice, branching the state machine along the committed narrative tree. The choice identifier (which branch to take) is included in the commitment chain update. The player can't deny their choices; the creator can't deny offering those choices.

**Oracle delivers content deterministically.** The Narrative Oracle (which can be a deterministic LLM with a committed seed, or a human author) delivers each chapter, signing it into the commitment chain. If using an AI, the deterministic seed ensures the same choice always produces the same chapter — reproducible and verifiable.

**The path IS the artifact.** At the terminal state (ENDING_X), the player's token contains a unique commitment chain — their specific sequence of choices and the resulting narrative. This is a one-of-a-kind story artifact, provably one of the committed narrative paths. It's a collectible, a proof of experience, and a creative work all in one.

**No funds settle.** Like the academic credential, this is a non-financial SM. The value is the narrative artifact itself, not a payout. (A variant could include micro-payments per chapter for serialized content.)

### Commitment chain usage

Each chapter: `SHA256(oracleSig || chapterContent || choiceId)`. The full chain is the player's story — readable, verifiable, and permanent. Two players who made different choices have different commitment chains, provably diverging at the choice points.

### What this demands from the SM platform

| Capability | Status |
|-----------|--------|
| 3-party authority | Enhancement spec |
| **Branching state graph** (binary tree of narrative paths) | Generic compiler: arbitrary state graphs with branch transitions |
| No-value terminal (narrative artifact, no payout) | Gap identified in §7 (Academic Credential) |
| **Commit-reveal for narrative tree** (Merkle root of all branches) | Same pattern as loot box odds commitment |
| Complex state graph (potentially dozens of states for deep narratives) | Generic compiler |

---

## 16. Capability Requirements Matrix (Updated)

Summary of all use cases (Part I and Part II) mapped to platform capabilities.

### New capabilities identified in consumer use cases

| Capability | Source | Status |
|-----------|--------|--------|
| Commit-reveal pattern | Loot box (§8), Interactive storytelling (§15) | **New gap** |
| Token issuance in settlement (cross-archetype atomic) | Loot box (§8), Battle pass (§10), Film crowdfunding (§13) | **New gap** |
| VOID/CANCEL terminal state (mutual equal refund) | PvP wager (§11) | **New gap** |
| Price cap enforcement (maxAmount on transfer/settlement) | Live event ticket (§14) | **New gap** |
| Resale royalty on transfer | Live event ticket (§14) | **New gap** |
| Pro-rata timeout settlement | Battle pass (§10) | **New gap** |
| Dynamic party registration (PKHs committed after creation) | Esports tournament (§9) | **New gap** |
| Branching state graph (binary narrative tree) | Interactive storytelling (§15) | Generic compiler |

### Full use case × capability matrix

| Capability | Freelance | Donation | Music | Supply | Predict | Construct | Credential | Loot Box | Esports | Battle Pass | PvP Wager | Content Rev | Film Fund | Ticket | Story |
|-----------|-----------|----------|-------|--------|---------|-----------|------------|----------|---------|-------------|-----------|-------------|-----------|--------|-------|
| 3-party authority | **yes** | **yes** | **yes** | — | **yes** | **yes** | **yes** | **yes** | **yes** | — | **yes** | **yes** | **yes** | **yes** | **yes** |
| 4+ party authority | — | — | — | **yes** | — | — | — | — | — | — | — | — | — | — | — |
| Per-transition signers | **yes** | **yes** | **yes** | **yes** | — | **yes** | **yes** | **yes** | **yes** | — | **yes** | **yes** | **yes** | — | **yes** |
| milestoneThreshold | opt | **yes** | — | — | — | **yes** | **yes** | — | — | **yes** | — | — | **yes** | — | — |
| commissionBPS | **yes** | **yes** | **yes** | **yes** | **yes** | **yes** | — | **yes** | **yes** | — | **yes** | **yes** | **yes** | — | — |
| Re-entrant settlement | — | — | **yes** | — | — | **yes** | — | — | — | — | — | **yes** | **yes** | **yes** | — |
| No-value terminal | — | — | — | — | — | — | **yes** | — | — | — | — | — | — | — | **yes** |
| M-of-N threshold sigs | — | — | — | — | opt | — | — | — | — | — | — | — | — | — | — |
| Conditional settlement | — | — | — | **yes** | **yes** | **yes** | — | — | — | — | **yes** | — | — | — | — |
| Commit-reveal | — | — | — | — | — | — | — | **yes** | — | — | — | — | — | — | **yes** |
| Token issuance in settle | — | — | — | — | — | — | — | **yes** | — | **yes** | — | — | **yes** | — | — |
| VOID/CANCEL state | — | — | — | — | — | — | — | — | — | — | **yes** | — | — | — | — |
| Price cap enforcement | — | — | — | — | — | — | — | — | — | — | — | — | — | **yes** | — |
| Resale royalty on transfer | — | — | — | — | — | — | — | — | — | — | — | — | — | **yes** | — |
| Pro-rata timeout | — | — | — | — | — | — | — | — | — | **yes** | — | — | — | — | — |
| Dynamic party registration | — | — | — | — | — | — | — | — | **yes** | — | — | — | — | — | — |
| Branching state graph | — | — | — | — | — | — | — | — | — | — | — | — | — | — | **yes** |

### Updated priority ranking by gap closure impact

| Gap | Use cases unblocked | Priority |
|-----|--------------------|--------------------|
| **Per-transition signer configuration** | 12 of 15 | Highest |
| **Re-entrant settlement** | Music, Construction, Content Rev, Film Fund, Ticket | Highest |
| **Token issuance in settlement** (cross-archetype atomic) | Loot box, Battle pass, Film crowdfunding | **High — enables the entire consumer reward/item economy** |
| **Commit-reveal pattern** | Loot box, Interactive storytelling | High |
| **No-value terminal** | Credential, Interactive storytelling | Medium |
| **VOID/CANCEL state** | PvP wager | Medium |
| **Price cap + resale royalty** | Live event ticket | Medium — high consumer impact but single use case |
| **4+ party authority** | Supply chain | Medium |
| **Pro-rata timeout settlement** | Battle pass | Medium |
| **Dynamic party registration** | Esports tournament | Medium |
| **M-of-N threshold signatures** | Prediction market (multi-oracle) | Lower |
| **Branching state graph** | Interactive storytelling | Lower — generic compiler handles this naturally |

Summary of what each use case demands from the SM platform, mapped to implementation status.

### Capability availability

| Capability | Source | Status |
|-----------|--------|--------|
| 2-party authority | PP1_SM v1 | Implemented |
| 3-party authority | [state-machine-enhancement.md](state-machine-enhancement.md) | Specified |
| 4+ party authority | Generic compiler | Roadmap |
| Per-transition signer configuration | Generic compiler | Roadmap |
| milestoneThreshold | Enhancement spec | Specified |
| commissionBPS (script-enforced) | Enhancement spec | Specified |
| Commitment hash chain | PP1_SM v1 | Implemented |
| Timeout (nLockTime) | PP1_SM v1 | Implemented |
| Atomic settlement (2 outputs) | PP1_SM v1 | Implemented |
| Atomic settlement (3 outputs) | Enhancement spec | Specified |
| Atomic settlement (4+ outputs) | Generic compiler | Roadmap |
| Re-entrant settlement (non-terminal SETTLED) | PP1_CSM periodic variant | Roadmap |
| No-value terminal (credential, no payout) | Not yet specified | **Gap** |
| M-of-N threshold signatures | Not yet specified | **Gap** |
| Conditional settlement splits (based on outcome/milestoneCount) | Generic compiler | Roadmap |
| Pro-rata settlement arithmetic | Generic compiler | Roadmap |
| Multi-output timeout (refund to multiple parties) | Generic compiler | Roadmap |
| Complex state graphs (10+ states) | Generic compiler | Roadmap |

### Use case × capability matrix

| Capability | Freelance | Donation | Music | Supply Chain | Prediction | Construction | Credential |
|-----------|-----------|----------|-------|-------------|------------|-------------|------------|
| 3-party authority | **yes** | **yes** | **yes** | — | **yes** | **yes** | **yes** |
| 4+ party authority | — | — | — | **yes** | — | — | — |
| Per-transition signers | **yes** | **yes** | **yes** | **yes** | — | **yes** | **yes** |
| milestoneThreshold | optional | **yes** | — | — | — | **yes** | **yes** |
| commissionBPS | **yes** | **yes** | **yes** | **yes** | **yes** | **yes** | — |
| Re-entrant settlement | — | — | **yes** | — | — | **yes** | — |
| No-value terminal | — | — | — | — | — | — | **yes** |
| M-of-N threshold sigs | — | — | — | — | optional | — | — |
| Conditional settlement | — | — | — | **yes** | **yes** | **yes** | — |
| Pro-rata settlement | — | **yes** | — | — | — | — | — |
| Multi-output timeout | — | — | — | — | **yes** | — | — |

### Priority ranking by gap closure impact

| Gap | Use cases unblocked | Recommended priority |
|-----|--------------------|--------------------|
| **Per-transition signer configuration** (generic compiler) | All 7 | Highest — this is the enabler for every multi-party use case beyond the funnel |
| **Re-entrant settlement** | Music royalties, Construction | High — unlocks periodic payment models |
| **No-value terminal** | Academic credentials | Medium — small script change (skip settlement outputs when no funds locked) |
| **4+ party authority** | Supply chain | Medium — parameterize the number of authority keys in the header |
| **M-of-N threshold signatures** | Prediction market (multi-oracle) | Lower — niche variant; single-oracle works for v1 |
| **Conditional settlement splits** | Supply chain, Prediction, Construction | Medium — extends settlement script with branching on state/outcome |
| **Pro-rata settlement arithmetic** | Conditional donation | Medium — extends commission math to `(total * count) / threshold` |
| **Multi-output timeout** | Prediction market | Lower — specific to equal-refund scenarios |
