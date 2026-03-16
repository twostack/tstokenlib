# Customer Journey Funnel on Blockchain

## Executive Brief

### What is it?

A tamper-proof digital contract between a merchant and a customer that tracks the customer's journey from first engagement through to purchase — and automatically distributes rewards when the journey is complete.

No intermediary holds the funds. No party can cheat. The rules are set upfront and enforced by the blockchain itself.

### Why does it matter?

Today's customer journey tracking is broken:

- **Merchants** pay for referral and loyalty programs through platforms they don't control, with fees they can't negotiate and attribution they can't verify.
- **Customers** earn rewards through opaque systems where points can be devalued, terms changed, or programs cancelled without notice.
- **Referrers** (affiliates, influencers) have no guarantee they'll be paid for conversions they drove, and no way to independently verify the merchant's reported numbers.

Every party is trusting the other to play fair, with no enforcement mechanism beyond reputation and contract law.

### How does it work?

The funnel is a digital token on the Bitcoin SV blockchain that acts as a shared, self-enforcing agreement. It moves through a series of stages, and at each stage the rules determine who needs to approve the next step.

#### The Journey

```
┌─────────────┐     ┌─────────────┐     ┌───────────────┐
│  Created    │────►│  Customer   │────►│   Milestones  │
│ by Merchant │     │  Enrolled   │     │   Confirmed   │─────┐
└─────────────┘     └─────────────┘     └───────────────┘     │
                                              ▲    │          │
                                              │    │          │
                                              └────┘          │
                                           more milestones    │
                                                              ▼
                                        ┌─────────────┐   ┌───────────┐
                                        │   Rewards   │◄──│ Purchase  │
                                        │ Distributed │   │ Confirmed │
                                        └─────────────┘   └───────────┘
```

**Step 1 — Merchant creates the funnel.** The merchant defines the journey: what milestones matter, what the reward is, and when the offer expires. This is locked into the token at creation. It cannot be changed after the fact.

**Step 2 — Customer is enrolled.** The customer joins the funnel. From this point, both parties have skin in the game — the merchant has committed funds, and the customer has a verifiable path to rewards.

**Step 3 — Milestones are confirmed.** As the customer progresses (visits a page, attends an event, completes a trial, etc.), both the merchant and customer sign off on each milestone. Each confirmation is permanently recorded.

**Step 4 — Conversion happens.** When the customer makes a purchase or completes the desired action, both parties confirm the conversion.

**Step 5 — Rewards are distributed automatically.** The settlement transaction pays the customer their reward and the merchant their share in a single, atomic operation. Either both payments happen, or neither does. There is no scenario where the state says "settled" but the customer didn't get paid.

#### What if something goes wrong?

**Customer abandons the funnel:** The merchant doesn't lose their funds forever. Every funnel has an expiry date set at creation. After that date, the merchant can reclaim the locked funds. This is enforced by the blockchain's clock — no human intervention needed.

**Merchant tries to skip paying rewards:** Impossible. The settlement rules are baked into the token. The blockchain will not allow the funnel to reach "settled" status without the reward payment being included in the same transaction.

**Someone tries to forge a milestone:** Every milestone requires digital signatures from both the merchant and the customer. Neither party can fabricate the other's signature.

### What makes this different from existing solutions?

| | Traditional Platforms | This Protocol |
|---|---|---|
| **Who holds the funds?** | The platform | The blockchain (no custodian) |
| **Can terms change mid-journey?** | Yes (platform T&Cs) | No (locked at creation) |
| **Can rewards be withheld?** | Yes (platform discretion) | No (enforced by code) |
| **Is attribution verifiable?** | Trust the platform's dashboard | Independently verifiable on-chain |
| **What if the platform shuts down?** | Funds and data may be lost | Token persists on blockchain |
| **Settlement speed** | Days to weeks (invoicing, reconciliation) | Instant (single transaction) |
| **Dispute resolution** | Manual, costly, slow | Not needed — rules are self-enforcing |

### Real-World Applications

#### Affiliate Marketing
A merchant creates a funnel for each affiliate campaign. When a referred customer completes a purchase, the affiliate's commission is paid automatically. The affiliate can independently verify that conversions are being tracked honestly.

#### Customer Loyalty
A retailer enrols a customer in a loyalty journey. Milestones might be: first visit, second purchase, referral of a friend. When the milestone threshold is met, the reward unlocks. The customer can see exactly where they stand, and the retailer can't retroactively change the terms.

#### Event Engagement
A conference sponsor tracks attendee engagement across sessions, workshops, and booth visits. Each interaction is a signed milestone. Attendees who complete the journey earn a reward, verifiably and automatically.

#### Brand Partnerships
Two brands run a co-marketing campaign. The funnel tracks customer progression across both brands' touchpoints. Settlement splits the cost and reward according to terms locked at the start — no invoicing disputes, no reconciliation delays.

### Adding Referrers (Coming Soon)

The current protocol supports two parties (merchant and customer). A planned extension adds a third party — the referrer — who earns a commission when the customer they referred completes the funnel.

The referrer's identity is cryptographically linked to the funnel at enrolment. At settlement, the commission is paid alongside the customer's reward in the same atomic transaction. The referrer doesn't need to trust the merchant's reporting — the blockchain enforces the payout.

### How is it built?

The protocol is built on TSL1, a token standard for Bitcoin SV that uses a technique called *inductive proofs* to create tokens that carry their own rules and enforce them at every step. Each funnel token is a self-contained state machine — a program that can only move forward through its defined stages when the right conditions are met.

Key technical properties (for the technically curious):

- **Atomic settlement** — rewards and state changes happen in a single indivisible transaction
- **Immutable terms** — the reward structure, participants, and expiry are locked at creation
- **Auditable history** — every milestone is cryptographically hashed into a tamper-evident chain
- **No back-end required** — the token enforces the rules; no server, API, or database is needed for the core protocol
- **Timeout protection** — locked funds are always recoverable after the expiry date

### Summary

This protocol turns customer journey tracking from a trust-based process into a rules-based one. The merchant, customer, and (optionally) referrer each have cryptographic guarantees that the agreed terms will be honoured. Settlement is instant, attribution is verifiable, and no intermediary takes a cut for holding the process together.

The funnel is the agreement. The blockchain is the enforcer.
