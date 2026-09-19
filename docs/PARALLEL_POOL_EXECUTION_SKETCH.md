# Parallel Pool Execution — Speculative Sketch

Companion note to [ZEC_STYLE_SHIELDED_POOL.md](ZEC_STYLE_SHIELDED_POOL.md). Explores whether pool operations can execute in parallel on-chain without recursion and without splitting the anonymity set.

**Status: speculative and untested.** Nothing here has been checked against the TSL1 generator, against `dartsv`, or against node policy. The cost figures are arithmetic on the parent document's measured numbers, not measurements. Section [Open Questions](#open-questions-to-test-against-tsl1) lists what has to hold for any of it to work; the first item is load-bearing for the whole of Part B.

---

## Table of Contents

1. [Problem Restated](#problem-restated)
2. [The Reframe](#the-reframe)
3. [Part A: Parallel Shields](#part-a-parallel-shields)
4. [Part B: Verify-Then-Merge for Transfers](#part-b-verify-then-merge-for-transfers)
5. [Cost Accounting](#cost-accounting)
6. [Comparison Against the Alternatives](#comparison-against-the-alternatives)
7. [Open Questions to Test Against TSL1](#open-questions-to-test-against-tsl1)
8. [Relationship to v1 and v2](#relationship-to-v1-and-v2)

---

## Problem Restated

The pool is one UTXO. Every operation spends and re-creates it, so all users are strictly serialized: Alice, then Bob, then Carol, globally, across shields, transfers, unshields and roll-ups alike. Throughput is capped near one operation per second, roll-ups compete for the same slot, and a transaction that fails to propagate orphans every transaction chained behind it.

This is not a cost of privacy. Zcash and Monero keep the equivalent state in consensus, where appends and set insertions commute and nothing is contended. It is the cost of hosting mutable shared state in a UTXO on a chain with no consensus-level state.

The parent document rules out lane sharding on this property:

> A script can authenticate another UTXO only if that UTXO is its sibling from the same parent transaction.

## The Reframe

The stated blocker is not the principle but the size. The full argument is that authenticating a non-sibling requires hashing the transaction that created it, "here a transaction carrying a 400 KB locking script — which is infeasible in script."

Hashing a *small* transaction in script is ordinary BSV technique: supply the raw parent transaction in the unlocking script, double-SHA256 it, check the result against the outpoint being claimed, then parse the referenced output's `scriptPubKey` and satoshi value out of the bytes. The outpoint list itself is bound by reconstructing it and checking against `hashPrevouts` from the sighash preimage — the same OCS machinery already used for output binding.

So the question becomes: which pool operations can be made to flow through UTXOs whose *locking scripts* are small, even when the transactions carrying them are large?

Two answers follow. Part A needs no new cryptography and looks close to free. Part B is the speculative one.

---

## Part A: Parallel Shields

A shield does not read pool state. It adds value and a commitment. Nothing about it depends on the current roots.

**Mechanism.**

1. A depositor creates an **inbox UTXO** in their own transaction, funded with the deposit satoshis. Its locking script is a fixed few-hundred-byte covenant: spendable only by a transaction whose first output carries the pool's script hash and tokenId, plus an optional timelocked refund path back to the depositor. The note commitment is carried as pushdata in the inbox script.
2. The next roll-up (or any pool operation) sweeps any number of inboxes as additional inputs. For each, the unlocking script supplies the raw creating transaction; the pool script hashes it, matches the txid against the bound outpoint, reads back the locking script and satoshi value, and checks the script against a hardcoded inbox-script hash.
3. The pool adds each inbox's satoshis to the vault and each commitment to `pendingHash`.

**Why forgery is not a concern.** A fabricated inbox is one containing real satoshis under a covenant that only pays the pool. Creating one is donating money. The commitment's value binding is checked directly by the merge, which reads both the committed value and the actual satoshi value out of the parsed parent transaction — no proof required, which matches the parent document's note that shields need nothing beyond commitment well-formedness.

**What it buys.** Shields leave the serial path entirely and become unboundedly parallel. For a growing pool they are a large fraction of all operations. Depositors also stop racing for the pool UTXO, which removes the worst onboarding experience in v1: a new user's very first interaction currently being a contended write.

**What it costs.** One extra small transaction per deposit, and a shield's value is not in the vault until swept. The latter is already true — a shielded note is not spendable until rolled up.

---

## Part B: Verify-Then-Merge for Transfers

Verifying a spend proof does not touch pool state. It is a pure predicate over the proof and its public inputs. Only the *application* of the result — nullifier insertion, commitment append, vault adjustment — is stateful.

Split them.

### Flow

**Verifier UTXOs.** Pre-minted in bulk by anyone — a vending service, or users on each other's behalf. Locking script is the full STARK verifier plus a receipt-shaping covenant. Single-use. Each carries enough satoshis to pay the fee of the transaction that spends it.

**Verify transaction (one per user, fully parallel).** The user spends a verifier UTXO with their proof in the unlocking script. The script verifies the proof, then enforces that output 0 is a **receipt UTXO** whose locking script embeds the public inputs as pushdata: anchor, nullifier(s), new commitment(s), fee, and the public-outputs hash. No funding input from the user; the fee comes out of the verifier UTXO's satoshis. These transactions conflict with nothing and can be broadcast simultaneously by any number of users.

**Merge transaction (periodic, serialized).** Inputs are the pool UTXO plus K receipts. For each receipt the pool script:

1. Hashes the receipt's creating transaction (the verify transaction) to confirm the outpoint, and reads the receipt's locking script to recover the public inputs.
2. Hashes that transaction's *parent* to confirm the output it spent carried the genuine verifier script.
3. Checks the anchor against `anchors[N]`, checks and inserts the nullifier, appends the commitments.

Then it enforces the vault equation once over the whole batch and reimburses the verifier-UTXO vendor from the proven fees — the same mechanism as `rollupReserve`.

### Properties

- **The anonymity set stays whole.** One tree, one nullifier set, one vault. This is the only thing distinguishing the design from simply running more pools.
- **Double-spends inside a batch are caught for free.** The merge processes receipts serially within itself, so a second receipt bearing the same nullifier fails non-membership. A receipt whose nullifier was already spent in an earlier merge is dead and its dust is lost.
- **Fee linkage is preserved.** The user still contributes no transparent input.
- **The merge's own locking script is small** — hashing, parsing and comparison only. Verifier headroom is untouched.
- **Contention drops to one write per batch** instead of one per user, and the unconfirmed chain depth between blocks drops proportionally.

---

## Cost Accounting

Arithmetic on the parent document's measured figures (391 KB verifier, 98 KB proof), not measurements.

| Item | Size |
|---|---|
| Verifier UTXO creation transaction | ~391 KB |
| Verify transaction (proof in unlocking script) | ~100 KB |
| Parent + grandparent data in the merge, per receipt | ~490 KB |
| **Per transfer, total** | **~1.0 MB** |
| v1 equivalent (one pool transaction) | ~450 KB |

Roughly 2.5× the fee cost per transfer, in exchange for parallel verification. Whether that trade is worth taking depends entirely on whether serialization actually binds before recursion is available.

Batch size is bounded by the 10 MB transaction policy: at ~490 KB of witness data per receipt, K is somewhere around 16–18 before the merge transaction itself is too large. That caps the parallelism factor, though it is a far better cap than one.

If the grandparent hash can be eliminated (see open questions) the per-transfer figure falls to roughly 600 KB and K roughly doubles.

---

## Comparison Against the Alternatives

| | v1 single pool | Independent pools | Verify-then-merge | v2 recursive rollup |
|---|---|---|---|---|
| On-chain parallelism | None | Full, across pools | K per merge | None needed |
| Anonymity set | Whole | Divided per pool | Whole | Whole |
| Cost per transfer | ~450 KB | ~450 KB | ~1.0 MB | Amortized, small |
| New cryptography | None | None | None | STARK recursion |
| Contention | Per operation | Per pool | Per merge | Per epoch |
| User needs on-chain funds | No | No | No | No |

The case for Part B is narrow: it is the only option that buys on-chain parallelism without either dividing the anonymity set or building recursion. If recursion lands, v2 dominates it on every axis except that v2 has an aggregator and this does not.

---

## Open Questions to Test Against TSL1

Ordered by how much of the sketch dies if the answer is unfavourable.

1. **Can the pool script read a co-input's provenance more cheaply than by hashing two ancestor transactions?** The grandparent hash exists only to establish that the verify transaction spent a genuine verifier script. If verifier UTXOs are themselves an SM-archetype token, the receipt could inherit the tokenId by PP1 induction — but it is not clear whether the pool can *read* a co-input's tokenId, as opposed to a co-input reading its own. This is the single biggest cost lever and also the most likely place the design breaks.

2. **Does the alternative of receipt-enforced transitions have a forgery hole?** Letting each receipt script enforce the pool's state update, with the pool checking only the vault equation, removes all ancestor hashing. It appears unsound — an attacker-authored receipt enforces whatever it likes and the pool cannot distinguish it — but it is worth confirming that there is no way for the pool to constrain the *shape* of its co-inputs sufficiently.

3. **Do ~500 KB stack items survive policy?** The parent document cites a 100 MB stack-memory policy, which suggests yes, but per-element limits and the interaction with `maxscriptsizepolicy` on the unlocking script need checking, as does `OP_HASH256` behaviour at that size.

4. **Is `maxscriptsizepolicy` applied per script or to the concatenation?** This already matters for v1. It matters more here, since the merge's unlocking script carries megabytes.

5. **Does the sighash preimage's `scriptCode` carry the full locking script?** If so, every spend of the pool UTXO already carries ~391 KB of preimage, and the v1 baseline in the cost table is understated — which would make Part B's ratio look better, not worse.

6. **Does PP1 induction work for a single-use, non-stateful token?** Verifier UTXOs and receipts are both one-shot. The parent document already flags that the single-transaction archetype without PP2/PP3 is unverified.

7. **Who mints verifier UTXOs, and does grabbing one reintroduce a race?** In principle an abundant, cheap resource with thousands available; in practice a coordination problem with its own griefing surface. Unminted supply is a liveness dependency.

8. **Does the receipt leak anything the pool transaction did not?** Nullifiers and commitments become public one hop earlier and are attributable to whoever broadcast the verify transaction. This looks equivalent to the status quo, but the two-transaction structure gives an observer a new timing correlation to work with.

9. **Part A only: does the inbox covenant interact correctly with the FT archetype?** Shielding satoshis is phase 1 and inboxes hold satoshis, so probably moot — but the parent document's `recipientPKH` problem for fungible tokens may recur here.

---

## Relationship to v1 and v2

Part A is independent of everything and should be evaluated on its own. It removes a whole operation class from the serial path with no new trust, no new cryptography and no change to the spend circuit. It is worth doing under v1 regardless of what happens to Part B.

Part B is a v1.5: it changes the roll-up path and the shape of a spend transaction, but the spend circuit and its public inputs — anchor, nullifiers, commitments, fee, public-outputs hash — are unchanged. That is the same interface the parent document identifies as the thing to hold fixed so that v2 is a change to the roll-up path only. Part B is therefore not a detour away from v2; it occupies the same seam.

The honest ordering: do Part A now, prototype Part B only if serialization is observed to bind in practice, and expect v2 to obsolete Part B if recursion arrives first.
