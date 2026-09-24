# Integrating the TSL1_SP shielded pool

For the author of anything that reads, builds or serves a TSL1_SP pool: a wallet,
a coordinator, an explorer, an exchange.

tstokenlib gives you the pool: its scripts, its circuits, its ledger, its wire
messages. It will not stop you from building something that looks correct and is
not. This document is the set of rules where getting it wrong costs money,
privacy, or the soundness of somebody else's proof.

Background is `../ZK_SHIELDED_POOL_TSL1_DESIGN.md`. This is only the integration
surface and only the sharp parts.

---

## 1. Never read a PP1 by offset. This is the whole ballgame.

A PP1_SP script keeps its `tokenId`, verifier body hash, genesis header and pool
header at fixed offsets. Reading them by slicing the script is the natural thing
to do and it is **completely insecure**.

Anyone can write those bytes into an output. Bytes in an output are not a claim
about anything: nothing ran, nothing was enforced, nobody spent anything. A
reader that slices offsets accepts a forged round.

This was not theoretical. A lookalike PP1 carrying this pool's `tokenId` was
built and **mined on a regtest node for the price of two ordinary transactions**,
and an offset-parsing reader accepted it as a genuine round.

**The only supported way to read a PP1:**

```dart
final (fields, why) = PoolEvidence.readPP1Of(round, PoolEvidence.pp1Vout);
```

It reads the fields, **regenerates the whole script from them**, and compares
bytes. A script carrying the fields of a PP1_SP but not its body is refused at
the step `PP1 is this pool's script`:

> the output at 1 carries the fields of a PP1_SP but not its body, so nothing was
> enforced when it was spent

If you are slicing `PP1SpScriptGen.tokenIdDataStart` in your own code, you have
reintroduced the attack. Do not. Every reader in this repository goes through
`PoolEvidence`.

---

## 2. On a UTXO chain, only a spend is unforgeable

The rule behind rule 1, stated generally, because it decides more than PP1.

A pool's recursion is carried by **spends terminating at a once-spendable genesis
outpoint**, not by the contents of any output. A phase-1 state script written
straight into an output, with copied slot scripts beside it, will advance a round
in any design that checks output contents: all inputs accepted, no genesis, a
whole cloned pool chain.

So whenever you are about to believe something:

- **Ask what was spent**, not what is written. `tokenId` separates this pool from
  a well-formed pool of somebody else's *because* the create branch anchors it to
  an outpoint that can be spent once, and the induction copies it untouched.
- **A round is proven by its witness.** `PoolEvidence.provenRound` requires the
  witness to spend that round's PP1 at input 1 and PP2 at input 2. The hop is the
  evidence: a witness is what proves its round was accepted by the chain.
- **You must establish the witness is mined yourself, first.** `provenRound`'s
  doc says so plainly: *"The caller has already established that [witness] is
  mined in a block it accepts. Without that, every check here is about bytes a
  stranger chose."* Check the merkle branch against a header from your own
  validated chain. Do not take a block hash on anybody's word.

---

## 3. What `provenRound` does and does not establish

It establishes: a transaction carrying a real PP1_SP script, with this pool's
`tokenId`, verifier body hash and genesis header, was accepted by the chain one
hop back from a mined witness.

It does **not** establish:

- **The round's number.** A pool header carries none. If you need a number, take
  it from an announcement or your own count, and know that this check does not
  vouch for it. A wallet that trusts a claimed round number is trusting the
  claimant. Where a round number matters, derive it: `PoolHeader.size /
  leavesPerRound`.
- **That the round is the pool's latest.** It says the round happened.
- **Anything about PP2** beyond the witness spending it. PP1's body carries the
  induction; that is deliberate.

---

## 4. Refuse a transfer cheaply, before you verify anything

```dart
final why = transfer.refusal();   // hashing and parsing only
```

`ShieldedTransfer.refusal()` uses no key agreement, no proof verification and no
pool state, so a coordinator can refuse a malformed transfer **before** spending
a STARK verification on it. Call it at intake, first. A server that verifies
first has a cheap denial-of-service against it.

It checks, in order: that `outHash` commits to this bundle and this withdrawal;
that a withdrawal exists exactly when BSV leaves and for exactly that amount;
that a non-BSV asset moves nothing in or out; that the bundle names the proof's
commitments; and the deposit shape.

---

## 5. Commitments are free lanes, and this is the trap for readers

**A transfer's output commitments are not in V's statement.** The proof does not
bind them. Readers get them from the **witness bundles**.

The consequence: a transfer whose bundle names commitments other than the
proof's **passes verification** and breaks every reader that then places leaves
from the bundle. The ledger would append leaves nobody proved.

`ShieldedTransfer.refusal()` catches it:

> names commitments other than the proof's, so it does not match the proof

**If you are building a coordinator, you must run this check at intake.** The
proof will not do it for you. If you are building a reader, place leaves only
through `ShieldedLedger.apply` or `ShieldedLedger.readLeaves`, both of which go
through the same `_read` and so cannot disagree with each other.

An empty bundle is legal **only** for a padding transfer, and then both
commitments must equal the padding note's.

---

## 6. `readLeaves` needs no ledger, and still checks the hop

```dart
final got = ShieldedLedger.readLeaves(layout,
    ShieldedLedger.parse(reply.roundTx!), ShieldedLedger.parse(reply.witnessTx!));
```

A wallet holding a fold rather than a ledger can read a round's leaves,
positions, nullifiers and block root from the two transactions alone. It refuses
a witness that does not spend the round's PP1 and PP2.

**Nothing in the result is trusted.** Check `got.blockRoot` against the round's
announced block root, and your folded root against a `cmRoot` you proved off the
chain. The positions it returns are **offsets within the round's block**; a
leaf's tree position is `(round - 1) * leavesPerRound + offset`.

---

## 7. A deposit's dummy inputs are a privacy rule, not a formality

`ShieldedTransfer.depositRefusal()` requires a deposit transfer to spend **two
dummy notes**. A real note beside a deposit is refused:

> spends a real note beside a deposit, which the root proof refuses

The reason: **a deposit is public.** Its amount and its transparent source are on
the chain. A real input beside it would name the depositor as the owner of an
earlier note, joining the public side of the ledger to the shielded side for
everyone to see, forever.

If you are building a wallet, do not "save a transfer" by combining a deposit
with a spend. If you are building a coordinator, the root proof refuses it and
so should your intake.

Also required: the deposit must be in BSV, must bring money in
(`publicOut < 0`), and its outpoint must be 36 bytes.

---

## 8. A withdrawal's record must equal its public amount

A withdrawal is the only way money leaves, and two numbers must agree: the
`PoolWithdrawal` record's `satoshis` and the proof's `publicOut`. If they differ,
the pool pays an amount nobody proved.

`refusal()` checks it, but note the ordering trap: **that check tests `outHash`
first**, so a record swapped after the proof was made fails at `outHash` naming
neither amount. If you want a person to see both numbers, compare them yourself
before calling `refusal()`. libcloak's `WithdrawalBuilder` does exactly this, for
exactly this reason.

---

## 9. Every wire message is hostile input, and decoders never throw

`PoolMessage` and its seven kinds are read through a bounded reader that:

- refuses a frame over the kind's maximum **before reading a byte**;
- names the field that stopped it in a `ProtocolRefusal`;
- converts anything that escapes into a refusal, so a decoder cannot throw.

**Rules for your code:**

- Do not decode a frame you have not size-bounded. `PoolMessage.maxOther` is 4 KB;
  `maxCatchUp` is two 10 MB transactions plus 8 KB. A message decoded at the wrong
  bound is either a rejection of something legitimate or an allocation you did not
  intend. Note that `maxCatchUp` exceeds the 10 MB ricochet frame, so the transport
  is the binding limit in practice.
- **Refuse an unknown version, never guess.** Version 3 refuses version 2 because
  the request layout genuinely changed: the `what` byte moved from offset 2 to 18.
  Anything poking bytes at version 2 offsets is now reading the wrong field.
- **A refusal is an answer, and it carries none of an answer's fields.** A refused
  `PoolCatchUpReply` has no block root, no transactions, no roots. Check
  `isRefused` before touching any payload. Reading `reply.blockRoot!` on a refusal
  is a null-check crash, and `notYet` is the *correct* answer before a pool's
  first round is mined.
- Route a reply **by kind, then by id**. One inbox can hold `PoolReply` (2),
  `PoolCatchUpReply` (6) and `PoolRoundMined` (7).

---

## 10. What a catch-up request says about you

The protocol is shaped so a request reveals nothing, and you can undo that.

- **Block-root ranges must be one of the aligned runs the descriptor publishes**
  (`PoolDescriptor.requireRange`). Asking for "everything since round 4,117" says
  when you were last current, and over a few catch-ups that is a fingerprint.
- **`CatchUpKind.round` is different and the protocol says so.** Which round you
  ask for follows from what you did. It is harmless for a round you submitted into
  **from the same peer id you submitted from**, because the pool already knows;
  it is a link between identities if you ask from another, and a receipt of
  payment if you are the payee. Prefer the pushed `PoolRoundMined` notice and keep
  round-by-number for recovery.
- The request's `id` is random per request and derived from nothing you hold.
  Keep it that way: do not make it a counter, a hash of your state, or anything
  reusable.

---

## 11. Nullifiers, and the file nobody should write

A nullifier is `H(nk, rho)`. It is how a spend is recognised without revealing
which note was spent.

**Do not persist nullifiers you computed for your own notes.** A file of them is
a file that says which spends on a public chain were yours. Compute, compare,
discard. libcloak's `NoteStore.settle` takes `nk` as an argument and never as a
field precisely so the store cannot accumulate them.

A coordinator, of course, must hold the pool's nullifier set; that set is public
by construction.

---

## 12. The padding note is public, spendable, and worth nothing

`ShieldedTransfer.paddingNote` has zero value, the zero address and zero
randomness. Its commitment is a public constant so a reader knows a padding
transfer's leaves without a bundle. **Anyone can spend it, once, for nothing.**

Do not treat a padding leaf as a note. Do not be surprised when the same
commitment appears many times in a round; `readLeaves` and `apply` both resolve
duplicates by taking the next untaken match, in order, and they agree because
they share one implementation.

---

## 13. Things that look like waste and are load-bearing

Before you "optimise" one of these, read why it is there.

- **V's body appears in every witness.** This is by design: PP1 certifies Y by
  txid. Removing it breaks the certification. Do not propose removing it.
- **The pool header is one 236-byte push, not six fields**, and `genesisHeader`
  is carried in full rather than as a hash. Both have reasons that are easy to
  undo by accident.
- **PP3's forward covenant is enforced by two length checks.** Its security was
  verified by removing one and watching it break. They are not redundant.
- **A slot PP1 that will not certify freezes the balance permanently.** Build-time
  guards exist (`checkSlotIsCertifiable`); do not route around them.
- **Deposits are refused until their covenant is mined** (`depositCovenant`), and
  a coordinator skips a deposit whose refund opens too soon, because a refund
  mined before its round would invalidate the round.

---

## 14. Parameters and chain limits

- **Test and production parameters are not interchangeable.** A transfer is
  decoded at the parameters it was proved at. A pool's descriptor carries them.
- **ARC caps a scriptSig at 1,636,802 bytes.** A production-parameter witness is
  larger, so production witnesses do not go through ARC. Testnet runs at test
  parameters for this reason.
- Teranode's limits are 10 MB per transaction, 1,000,000 ops per script, 100 MB
  per script. The old 500 KB budget is obsolete; check
  `https://bsv-blockchain.github.io/teranode/` before relying on a recorded number.
- The ricochet frame is 10 MB, roughly 7.5 MB after base64. That, not
  `maxCatchUp`, is what a real message has to fit.

---

## 15. What tstokenlib does not check for you

A short list of things you must do yourself, because the library has no way to:

| you must | or else |
|---|---|
| establish a witness is mined, in a chain you validated | every check is about bytes a stranger chose |
| call `transfer.refusal()` at intake, before verifying | cheap denial of service, and unprovable leaves in your ledger |
| derive a round number rather than believe one | you trust the claimant |
| bound a frame before decoding it | unintended allocation, or a wrong rejection |
| check `isRefused` before reading a reply's payload | a null-check crash on a correct answer |
| keep catch-up ranges to the published runs | you fingerprint yourself |
| check a block root and a folded root against something you proved | you are trusting the pool, which is the one thing the design refuses to do |

---

## 16. Known gaps, so you do not assume otherwise

- **TSL1's base case does not anchor outside PP1_SP.** Issuance never binds
  `tokenId` to a spent outpoint, so the Rabin attestation is replayable and
  counterfeit tokens with the same `tokenId` were accepted. Fixed in PP1_SP (a
  create Phase 0); **still open in SM, NFT, FT, RFT, RNFT and AT**, which is a
  protocol decision rather than a bug to route around. If you are building on one
  of those archetypes, this is your problem to know about.
- Rabin, not ECDSA, is used for identity and oracle verification; see
  `../SIGNATURE_SCHEMES.md`.
