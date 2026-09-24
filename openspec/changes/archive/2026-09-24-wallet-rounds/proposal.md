## Why

The cloak wallet (../cloak-cli, libcloak) cannot join a running pool, prove a payment it made, or take on its change and deposits against a real coordinator. Its asks (2026-09-24, "Rounds for Wallets") come down to four gaps in this library's protocol. A catch-up request has no id, so a pool cannot refuse one: the wallet waits out a 30 s timeout per attempt and cannot tell "not served" from "lost". There is no way to fetch a mined round other than the head, but a payer needs its own round's transactions after later rounds have been mined. A wallet holds a fold, not a ledger, so it cannot read a round's leaves and nullifiers out of the round's transactions. And a submitter is never told that its round was mined.

## What Changes

- **BREAKING (wire):** protocol format version 3. Every catch-up request carries a 16-byte random id, and its reply echoes it. A version 2 message is refused. The Dart constructors stay source-compatible: the id is optional and random by default.
- A reply can be a **refusal** naming a reason (not served, unpublished range, not mined yet, unavailable) and a sentence, so a wallet never waits for an answer that will not come.
- A fourth catch-up kind, **round**: a mined round by number, carried as a head is (both transactions, the block hash, the index, the merkle branch).
- A seventh message, **mined-round notice** (`PoolRoundMined`): a pool sends it unasked to a peer whose accepted submissions a mined round took in. It names those submission ids, the round's and witness's txids, and the witness's block, index and branch. It carries no transactions (141 bytes at test parameters), and a wallet that needs them asks for the round by number.
- **`ShieldedLedger.readLeaves`**: a round's leaves, its transfers' positions within them, the nullifiers it spent and its block root, from its round transaction and witness alone. It is the same reading `apply` does, factored out, so the two cannot disagree. R3's leaves therefore need no new wire fields.
- **`ShieldedLedger.frontierAt(n)`**: the frontier as it stood at any applied round, so a pool can answer at its last *mined* round while it has published further.
- **`PoolCatchUpResponder`** and **`CatchUpSource`**: the rules for answering catch-up in one place (published ranges only, every answer pinned to the last mined round, refusals for everything else), so a coordinator and a wallet's fake pool answer alike.
- A test fixture: `PoolTestChain.descriptor()`, `.catchUpSource()` and `.responder()`, so a wallet's test pool answers exactly as a coordinator does.

Numbers this holds (measured by the tests in `test/pool_catch_up_test.dart`): a round reply at test parameters is 792 KB, the size of the existing head proof, since it carries the same two transactions. A notice is 141 bytes, and under 1 KB with a 20-deep branch. The added id costs 16 bytes a message. A production round's two transactions (about 2.5 MB of witness) stay well under the 10 MB transport frame and `PoolMessage.maxCatchUp`.

Non-functional contract:
- **Untrusted input:** every new field is bounded and named on refusal; there is a 10,000-message mutation fuzz.
- **Secrets and privacy:** the id is random per request and derived from nothing the wallet holds. The round kind's privacy cost is stated in the spec, and the notice is the private path.
- **Trust:** nothing new is trusted. A round reply and a notice are checked as a head is, and `readLeaves` output is checked against the announced block root and the proven `cmRoot`.
- **Determinism:** the same request gets the same answer bytes, apart from the echoed id.
- **Compatibility:** version 3 is a clean break, refused by version 2 readers and refusing them.
- **Performance:** `readLeaves` costs one read of the round, the same as `apply` without the tree copy.
- **Failure:** a source failure is an `unavailable` refusal, never a silence.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `pool-protocol`: catch-up request ids and refusals, the round kind, the mined-round notice, version 3.
- `pool-ledger`: a round's leaves from its transactions alone; the frontier at a past round.

The catch-up requirements live in the unarchived `sp-block-roots` change. This change amends one of them ("A catch-up request carries nothing about the asker": a reply now echoes the request's own random id), so `sp-block-roots` must be archived first.

## Impact

- `lib/src/shielded_pool/pool_protocol.dart` (version 3, `CatchUpKind.round`, `CatchUpRefusal`, ids, `PoolRoundMined`), the new `lib/src/shielded_pool/pool_catch_up.dart`, `shielded_ledger.dart` (`readLeaves`, `frontierAt`, `RoundLeaves`), `lib/src/testing/pool_test_chain.dart`, and the exports.
- **Dependents:**
  - pool-coordinator serves all of it (its own change, `wallet-catch-up`).
  - libcloak and cloak-cli compile unchanged, but must speak version 3 on the wire.
  - libcloak's version check compares against `PoolMessage.formatVersion`, so it follows automatically. Its fake pool can switch to `PoolTestChain.responder()`.
