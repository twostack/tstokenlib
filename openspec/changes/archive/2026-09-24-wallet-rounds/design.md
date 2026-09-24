## Context

The catch-up messages came with `sp-block-roots` (format version 2): block roots over a published range, the frontier, and the head proof. They have no id and no refusal form. `ShieldedLedger._apply` reads a round's statement, bundles, receipts and withdrawals, then places the leaves. That reading needs no ledger state, only the tip checks before it do.

## Goals / Non-Goals

**Goals:** everything the cloak asks R1 to R5 need from the library, on the wire and in code, with the coordinator's and a fake pool's answers coming from one set of rules.

**Non-Goals:**
- How a coordinator finds a witness's place in a block (its chain access does that).
- The wallet's own checking (libcloak's).
- Persisting who submitted what (a coordinator's concern).

## Decisions

### D1. Version 3, not new kinds under version 2
An id on requests changes the request encoding, and the reply must echo it. Adding it under version 2 would make one kind byte mean two layouts. `formatVersion` is one constant for every message, so every message moves to 3. Nothing is deployed on version 2, and both dependents (libcloak, pool-coordinator) compile against this library by path and read the constant. The cost is that a version 2 peer refuses every message, naming both versions, which libcloak already does.

### D2. The id is random per request and echoed
It lets a wallet route catch-up replies as it routes submission replies, and send several requests at once. It is drawn fresh for each request (`Random.secure`, 16 bytes), so it links nothing. The coordinator already knows the sender's peer id, and the id adds nothing to that. The "reply carries no asker" requirement is amended to allow exactly this.

### D3. A refusal is a reply, with four reasons
The reasons are:
- **notServed:** a kind the pool does not answer.
- **unpublishedRange:** the descriptor rule.
- **notYet:** nothing mined yet, or a round past the last mined one; ask after the next round.
- **unavailable:** the pool's chain access failed; ask later.

A wallet needs to tell "never" (the first two) from "later" (the last two), and nothing finer. The sentence is for a person, as on `PoolReply`.

### D4. Round by number is a catch-up kind; the notice is its own message
The round reply has exactly the head's body, so the two share one codec (`_Proven`).

The notice is a separate kind (7) so a wallet can tell an answer it asked for from one it did not. It names the recipient's submission ids so the wallet can match it to what it submitted. It carries no reply id, since nobody asked.

It carries no transactions, only the round's and witness's txids and the witness's place in its block. The first version carried both transactions, as a head does. That is about 2.6 MB at production (a 0.4 MB round and a 2.2 MB witness), sent to every submitter of every round: up to 256 of them, or about 650 MB a round through the transport. Slim, it is 141 bytes at test parameters and under 6 KB at its bounds. A wallet that needs the transactions asks for its round by number from the identity it submitted with, which tells the pool nothing new. (Changed after libcloak's review, which also moved the notice out of the replies folder; that is the coordinator's transport.)

Privacy: asking for a round by number tells the pool which round this peer cares about. That is harmless for the payer's own round, which the pool knows from the submission. It is a link, though, when the asker submitted under another identity or is a payee. So the notice is the primary path, and the round kind is recovery. The doc comment and the spec say so.

### D5. Leaves from the transactions, not on the wire
The cloak ask R3 offered two routes: send a round's leaves, frontier and nullifiers, or let the library read them from the round's transactions. The reading already exists inside `_apply`. It is factored into a static `_read` that both `apply` and the new `readLeaves` call, so they cannot drift. `readLeaves` then places the leaves in a fresh tree to compute the block root, since a round's block is aligned and its root does not depend on where it sits.

Sending leaves would add 16 KB a reply at production and exceed `maxCatchUp`'s 8 KB slack. It would also be one more thing to check. The frontier "as of round N" a payer needs is the frontier kind at N-1, or its own fold.

### D6. Answers are pinned to the last mined round
`CatchUpSource.minedTip` is the round up to which every round is mined. A head, a frontier and the end of a block-root run all stand at it. A pool that has published round N+1 but not seen it mined answers at N. So a head and a frontier asked back to back agree, unless a round is mined between the two. The wallet refuses that case and asks again.

### D7. One responder for every pool
`PoolCatchUpResponder` holds the rules. A coordinator implements `CatchUpSource` over its ledger, store and chain; `PoolTestChain.catchUpSource()` implements it over the fixture. The fixture has no blocks, so a placement function says where each witness sits. By default each witness is alone in its block: index 0, an empty branch, and the merkle root equal to its txid.

## Risks / Trade-offs

- **libcloak and cloak-cli break on the wire until rebuilt:** they compile unchanged, and their tests must run against version 3 fakes. Mitigation: the fixture now provides the responder.
- **A round mined between a head and a frontier request:** the wallet asks again. With an id, it can now ask both at once, and the pool answers in arrival order.
