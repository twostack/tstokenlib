## Why

A wallet that holds a note has to keep its Merkle path current, because the pool
appends leaves every round and the old path stops reaching the new root. Today
the only way to do that is to take every commitment of every round: 16,384 bytes
a round at production parameters. That is a server's job, not a phone's, and the
alternative, asking someone for a fresh path, tells them which leaf is yours and
hands them the wallet's whole history a few rounds later.

There is a third way, and the tree already has the shape for it. A round appends
a fixed power-of-two block of leaves, so round N owns exactly the aligned subtree
at level log2(block): 512 leaves and level 9 at production, 32 and level 5 at
test. A note's siblings below that level are frozen when its own round is mined.
The ones above it are a tree with one leaf per round, and a wallet keeps them
current by folding one 32-byte block root a round. Same privacy as following
everything, 512 times less data, and nothing on chain changes.

This change publishes that block root, makes the invariant it rests on an
assertion instead of an accident, puts in the descriptor the things a wallet
cannot look up, and moves the rules a payee applies into the library that owns
the pool. ../libcloak is blocked on all of it.

## What Changes

- **The per-round block root** is exposed on `ShieldedLedger` and carried in
  `PoolAnnouncement`. It is the tree node at level log2(block), index N, already
  computed while the round is applied.
- **The power-of-two invariant is asserted** where an `AggregationTree` is built.
  A round's leaf count must be a power of two, and a pool's must never change,
  or the block boundaries and the round boundaries drift apart and a note's
  lower siblings stop being determined by its own round. Production (16 subtrees,
  512 leaves) and test (1 subtree, 32 leaves) both pass; a 300-transfer plan
  would give 19 subtrees and 608 leaves and would not. **BREAKING** for any plan
  that does not satisfy it, which is none that exists.
- **The descriptor carries** the leaves a round appends, the pool's tokenId and
  its genesis header. It carries three txids today, which are useless to a wallet
  that will not look anything up.
- **Path maintenance** on `NoteCommitmentTree`: fold a block root into an upper
  frontier, and update a note's siblings from it.
- **Proven-round and proven-note checks**: the rules by which mined bytes place a
  round in a pool and a note in a round, in the library that owns the pool rather
  than restated in every wallet.
- **`PoolChainFixture` exported** as `package:tstokenlib/testing.dart`, so other
  packages can write scenarios against the pool's own chain.

### Numbers this change is meant to move, and their bounds

| | before | after | requirement in |
|---|---|---|---|
| bytes a wallet must take per round to stay spendable (production) | 16,384 | **32** | `pool-ledger` |
| bytes a wallet must take per round (test) | 1,024 | **32** | `pool-ledger` |
| folding one block root and updating one note's path | — | under **1 ms** | `pool-ledger` |
| checking a proven round from mined bytes | — | under **20 ms** at test parameters | `pool-evidence` |
| descriptor size | 115 B | under **512 B** | `pool-protocol` |

Nothing that is already measured moves. The spend circuit is a flat 32-step
Merkle chain that takes siblings as witness, and the round proof already appends
aligned subtrees at a known index, so neither is touched: no change to proof
size, to the 254 s production round, to the verifier script, the covenant, the
header or any transaction.

## Capabilities

### New Capabilities

- `pool-evidence`: what mined bytes have to show before a round counts as this
  pool's and a note counts as being in it. The rules a payee applies, stated once
  where the pool is defined.

### Modified Capabilities

- `pool-ledger`: "Merkle paths for spending" gains the block root, the invariant
  it rests on, and path maintenance by folding.
- `pool-protocol`: "Message kinds" gains the descriptor's block size, tokenId and
  genesis header, and the announcement's block root.
- `pool-aggregation`: a new requirement that a plan's leaf count is a power of
  two and fixed for a pool's life.

## Impact

**Code:** `lib/src/crypto/note_commitment_tree.dart` (fold and update),
`lib/src/recursion/verifier_program.dart` (the assertion on `AggregationTree`),
`lib/src/shielded_pool/shielded_ledger.dart` (the block root),
`lib/src/shielded_pool/pool_protocol.dart` (descriptor and announcement fields,
format version 2), a new `lib/src/shielded_pool/pool_evidence.dart`, and a new
`lib/testing.dart`.

**Wire compatibility:** the descriptor and the announcement change, so the
protocol's format version goes to 2 and a version 1 message is refused as the
spec already requires. No pool is deployed, so nothing needs migrating.

**Downstream:** ../libcloak's `libcloak-core` is blocked on this change.
../pool-coordinator must publish the block root once it is on the announcement,
which is part of that repo's own rewrite.

**Not affected:** the spend circuit, the round proof, the verifier script, the
state script, the covenant, the pool header and every transaction the pool
builds.
