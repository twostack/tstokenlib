# Design

## The geometry this change exposes

The commitment tree is depth 32 and `NoteCommitmentTree.appendSubtree` appends
aligned blocks of 32 leaves. `ShieldedLedger` applies a round by running that
append `L.tree.subtrees` times unconditionally, padding with empty leaves, so a
round with four real transfers appends exactly as many leaves as one with 256.
Constant block size is therefore already structural: a short round cannot happen.

| | transfers | leaves | subtrees | block | level |
|---|---|---|---|---|---|
| production | 256 | 512 | 16 | 512 | 9 |
| test | 4 | 8 | 1 | 32 | 5 |

Round N owns the aligned node at that level, index N. A note's 32 siblings split
there: the lower ones are inside its own round's block and freeze when the round
is mined; the upper ones form a tree with one leaf per round.

So the wallet-side arithmetic needs exactly one new value a round, the block
root, and one new operation, the fold. Everything else already exists.

## What is not touched, and why

The spend circuit is a flat chain (`pool_spend_air.dart`):

```dart
for (int i = 0; i < depth; i++)
  ChainStep.chained(sn.siblings[i], swap: (sn.position >> i) & 1 == 1)
```

It consumes 32 siblings as witness and is indifferent to how the holder kept
them current. The round proof's `_treeUpdate` already walks whole aligned
subtrees at a known index from `rootBefore` to `rootAfter`. Neither changes.

Nor does the verifier script, the state script, the covenant, the pool header,
any transaction, the proof sizes or the 254 s production round. This change adds
a published value, an assertion, three descriptor fields, a tree operation and a
checker. It is wallet-facing arithmetic, not protocol.

## The invariant, and where it is enforced

The block size must be a power of two and must not change for a pool's life. If
it is not a power of two, round boundaries and block boundaries drift apart: at
608 leaves a round the blocks still sit at multiples of 512 and the rounds do
not, so a note's lower siblings stop being determined by its own round and the
holder needs a neighbouring round's commitments as well. If it changes mid-life,
nothing after the change is aligned and there is no repair short of a new pool.

Three places enforce it, because one is not enough:

1. **Where a plan is built.** `AggregationTree` throws on a leaf count that is
   not a power of two, naming it. This fails in a unit test, which is the only
   place it can be fixed cheaply.
2. **In the descriptor.** The count is part of what a pool tells a wallet, so a
   wallet can check that the pool it is talking to has the shape its stored state
   was built under.
3. **At the coordinator's open.** A coordinator restoring a snapshot whose tree
   was built under a different count must stop and say so, rather than appending
   misaligned rounds onto it. That check belongs to `pool-coordinator` and is a
   task here.

A plan change also replaces the verifier scripts and the root program, so it is
already most of the way to being a different pool; forbidding it costs nothing.

## Where the block root comes from

After `ShieldedLedger.apply` the value is `tree.nodeAt(blockLevel, N)`, with
`blockLevel = log2(plan leaves per round)`. `NoteCommitmentTree.nodeAt` is
already public; the ledger holds its tree privately and needs a small accessor.
Nobody has to recompute anything.

A party without the ledger computes the same value from the round's 512
commitments through `NoteCommitmentTree.subtreeRoot`, so the two paths agree and
a wallet that has a round does not need the announcement to have carried it.

## Why a folded root needs no attestation

A block root is not signed and does not need to be. Folding the sequence of
block roots up the upper levels must land on the `cmRoot` in the pool header of
the round folded, and that header comes from a round the holder proved against a
block header it accepts. A wrong root, or a round quietly skipped, fails that
check by collision resistance. So the 32 bytes can be taken from anyone,
including the coordinator, and the coordinator gains nothing by lying.

That is the whole reason this is a privacy win rather than a trade: the holder
never asks a question, and never has to believe an answer.

## The one-hop claim

`pool-evidence` states the payee's rules, and one of them rests on something
nobody has attacked: that a witness spending a round's PP1 and PP2, with the
pool's tokenId in that PP1, places the round in this pool. The spec says so in
its own requirement rather than burying it, and the task list attacks it on
localnet before anything is built on top.

If the attack succeeds, this change still stands, but `pool-evidence` grows: a
proven round would need a chain of rounds rather than one hop, and the cost in
payment-proof size would have to be measured before ../libcloak continues. The
attack is therefore first in the task list and its own gate.

## The cost of an anchor, and one idea that does not work yet

Everything a wallet believes about the pool reduces to one authenticated
`cmRoot`, and the only way to get one is a **head proof**: the tip round, its
witness, and the witness's merkle proof. Measured on the test chain, that is
141,651 B of round and 577,843 B of witness; at production parameters 395,698 B
and 2.2 to 2.5 MB. The witness is most of it, and the payee reads almost none of
it: a txid is the hash of the whole serialised transaction, so every byte of the
PP1 unlock has to be hashed to check the merkle proof, and the proof inside it is
never verified because the chain already did that.

It must be the **witness** and not the round, because spending PP1 is what runs
the induction. A mined round on its own never shows its PP1 was satisfied.

The obvious idea for making this four times cheaper is to anchor on a later round
instead: round N+1 spends round N's PP3, so a mined round N+1 shows N's PP3
covenant held, and a round is 395 KB against a witness's 2.5 MB. It does not work
as it stands, for a reason worth writing down so nobody re-derives it: **a pool
PP3 carries no tokenId.** `PartialWitnessLockBuilder.forPool` takes a 36-byte
next-slot outpoint and no owner, and the identity of the pool lives in PP1's
immutable region. So a PP3 chain shows continuity without showing whose
continuity it is, and identity still has to come from a PP1 that was spent.
Whether PP3's covenant constrains its successor's PP1 closely enough to carry
identity across is unanswered and would need reading the witness-check script,
not guessing. Left open.

What does make it cheap in practice is that most payees never need a head proof
twice: a **checkpoint** (the frontier, 736 bytes, verified against one proven
`cmRoot`) carries a wallet with no notes, and a wallet with notes folds 32 bytes
a round thereafter.

## Bounds, and what happens if a measurement misses

| bound | if it is missed |
|---|---|
| folding one root and updating one path under 1 ms | Batch the update: a holder with many notes in the same block shares most of the walk. The data cost is unaffected either way. |
| a proven round and a proven note together under 20 ms at test parameters | Report where the time went. Both are hashing, parsing and script reading, so a miss means a whole transaction is being parsed where one output should be read. |
| a production descriptor under 512 B | Accept and record. The genesis header is 236 bytes of it and is not compressible; the alternative is a lookup, which is the thing being removed. |

## Testing

Everything runs against `PoolChainFixture` at test parameters except the
thousand-block fold, which builds a tree directly, and the lineage attack, which
needs localnet. Exporting the fixture as `package:tstokenlib/testing.dart` is
part of this change because ../libcloak cannot write a single scenario against
the pool's chain without it; the export carries the fixture and the plans and
nothing a production wallet would reach for.
