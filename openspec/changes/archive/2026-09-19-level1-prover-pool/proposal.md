## Why

Level 1 is 170 s of the 342 s round: sixteen 2^20 nodes at about 10.5 s each, every one of them independent of the others and of the coordinator's ledger state. On one machine they run one after another; on machines the coordinator operates they can run side by side. The round already fits the ten-minute budget on one machine (5.9 minutes), so this is not about fitting the budget. It is about which part of a round grows with the transfer count: level 1 does, the five proofs above it do not. A pool of the coordinator's own provers makes level 1 the part that shortens by adding machines, and halves the coordinator's own share of a round to about 3 minutes.

## What Changes

- A level-1 node becomes a self-contained job: the sixteen spend proofs and publics of one node, the level program's identity, and the expected statement digest; a pool member returns the node proof.
- A pluggable node prover interface: the local prover is one implementation, a prover pool (assign to a member, await with a timeout, fall back to local proving) another; the aggregation accepts level-1 proofs from either.
- The pool verifies every returned node with the reference verifier against the digest the coordinator computes itself before folding it, so a wrong or broken result from any member is rejected at level 1 and proved locally instead. This is also what would let a machine the coordinator does not operate be admitted to the pool later without trusting it.
- A canonical binary encoding of a Poseidon2-flavour proof, so jobs and results can cross a process or network boundary (transport itself is out of scope: an in-process member and a serialised round trip are what this change delivers and tests).

Not in scope, and not the plan: asking users' wallets to fold nodes. A level-1 node is one proof over sixteen transfers and has no per-user share; folding it on a wallet would land a 9 GB, 10 to 40 s job on one user in sixteen and nothing on a phone user at all. The pool is the coordinator's machines first. Participants' servers are a possible later addition, on the same interface, in corporate deployments where they exist.

## Capabilities

### New Capabilities
- `prover-pool`: level-1 node jobs handed to pool members, verified results, timeout and local fallback, proof encoding.

### Modified Capabilities
- `pool-aggregation`: the aggregation accepts level-1 node proofs produced by any prover in the pool and verifies them before folding.

## Impact

- `lib/src/recursion/pool_aggregator.dart`: `aggregate` takes level-1 proofs from a node prover rather than proving inline, and is asynchronous.
- New `lib/src/recursion/prover_pool.dart` (job, node prover interface, local prover, pool) and `lib/src/crypto/proof_codec.dart` (encoding of `StarkProof` in both flavours).
- `tool/scratch/round_throughput.dart` gains a mode that times the coordinator's share with level 1 done by a simulated pool member.
- Numbers: the coordinator's share of a round from 342 s to 173 s measured; the level-1 job payload (16 spend proofs plus publics, 1,019,900 B) and the result (327,428 B) are the transport budget between the coordinator's machines.
