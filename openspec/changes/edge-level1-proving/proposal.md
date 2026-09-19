## Why

Level 1 is 174 s of the 356 s round: sixteen 2^20 nodes at about 10.9 s each, every one of them independent of the others and of the coordinator's state. A desktop or server wallet can prove one (9 GB peak, about 10 s on 12 cores, 30 to 40 s on a laptop), which moves the bulk of the round off the coordinator and brings its share to about 3 minutes (levels 2 to 4 and the root). Now that the round is measured and padded, the coordinator's work has a shape that can be handed out.

## What Changes

- A level-1 node becomes a self-contained job: the sixteen spend proofs and publics of one node, the level program's identity, and the expected statement digest; a worker returns the node proof.
- A pluggable node prover interface: the local prover is one implementation, an edge scheduler (assign, await with a timeout, fall back to local proving) another; the aggregation accepts level-1 proofs from either.
- The coordinator verifies every returned node with the reference verifier against the digest it computes itself before folding it, so a wrong or malicious result is rejected at level 1 and proved locally instead.
- A canonical binary encoding of a Poseidon2-flavour proof, so jobs and results can cross a process or network boundary (transport itself is out of scope: an in-process worker and a serialised round trip are what this change delivers and tests).

## Capabilities

### New Capabilities
- `edge-proving`: level-1 node jobs handed to workers, verified results, timeout and local fallback, proof encoding.

### Modified Capabilities
- `pool-aggregation`: the aggregation accepts level-1 node proofs produced outside the coordinator and verifies them before folding.

## Impact

- `lib/src/recursion/pool_aggregator.dart`: `aggregate` takes level-1 proofs from a node prover rather than proving inline.
- New `lib/src/recursion/edge_proving.dart` (job, result, node prover interface, local prover, scheduler) and `lib/src/crypto/proof_codec.dart` (encoding of `StarkProof` in both flavours).
- `tool/scratch/round_throughput.dart` gains a mode that times the coordinator's share with level 1 done by a simulated worker.
- Numbers to move: coordinator round time from 356 s to about 180 s; the level-1 job payload (16 spend proofs at 64 KB plus publics, about 1 MB) and the result (327 KB) are the transport budget.
