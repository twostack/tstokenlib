## Why

Each transfer costs 56 public lanes on chain: about 2,156 ops and 5.5 KB in the root verifier slot and 3,432 ops and 5.9 KB in the state script, which is what caps a round at about 290 transfers and puts the 256-transfer root script at 883,000 of 1,000,000 ops. The anchor (8 lanes) and the two commitments (16 lanes) are never read by the state script in aggregated mode: the anchor is checked against the ring and the commitments only reach the tree through the root proof. Moving both inside the proof takes a transfer to 32 lanes, about 1,100 ops less in the slot and a third off the state script per transfer, and gives the round headroom (about 400 transfers) or a smaller root script.

## What Changes

- **BREAKING** (aggregated mode only): the wide publics per transfer become 32 lanes (nullifiers 16, public amount 2, outHash 8, flags 2, asset 4); the anchor and commitments leave the on-chain statement.
- The level-1 node checks each spend's anchor against the round's ring in-circuit and carries the commitments as witness; the round chunks carry the ring (32 lanes once per round) so the root derives the level-1 digests from the ring and the reduced lanes.
- The root proves the tree update from commitments it receives as witness, bound by the level-1 digests.
- The aggregated state script reads 32 lanes per transfer; direct-slot mode keeps 56 lanes (separate solution, unchanged).

## Capabilities

### New Capabilities

(none)

### Modified Capabilities
- `verifier-recursion`: wide root publics and the level-1 statement change (ring in the round chunks, anchor and commitments inside the proof).
- `pool-state-script`: aggregated mode reads 32 lanes per transfer; the anchor check moves into the proof for aggregated rounds.
- `pool-coordinator`: the reader takes commitments from the round's leaves rather than the lanes.

## Impact

- `lib/src/recursion/verifier_program.dart` (level-1 program: ring membership, commitment witness; wide root: reduced chunks, ring chunks), `lib/src/recursion/pool_aggregator.dart`, `lib/src/script_gen/pp1_sp_script_gen.dart` (aggregated per-transfer section), `lib/src/transaction/pool_chain_reader.dart` (`_applyAggregated`), templates re-exported.
- Numbers to move: slot ops per transfer 2,156 to about 1,050; state ops per transfer 3,432 to about 2,300; the 256-transfer root script 883,000 ops to about 600,000; round capacity about 290 to about 400 transfers. Level-1 periods grow by the ring check (about 4 x 8-lane comparisons per spend), to be sized first.
