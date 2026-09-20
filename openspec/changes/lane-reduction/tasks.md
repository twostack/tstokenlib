## 1. Sizing

- [x] 1.1 Add the ring check to the level-1 program behind a flag and size it with a dry run (`PoolAggregation.throughput(dryRun: true)`); record periods per spend before and after in a new design-doc section "Lane reduction (sized)" and confirm 16 spends still fit 2^20 or adopt the 15-spend plan.

## 2. Recursion

- [x] 2.1 Change the level-1 program to take the ring as public input, pin each real spend's anchor to it, and include ring, anchors and commitments in its statement digest; verify with `test/verifier_air_test.dart` that a stale anchor has no witness and a valid one proves.
- [x] 2.2 Change the wide root to reduced lanes plus ring chunks and to derive level-1 digests from lanes, ring and witness commitments; verify with `test/recursion_tree_test.dart` that a substituted commitment or ring is rejected and a correct round proves.
- [x] 2.3 Update `AggregationTree.widePublics`, `subtreeLeavesOf` and `PoolAggregation.aggregate`; verify `test/pool_aggregation_test.dart` passes.

## 3. State script and reader

- [x] 3.1 Change the aggregated per-transfer section to 32 lanes, add the ring-equals-state check on the round chunks, and re-export templates; verify `test/template_sync_test.dart` and `test/pp1_sp_aggregated_test.dart` pass.
- [x] 3.2 Change the chain reader's aggregated path to take commitments from bundles and check rootAfter; verify `test/pool_chain_reader_test.dart` and the aggregated test's reader assertions pass.

## 4. Measurement

- [x] 4.1 Re-run `tool/scratch/root_script_size.dart` and `tool/scratch/state_script_size.dart` and record slot and state ops per transfer, the 256-transfer root script size and the new round capacity in the design doc; verify the pool-state-script spec's numbers match.
