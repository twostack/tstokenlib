# pool-aggregation Specification

## Purpose
How the coordinator folds a round's spend proofs into the one root proof the chain verifies: the tree of levels with their arities, trace sizes and parameter sets, the production plan and its budget, and how short rounds are filled.

## Requirements

### Requirement: Levels with their own shape
An aggregation SHALL be a list of levels, each with its arity, trace size and parameter set, followed by the wide root; the number of transfers is the product of the arities. Inner levels use the Poseidon2 flavour, the root the SHA256 flavour.

#### Scenario: Throughput plan
- **WHEN** the production plan is compiled
- **THEN** it is 16 x 4 x 2 x 2 = 256 transfers: level 1 on 2^20 at blowup 8, level 2 on 2^21 at blowup 8, then the narrowing levels 2^20 and 2^19 at blowup 16 with 23 queries, the root on 2^19 at blowup 32 with 18 queries (only the root is verified by a script, which is what prices queries)

### Requirement: Fit
Every level's program SHALL fit its trace (periods used at most periods available) and the root SHALL fit beside the wide publics; a dry run SHALL check the fit without computing the multi-gigabyte preprocessed commitments.

#### Scenario: Dry-run sizing
- **WHEN** the plan is compiled in dry-run mode
- **THEN** the periods used per level and by the root are reported and each is within its trace

### Requirement: Round budget
A 256-transfer round SHALL be provable on one 12-core machine in under 10 minutes, excluding the wallets' spend proofs.

#### Scenario: Measured round
- **WHEN** the plan is proved end to end at production parameters
- **THEN** the levels and root take about 220 s and peak under 16 GB, the root script is under 1,000,000 ops and the interpreter accepts it

### Requirement: Short rounds are padded
A round with fewer transfers than the plan SHALL be filled with padding transfers from the coordinator's supply, which MAY be proved ahead of time and never expire.

#### Scenario: Round of one
- **WHEN** one real transfer is submitted and the supply holds two padding transfers
- **THEN** the round closes with one on-the-spot padding proof and the state script accepts it

### Requirement: Verification of every node
The coordinator SHALL be able to verify every node's proof with the reference verifier before folding it further, so that a bad node (its own or one returned from elsewhere) is found at the level it occurs. Level-1 nodes MAY be proved by any prover in the coordinator's pool; the aggregation SHALL take them from a node prover and SHALL fold only proofs that verify against the digest it expects.

#### Scenario: Node check cost
- **WHEN** a level-1 node proof is verified
- **THEN** the check takes about 0.1 s

#### Scenario: Pooled level-1 proofs
- **WHEN** level-1 proofs come from pool members and all verify
- **THEN** the root proof and wide publics are the same as when the coordinator proved level 1 itself

### Requirement: A round's leaf count is a fixed power of two
A plan SHALL append a number of leaves per round that is a power of two, and that number SHALL NOT change for the life of a pool. Round N then owns exactly the aligned subtree at level log2(count), which is what lets a note's lower siblings freeze when its own round is mined and a party keep paths current from one block root a round.

Construction of a tree layout SHALL refuse a count that is not a power of two, naming the count, so a plan that would break the property fails where it is written rather than at the round where a wallet first notices. Production (16 subtrees, 512 leaves) and test (1 subtree, 32 leaves) satisfy it; a 300-transfer plan gives 19 subtrees and 608 leaves and does not.

#### Scenario: The plans in use
- **WHEN** the production throughput plan and the test plan are built
- **THEN** each reports a leaf count that is a power of two, 512 and 32

#### Scenario: A plan that would straddle
- **WHEN** a layout is built for 300 transfers a round
- **THEN** construction is refused, naming 608

#### Scenario: A round always appends its whole block
- **WHEN** a round with fewer real transfers than the plan allows is applied
- **THEN** it appends the plan's full leaf count, padded with empty leaves, so the block boundary does not move
