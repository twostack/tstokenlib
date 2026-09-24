## ADDED Requirements

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
