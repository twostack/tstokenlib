## MODIFIED Requirements

### Requirement: Verification of every node
The coordinator SHALL be able to verify every node's proof with the reference verifier before folding it further, so that a bad node (its own or one returned from elsewhere) is found at the level it occurs. Level-1 nodes MAY be proved by any prover in the coordinator's pool; the aggregation SHALL take them from a node prover and SHALL fold only proofs that verify against the digest it expects.

#### Scenario: Node check cost
- **WHEN** a level-1 node proof is verified
- **THEN** the check takes about 0.1 s

#### Scenario: Pooled level-1 proofs
- **WHEN** level-1 proofs come from pool members and all verify
- **THEN** the root proof and wide publics are the same as when the coordinator proved level 1 itself
