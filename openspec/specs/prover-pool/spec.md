# prover-pool Specification

## Purpose
Lets the coordinator spread level-1 aggregation nodes over a pool of provers it operates, with every returned node verified before it is used and a local fallback when a member is late or wrong. The verification is what would let a machine the coordinator does not operate join the pool without being trusted.

## Requirements

### Requirement: Node job
A level-1 node job SHALL contain exactly the inputs the node's witness needs: the spend proofs and public inputs of its transfers in order, the identity of the level program (its parameters, including trace size, and its preprocessed root) and the spend parameter set, and the statement digest the node is expected to prove. A job SHALL be encodable to bytes and decodable to an identical job.

#### Scenario: Round trip
- **WHEN** a job is encoded and decoded
- **THEN** the decoded job's proofs, publics and digest equal the original's

### Requirement: Proof encoding
A proof in either hash flavour SHALL have a canonical byte encoding that decodes to a proof the reference verifier accepts, and decoding SHALL reject a truncated or oversized encoding.

#### Scenario: Truncated proof
- **WHEN** an encoded proof is cut short
- **THEN** decoding fails with an error rather than producing a partial proof

### Requirement: Returned nodes are verified
Before a level-1 proof from a pool member is folded, the coordinator SHALL verify it with the reference verifier against the level program and the digest it computed itself; a proof that fails SHALL be discarded and the node proved locally.

#### Scenario: Faulty member
- **WHEN** a member returns a valid proof of a different node, or an invalid proof
- **THEN** the round completes with the coordinator's own proof of that node and the member's result is not used

### Requirement: Timeout and fallback
The pool SHALL wait for each assigned node up to a configured timeout and then prove it locally; a late result arriving after the fallback started SHALL be ignored. A round SHALL complete with an empty pool.

#### Scenario: Empty pool
- **WHEN** no member is registered
- **THEN** every node is proved locally and the round's proofs are identical to the inline aggregation's

#### Scenario: One member stalls
- **WHEN** one of sixteen assigned nodes has not returned by the timeout
- **THEN** that node is proved locally and the round completes

### Requirement: Job exposure
A job SHALL expose to a member nothing beyond the spend proofs and public inputs of its node, which are zero-knowledge proofs and data the chain publishes; in particular no ledger state or other rounds' data.

#### Scenario: Job contents
- **WHEN** a job is inspected
- **THEN** it holds only proofs, publics, program identity, parameters and the digest
