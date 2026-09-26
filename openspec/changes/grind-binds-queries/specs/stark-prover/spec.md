## MODIFIED Requirements

### Requirement: Parameter sets
A parameter set SHALL fix logTrace, logBlowup, logExpand (the composition polynomial's degree bound, 8 x the trace), logFinal (the FRI final layer), the number of queries, the grind bytes and the zk randomizer count. Security SHALL be stated in two columns, as `docs/SECURITY_CLAIM.md` §4 does: conjectured, queries x logBlowup + grind bits, under the proximity-gaps-up-to-capacity conjecture; and proven, queries x logBlowup / 2 + grind bits, under the Johnson bound. Grind bits are 8 per grind byte in the SHA256 flavour and 7 in the Poseidon2 flavour, and count only because the query indices depend on the nonce (see "Transcript and hash flavours"). Every production set SHALL reach at least 100 bits in the conjectured column; the proven column is recorded, not required.

#### Scenario: On-chain spend parameters
- **WHEN** a spend proof is destined for a verifier slot on chain
- **THEN** it is proved at logTrace 12, blowup 32, 18 queries, 16 grind bits: 106 bits conjectured, 61 proven

#### Scenario: Inner aggregation parameters
- **WHEN** a proof will only be verified inside another proof
- **THEN** it is proved at blowup 8 with 30 queries (or blowup 256 with 11 for spends) and 14 grind bits, trading verifier work for prover throughput: 104 bits conjectured (102 for spends), 59 proven (58 for spends)

### Requirement: Transcript and hash flavours
The transcript SHALL be Fiat-Shamir over the statement (public values and the preprocessed root), the trace root, the aux root, the composition root, the out-of-domain values, the FRI roots and the final polynomial, in that order, then proof-of-work grinding on the nonce. The grind digest, H(state ‖ nonce) in the SHA256 flavour and the Poseidon2 compression of the state with the nonce lane in the other, SHALL become the transcript state when its low bits meet the target, and the query indices SHALL be squeezed from that state, so that no query index is known before the grind for its nonce is done. A nonce that misses the target SHALL be refused with the state unchanged. Two hash flavours SHALL exist with identical protocol: SHA256 (for proofs a Bitcoin script verifies) and Poseidon2 over M31, width 16 (for proofs a circuit verifies).

#### Scenario: Flavour is part of the statement
- **WHEN** a proof in one flavour is presented to a verifier of the other
- **THEN** verification fails

#### Scenario: Another valid nonce is another set of queries
- **WHEN** a valid proof's nonce is replaced by the next nonce that also meets the grind target
- **THEN** the reference verifier, the generated script and the verifier AIR all refuse it, because the query indices no longer match the openings
