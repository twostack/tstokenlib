# stark-prover Specification

## Purpose
The Circle-STARK proof system the shielded pool runs on: how a trace over the Mersenne-31 field is committed, constrained, opened and folded so that a Bitcoin script, a recursive verifier circuit or a Dart verifier can check it. This is the protocol both provers (the FFT prover and the reference prover) and every verifier implement.

## Requirements

### Requirement: Field and domains
Proofs SHALL be over the Mersenne-31 field (p = 2^31 - 1) with the degree-4 extension QM31 for challenges and quotients. A trace of 2^t rows SHALL be interpolated on the circle group's coset of size 2^t in twin layout (position i holds a point of the half coset, position M + i its conjugate) and committed on the half coset of size 2^(t + b), b the log blowup. The field bounds the size: t + 3 + b SHALL be at most 30.

#### Scenario: Domain exceeds the circle group
- **WHEN** a parameter set has logTrace + 3 + logBlowup greater than 30
- **THEN** the prover refuses the parameters

### Requirement: Parameter sets
A parameter set SHALL fix logTrace, logBlowup, logExpand (the composition polynomial's degree bound, 8 x the trace), logFinal (the FRI final layer), the number of queries, the grind bytes and the zk randomizer count. Security SHALL be counted as queries x logBlowup + 8 x grindBytes bits, and every production set SHALL reach at least 100 bits.

#### Scenario: On-chain spend parameters
- **WHEN** a spend proof is destined for a verifier slot on chain
- **THEN** it is proved at logTrace 12, blowup 32, 18 queries, 16 grind bits

#### Scenario: Inner aggregation parameters
- **WHEN** a proof will only be verified inside another proof
- **THEN** it is proved at blowup 8 with 30 queries (or blowup 256 with 11 for spends), trading verifier work for prover throughput at the same security

### Requirement: Zero-knowledge masking
When a parameter set enables zk, every trace and aux column SHALL be masked by adding a random polynomial of the configured degree times the vanishing polynomial of the trace domain, so that the openings a verifier sees reveal nothing about the witness. The number of randomizers SHALL cover every position a verifier can open (queries x openings per column).

#### Scenario: Spend proofs are hiding
- **WHEN** a wallet proves a spend at production parameters
- **THEN** 128 randomizers per column mask the 2 x 18 openings

#### Scenario: Verifier proofs are not masked
- **WHEN** a verifier (recursion) proof is made
- **THEN** no masking is applied, because its witness is public data (proofs and their publics)

### Requirement: Transcript and hash flavours
The transcript SHALL be Fiat-Shamir over the statement (public values and the preprocessed root), the trace root, the aux root, the composition root, the out-of-domain values, the FRI roots and the final polynomial, in that order, with proof-of-work grinding on the nonce. Two hash flavours SHALL exist with identical protocol: SHA256 (for proofs a Bitcoin script verifies) and Poseidon2 over M31, width 16 (for proofs a circuit verifies).

#### Scenario: Flavour is part of the statement
- **WHEN** a proof in one flavour is presented to a verifier of the other
- **THEN** verification fails

### Requirement: Interaction round
An AIR with aux columns SHALL receive its challenges after the trace commitment, compute the aux columns (LogUp helpers and accumulator for a bus), and commit them before the composition challenge is drawn.

#### Scenario: Bus totals
- **WHEN** the LogUp accumulator of a verifier trace does not total zero
- **THEN** the aux constraints fail and no proof is produced

### Requirement: Composition split
The composition polynomial (2^(t + e) coefficients) SHALL be committed as 2^e blocks of trace-size coefficient ranges in the circle FFT basis, each block as four limb columns on the trace's commitment domain. The verifier SHALL recombine the value at the out-of-domain point z as the sum over blocks of the block's value times its basis multiplier, and check it against the constraints evaluated at z.

#### Scenario: Out-of-domain check
- **WHEN** the recombined composition value at z differs from the constraints' value at z
- **THEN** the verifier rejects

### Requirement: DEEP quotients and folding
Openings SHALL be batched into two DEEP groups: every column opened at z (trace, aux, preprocessed, then the composition blocks) with weights that are powers of one challenge, and the trace columns at z x g with the same weights scaled by a second challenge. The two quotients SHALL be folded once on the circle and then by FRI line folds down to a final polynomial of the configured degree, with Merkle roots of every layer in the transcript.

#### Scenario: Final layer degree
- **WHEN** the last FRI layer is not of the final degree
- **THEN** the prover raises an error instead of producing a proof

### Requirement: Queries
Each query SHALL open one leaf per commitment at the query index (trace, aux, preprocessed, composition), the FRI layer pairs along the fold path with their Merkle paths, and the inverses the verifier needs as hints; the verifier SHALL check every hint by multiplication.

#### Scenario: Tampered opening
- **WHEN** any opened value or path in a query is changed
- **THEN** the Merkle check or the fold check fails

### Requirement: Two provers, one proof
The FFT prover (with native or Dart kernels) and the reference prover SHALL produce byte-identical proofs from the same trace, randomness and parameters, and the reference verifier SHALL accept both.

#### Scenario: Kernel byte-identity
- **WHEN** the same spend is proved with the native kernels and with the Dart kernels
- **THEN** the serialised unlocking scripts are identical
