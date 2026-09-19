## MODIFIED Requirements

### Requirement: Round budget
A 256-transfer round SHALL be provable on one 12-core machine in under 10 minutes, excluding the wallets' spend proofs. No single prover stage SHALL account for more than a fifth of the round's time.

#### Scenario: Measured round
- **WHEN** the plan is proved end to end at production parameters
- **THEN** the levels and root take about 210 s and peak under 16 GB, the root script is under 1,000,000 ops and the interpreter accepts it

#### Scenario: Stage share
- **WHEN** the per-stage laps of every node and the root are summed over a round
- **THEN** the largest stage is under a fifth of the round and every proof is byte-identical to the Dart kernels' proof
