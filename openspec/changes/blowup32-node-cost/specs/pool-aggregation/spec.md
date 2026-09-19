## MODIFIED Requirements

### Requirement: Round budget
A 256-transfer round SHALL be provable on one 12-core machine in under 10 minutes, excluding the wallets' spend proofs. The blowup-32 proofs above level 2 (two 2^20 nodes, one 2^19 node and the root) SHALL together take under 60 s.

#### Scenario: Measured round
- **WHEN** the plan is proved end to end at production parameters
- **THEN** the levels and root take about 356 s, the root script is under 1,000,000 ops and the interpreter accepts it

#### Scenario: Blowup-32 share
- **WHEN** levels 3 and 4 and the root are proved
- **THEN** their combined prover time is under 60 s and every proof is byte-identical to the Dart kernels' proof
