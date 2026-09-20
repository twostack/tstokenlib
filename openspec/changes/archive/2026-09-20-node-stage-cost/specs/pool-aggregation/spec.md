## MODIFIED Requirements

### Requirement: Round budget
A 256-transfer round SHALL be provable on one 12-core machine in under 10 minutes, excluding the wallets' spend proofs.

#### Scenario: Measured round
- **WHEN** the plan is proved end to end at production parameters
- **THEN** the levels and root take about 220 s and peak under 16 GB, the root script is under 1,000,000 ops and the interpreter accepts it
