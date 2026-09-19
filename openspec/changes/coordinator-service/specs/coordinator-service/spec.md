## Purpose

Runs a shielded pool over time: accepts transfers from wallets, closes rounds on a schedule, keeps the stock and caches warm between rounds, and recovers its ledger from the chain after a restart.

## ADDED Requirements

### Requirement: Intake validation
A submitted transfer SHALL be accepted into the pending round only if its proof verifies against its publics, its extra outputs hash to its outHash, it carries the issuer's authorisation when it needs one, its anchor is in the ring (unless it has no real input), its real nullifiers are neither in the set nor pending, and the pending round's BSV withdrawals stay within the vault. A rejection SHALL name its reason.

#### Scenario: Nullifier already pending
- **WHEN** two transfers spending the same note are submitted to one round
- **THEN** the second is rejected as a pending double spend

#### Scenario: Bad proof
- **WHEN** a transfer's proof does not verify
- **THEN** it is rejected before it touches the pending round

### Requirement: Round trigger
The coordinator SHALL close the pending round when it is full or when the configured deadline since the first pending transfer passes, whichever is first, and SHALL not close an empty round. In recursive mode a short round SHALL be padded from the stock.

#### Scenario: Deadline with a short round
- **WHEN** the deadline passes with three pending transfers in recursive mode
- **THEN** a padded round of the plan's size is built and published

### Requirement: Idle work
Between rounds the coordinator SHALL refill the padding stock to its configured level and keep the level programs and preprocessed commitments resident, so a round starts without proving padding or recomputing commitments.

#### Scenario: Stock after a round
- **WHEN** a round consumed padding and the coordinator is idle
- **THEN** the stock is back at its configured level before the next round closes

### Requirement: Prover pool
In recursive mode the coordinator SHALL prove level-1 nodes through a pool of provers it is configured with, this machine included as the fallback, and SHALL run with an empty pool.

#### Scenario: Empty pool
- **WHEN** no member is configured
- **THEN** every level-1 node is proved on the coordinator and the round completes

#### Scenario: Member out
- **WHEN** a configured member does not answer within the timeout
- **THEN** its node is proved on the coordinator and the round completes

### Requirement: Recovery
On start the coordinator SHALL rebuild its ledger from the genesis transaction and every round transaction since, through the chain reader, and SHALL refuse to run if the rebuilt ledger disagrees with the last published state.

#### Scenario: Restart mid-history
- **WHEN** the coordinator restarts after five rounds
- **THEN** its ledger equals the one it had before stopping

### Requirement: Mode configuration
The coordinator SHALL be configured for exactly one of direct-slot rounds (k transfers per round, per-transfer verifier slots) or recursive rounds (an aggregation plan and a padding stock), sharing intake and ledger but not round building; the mode SHALL be fixed for the pool's life.

#### Scenario: Mode mismatch
- **WHEN** a recursive-mode coordinator is pointed at a pool whose state script is the direct-slot script
- **THEN** it refuses to start and names the mismatch
