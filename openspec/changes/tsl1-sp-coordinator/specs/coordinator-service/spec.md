## MODIFIED Requirements

### Requirement: Intake validation
A submitted transfer SHALL be accepted into the pending round only if, in this order: it decodes and passes the self-consistency checks of `pool-transfer`; its anchor is one of the ledger's ring roots (unless it has no real input); its real nullifiers are neither in the ledger's nullifier tree nor claimed by a pending or in-flight round; a deposit carries a covenant the coordinator accepts and the round has a receipt slot left; the pending round's withdrawals stay within the ledger's balance; and its proof verifies against its publics at the pool's spend parameters. A rejection SHALL name its reason with a stable number and a sentence.

#### Scenario: Nullifier already pending
- **WHEN** two transfers spending the same note are submitted to one round
- **THEN** the second is rejected as a pending double spend

#### Scenario: Bad proof
- **WHEN** a transfer's proof does not verify
- **THEN** it is rejected before it touches the pending round, and after every cheaper check

#### Scenario: Bundle that does not match the proof
- **WHEN** a transfer's bundle names a commitment other than its proof's
- **THEN** it is rejected before its proof is verified, since a round carrying it would strand every reader

### Requirement: Round trigger
The coordinator SHALL close the pending round when it is full or when the configured deadline since the first pending transfer passes, whichever is first, and SHALL not close an empty round. At close it SHALL drop any accepted transfer whose anchor has since left the ring, telling its wallet the transfer expired, and SHALL pad the rest to the plan's size.

#### Scenario: Deadline with a short round
- **WHEN** the deadline passes with three pending transfers
- **THEN** a padded round of the plan's size is built and published

#### Scenario: Anchor aged out while pending
- **WHEN** a transfer anchored to a root that four later rounds have rotated out is still pending at close
- **THEN** it is dropped with an expired reply and the round is built without it

### Requirement: Idle work
Between rounds the coordinator SHALL refill the padding stock to its configured level and keep the level programs compiled, so a round starts without proving padding or recompiling. It SHALL NOT hold the levels' preprocessed commitments while idle: each is gigabytes and the levels are proved one after another, so only their roots are kept and a level rebuilds its own commitment when it starts.

#### Scenario: Stock after a round
- **WHEN** a round consumed padding and the coordinator is idle
- **THEN** the stock is back at its configured level before the next round closes

#### Scenario: Nothing held while idle
- **WHEN** the coordinator has finished its idle work after a round
- **THEN** it holds no preprocessed column set, and the levels' preprocessed roots are still known

### Requirement: Prover pool
The coordinator SHALL prove level-1 nodes through a pool of provers it is configured with, this machine included as the fallback, and SHALL run with an empty pool.

#### Scenario: Empty pool
- **WHEN** no member is configured
- **THEN** every level-1 node is proved on the coordinator and the round completes

#### Scenario: Member out
- **WHEN** a configured member does not answer within the timeout
- **THEN** its node is proved on the coordinator and the round completes

### Requirement: Recovery
On start the coordinator SHALL rebuild its ledger from the pool's issuance, witness 0 and Y_0 and every (round, witness, next slot) triple since, or from its last snapshot and the triples since, through the chain reader, and SHALL refuse to run if a triple it published is refused or if the chain ends at a round other than the last it published, naming which.

#### Scenario: Restart mid-history
- **WHEN** the coordinator restarts after round 2 of the test chain with a snapshot taken after round 1
- **THEN** its ledger equals the one it had before stopping

#### Scenario: Chain disagrees with the snapshot
- **WHEN** the snapshot's tip is not the round the chain's next triple spends
- **THEN** the coordinator refuses to start and names the tip and the triple

## REMOVED Requirements

### Requirement: Mode configuration
**Reason**: The pool has one round shape since 2026-09-21 (aggregated rounds through the slot transaction Y); direct-slot rounds were dropped with the decision recorded in the design record's section 11.11.
**Migration**: A coordinator is configured with the aggregation plan alone; the layout it reads from the chain must match it, which Recovery checks.

## ADDED Requirements

### Requirement: Untrusted submissions
The coordinator SHALL treat every submission as hostile: it SHALL run the cheap checks (size, decode, self-consistency, ring, nullifiers, deposit, balance) before the proof is verified, SHALL end every submission in a reply or a drop and never any other failure, and SHALL keep no state for a refused submission. A submission that does not decode SHALL be dropped without a reply when it carries no readable id.

#### Scenario: Mutated submissions
- **WHEN** 1,000 single-byte mutations of a valid submission are each given to the coordinator
- **THEN** each is accepted, refused with a reason, or dropped, the pending round holds only the accepted ones, and none raises any other error

### Requirement: What the coordinator learns and tells
The coordinator SHALL hold, per transfer, only what the round publishes (the transfer as submitted) and the submission id, SHALL send a reply only to the submitter, and SHALL put nothing per transfer in an announcement, so a coordinator's records and feed reveal no more than the chain does. It SHALL NOT need or hold any wallet key.

#### Scenario: Announcement reveals nothing per transfer
- **WHEN** a round of the fixture's transfers is announced
- **THEN** the announcement carries the round number, header and three txids and nothing that names a transfer, a submission or a wallet

### Requirement: Restart
A restart SHALL lose the pending round and nothing else: accepted transfers not yet in a published round are gone, and their wallets learn it by not finding their notes in the rounds announced, then resubmit. The ledger SHALL be snapshotted after every witness is built, before the round is published.

#### Scenario: Pending lost
- **WHEN** the coordinator restarts with two accepted transfers pending
- **THEN** its ledger is the last published state, the pending round is empty, and resubmitting the two is accepted

### Requirement: Performance bounds
On the coordinator's machine (12 cores): a submission SHALL be accepted or refused in under 50 ms at production parameters; a round SHALL take under 10 minutes from close to the witness being built at production with the plan's 256 transfers; recovery from a snapshot of 1,000 production rounds plus two rounds since SHALL take under 30 s.

#### Scenario: Intake cost
- **WHEN** a production transfer is submitted
- **THEN** it is accepted in under 50 ms

#### Scenario: Round cost
- **WHEN** a production round of the localnet run is closed
- **THEN** Y, the round and the witness are built in under 10 minutes

#### Scenario: Recovery cost
- **WHEN** a coordinator restores a 1,000-round snapshot and applies the two production rounds
- **THEN** it is ready in under 30 s

### Requirement: A failed round
If proving or building fails, the coordinator SHALL publish nothing, leave its ledger unchanged, return the round's transfers to the pending round, and report the failure; a transfer that fails at aggregation (its anchor left the ring, or its nullifier was spent by a round published meanwhile) SHALL be dropped with an expired reply instead of returned.

#### Scenario: Funding fails at close
- **WHEN** the funding source fails while a round is being built
- **THEN** nothing is published, the ledger is unchanged, and the transfers are pending again
