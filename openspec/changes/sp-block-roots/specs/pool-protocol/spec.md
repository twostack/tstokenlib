## MODIFIED Requirements

### Requirement: Message kinds
The protocol SHALL have six messages, four of them here and the two catch-up messages below. A submission carries one transfer in the pool-transfer wire format, the raw deposit transaction when the transfer backs a deposit, and a 16-byte submission id the wallet chooses. A reply carries the submission id it answers and one outcome: accepted, with the number of the round the transfer is pending for; refused, with a numbered reason and a sentence; or expired, when a transfer accepted earlier could not be included.

A descriptor carries what a wallet needs to open a ledger, build transfers for the pool, and check that a round is this pool's: the network, the txids of the issuance, witness 0 and Y_0, the aggregation arities, the nullifier level, the receipt slots a round has, the spend parameters, **the number of leaves a round appends, the pool's tokenId, and the genesis header in full**. The last three are there because a wallet does not look anything up: a txid it cannot resolve tells it nothing, the leaf count is what its whole path arithmetic rests on, and the tokenId is what a round has to carry before the wallet will believe it belongs to this pool.

An announcement carries a round's number, its 236-byte header, the txids of the round, its witness and the slot transaction the round pins, so a reader has the triple it applies, **and the round's 32-byte block root**, so a party keeping a path current needs nothing else from that round.

#### Scenario: A deposit submission
- **WHEN** a wallet submits a transfer backing a deposit
- **THEN** the submission carries the transfer, the deposit transaction and the wallet's id, and decodes to the same three

#### Scenario: A reply to a refused transfer
- **WHEN** the coordinator refuses a submission
- **THEN** the reply carries the submission's id, the outcome refused, the reason's number and its sentence, and nothing else

#### Scenario: An announcement has what a reader applies
- **WHEN** round 2 of the test chain is announced
- **THEN** the announcement names round 2's txid, witness 2's txid and Y_2's txid, and carries header 2's bytes

#### Scenario: An announcement carries its block root
- **WHEN** round 2 of the test chain is announced
- **THEN** the announcement carries a 32-byte block root equal to the one the ledger reports for round 2

#### Scenario: A descriptor a wallet can act on alone
- **WHEN** a descriptor for the test pool is decoded
- **THEN** it states 32 leaves a round, the pool's tokenId and the genesis header in full, and a ledger opens from it without any lookup

#### Scenario: A descriptor stays small
- **WHEN** a descriptor for the production plan is encoded
- **THEN** it is under 512 bytes

## ADDED Requirements

### Requirement: Catch-up messages
The protocol SHALL carry a fifth and sixth message: a **catch-up request** naming one of three things, and its **reply**. The three are the pool's **block roots** over a round range, the pool's **current frontier** (the round it stands at, that round's block root, and the complete left subtrees above the block level, 32 bytes each, at most one per level: 23 nodes and 736 bytes at production parameters, whatever the pool's age), and a **head proof**: the tip round, its witness, and the witness's merkle branch with the hash of the block holding it.

None of the three is trusted. A block root is checked by folding it and matching the round's `cmRoot`; a frontier by computing the tree's root from it and matching a proven `cmRoot`; a head proof by the rules in `pool-evidence`. A pool is therefore a convenient server for them and never an authority, and a wallet that obtains any of the three elsewhere reaches the same verdict.

Block roots are also carried one at a time on the announcement, so a wallet already reading the feed needs no request. The request exists because an announcement is 370 bytes where a block root is 32, and a wallet catching up over thousands of rounds should not pay eleven times over for headers it already has or does not want.

#### Scenario: Three kinds of request
- **WHEN** each of the three catch-up requests is encoded and decoded
- **THEN** each decodes to an equal request, and an unknown kind byte is refused naming it

#### Scenario: A head proof checks out
- **WHEN** a head proof for round 2 of the test chain is decoded and given to `pool-evidence`
- **THEN** the round is reported proven and its `cmRoot` matches the ledger's

#### Scenario: A frontier reproduces the root
- **WHEN** the frontier reply for a round of the test chain is decoded and a follower is built from it
- **THEN** the follower's commitment root equals that round's `cmRoot`, and it folds the next round as a follower that had folded every round since the genesis

#### Scenario: Block roots in a range
- **WHEN** block roots for rounds 1 to 2 are requested on the test chain
- **THEN** the reply carries two 32-byte roots in round order, and folding them in order reaches round 2's `cmRoot`

### Requirement: A catch-up request carries nothing about the asker
A block-root request SHALL name a round range drawn from a set the descriptor publishes, and the protocol SHALL refuse a range outside it, naming the range. A request derived from what a wallet holds, such as the round it was last current at, is a fingerprint across repeated catch-ups; a published set makes every wallet's request one of a handful.

#### Scenario: A range outside the published set
- **WHEN** a request names a range the descriptor does not publish
- **THEN** it is refused, naming the range, and no roots are served

#### Scenario: A reply carries no asker
- **WHEN** any catch-up reply is encoded
- **THEN** it holds nothing derived from who asked: no id, no address, no round the asker named beyond the range it serves

### Requirement: Catch-up replies are bounded
A catch-up reply SHALL bound its size before allocation. A block-root reply SHALL be refused above a configured number of roots (default 65,536, about 2 MB, more than a year of a pool closing a round every ten minutes), a frontier reply above the tree's depth, and a head proof's two transactions above the chain's own 10 MB per-transaction limit each, since a larger transaction cannot be mined and so cannot be part of a head proof.

#### Scenario: A reply that claims too many roots
- **WHEN** a block-root reply declares more roots than the bound
- **THEN** it is refused before allocation, naming the count and the bound

#### Scenario: Mutated catch-up messages
- **WHEN** 10,000 random and mutated catch-up requests and replies are decoded
- **THEN** each one either decodes to a message or is refused with a named field and reason, and none throws an unnamed error
