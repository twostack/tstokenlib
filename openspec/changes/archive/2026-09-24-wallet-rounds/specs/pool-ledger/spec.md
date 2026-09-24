## ADDED Requirements

### Requirement: A round's leaves from its transactions alone
The library SHALL read, from a round's transaction and its witness alone with no ledger state:
- the leaves the round appends, in tree order;
- each transfer's two output positions within them;
- the nullifiers the round spent;
- the round's block root;
- the header the round carries.

They SHALL be what applying the round places, read the same way. A witness that does not spend the round's PP1 and PP2 SHALL be refused, naming the check. A wallet holding a fold uses this to find and path its own note in a round it paid, deposited or received change in. It trusts nothing: it checks the block root against the round's announcement and its folded root against the round's proven `cmRoot`.

#### Scenario: Leaves agree with the ledger
- **WHEN** rounds 1 and 2 of the test chain are read from their transactions alone
- **THEN** each gives the plan's leaves per round, and the block root, the positions (offset by the round's first leaf), the nullifiers and the header match what the ledger's application of that round reports

#### Scenario: Another round's witness
- **WHEN** round 2's transaction is read with witness 1
- **THEN** it is refused, naming `tip`

### Requirement: The frontier at a past round
The ledger SHALL give the frontier as it stood at any round it has applied, the same as the frontier it gave when it stood there, so a pool can answer at its last mined round while it has published further.

#### Scenario: The frontier one round back
- **WHEN** a ledger that has applied rounds 1 and 2 gives the frontier at round 1
- **THEN** a follower built from it reaches round 1's `cmRoot`
