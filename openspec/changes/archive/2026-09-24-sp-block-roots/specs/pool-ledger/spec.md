## MODIFIED Requirements

### Requirement: Merkle paths for spending
For any leaf the ledger holds, the ledger SHALL give its Merkle path against the current commitment root. A spend proved against that root SHALL stay acceptable to the pool for as long as the root is in the header's ring, the current round and the three after it, because the ring is what the next rounds check anchors against; the ledger SHALL say how many more rounds a given root stays in the ring.

A round appends a fixed power-of-two block of leaves, so round N owns exactly the aligned subtree at level log2(block): 512 leaves and level 9 at production parameters, 32 and level 5 at test parameters. The ledger SHALL therefore also give **the block root of the round it has just applied**, the tree node at that level and index N − 1 (round 1 owns block 0, since the genesis appends nothing), in 32 bytes.

A party that holds a leaf's path SHALL be able to keep it current from those block roots alone, without the rounds' commitments: the siblings below the block level are frozen once the leaf's own round is mined, and the siblings above it follow from folding one block root per round into an upper frontier. The library SHALL provide that fold and that update, and the root it computes after a fold SHALL equal the `cmRoot` of the header of the round folded, which is what makes a block root safe to take from anyone.

#### Scenario: Path to the current root
- **WHEN** a wallet asks for the path of leaf 0 after round 2
- **THEN** the path and the leaf reproduce the header's current commitment root

#### Scenario: Anchor ageing out
- **WHEN** a root was current four rounds ago
- **THEN** the ledger reports it no longer in the ring, so a spend anchored to it would be refused

#### Scenario: A round's block root
- **WHEN** round 2 of the test chain is applied
- **THEN** the ledger reports a 32-byte block root equal to the tree node at level 5, index 1

#### Scenario: A path kept current by folding
- **WHEN** a path for a leaf in round 1 of the test chain is folded forward with round 2's block root
- **THEN** it equals the ledger's own path for that leaf after round 2

#### Scenario: Thirty-two bytes a round
- **WHEN** a party keeps ten leaves' paths current across the test chain's rounds
- **THEN** the only round-derived input it consumed is 32 bytes a round, whatever the number of leaves

#### Scenario: A fold that does not match
- **WHEN** a block root with one byte changed is folded
- **THEN** the computed root does not equal that round's `cmRoot`, and the fold is refused naming the round

#### Scenario: Folding a thousand blocks
- **WHEN** a tree of 1,000 blocks of 512 leaves is built directly and the same 1,000 block roots are folded
- **THEN** the folded path for a leaf in block 3 equals `NoteCommitmentTree.path` for that position, and folding one root and updating one path takes under 1 ms on one core of an Apple M3 Pro

## ADDED Requirements

### Requirement: A PP1 is read through the body check, everywhere
Every place the library reads a field out of a PP1 output SHALL first establish that the output is a real PP1_SP script, by regenerating the script from the fields it parsed and requiring byte equality. Reading `ownerPKH`, `tokenId`, `verifierBodyHash`, `genesisHeader` or `header` at their offsets without that check reads a forgery's own account of itself: the offsets carry no authority, the script body does, and the body is the only part a forger cannot copy and still spend cheaply.

`apply` survives a forged round without this check, because it already requires the round to spend the tip's PP3, the tip's Y and the previous witness's output 0, which a forger cannot do. `open` does not: its three transactions are related only to each other, so nothing outside them says which pool they are. The check therefore belongs in the shared reader, not in one caller.

#### Scenario: A forged round offered to a ledger
- **WHEN** a round whose output 1 carries a PP1's first 563 bytes over a body that spends on a signature is offered to the ledger
- **THEN** it is refused, naming output 1 as not a PP1_SP, before any header is read

#### Scenario: A round cannot be applied over a real tip anyway
- **WHEN** a forged round is applied to a ledger at the fixture's round 1
- **THEN** it is refused for not spending the tip's PP3, which is the spend chain holding independently of the body check

### Requirement: Opening checks which pool it is
`open` SHALL take the pool's tokenId and genesis header from the caller (the descriptor carries both) and SHALL refuse a genesis triple whose issuance does not carry them, naming the field. Without it, opening checks only that the three transactions point at each other, which a forger can arrange for a pool of their own, and every later round inherits that mistake.

#### Scenario: A forged genesis
- **WHEN** a ledger is opened on an issuance, witness and slot a forger built, with the descriptor of the real pool
- **THEN** opening is refused, naming the tokenId

#### Scenario: The test pool opens
- **WHEN** the fixture's genesis triple is opened with the fixture pool's tokenId and genesis header
- **THEN** it opens at round 0 as before
