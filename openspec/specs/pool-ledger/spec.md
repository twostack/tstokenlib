# pool-ledger Specification

## Purpose

The TSL1_SP pool's state as a coordinator or a wallet holds it (the header, the commitment tree, the nullifier tree and the chain tip the next round spends), rebuilt from mined transactions alone, and the way a wallet finds, proves and tracks its own notes in it.

## Requirements

### Requirement: Ledger state
A ledger SHALL hold the pool's current header, its note commitment tree, its nullifier tree, and the tip the next round must spend: slot transaction Y_N, round N and witness N. A ledger opened from a pool's issuance and witness 0 SHALL hold the genesis header, an empty commitment tree and an empty nullifier tree, and its roots SHALL equal the genesis header's.

#### Scenario: Genesis
- **WHEN** a ledger is opened from an issuance and its witness
- **THEN** its size is 0, its roots are the genesis header's, and its tip is round 0, witness 0 and Y_0

### Requirement: Applying a round
Given round N+1, witness N+1 and the slot transaction Y_{N+1} that round N+1's PP3 pins, a ledger SHALL advance only if every one of these holds, and otherwise SHALL be left unchanged and name the first that fails:
- round N+1 spends the tip's Y_N output 0 at input 2 and round N output 3 at input 3, and witness N+1 spends round N+1's outputs 1 and 2;
- the new header is the one round N+1's PP1 output carries;
- the per-transfer lanes are read from the root proof's statement at the bottom of round N+1's input 2 unlock, in the statement layout of the pool's verifier;
- the bundles are the ones witness N+1 carries, their hashes combine to the new header's outHash, and every transfer's outHash lanes match its bundle and its withdrawal, the withdrawals being round N+1's withdrawal outputs in order;
- every transfer's commitments come from its bundle, or are the padding note's for a padding transfer with an empty bundle, and are placed at the leaf positions the aggregation gives them;
- every real nullifier is inserted, and none was already present;
- the rebuilt commitment tree and nullifier tree reach the new header's roots, its size is the old size plus the round's leaves, its ring is the old ring rotated with the new root first, and its balance is the old balance minus the sum of the transfers' public amounts;
- round N+1's receipts are exactly the deposit transfers' first commitments and values, in receipt order.

#### Scenario: Honest round
- **WHEN** a ledger applies a round and witness the tool built from well-formed transfers
- **THEN** its header equals the round's new header and its roots match

#### Scenario: Bundle swapped in the witness
- **WHEN** a witness carries a bundle other than the one a transfer's outHash commits to
- **THEN** the round is refused and the ledger keeps its previous state

#### Scenario: Round does not extend the tip
- **WHEN** a round spends a PP3 other than the tip's
- **THEN** it is refused as belonging to another chain or another point in this one

### Requirement: Chain reader
A reader SHALL rebuild a ledger from a pool's issuance, witness 0, and every (round, witness, next slot) triple since, in order, using no other input, and SHALL reach the same header bytes, commitment root, nullifier root and balance as the ledger that built the rounds. It SHALL flag each padding transfer, report each round's withdrawals and receipts, and stop at the first triple it refuses, reporting the last round it applied.

#### Scenario: Reader agrees with the builder
- **WHEN** a reader applies the two rounds of the test chain as mined
- **THEN** its header bytes, roots and balance equal those the builder advanced to

#### Scenario: Stops at a bad round
- **WHEN** round 2 of the test chain is given with a witness whose bundles do not match its outHash
- **THEN** the reader applies round 1, refuses round 2, and reports round 1 as its last

### Requirement: Snapshot
A ledger SHALL serialise to bytes and restore to an equal ledger (header, both trees, tip), so a coordinator or wallet can restart without re-reading every round. A restored ledger SHALL apply the next round exactly as the original would. The snapshot SHALL begin with a format version and a decoder SHALL refuse a version it does not know. Restoring SHALL check the rebuilt roots against the stored header and refuse a snapshot that does not reach them, so a corrupted or edited file is refused rather than loaded.

#### Scenario: Restart
- **WHEN** a ledger is serialised after round 1, restored, and given round 2
- **THEN** it reaches the same header as a ledger that never stopped

#### Scenario: Edited snapshot
- **WHEN** one leaf in a snapshot is changed
- **THEN** restoring it is refused, because the rebuilt root is not the header's

#### Scenario: Restore time
- **WHEN** a snapshot of 1,000 production rounds (512,000 leaves and their nullifiers) is restored
- **THEN** it takes under 10 s on one core (measured 2026-09-22: 9.4 s with both trees rebuilt bottom-up through the native batch compression, `tool/scratch/ledger_apply_probe.dart`, design record 14.1)

### Requirement: Note scanning
Given an incoming viewing key, a scanner SHALL return, for each round applied, the notes addressed to that key: the plaintext, the commitment, its leaf position, and the round it arrived in. It SHALL only decrypt bundles the ledger accepted (so their hash chain to the header's outHash is checked), SHALL discard a note whose plaintext does not reproduce its commitment, and SHALL return no note for a key the round did not pay. Given the nullifier key as well, it SHALL report a note spent from the round its nullifier enters the tree.

#### Scenario: Wallet finds its deposit
- **WHEN** the depositor scans round 1 of the test chain with the deposit note's viewing key
- **THEN** it finds one note of 500 at leaf position 0

#### Scenario: Stranger finds nothing
- **WHEN** another key scans the same round
- **THEN** no note is returned

#### Scenario: Spent after round 2
- **WHEN** the depositor scans round 2 with its nullifier key
- **THEN** the 500 note is reported spent in round 2 and the 200 change note is found

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

### Requirement: No keys, no trust
Reading the chain SHALL need no key of any kind and no statement from the coordinator: given the same mined transactions, any party SHALL reach the same ledger, and a coordinator's claim about the pool's state SHALL be checkable against it. Two ledgers that applied the same rounds SHALL serialise to identical bytes.

#### Scenario: Two independent readers
- **WHEN** a wallet and a coordinator each read the test chain from the same transactions
- **THEN** their snapshots are byte-identical

### Requirement: Malformed chain data
A round, witness or slot transaction given to the ledger SHALL be treated as unverified input, since a wallet may fetch it from any source. Anything malformed (a truncated unlock, a push of the wrong size, a bundle blob whose lengths overrun, a transaction of the wrong shape) SHALL end in a refusal naming what was wrong, never any other failure, and SHALL leave the ledger unchanged.

#### Scenario: Truncated witness
- **WHEN** witness 1 of the test chain is given with its bundles push cut short
- **THEN** the round is refused as malformed and the ledger keeps its previous state

#### Scenario: Mutated round
- **WHEN** 1,000 single-byte mutations of round 1 are each applied to a fresh genesis ledger
- **THEN** each is refused or, if the mutation leaves the round well formed and consistent, applied, and none raises any other error

### Requirement: Scanning stays local
Finding, decrypting and tracking a wallet's notes SHALL need nothing beyond round data the wallet already holds and the wallet's own keys, so a wallet can fetch whole rounds, as every wallet does, and reveal to no one which notes, keys or addresses are its own. The scanner SHALL make no request of any party and SHALL return its results only to its caller.

#### Scenario: Offline scan
- **WHEN** a wallet scans the test chain's rounds read from files, with no network available
- **THEN** it finds the same notes as when the rounds were fetched

### Requirement: Performance bounds
On one core of the coordinator's machine: applying one production round (256 transfers) SHALL take under 5 s, excluding fetching; scanning one production round for one diversifier SHALL take under 5 s; checking a transfer's self-consistency is bounded by pool-transfer's Untrusted input requirement. These bounds hold for readers and wallets that apply every round as it is mined, so a round must be applied in well under the time between rounds.

#### Scenario: Reader keeps up
- **WHEN** a production round from the localnet production chain is applied
- **THEN** it takes under 5 s on one core (measured 2026-09-22: 716 ms and 557 ms for rounds 1 and 2, design record 14.1)

#### Scenario: Scanner keeps up
- **WHEN** a production round's 512 hybrid bundles are scanned for one diversifier
- **THEN** it takes under 5 s on one core (measured 2026-09-22: 540 ms, `tool/scratch/scan_cost_probe.dart`, design record 14.1)

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
