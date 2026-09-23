## Purpose

What mined bytes have to show before a round counts as a given pool's, and
before a note counts as being in that round. These are the rules a payee applies
to a payment it was handed, stated once in the library that defines the pool so
that no wallet has to restate them and none can drift.

## ADDED Requirements

### Requirement: A proven round
Given a round transaction, its witness transaction, the height at which the
witness is mined (established elsewhere, by a merkle proof against a block
header the caller accepts) and the pool's descriptor, the library SHALL report
whether the round is that pool's. It SHALL check that the witness spends the
round's PP1 and PP2 outputs, that the PP1 output is a real PP1_SP script rather
than one carrying the pool's fields at the right offsets over a body that
enforces nothing, that it carries the descriptor's tokenId and genesis header,
and that the round's 236-byte pool header parses; and it SHALL report the
round's header, owner and commitment root when it passes, and the first failing
check by name when it does not.

It SHALL NOT report a round number: a pool header carries none, so a caller that
needs one takes it from an announcement or from its own count, and this check
does not vouch for it.

#### Scenario: A round of the test chain
- **WHEN** round 2 of the test chain, its witness and the test pool's descriptor are checked
- **THEN** the round is reported proven, with header 2 and its commitment root

#### Scenario: A witness that spends another round
- **WHEN** the witness of round 1 is offered with round 2
- **THEN** the check fails naming the PP1 spend, and reports nothing about the round

#### Scenario: Another pool's tokenId
- **WHEN** the descriptor of a different pool is used
- **THEN** the check fails naming the tokenId, and reports both

### Requirement: What a proven round does and does not establish
A proven round establishes that a transaction carrying the pool's tokenId in its
PP1 was accepted by the chain, one hop back from a mined witness. The library
SHALL document that this is a one-hop claim and SHALL state, beside the check,
what it rests on: that the chain ran the pool's verifier script over the round
and accepted it, and that the tokenId in PP1 cannot be carried by a transaction
the pool's own covenant did not produce. The library SHALL NOT claim more than
the check performs.

#### Scenario: A forged round carrying the pool's tokenId
- **WHEN** a round is forged on localnet to carry the pool's tokenId with a header of the forger's choosing, given a witness and mined
- **THEN** the check refuses it, naming the step that caught it

### Requirement: A proven note
Given a proven round, a note's opening (value, rho, rcm, asset and diversifier),
the holder's `pk_d`, a leaf position and a Merkle path, the library SHALL report
whether that note is in that round: the commitment SHALL equal `PoolHash.commit`
over the opening and `pk_d`, and the path SHALL take that commitment from the
position to the round's commitment root. It SHALL report the value when it
passes and the failing check by name when it does not.

#### Scenario: A note of the test chain
- **WHEN** the fixture wallet's note from round 1, its opening, position and path are checked against that proven round
- **THEN** the note is reported present, with its value

#### Scenario: An opening that is not the holder's
- **WHEN** the opening does not commit under the given `pk_d`
- **THEN** the check fails naming the path, because a commitment under another key is simply not in the tree, and reports no value

The library SHALL also offer the same check against a commitment root the
caller established some other way, for the one other way there is: a party
following the pool folds a block root a round and checks the result against the
`cmRoot` of a round it proved off the chain, so the root it holds for a round is
as good as the round's own. That is what a short payment proof rests on. A root
that arrived inside a proof is not such a root, and the library SHALL say so
where the entry point is documented.

#### Scenario: A path to another root
- **WHEN** the path leads to a root that is not the round's
- **THEN** the check fails naming both roots

#### Scenario: A note under a folded root
- **WHEN** the same note, opening, position and path are checked against the commitment root a follower folded for that round rather than against the round itself
- **THEN** the verdict and the value are the same

### Requirement: No keys, no trust, no lookups
Both checks SHALL need no key: no spending key, no viewing key, no signature
from the coordinator. They SHALL take no input beyond what the caller passes
them, make no request of any kind, and reach the same verdict for every party
given the same bytes.

#### Scenario: Checking makes no requests
- **WHEN** a proven-round and a proven-note check run with every outward call recorded
- **THEN** no call is made

#### Scenario: Two parties agree
- **WHEN** two parties check the same round and note from the same bytes
- **THEN** they reach the same verdict and report the same fields

### Requirement: Untrusted input
Both checks take bytes from a stranger. Every length SHALL be bounded before
allocation, transactions SHALL be parsed as the chain reader parses them, a path
SHALL be refused unless it has `PoolSpendAir.depth` siblings inside the field, a
position unless it is inside the tree, and every failure SHALL be a named
refusal rather than an exception.

#### Scenario: Mutated evidence
- **WHEN** 10,000 randomly mutated rounds, witnesses, openings, positions and paths are checked
- **THEN** each one is refused with a named reason or reaches the same verdict it would have without the mutation, none throws an unnamed error, and no forged PP1 is ever reported proven

### Requirement: Cheap enough to run while someone waits
Neither check SHALL verify a STARK: the round was mined, which means the chain
ran the pool's verifier script over it, so the checks are hashing, parsing and
script reading only. A proven-round and a proven-note check together SHALL take
under 20 ms at test parameters on one core of an Apple M3 Pro.

#### Scenario: Check cost
- **WHEN** a round and a note of the test chain are checked
- **THEN** the pair completes in under 20 ms, and the measurement is recorded in the design record

### Requirement: Failure behaviour
A failed check SHALL report the first failing step and leave nothing behind: no
partial state, no cached verdict and no file. Checking the same evidence again
SHALL give the same answer.

#### Scenario: Nothing left after a failure
- **WHEN** a check fails at any step
- **THEN** no state is written, and a repeat of the same check gives the same named failure
