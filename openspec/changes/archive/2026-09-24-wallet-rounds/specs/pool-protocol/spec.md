## ADDED Requirements

### Requirement: Protocol version 3
Every message SHALL begin with format version 3. A message of any other version SHALL be refused, naming the version, before any other field is read. Version 3 adds the catch-up request id, the refusal form of a catch-up reply, the round kind, and the mined-round notice; a version 2 catch-up request has no id to answer to.

#### Scenario: Another version is refused
- **WHEN** a message of each kind is re-encoded with version 2 or 4
- **THEN** each is refused with the field `version`

### Requirement: Catch-up requests carry an id their replies echo
A catch-up request SHALL carry a 16-byte id, drawn at random for that request and derived from nothing the wallet holds, and every reply SHALL carry the id of the request it answers. Two requests SHALL NOT share an id. The id lets a wallet send several requests at once and route each reply, as it routes submission replies by submission id.

#### Scenario: A reply echoes its request's id
- **WHEN** a frontier request with a given id is encoded, decoded and answered
- **THEN** the decoded request and the decoded reply both carry that id, and two requests built without one carry different ids

### Requirement: A catch-up request the pool will not answer is refused
A pool SHALL answer every catch-up request it can read, with the answer or a refusal naming one of four reasons:
- `notServed`: a kind the pool does not serve.
- `unpublishedRange`: a block-root range the descriptor does not publish.
- `notYet`: nothing mined to answer from, or a round past the last mined one.
- `unavailable`: the pool cannot answer now.

The refusal SHALL also carry a sentence for a person. A pool whose chain access fails SHALL refuse with `unavailable` rather than stay silent.

#### Scenario: Every reason round trips
- **WHEN** a refusal of each reason for each kind is encoded and decoded
- **THEN** each decodes to an equal reply naming its kind, reason and sentence, and an unknown reason number is refused with the field `reason`

#### Scenario: Not mined yet
- **WHEN** the test chain's responder has no round mined and is asked for the head, the frontier, round 1 and a published block-root range
- **THEN** each is refused with `notYet`, echoing the request's id

#### Scenario: A source that fails
- **WHEN** the responder's source throws while reading a mined round
- **THEN** the head and round requests are refused with `unavailable`, and the sentence names the failure

### Requirement: Catch-up answers stand at the last mined round
A pool SHALL answer a head, a frontier and a block-root range at or below its last mined round (every round up to it mined), never at a round it has published but not seen mined. A block-root reply SHALL serve the published range from its first round up to the last mined round.

#### Scenario: Head and frontier agree below the ledger's round
- **WHEN** the test chain's responder has round 1 mined and round 2 applied, and is asked for the head and then the frontier
- **THEN** both stand at round 1, the head carries round 1 and witness 1, and a follower built from the frontier reaches round 1's `cmRoot`

#### Scenario: Block roots up to the last mined round
- **WHEN** the descriptor publishes runs of 4, rounds 1 and 2 are mined, and rounds 1 to 4 are asked for
- **THEN** the reply serves rounds 1 and 2, and a request for rounds 2 to 5 is refused with `unpublishedRange`, naming the range

### Requirement: A mined round by number
The protocol SHALL carry a fourth catch-up kind naming one mined round, answered as a head is: the round and witness transactions whole, the hash of the block holding the witness, the witness's index there, and its merkle branch. A request for a round past the last mined one SHALL be refused with `notYet`. Which round a wallet asks for follows from what it did, so the request tells the pool that the peer cares about that round. This is harmless for the round the same peer submitted into, and a link otherwise. A submitter SHALL be able to learn its round without asking (the mined-round notice), and this kind SHALL be documented as the recovery path.

#### Scenario: A round after later rounds are mined
- **WHEN** the test chain has rounds 1 and 2 mined and round 1 is asked for
- **THEN** the reply carries round 1 and witness 1, and its branch computes the block's merkle root for witness 1

#### Scenario: A round request is one round
- **WHEN** a round request names round 0, or names a count
- **THEN** it is refused, naming `from` or `count`

### Requirement: A submitter is sent its mined round
The protocol SHALL carry a seventh message, the mined-round notice. It names one or more (at most 256) of the recipient's accepted submission ids that the round took in, the round's number, the round's and the witness's txids, and the witness's block hash, index and merkle branch. It SHALL carry no transactions: a notice goes to every submitter of every round, and at production a round's two transactions are about 2.6 MB. A wallet that needs them asks for the round by number from the identity it submitted with. The notice SHALL be sent only to the peer that submitted those ids, which the pool already knows took part in the round. Nothing in it is trusted: its branch is checked against the wallet's own header, its txids against the round's announcement.

#### Scenario: A notice round trips
- **WHEN** a notice for round 2 naming two submission ids is encoded and decoded
- **THEN** it names the same ids and round and the txids of round 2 and witness 2, its branch computes the block's merkle root, and it is under 4,096 bytes; a notice naming no ids is refused

#### Scenario: A notice stays small
- **WHEN** a notice names one id and carries a 20-deep branch, as a block of a million transactions has
- **THEN** it encodes under 1,024 bytes, and a decoder refuses anything over the notice's bound as too large

### Requirement: New catch-up messages are bounded
A round reply SHALL be bounded as a head proof is: each transaction at most the chain's 10 MB, the branch at most 40 nodes, the whole under `PoolMessage.maxCatchUp`. A notice SHALL be bounded by its fields: at most 256 ids and 40 branch nodes, about 5.5 KB in all. Each bound is checked before allocation.

#### Scenario: Mutated version 3 messages
- **WHEN** 10,000 single-byte mutations of a round request, a refusal, a round reply and a notice are decoded
- **THEN** each either decodes to a message or is refused with a named field, and none throws an unnamed error

## MODIFIED Requirements

### Requirement: A catch-up request carries nothing about the asker
A block-root request SHALL name a round range drawn from a set the descriptor publishes, and the protocol SHALL refuse a range outside it, naming the range. A request derived from what a wallet holds, such as the round it was last current at, is a fingerprint across repeated catch-ups; a published set makes every wallet's request one of a handful. A request's id SHALL be drawn at random for that request, and a reply SHALL carry nothing about the asker beyond echoing that id.

#### Scenario: A range outside the published set
- **WHEN** a request names a range the descriptor does not publish
- **THEN** it is refused, naming the range, and no roots are served

#### Scenario: A reply carries no asker
- **WHEN** any catch-up reply is encoded
- **THEN** it holds nothing derived from who asked: no address, no round the asker named beyond what it asked for, and no id other than the request's own random one
