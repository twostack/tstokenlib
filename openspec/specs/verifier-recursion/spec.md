# verifier-recursion Specification

## Purpose
A STARK verifier expressed as an AIR so that proofs can verify other proofs: the verifier program, its preprocessed columns, the bus that binds hash chain and program, and the two modes (digest of inner statements, or the wide root that carries every transfer's publics and the tree update).

## Requirements

### Requirement: Verifier program over the Poseidon2 chain
The verifier AIR SHALL run a fixed program (a VM of periods over a Poseidon2 chain) that replays the inner proof's transcript, checks every Merkle path, the out-of-domain relation and every fold, with the program's structure held in preprocessed columns whose root is a constant the verifier of the outer proof knows.

#### Scenario: Wrong inner proof
- **WHEN** any inner proof presented to the program is invalid
- **THEN** no witness satisfies the program and no outer proof can be produced

### Requirement: Statement digests
In digest mode the program's public input SHALL be one 8-lane digest of its inner statements (each inner statement's digest covering the inner AIR's publics and preprocessed root), so a chain of levels binds all the way down to the spends.

#### Scenario: Substituted spend
- **WHEN** a spend proof is swapped for another valid one after the level-1 node was proved
- **THEN** the level-1 statement digest no longer matches the root's expectation

### Requirement: Wide root
In wide mode the root program SHALL take every transfer's public lanes (padded to whole 8-lane chunks) followed by the round chunks (root before, root after, first subtree index) as its public input, derive the spend digests from those lanes in-circuit, and verify the top inner proof against them.

#### Scenario: Public lanes are the statement
- **WHEN** the verifier slot's unlocking script supplies the wide publics
- **THEN** the same lanes are what the state script reads as the round's transfers

### Requirement: In-circuit tree update
The wide root SHALL prove that appending the round's commitments as whole subtrees (32 leaves each, empty leaves for padding positions) to the commitment tree at the given index takes the root from rootBefore to rootAfter.

#### Scenario: Wrong rootAfter
- **WHEN** the round chunks claim a rootAfter that does not result from the appended leaves
- **THEN** no witness satisfies the program

### Requirement: One program per level
Every node of a level SHALL run the same compiled program (the same preprocessed root), regardless of which transfers it holds, so the preprocessed commitment is computed once per level and cached.

#### Scenario: Cached commitment
- **WHEN** sixteen level-1 nodes are proved in one round
- **THEN** the preprocessed columns are committed once and reused fifteen times
