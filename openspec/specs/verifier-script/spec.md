# verifier-script Specification

## Purpose
The Bitcoin-script STARK verifier: a locking script generated from an AIR and a parameter set that checks a proof supplied in the unlocking script, used as the verifier slot of a round (a spend proof in direct mode, the aggregation's wide root in aggregated mode).

## Requirements

### Requirement: Generated from the AIR
The generator SHALL emit, for a parameter set and an AIR, a script that recomputes the transcript (SHA256), checks the out-of-domain relation from the AIR's constraints, the DEEP quotients, the circle fold, every FRI layer and every Merkle path, with all field inverses supplied as hints and verified by multiplication.

#### Scenario: Wrong proof rejected
- **WHEN** any element of the proof in the unlocking script is altered
- **THEN** the interpreter rejects the spend

### Requirement: Public lanes as the statement
The slot SHALL take the public lanes from the unlocking script and expose them in a result output so the state script can read the same lanes; the proof is bound to them through the transcript.

#### Scenario: Aggregated slot
- **WHEN** the slot verifies a wide root over 256 transfers
- **THEN** it carries 14,360 public lanes and its result output holds them

### Requirement: Limits
The slot script SHALL stay under 1,000,000 ops and the round transaction under 10 MB at the plan's transfer count; the fixed cost at blowup 32 with 18 queries is about 336,000 ops plus about 2,156 ops per transfer.

#### Scenario: Plan-size root
- **WHEN** the root of a 256-transfer round is verified in the interpreter
- **THEN** the script is about 2.2 MB and 883,000 ops and is accepted in about 15 s

### Requirement: Templates
Exported templates of the state script and the slots SHALL round-trip through the template loader, and SHALL be regenerated whenever a generator changes.

#### Scenario: Stale template
- **WHEN** a generator changes and the templates are not re-exported
- **THEN** the template sync test fails
