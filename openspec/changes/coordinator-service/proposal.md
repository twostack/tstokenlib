## Why

Everything a round needs exists as library calls (`ShieldedPoolTool`, `PoolAggregation`, `PaddingSupply`, `PoolChainReader`) but nothing runs a pool: transfers arrive from wallets over time, rounds must close on a schedule or when full, the padding stock must be refilled between rounds, the preprocessed commitments must be warm before the first round, and a restart must recover the ledger from the chain. The decision that direct-slot rounds and recursive rounds are separate solutions also needs a place: one coordinator binary configured for one or the other.

## What Changes

- A long-running coordinator: an intake that validates each submitted transfer (outHash, issuer authorisation, proof verified with the reference verifier) and queues it; a round trigger (deadline or full); round building through the existing tool; a publish hook for the round transaction; ledger recovery through the chain reader on start.
- Idle work between rounds: refill the padding stock to a configured level, keep the level programs and preprocessed commitments cached.
- In recursive mode the configuration lists the level-1 prover pool (this machine, plus machines the coordinator operates once a transport exists) and round building proves level 1 through it.
- Configuration selects the mode (direct slots with k transfers, or recursive with a plan) and the parameters; the two modes share intake and ledger but not round building.
- Rejection reasons are returned to the submitter (bad proof, spent nullifier, unknown anchor, missing authorisation, vault overdraw).

## Capabilities

### New Capabilities
- `coordinator-service`: intake validation, round scheduling, idle work, recovery, mode configuration.

### Modified Capabilities
- `pool-coordinator`: the padding-supply requirement gains the refill-between-rounds scenario; rounds gain the intake-validation scenario.

## Impact

- New `lib/src/transaction/pool_coordinator.dart` (service, config, intake, scheduler) with a transport-free API (submit, status, close round) so a CLI or an HTTP layer can wrap it later.
- `bin/` gets a `pool_coordinator` entry point reading a config file.
- Numbers to keep: a 256-transfer recursive round under 10 minutes including intake and publishing; intake verification of a spend proof about 0.1 s.
