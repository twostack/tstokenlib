## 1. Configuration and intake

- [x] 1.1 Add `CoordinatorConfig` (mode, parameters, round deadline, padding stock level) and the mode check against the pool's state script; verify with a test that a mismatched mode is refused with a message naming both.
- [x] 1.2 Implement intake validation (proof verification, outHash, authorisation, ring, pending nullifiers, vault) with named rejection reasons; verify with tests for each rejection and for acceptance.

## 2. Rounds and scheduling

- [x] 2.1 Implement the pending round, the full-or-deadline trigger with an injectable clock, and round building through the tool for both modes with a publish callback; verify with a test using a fake clock that a short recursive round is padded and published at the deadline and that an empty round is not built.
- [x] 2.2 Keep intake open while a round is being built; verify with a test that a transfer submitted during building lands in the next round.

- [x] 2.3 Wire the configured prover pool into recursive round building (`ProverPool` over the configured `NodeProver`s as `level1`); verify with a test that a round with one in-process member and one that never answers completes with the same root as the local round.

## 3. Idle work and recovery

- [x] 3.1 Implement the idle refill of the padding stock and the warm-up of the level programs (the preprocessed commitments are deliberately not kept warm: they are 14.5 GB of a round's peak and the levels are proved in sequence, so each rebuilds its own); verify with a test that the stock returns to its level after a padded round and that an idle coordinator holds no preprocessed column set.
- [x] 3.2 Implement recovery from genesis plus round transactions through the chain reader with a disagreement check; verify with a test that a coordinator restarted after several rounds has the same ledger.

## 4. Entry point and documentation

- [x] 4.1 Add `bin/pool_coordinator.dart` reading a config file and wiring an in-memory publish callback (real transport later); verify it starts against a test pool and prints its mode and ledger.
- [x] 4.2 Add the "Coordinator service (built)" section to `docs/ZK_SHIELDED_POOL_DESIGN.md`.
