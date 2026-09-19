## 1. Configuration and intake

- [ ] 1.1 Add `CoordinatorConfig` (mode, parameters, round deadline, padding stock level) and the mode check against the pool's state script; verify with a test that a mismatched mode is refused with a message naming both.
- [ ] 1.2 Implement intake validation (proof verification, outHash, authorisation, ring, pending nullifiers, vault) with named rejection reasons; verify with tests for each rejection and for acceptance.

## 2. Rounds and scheduling

- [ ] 2.1 Implement the pending round, the full-or-deadline trigger with an injectable clock, and round building through the tool for both modes with a publish callback; verify with a test using a fake clock that a short recursive round is padded and published at the deadline and that an empty round is not built.
- [ ] 2.2 Keep intake open while a round is being built; verify with a test that a transfer submitted during building lands in the next round.

## 3. Idle work and recovery

- [ ] 3.1 Implement the idle refill of the padding stock and the warm-up of level programs and preprocessed commitments; verify with a test that the stock returns to its level after a padded round.
- [ ] 3.2 Implement recovery from genesis plus round transactions through the chain reader with a disagreement check; verify with a test that a coordinator restarted after several rounds has the same ledger.

## 4. Entry point and documentation

- [ ] 4.1 Add `bin/pool_coordinator.dart` reading a config file and wiring an in-memory publish callback (real transport later); verify it starts against a test pool and prints its mode and ledger.
- [ ] 4.2 Add the "Coordinator service (built)" section to `docs/ZK_SHIELDED_POOL_DESIGN.md`.
