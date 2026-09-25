## 1. The hook and the reservation

- [x] 1.1 Add the optional `admitDeposit` hook to `ShieldedCoordinator` and `ShieldedCoordinator.open`, and add `receiveBytes`, `receive` and `admit`. With no hook, or with no deposit, they return what `submitBytes`, `submit` and `intake` do. Verify that the existing `test/shielded_coordinator_test.dart` passes unmodified, and verify "No admitting caller".
- [x] 1.2 Reserve through the pending entry and release on refusal (design 3). Verify "Held while admitted" and "Admission refused" with a hook that completes when the test says so. Verify also that a hook that throws is a refusal naming the error.
- [x] 1.3 Add the `admission` stage to `_buildAndPublish` (design 4). Verify "The deadline during an admission" both ways with the fake clock, building the round.
- [x] 1.4 Verify "A failing check is never admitted": a counting hook is never called for a bad proof, a covenant for another PP3, a refund too soon or no slot left. Mutation test: call the hook before `_check` and confirm the test fails.

## 2. Record and release

- [x] 2.1 Append a dated section to docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md: the hook, the reservation, why the library holds the place, and the coordinator change it serves. Verify that `dart analyze lib test` is clean and that the coordinator and protocol suites pass.
- [ ] 2.2 Back-port to a 2.0.x branch from the v2.0.1 tag as 2.0.2, and run the pool-coordinator suite against it through a path override. Publish 2.0.2 and the main line's next minor only with the user's go-ahead.
