## Why

The pool coordinator (../pool-coordinator, change `deposit-on-seen`) is moving deposits from "the depositor broadcasts the covenant and submits it once mined" to "the depositor hands the covenant to the coordinator, which broadcasts it and admits the deposit once ARC reports it seen on the network". The broadcast takes 4 to 5 s (ARC with X-WaitFor SEEN_ON_NETWORK, live testnet round 2, pool-coordinator docs/DESIGN.md). Intake here is synchronous and closes rounds from inside itself (full, or its own deadline alarm). So a round could close while its deposit is still being broadcast. The covenant would then name a spent PP3 and stay locked until its refund height, about a day. The library has to hold the deposit's place while the caller admits it.

## What Changes

- An optional admission hook on `ShieldedCoordinator`, and an asynchronous entry point beside `submitBytes`, `intake` and `submit`. With no hook, nothing changes.
- With the hook, a deposit that passes every check (the proof last) is added to the pending round at once, marked admitting. It holds its place in capacity, the receipt slots, the covenant's pending key and the nullifiers while the hook runs. It is accepted when the hook reports it admitted. When the hook refuses, it leaves the pending round with a `depositCovenant` refusal naming the hook's reason.
- Closing a round waits for the admissions still open in it, and builds without the refused ones, padding in their places.
- No wire change: no new `RefusalReason`, no new message.

## Capabilities

### Modified Capabilities

- `pool-coordinator`: "Deposits by covenant". The covenant no longer has to be mined; a caller may admit it before the round is built, with the deposit's place held meanwhile.
- `pool-protocol`: "No secrets in a message". The deposit transaction is published by the coordinator, not only once mined.

## Measured numbers and bounds

- **Intake cost:** unchanged. The hook is called after the 20 ms proof verification, never before, so a refused deposit costs no admission. That ordering is a requirement.
- **A round that closes during an admission waits for it.** The wait is bounded by the caller's hook (20 s in the coordinator's design). Only the coordinator's measurement task (its 7.3) checks it; no library number moves.

## Non-functional contract

- **Untrusted input:** the hook is reached only by a submission that passed every check. The receipt-slot cap counts admitting deposits. Requirement.
- **Secrets and privacy:** nothing new; the covenant transaction was already in the submission. Requirement text updated.
- **Trust:** the library trusts the hook's answer as it trusts `funding`; what "admitted" means is the caller's.
- **Determinism:** a round is built from the entries admitted when it closes; given the same admissions, the same round.
- **Compatibility:** additive API; with no hook the behaviour and every existing test are unchanged. Requirement.
- **Performance and resources:** one pending future per admitting deposit, at most the receipt slots (8) a round.
- **Failure behaviour:** a hook that throws counts as a refusal naming the error; the place is released.

## Impact

- `lib/src/shielded_pool/shielded_coordinator.dart`; `test/shielded_coordinator_test.dart`.
- A patch release on the 2.0.x line (2.0.2, from the v2.0.1 tag) for the coordinator's release branch, and the next minor on main. Publishing needs the user's go-ahead.
