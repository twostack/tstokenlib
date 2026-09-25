## Context

`ShieldedCoordinator.intake` checks a submission in cost order, the proof last, then adds it to the pending round and closes the round when it is full. The deadline alarm closes it too. Both happen synchronously, inside the library. The pool coordinator's change `deposit-on-seen` (../pool-coordinator/openspec/changes/deposit-on-seen/design.md, decision 1) needs a deposit's place held while it broadcasts the covenant. That design records the rejected alternatives: doing it all in the server, and deferring closes.

## Goals / Non-Goals

**Goals:** hold an admitting deposit's place with no window in which its round builds without waiting for it. Never ask the caller about a submission that failed a check. Change nothing for a coordinator built without the hook.

**Non-Goals:** bounding the hook's time. The caller owns its timeouts, as it owns `funding`'s, and the fake clock in tests has no real timers. No new refusal reason.

## Decisions

1. **The hook's shape.** It is `Future<String?> Function(Transaction covenant)`: null when admitted, a sentence when not. A throw counts as a refusal naming the error. A sentence rather than a result type, because the only thing the library does with a refusal is put it in a `depositCovenant` reply.

2. **The entry point.** It is asynchronous, beside the synchronous one: `receiveBytes`, `receive` and `admit` mirror `submitBytes`, `submit` and `intake`, and return futures. For anything but a deposit with a hook, the future completes at once with what `intake` returns. The synchronous API is left alone, so every existing caller and test keeps its meaning.

3. **The reservation is the pending entry itself.** The entry is added with the round number it will be accepted into, and carries its admission future. It counts toward capacity, `deposits`, `nullifiers` and `withdrawn` exactly as an accepted entry does, so every existing check sees it without a special case. A refusal while it is still pending rebuilds the pending round without it, keeping `openedAt`. If that leaves the round empty, the refusal cancels the alarm and clears `openedAt`, as an empty pending round has none.

4. **Closing waits.** `_buildAndPublish` gets a first stage, `admission`, which awaits every open admission in the closed round. It then keeps only the admitted entries, with no second reply: the refusal already went back through the entry point's future. If nothing is left, the round ends as a round of expired transfers does, with null and nothing built.

5. **A round that fails and is restored** puts its entries back as they are. Their admissions have ended, so they carry no open futures.

## Risks / Trade-offs

- **A hook that never completes holds its round forever.** → Documented on the hook: the caller must bound it. The coordinator's hook is bounded at 20 s.
- **A round closed on capacity** may be full of admitting deposits that are then all refused, leaving it empty. → The build returns null, as for an all-expired round, and the refusals were already replied.
