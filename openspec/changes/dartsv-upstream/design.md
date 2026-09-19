## Context

`dartsv` is a path dependency (`../../dartsv/`) with three local modifications the pool relies on (see proposal.md). Its test runner fails before running because of an SDK/tooling mismatch, so the modifications have no tests of their own.

## Goals / Non-Goals

**Goals:**
- Every dartsv modification committed, tested and referenced from this repository by an immutable ref.

**Non-Goals:**
- Upstreaming to the public dartsv (a later decision), repairing unrelated dartsv tests.

## Decisions

- **Branch, not fork copy.** Commit on a `tstokenlib` branch in the dartsv checkout; pin `pubspec.yaml` to the path dependency plus a documented commit hash (path dependencies cannot pin, so the README records the hash and a script checks it). Alternative: vendoring dartsv into this repository, rejected for size and licence bookkeeping.
- **Tests in dartsv where its runner works, else here.** Try `dart test` in dartsv after aligning its SDK constraint; if it still fails, put the three regression tests in `test/dartsv_patches_test.dart` here and say so in the README.

## Risks / Trade-offs

- [Runner stays broken] Tests live here → acceptable, documented.
- [Path dependency drift] Someone checks out a different dartsv commit → the check script fails loudly in CI or on `dart test`.
