## Why

The pool's scripts run only on a patched dartsv: the FindAndDelete fix (`removeAllInstancesOf` inside the interpreter), the `ScriptException.toString`, and the `OP_EQUALVERIFY` diagnostics live uncommitted in the local checkout at `../../dartsv`, whose own test runner is broken by an SDK mismatch, so they are validated only through this repository's suite. Any second machine, any Opus session and any future release of the pool depends on changes that exist in one working tree.

## What Changes

- The dartsv changes are committed on a branch of the dartsv checkout with a test for each (FindAndDelete against a script containing the signature push, the exception message, the diagnostic), and its test runner is repaired or the tests are run through a documented command.
- This repository pins the dartsv dependency to that branch or commit and documents it in the README and the design doc's open items.
- No behaviour of the pool changes: this is dependency hygiene (skip_specs).

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

(none; `skip_specs: true`)

## Impact

- `../../dartsv` (branch, tests, tooling), `pubspec.yaml` (dependency reference), `README` and `docs/ZK_SHIELDED_POOL_DESIGN.md` open items.
- Numbers: none; the check is that this repository's full suite passes against the pinned dartsv on a clean checkout.
