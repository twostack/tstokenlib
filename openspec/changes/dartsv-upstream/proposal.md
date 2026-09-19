## Why

The pool's scripts do not run on the published `dartsv`. Two patches it depends on live uncommitted in one local checkout, and the checkout is wired in through a `pubspec_overrides.yaml` that is gitignored and holds an absolute path, so `pubspec.yaml` still resolves `dartsv: ^3.0.0` from pub.dev. A fresh checkout on another machine, or any Opus session on a different box, silently builds against unpatched dartsv and fails at run time rather than at resolution. Any second machine and any future release of the pool depends on changes that exist in one working tree.

## What Changes

- The two uncommitted dartsv patches are committed to dartsv's `master`, the version is bumped and a new `dartsv` is published to pub.dev.
- This repository moves to that published version in `pubspec.yaml`, and the gitignored path override is no longer needed: the version constraint is the pin.
- Regression tests for the patched behaviour live in this repository, because dartsv's own test runner cannot load any test file on this machine.
- No behaviour of the pool changes: this is dependency hygiene (skip_specs).

## The patches

Investigation while applying this change found that the set is not the one this proposal first named. `ScriptException.toString` and the `OP_EQUALVERIFY` hex diagnostic are already committed in dartsv, and the tests confirm they survive reverting the working tree. What is uncommitted is:

- `SVScript.removeAllInstancesOf` (FindAndDelete) rewritten as a single linear pass. The previous version allocated a script-sized buffer per opcode, which exhausted the heap on scripts of a few hundred KB.
- The 1,000-element stack limit applied only before Genesis. After Genesis BSV bounds stack memory by policy instead. This one was not named in the original proposal and is consensus-relevant, not a diagnostic: without it dartsv rejects every pool script with `SCRIPT_ERR_STACK_SIZE`.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

(none; `skip_specs: true`)

## Impact

- `../../dartsv` (commits on `master`, version bump, changelog, publish), `pubspec.yaml` (published version constraint), `README.md` and the dartsv open item in `docs/ZK_SHIELDED_POOL_DESIGN.md`.
- Numbers: none; the check is that this repository's full suite passes against the published dartsv with no path override.
