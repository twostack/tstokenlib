## Context

`dartsv` is declared in `pubspec.yaml` as `dartsv: ^3.0.0` from pub.dev. The patched checkout at `../../dartsv` reaches the build only through `pubspec_overrides.yaml`, which `.gitignore` excludes and which names an absolute path under one user's home directory. Two patches the pool depends on are uncommitted in that checkout. See proposal.md for what they are and why the published package is not enough.

## Goals / Non-Goals

**Goals:**
- The patches published, so any checkout of this repository resolves a dartsv that runs the pool's scripts.
- Regression cover for the patched behaviour that runs in this repository's working test runner.

**Non-Goals:**
- Repairing the Flutter install whose Dart SDK breaks dartsv's test runner.
- Repairing unrelated dartsv tests, or upstreaming beyond the maintainer's own package.

## Decisions

- **Publish, do not branch.** Commit to dartsv's `master`, bump the version and publish to pub.dev, then move `pubspec.yaml` to that version. Supersedes this change's first design, which put the patches on a `tstokenlib` branch and recorded the commit hash in the README with a check script. That was rejected once applying it showed the real hole: the path dependency is gitignored and machine-absolute, so a recorded hash documents the pin without creating one. A published version is the pin, and it removes `pubspec_overrides.yaml` from the workflow rather than documenting it. Alternative considered: a git dependency on the dartsv repository, which pins without publishing but leaves consumers of tstokenlib pulling from GitHub.
- **Minor version bump.** 3.0.0 to 3.1.0. Neither patch breaks an existing caller: FindAndDelete keeps its contract and gets faster, and the stack-limit change only lets post-Genesis scripts that previously failed succeed. Pre-Genesis behaviour is unchanged and a test holds it in place.
- **Tests stay in this repository.** dartsv's runner cannot load any test file on this machine, including a trivial one-expectation file: the Dart SDK bundled with the Flutter install no longer ships `frontend_server.dart.snapshot`, which the runner asks for when compiling that package. Raising dartsv's SDK constraint to 3.4, raising its `test` constraint across 1.24.6, 1.25.2, 1.31.1 and the exact 1.30.0 this repository runs on, and clearing its kernel cache all leave the failure unchanged. `test/dartsv_patches_test.dart` covers all four patched behaviours here instead, and is verified to fail against unpatched dartsv.
- **The publish itself is the maintainer's.** Everything up to and including `dart pub publish --dry-run` is prepared here; the irreversible push to pub.dev is run by the user, since it publishes under their identity and cannot be undone after the retraction window.

## Risks / Trade-offs

- [Published version lags the checkout] Someone patches dartsv locally again and forgets to publish → the override is gone from the documented workflow, so a local patch is a deliberate act rather than the default state.
- [Unrelated working-tree changes] The dartsv checkout also holds the maintainer's own unrelated test work → the patch commit takes the two library files only and leaves that work in the tree.
- [Publish window] Until the new version is on pub.dev, this repository cannot resolve it → `pubspec.yaml` moves in the same step as the publish, and the override stays valid in the meantime.
