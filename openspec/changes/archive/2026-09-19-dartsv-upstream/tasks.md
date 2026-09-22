## 1. Commit and publish dartsv

- [x] 1.1 In `../../dartsv`, commit the two library patches (FindAndDelete, the post-Genesis stack limit) to `master` with a message naming both, leaving the maintainer's unrelated test work in the tree; verify `git log` shows the commit and `git diff --stat` shows only that unrelated work.
- [x] 1.2 Try to run dartsv's own tests after aligning its SDK constraint; verify either they run or the failure is recorded in the README.
- [x] 1.3 Bump dartsv to 3.1.0 with a changelog entry naming both patches, and verify `dart pub publish --dry-run` reports the package is ready.
- [x] 1.4 Publish to pub.dev (`dart pub publish`, run by the maintainer) and verify the new version resolves.

## 2. Regression tests

- [x] 2.1 Add tests for FindAndDelete, the post-Genesis stack limit, `ScriptException.toString` and the `OP_EQUALVERIFY` diagnostic, in dartsv if its runner works, else in `test/dartsv_patches_test.dart`; verify they pass and fail against unpatched behaviour.

## 3. Depend on the published version

- [x] 3.1 Move `pubspec.yaml` to the published `dartsv` version, remove the path override from the workflow and rewrite the README's dartsv section accordingly; verify `dart pub get` resolves the published version with no `pubspec_overrides.yaml` present and the full suite passes.
- [x] 3.2 Update the dartsv open item in `../../../../docs/LEGACY_ZK_SHIELDED_POOL_DESIGN.md` to point at the published version and the tests.
