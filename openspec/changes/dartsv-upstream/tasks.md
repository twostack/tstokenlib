## 1. Commit the dartsv changes

- [ ] 1.1 In `../../dartsv`, review the working-tree diff, commit it on a `tstokenlib` branch with a message naming the three changes, and verify `git status` is clean there.
- [ ] 1.2 Try to run dartsv's own tests after aligning its SDK constraint; verify either they run or the failure is recorded in the README.

## 2. Regression tests

- [ ] 2.1 Add tests for FindAndDelete with a signature push in the script, for `ScriptException.toString`, and for the `OP_EQUALVERIFY` diagnostic, in dartsv if its runner works, else in `test/dartsv_patches_test.dart`; verify they pass and fail against unpatched behaviour.

## 3. Pin and document

- [ ] 3.1 Record the dartsv commit hash in the README with a check script (`tool/check_dartsv.dart`) that compares it with the checkout; verify the full suite passes with the pinned checkout and the check fails on another commit.
- [ ] 3.2 Update the dartsv open item in `docs/ZK_SHIELDED_POOL_DESIGN.md` to point at the branch and tests.
