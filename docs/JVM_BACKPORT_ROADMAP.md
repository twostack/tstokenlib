# JVM-to-Dart Backport Roadmap

tstokenlib4j and libspiffy4j (JVM) have diverged from their Dart counterparts with changes covering terminology, signing, paired transactions, and provisioning. This roadmap captures all backport-worthy items in dependency order, phased to minimize risk while maximizing cross-language consistency at each milestone.

---

## Dependency Graph

```
Phase 0 (SM Rename)  ──────────────────────────> Phase 4 (SigningCallback tstokenlib)
                                                       |
Phase 1a (3-arg Signing) ──+──> Phase 2 (Paired TX) ──+──> Phase 3 (changeAddress) ──> Phase 5 (Provisioning)
Phase 1b (TX Lookup)    ───+                           |
                                                       |
                              (pattern reference) ─────+
```

## Summary

| Phase | Items | Library | Breaking? | Risk | Scope |
|-------|-------|---------|-----------|------|-------|
| 0 | SM Rename | tstokenlib | Names only | Low | 13 files |
| 1 | 3-arg Signing + TX Lookup | libspiffy | No | Low | 3-4 files |
| 2 | Paired Witness TX | libspiffy | Return type | Medium | 4-5 files |
| 3 | changeAddress Removal | libspiffy | Field removal | Med-High | 6-8 files |
| 4 | SigningCallback Abstraction | tstokenlib | No | Medium | 8 files (2 new) |
| 5 | Funding Provisioning | libspiffy | New subsystem | High | 11-13 files (3 new) |

---

## Phase 0: SM Archetype Rename (tstokenlib)

**Priority**: Immediate | **Risk**: Low | **Breaking**: API names only | **Files**: 13

Pure terminology alignment with zero behavioral/bytecode impact. Independent of all other phases. The JVM side completed this in commit `0f79c00` (496 insertions, 460 deletions across 21 files).

### Rename Mapping

| Old | New |
|-----|-----|
| `merchant` / `merchantPKH` | `operator` / `operatorPKH` |
| `customer` / `customerPKH` | `counterparty` / `counterpartyPKH` |
| `custReward` | `counterpartyShare` |
| `merchPay` | `operatorShare` |
| `merchRefund` | `operatorRecovery` |
| `milestone` / `milestoneCount` | `checkpoint` / `checkpointCount` |

### Files

Library sources (8 files):
- `lib/src/script_gen/pp1_sm_script_gen.dart` (largest -- ~135 occurrences)
- `lib/src/builder/pp1_sm_lock_builder.dart`
- `lib/src/builder/pp1_sm_unlock_builder.dart`
- `lib/src/transaction/state_machine_tool.dart`
- `lib/src/builder/pp1_at_lock_builder.dart` (comments only)
- `lib/src/builder/pp1_at_unlock_builder.dart` (comments only)
- `lib/src/script_gen/pp1_at_script_gen.dart` (comments only)
- `lib/src/transaction/appendable_token_tool.dart` (comments only)

Tests (4 files):
- `test/sm_token_test.dart` (~275 occurrences)
- `test/at_token_test.dart` (comments only)
- `test/state_machine/definition_test.dart`
- `test/state_machine/header_layout_test.dart`

Templates (1 file):
- `templates/sm/pp1_sm.json` (placeholder names)

### Verification

- `dart test` passes
- `grep -r 'merchant\|custReward\|merchPay\|merchRefund' lib/ test/ templates/` returns zero hits
- Cross-language vectors file does not contain SM vectors, so byte-level validation is unaffected

---

## Phase 1: Foundation Interfaces (libspiffy)

**Priority**: High | **Risk**: Low | **Breaking**: No | **Depends on**: Nothing

Two independent, additive interface extensions that all later phases build on.

### 1a. 3-Arg Signing Callback

Add `scriptPubKey` parameter to the signing path so plugins can add custom inputs (witness outputs, PP3 tokens) and the signing actor resolves the correct HD key from the locking script.

Current (2-arg):
```dart
typedef SigningCallback = Uint8List Function(Uint8List sighash, int inputIndex);
```

Target (backward-compatible 3-arg):
```dart
typedef SigningCallbackWithScript = Uint8List Function(
    Uint8List sighash, int inputIndex, Uint8List scriptPubKey);
```

`CallbackTransactionSigner` accepts either variant; 3-arg delegates to 2-arg by default.

**Files**:
- `libspiffy/lib/src/services/callback_transaction_signer.dart`

### 1b. TransactionLookup Callback

Let plugins resolve parent/witness transactions from the wallet's append-only log.

```dart
typedef TransactionLookup = String? Function(String txid);
```

**Files**:
- `libspiffy/lib/src/plugin/plugin_types.dart` -- add typedef + optional field on `PluginTransactionRequest`
- `libspiffy/lib/src/actors/payment_coordinator_actor.dart` -- wire lookup from read-model storage

### Verification

All existing tests pass unchanged. New unit tests for 3-arg callback and lookup resolution.

---

## Phase 2: Paired Witness TX Support (libspiffy)

**Priority**: High | **Risk**: Medium | **Breaking**: Return type change | **Depends on**: Phase 1

Extend the plugin result to carry both primary and witness TX atomically. Needed for AT issuance where a token TX and its witness TX must be broadcast together from a single UTXO reservation.

### New Class

```dart
class TransactionBuilderResult {
  final String txid, rawHex;
  final int feeSats;
  final String? witnessTxid, witnessRawHex;
  final int? witnessFeeSats;
  bool get hasPairedWitness => witnessTxid != null;
}
```

### Files

- `libspiffy/lib/src/plugin/plugin_types.dart` -- add result class
- `libspiffy/lib/src/plugin/transaction_builder_plugin.dart` -- change `buildTransaction` return type
- `libspiffy/lib/src/actors/payment_coordinator_actor.dart` -- handle dual-broadcast path
- Integration test files -- update mock plugin implementations

### Verification

Single-TX flows work via convenience constructor. Paired-witness test verifies atomic recording. Existing token lifecycle test adapted and passes.

---

## Phase 3: changeAddress Removal from Plugin API (libspiffy)

**Priority**: Medium | **Risk**: Medium-High | **Breaking**: Field removal | **Depends on**: Phases 1, 2

Access-control hardening. Plugins should not derive addresses or manage wallet internals. The coordinator derives change address internally from the aggregate's `addressToIndex` map, matching the JVM's approach (commit `5ef5786`).

### Files

- `libspiffy/lib/src/plugin/plugin_types.dart` -- remove `changeAddress` field
- `libspiffy/lib/src/actors/payment_coordinator_actor.dart` -- derive internally
- `libspiffy/lib/src/actors/coordinator_messages.dart` -- may need adjustment
- Plugin implementations and tests that reference `request.changeAddress`

### Verification

Grep all consumers for `changeAddress` references. All integration tests pass. Coordinator correctly derives from aggregate state.

---

## Phase 4: SigningCallback Abstraction (tstokenlib)

**Priority**: Medium | **Risk**: Medium | **Breaking**: No (additive) | **Depends on**: Phase 0 (naming), Phase 1 (pattern reference)

Decouple tstokenlib's transaction tools from dartsv's `TransactionSigner`, matching the JVM's `SigningCallback` + `SignerAdapter` pattern. Enables KMS/HSM integration at the token layer without exposing private keys to the token library.

### New Files

- `tstokenlib/lib/src/transaction/signing_callback.dart` -- typedef (1-arg base + 3-arg)
- `tstokenlib/lib/src/transaction/signer_adapter.dart` -- wraps callback into dartsv `TransactionSigner`

### Modified (additive overloads)

All 6 tool files:
- `token_tool.dart`
- `fungible_token_tool.dart`
- `restricted_token_tool.dart`
- `restricted_fungible_token_tool.dart`
- `appendable_token_tool.dart`
- `state_machine_tool.dart`

### Verification

New `signer_adapter_test.dart` -- callback-wrapped signing produces same signature as direct-key. All existing tool tests pass unchanged (existing `TransactionSigner` API preserved).

---

## Phase 5: Funding Provisioning System (libspiffy)

**Priority**: Lower | **Risk**: High | **Breaking**: New subsystem | **Depends on**: Phases 1, 2, 3

The largest item. Introduces earmark-aware UTXO inventory, auto-provisioning by purpose, and the `provisionFunding()` plugin method. The JVM implementation uses a two-level funding tree: a split TX (level 1) fans out into earmark TXs (level 2), each placing the target amount at a specific vout for protocol constraints.

### New Files

- `libspiffy/lib/src/models/utxo_policy.dart` -- target lifecycle steps, thresholds, auto-provision flag
- `libspiffy/lib/src/models/utxo_inventory.dart` -- per-purpose UTXO counts, lifecycle step bottleneck
- `libspiffy/lib/src/plugin/provisioned_transaction.dart` -- role (split/earmark), purpose, funding vout/sats

### Modified (~8-10 files)

- `transaction_builder_plugin.dart` -- add `provisionFunding()` method
- `payment_coordinator_actor.dart` -- auto-provisioning logic, earmark-aware UTXO selection
- `wallet_commands.dart` / `wallet_events.dart` -- provisioning command/event types
- `bitcoin_wallet_aggregate.dart` -- handle provisioning lifecycle
- `wallet_projection.dart` -- earmarked UTXOs in read model
- Storage layer files for earmark persistence

### Verification

Unit tests for model classes. Integration test: provision then execute token lifecycle with provisioned UTXOs. Regression: all existing payment flows unaffected. Earmark accounting: provisioned UTXOs correctly reserved and not double-spent.
