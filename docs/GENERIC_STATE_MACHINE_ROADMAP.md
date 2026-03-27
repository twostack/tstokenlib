# Verified Generic State Machine Compiler — Roadmap

A phased plan to generalize PP1_SM from a single hardcoded funnel state machine into a runtime compiler that accepts arbitrary state machine definitions, formally verifies them, and emits deployable Bitcoin Script — with structural proof that the generated code faithfully implements the verified definition.

---

## Scope and Constraints

**In scope:**
- Arbitrary state sets, transition tables, roles, auth rules, guards, and field effects
- Fixed output topology (same 5-output standard / 6-output timeout / 7-output settle structure as PP1_SM)
- No splits, no merges — in-token state transitions only
- Runtime (server-side) code generation from a structured definition
- Formal verification of abstract machine properties (reachability, deadlock freedom, invariants)
- Structural conformance proof that generated Script matches the verified definition

**Out of scope:**
- Variable output topologies per transition
- Composable / nested state machines
- General-purpose smart contract language
- Client-side code generation

**Key design decision:** The "generic" part lives in the tooling (compiler + verifier), not on-chain. Each generated contract is optimized for its specific machine. There is no universal interpreter contract.

---

## Architecture Overview

```
StateMachineDefinition (Dart object / JSON)
         │
         ├──► WellFormednessChecker ──► pass/fail
         ├──► ModelChecker ──────────► pass/fail + counterexamples
         ├──► InvariantChecker ──────► pass/fail + witnesses
         │         (all must pass)
         │
         ├──► HeaderLayoutEngine ────► byte offsets, pushdata prefixes
         ├──► ScriptCompiler ────────► script bytes
         ├──► ConformanceChecker ────► structural proof certificate
         │
         └──► DartCodeGen ──────────► LockBuilder, UnlockBuilder, Tool
```

### Correctness Argument (Three Independent Layers)

| Layer | Claim | Proven By |
|-------|-------|-----------|
| A. Abstract machine | Definition satisfies all required properties | Model checker (graph exploration + abstract interpretation) |
| B. Compilation | Generated Script faithfully implements verified definition | Conformance checker (decompile and compare) |
| C. Platform | Reusable primitives (OCS, inductive proof, tx reconstruction) are correct | Existing test suite + interpreter verification (proven once, shared by all machines) |

---

## Guard Taxonomy

Transitions in PP1_SM are currently protected by five structural guard types, all evaluated against compile-time constants or issuance-time header values. For the generic state machine to support meaningful BPMN-modeled business processes, we need two additional guard types that evaluate runtime data supplied in the scriptSig.

### Existing Guard Types

These are already implemented in PP1_SM and generalize directly.

#### StateGuard

Checks `currentState` against one or more expected values.

| Property | Value |
|---|---|
| Evaluates | `currentState` (1-byte mutable header field) |
| Defined at | Compile time (transition table) |
| Script pattern | `BIN2NUM <constant> EQUALVERIFY` or OR-chain for multiple source states |
| Example | "Only fires from ACTIVE or PROGRESSING" |
| PP1_SM usage | Every transition; Confirm uses IF/ELSE for two source states |

#### AuthGuard

Verifies one or more signatures against immutable role PKHs from the header.

| Property | Value |
|---|---|
| Evaluates | Signature(s) in scriptSig against immutable PKH(s) in header |
| Defined at | Issuance time (PKHs fixed in header) |
| Script pattern — single | `PICK pubkey → HASH160 → compare PKH → EQUALVERIFY → PICK sig → PICK pubkey → CHECKSIG → VERIFY` |
| Script pattern — dual | Two sequential single-sig checks against different role PKHs |
| Example | "Merchant signs" or "Merchant and customer both sign" |
| PP1_SM usage | Every transition; enroll/settle/timeout = single-sig, confirm/convert = dual-sig |

#### BitmaskGuard

Checks that a specific bit is set in the immutable `transitionBitmask` header field. Allows the issuer to enable/disable transitions at token creation time without changing the script.

| Property | Value |
|---|---|
| Evaluates | `transitionBitmask` (1-2 byte immutable header field) |
| Defined at | Issuance time (bitmask value chosen by issuer) |
| Script pattern | `BIN2NUM <2^bitIndex> DIV 1 AND VERIFY` |
| Example | "Bitmask bit 2 must be set for self-loop Confirm" |
| PP1_SM usage | Enroll (bit 0), Confirm (bit 1 or 2), Convert (bit 3), Settle (bit 4), Timeout (bit 5) |

#### FieldGuard

Evaluates a mutable header field against a compile-time constant. Currently only used for one predicate in PP1_SM, but the pattern generalizes to any numeric comparison.

| Property | Value |
|---|---|
| Evaluates | Any mutable header field (COUNTER or AMOUNT type) |
| Defined at | Compile time (field reference + comparator + constant) |
| Script pattern | `FROMALTSTACK BIN2NUM <constant> <comparator-opcode> VERIFY` |
| Comparators | `GREATERTHAN`, `GREATERTHANOREQUAL`, `LESSTHAN`, `LESSTHANOREQUAL`, `EQUAL`, `NUMNOTEQUAL` |
| Example | "milestoneCount > 0" |
| PP1_SM usage | Convert requires milestoneCount > 0 |

#### TimelockGuard

Enforces a time-based condition by comparing the transaction's `nLockTime` (extracted from the sighash preimage) against an immutable header field.

| Property | Value |
|---|---|
| Evaluates | `nLockTime` from sighash preimage vs immutable `timeoutDelta` in header |
| Defined at | Issuance time (timeoutDelta value) |
| Script pattern | Extract nLockTime from preimage[len-8:len-4], extract nSequence from preimage, verify `nSequence < 0xFFFFFFFF` (activates nLockTime), verify `nLockTime >= timeoutDelta` |
| Example | "Only after the deadline (Unix timestamp or block height)" |
| PP1_SM usage | Timeout transition only |

### New Guard Types

These do not exist in PP1_SM. They enable transitions to be gated by **runtime conditions** — data supplied in the scriptSig at spend time, rather than constants known at compile time. This is what makes the BPMN integration genuinely useful for real business processes.

#### DataGuard

Extracts a value from the event payload in the scriptSig and evaluates it against a compile-time predicate. The event payload is the same data that gets hashed into the commitment chain — DataGuard inspects it before hashing.

| Property | Value |
|---|---|
| Evaluates | Byte range within `eventData` (supplied in scriptSig) |
| Defined at | Compile time (byte offset, byte length, comparator, constant) |
| Script pattern | `PICK eventData → <offset> SPLIT NIP → <length> SPLIT DROP → BIN2NUM → <constant> <comparator> → VERIFY` |
| Example | "Invoice amount (bytes 0-7 of event payload) must exceed 1000 satoshis" |
| Header impact | None — the guard definition is baked into the script body, not the header |

**Design considerations:**

- The event payload format becomes part of the state machine contract — the compiler must document the expected byte layout per transition so that clients construct valid payloads.
- Multiple DataGuards per transition are allowed (e.g., check amount > 0 AND status byte == 0x01).
- The same event payload is still hashed into the commitment chain after guard evaluation, so the guarded values become part of the tamper-proof audit trail.
- For the BPMN modeler, DataGuard maps to a **condition expression** on a sequence flow leaving an exclusive gateway. The property panel lets the designer specify which payload field to inspect and what condition to apply.

**Definition model extension:**

```dart
class DataGuardDef extends GuardDef {
  final int payloadOffset;    // byte offset into eventData
  final int payloadLength;    // bytes to extract (1, 2, 4, or 8)
  final GuardOp op;           // GT, GTE, EQ, NEQ, LT, LTE
  final int value;            // compile-time constant comparand
  final String description;   // human-readable label for BPMN display
}
```

**Script cost:** ~15 bytes per DataGuard (SPLIT + SPLIT + BIN2NUM + constant + comparator + VERIFY).

#### OracleGuard

Verifies a Rabin signature from a trusted oracle over the event payload (or a subset of it), then optionally evaluates a predicate on the signed data. This enables transitions gated by external real-world conditions — "the oracle attests that X happened."

| Property | Value |
|---|---|
| Evaluates | Rabin signature in scriptSig over event payload, verified against immutable oracle public key in header |
| Defined at | Issuance time (oracle Rabin public key stored as immutable header field) |
| Script pattern | `PICK oracleSig → PICK eventData → <oraclePubKey from header> → RABIN_VERIFY → VERIFY`, optionally followed by DataGuard on the verified payload |
| Example | "Oracle attests goods were delivered (signed attestation in event payload)" |
| Header impact | Adds one immutable field per oracle: Rabin public key (variable size, typically 128-512 bytes depending on security level) |

**Design considerations:**

- OracleGuard adds a new role type (`AuthType.RABIN_ORACLE`) that is not a signing party (doesn't use CHECKSIG) but whose public key is stored in the header as an immutable field.
- The oracle is a **passive verifier**, not an active participant — it signs attestations off-chain, and the spender includes the signed attestation in the scriptSig. The oracle never needs to construct or sign Bitcoin transactions.
- OracleGuard can be **combined** with DataGuard: the oracle signs the event payload, OracleGuard verifies the signature, then DataGuard inspects the verified payload. This gives "oracle says delivery happened AND delivery value > 1000."
- Multiple oracles per state machine are supported (each gets its own header field). Different transitions can require different oracles.
- For the BPMN modeler, OracleGuard maps to a **message intermediate catch event** or a **service task** — "wait for oracle attestation." The property panel lets the designer select which oracle and optionally add DataGuard conditions on the attested data.

**Definition model extension:**

```dart
class OracleRoleDef extends RoleDef {
  final AuthType authType = AuthType.RABIN_ORACLE;
  final int pubKeySize;  // bytes (determines header space)
}

class OracleGuardDef extends GuardDef {
  final String oracleRole;       // references an OracleRoleDef
  final List<DataGuardDef> dataGuards;  // optional predicates on verified payload
}
```

**Script cost:** Rabin signature verification is ~200-400 bytes depending on key size, plus ~15 bytes per chained DataGuard.

### Guard Composition

A single transition can combine any number of guards. The compiler emits them in a fixed order:

```
1. AuthGuard(s)         — verify signatures first (most expensive to forge)
2. StateGuard           — check current state
3. OracleGuard(s)       — verify oracle attestations (includes Rabin verify)
4. FieldGuard(s)        — check header field predicates
5. DataGuard(s)         — check event payload predicates
6. BitmaskGuard         — check transition is enabled
7. TimelockGuard        — check nLockTime (if applicable)
8. [Inductive proof]    — structural integrity verification
```

All guards are conjunctive (AND) — every guard on a transition must pass. Disjunctive (OR) conditions are modeled as **separate transitions** from the same source state with different guards, which maps naturally to exclusive gateway branches in BPMN.

### Guard Taxonomy Summary

| Guard | What it checks | Data source | When defined | Script cost | Exists today |
|---|---|---|---|---|---|
| StateGuard | Current state value | Header (mutable) | Compile time | ~5 bytes | Yes |
| AuthGuard | Cryptographic identity | scriptSig signature vs header PKH | Issuance time | ~30 bytes/sig | Yes |
| BitmaskGuard | Transition enabled | Header (immutable) | Issuance time | ~8 bytes | Yes |
| FieldGuard | Header field predicate | Header (mutable) | Compile time | ~8 bytes | Yes |
| TimelockGuard | Time/block height | Preimage nLockTime vs header | Issuance time | ~20 bytes | Yes |
| DataGuard | Event payload predicate | scriptSig (runtime) | Compile time | ~15 bytes | **New** |
| OracleGuard | External attestation | scriptSig (runtime) + header pubkey | Issuance time | ~200-400 bytes | **New** |

### Impact on Formal Verification

DataGuard and OracleGuard introduce **runtime-dependent** transitions — whether a transition fires depends on data supplied at spend time, not just on the current state and who signs.

For the model checker, this means:

- **Reachability analysis** must treat DataGuard and OracleGuard conditions as **non-deterministic** — the checker assumes the data *could* satisfy the guard or *could* fail it. This is conservative: if a property holds under non-deterministic guards, it holds under any concrete guard evaluation.
- **Deadlock freedom** must account for the possibility that all DataGuard/OracleGuard conditions on outgoing transitions fail simultaneously. If the only exit from a state is through a DataGuard, the model checker should **warn** that liveness depends on external data availability. A TimelockGuard timeout from that state would resolve the warning.
- **Domain invariants** over guarded fields (e.g., "invoice amount is always positive when entering SETTLED") can be verified if the DataGuard on the incoming transition enforces the predicate. The abstract interpreter tracks DataGuard postconditions as established facts for the target state.

This is analogous to how TLA+ handles external inputs — they're modeled as unconstrained variables in the Next-state relation, and properties must hold for all possible input values.

---

## Phase 1: Definition Model and Header Layout Engine

**Goal:** Establish the data model that drives everything downstream, and the mechanical mapping from definition to on-chain byte layout.

### 1.1 StateMachineDefinition Data Model

Create `lib/src/state_machine/definition.dart`:

- `StateMachineDefinition` — top-level container
- `RoleDef` — named role with auth type (PKH, Rabin, or Rabin oracle)
- `StateDef` — named state with terminal flag, auto-assigned encoding (0x00, 0x01, ...)
- `TransitionDef` — from-states, to-state, required signers, owner-after, guards, effects, timelock
- `GuardDef` — base class for all guard types (see Guard Taxonomy)
  - `FieldGuardDef` — header field comparator (field name, op, constant)
  - `DataGuardDef` — event payload comparator (offset, length, op, constant)
  - `OracleGuardDef` — Rabin oracle attestation (oracle role, optional chained DataGuards)
- `EffectDef` — field name, effect type (SET, INCREMENT, HASH_CHAIN), optional value
- `FieldDef` — name, byte size, field type (COUNTER, HASH, AMOUNT, RAW)
- `PropertyDef` hierarchy — user-defined verification properties (see Phase 3)

Serialization: `toJson()` / `fromJson()` for network transport.

### 1.2 HeaderLayoutEngine

Create `lib/src/state_machine/header_layout.dart`:

- Compute byte offsets and pushdata prefixes from a definition
- Built-in fields always present in fixed order: ownerPKH, tokenId, role PKHs, currentState, custom mutable fields, commitmentHash, transitionBitmask, custom immutable fields
- Produce: `HeaderLayout` with per-field offset, data start, data end, pushdata byte, mutability flag
- Produce: mutable region map (for inductive proof script rebuild)
- Produce: altstack push/pop order

### 1.3 PP1_SM Equivalence Test

Express the existing PP1_SM funnel as a `StateMachineDefinition` and assert that `HeaderLayoutEngine` produces the same 140-byte layout with identical offsets. This is the baseline correctness check — if the engine can reproduce PP1_SM's layout exactly, it handles the general case.

**Deliverables:**
- `lib/src/state_machine/definition.dart`
- `lib/src/state_machine/header_layout.dart`
- `test/state_machine/definition_test.dart`
- `test/state_machine/header_layout_test.dart`

---

## Phase 2: Well-Formedness and Model Checking

**Goal:** Catch design errors in state machine definitions before any code generation. This is the "TLA+ equivalent" layer.

### 2.1 Well-Formedness Checker

Create `lib/src/state_machine/well_formedness.dart`:

Static checks (no graph exploration):
- All states, roles, and fields referenced in transitions exist in the definition
- Terminal states have no outgoing transitions (burn is implicit, not in the transition table)
- Every transition requires at least one signer or uses a timelock
- No duplicate (fromState, selectorOpcode) pairs
- Transition count fits bitmask capacity (≤8 for 1-byte, ≤16 for 2-byte)
- Guard predicates reference mutable fields only
- Effects reference mutable fields only; INCREMENT only on COUNTER fields; HASH_CHAIN only on HASH fields
- At least one terminal state exists
- Initial state (encoding 0x00) is not terminal

Returns: list of `Violation` objects with category, message, and reference to the offending element.

### 2.2 Model Checker (Reachability and Deadlock Freedom)

Create `lib/src/state_machine/model_checker.dart`:

Build the state graph (nodes = states, edges = transitions) and verify:

1. **Forward reachability:** Every state is reachable from the initial state via BFS.
2. **Terminal reachability:** Every non-terminal state can reach at least one terminal state. (No deadlocks.)
3. **Dead-end freedom:** Every non-terminal state has at least one outgoing transition.
4. **Timeout coverage (warning):** If a timeout transition exists, warn for any non-terminal state not in its `fromStates`.
5. **Determinism:** No two transitions share a (fromState, action) pair without distinguishing guards. (For simplicity, the first version may require unique selectors per fromState.)

Counterexamples: when a property fails, return a concrete witness — e.g., the unreachable state, or the path that leads to a deadlock.

### 2.3 Verification Report

Create `lib/src/state_machine/verification_report.dart`:

- Aggregates results from well-formedness and model checking
- Each check: name, status (pass/fail/warn), message, optional counterexample
- Overall verdict: pass only if all checks pass (warnings don't block)
- Serializable to JSON for API responses

**Deliverables:**
- `lib/src/state_machine/well_formedness.dart`
- `lib/src/state_machine/model_checker.dart`
- `lib/src/state_machine/verification_report.dart`
- `test/state_machine/well_formedness_test.dart`
- `test/state_machine/model_checker_test.dart`

---

## Phase 3: Domain Invariant Checking

**Goal:** Support user-defined properties beyond basic graph properties. These are the application-specific assertions that give confidence the state machine does what the designer intended.

### 3.1 Property Language

Extend `PropertyDef` with concrete property types:

| Property Type | Example | Verification Method |
|---------------|---------|---------------------|
| `AuthGateProperty` | "SETTLED is only reachable via transitions requiring merchant" | For every transition T where T.toState == target, check requiredRole ∈ T.requiredSigners |
| `MustPassThroughProperty` | "COMPLETED is unreachable from CREATED without passing through FUNDED" | Remove through-state from graph, check target unreachable from source |
| `NoUnilateralPathProperty` | "buyer cannot unilaterally reach REFUNDED from FUNDED" | Remove all transitions where role is sole signer, check reachability |
| `MonotonicFieldProperty` | "milestoneCount never decreases" | No transition has a SET effect that could decrease the field |
| `StateRequiresFieldProperty` | "CONVERTING requires milestoneCount > 0" | Every path to target passes through a transition that guards or establishes the condition |

### 3.2 Invariant Checker

Create `lib/src/state_machine/invariant_checker.dart`:

- Dispatch on property type
- Graph-based properties: BFS/DFS on modified graphs (node/edge removal)
- Field-dependent properties: abstract interpretation over a simple lattice
  - Counter fields: `{bottom, zero, nonzero, top}`
  - Hash fields: `{bottom, allZeros, nonZero, top}`
  - Forward propagation from initial state to fixed point
  - Check property predicate at target states

### 3.3 Abstract Interpretation Engine

Create `lib/src/state_machine/abstract_interp.dart`:

- `AbstractFieldState` — map from field names to abstract values
- `AbstractDomain` — lattice operations (join, meet, transfer functions for effects)
- `AbstractExplorer` — worklist algorithm over (state × abstractFieldState) pairs
- Termination guaranteed: finite states × finite abstract domain = finite worklist

State space is tiny: even 20 states × 2^5 abstract field combinations = 640 nodes. Runs in microseconds.

**Deliverables:**
- `lib/src/state_machine/invariant_checker.dart`
- `lib/src/state_machine/abstract_interp.dart`
- `test/state_machine/invariant_checker_test.dart`

---

## Phase 4: Script Compiler

**Goal:** Generate Bitcoin Script from a verified definition, reusing the existing proven primitives.

### 4.1 Refactor Existing Emitters

Extract reusable emitters from `pp1_sm_script_gen.dart` into parameterized form:

- `AuthEmitter` — emits single-sig P2PKH check, dual-sig check, or Rabin check. Parameterized by role PKH offset in header.
- `StateGuardEmitter` — emits `currentState == X` or `currentState ∈ {X, Y, Z}`. Parameterized by state encodings.
- `BitmaskGuardEmitter` — emits bitmask bit check. Parameterized by bit index and bitmask field offset.
- `FieldGuardEmitter` — emits field comparison (GT, GTE, EQ, etc.). Parameterized by field offset and constant.
- `DataGuardEmitter` — emits event payload extraction (SPLIT at offset/length) + comparison against constant. Parameterized by payload offset, length, comparator, and constant.
- `OracleGuardEmitter` — emits Rabin signature verification against oracle public key from header, optionally followed by chained DataGuard checks on the verified payload. Parameterized by oracle pubkey field offset and key size.
- `EffectEmitter` — emits INCREMENT (OP_1 OP_ADD), SET (push constant), or HASH_CHAIN (SHA256 chain update). Parameterized by field.
- `TimelockEmitter` — emits nLockTime extraction and comparison. Parameterized by timelock field offset.

These are leaf-level emitters. Each is ~20-50 lines, independently testable.

### 4.2 Inductive Proof Generator

Parameterize the existing inductive proof pattern:

- `InductiveProofEmitter` takes a `HeaderLayout` and emits the generic phases (1-7): preimage validation, parent tx parsing, output extraction.
- `ScriptRebuildEmitter` takes a `HeaderLayout` and emits the PP1 rebuild: splice mutable fields into immutable skeleton. Uses the mutable region map from `HeaderLayout` to compute SPLIT offsets.
- Output topology selection remains fixed: 5-output standard, 6-output timeout, 7-output settle. The emitter selects topology based on transition flags (usesTimelock → 6-output, hasPayouts → 7-output, else → 5-output).

### 4.3 Dispatch Tree Generator

Create `lib/src/state_machine/script_compiler.dart`:

- `StateMachineScriptCompiler.compile(def)` → `SVScript`
- Emit header pushes from `HeaderLayout`
- Emit altstack setup
- Emit dispatch tree: burn (always first), create (always second), then user transitions in definition order
- For each transition: compose the leaf emitters (state guard → bitmask → custom guards → auth → effects → inductive proof)

**Design note — dispatch tree / inductive proof boundary:**

The dispatch tree size varies per definition (PP1_SM: ~600 bytes; a 30-transition machine: ~3 KB). The inductive proof that follows it needs SPLIT offsets computed relative to the total script layout. Two approaches were considered:

1. **Runtime boundary marker** — encode the dispatch tree length as a pushdata constant in the script; the inductive proof reads it at spend time to compute SPLIT positions dynamically. Costs ~3 extra bytes.

2. **Compile-time offset baking** — the compiler knows the dispatch tree size at generation time, so it hardcodes the correct SPLIT offsets into the inductive proof. No runtime marker needed. This is what PP1_SM does today with its hardcoded constants in `PP1SmScriptGen`, generalized to arbitrary definitions.

**Decision: approach 2 (compile-time).** The compiler already knows all sizes when it emits the script — `HeaderLayout` provides the header offsets, and the compiler tracks the dispatch tree size as it emits branches. The `ScriptRebuildEmitter` receives these computed offsets directly. No fixed-size reservation or runtime boundary detection is needed. Each compiled script is self-consistent with its own baked-in offsets, just as PP1_SM is today.

A fixed-size code reservation was also considered (e.g., 4 KB for the dispatch tree, padded with OP_NOPs). This was rejected: it wastes space for simple machines, the fee cost is negligible either way at BSV rates, and compile-time baking achieves the same predictability without dead bytes. Script template matching by prefix is not a requirement — each state machine definition produces a unique script.

### 4.4 PP1_SM Equivalence Test

Compile the PP1_SM funnel definition through the generic compiler. Compare the output script bytes against the handwritten `PP1SmScriptGen.generate()` output. They must be byte-identical (or functionally equivalent if minor opcode ordering differs — verified via interpreter on the same test vectors).

**Deliverables:**
- `lib/src/state_machine/emitters/auth_emitter.dart`
- `lib/src/state_machine/emitters/state_guard_emitter.dart`
- `lib/src/state_machine/emitters/bitmask_guard_emitter.dart`
- `lib/src/state_machine/emitters/field_guard_emitter.dart`
- `lib/src/state_machine/emitters/data_guard_emitter.dart`
- `lib/src/state_machine/emitters/oracle_guard_emitter.dart`
- `lib/src/state_machine/emitters/effect_emitter.dart`
- `lib/src/state_machine/emitters/timelock_emitter.dart`
- `lib/src/state_machine/emitters/inductive_proof_emitter.dart`
- `lib/src/state_machine/emitters/script_rebuild_emitter.dart`
- `lib/src/state_machine/script_compiler.dart`
- `test/state_machine/script_compiler_test.dart`
- `test/state_machine/pp1_sm_equivalence_test.dart`

---

## Phase 5: Conformance Checker

**Goal:** Close the correctness gap between the verified abstract machine and the compiled Script. Prove structurally that the Script implements the definition.

### 5.1 Script Decompiler (Targeted)

Create `lib/src/state_machine/script_decompiler.dart`:

Not a general-purpose decompiler. Exploits the known structure of compiler output:

- Parse opcode stream into header section + dispatch tree
- Identify IF/ELSE branch boundaries
- For each branch, extract:
  - State guard values (the constants compared against currentState)
  - Bitmask bit index
  - CHECKSIG count (→ single-sig vs dual-sig)
  - Target state value (the constant written to currentState in the rebuild)
  - Effect opcodes (OP_1 OP_ADD for INCREMENT, etc.)
  - Timelock presence (nLockTime extraction pattern)

Produces a `DecompiledTransitionTable` — a list of extracted transitions with their properties.

### 5.2 Conformance Comparator

Create `lib/src/state_machine/conformance_checker.dart`:

Compare `DecompiledTransitionTable` against `StateMachineDefinition`:

- For each transition: source states match, target state matches, auth pattern matches, bitmask bit matches, effects match
- Burn branch: terminal state guard matches definition's terminal states
- Header size: matches `HeaderLayout` computation
- Branch count: matches transition count + 2 (burn + create)

### 5.3 Conformance Certificate

Produce a serializable certificate:

```
{
  "definitionHash": "SHA256 of canonical JSON definition",
  "scriptHash": "SHA256 of compiled script bytes",
  "headerSize": 140,
  "transitionCount": 5,
  "checks": [
    {"name": "enroll.stateGuard", "status": "pass", "expected": [0], "found": [0]},
    {"name": "enroll.targetState", "status": "pass", "expected": 1, "found": 1},
    {"name": "enroll.authPattern", "status": "pass", "expected": "single", "found": "single"},
    ...
  ],
  "verdict": "CONFORMANT",
  "compilerVersion": "1.0.0",
  "timestamp": "2026-03-17T..."
}
```

The certificate is **reproducible**: given the same definition, any party can re-run the compiler and conformance checker to obtain the same result.

**Deliverables:**
- `lib/src/state_machine/script_decompiler.dart`
- `lib/src/state_machine/conformance_checker.dart`
- `test/state_machine/conformance_checker_test.dart`

---

## Phase 6: Dart Code Generation

**Goal:** Generate the Dart builder and tool classes that let applications construct transactions for a given state machine without manual script assembly.

### 6.1 LockBuilder Generator

Given a `HeaderLayout`, generate a `*LockBuilder` class:

- Constructor: takes all header field values
- `getScriptPubkey()`: pushes header fields + appends compiled script body
- Field getters: parse header bytes at computed offsets
- `fromScript(SVScript)`: factory constructor that parses an existing script

The generator produces Dart source code (string) that can be written to a file or compiled in memory.

### 6.2 UnlockBuilder Generator

Given a `StateMachineDefinition`, generate a `*UnlockBuilder` class:

- One method per transition: builds the scriptSig with correct stack order
- Correct signature count per transition (single vs dual)
- Padding calculation for witness transactions
- Selector opcode at top of stack

### 6.3 Tool Class Generator

Given a definition, generate a `*Tool` class (high-level API):

- `createIssuanceTxn(...)` — always the same structure
- `createTransitionTxn(transition, ...)` — parameterized by transition name
- `createBurnTxn(...)` — always the same structure
- Transaction topology selection based on transition flags

### 6.4 Test Scaffold Generator

Generate a skeleton test file that exercises the full lifecycle:

- Issue token
- Walk through one representative path from initial state to each terminal state
- Verify each transition via `Interpreter.correctlySpends()`
- The scaffold requires manual completion (funding keys, amounts) but provides the structure

**Deliverables:**
- `lib/src/state_machine/codegen/lock_builder_gen.dart`
- `lib/src/state_machine/codegen/unlock_builder_gen.dart`
- `lib/src/state_machine/codegen/tool_gen.dart`
- `lib/src/state_machine/codegen/test_scaffold_gen.dart`
- `test/state_machine/codegen_test.dart`

---

## Phase 7: End-to-End Validation

**Goal:** Prove the full pipeline works by generating, verifying, and deploying a non-funnel state machine.

### 7.1 Escrow State Machine

Define a 3-role escrow (buyer, seller, arbiter) with states: CREATED → FUNDED → SHIPPED → DISPUTED → COMPLETED/REFUNDED. This exercises:

- 3 roles (vs 2 in funnel)
- Branching paths (SHIPPED can go to COMPLETED or DISPUTED)
- Arbiter-only transitions (resolve for buyer/seller)
- All three auth patterns (single-sig, dual-sig, timelock)

### 7.2 Full Pipeline Test

```
define escrow → verify → compile → conformance check → generate builders →
  issue token → walk every path → interpreter.correctlySpends() on every transition
```

This is the ultimate correctness test: a state machine that was never hand-coded, generated entirely from a definition, verified at every layer, and proven correct by the BSV script interpreter.

### 7.3 PP1_SM Regression

Re-derive PP1_SM funnel through the generic pipeline. Run the existing `sm_token_test.dart` test suite against the generically-generated code. All tests must pass unchanged.

**Deliverables:**
- `test/state_machine/escrow_e2e_test.dart`
- `test/state_machine/pp1_sm_regression_test.dart`

---

## Phase 8: Runtime API

**Goal:** Expose the pipeline as a server-side API for runtime state machine deployment.

### 8.1 Pipeline Orchestrator

Create `lib/src/state_machine/pipeline.dart`:

```dart
class StateMachinePipeline {
  /// Pure function: definition in, verified artifacts out.
  /// Throws VerificationException if any check fails.
  PipelineResult compile(StateMachineDefinition def) {
    WellFormednessChecker(def).check().assertPass();
    ModelChecker(def).check().assertPass();
    InvariantChecker(def).check().assertPass();

    var layout = HeaderLayoutEngine.compute(def);
    var script = ScriptCompiler(def, layout).compile();

    ConformanceChecker(def, script).check().assertPass();

    return PipelineResult(
      scriptHex: script.toHex(),
      headerLayout: layout.toJson(),
      transitionTable: def.transitionTableJson(),
      verificationReport: ...,
      conformanceCertificate: ...,
    );
  }
}
```

### 8.2 JSON Schema for Definitions

Publish a JSON Schema that validates `StateMachineDefinition` payloads before deserialization. Clients can validate locally before submitting to the server.

### 8.3 Determinism Guarantee

Document and test that the pipeline is fully deterministic: same definition → same script bytes → same certificate. No randomness, no timestamps in the script, no host-dependent behavior. This enables independent verification by any party.

**Deliverables:**
- `lib/src/state_machine/pipeline.dart`
- `lib/src/state_machine/definition_schema.json`
- `test/state_machine/pipeline_test.dart`
- `test/state_machine/determinism_test.dart`

---

## BPMN Visual Modeler Integration

The state machine definition model maps naturally onto a restricted subset of BPMN 2.0. By embedding a custom bpmn.io modeler that exposes only the achievable subset, business users can design verified on-chain workflows visually — without knowing they are producing Bitcoin Script.

### BPMN-to-StateMachine Semantic Mapping

| BPMN Construct | StateMachineDefinition Equivalent | Notes |
|---|---|---|
| Start event (single) | Initial state (encoding 0x00) | Exactly one per diagram |
| End event | `StateDef(isTerminal: true)` | One or more; each becomes a terminal state |
| User task / Service task | Implicit in `TransitionDef` | A task completing IS the transition firing; the state between two tasks is the `StateDef` |
| Sequence flow | Edge from `fromStates` → `toState` | Direct 1:1 mapping |
| Sequence flow with condition | `GuardDef` on the `TransitionDef` | Condition expression compiled to field comparator |
| Exclusive gateway (XOR split) | Multiple `TransitionDef` from same state with different guards | Each outgoing flow becomes a guarded transition |
| Exclusive gateway (XOR join) | Multiple `TransitionDef` with different `fromStates` targeting same `toState` | Implicit in the transition table; no special construct needed |
| Lane / Pool | `RoleDef` | Each lane = a signing role (PKH or Rabin key) |
| Timer boundary event (interrupting) | `TransitionDef` with `usesTimelock: true` | Maps to nLockTime-gated timeout; attached to one or more source states |
| Data object | `FieldDef` (mutable) | Displayed as annotations on the diagram; editable as field definitions |
| Data object with numeric annotation | `FieldDef(type: COUNTER)` or `FieldDef(type: AMOUNT)` | Enables INCREMENT effects and numeric guards |
| Task with single-performer lane | `TransitionDef(requiredSigners: [oneRole])` | Single-sig auth |
| Task spanning two lanes | `TransitionDef(requiredSigners: [roleA, roleB])` | Dual-sig auth; visually represented as a task touching two lanes |
| Subprocess (simple, non-parallel) | Inlined — flattened into parent state set during translation | Translator expands subprocess states with prefixed names |

### BPMN Constructs Excluded from the Custom Modeler

These constructs are **not exposed in the UI** — the custom bpmn.io palette simply does not include them:

| Excluded Construct | Reason |
|---|---|
| Parallel gateway (AND split/join) | Single `currentState` byte cannot represent concurrent execution; would require token composition (future extension) |
| Inclusive gateway (OR split/join) | Complex synchronization semantics incompatible with flat state machine |
| Complex gateway | Arbitrary merge conditions have no finite-state equivalent |
| Event subprocess | Asynchronous event handling requires concurrent state |
| Multi-instance task (sequential/parallel) | Loop semantics map poorly; use self-loop transitions instead (e.g., Confirm in PP1_SM) |
| Message flow between pools | Cross-token communication is out of scope; each token is a self-contained machine |
| Compensation / transaction handlers | Rollback semantics conflict with append-only UTXO chain; use explicit "cancel" transitions instead |
| Signal / escalation events | Global broadcast has no on-chain equivalent |
| Conditional event | Subsumes inclusive gateway complexity |
| Link events | Syntactic sugar for sequence flows; unnecessary with direct flow editing |

### Custom bpmn.io Modeler Customization

bpmn.io is built on a modular architecture (bpmn-js, diagram-js) that supports palette and rule customization. The custom modeler would:

**Palette restrictions** — Override the `PaletteProvider` to expose only:
- Start event (exactly one)
- End event (one or more)
- User task
- Service task
- Exclusive gateway
- Timer boundary event (attach to task)
- Lanes (within a single pool)
- Data objects
- Sequence flows

**Custom property panels** — Extend the `PropertiesPanel` to add:
- **Role assignment** (lane → PKH role name + auth type)
- **Field definitions** (data object → name, size, type, mutability)
- **Guard expressions** (sequence flow condition → field, comparator, value)
- **Effects** (task completion → field mutations: INCREMENT, SET, HASH_CHAIN)
- **Timelock configuration** (timer event → immutable field reference + duration)
- **Terminal flag** (end event → which terminal state name)

**Validation rules** — Override the `RuleProvider` to enforce:
- Exactly one start event, at least one end event
- No unconnected nodes
- Every task is inside a lane
- Gateway outgoing flows have non-overlapping guard conditions
- Timer events reference a defined immutable field
- Total transitions ≤ 16 (bitmask capacity)
- Total states ≤ 255 (1-byte encoding)
- Total roles ≤ 4 (practical scriptSig size limit)

**Real-time feedback** — As the user edits the diagram, run the well-formedness checker (Phase 2.1) and model checker (Phase 2.2) continuously. Display results as:
- Green overlay: all states reachable, all paths terminate
- Red markers: unreachable states, deadlocked states, unauthorized transitions
- Warnings: states not covered by timeout, single-exit-path bottlenecks

This gives the designer **live formal verification** while they draw — an experience no existing BPMN tool provides.

### Translation Pipeline

```
┌──────────────────────────────────────────────────────────┐
│  Custom bpmn.io Modeler (browser)                        │
│  Designer draws process using restricted palette         │
│  Live verification feedback as they edit                 │
└────────────────────┬─────────────────────────────────────┘
                     │ BPMN 2.0 XML (restricted subset)
                     │ + custom extension elements
                     │   (role defs, field defs, guards,
                     │    effects, timelock config)
                     ▼
┌──────────────────────────────────────────────────────────┐
│  BPMN-to-SM Translator (client-side or server-side)      │
│                                                          │
│  1. Parse BPMN XML + extension elements                  │
│  2. Validate structural constraints (subset compliance)  │
│  3. Map BPMN elements to SM definition:                  │
│     a. Lanes → RoleDefs                                  │
│     b. Walk sequence flows to identify states            │
│        (states = points BETWEEN tasks, not tasks         │
│         themselves — a task is a transition)              │
│     c. Tasks → TransitionDefs                            │
│        - Lane assignment → requiredSigners               │
│        - Outgoing flow conditions → guards               │
│        - Attached timers → timelock config               │
│        - Property panel effects → EffectDefs             │
│     d. Exclusive gateways → additional TransitionDefs    │
│        with guards from outgoing flow conditions         │
│     e. Data objects → FieldDefs                          │
│     f. End events → terminal StateDefs                   │
│  4. Flatten subprocesses (prefix state names)            │
│  5. Auto-assign state encodings (0x00, 0x01, ...)        │
│  6. Auto-assign selector opcodes (OP_1, OP_2, ...)       │
│  7. Compute transition bitmask                           │
│  8. Emit StateMachineDefinition JSON                     │
└────────────────────┬─────────────────────────────────────┘
                     │ StateMachineDefinition JSON
                     ▼
┌──────────────────────────────────────────────────────────┐
│  Verified State Machine Pipeline (Phases 1-8)            │
│  verify → compile → conformance check                    │
│  Returns: script, layout, certificate                    │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│  Business Application                                    │
│  Uses generated artifacts to issue and operate tokens    │
└──────────────────────────────────────────────────────────┘
```

### The State Identification Problem

The subtlest part of the translation is **where states live** in a BPMN diagram. In BPMN, "state" is implicit — it's the position of the process token between activities. In our model, states are explicit.

The mapping rule: **a state exists at every point where the process waits for external input**. Concretely:

- After the start event, before the first task → initial state
- After each task completes, before the next task begins → intermediate state
- After the last task, at an end event → terminal state
- At an exclusive gateway → the state is the gateway itself (waiting for the condition to be evaluated, which happens when the preceding task completes)

For a simple linear process `Start → Task A → Task B → End`:
- States: `S0` (initial), `S1` (A done, waiting for B), `S2` (terminal)
- Transitions: `task_a` (S0 → S1), `task_b` (S1 → S2)

For a process with a decision `Start → Task A → XOR → [guard1] Task B / [guard2] Task C → End`:
- States: `S0`, `S1` (at gateway), `S2` (B done), `S3` (C done), or merge `S2` if B and C converge
- Transitions: `task_a` (S0 → S1), `task_b` (S1 → S2, guard1), `task_c` (S1 → S2, guard2)

The translator performs this extraction automatically by walking the BPMN graph.

### Example: PP1_SM Funnel as BPMN

The existing funnel maps to a BPMN diagram with two lanes:

```
┌─────────────────────────────────────────────────────────┐
│ Pool: Funnel                                            │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Lane: Merchant                                      │ │
│ │                                                     │ │
│ │  (●)──► [Enroll] ──►                                │ │
│ │                      │                              │ │
│ │               ◄──────┤                              │ │
│ │                      │                              │ │
│ │         [Settle] ◄───┤                              │ │
│ │             │        │                              │ │
│ │             ▼        │                              │ │
│ │           (◉)        │   ⏱──► [Timeout] ──► (◉)    │ │
│ │         settled      │         expired              │ │
│ └──────────────────────┼──────────────────────────────┘ │
│ ┌──────────────────────┼──────────────────────────────┐ │
│ │ Lane: Customer       │                              │ │
│ │                      │                              │ │
│ │              [Confirm]* ──► [Convert] ──►           │ │
│ │              (spans     (spans                      │ │
│ │               both       both                       │ │
│ │               lanes)     lanes)                     │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘

* self-loop represented as a task with a loop marker
```

Confirm and Convert span both lanes (dual-sig). The timer boundary event on the pool triggers Timeout from any non-terminal state.

### Value Proposition

This integration gives business users something that does not exist today:

1. **Draw** a business process in a familiar visual notation
2. **See** formal verification results in real time as they edit (no deadlocks, all paths terminate, authorization correct)
3. **Deploy** the process as an on-chain token with cryptographic enforcement — no one can skip steps, forge approvals, or bypass timeouts
4. **Prove** the deployed code matches the diagram via the conformance certificate

The designer never sees Bitcoin Script, transition bitmasks, or PKH offsets. They draw lanes, tasks, and arrows. The pipeline handles everything below.

---

## Dependency Graph

```
Phase 1 ──► Phase 2 ──► Phase 3
   │                       │
   │            ┌──────────┘
   ▼            ▼
Phase 4 ──► Phase 5
   │            │
   ▼            │
Phase 6 ◄──────┘
   │
   ▼
Phase 7
   │
   ▼
Phase 8
   │
   ▼
BPMN Integration (depends on Phases 1-8)
```

- Phases 2 and 3 (verification) can proceed in parallel once Phase 1 is done
- Phase 4 (compiler) depends on Phase 1 (header layout) but not on Phases 2-3 (verification)
- Phase 5 (conformance) depends on Phase 4 (needs compiled script to decompile)
- Phase 6 (codegen) depends on Phases 1 and 4
- Phase 7 (validation) depends on everything
- Phase 8 (API) depends on Phase 7
- BPMN integration depends on Phase 8 (runtime API) and Phases 2-3 (verification, for live feedback in the modeler)

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Inductive proof parameterization is harder than expected due to variable header sizes | Phase 4 delay | PP1_SM equivalence test (Phase 4.4) catches regressions early; build incrementally from the working PP1_SM proof |
| Script size grows too large for machines with many transitions (>10) | Unusable for complex machines | Profile script size per transition (~300-500 bytes each); set documented limits; optimize shared subroutines if needed |
| Conformance decompiler is fragile to compiler output changes | Phase 5 breaks on compiler updates | Version the compiler output format; conformance checker is tightly coupled to compiler by design — update them together |
| Abstract interpretation misses field-dependent edge cases | False verification passes | Conservative: abstract domain over-approximates; any uncertainty → fail rather than pass; supplement with interpreter tests |
| 3+ role auth (triple-sig) produces large scriptSigs | Transaction size limits | Document max role count (practical limit ~4); optimize scriptSig layout |
| BPMN state identification ambiguity for complex gateway patterns | Incorrect translation produces wrong state machine | Restrict palette to eliminate ambiguity; validate translated definition against BPMN source via round-trip rendering |
| bpmn.io customization depth insufficient for guard/effect property panels | Poor designer UX or missing features | bpmn.io properties panel is fully extensible; prototype early to validate |
| Live verification latency in browser for large diagrams | Sluggish editing experience | Well-formedness + model checking runs in microseconds for ≤20 states; only re-run on diagram change, not on every keystroke |

---

## Success Criteria

The project is complete when:

1. The PP1_SM funnel can be expressed as a `StateMachineDefinition`, compiled through the generic pipeline, and all existing `sm_token_test.dart` tests pass against the generated code
2. A novel state machine (escrow) can be defined, verified, compiled, and every transition passes `Interpreter.correctlySpends()`
3. The model checker catches intentionally-broken definitions (unreachable states, deadlocks, unauthorized transitions) and produces correct counterexamples
4. The conformance checker detects intentionally-mismatched definitions (wrong target state, missing guard) and rejects them
5. The pipeline is deterministic: same input → same output across runs and machines
6. The PP1_SM funnel can be represented as a BPMN diagram in the custom modeler, translated to a definition, and the compiled output matches the handwritten PP1_SM contract
7. A novel business process drawn in the BPMN modeler produces a verified, deployable state machine token with all transitions passing interpreter verification
