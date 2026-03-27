# Zero-Knowledge STARK Verifier Feasibility on BSV

Speculative research into the smallest general-purpose zero-knowledge proof verifier that could be computed on-chain in Bitcoin Script, given BSV's post-Chronicle opcode set (no script size limit, no opcode count limit, restored arithmetic and bitwise operations).

---

## Table of Contents

1. [The Question](#the-question)
2. [BSV Script Capabilities That Matter](#bsv-script-capabilities-that-matter)
3. [Why Most ZK Schemes Are Eliminated](#why-most-zk-schemes-are-eliminated)
4. [The Optimal Construction: Circle-STARK over M31 + SHA256](#the-optimal-construction-circle-stark-over-m31--sha256)
5. [Field Choice: Why Mersenne-31](#field-choice-why-mersenne-31)
6. [The Circle Group: FFT-Friendly Domains from M31](#the-circle-group-fft-friendly-domains-from-m31)
7. [SHA256 as a Commitment Scheme](#sha256-as-a-commitment-scheme)
8. [Extension Field: QM31](#extension-field-qm31)
9. [Verifier Opcode Budget](#verifier-opcode-budget)
10. [Estimated Script Size](#estimated-script-size)
11. [Special-Purpose Alternative: Schnorr Sigma via OP_CHECKSIG](#special-purpose-alternative-schnorr-sigma-via-op_checksig)
12. [Use Cases Beyond TSL1](#use-cases-beyond-tsl1)
13. [Engineering Gaps](#engineering-gaps)

---

## The Question

What is the smallest possible general-purpose zero-knowledge verifier that could run entirely in a BSV locking script? "General-purpose" means the verifier can check proofs for arbitrary computations — not just discrete-log knowledge or signature verification, but any circuit expressible as an algebraic constraint system.

---

## BSV Script Capabilities That Matter

Three native operations dominate the feasibility analysis:

| Opcode | Cost | What It Provides |
|---|---|---|
| `OP_SHA256` | 1 opcode | Hash-based commitments at native speed |
| `OP_MUL` / `OP_MOD` | 1 opcode each | Arbitrary-precision integer multiplication and modular reduction |
| `OP_CHECKSIG` | 1 opcode | secp256k1 ECDSA verification (special-purpose ZK only) |

Supporting opcodes restored post-Chronicle:

| Opcode | Role in ZK Verification |
|---|---|
| `OP_CAT` | Concatenating hash inputs for Merkle path verification |
| `OP_SPLIT` | Extracting sub-fields from proof data |
| `OP_LSHIFT` / `OP_RSHIFT` | Bit manipulation for field arithmetic optimizations |
| `OP_AND` / `OP_OR` / `OP_XOR` | Bitwise operations for Fiat-Shamir transcript building |
| `OP_NUM2BIN` / `OP_BIN2NUM` | Encoding conversions between integers and byte arrays |

Critical **absences**:

- **No pairing opcodes** — no BN254, BLS12-381, or any bilinear map operation
- **No `OP_CHECKSIGFROMSTACK`** — cannot verify signatures over arbitrary messages natively (see [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md) for the impact of this limitation)
- **No random-access memory** — all data lives on the stack, requiring explicit manipulation

---

## Why Most ZK Schemes Are Eliminated

The absence of native pairing opcodes is the decisive constraint. Any scheme whose verifier requires bilinear pairings must implement them from arithmetic primitives in script. As established in [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md), even a single ECDSA verification over secp256k1 (256-bit field) costs ~10 MB of script. Pairing-friendly curves (BN254, BLS12-381) are larger, and the pairing operation itself (Miller loop + final exponentiation) involves thousands of field multiplications over those larger fields.

| Scheme | Verifier Requires | Estimated BSV Script Size | Verdict |
|---|---|---|---|
| **Groth16** | 3 bilinear pairings over BN254 | ~10–50 MB | Impractical |
| **PLONK (KZG)** | 2 pairings over BN254 or BLS12-381 | ~10–40 MB | Impractical |
| **Marlin / Fractal** | Pairings for polynomial commitments | ~10–40 MB | Impractical |
| **Bulletproofs** | Multi-scalar EC multiplication (secp256k1) | ~1–5 MB | Marginal |
| **Hyrax** | Pedersen commitments (EC arithmetic) | ~500 KB–2 MB | Marginal |
| **ZKBoo / Picnic** | Thousands of SHA256 calls (MPC-in-the-head) | ~200 KB–1 MB | Competitive but larger |
| **Ligero / Brakedown** | Hash checks + linear algebra over small field | ~200–500 KB | Competitive |
| **STARK (FRI/SHA256)** | Merkle paths (SHA256) + small-field arithmetic | **~100–300 KB** | **Optimal** |

The STARK verifier wins because its two dominant costs — hashing and field arithmetic — map directly to BSV's cheapest operations.

---

## The Optimal Construction: Circle-STARK over M31 + SHA256

The recommended construction uses:

- **Field:** Mersenne-31 (p = 2^31 − 1)
- **Evaluation domain:** Circle group over M31 (order 2^31, power-of-two FFT)
- **Hash function:** SHA256 (native `OP_SHA256`)
- **Extension field:** QM31 (degree-4 extension, 124-bit challenge space)
- **Polynomial commitment:** FRI (Fast Reed-Solomon IOP of Proximity) with SHA256 Merkle trees

This combination was introduced by StarkWare (Stwo, 2024) and is used in Plonky3. It achieves the smallest known general-purpose ZK verifier when the target VM has native SHA256 but no pairing opcodes — exactly BSV's profile.

---

## Field Choice: Why Mersenne-31

### Native integer alignment

M31 elements are 31 bits — they fit in a 4-byte BSV script integer. Every field operation maps to native-width CPU instructions underneath the script interpreter.

```
; M31 field multiplication: 3 opcodes
<a> <b> OP_MUL <0x7fffffff> OP_MOD

; M31 field addition: 3 opcodes
<a> <b> OP_ADD <0x7fffffff> OP_MOD

; M31 field subtraction (with negative correction): 5 opcodes
<a> <b> OP_SUB <0x7fffffff> OP_ADD <0x7fffffff> OP_MOD
```

The product of two M31 elements is at most (2^31 − 2)^2 ≈ 2^62, which fits in an 8-byte script integer. No overflow. No multi-limb decomposition. No carry propagation. Just `OP_MUL` then `OP_MOD`.

### Comparison to pairing-friendly field arithmetic

| Operation | M31 (31-bit) | BN254 Fq (254-bit) | BLS12-381 Fq (381-bit) |
|---|---|---|---|
| Field multiply | **3 opcodes** | ~80–120 opcodes | ~120–180 opcodes |
| Field add | **3 opcodes** | ~10–15 opcodes | ~15–20 opcodes |
| Modular reduction | **1 opcode** (`OP_MOD`) | ~30–50 opcodes (Barrett) | ~40–60 opcodes (Barrett) |

BN254/BLS12-381 multiplications require splitting into 4–6 limbs of 64 bits, performing schoolbook or Karatsuba multiplication across limbs, then Barrett or Montgomery reduction — all expressed as sequences of `OP_MUL`, `OP_ADD`, `OP_RSHIFT`, `OP_AND` on sub-limbs. A single pairing over these fields involves thousands of such multiplications.

M31 avoids all of this because the entire field element fits in the BSV interpreter's native machine word.

### Why not BabyBear?

BabyBear (p = 2^31 − 2^27 + 1) is the other popular small field for STARKs (used in RISC Zero, Plonky3). It also fits in 4 bytes and has the same 3-opcode multiplication cost. The difference is in the evaluation domain:

- BabyBear's multiplicative group: order p − 1 = 2^27 × 15, maximum power-of-two subgroup of size **2^27**
- M31's multiplicative group: order p − 1 = 2(2^30 − 1) — only **one factor of 2**, useless for NTT/FFT

This would rule M31 out entirely — except for the circle group construction described next.

---

## The Circle Group: FFT-Friendly Domains from M31

### The problem

STARKs require evaluating polynomials over a domain that supports FFT — meaning a group of order 2^k for some large k. M31's multiplicative group doesn't have this (only one factor of 2), so naively M31 seems worse than BabyBear for STARKs.

### The solution: the unit circle over M31

Consider the set of points (x, y) in M31^2 satisfying:

```
x^2 + y^2 = 1   (mod 2^31 - 1)
```

This is the **circle group** C(M31). Its group operation is analogous to complex multiplication on the unit circle:

```
(x1, y1) * (x2, y2) = (x1*x2 - y1*y2,  x1*y2 + x2*y1)
```

The critical property: **|C(M31)| = p + 1 = 2^31**, a perfect power of two.

This gives an FFT-friendly evaluation domain of size up to 2^31 — four times larger than BabyBear's 2^27. The "Circle FFT" (CFFT) operates by repeated halving of the circle domain, analogous to how standard FFT halves multiplicative cosets.

### Circle group operations in BSV script

The group operation requires 4 M31 multiplications + 1 addition + 1 subtraction:

```
(x1, y1) * (x2, y2) = (x1*x2 - y1*y2,  x1*y2 + x2*y1)

Cost: 4 * 3 + 3 + 5 = 20 opcodes per circle group operation
```

The verifier needs very few group operations — those are the prover's job during FFT. The verifier only needs to:

1. Compute evaluation points from query indices (a few group squarings)
2. Perform field arithmetic for consistency checks

---

## SHA256 as a Commitment Scheme

STARKs are built on Merkle-committed oracles — the prover commits to polynomial evaluations by placing them in a Merkle tree and sending the root. The verifier checks inclusion proofs.

### Merkle path verification in BSV script

```
; One level of Merkle path verification:
; Stack: [current_hash, sibling_hash, direction_bit]

<direction_bit>
OP_IF
    OP_SWAP           ; sibling goes first (we're a right child)
OP_ENDIF
OP_CAT                ; concatenate 32+32 = 64 bytes
OP_SHA256             ; hash to get parent node
; ~5 opcodes per level
```

For a tree of depth d = 15 (trace size 2^13 with blowup factor 4 = 2^15):

```
5 opcodes * 15 levels = 75 opcodes per Merkle path
```

SHA256 is doing the heavy lifting in a single opcode that would otherwise require hundreds of opcodes if implemented from primitives (SHA256 internals: 64 rounds of bitwise operations, additions, and rotations over 32-bit words).

### Why not algebraic hashes (Poseidon, Rescue)?

Algebraic hashes are designed to minimize field multiplications when the hash must be *proven inside a STARK* (recursive verification). But here the hash is being *executed natively by the VM*:

| Hash | Cost in BSV script |
|---|---|
| **SHA256** | **1 opcode** |
| Poseidon (M31, t=8) | ~300–500 M31 field operations = ~900–1,500 opcodes |
| Rescue (M31) | ~200–400 M31 field operations = ~600–1,200 opcodes |

SHA256 wins by 2–3 orders of magnitude because BSV has a dedicated opcode for it. Algebraic hashes only make sense on VMs without native SHA256 — the exact opposite of BSV's situation.

---

## Extension Field: QM31

For soundness, the FRI verifier samples random challenges from a field large enough that the prover cannot guess them. M31 alone (2^31 elements) gives only 31 bits of entropy — too small. The standard solution is a degree-4 extension:

```
CM31 = M31[i] / (i^2 + 1)          -- complex extension
QM31 = CM31[u] / (u^2 - i - 2)     -- quartic extension
```

Each QM31 element = 4 M31 elements = 16 bytes. The extension gives 4 * 31 = 124 bits of field size — enough for 100+ bit security challenges.

### QM31 arithmetic in BSV script

QM31 multiplication uses Karatsuba-style decomposition:

```
QM31 multiply ~ 12-16 M31 multiplications + 20-30 M31 additions
             ~ (16 * 3) + (30 * 3) = ~138 opcodes per QM31 multiply
```

The verifier needs QM31 arithmetic only for FRI folding consistency checks (one per FRI layer per query) and constraint evaluation at random points.

---

## Verifier Opcode Budget

Concrete parameters for a representative circuit (e.g., proving a valid state transition or hash preimage knowledge):

| Parameter | Value |
|---|---|
| Trace length | N = 2^13 (8,192 rows) |
| Blowup factor | 4 (rate 1/4) |
| Evaluation domain | 2^15 = 32,768 circle-domain points |
| FRI layers | 15 (log of domain size) |
| Security target | 100 bits |
| Queries | ~26 (at ~4 bits of security per query with blowup 4) |

### Component breakdown

| Component | Work | Opcodes (est.) |
|---|---|---|
| Fiat-Shamir transcript | ~60 SHA256 calls (hash commitments to derive verifier challenges) | ~1,000 |
| Merkle path verification | 26 queries * ~4 paths * depth 15, at ~5 opcodes per level | ~7,800 |
| FRI consistency checks | 26 queries * 15 layers * ~30 M31 ops per interpolation check | ~35,000 |
| AIR constraint evaluation | 26 queries * ~50 M31 ops for constraint polynomials | ~3,900 |
| Domain point computation | Compute circle-domain evaluation points from query indices | ~2,000 |
| Proof deserialization | Extract commitments, openings, FRI polynomials from witness data | ~5,000 |
| Stack management overhead | OP_DUP, OP_SWAP, OP_ROT, OP_PICK, OP_ROLL for data flow | ~30,000–50,000 |
| **Total** | | **~85,000–105,000** |

### Where the opcodes go

```
Stack management    ████████████████████████████  ~40%
FRI consistency     ████████████████████           ~33%
Merkle paths        ███████                         ~8%
Constraint eval     ████                            ~4%
Proof parsing       █████                           ~5%
Domain points       ███                             ~3%
Fiat-Shamir         ██                              ~2%
Other               ████                            ~5%
```

Stack management dominates because BSV script is a stack machine with no random-access memory. Every time a value buried in the stack is needed, it must be surfaced via `OP_PICK` or `OP_ROLL`, used, and the stack rearranged. A register-based VM would be ~2x more compact.

---

## Estimated Script Size

At ~2.5 bytes per opcode average (mix of 1-byte opcodes like `OP_DUP`/`OP_SWAP` and 5-byte pushes for M31 constants):

| Component | Size |
|---|---|
| Locking script (verifier) | **~210–260 KB** |
| Unlocking script (proof data: Merkle roots, authentication paths, FRI layer polynomials, query openings) | ~100–150 KB |
| **Total transaction overhead** | **~310–410 KB** |

For comparison:

| Reference | Size |
|---|---|
| TSL1 5-output token transaction (current) | ~100 KB |
| On-chain ECDSA verification (from [SIGNATURE_SCHEMES.md](SIGNATURE_SCHEMES.md)) | ~10 MB |
| Groth16 verifier (estimated, no pairing opcodes) | ~10–50 MB |

The STARK verifier is ~3–4x a current TSL1 token transaction — large but within the same order of magnitude and well within BSV's operating parameters.

---

## Special-Purpose Alternative: Schnorr Sigma via OP_CHECKSIG

For proofs limited to discrete-log knowledge on secp256k1, the verifier is trivially small:

```
<pubkey> OP_CHECKSIG
```

~35 bytes total. A Schnorr proof-of-knowledge is essentially a single signature verification. This can be extended with AND/OR composition:

```
; Prove knowledge of sk1 AND sk2
<pk1> OP_CHECKSIGVERIFY <pk2> OP_CHECKSIG
```

~70 bytes, growing linearly with the number of sub-protocols.

By carefully constructing sighash preimages (the OP_PUSH_TX pattern), this extends beyond bare DL knowledge to constrain output values, destinations, and transaction structure — but it remains algebraically limited to statements about secp256k1 scalars. It cannot prove arbitrary computation.

| Property | Circle-STARK | Schnorr Sigma |
|---|---|---|
| Verifier script size | ~210–260 KB | ~35–100 bytes |
| Proof size in unlocking script | ~100–150 KB | ~64–128 bytes |
| Proves arbitrary computation | Yes | No |
| Trusted setup | None | None |
| Primary cost in script | SHA256 + M31 field arithmetic | OP_CHECKSIG |

---

## Use Cases Beyond TSL1

The following use cases are independent of the TSL1 token protocol and represent general-purpose applications of an on-chain STARK verifier on BSV.

### 1. Trustless Cross-Chain Bridge Verifier

**Problem:** Current cross-chain bridges use 3/5 or 5/7 multisig federations to attest that events occurred on a source chain. These federations have been the single largest source of bridge exploits — Ronin ($625M), Wormhole ($325M), Nomad ($190M) — all multisig compromises.

**STARK solution:** A BSV UTXO carries a locking script containing the Circle-STARK verifier. The STARK circuit encodes:

1. Block header hash verification for the source chain (e.g., Keccak for Ethereum)
2. Transaction/receipt inclusion proof (e.g., Merkle-Patricia Trie for Ethereum)
3. Optionally: a chain of N block headers linking to a known finalized checkpoint

The prover runs this off-chain and produces a ~100–150 KB proof. The spending transaction supplies the proof in the unlocking script. The verifier script either accepts or rejects — no trusted oracle, no federation, no multisig. The math enforces correctness.

**Size budget:**

| Component | Size |
|---|---|
| STARK verifier (locking script) | ~250 KB |
| Proof data (unlocking script) | ~150 KB |
| Bridge logic (output construction) | ~10 KB |
| **Total bridge-verification tx** | **~410 KB** |

This is unremarkable on BSV — a single 410 KB transaction is well within normal operating parameters.

### 2. Private Credential Verification

**Problem:** On-chain identity checks today require revealing the credential itself (KYC documents, age, residency, professional licenses). This creates a privacy/compliance tension — either you leak personal data on-chain or you trust an off-chain attestor.

**STARK solution:** The STARK circuit verifies:

1. The issuer's signature over the credential fields (proving authenticity)
2. A predicate over the credential (e.g., `age >= 18`, `residency == "US"`, `license.type == "medical"`)

The proof reveals **nothing** about the credential except that the predicate is satisfied. The BSV locking script verifies the proof on-chain.

**Applications:**
- Age-gated token purchases (prove age >= 18 without revealing birthdate)
- KYC-once-prove-many (one credential issuance, unlimited on-chain verifications)
- Professional licensing checks (prove valid medical/legal/engineering license)
- Jurisdiction-gated access (prove residency without revealing address)

### 3. Provable Off-Chain Computation

**Problem:** Some computations are too expensive to run directly in Bitcoin Script — large matrix operations, ML inference, game state resolution, complex financial calculations. Today these require trusted off-chain execution.

**STARK solution:** Run the computation off-chain. Produce a STARK proof that the computation was performed correctly. The BSV locking script verifies the proof. The script does not execute the computation — it verifies the proof that someone else did.

This turns BSV into a **settlement layer for arbitrary computation**:

- Run complex game logic off-chain, settle the outcome on-chain
- Execute financial risk models off-chain, commit the result on-chain with a proof of correctness
- Perform database queries off-chain, prove the result on-chain

### 4. Compressed Transaction History

**Problem:** Systems that accumulate state over many transactions (audit trails, loyalty programs, supply chains) may need periodic verification that the entire history followed the rules. Replaying N transactions on-chain is expensive.

**STARK solution:** Prove that a chain of 1,000 transactions all followed specific rules (each transfer was correctly signed, balances never went negative, state transitions were valid) by producing a single STARK proof. The on-chain verifier checks one proof instead of replaying 1,000 transactions.

This is particularly relevant to any protocol where the validity of the current state depends on the integrity of the full history — a single STARK proof compresses the history verification to constant size.

---

## Engineering Gaps

This construction is theoretically sound but has not been built. The following work is required to move from feasibility analysis to implementation.

### Gap 1: M31 Field Arithmetic Library in BSV Script

No M31 arithmetic library exists in BSV Script today. The operations are individually trivial (3 opcodes per multiply) but must be packaged as composable script fragments with correct stack management — especially for QM31 extension field operations where 4 M31 elements must be tracked simultaneously.

**Estimated effort:** Low–moderate. The arithmetic is simple. The difficulty is in stack layout design for the composed operations.

### Gap 2: Circle-STARK Verifier Logic in Script

The FRI protocol, Fiat-Shamir transcript computation, AIR constraint evaluation, and query dispatch logic must be expressed as unrolled Bitcoin Script. BSV script has no loops — every FRI layer and every query is unrolled into sequential opcodes.

**Estimated effort:** High. This is the core engineering challenge. The verifier logic is well-understood in Rust/C++ (Stwo, Plonky3) but has never been compiled to a stack-based scripting language with no control flow.

### Gap 3: Script-Level Debugging Tooling

A ~250 KB script with ~100,000 opcodes is difficult to test without purpose-built debugging tools — step-through execution, stack visualization, breakpoint support. Existing BSV script debuggers are designed for scripts orders of magnitude smaller.

**Estimated effort:** Moderate. Could extend existing tools (e.g., bsv script debuggers or sCrypt IDE) rather than building from scratch.

### Gap 4: Proof Generation Toolchain

The off-chain prover must generate proofs compatible with the on-chain verifier's expected format — proof layout, field encoding, Merkle tree construction, Fiat-Shamir transcript. This requires either building a custom prover or adapting an existing one (Stwo, Plonky3) to emit BSV-compatible proofs.

**Estimated effort:** Moderate–high. Existing provers can likely be adapted rather than rewritten, but the output format must match the script verifier exactly.

### Gap 5: Security Analysis

The construction's security depends on the soundness of the FRI protocol with SHA256 as the hash function and M31/QM31 as the field. While these components are individually well-studied, their composition in a BSV script context needs review — particularly around Fiat-Shamir transcript construction (the script must produce identical challenges to the prover) and stack-related side channels.

**Estimated effort:** Moderate. Requires cryptographic review, not novel research.

---

## Summary

| Property | Value |
|---|---|
| Smallest general-purpose ZK verifier on BSV | **Circle-STARK over M31 + SHA256** |
| Estimated verifier script size | **~210–260 KB** |
| Estimated proof size | **~100–150 KB** |
| Security level | 100 bits |
| Trusted setup | None |
| Primary BSV advantages exploited | `OP_SHA256` (1 opcode), `OP_MUL`/`OP_MOD` (3-opcode field multiply), no script/opcode limits |
| Primary BSV limitation | No pairing opcodes — eliminates Groth16/PLONK |
| Maturity | Speculative — no implementation exists |

The key insight is that BSV's specific opcode profile — native SHA256, arbitrary-precision integer arithmetic, no pairings, no size limits — creates a cost structure that is the exact inverse of Ethereum's (where pairings are cheap via precompiles and SHA256 is expensive in gas). This inverted cost structure makes hash-based STARKs the natural choice on BSV, just as pairing-based SNARKs are the natural choice on Ethereum.
