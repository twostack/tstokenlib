# ZEC-Style Shielded Pool on TSL1 — Design Notes

Design exploration for a Zcash-style shielded pool (notes, nullifiers, shield / private transfer / unshield) built as a TSL1 token archetype on BSV. Covers the architecture, why the pool state must live in a UTXO, the choice of proof system, four candidate designs with their trade-offs against ZEC, a measured prototype of in-script modular exponentiation, and the fee-linkage and liveness fixes required for the STARK design to reach ZEC parity.

Companion to [ZK_STARK_VERIFIER_FEASIBILITY.md](ZK_STARK_VERIFIER_FEASIBILITY.md), which sizes the on-chain verifier this design depends on.

---

## Table of Contents

1. [Functional Target](#functional-target)
2. [Why the Pool State Must Live in a UTXO](#why-the-pool-state-must-live-in-a-utxo)
3. [Why TSL1 Is the Right Host](#why-tsl1-is-the-right-host)
4. [Pool Architecture](#pool-architecture)
5. [Hash Function Split](#hash-function-split)
6. [Design Space: Four Candidates](#design-space-four-candidates)
7. [Prototype: In-Script Modular Exponentiation](#prototype-in-script-modular-exponentiation)
8. [Prototype: M31 Arithmetic and FRI Folding Layer](#prototype-m31-arithmetic-and-fri-folding-layer)
9. [Fee Linkage Fix](#fee-linkage-fix)
10. [Liveness Fix](#liveness-fix)
11. [Version Comparison Against ZEC](#version-comparison-against-zec)
12. [The Spend Circuit: Structure Without Columns](#the-spend-circuit-structure-without-columns)
13. [Open Items](#open-items)

---

## Functional Target

A ZEC shielded pool provides four properties. Each has a distinct on-chain cost on BSV, and the designs below differ mainly in which ones they pay for.

| Property | Meaning | ZEC mechanism |
|---|---|---|
| Double-spend prevention | A note can be spent at most once, enforced by validators | Nullifier set in consensus state |
| Hidden sender / unlinkability | A spend does not reveal which note was consumed | ZK proof of Merkle membership; anonymity set = whole pool |
| Hidden recipient | No address appears on-chain | Commitment-only outputs, encrypted note ciphertext |
| Hidden amounts | Values never appear on-chain | Value commitments + range proofs inside the circuit |

Operations: **shield** (transparent → note, public amount), **transfer** (note(s) → note(s), nothing public), **unshield** (note → transparent, public amount and recipient).

---

## Why the Pool State Must Live in a UTXO

Zcash maintains the note commitment tree and nullifier set as consensus state. BSV has no such thing, and TSL1's design rule is miner validation without indexers. The state must therefore live inside a UTXO that every pool operation spends and re-creates.

The tempting shortcut — make each note its own UTXO and let the UTXO set act as the nullifier set — destroys the design. Any UTXO created when a note is born and consumed when it is spent is a public link between commitment and nullifier, which is precisely the link nullifiers exist to hide. The anonymity set collapses to one. Notes cannot be UTXOs.

Consequence: the pool is a single UTXO (per pool) carrying the commitment tree root and the nullifier tree root in its state. This creates the contention problem addressed in [Liveness Fix](#liveness-fix).

---

## Why TSL1 Is the Right Host

A pool covenant on bare BSV has a forgery problem: anyone can create a UTXO with the same locking script and a fabricated state (a fake root containing notes they minted from nothing), and a miner cannot distinguish it from the real pool.

TSL1's PP1 inductive tokenId proof is exactly the missing piece. The pool becomes an SM-archetype token. "This pool UTXO descends from the genuine pool genesis" is verified in script with no back-to-genesis walk, because each pool transaction verifies that its child carries the same script and tokenId.

The pool archetype differs from existing TSL1 archetypes in two ways:

- **No owner key in operation, an identity at genesis.** Transitions are authorized by a proof, not a signature. The create funnel keeps the SM's Rabin-signed operator identity: without it a genesis can be replayed and a second pool forged under the same identity, leaving only a first-seen rule to tell them apart. (Plan: [PP1_SP](#pp1_sp-the-pool-as-a-tsl1-primitive-plan).)
- **One transaction per operation.** The witness transaction exists to prove key control; the pool has none. The inductive check operates on parent bytes and output structure and should carry over without PP2 and PP3. This has not yet been verified in the generator code.

---

## Pool Architecture

### Pool state (carried in the SM header)

| Field | Purpose |
|---|---|
| `commitmentRoot` | Current root of the note commitment tree |
| `anchors[N]` | Ring buffer of the last N roots; a spend proof may reference any of them |
| `nextLeafIndex` | Append position in the commitment tree |
| `pendingHash` | Hash chain of commitments emitted since the last roll-up |
| `nullifierRoot` | Root of the nullifier set (sparse or indexed Merkle tree) |
| `rollupReserve` | Accumulated bounty for whoever performs the next roll-up |
| Satoshi value of the output | The vault backing all unspent notes |

### Operations

**Shield.** Deposit input brings public value. The script adds the amount to the vault and appends the new commitment to `pendingHash`. No proof needed beyond commitment well-formedness (or a small proof that the commitment's value equals the deposit).

**Transfer / unshield.** The spend proof's public inputs are: anchor, nullifier(s), new commitment(s), fee, and a hash of any public outputs (unshield recipient script + amount). The script:

1. Verifies the STARK proof.
2. Checks the anchor is in `anchors[N]`.
3. Verifies nullifier non-membership against `nullifierRoot` using a witness supplied in the unlocking script, then inserts it and writes the new root.
4. Appends new commitments to `pendingHash`.
5. Enforces the vault equation (see [Fee Linkage Fix](#fee-linkage-fix)).
6. Verifies the public outputs hash against the transaction's outputs via the sighash preimage (existing OCS machinery), preventing proof theft from the mempool.

**Roll-up.** Anyone may submit a transaction with a proof that `commitmentRoot'` equals `commitmentRoot` with a *prefix* of the pending chain appended. The script verifies the prefix against `pendingHash`, restarts the chain with any leftover commitments, rotates `anchors`, and releases `rollupReserve` to the submitter. A note is spendable once it has been rolled up — the analogue of waiting for a block confirmation.

### What the spend circuit proves

1. `cm = H(pk_d, value, rho, r)` opens to a note the prover knows.
2. `cm` is a leaf under `anchor` (Merkle path, depth 32).
3. `nf = H(nk, rho)` where `nk` derives from the spending key. Key hierarchy is hash-based; no elliptic-curve arithmetic anywhere in the circuit and no dependence on the missing `OP_CHECKSIGFROMSTACK`.
4. Value balance: inputs = outputs + fee + unshield, with 64-bit range checks on outputs.
5. Output commitments are well-formed.

Nullifier non-membership is *not* proven in the circuit. The script checks it directly against pool state, which is what allows the nullifier tree to use SHA256 and the witness to be rebuilt without re-proving.

---

## Hash Function Split

The feasibility doc's argument that SHA256 wins because it is native applies to the *verifier's* commitment scheme. It does not apply to the *application's* Merkle tree, which is hashed inside the circuit. Splitting the choice keeps both sides cheap.

| Structure | Hash | Where it runs | Why |
|---|---|---|---|
| FRI Merkle trees, Fiat-Shamir transcript | SHA256 | Script only | One opcode per hash |
| Nullifier set | SHA256 | Script only | Non-membership checked by script, never in-circuit |
| Note commitments, commitment tree, nullifier derivation | Poseidon2 over M31 | Circuit (and prover) | SHA256 in a STARK costs ~2^12 trace rows per compression; Poseidon2 costs a few rows |

With this split, a 2-in-2-out transfer is roughly 70 Poseidon2 permutations and lands near the 2^13 trace size the feasibility doc priced at ~250 KB of verifier. Poseidon2 must stay out of script entirely — a naive in-script tree append costs thousands of opcodes per hash times 32 levels and exceeds default node policy. That is why appends are batched into a proven roll-up rather than computed in script.

**Column budget is a first-order constraint.** Constraint evaluation at the out-of-domain point and the DEEP quotient scale with AIR column count. A sloppy Poseidon2 arithmetization could push the verifier toward a megabyte and past the 500 KB default `maxscriptsizepolicy`.

### Estimated per-transaction budget (STARK design)

| Component | Size |
|---|---|
| STARK verifier (locking script) | ~210–260 KB |
| Nullifier check/insert, SM header logic, OCS | ~10–20 KB |
| Proof (unlocking script) | ~100–150 KB |
| Encrypted note ciphertexts (OP_RETURN) | ~1 KB |
| **Total** | **~350–450 KB** |

At 100 sats/kB this is under 50,000 sats per private transfer.

---

## Design Space: Four Candidates

BSV's cost profile is the inverse of Ethereum's: no pairings, but native arbitrary-precision `OP_MUL` / `OP_MOD`. One opcode multiplies two 3072-bit integers. This is why TSL1 uses Rabin signatures, and it means the pre-SNARK privacy constructions — Zerocoin, linkable ring signatures, Pedersen commitments — are cheap to verify on-chain if rebuilt in a finite-field Schnorr group instead of on an elliptic curve. In script, a modular exponentiation is an unrolled loop of native opcodes with no field inversions, and its size is independent of the modulus width (see [Prototype](#prototype-in-script-modular-exponentiation)).

| Property | ZEC Orchard | STARK pool | Zerocoin / RSA accumulator | Ring signature (Schnorr group) | Chaumian mint |
|---|---|---|---|---|---|
| Anonymity set | Whole pool | Whole pool | Whole pool | Ring (16–32) | Whole pool |
| Hidden amounts | Yes | Yes | No (denominations) | No (denominations) | No (denominations) |
| Hidden sender / receiver | Yes | Yes | Yes | Yes | Yes |
| Trusted setup | None | None | RSA modulus ceremony | None | Signing-key holder |
| Inflation resistance | Cryptographic | Cryptographic | Cryptographic | Cryptographic | Trust in signer |
| Post-quantum soundness | No | Yes (hash-based) | No | No | No |
| Verifier on-chain | n/a | ~400 KB | ~400 KB | ~200–400 KB | ~1 KB |
| Proof in unlocking script | n/a | ~150 KB | ~25 KB | ~1 KB | ~0.5 KB |
| Engineering lift | — | Very high (unbuilt verifier + Rust prover) | Low (BigInt sigma protocols in Dart) | Low | Very low |

**STARK pool.** The only candidate that matches ZEC on privacy. Exceeds it on cryptographic robustness: no ceremony (matches Orchard, beats Sapling) and hash-based soundness, so a quantum adversary cannot forge spends. With a hash-based or lattice KEM for note encryption, privacy is post-quantum too. Its operational robustness is weaker until the fee and liveness gaps below are closed.

**Zerocoin / RSA accumulator.** Coins are prime Pedersen commitments accumulated into an RSA accumulator in pool state. Full-pool anonymity, ~25 KB proofs, prover is a few dozen BigInt exponentiations in Dart. Denominations leak amounts; adding range proofs (four-squares in the RSA group, ~200 KB per output) pushes the verifier near a megabyte. Requires an RSA modulus of unknown factorization.

**Ring signature.** Pool state holds a SHA256 Merkle tree of note public keys plus the nullifier tree. A spend supplies decoys with public inclusion proofs, a linkable ring signature in a safe-prime group (RFC 3526 MODP groups make hash-to-subgroup a single squaring), and a key image as nullifier. No trusted setup, no witness maintenance. Anonymity is the ring, with Monero's known decoy-selection weaknesses.

**Chaumian mint.** Blind RSA signatures over serial numbers, verified in script for a few hundred bytes, with miner-enforced nullifiers. Blindness is information-theoretic, stronger than ZEC's. But a covenant cannot hold a signing key, so inflation rests on whoever does. A legitimate staging strategy: every other component (pool state, nullifier tree, note format) is identical, and the authorizer can later be swapped for a verifier.

**Verdict.** Only the STARK pool matches or exceeds ZEC. The bignum designs are the right build if the bar is "much better than transparent" rather than "ZEC-equivalent", and the Chaumian mint is the right way to ship the full pool flow while the verifier is being built.

---

## Prototype: In-Script Modular Exponentiation

`lib/src/script_gen/modexp_script_gen.dart` emits an unrolled right-to-left square-and-multiply with the exponent as stack data and the modulus embedded as a constant. `test/modexp_script_gen_test.dart` checks correctness against Dart's `modPow` (including exponent 0, exponent 1, max exponent, rejection of a wrong result, and randomized cases) and reports size and interpreter time.

| Exponent | Modulus | Locking script | Bytes per exponent bit | dartsv interpreter time |
|---|---|---|---|---|
| 256-bit | 3072-bit | 6.4 KB | 22.0 | 376 ms |
| 256-bit | 2048-bit | 6.1 KB | 22.0 | 218 ms |
| 1500-bit | 3072-bit | 33.8 KB | 22.0 | 2.4 s |
| 3072-bit | 3072-bit | 68.4 KB | 22.0 | 4.7 s |

Findings:

- **Script size is independent of modulus width.** Only the two constant pushes differ. This is the property that makes finite-field groups beat curves on BSV: a secp256k1 scalar multiplication in projective coordinates is roughly 30 KB, an order of magnitude worse.
- **22 bytes per bit**, not the 15 originally estimated. A 256-bit exponentiation is 6.4 KB. Revised: a 16-member ring verifier is ~200 KB, a 32-member ring ~400 KB, which brushes the 500 KB default policy limit.
- **Interpreter time is overhead, not arithmetic.** Raw Dart `BigInt` does the same 384 modular multiplications in 3.7 ms; the remaining ~370 ms is dartsv's byte-to-BigInt conversion per opcode. A C++ node lands in single-digit milliseconds per exponentiation. dartsv is modifiable if this becomes a test-iteration bottleneck.
- **Fixed exponents are ~3× cheaper.** With a compile-time exponent (hash-to-subgroup, RSA `e = 65537`) there is no bit extraction or branching, roughly 8 bytes per bit.
- **Loop slack.** Two `OP_PICK` fetches of the modulus per bit and the altstack round-trip for the exponent account for most of the 22 bytes; a 2-bit windowed variant could plausibly reach under 18.
- **dartsv builder quirk.** `ScriptBuilder.addData` mis-serializes a one-byte push with value 1–16; the generator routes those through `smallNum`.

This measurement is the foundation for the Zerocoin and ring-signature designs. It does not feed the STARK verifier directly, which lives in 31-bit arithmetic.


## Prototype: M31 Arithmetic and FRI Folding Layer

`lib/src/crypto/m31.dart` is the reference implementation (M31, CM31, QM31, circle group, Stwo-layout half-cosets). `lib/src/script_gen/m31_script_gen.dart` provides a symbolic stack tracker (`StackEmitter`) with lazy reduction and sign tracking, plus QM31 emitters. `lib/src/script_gen/fri_fold_script_gen.dart` emits leaf hashing, SHA256 Merkle paths with index-derived direction bits, fixed-base domain-point computation from the query index, the twiddle recurrence `x' = ±(2x² − 1)`, the `fold_line` step, and a complete single-query multi-layer verifier. `test/m31_fri_script_gen_test.dart` (14 tests) checks every emitter against the reference and runs a genuine 10-layer FRI query (16,384-point domain, depths 13 down to 4) through the interpreter, including rejection of a tampered opening and a wrong index.

| Component | Script bytes |
|---|---|
| M31 multiply, lazy / reduced | 3 / 9 |
| QM31 multiply, lazy / reduced | 106 / 174 |
| QM31 add | 44 |
| `fold_line` step (QM31 in, QM31 out) | 250 |
| Leaf hash (8 limbs) | 39 |
| Merkle path, per level | 15.4 |
| Twiddle step | 53 |
| Domain point from index, per bit | 65 |
| Select-and-compare against next layer | 50 |
| **One query, 10 layers, depths 13..4** | **7,384** (unlock 3,258; 14 ms in dartsv) |

Findings:

- **Lazy reduction is the big lever.** Script numbers are arbitrary precision, so sums of products are accumulated unreduced and reduced once per output limb. A QM31 multiply drops from ~300 bytes to 106 lazy / 174 reduced. Sign tracking picks the 6-byte reduction when a value is known non-negative and the 18-byte sign-correcting one otherwise.
- **Multiply costs the same as add.** Both are one opcode. Karatsuba-style tricks that trade multiplies for adds buy nothing here; schoolbook is optimal.
- **Per layer per query is ~650 bytes** at depth 13, dominated by the fold (250) and the Merkle path (200). The domain point (850 bytes) is paid once per query.
- **Projection.** For the feasibility doc's parameters (2^15 domain, 15 layers, 26 queries), FRI alone projects to ~260 KB before the DEEP quotient, constraint evaluation and Fiat-Shamir. That is above the doc's 210–260 KB total estimate. Two cheap wins remain unapplied: keeping per-layer roots and alphas on the stack instead of re-pushing them per query (~20 KB), and stopping the fold at degree 16 and evaluating the final polynomial directly (~15 KB).
- **FRI parameters, settled.** A query yields log2(blowup) bits under the standard conjecture and half that provably. The feasibility doc's "26 queries at blowup 4" was inconsistent with both. Because the prover is off-chain and a narrow AIR keeps the trace small (~2^12 rows), a very high blowup is nearly free for the prover and cuts the on-chain verifier roughly in half:

  | Trace | Blowup | Grinding | Queries | Final degree | Verifier (FRI + DEEP + ~30 KB fixed), 32 cols |
  |---|---|---|---|---|---|
  | 2^12 | 4 | 20 | 40 | 32 | ~355 KB |
  | 2^12 | 16 | 20 | 20 | 32 | ~221 KB |
  | 2^12 | 32 | 20 | 16 | 32 | ~195 KB |
  | 2^12 | 64 | 20 | 14 | 32 | ~185 KB |
  | 2^12 | 32 | 20 | 32 (provable) | 32 | ~361 KB |
  | 2^12 | 64 | 20 | 27 (provable) | 32 | ~330 KB |

  Chosen: **trace 2^12, blowup 32, 20-bit grinding, 16 queries, stop folding at degree 32, roots and alphas stack-resident**, targeting 100 bits under the conjecture. That is ~195 KB with 32 opened columns and ~240 KB with 128. The provable-security variant at the same parameters is 32 queries and ~360 KB, still under the 500 KB policy limit but with little headroom for the pool logic. QM31's 124-bit challenge space caps achievable soundness near 110 bits regardless of query count; 128-bit is not available without a larger extension. Column count is the other lever: every opened column costs ~25 bytes per query, so the AIR should be tall and narrow.
- **Interpreter time is not a concern:** 14 ms per query in dartsv, so ~0.4 s for 26 queries even with the interpreter's known overhead.

### Remaining pieces, measured

`lib/src/script_gen/deep_quotient_script_gen.dart` (Stwo's complex-conjugate-line DEEP quotient), `fiat_shamir_script_gen.dart` (SHA256 transcript), and `air_ood_script_gen.dart` (out-of-domain constraint check for a width-16 Poseidon2 external-round AIR) each ship with a Dart reference; `test/stark_verifier_pieces_test.dart` (7 tests) checks the scripts against them in the interpreter, including rejection of a wrong inverse hint, a wrong grinding nonce and a tampered next-row value.

| Component | Script bytes |
|---|---|
| DEEP quotient, per query point, 20 columns | 1,234 |
| DEEP precompute, once per sample point, 20 columns | 10,920 (546/col) |
| Fiat-Shamir: absorb 32-byte item / absorb 4 limbs / squeeze QM31 / 16 indices | 3 / 20 / 70 / 260 |
| Fiat-Shamir, full transcript for the chosen parameters | 3,311 |
| OODS: one x^5 S-box / external linear layer / β-combine 16 constraints / vanishing polynomial | 560 / 3,040 / 3,380 / 2,098 |
| OODS check, complete, trace 2^12 | 18,392 |

Two algebraic simplifications mattered. The DEEP precompute originally cost 982 bytes per column; observing that the per-column line intercepts sum to c·V − zy·A (with V and A the weighted sums of values and their conjugate differences) removed two of the five QM31 multiplies per column. And the DEEP quotient's only per-query, per-column work is Σ_j w_j f_j(p) with base-field openings, so a column costs ~25 bytes per query point.

**Full verifier projection** for the chosen parameters (trace 2^12, blowup 32, 20-bit grinding, 16 queries, final degree 32, 20 opened columns), every line from measured emitters:

| Component | Bytes |
|---|---|
| FRI per query | 8,852 |
| DEEP quotient per query (2 sample points × (p, −p)) | 4,936 |
| Trace + composition Merkle openings per query | 973 |
| **Per query** | **14,761** |
| DEEP precompute (2 sample points) | 21,840 |
| OODS constraint check | 18,392 |
| Fiat-Shamir | 3,311 |
| **Total, 16 queries** | **~273 KB** |

The earlier 195 KB model undercounted the DEEP quotient: the circle-to-line first fold needs the quotient at both p and its conjugate, and the trace is opened at two sample points, so four quotient evaluations per query rather than one. At ~273 KB plus ~20 KB of pool logic the spend transaction fits the 500 KB policy limit with room; the provable-security variant (32 queries, ~510 KB) does not. A partial-round selector in the AIR, not yet modeled, would add roughly 50% to the OODS check and a few columns.

The last two pieces are now measured as well. The circle-to-line first fold is integrated into the query verifier (`circleFirst` in `FriQueryVerifierGen`): the domain-point computation keeps y, the fold uses a verified y-inverse hint, and the transition to the line domain is a conditional sign flip on x rather than a doubling. Against a reference with a genuine circle layer over a 16,384-point circle domain, the marginal cost is 811 bytes per query, essentially the same as the depth-13 line layer it stands in for, so the projection above is unchanged. Deriving the OODS point from a transcript challenge via the rational parametrisation with a verified inverse hint costs 794 bytes once per proof.

### Assembled verifier, end to end

`lib/src/script_gen/stark_verifier_gen.dart` is one generator that consumes a complete proof from the unlocking script in transcript order and verifies it: Fiat-Shamir for β, z, the three DEEP challenges and the FRI alphas; the OODS constraint check with a selector column; the DEEP precompute for three sample groups (composition at z, trace at z, trace at z·g); grinding and query sampling; and per query the composition opening, the DEEP quotients at p and its conjugate, the circle fold, the mixed-degree line folds with the trace group folded in three layers down, and the final-polynomial evaluation. `lib/src/crypto/stark_prover_ref.dart` is a naive reference prover (interpolation by linear solve, tiny traces only) that produces proofs in exactly that layout. `test/stark_assembly_test.dart` proves a 16-row Poseidon2 external-round trace, verifies it in the interpreter, and rejects a tampered OODS value, a tampered composition opening and a wrong grinding nonce.

**Mixed-degree FRI is real cost.** The constraint is degree 6 (x⁵ S-box times the selector), so the composition polynomial lives on a domain 8× the trace and its quotient enters FRI three layers above the trace quotient, as in Stwo. That adds three line layers and a second circle fold per query. The earlier per-query figure assumed a single domain.

**Production parameters, measured on the generated script** (trace 2^12, blowup 32, 16 queries, final degree 32, 17 trace columns + 4 composition columns):

| | Bytes |
|---|---|
| Per query | 18,975 |
| Fixed, once per proof (transcript, OODS check, DEEP precompute) | 46,437 |
| **Full locking script** | **350,036 (342 KB); 349,684 with zk masking** |

With ~20 KB of pool logic the spend stays under the 500 KB policy limit with ~130 KB of headroom. The provable-security variant (32 queries) would be ~650 KB and does not fit.

The end-to-end run caught one real protocol bug the unit tests could not: the DEEP quotient's conjugation must be the automorphism u → −u of QM31 (fixing CM31), not the negation of the i-components; with the wrong map the quotient is not regular at the conjugate point and the final FRI layer carries one extra degree. The prover's own low-degree assertion surfaced it, and it is exactly the kind of error only a full pipeline exposes.

### Zero-knowledge masking

A sound STARK is not automatically zero-knowledge: query openings reveal trace values at sampled points and the out-of-domain values reveal evaluations of the trace polynomials. The pool needs hiding, so each trace column is masked as f' = f + v_N · r, where v_N is the vanishing polynomial of the trace domain and r is a random polynomial with R coefficients. f' agrees with the trace on the trace rows (constraints still hold) and is uniformly random at up to R other points. The selector column is public and stays unmasked.

Accounting for what is revealed: per query, the trace at p and conj p directly, and at p·g and conj(p)·g through the composition openings; plus the two QM31 out-of-domain evaluations, four M31 dimensions each. That is 4Q + 8 = 72 points at 16 queries, so R = 128. The masked columns have degree up to N and are committed in the 2N space, which doubles the trace LDE (prover cost) and moves the trace group's FRI entry one layer up. The composition degree bound is unchanged because R ≪ N.

Measured on the production script: **341 KB with masking versus 342 KB without.** The extra Merkle level per query is offset by one fewer point doubling, so zero-knowledge is free on-chain; the cost is on the prover. `StarkParams.zkSufficient` checks R against the revealed count, and a test confirms two proofs of the same trace agree on trace rows and differ off-domain.

Remaining before this is a product: the full Poseidon2 AIR with partial rounds and preprocessed selector columns, range-checking the opened values, salting Merkle leaves if any committed column has low entropy, and the pool state machine around the verifier.

### Real prover: circle FFT in Dart

`lib/src/crypto/circle_fft.dart` and `lib/src/crypto/stark_prover.dart` replace the naive reference prover with an FFT-based one, written in Dart rather than adapted from Stwo so that prover, reference and verifier are validated in one test process. The circle FFT works in a "twin layout" that is the verifier's Merkle-leaf order: a domain of size 2^(m+1) is stored as the values on HalfCoset(m) followed by the values on its conjugate, and the standard cyclic domain D_k is the twin layout of HalfCoset(k−1). Coefficients live in the basis y^{b0} x^{b1} π(x)^{b2} ⋯ (index bits low to high), whose x-part of index j has degree exactly j, so zero-padding is the low-degree extension and multiplying by the vanishing polynomial v_t = π^(t−1)(x) is a shift of the coefficient index by 2^t. The zero-knowledge mask is therefore R random coefficients written directly above the trace's coefficients, with no extra FFT.

Everything else is the reference protocol done pointwise on evaluations: the composition is computed on D_{t+3} in base-field arithmetic (the next row is a cyclic shift of 2^3), DEEP denominators are batch-inverted, FRI folds use cached coset tables and batch-inverted twiddles, and the final polynomial is solved on its first 32 points and checked on the remaining 992, which keeps the reference's low-degree assertion.

**Validation.** With masking off the FFT prover's output is byte-identical to the reference prover's on three parameter sets, down to every Merkle path, inverse hint and debug intermediate. With masking on, proofs verify in the interpreter and two proofs of the same trace agree on trace rows and differ off-domain.

**Production parameters, end to end** (trace 2^12, blowup 32, 16 queries, R = 128, 3-byte grinding), single-threaded Dart:

| | |
|---|---|
| Prover, total | 13.8 s |
| of which grinding (2^24 expected SHA256 trials) | 9.7 s |
| of which FFTs, Merkle trees, DEEP and FRI | 4.1 s |
| Unlocking script (the proof) | 98,277 bytes |
| Locking script | 349,684 bytes |
| dartsv interpreter, verify | 0.42 s |

This was the first production-size proof verified by the generated script (with the toy one-round AIR; the full Poseidon2 AIR below adds ~42 KB to the locking script). The 4 s of real prover work is dominated by SHA256 (1.1 s of Merkle hashing in package:crypto) and QM31 object arithmetic in the DEEP and FRI stages; grinding is embarrassingly parallel and moves to isolates or native code when it matters. The 500 KB script-size policy is applied to each script separately when it is evaluated, so the 98 KB proof in the unlocking script does not eat into the locking script's headroom; the spend as a whole is ~450 KB against a 10 MB transaction-size policy.

### The real Poseidon2 AIR

The toy AIR was one external round per row with a committed selector column. The pool needs the full permutation, and the way its selectors and round constants reach the verifier decides the on-chain cost, so this step also fixed the general AIR framework (`lib/src/script_gen/air.dart`).

**Instance** (`lib/src/crypto/poseidon2_m31.dart`): width 16 over M31, S-box x⁵, 4 + 4 external rounds around 14 internal rounds, the Poseidon2-paper M4 in the external matrix, and Plonky3's Mersenne-31 internal matrix J + diag(−2, 2⁰, 2¹, …, 2¹⁶). Round constants are derived from SHA256 of a fixed seed string. Plonky3 ships no canonical Mersenne-31 constants, so this loses no interoperability; the hash is this protocol's own either way.

**Layout** (`lib/src/script_gen/poseidon2_air.dart`): one round per row, 16 state columns, a 32-row period per permutation. Row 0 applies the initial linear layer, rows 1 to 22 the 22 rounds, row 23 holds the output and rows 24 to 31 are free. The 19 selector and round-constant columns are *periodic* rather than committed: a column with period 2^k on a trace of size 2^t is F(φ^(t−k)(p)) for the interpolant F of its 2^k values and the doubling map φ, so the verifier evaluates it at the out-of-domain point from 2^k constants baked into the script. Nothing is committed, nothing is opened per query, and the trace no longer carries a selector column. The alternative, committing preprocessed columns, would have cost about 4.5 KB per query in openings and DEEP terms, ~72 KB per proof.

The constraint per lane is `(sE + sP + sL)·next − M_E(sE·t + sL·cur) − M_I(sP·b)` with t the S-boxed lanes and b the partial-round vector, degree 6, so the composition domain and FRI shape are unchanged. The prover computes constraints in base-field arithmetic and reads the periodic columns from a 256-point table; the verifier's doubling chain for the periodic evaluation ends at the trace vanishing value, so that comes for free.

**Validation.** Constraints vanish on every row of an honest trace and fail on a corrupted external, partial or linear-layer row; the base-field and QM31 constraint paths agree; the periodic interpolants reproduce the columns on the trace domain; the script check accepts a consistent instance and rejects a tampered one; the FFT prover is still byte-identical to the reference; the stage bisection passes; and a production-size proof verifies in the interpreter.

**Cost.** The out-of-domain check is now 64 KB, of which periodic column evaluation is 30.7 KB (19 columns × 32 coefficients), the constraints 26.4 KB, the doubling chain 3.5 KB and the β-combination 2.9 KB.

| Production parameters, full Poseidon2 AIR | |
|---|---|
| Locking script | 391,289 bytes (382 KB) |
| Per query | 18,778 bytes |
| Fixed per proof | 90,837 bytes |
| Proof | 98,094 bytes |
| Interpreter verify | 0.46 s |

Headroom under the 500 KB policy is now ~118 KB for the pool circuit's own constraints. The cheapest known saving is to evaluate the periodic columns in Lagrange form: only 165 of the 608 periodic values are nonzero, and the 32 Lagrange values at the mapped point cost 16 verified inverse hints plus ~50 multiplications, roughly 10 KB in place of 30 KB.

---

## Fee Linkage Fix

**Problem.** ZEC pays fees from the shielded value balance. A pool transaction on BSV needs satoshis for the miner, and a funding input is a transparent identity link on every private transfer.

**Fix.** The pool transaction has exactly one input, the pool UTXO itself. No funding input, no change output.

- **Fee is a public input to the spend proof.** Value balance becomes `inputs = outputs + fee + unshield`. The spender burns the fee from their own shielded value, so the proof caps the fee at what they hold and overpaying hurts only them.
- **Script enforces the vault equation.** The sighash preimage exposes the spent input's satoshi value; the script already reconstructs outputs for hashOutputs. It checks `newPoolValue = oldPoolValue − fee − unshield + shield`. Whatever the transaction leaves out of its outputs goes to the miner, and that difference is forced to equal the proven fee.
- **Uniform shape, uniform fee.** Every transfer is padded to 2-in-2-out with identical size, so every transfer pays the identical fee. A fee amount cannot fingerprint a user.
- **Coordinator or relayer cut**, if any, is a second public output bound into the proof as script-hash plus amount, exactly as unshield payouts are bound.
- **Shield fees stay transparent.** A deposit brings its own input; that is public by nature, as in ZEC's t-to-z.
- **Roll-up bounty.** Each operation adds a small increment to `rollupReserve`. Whoever performs the roll-up claims it. The append step is permissionless and paid for by users without any of them paying at roll-up time.

---

## Liveness Fix

**Problem.** ZEC's pool state is consensus. Ours is one UTXO. Anyone with a valid proof can chain transactions faster than another user, and a hostile party can grief the pool at the cost of fees. Safety holds; liveness does not.

### Why sharding into lanes is unsafe

The natural fix is K lane UTXOs sharded by nullifier prefix, all feeding one tree UTXO. It fails on a property specific to script-only validation:

> **A script can authenticate another UTXO only if that UTXO is its sibling from the same parent transaction.**

That is the trick PP2 uses to know the witness inputs share its token transaction, via hashPrevouts. Anything else requires hashing the transaction that created the other UTXO — here a transaction carrying a 400 KB locking script — which is infeasible in script. So a lane can verify it is co-spent with the tree only for one epoch after they were created together, and the tree can never verify a lane once the lane has advanced. A fake lane with fabricated commitments is indistinguishable, and fabricated commitments are inflation. Lanes sharing a tree are ruled out unless the tree verifies the lane's *work* rather than its identity, which is the v2 design.

### Version 1: one pool UTXO, made hard to grief

- **Proofs bind to an anchor, not an outpoint.** With `anchors[N]` covering the last N epochs, a lost race means rebuilding the transaction around the new pool outpoint and regenerating the nullifier non-membership witness, which is local and instant. The proof is reused. Proving time never sits in the critical path of a race.
- **Roots change only at roll-up.** Spends append to `pendingHash`; the roll-up proves the append over a *prefix* of the chain, so a roll-up that loses a race also rebuilds without re-proving. Leftovers after the prefix restart the chain.
- **Griefing is blind and costs real money.** An attacker needs a valid proof per transaction and burns the fee from their own shielded notes each time. They cannot target a victim because nullifiers are secret until spent. Sustained blocking is a fee-burning race against everyone.
- **A coordinator, optional and non-custodial.** Users submit pool transactions to a sequencer that chains them in order, eliminating races among honest users. It can delay but cannot forge or steal; any user can fall back to direct broadcast.
- **Roll-up pressure valve.** Cap the pending chain length. When full, only roll-ups and spends of already-rolled notes proceed, and the accrued bounty makes the roll-up worth doing.
- **Horizontal scale by independent pools.** Each pool is a complete shielded pool with its own tree and nullifiers. Safe because pools never trust each other. Cost: each pool is its own anonymity set and moving between pools goes through the transparent layer. Start with one; add pools as load demands.

Throughput of one pool is bounded by how fast a chain of unconfirmed transactions can be built — roughly one per second — which exceeds ZEC's shielded volume. The v1 exposure is orderliness under adversarial load, not capacity.

### Version 2: zk-rollup with recursive aggregation

Spenders send proofs to an aggregator off-chain, never to the chain. The aggregator produces one batch proof per epoch that:

1. Recursively verifies every spend proof.
2. Checks nullifier uniqueness against the tree's nullifier set inside the circuit.
3. Appends the new commitments.
4. Authorizes unshield payouts and releases each spender's fee to the aggregator from the vault.

One on-chain transaction per epoch, one verifier, no contention. Spenders need no on-chain funds at all. Censorship resistance comes from multiple aggregators plus the ability to self-post a proof as data for anyone to include.

The engineering price is recursion: the spend circuit must use a Poseidon2-based FRI so it can be verified inside another STARK, while the batch proof keeps SHA256 FRI for the on-chain verifier. Plonky3-style recursion is production technology, but it roughly doubles the circuit work.

The spend proof's public inputs — anchor, nullifiers, commitments, fee, public-outputs hash — are identical in v1 and v2. That interface is what to hold fixed so that v2 is a change to the roll-up path only.

---

## Version Comparison Against ZEC

| | ZEC | v1 single pool | v2 rollup |
|---|---|---|---|
| Fee linkage | None | None | None |
| Spend contention | None | Races, coordinator-mitigated | None |
| Settlement latency | One block | One transaction | One epoch |
| Targeted censorship | Impossible | Impossible (nullifiers secret) | Aggregator can delay; self-post fallback |
| Pool halts if | Consensus failure | Nobody rolls up (bounty-mitigated) | Nobody aggregates (self-post fallback) |
| Trusted setup | None | None | None |
| Post-quantum soundness | No | Yes | Yes |
| Extra cryptography | — | None beyond the verifier | STARK recursion |

---

## The Spend Circuit: Structure Without Columns

The Poseidon2 AIR gives one permutation per 32-row period. The spend needs about 72 of
them per transaction, wired into a specific program: derive the key, commit the note,
walk 32 Merkle levels, emit the nullifier. Three questions had to be answered before any
of that could be written, and the measurements settle them.

### What the verifier actually charges for

Measured against the production verifier (trace 2^12, blowup 32, 16 queries), where the
per-query work is 77% of the 391 KB locking script:

| addition | locking-script cost |
| --- | --- |
| one trace column | 3,954 B |
| one periodic column | 768 B |
| one degree-2 constraint | ~500 B |
| one boundary group of 8 pins | ~4.3 KB |
| logPeriod 5 -> 6 | +20 KB |
| a longer trace | nothing |

Columns are the expensive resource and rows are free, which inverts the usual circuit
intuition: spend rows, hoard columns.

### Why program structure cannot be a public column

A periodic column of period 2^k is cheap because the doubling map quotients the trace
domain by the *low* bits of the row index: a function of `r mod 2^k` collapses onto a
2^k-point domain, and the verifier evaluates it from 2^k baked-in coefficients. A
function of `r div 32` — which period this is, and therefore what the program does here —
has no such collapse. It is a general degree-2^12 polynomial: 4096 basis multiplications,
roughly 1.2 MB of script. Committing it instead as a preprocessed column costs about
4 KB per column plus a second Merkle tree, a new transcript step and new query openings.

### Point divisors

A line meets a circle in two points. That makes a linear form `alpha*x + gamma*y` the
cheapest non-trivial public structure available, at two constant multiplications per
evaluation:

- `LinearForm.vanishingAt(p)` is zero at exactly `p` and `-p`, which are cyclic rows
  `r` and `r + 2^(t-1)`.
- `LinearForm.selectorAt(p)` is `+1` at `p` and `-1` at `-p`, so
  `(a+b)/2 + ((a-b)/2)*s` interpolates two different public values across the pair.

A `ConstraintGroup` carrying such a form as its divisor is enforced only at those two
rows. Multiplying a transition constraint by one instead excepts it there. Both cost
one degree, not 2^12, which is what makes the scheme affordable: the composition budget
allows constraint degree 8 and Poseidon2 already uses 6.

The verifier never inverts anything. It multiplies the out-of-domain identity through by
`v_t` and the product of the distinct divisor forms, so `StarkProof` and the unlocking
script layout are unchanged, and an AIR that declares no forms produces the old check to
within 11 bytes.

Every break and every pin therefore applies at row `r` and at row `r + 2^(t-1)` together.
Rather than fight that, the layout leans on it: the trace is two structurally identical
halves, one input note in each, with public values allowed to differ between them through
the selector interpolant.

### The chain machine

`Poseidon2ChainAir` turns the periods into a chain. Row 0 is the permutation input, row
23 its output, and rows 24..31 carry the 8-lane digest forward in lanes 0..7 while lanes
8..15 stay free. Row 31 lane 8 holds a prover-chosen **swap bit**, constrained boolean,
that muxes the digest into the next input's low or high half — the other half is witness,
which is exactly a Merkle sibling and a genuinely free choice, since the leaf's position
in the tree is private. `breakPeriods` cuts the otherwise cyclic chain wherever a segment
must start from fresh witness.

### Registers, and why a chain is not enough

The key hierarchy is a DAG, not a chain: `sk` feeds both `pk_d = H(sk, d)`, which leads to
the note commitment and the Merkle path, and `nf = H(sk, rho)`. No reordering fixes this.
The commitment must be computable by the *sender*, so the permutation producing it takes
exactly `(pk_d, value, rho, rcm)` and cannot also carry the nullifier key; and a boundary
constraint pins cells to public values, so it cannot tie two secret cells at distant rows
to each other.

The fix is a small register: columns held constant along each half of the trace, excepted
at one half-turn pair so each half gets its own value, with `BoundaryPin.equal` tying a
register column to a state lane at a chosen row. Five lanes carry a 155-bit key. The
general alternative — a permutation or lookup argument — would need a second commitment
round, which the single-commitment protocol currently avoids.

### Soundness of clearing denominators

Multiplying through creates, at each pinned row, a pole shared by `v_t` and that
group's form `w_j`. A cheating trace could satisfy the polynomial identity there if a
main-constraint violation and a boundary violation cancelled,
`A(p)·w_j'(p) + S_j(p)·v_t'(p) = 0`. What rules this out is that **every constraint
carries a distinct power of β across all groups**, so the cancellation would have to
hold identically in β, which a trace fixed before β is sampled cannot arrange. This is
load-bearing, not a tidiness choice: restarting the Horner at β⁰ per group would break
soundness silently. `AirScriptGen.emitOodsCheck` and the prover both keep the global
exponents.

### Lane packing, values and balance

Three things the first layout got wrong:

- **The commitment needs two blocks.** With `pk_d` occupying the carried 8 lanes, the
  free half cannot hold `value`, `rho` and a properly sized `rcm` (a one-lane blinding
  is 31 bits, not hiding). So `cm = P(s ‖ rcm, pad)` with `s = P(pk_d ‖ value, rho)`,
  one more chained period per half. Width-24 Poseidon2 would fit one block but costs
  eight columns.
- **Values are 51-bit, not 64-bit.** BSV's supply is under 2⁵¹ sats. Two limbs of 26
  and 25 bits keep every four-term sum below p, so limb-wise balance needs a single
  small carry witness. Range checks are bit decompositions in the free cells (rows
  24..31, lanes 9..15, plus the register) with an accumulator lane
  `acc' = 2·acc + bit`; the accumulator meets the value lane locally at the row-31 →
  row-0 transition into the commitment period, gated by a break-style form. "Spare
  periods" are not free: every period still runs its permutation on rows 0..22.
- **Balance is a cyclic accumulator.** A whole-trace register lane is constant except
  at the four value rows (input and output, both halves), where boundary groups impose
  `acc_next − acc_cur ∓ cur[value] = 0`, and at the existing row-4095 break, where the
  jump is `−(fee + unshield)`. The jumps around a cycle must sum to zero, which *is*
  the balance equation, and no public pin ever touches a secret cell.

**One-input spends** need a dummy second note. The anchor pin applies to both halves,
so gate it Sapling-style, `value · (root − anchor) = 0`: a zero-value dummy skips
membership, its nullifier is a fresh hash that harms nothing, and it contributes nothing
to the balance. Degree +1.

### Planned layout and budget

At t = 12 there are 128 periods, 64 per half. Each half holds one input note:

| periods | permutation | notes |
| --- | --- | --- |
| 0 | `P(sk, d ‖ pad)` -> pk_d | break |
| 1 | `P(pk_d ‖ value, rho)` -> s | |
| 2 | `P(s ‖ rcm, pad)` -> cm | |
| 3..34 | 32 Merkle steps -> root | pinned to the anchor (value-gated), same both halves |
| 35 | `P(sk from register, rho ‖ pad)` -> nf | break; pinned, differs per half |
| 36..37 | output commitment, two blocks | break; pinned, differs per half |
| 38..63 | unused | |

Three break forms, one register break, roughly eight boundary groups, five register
lanes for the key and three accumulator lanes. The projected verifier is **~470 KB** of
the 500 KB per-script policy, leaving ~30 KB for the pool state machine. Two levers
exist if that is too thin: Lagrange-form periodic evaluation (~20 KB) and a larger FRI
blowup with fewer queries (measured below).

### FRI blowup versus query count

Holding the final polynomial at degree 32 (`logFinal = logBlowup + 5`) keeps the number
of line folds at `t − 3` whatever the blowup, so a larger blowup costs the verifier
nothing per query and each query is worth more bits. Measured on the Poseidon2 verifier
at t = 12, 3 grinding bytes, zk R = 128 (all variants prove and verify end to end):

| blowup | queries | conjectured security | locking script | proof | prover work* |
| --- | --- | --- | --- | --- | --- |
| 32 | 16 | 104 bits | 391,300 B | 98 KB | ~4 s |
| 64 | 14 | 108 bits | 357,251 B | 91 KB | ~8 s |
| 64 | 13 | 102 bits | 338,210 B | | |
| 128 | 12 | 108 bits | **322,229 B** | 83 KB | ~17 s |

*excluding grinding, a 2²⁴ hash search whose wall time swings 3–40 s by luck.

Blowup 128 with 12 queries frees **69 KB** at slightly higher security than the current
parameters, for a prover that is still well under a minute. That turns the ~30 KB of
state-machine headroom into ~100 KB and is the parameter set to build the pool against.
The remaining cost is prover memory: the composition Merkle tree has 2²¹ leaves.

### The note and nullifier program (built)

`pool_spend_air.dart` is the spend as a program over the chain, with `PoolHash` holding
the hash definitions wallets and the prover share (Poseidon2 truncated to 8 lanes; sk 5
lanes, d 3, rho 3, rcm 4, pk_d and digests 8, values 26 + 25 bits). One correction to
the layout above: `rho` appears in both the commitment block and the nullifier
permutation, so it is a second cross-row secret and joins `sk` in the register, which is
therefore 8 lanes. Per half:

| period | permutation | pin |
| --- | --- | --- |
| 0 | `P(sk, d ‖ pad)` -> pk_d | register = sk |
| 1 | `P(pk_d ‖ value, rho)` -> s | register = rho |
| 2 | `P(s ‖ rcm)` -> cm | |
| 3..34 | 32 Merkle steps, swap bit = position bit | root = anchor |
| 35 | `P(sk, rho ‖ pad)` -> nf | register = sk, rho; nf public |
| 36..37 | output commitment, two blocks | cm' public |

The result is 24 columns, 73 constraints, 21 periodic columns, 16 linear forms and 7
constraint groups. It proves and verifies end to end; forged nullifiers, wrong siblings,
a nullifier from another key or another rho, and cheats in the second half are all
caught, and a verifier built for different public inputs rejects the honest proof.

At the chosen production parameters (t = 12, blowup 128, 12 queries, zk R = 128):

| | |
| --- | --- |
| locking script | **389,400 B** (110 KB under the 500 KB policy) |
| proof | 83,952 B |
| prover | ~18 s of work plus grinding |
| verify (dartsv) | 0.41 s |

### Value balance and range checks (built)

The chain AIR grew three generic features for this: *bit lanes* (lanes 9..15 of rows
24..31, boolean in every period), *accumulator* columns with a periodic reset / shift /
hold schedule over the bit lanes, and *boundary expressions* — affine in the current and
next row, with terms optionally multiplied by the selector so they apply on one side of a
half-turn pair only. Values are two 28-bit limbs (56 bits; every bit cell used).

**Range checks** cover the output values only; input values are bound by commitments that
were range-checked when created. The output value sits at period 36 row 0, so its 56 bits
go in period 35's bit cells, the low limb in rows 24..27 and the high limb in 28..31. Two
accumulators run in every period (`acc' = m·acc + g·Σ2ᵏ·bit`, harmless where the cells are
zero) and a boundary group at row 1151 equates them with the value lanes of the next row.

**Balance** is two cyclic register lanes, one per limb, constant except at the input-value
row (+value), the output-value row (−value) and a closing row, where the jump is
−public − carry·2²⁸ for the low limb and −public + carry for the high one. The carry
`c ∈ [−3, 4]` is `c + 3` in three bit cells of the closing row, so no column is spent on
it; the selector confines the closing jump to one side of the pair. The jumps around the
cycle must sum to zero, which is the balance equation over the integers because every
term is far below p. A verifier built for a different public amount rejects the proof —
that is the fee cheat.

Result: 28 columns, 92 constraints, 26 periodic columns, 14 forms, 10 groups. Caught:
a value lane disagreeing with its bits, a non-boolean bit, a minted satoshi with
consistent bits, and a wrong carry.

At production parameters (t = 12, blowup 128, 12 queries, zk R = 128):

| | |
| --- | --- |
| locking script | **432,140 B** (68 KB under the 500 KB policy) |
| proof | 84,590 B |
| prover | ~33 s including grinding |
| verify (dartsv) | 0.45 s |

The circuit's soundness story is now complete for a two-input, two-output spend.

### Dummy notes: the gated anchor (built)

A one-input spend needs a dummy second note, and the dummy must not have to sit in the
tree. The plan was the Sapling trick, `value · (root − anchor) = 0`, with the gate pinned
to `lo + hi` so that no booleanity check was needed. That is **unsound here**: a dummy's
limbs are unconstrained (its commitment is never checked against anything), so a cheater
picks `lo = −hi mod p`, the gate reads zero, and the pair still feeds the balance lanes.
The two balance equations then reduce to one integer relation on limb *sums*, which a
real input of value 5 satisfies against an output of `5·2²⁸`. Value-sum gating mints.

What is built instead is a boolean **flag register lane**, one value per half, pinned at
the input-value row (row 32) with three gated expressions:

- `flag · (flag − 1) = 0`
- `(1 − flag) · lo = 0` and `(1 − flag) · hi = 0`

and the eight anchor pins become `flag · (root_j − anchor_j) = 0`. A real note (flag 1)
has its root pinned; a dummy (flag 0) has both limbs forced to zero, so it contributes
nothing to the balance and its Merkle path is free. Flagging a real note as a dummy is
allowed and harmless: the note then spends nothing. The boundary-expression language
gained an optional gate column with either polarity (one QM31 multiplication in script),
so this is eleven gated expressions and one column. The dummy's nullifier `H(sk, rho)` is
published like any other, but since the flag became public (below) the pool no longer
inserts it, so a dummy's `rho` no longer has to be fresh.

**The flag is public (built).** Two more public lanes, `real1` and `real2`, are pinned
to the flag register at the input value row (`BoundaryExpr.publicAt(regFlag, …)`), so
the publics say which input notes are dummies and the proof stands behind it: a dummy
declared real fails the anchor pin, a real note with value declared dummy fails the
zero-value pins. The state script reads each lane with `OP_IF` around the insertion
(the ELSE branch drops the unused witness and rolls the root back up), so a dummy's
nullifier never enters the set. Cost: 52 publics instead of 50, about 1.4 KB on the
verifier slot and 1.25 KB per transfer on the state script. Tests: the AIR test
rejects both mislabelled directions; the reader test checks the set holds one real
nullifier after a deposit and a one-input spend.

Result: 29 columns, 96 constraints, 14 forms, 10 groups. The test builds a spend of one
real note with a dummy whose root is visibly not the anchor, proves it, and checks that
a verifier for a different anchor still rejects. Caught: a dummy with `lo = −hi`, a dummy
with a high limb, a dummy flagged real with its bogus path, a real note flagged dummy
while keeping its value, and a non-boolean flag.

At production parameters (t = 12, blowup 128, 12 queries, zk R = 128):

| | |
| --- | --- |
| locking script | **439,773 B** (60 KB under the 500 KB policy; +7.6 KB for the gate) |
| proof | 84,754 B |
| prover | ~26 s including grinding |
| verify (dartsv) | 0.46 s |

The remaining 60 KB has to hold the pool state machine; Lagrange-form periodic
evaluation (~20 KB) is the reserve.

### The note commitment tree (built)

`note_commitment_tree.dart` is the wallet side of the anchor. The tree is depth 32 over
Poseidon2 nodes `H(left, right)` with an all-zero empty leaf; `emptyRoots[l]` is the
root of an empty subtree of height l. Two structures share one hash definition:

- **`MerkleFrontier`** holds only the roots of the complete left subtrees on the path to
  the next free leaf, one per set bit of the leaf count, so a leaf is appended with at
  most 32 hashes and the root recomputed with exactly 32. This is the state a covenant
  would carry to append commitments on chain, and the size of the on-chain problem: two
  new commitments per spend are 64 permutations, either in script or proved inside the
  STARK (the trace has 52 idle permutations at t = 12 and 180 at t = 13, and script size
  does not depend on the trace length).
- **`NoteCommitmentTree`** keeps every computed node as well, appends through its own
  frontier, and produces a `MerklePath` (siblings leaf-first, position) for any leaf
  against the current root. The two roots are asserted equal on every append.

Tested: the empty-root table, 21 appends with every earlier leaf re-proved against each
new root, a frontier reconstructing the root of a 40-leaf tree from its peaks alone, and
two notes appended to a real tree going through `PoolSpendAir.witness` with every
constraint holding, plus a stale path being rejected.

### Runtime public inputs (built)

Until this step the anchor, nullifiers, output commitments and public amount were
compile-time constants: `PoolSpendAir.air(publics)` baked them into the constraint
system and the generator emitted them as immediates, so every spend had its own locking
script. A pool UTXO is locked before its spender exists, so that could never be the
covenant's script.

Public inputs are now **data at the bottom of the unlocking script**, 42 M31 limbs for
the pool, and the locking script depends only on their number:

- The AIR declares `numPublics` and names them `pub0..`; boundary expressions carry
  indices (`BoundaryExpr.publicAt(col, idxA, idxB)`) instead of values, with the
  half-turn interpolant `(a+b)/2 + ((a−b)/2)·s` computed at runtime from the two picked
  limbs. An index of −1 stands for zero, which is how the closing balance jump takes the
  public amount on one side of the pair only.
- The verifier **absorbs the publics into the transcript before the trace root**, and
  both provers do the same. Without this a spender could choose the publics after
  seeing the challenges, since the publics define the constraint system.
- `buildUnlock` pushes the AIR's concrete values; the test proves once, checks that a
  generator built for different publics emits a byte-identical locking script, and that
  the same proof under those other publics is rejected.

Cost at production parameters: **440,693 B** (+920 B). One locking script now serves
every spend, which is what the covenant needs; binding the publics to the transaction is
the covenant's job and the next piece of work.

### The nullifier set, and what it costs (measured)

A spend must show its nullifiers are *absent* from the pool's spent set and then insert
them. Zcash lets consensus nodes hold that set; here the covenant holds a root of it, so
absence has to be proved in circuit.

The set is an **indexed Merkle tree** (`nullifier_set.dart`). Every leaf is a pair
`(value, next)`, hashed as `H(value ‖ next)` — exactly the permutation's sixteen lanes,
so a leaf costs one permutation — and covers the open interval between them. A nullifier
is absent exactly when some leaf's interval contains it, which is **one** Merkle path
rather than the key's full bit depth. The list carries no next-index: a spender only
needs the two values to bracket the nullifier, insertion preserves the interval
invariant without one, and traversal is the wallet's problem.

An insertion is three leaves and four passes over a path: the low leaf in the old root,
the low leaf updated, the empty slot, the new leaf. At depth 32 that is **131
permutations**, plus two lane-ordered comparisons.

That is what forces the trace length. Per half, one input note:

| | periods |
| --- | --- |
| spend program (built) | 38 |
| nullifier insertion | 131 |
| note commitment append | 32 |
| **total** | **201** |

A 2¹³ trace gives 128 periods per half and does not fit; 2¹⁴ gives 256 and fits with 55
spare. But the verifier script is **not** independent of trace length, contrary to what
the early column-versus-row measurement suggested. The fold count is `t − 3`, and each
doubling adds a fold and a Merkle level per query:

| trace | periods | lock | headroom |
| --- | --- | --- | --- |
| 2¹² | 128 | 440,469 B | 60 KB |
| 2¹³ | 256 | 452,754 B | 47 KB |
| 2¹⁴ | 512 | 465,278 B | 35 KB |
| 2¹⁵ | 1024 | 478,019 B | 22 KB |

So moving to 2¹⁴ costs 25 KB of headroom before the nullifier constraints are written,
and those constraints add columns and groups on top — at roughly 4 KB per column and
4.3 KB per boundary group, a handful of each would consume most of what is left and
leave nothing for the covenant. **The budget no longer closes by itself**, and the next
decision is which lever to pull: fewer queries against a larger blowup, a larger final
polynomial to buy back folds at the cost of proof size, or moving the nullifier
insertion out of the spend proof entirely.

### The parameter sweep at 2¹⁴ (measured)

Two of those levers were measured with the pool-shaped AIR at the 2¹⁴ trace, zk R = 128,
24 grinding bits. Security bits are `queries × log blowup + 24`.

**A larger final polynomial does not help.** The verifier evaluates the final polynomial
at every query, and that grows faster than the fold it removes: at blowup 128 and 12
queries, each step of the final degree above the minimum adds 17 KB, then 42 KB, then
93 KB. The minimum, `logFinal = logBlowup + 5` (32 coefficients), is the right setting
and stays so. (Its cost in proof size is also negligible, which corrects an earlier
remark that the final coefficients dominate the unlock.)

**Blowup against queries is the lever, and it is large.** At the minimum final degree:

| blowup | queries | bits | lock | headroom | ~proof | prover domain |
| --- | --- | --- | --- | --- | --- | --- |
| 2⁷ | 12 | 108 | 465,230 B | 34 KB | 99 KB | 2²⁴ |
| 2⁷ | 11 | 101 | 441,684 B | 57 KB | 91 KB | 2²⁴ |
| 2⁸ | 10 | 104 | 421,039 B | 77 KB | 86 KB | 2²⁵ |
| 2⁹ | 9 | 105 | 399,824 B | 98 KB | 80 KB | 2²⁶ |
| 2¹⁰ | 8 | 104 | 378,008 B | 119 KB | 74 KB | 2²⁷ |

The proof shrinks too, because fewer queries means fewer Merkle paths. What grows is the
prover: the composition domain is `2^(t + blowup + 3)`, and at 2¹⁴ each blowup step
doubles a domain that is already 2²⁴ points. The Dart prover took 26 s at 2¹² and
blowup 128 (domain 2²²); blowup 256 at 2¹⁴ is eight times that domain, blowup 512
sixteen times, with memory to match (the composition column alone is a gigabyte of
QM31 at blowup 512).

The working choice is **blowup 256, 10 queries** at 2¹⁴: 104 bits, a 421 KB verifier,
77 KB for the nullifier constraints and the covenant, and a prover in the minutes rather
than tens of minutes. Blowup 512 stays in reserve for another 21 KB if the covenant
needs it, at the price of a prover most wallets would find slow.

### Correction: the nullifier set goes back to script

The section above reversed the hash-function split without an argument. Nullifier
non-membership is a check on *public* data — the nullifier is published, and anyone
rebuilds the set from published nullifiers — so it belongs in script with SHA256, as the
split table says: four depth-32 walks at ~15 B per level plus two `OP_LESSTHAN`
comparisons, under 3 KB, zero trace periods, and no sibling-binding problem because the
script reads the same stack items for every pass. The 131 periods per half come off the
trace, and with the append paired as below a half is 38 + 64 periods, which fits 2¹³.

### Sibling binding: the interaction round (built)

Every tree update is two Merkle walks over the same siblings — the old root with the
old leaf, the new root with the new leaf — and nothing in the chain AIR relates a
witness lane in one period to a witness lane thirty-two rows later. Left unbound, the
second walk's siblings are free and the new root is whatever the prover wants: for the
commitment tree that deletes or plants notes, for an in-circuit nullifier set it
resets the set. The 131-permutation cost above assumed the reuse was free; it is not.

Two walks cannot be interleaved on one chain either: the chain hands each period's
output to the next period, so alternating walks feeds the wrong node to every step.
Carrying the second walk's node and the siblings in registers costs 17 columns, and a
column is **3.4 KB** at 2¹³ / blowup 256 / 10 queries (measured: 314,531 B without and
372,895 B with 17 registers), so about 63 KB. The alternative built instead is a second
commitment round:

- After the trace root is absorbed the transcript yields a challenge γ; the AIR derives
  *aux columns* from the trace and γ, commits them in a second tree, and only then is β
  drawn. Aux columns are masked, opened and folded into the DEEP groups exactly like
  trace columns (indices `numCols..`), and the aux constraints are QM31-valued, form one
  more group divided by v_t, and may use γ. `Air` gained `numChallenges`, `numAuxCols`,
  `auxColumns`, `auxConstraints`, `auxConstraintsM31`, `emitAuxConstraints`; the proof
  gained `auxRoot` and a per-query aux opening; with no aux round nothing changes and
  the existing proofs are byte-identical.
- `SiblingBinding(walk1, walk2, steps)` on `Poseidon2ChainAir`: one accumulator
  (a QM31 aux column, four base columns) absorbs `S = Σ_j γ^j w_j + γ^8 b` at every
  glue row — the next period's witness half selected by its swap bit, and the bit
  itself — shifting by γ⁹ per period, weighted +1 during walk 1 and −γ^(9·D) during
  walk 2 (D the period offset), and is pinned to zero at the glue row into walk 1 and
  at walk 2's end row. The weight comes from a *mode* register (0 / 1 / 2) with break
  rows at the four walk boundaries and a constant pin in each region; without the
  zero-region pins a prover could absorb free witness lanes between the walks and
  cancel any mismatch. Both halves bind their own pair. Soundness is Schwartz–Zippel
  over QM31: a mismatch survives with probability about 2⁻¹²⁰.
- Gotchas found: at a glue row the absorbed sibling belongs to the *next* period, so
  the weight is the next row's mode; the FRI alphas are named `al$l` in script, so the
  aux opening cannot be `al${q}_$i`; `emitComposeColumns` drops its inputs.

**Measured (t=13, blowup 256, 10 queries): 35,151 B** — mode register and four
accumulator columns (17 KB), pins in four groups, the aux opening per query, the
constraint itself and the divisor products. Test `sibling_binding_test.dart`
(paired walks at 2⁹, cheats on siblings, directions, mode and accumulator all caught,
proof verified in script, forged aux opening rejected). The reference prover agrees
byte for byte with the FFT prover with an aux round at 2⁸.

### The paired append in the spend circuit (built)

`PoolSpendAir` now runs at 2¹³ (128 periods per half): key, cm, membership walk, nf,
then a **before-walk** (32 steps from the prover's empty-leaf claim, pinned to the pool
root / the mid root), out1, out2, and an **after-walk** (32 steps chained from cm′,
pinned to the mid root / the new root), bound by `SiblingBinding(walk1: 36, walk2: 70,
steps: 32)`. Half A appends the first output commitment at position `size`, half B the
second at `size + 1`; `rootMid` is a public the covenant ignores. The witness takes the
wallet's `NoteCommitmentTree` and advances it by two leaves.

**Position binding.** Without it the prover picks the slot and overwrites someone's
note. A 32-bit position does not fit M31 (2³¹ ≡ 1: positions differing in the level-0
and level-31 bits collide), so a base column accumulates the first thirty direction
bits of walk 1 as `pos′ = 2 pos + b` (weight `m(2 − m)` from the mode register, reset
excepted by one form at the glue row into the walk) and the two top bits are pinned
directly from the swap-bit lane. Publics: the bit-reversed low position, the two top
bits, each for both halves (`PositionPins.valuesFor`). Walk 2's bits follow from the
sibling binding. Publics total 72 lanes.

**Out-of-domain check made linear.** With 17 distinct boundary divisors the
cleared-denominator products were emitted quadratically (each divisor's "all others"
product from scratch); prefix and suffix products cut it to 3D multiplications and
saved **40.5 KB** on the pool lock. This is the second time the OODS check was the
cheapest place to look.

**Measured, production parameters, full 2-in-2-out spend with the append:**

| | t=13, blowup 256, 10 q | t=13, blowup 512, 9 q |
| --- | --- | --- |
| locking script | **463,094 B** | 441,489 B |
| headroom under 500 KB | 37 KB | 59 KB |
| security bits | 104 | 105 |
| proof (unlock) | 91,148 B | — |
| prover (Dart, one thread) | 103 s, of which grinding 16 s | ~2× |
| verify (dartsv interpreter) | 0.84 s | — |

AIR: 31 + 4 columns, 131 constraints, 28 forms, 19 groups. Tests: `pool_spend_air_test`
(cheats on the after-walk sibling, the claimed position, the claimed roots, the mode
register and the leaf claim are all caught; a verifier claiming another new root or
another position rejects the honest proof), `note_commitment_tree_test` (a spend built
from a real tree appends to it).

What is left for the covenant: 37 KB at blowup 256, or 59 KB at blowup 512 with a
prover twice as slow. Cheap cuts still unclaimed: Lagrange-form periodic evaluation
(~20 KB), the accumulator zero pins as one QM31-coefficient expression instead of
four limb pins (~3 KB).

### The covenant (built)

`PoolCovenantGen` (`lib/src/script_gen/pool_covenant_gen.dart`) is the pool's locking
script: a `PoolState` header of pushes, then the spend verifier with the covenant run as
its **prologue** on the same stack emitter (`StarkVerifierGen.prologue`/`unlockAbove`).
The covenant's witness sits above the proof in the unlocking script and the header
pushes land above that, so the verifier's final cleanup drops everything.

**State** (170 B of pushes): `ring[0..3]` — the commitment root now and the three
before it, 32 B each as 8 lanes in 4-byte LE words, exactly the transcript's
serialisation; `size` (4 B LE, the next append slot); `nfRoot` (32 B, the SHA256
indexed Merkle tree of spent nullifiers). The vault is the output's satoshis. Every
spend rewrites the header: `[rootAfter, ring[0..2]]`, `size + 2`, the new `nfRoot`.

**Checks**, over the proof's 80 publics (the 72 of the append plus `outHash`):

- *Canonical lanes.* Every lane the script interprets (anchor, nf1, nf2, rootBefore,
  rootAfter) is verified `< p`. The value `p` reads as 0 inside the circuit but as the
  bytes `ff ff ff 7f` here; unchecked, a nullifier with a zero lane would have two
  byte spellings, i.e. a double spend for anyone willing to grind 2³¹ notes.
- *Anchor ring.* `anchor ∈ ring`; `rootBefore == ring[0]`.
- *Positions.* The six position publics are recomputed from `size` and `size + 1`
  (30 bit-reversal steps each, ~330 B a walk).
- *Nullifier set.* For nf1 then nf2: `low.value < nf < low.next` as unsigned
  little-endian integers (`OP_BIN2NUM` on the 32-byte strings); the low leaf's path
  reaches the current root; the same path with the low leaf's `next` replaced gives
  the mid root; an all-zero leaf under the mid root at the new slot; the new leaf
  `(nf, low.next)` there gives the root after. Both walks of a pair share siblings and
  direction bits, so one loop climbs two nodes (22 B a level). Indices are witness
  bits only: any bracketing leaf and any empty slot will do. The wallet model is
  `NullifierSet` in `nullifier_set.dart`, now over SHA256 and 32-byte values.
- *Preimage.* `checkPreimageOCS` on the sighash preimage; `value` is the vault,
  `hashOutputs` the target, and the scriptCode after the header is this script's
  body (the varint is 5 bytes: the lock exceeds 64 KB).
- *Value.* `vault_out = value − (pubLo + 2²⁸ pubHi)` with both limbs read as signed
  residues (above `(p−1)/2` means negative), the result non-negative. A negative
  balance is a deposit and the vault grows. Whatever the extra outputs do not take
  is fee.
- *Outputs.* `SHA256(extra outputs)` split into eight 31-bit lanes must equal the
  `outHash` publics, so a relayer cannot redirect an unshield. No constraint reads
  `outHash`; its absorption into the transcript is the binding.
- *hashOutputs* = `SHA256d(vault_out ‖ varint ‖ new header ‖ body ‖ extra outputs)`.

**Measured, production parameters (t=13, blowup 256, 10 queries):**

| | |
| --- | --- |
| locking script | **468,644 B** (bare verifier 463,154 + covenant 5,490) |
| headroom under 500 KB | 31 KB (at blowup 512 / 9 queries: 447,039 B, 53 KB) |
| unlocking script | 564,489 B: preimage 468,775 + proof 91 KB + nullifier witness 4.3 KB |
| transaction | ~1.03 MB |
| prover | 95 s (grinding 5.5 s this run) |
| verify (dartsv interpreter) | 1.4 s |

The preimage carries the whole 469 KB scriptCode, which is what doubles the
transaction; there is no way around it while the output must be rebuilt from the
script's own bytes. Tests: `pool_covenant_test` (the spend at small and production
parameters; rejected: an output paid elsewhere, a vault one satoshi off either way,
a stale root / size / nullifier root / unrotated ring, insertions reordered, a low leaf
that does not bracket or is not in the set, an anchor outside the ring, a wrong size).

**Deposits (built).** No second circuit. The balance constraints hold modulo p and
fix both public limbs exactly whatever their sign: the low limb is `X − 2²⁸c` and the
high limb `Y + c` for the true limb differences X, Y and the small carry c, so a
residue above `(p−1)/2` is unambiguously negative and `lo + 2²⁸ hi` is the signed
balance. A deposit is therefore a spend of two dummies (allowed now, with a
caller-supplied anchor from the ring since the anchor pins are off) whose outputs
sum to the deposit and whose `publicOut` is its negative; the covenant adds it to the
vault. `PoolHash.signedLimbs` builds the lanes; the depositor funds the transaction
with an ordinary input and any change is an extra output bound by `outHash`. Cost:
30 B of script. The two dummy nullifiers used to go into the set (two leaves per
deposit); the public `real1`/`real2` flags now let the state script skip them.

Found on the way: dartsv's `removeAllInstancesOf` (FindAndDelete inside
`OP_CHECKSIG`) allocated a script-sized buffer per opcode of the scriptCode — 270 K
opcodes × 272 KB — and exhausted the heap on any lock above ~100 KB; it is now one
linear pass (local dartsv patch, uncommitted).

## PP1_SP: the pool as a TSL1 primitive (plan)

Agreed 2026-09-19 after the covenant landed. Supersedes the single-output covenant as
the target shape and the roll-up / `pendingHash` parts of [Pool Architecture](#pool-architecture).

**Policy, corrected.** BSV runs Teranode. Defaults: 100 MB per script, 10 MB per
transaction, 1,000,000 ops per script, 100 MB stack memory. The 500 KB per-script
budget that drove every size decision above is gone; the binding limits are ops per
script and bytes per transaction. Measured on the pool lock at t=13: blowup 256 / 10
queries 468 KB and 212 K ops; blowup 32 / 16 queries 600 KB and 272 K ops with the
prover's domain eight times smaller. FRI gets re-tuned for prover speed once the
primitive lands.

**A regression to undo.** The paired append inside the spend circuit pins every proof
to `rootBefore`. Two users proving at once conflict, the loser re-proves for 95 s, and
no batching is possible because proof *i* must start from proof *i−1*'s root. The v1
property that a lost race is a rebuild, not a re-proof, needs the append back out of
the spend proof. Spend proofs become state-free again: anchor from the ring,
nullifiers, output commitments, balance, `outHash`.

**Why not an aggregation layer between users and the pool.** The state can vouch for
a co-input only as a sibling from the same parent transaction, one hop. An
intermediate transaction's result is not a sibling; authenticating it means hashing a
transaction whose inputs carry proofs (the PP3 tail trick needs a last input with a
tiny unlock, which an aggregator policing a whole output list cannot have). And every
460 KB slot script must be re-minted per use by a transaction the pool trusts, so the
10 MB pool transaction caps slots per round wherever they are spent. The bottleneck
is bytes minted per pool transaction, not verification parallelism; the coordinator
already accumulates proofs off-chain for free.

**Shape: one state output plus single-use sibling slots.**

- **State output** (`PP1_SP`, ~30 KB). Header, single-byte pushdata each, parked on
  the altstack SM-style: `tokenId` (32, funding txid), `rabinPubKeyHash` (20),
  `phase` (1: issued → live), `ring[4]` (32 each), `size` (4, in subtree slots and
  leaves), `nfRoot` (32). Body: dispatch on a trailing selector; *create* mirrors
  `_emitCreateFunnel` (Rabin signature over `SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId)`,
  empty-state header, hashPrevouts binding the funding outpoint); *spend* is the
  covenant generalised to K transfers: K publics blocks, 2K nullifier insertions, ring
  and vault updates, the subtree position, and the rebuild of every output.
- **Verifier slots** (K per round, 463 KB, 1 sat, stateless, byte-constant per pool
  version). Each verifies one user's proof from its unlock, then signs SIGHASH_SINGLE
  so its preimage covers only output *i* = `OP_RETURN H(publics_i)`; an
  `OP_CODESEPARATOR` before the final CHECKSIG keeps its scriptCode to one byte, so its
  unlock is the proof alone. It also checks hashPrevouts contains the state outpoint,
  so it cannot be spent without the state.
- **Subtree-append slot** (one per round; **built and measured 2026-09-19: 571,056 B,
  342,598 ops, 0.8 s in the interpreter, unlock 1.7 KB**; Poseidon2 in script is
  7,786 B and ~4,700 ops per permutation, `poseidon2_script_gen.dart`). Takes the
  batch's 2K commitments,
  builds a depth-4 subtree (15 permutations), walks the empty slot under `rootBefore`
  and the written slot to `rootAfter` over the same siblings (2 × 28 permutations), and
  publishes `(rootBefore, rootAfter, subtreeIndex, H(cms))` the same SIGHASH_SINGLE way.
- **The binding.** The state rebuilds all outputs: itself, the K + 1 `OP_RETURN`
  results from its own copy of the publics, fresh slots for the next round from bytes
  supplied once in its unlock and checked against hashes baked into the body, and the
  extras bound by each proof's `outHash`. The same `OP_RETURN` bytes in two sighashes
  make the slot's result and the state's input one and the same. hashPrevouts on both
  sides pins the slots to fixed vouts of the state's own parent, so every slot lives
  exactly one hop and nobody can brick the pool by spending one alone.
- **Tree.** Depth 28 over depth-4 subtrees. Membership paths stay 32 levels, so the
  spend circuit's walk is unchanged; wallets read position as
  `subtreeIndex × 16 + leaf`. Unused subtree leaves are the empty leaf.
- **Deposits** are spends of two dummies with a negative balance (built). In a batch
  the depositor signs their funding input interactively; solo, they build the pool
  transaction themselves.
- **Coordinator.** Users submit `(proof, publics)` off-chain; the coordinator assembles
  a round of up to K. Solo submission with K = 1 is the censorship-resistance
  fallback and uses the same scripts. A lost race is an instant rebuild.

**Per transfer, on chain:** verifier slot 463 KB + proof 91 KB + a K-th of the
append slot, about 600 KB. A 10 MB pool transaction holds 14–16 transfers; chained at
about one per second that is on the order of 15 transfers per second. Fees at Teranode
rates are a few hundred satoshis per transfer.

**Later levers, both drop-in:** a roll-up proof replacing the append slot (91 KB per
round; the native prover below makes it affordable), and proof recursion so one
verifier slot covers many spends (v2, the route to hundreds per transaction).

**Build order.**

1. ~~Poseidon2 script emitter and the subtree-append slot; measure the estimate.~~ Done:
   `poseidon2_script_gen.dart` (lazy reduction, modulus pinned on the stack),
   `subtree_append_slot_gen.dart` (+ `NoteCommitmentTree.subtreePath/appendSubtree`),
   tests `poseidon2_script_gen_test`, `subtree_append_slot_test` (real round transaction,
   SIGHASH_SINGLE preimage, rejections). Per transfer the slot's share is ~36 KB at K = 16.
2. ~~`pp1_sp_script_gen.dart`: header, dispatch, Rabin create funnel, spend path for K;
   the verifier slot script.~~ Done (2026-09-19): `pp1_sp_script_gen.dart` (`PP1SpHeader`
   with `parse`, `PP1SpScriptGen` with `lock/body/createUnlock/spendUnlock/roundOutputs`),
   `verifier_slot_gen.dart` (proof path and a *skip* path for an unused slot, which
   signs an empty `OP_RETURN`; the state gates each transfer on a used flag),
   `slot_script_common.dart`. Test `pp1_sp_test`: create with the Rabin identity, a round
   with a deposit and an unused slot, a round spending the deposited note with an
   unshield, every input of each round transaction verified in the interpreter;
   rejected: a signature for another tokenId, a create not spending `(tokenId, 0)`, an
   output left issued, the same transfer twice (nullifiers), an anchor outside the ring.
   One deviation from the SM funnel: the create binds `hashPrevouts` to `(tokenId, 0)`
   built from the header, not to a spender-supplied funding outpoint, so exactly one
   create per tokenId can ever exist. Measured at production verifier parameters:

   | K | state lock | state ops | state unlock | round tx | per transfer |
   | --- | --- | --- | --- | --- | --- |
   | 2 | 16.5 KB | 8.4 K | ~1.2 MB | ~3.0 MB | 1.5 MB |
   | 8 | 56 KB | 31 K | ~1.3 MB | ~6.5 MB | 813 KB |
   | 14 | 96 KB | 54 K | ~1.4 MB | ~10.0 MB | 714 KB |

   The 10 MB transaction policy therefore caps a round at K = 13 with today's verifier
   (465 KB) and append slot (684 KB, depth-5 subtrees so K ≤ 16 fits one slot).
3. ~~Circuit: remove the append walks (t=12), publics without `rootBefore/Mid/After`
   and the position pins; `SiblingBinding` stays as a tested tool.~~ Done (2026-09-19).
   `PoolSpendAir` is back to 2^12 rows (64 periods per half: key, cm, 32-step
   membership walk, nf, out1, out2, filler), 29 columns, 96 constraints, 10 groups,
   50 publics (anchor, nf1, nf2, cm1, cm2, balance limbs, outHash). Spend proofs are
   state-free again. The standalone covenant (`pool_covenant_gen.dart`) is retired;
   PP1_SP is its successor. Measured at production parameters: verifier slot
   **392,989 B** (was 464,909), proof 74,822 B, prover 52 s of which grinding 14 s,
   verify 0.6 s. Rounds at K = 8: ~5.8 MB (731 KB/transfer); K = 14: ~8.9 MB
   (636 KB/transfer), so K = 14 fits the 10 MB policy now.
4. ~~Lock builder with `parse()`, unlock builders, `ShieldedPoolTool` (issuance,
   create, round assembly), template export and sync test, lifecycle and negative
   tests (replayed genesis, forged slot, cross-round double spend).~~ Done (2026-09-19).
   `PP1SpLockBuilder` (+ `PP1SpSlotLockBuilder`), `PP1SpUnlockBuilder` (create/round,
   preimage set in the second pass), `VerifierSlotUnlockBuilder` (proof/skip),
   `AppendSlotUnlockBuilder`; `ShieldedPoolTool` with `createIssuanceTxn` (tokenId =
   the funding txid, whose output 0 the genesis consumes), `createGenesisTxn` and
   `createRoundTxn`, which builds the whole round, signs deposit funding inputs and
   advances a `PoolLedger` (header, vault, tree, nullifier set). Rounds carry no change
   output of their own: what the vault, the slots and the extra outputs leave is the
   fee. Tool-level test `shielded_pool_tool_test`: issuance, genesis, a deposit round
   with a signed depositor input and change, a spend round with an unshield, every
   input of every transaction verified in the interpreter, a foreign identity's
   signature rejected, the wallet refusing a re-spend. Templates in `templates/sp/`
   (`pp1_sp_k8.json`, `pp1_sp_verifier.json`, `pp1_sp_append.json`), exported by
   `tool/export_templates.dart` as category `sp` and checked by
   `test/template_sync_test.dart` (folded in on 2026-09-19).

   One layout fix found by the tool: a slot signs SIGHASH_SINGLE over the output at
   its own input index, so the K + 1 results occupy vouts 1..K+1 and the fresh slots
   sit at K+2..2K+2 of every round transaction. The genesis now emits K + 1 empty
   results so it has the same layout, and the state script's hashPrevouts check
   names those vouts.
5. ~~FRI re-tune for prover speed.~~ Done (2026-09-19). Measured at 2^12 rows (verifier
   slot bytes / proof bytes / Dart prover, one thread):

   | blowup / queries / grinding bytes | bits | slot | proof | prover |
   | --- | --- | --- | --- | --- |
   | 256 / 10 / 3 (before) | 104 | 393 KB | 75 KB | 52 s |
   | 128 / 13 / 2 | 107 | 455 KB | 92 KB | 19 s |
   | 64 / 15 / 2 | 106 | 494 KB | 100 KB | 9.8 s |
   | **32 / 18 / 2 (chosen)** | **106** | **554 KB** | **113 KB** | **5.3 s** |
   | 16 / 23 / 2 | 108 | 653 KB | 136 KB | 2.7 s |

   Three grinding bytes cost 10–40 s of luck; two cost 0.1 s, paid for with two or
   three more queries. `PoolSpendAir.productionParams` is now blowup 32, 18 queries,
   16-bit grinding, 128 randomizers; verify 1.0 s in the interpreter; the templates
   are re-exported. Rounds: K = 8 is ~7.3 MB, K = 11 ~9.3 MB, so **K ≤ 11** under the
   10 MB policy at about 810 KB per transfer. Blowup 64 / 15 queries is the
   alternative if round size matters more than latency (K ≤ 13, ~10 s).
   After the public dummy flags (52 publics): verifier slot 555,268 B; state lock
   K = 2 18.1 KB / 9.1 K ops, K = 8 62.6 KB / 33.8 K ops, K = 14 107 KB / 58.5 K ops;
   round tx K = 8 ~7.3 MB (916 KB per transfer), K = 14 ~11.4 MB; K ≤ 11 still holds.

### The native prover (built)

At production parameters the Dart prover spent 5.1 s, of which only 0.4 s was the
AIR-specific composition evaluation; the rest was generic: low-degree extension and
Merkle hashing of the trace and composition (2.0 s), DEEP quotients (1.6 s) and FRI
folds (1.0 s). Those kernels now live in a small Rust crate, `native/stark_kernels`
(no external crates, `cargo build --release`), called through `dart:ffi`. The prover
was refactored onto a `ProverKernels` interface with two implementations, `DartKernels`
(the reference) and `StarkKernels` (native), so the transcript, the composition
evaluation and the proof layout stay in Dart and a proof is byte-identical whichever
implementation runs. `StarkKernels.tryLoad()` finds the library under the crate's
release directory or `$STARK_KERNELS_LIB` and the prover uses it by default, falling
back to Dart when it is not built. Native kernels are exact ports: canonical M31
arithmetic with the same reduction, the same twin layout, the same SHA256 leaf
serialisation; the trace and composition columns are evaluated in parallel with scoped
threads, as are the leaf hashes, tree levels and the DEEP loop.

| Stage (production params) | Dart | native |
|---|---|---|
| trace interpolation | 67 ms | 106 ms (includes the table warm-up) |
| trace LDE + Merkle | 814 ms | 56 ms |
| composition values (Dart both ways) | 403 ms | 348 ms |
| composition LDE + Merkle | 1146 ms | 96 ms |
| DEEP quotients + circle fold | 1558 ms | 36 ms |
| FRI layers | 1009 ms | 69 ms |
| **total** | **4.5–5.1 s** | **0.77 s** |

`test/stark_kernels_test.dart` checks SHA256 against `package:crypto`, every kernel
against `DartKernels` on random inputs (including accumulation and low-degree
extension), and whole proofs at test and production parameters. What remains in Dart
is the composition evaluation (0.35 s, AIR-specific) and the openings; porting the
Poseidon2 chain constraint evaluator would bring the prover to about 0.4 s.

### Recursion (built): a verifier inside the proof

The route to hundreds of spends per round is one verifier slot per round checking one
proof that itself verifies many spend proofs. The building block is a STARK whose
statement is "this inner proof verifies", and the test of the design is that it can
verify *itself* without growing: the same circuit, the same proof size and the same
prover time at every depth.

**Hash flavours.** Inner proofs commit and run their transcript with Poseidon2 over M31
(`Poseidon2ProofHash`): one permutation is 32 rows of the chain AIR, whereas SHA256
would cost tens of thousands of constraints. Only the outermost proof, the one a script
verifies, keeps SHA256. The transcript is in *chain form* (an 8-lane state h, h' =
P(h ‖ block)[0..8]) so every transcript step is one period of the chain; the
statement (publics padded to 64 lanes, then the preprocessed root or zeros) is absorbed
in nine fixed periods, and the state afterwards is the *statement digest*, the only
public input of the verifier circuit. `StarkVerifierRef` is the Dart reference verifier
for both flavours, check for check the script's order, and the executable spec the
circuit follows.

**Generic constraints and preprocessed columns.** An AIR's constraints are written
once against a `Ring<T>` (`constraintsG`): over QM31 they are the spec, over `M31Ring`
the prover's fast path, and over an `ExprRing` or the circuit's own `_WireRing` they
become straight-line arithmetic. The cleared-denominator out-of-domain check
(`Air.oodCheckG`) is what the script does and what the circuit evaluates. A fourth
commitment holds *preprocessed columns* (`Air.numPreCols`), fixed per circuit
instance, opened per query, root pinned by the verifier.

**The verifier AIR (`VerifierAir`).** One circuit for every inner shape: 24 main
columns (16 Poseidon2 state lanes, two 4-limb bus operands A and B), 20 aux columns
(a LogUp accumulator with tags and four helper inverses), 32 preprocessed program
columns, 69 + 8 main constraints and 5 aux constraints. The hash side is the chain:
the transcript replay, leaf chains and Merkle walks whose direction bits are the
(boolean) swap bits. Every value lives on the *bus* (producers tagged by row,
consumers by program tag, multiplicities from the program); a small VM (add, sub,
mul, mul-by-immediate, constant, limb extract) does the field arithmetic: the inner
AIR's constraint program at z, the DEEP quotients, folds, the query points from
their bits, the range checks that bind walk bits and grinding bits to the squeezed
lanes. `VerifierProgram.compile(shape, logTrace)` lays out the verification of an
inner shape as periods and VM rows and fills the program columns;
`witness(proof)` runs the same builder with values.

**Measured.** `test/recursion_depth_test.dart` (small parameters, 2^15 trace) and
`test/recursion_production_test.dart` (production-grade: the spend proof exactly as
the pool makes it, 106 conjectured bits; verifier levels at blowup 16, 22 queries,
14-bit grinding, about 102 bits, on a 2^18 trace):

| Level | Inner statement | Periods used | VM rows | Prover | Proof | Verify |
|---|---|---|---|---|---|---|
| 0 | the spend (production params) | | | 1.3 s | 107,852 B | |
| 1 | the spend proof | 3,341 of 8,192 | 42,060 | 62.2 s | 255,892 B | 83 ms |
| 2 | level 1 (a verifier proof) | 7,950 of 8,192 | 80,160 | 60.6 s | 255,892 B | 84 ms |
| 3 | level 2 | 7,950 of 8,192 | 80,160 | 62.4 s | 255,892 B | 84 ms |
| 4 | level 3 | 7,950 of 8,192 | 80,160 | 62.6 s | 255,892 B | 81 ms |

From level 2 on the program columns are identical (the test asserts it), so the
circuit, the preprocessed root, the proof size and the prover time are the same at
every further depth. Of the 61 s per level, 35 s is the composition evaluation of the
verifier's own constraints in Dart (through the generic `M31Ring`); the native kernels
do the rest in about 26 s. Porting that evaluation to the Rust crate is the next
lever and would bring a level to roughly half a minute. Compile and witness
generation are under 0.4 s.

**Aggregation on chain (built).** The outermost level and the round around it:

- *The verifier AIR in script.* Its constraints are the recorded `ExprRing` programs
  (`VerifierAir.mainProgram/auxProgram`) compiled to script by a generic
  `ProgramScriptGen` (every node four limbs, rolled at its last use), so the AIR has no
  hand-written emitter: 588 + 226 operations, 344 QM31 multiplications, 156 KB and 102 K
  ops for the out-of-domain check. `StarkVerifierGen` opens the preprocessed columns
  per query against a root baked into the script.
- *The wide statement.* The root's public inputs are every transfer's raw publics
  (56 lanes each, the spend's 52 padded to chunks) and three round chunks (the tree
  root before and after, the subtree index). In the circuit they are *public columns*
  (`Air.pubColumns`): a column holding public chunk c at the hash-input row of the
  period that absorbs it, zero elsewhere, pinned by `pinPub` to lanes 8..15 of that
  row. The prover extends them like trace columns; the script evaluates each at z in
  closed form with the trace domain's Lagrange kernel,
  v(z) Σ_c p_c s_c (1 + ⟨z, h_c⟩) / (z × h_c), s_c = (−1)^{r_c}/2^t, one hinted
  inverse per chunk (checked against the FFT interpolant), about 330 ops per chunk.
  Nothing else crosses the SHA256/Poseidon2 boundary.
- *Digest chains.* An aggregator node verifies k inner proofs and publishes one 8-lane
  digest, the Poseidon2 chain over the inner statement digests. The root re-derives
  every digest from the raw publics: the spends' statements from the pinned chunks,
  each level's node digests and statements (its preprocessed root as VM constants),
  and pins the top proof's publics to the result. Every preprocessed root a walk
  checks is the same wire the statement absorbed (a per-query hint before, a
  soundness gap now closed).
- *The tree update.* The root hashes the round's commitments into whole 32-leaf
  subtrees (a Merkle node takes its two children from the bus: a program column pins
  the high input half to the *next* row's operands), walks each slot empty from the
  root before and filled to the root after, so the append slot is gone.
- *One slot per round.* `PP1SpScriptGen.aggregated`: the state input reads N × 56 + 24
  lanes and per transfer applies the balance, the two nullifier insertions and the
  extra-output hash as before, checks rootBefore against ring[0] and the index
  against size/32, and rebuilds the single result output `OP_RETURN SHA256(all
  lanes)`; the verifier slot is the root's (`VerifierSlotGen(airFor:)`).
  `PoolAggregation` is the coordinator's driver (levels compiled once, preprocessed
  roots as constants); `ShieldedPoolTool.createAggregatedRoundTxn` builds the round,
  `PoolChainReader` reads it back.

Measured at small parameters (`test/recursion_tree_test.dart`,
`test/pp1_sp_aggregated_test.dart`: four deposits, two level-1 verifiers on 2^15,
one level-2 on 2^16, the wide root on 2^15 in SHA256 flavour): root program 861
periods and 248 public lanes; root proof 22,004 B; root verifier script 357 KB and
248 K ops, 0.5 s in the interpreter; state body 26 KB; the round transaction 811 KB
with three inputs verified in 1.1 s; aggregation 31 s end to end.

### Sizing the round at production parameters (measured)

The root slot's script was generated at production shape (spends at the pool's
production parameters, verifier levels on 2^18 then 2^19 with blowup 32 and 18
queries, the wide root on 2^19; `tool/scratch/root_script_size.dart`) and counted
the way the node does: opcodes above OP_16, pushes free. Four generic cuts to the
script verifier took the fixed part from 434 K to 336 K ops and the per-transfer
part from 2.4 K to 2.2 K:

- the query index's bits are split once per query and every Merkle path,
  selector and twiddle sign picks them (7 ops per path level instead of 12);
- the DEEP group at z·g takes weights λ_C·λ_B^j instead of λ_C^j, so both groups
  share one weighted sum of the openings per query point (the prover, reference
  verifier, in-circuit verifier and script all changed; two independent
  challenges keep the combination sound);
- the DEEP precompute multiplies by the two-limb `conj(v) − v` with a half-width
  product and reads operands in place, as does the compiled constraint program;
- the public-column accumulation loops over chunks innermost so the running sum
  never leaves the top of the stack.

| root FRI (blowup / queries / grind) | bits | fixed ops | + per transfer | script fixed B | + per transfer | proof B | transfers under 1 M ops |
|---|---|---|---|---|---|---|---|
| 16 / 22 / 16-bit | 104 | 385 K | 2,156 | 894 K | 5.5 K | 285 K | 285 |
| 32 / 18 / 16-bit | 106 | 336 K | 2,156 | 782 K | 5.5 K | 246 K | 308 |
| 64 / 15 / 16-bit | 106 | 299 K | 2,156 | 698 K | 5.5 K | 215 K | 325 |

The aggregated state script costs 1.1 K ops fixed plus 3,432 ops and 5.9 KB per
transfer (nullifier set and per-transfer bookkeeping), so it reaches the 1 M-op
limit at 291 transfers: the state input binds first, at about 290 transfers per
round. A 290-transfer round is then roughly 6 MB (slot 2.4 MB, state 1.7 MB plus
its 1.5 MB unlock, proof 0.25 MB), under the 10 MB transaction limit, and the
root program needs about 14,600 periods of the 16,384 on 2^19 (24 periods per
transfer over the 7,800 the top proof costs). Beyond that the state script and
the root trace both need work: the state script's per-transfer cost (a second
1 M-op budget) and 2^20 for the root. Halving the per-transfer lanes (anchors
checked in-circuit against the ring, commitments only through the tree) would
cut the slot's per-transfer cost to about 1.1 K ops and the state's by a third.

### Proving the round at production parameters (measured)

A depth-2 round (four transfers: two level-1 nodes on 2^18, one level-2 node
and the wide root on 2^19, all at blowup 32 with 18 queries and 16-bit grinding)
was proved end to end on a 12-core laptop with 36 GB, and the root proof was
accepted by the generated script in the interpreter. The first run showed the
Dart composition loop at 45% of a node (37 s of 83 s at 2^18, 74 s of 179 s at
2^19), so the AIR's constraints are now recorded once as a straight-line program
and evaluated row by row in the native crate (`sk_composition`), which brought
the composition to 1.4 s and 3.0 s; the same run also found the preprocessed
commitment cache keyed on the AIR instance (recomputed per node, never
released: the root ran out of the 30 GB Dart heap), now keyed on the program
and capped. Per node afterwards:

| node | trace | flavour | prover | of which | proof |
|---|---|---|---|---|---|
| level 1 (2 spends) | 2^18 × 79 cols | Poseidon2 | 38 s | comp LDE+Merkle 11.5, FRI 10, aux 4.7, LDE 4.1, oods 3.2, DEEP 4.3, comp 1.4 | 226,604 B |
| level 2 (2 level-1 proofs) | 2^19 × 79 cols | Poseidon2 | 88 s | comp LDE+Merkle 26, FRI 17, DEEP 14.6, aux 9.3, LDE 8.4, oods 6.5, comp 3.0 | 243,988 B |
| wide root (4 transfers) | 2^19 × 79 cols | SHA256 | 54 s | comp LDE+Merkle 12.3, DEEP 13.3, oods 6.6, FRI 6.1, aux 4.4, pre 3.6, comp 3.0 | 244,948 B |

Compiling the three programs takes 18 s and 8 GB; a 2^19 node peaks at 25 GB
resident, most of it uncollected garbage under the 30 GB default heap (the live
set is the 5.3 GB extension plus a few GB). The root's script for four transfers
is 804,456 bytes and 344,558 ops (unlock 258 KB), and the interpreter runs it in
2.7 s. Verification by the reference verifier is 70 ms per node.

**What a 256-transfer round costs.** Arity 2 over eight levels is 128 level-1
nodes and 127 deeper nodes plus the root: 128 × 38 + 127 × 88 + 54 ≈ 16,000 s,
about 4.5 hours of prover time, or 63 s per transfer, on this machine. The
native kernels already use every core, so running nodes side by side gains
little on one machine; a round of this size wants either many machines (each
level-1 node is independent, deeper levels pairwise) or a cheaper node. Where a
2^19 node's 88 s goes: the composition polynomial has eight times the trace's
degree, so its extension and Merkle tree sit on 2^27 positions (26 s) and FRI
starts there (17 s) as does DEEP quotient A; splitting the composition into
eight trace-degree columns, as other Circle STARK provers do, would put FRI and
DEEP on 2^24 and take roughly 40 s off the node, at the cost of eight times the
composition openings per query in the script. The Dart parts that remain are
the aux round (the bus helpers, 9.3 s), the out-of-domain evaluation (6.5 s) and
the trace interpolation; each is a straightforward native port. Verifying an
inner proof costs about 7,000 periods on 2^19, so a node verifying two proofs
is the unit of work, and halving the queries on inner levels is not available
(18 already at blowup 32).

Padding a round to arity^depth with dummy transfers in the coordinator and
native Poseidon2 grinding remain to be built.

### Re-tuning the inner proofs (sized)

The 4.5 hours are 27 times the budget of ten minutes per round on one
machine, so the parameters were re-sized around prover throughput. The
production parameters (blowup 32, 18 queries) were chosen for the on-chain
script, where cost is per query; but inner proofs never reach the chain, and
their verification cost inside the next circuit is per query while their
proving cost is per blowup. Periods one in-circuit verification costs, from the
program compiler at about 104 bits (queries × log blowup + 16 bits of
grinding), and the wallet's proving time for a spend:

| blowup, queries | spend proof: periods, wallet prover | verifier proof at 2^19: periods |
|---|---|---|
| 4, 45 | 6,793, 0.2 s | 16,037 |
| 8, 30 | 4,888, 0.3 s | 11,342 |
| 16, 22 | 3,850, 0.7 s | 8,798 |
| 32, 18 (today) | 3,364, 1.3 s | 7,586 |
| 64, 15 | 2,983, 2.6 s | 6,647 |
| 256, 11 | 2,453, 5.1 s (measured) | 5,355 |

A node's prover time scales with its blowup for the extension, Merkle, DEEP and
FRI stages (66 of the 88 s at 2^19) and not for the rest (22 s), so the search
over spend parameters, level-1 node size and parameters, and inner node size and
parameters gives, for 256 transfers: spends at blowup 256 with 11 queries; level
1 on 2^20 at blowup 8 with 30 queries holding 13 spends (20 nodes); inner nodes
on 2^21 at blowup 8 holding 5 proofs; then a narrowing to a blowup-32 top proof
the root can verify (two nodes on 2^20 and one on 2^19 at blowup 32, or a root
on 2^20 verifying the 2^21 top proof directly). That is 25 nodes and about 40
minutes instead of 255 nodes and 4.5 hours, a 7× cut with no new code beyond
parameters. Measured, not modelled: a real level-1 node on 2^20 at blowup 8 over
13 spends at blowup 256 proves in 67 s (model said 77), proof 394 KB, live set
about 2.6 GB (Dart peaked at 19 GB with garbage). Per transfer that is 5.1 s
at level 1 against 19 s today. Costs move: the wallet's spend proof goes from
1.3 s to 5.1 s and shrinks from 108 KB to 79 KB. At low blowup the Dart stages
dominate a node (out-of-domain evaluation 13 s, aux round 8 s, composition
upload 6 s of the 67), so their native ports are now the next lever and would
take a node to roughly 40 s, the round to about 25 minutes on one machine.

*Native ports built.* The out-of-domain evaluation runs in the crate
(`sk_eval_at`, every coefficient column at a point), and so do the LogUp aux
columns: the verifier AIR describes its bus as a recorded program (per helper,
the enable, value, tag and multiplicity; `Air.logUpSpec`) and `sk_logup_columns`
runs it per row, batch-inverts the denominators and accumulates. Proofs stay
byte-identical to the Dart path. The 2^20 level-1 node over 13 spends went
from 67 s to 49 s: the out-of-domain stage from 13.3 s to 0.3 s, the aux round
from 7.8 s to 4.0 s (what remains is its interpolation and commitment). Of the
49 s, the composition's extension and Merkle tree take 11.6, FRI 8.4, the
composition kernel 6.4 (mostly copying 2.6 GB of column values into native
memory), the preprocessed commitment 6.1 (cached across a level's nodes in a
real round), the trace extension 4.1 and the aux round 4.0. Per transfer at
level 1 that is 3.8 s.

*Composition split built (protocol change).* The composition polynomial has
2^(t+e) coefficients, eight times the trace's, and used to be committed on its
own domain eight times the trace's, where its extension, Merkle tree, DEEP
quotient and FRI cost most of a node. It is now cut into 2^e blocks of
trace-size coefficient ranges in the circle FFT basis (block k's coefficients
are relative to the basis elements M_k(x), products of the doubling chain of x
from pi_{t-1}), each block committed as four limb columns on the trace domain.
The verifier recombines C(z) = sum_k M_k(z_x) C_k(z) from the doubling chain it
already computes, one DEEP group covers every column opened at z (trace, aux,
preprocessed, then the blocks; group C stays the trace at z·g), the quotient is
circle-folded once and FRI starts at the trace domain, three layers shorter.
Every query walks one domain, so the verifier's per-query work shrank in the
script and in the circuit: an in-circuit verification costs 15 to 19% fewer
periods, and the level-1 node on 2^20 now holds 16 spends. The 2^20 node over
13 spends: 34 s (from 49), of which composition 7.6, preprocessed commitment
6.3 (cached in a round), composition extension and Merkle 5.8, trace
extension 4.4, aux round 4.2, DEEP 3.3, FRI 1.2; proof 327 KB (from 394),
peak memory 12 GB (from 20). A spend proof at blowup 256 takes 3.2 s and 64 KB
(from 5.1 s and 79 KB). Both provers, the reference verifier, the script and
the in-circuit verifier were updated together; proofs stay byte-identical
between the FFT prover and the reference, and every suite passes with the
templates re-exported. The plan is re-cut to 16 × 4 × 2 × 2 = 256 transfers
(24 nodes), fitting at 31,872 of 32,768, 40,724 of 65,536, 21,986 of 32,768,
13,642 of 16,384 and 10,473 of 16,384 periods: about 16 × 34 s at level 1 and
an estimated 5 minutes above it, so roughly 14 minutes on one machine and, with
level 1 at the edge, about 5 minutes for the coordinator.

*Wired.* `PoolAggregation` takes one `AggregationLevel` (parameters, trace
size, arity) per level and `AggregationTree` one arity per level;
`PoolAggregation.throughput()` is the plan above as a 256-transfer tree
(16 × 4 × 2 × 2 after the composition split; 13 × 5 × 2 × 2 before: level 1 on 2^20 at blowup 8, level 2 on 2^21 at blowup 8, then
2^20 and 2^19 at blowup 32 to narrow to a top proof the 2^19 root verifies),
and a dry run compiles it without the multi-gigabyte commitments: the levels use
31,889 of 32,768, 61,070 of 65,536, 26,232 of 32,768 and 16,292 of 16,384
periods, the root 11,890 of 16,384 beside 14,584 public lanes. A 3 × 2 tree
with its own parameters per level proves and verifies end to end at small
parameters (`test/pool_aggregation_test.dart`). Rounds with fewer than 260
transfers still need the coordinator's dummy padding.

### Node cuts and the measured round (measured)

Four cuts to the native kernels, all keeping proofs byte-identical to the
Dart prover (`test/stark_kernels_test.dart` now covers both composition
paths):

- *Poseidon2, sixteen states at a time.* Committing 30 columns on 2^23 points
  took 5.4 s under Poseidon2 against 1.5 s under SHA256: the Merkle hashing
  was 4.3 s of it. The permutation now runs on 16 states in struct-of-arrays
  layout so every field operation vectorises, the external matrix is the
  paper's add chain and the internal diagonal is 31-bit rotations instead of
  multiplications; leaves and tree levels are hashed 16 at a time. The same
  commit is 2.1 s (hashing about 1.0 s). A spend proof at blowup 256 drops
  from 3.2 s to 1.5 s.
- *The composition program in row blocks.* The constraint program ran one row
  at a time, 13 ns per op; it now runs 16 rows per op so the dispatch is paid
  once per block and the arithmetic vectorises: 7.5 s to 3.7 s.
- *Committed values reused; DEEP sums by column.* With blowup equal to the
  composition expansion the composition domain is the commit domain, so the
  committed evaluations are passed to the kernel instead of re-evaluating
  every column (3.7 s to 2.6 s). The DEEP weighted sum walked 190 column
  streams per row; it now sums one contiguous column at a time over row
  blocks: 3.3 s to 0.5 s.
- *A native column store.* The committed evaluations never come back to Dart:
  the commit kernels keep them and return an id, and the composition, DEEP
  and opening steps read them in place; the prover releases them when the
  proof is done and the preprocessed-commitment cache (now 8 entries, one
  per level and one for the root) when it evicts. That removes four
  multi-gigabyte copies per node and most of the Dart heap: the level-1 node
  peaks at 8.7 GB (from 12.5), and the 2^20 nodes at blowup 32 the plan
  needs above level 2 fit at all.

The level-1 node on 2^20 over 16 spends: 12.0 s standalone (from 33.7 s at
the start of this pass and 34 s for 13 spends before it), 10 s inside a round
where its preprocessed commitment is cached. What is left: composition
extension and Merkle 2.2 s, composition 2.0, aux round 1.7, trace extension
1.5, trace interpolation 0.8, DEEP 0.5, FRI 0.4.

*The round, measured.* `tool/scratch/round_throughput.dart` proves the
256-transfer plan (16 × 4 × 2 × 2, then the wide root) end to end at
production parameters on the 12-core laptop:

| stage | nodes | per node | total |
|---|---|---|---|
| level 1, 2^20 at blowup 8 / 30 queries, 16 spends each | 16 | 10.9 s | 173.8 s |
| level 2, 2^21 at blowup 8 / 30 queries, 4 proofs each | 4 | 21.1 s | 84.4 s |
| level 3, 2^20 at blowup 32 / 18 queries, 2 proofs each | 2 | 34.0 s | 67.9 s |
| level 4, 2^19 at blowup 32 / 18 queries | 1 | 14.3 s | 14.3 s |
| root, 2^19 at blowup 32 / 18 queries, SHA256 flavour | 1 | 15.5 s | 15.5 s |
| **round** | 24 | | **356 s (5.9 min)** |

The preprocessed commitments of the four levels take 20.8 s once and stay
cached across rounds (19.4 GB of the 23.8 GB peak). The 256 spend proofs are
the wallets' work (1.5 s each) and are excluded; the reference verifier checks
every node in 0.1 s. The root script is 2,208,106 bytes and 882,775 ops (under
Teranode's 1 M), the unlock 314 KB, and the interpreter accepts it in 15.2 s.
So a 256-transfer round costs 6 minutes of one machine, inside the 10-minute
budget; with level 1 at the edge the coordinator's share is 3 minutes. The
blowup-32 nodes of levels 3 and 4 are the most expensive per node (their
extensions run on 2^25 points) and the next thing to look at, together with
the composition commitment (32 limb columns per node).

### Moving proving to the edge (considered)

The round's work is a tree whose leaves are the transfers, so it distributes
naturally; the question is what a wallet can carry. The measured shape gives
three tiers:

- **Every wallet proves its spend** (already the case): 5 s and a few hundred MB
  at blowup 256, on anything from a phone up.
- **Level-1 nodes at the edge.** A node folds 13 spends in 67 s with a 2.6 GB
  live set: a desktop or a corporate server, not a phone. The coordinator
  groups 13 admitted transfers, sends their proofs and public statements to one
  of the 13 wallets (or any volunteer with the resources), and receives a
  level-1 proof it verifies in 70 ms. Nothing is trusted: a bad or late node is
  proved by the coordinator itself, a 67 s penalty, so liveness is the
  coordinator's fallback rather than a protocol assumption. Privacy is
  unchanged: a folding wallet sees other transfers' proofs and public statements,
  which the chain shows anyway. With level 1 at the edge the coordinator does
  the inner and narrowing nodes and the root, about 15 minutes today and about
  9 with the native ports, inside the ten-minute budget on one machine.
- **Inner nodes at the edge too.** A 2^21 node (5 proofs, about 135 s, 5.3 GB)
  suits corporate servers; then the coordinator keeps only the narrowing to the
  top proof and the root, about 5 minutes.

What this needs in code: the aggregation already proves each node from proofs
and shapes (`witnessAll` then `prove`), so the change is a work-assignment
message (proofs and statements out, a proof back), verification of returned
nodes, timeouts with local fallback, and the wallet side running the prover
with the native crate. It moves the coordinator's machine-hours to the
participants in proportion to their transfers, which fits the corporate
deployments where participants run servers, and it keeps a phone-only user
able to transact at the cost of never being asked to fold.

### The key hierarchy (built)

One spending key did everything: `pk_d = H(sk, d)`, `nf = H(sk, rho)`, and the
circuit proved knowledge of `sk`. Nothing could be handed to a third party
without handing over the funds. The circuit now derives two keys from the `sk`
register and uses them in place of `sk`:

    ivk = H(sk, tagIvk)      pk_d = H(ivk, d)       (address, tag 1)
    nk  = H(sk, tagNk)       nf   = H(nk, rho)      (nullifier, tag 2)

Per note that is two more Poseidon2 periods (the trace has room: 40 of 64 per
half). Every lane of a derivation's input is pinned: `sk` from its register, the
tag, and zero padding, as is the padding beside `d` and `rho`. Holding `ivk`
lets a viewer detect and open every note sent to the wallet's addresses; `ivk`
and `nk` together also show which of them were spent, which is a full account
history for an auditor; neither can produce a spend, since the circuit needs the
`sk` behind both. This is the piece that had to land before the address format
is frozen. What remains for view keys to be usable: encrypted note ciphertexts
in the round transaction (bytes only, no script cost) and a KEM choice.

Pinning the padding also closed a hole. In the previous layout the nullifier was
a fresh period `P(sk, rho ‖ pad)` whose high half was free witness, since a
break period's sixteen input lanes are all witness and only eight were pinned.
A spender could therefore produce a different valid nullifier for the same note
per padding value and spend it as often as they liked. Verified against the old
circuit before the change (a tampered padding lane, a recomputed nullifier, all
constraints satisfied); the new cheat tests cover the padding beside the
nullifier, the tags, and the padding beside the viewing key and the
diversifier.

### Settled for corporate use: notes, ciphertexts, the issuer role (decided)

Target uses: payroll and vendor payments, trading and treasury, supply-chain
settlement, tokenized securities and RMBS-style instruments. Decided 2026-09-19,
before the note and address formats freeze. Judgment calls are marked *(call)*.

**Note layout.** A note is `(asset, pk_d, value, rho, rcm)` with the memo outside
the commitment:

    s  = H(pk_d ‖ value_lo, value_hi ‖ rho)          as today
    cm = H(s ‖ rcm ‖ asset[0..3])                    asset in the four spare lanes

- `asset` is 4 lanes, 124 bits: the low 124 bits of `SHA256(asset record)`. BSV is
  the constant `(1, 0, 0, 0)`. Ids are self-certifying, so the pool header keeps
  no asset registry; whoever presents the record whose hash is the id, signed by
  the record's issuer key, may mint it. A forged record needs a 2^124 preimage.
- `value` stays two 28-bit limbs (56 bits) in the issuer's chosen unit.
- A transfer moves one asset: three new registers hold the asset lanes for the
  whole trace and are pinned at both input commitments and both output notes.
  Dummies carry the transfer's asset. `publicOut` is that asset's public balance.
- *(call)* **The asset id is public**, four more public lanes (52 → 56, still
  seven chunks, so the aggregated root's per-transfer cost is unchanged).
  Amounts and parties stay hidden; which asset a transfer moves does not. This
  is what lets the state script apply per-asset rules without the circuit
  carrying a policy-flag lane, a reveal bit and a range check on it, and it fits
  the target uses, where the instrument is known to the parties anyway. Hiding
  the asset type later (as Zcash's shielded assets do) is an additive change:
  a flags lane in the id, a private reveal bit, and `outHash` truncated to
  seven lanes to keep 56 publics.
- The memo is 512 bytes, in the ciphertext only, as in Zcash: invoice and
  settlement references, structured payloads. Not consensus data.

**Keys and addresses.** `sk` derives `ivk = H(sk,1)`, `nk = H(sk,2)` (in the
circuit, built above) and `ovk = H(sk,3)` (wallet only). An address is
`(d, pk_d, epk_d)` with `pk_d = H(ivk, d)` and `epk_d` the public key of a KEM
key pair generated deterministically from `H(ivk, d, 4)`, so `ivk` alone decrypts
every diversified address of the wallet. `pk_d` and `epk_d` are not bound to each
other by the chain; a forged address pairing pays the right `pk_d` with an
unreadable ciphertext, which only the recipient can detect, the same trust as
any address exchange.

**Ciphertexts.** Per output note the sender produces a bundle:

1. *Recipient ciphertext.* `KEM.Encaps(epk_d)` → shared secret; note key
   `K = HKDF(secret, cm)`; `AEAD_K(plaintext, aad = cm)` with plaintext
   `version(1) ‖ asset(16) ‖ d(12) ‖ value(7) ‖ rho(12) ‖ rcm(16) ‖ memo(512)`.
   Binding the key and the AAD to `cm` stops a ciphertext being replayed
   under another commitment.
2. *Outgoing copy.* `AEAD_{HKDF(ovk, cm)}(secret ‖ d)`, 60 bytes: an auditor
   holding `ovk` recovers the note key and reads what the wallet sent.
3. *Issuer copy*, only for gated assets: the same `secret ‖ d` encapsulated to
   the asset record's issuer KEM key, so the issuer reads every note of its
   asset.

*(call)* **KEM: X25519 + ML-KEM-768 hybrid**, HKDF-SHA256, ChaCha20-Poly1305.
The proofs are post-quantum sound; ECDH alone would leave thirty-year
instruments open to harvest-now-decrypt-later on amounts and counterparties.
The cost is size: 1,088 bytes of ML-KEM ciphertext and 1,184 of public key per
address, about 1.7 KB per output note, 1 MB per full round, inside the 10 MB
transaction. X25519, HKDF and ChaCha20-Poly1305 come from the `cryptography`
package already in use; ML-KEM goes into the native Rust crate beside the
prover kernels.

**Where the bundles live.** Each transfer gets its own `OP_RETURN` output in the
round transaction carrying its bundles in output-note order. That output is one
of the transfer's extra outputs, so the transfer's `outHash`, which the spend
proof already binds, covers it: a coordinator cannot swap or garble a
ciphertext. The state script does not read it; the chain reader indexes it.

**The issuer role, per asset.** The asset record is
`(issuer Rabin key hash, nonce, flags)`; `flags` has one bit today, *gated*.

- *Mint* = a transfer of the asset with negative `publicOut`, carrying the
  record, the issuer's Rabin signature over `SHA256(the transfer's public lanes)`
  and the record's hash matching the asset id; the state script checks all
  three. Supply is public arithmetic over mints and burns; no header field.
- *Burn* = positive `publicOut` on a non-BSV asset: allowed freely, the vault
  does not move, redemption is the issuer's off-chain obligation.
- *Gated asset*: every transfer of it in a round carries an issuer signature over
  its public lanes, verified by the state script (Rabin, cheap in ops). The
  nullifiers make each message unique, so no replay. The issuer reads the
  transfer through the issuer copy before signing, which gives eligibility
  checks, holder registry and freezes (refuse to sign) without any credential
  proof in the circuit. BSV and ungated tokens stay fully shielded.
- *Forced transfer*: not by spending someone's note. The supported path is a
  burn-and-reissue under the gate: the frozen units stay frozen, replacement
  units are minted to the ordered recipient, and the issuer's public mint and
  burn records reconcile supply. An in-circuit revocation list is the
  alternative if ever required; it costs a second non-membership proof per
  input.

**Also settled.** No swap id lane now: atomic swaps are a later, additive
change (a shared id in the publics and a same-round pairing check in the state
script). One-to-many payments are a circuit variant with up to about
sixteen outputs in the present trace, also additive. Authorization separate from
proving (a hardware-held key) is not provided; the spending key lives with the
prover behind the operator's approval flow.

**Build order.** (1) `PoolHash`/note classes: asset lanes, `ovk`, KEM key
derivation, the ciphertext bundle and the extra output; (2) the circuit's asset
registers and public lanes, then the state script's per-asset rules (mint, burn,
gate), tool and chain reader; (3) ML-KEM in the native crate. None of it changes
the recursion or the round sizing beyond four public lanes per transfer.

*Step 1 built.* `PoolHash.commit` takes the asset (`cm = H(s ‖ rcm ‖ asset)`,
BSV = `(1,0,0,0)`), `ovk`, `diversifier(ivk, i)` and `assetIdOf`; `AssetRecord`;
`SpendNote`/`OutputNote` carry an asset. The circuit's commitment blocks carry
the asset lanes and pin them to BSV until step 2 makes them registers with
public lanes, so the circuit stays sound at every commit. The wallet layer is
`lib/src/crypto/note_encryption.dart`: `PoolWalletKeys`, `NoteAddress`
(`(d, pk_d, epk)`, KEM key pair from `SHA256("tsl1-pool-kem" ‖ ivk ‖ d)`,
enumerable by index), `NotePlaintext` (576 bytes with a 512-byte memo),
`NoteBundle` (recipient ciphertext, outgoing copy, optional issuer copy, the
commitment it is for) and `NoteEncryption` over X25519, HKDF-SHA256 and
ChaCha20-Poly1305 from the `cryptography` package; KEM id 1 is X25519, the
hybrid is id 2 (step 3). An X25519-only bundle is 739 bytes; a transfer's
note-data output `OP_RETURN 'TSLN' <bundles>` for two such notes is 1,497 bytes, built
by `ShieldedPoolTool.extras(bundles, payouts)` as the first extra output so
`outHash` covers it; `PoolRound.noteBundles` returns a round's bundles for
trial decryption. Tested end to end in `test/note_encryption_test.dart` and the
chain-reader test (a round carrying a bundle, opened by the recipient's viewing
key and the sender's outgoing key).

*Step 2 built.* The circuit has four asset registers (columns 27..30, constant
over the trace) pinned to the asset lanes of both commitments and both output
notes, and to four new public lanes (`PoolPublicInputs.asset`, 52..55; 56 lanes,
still seven chunks). One asset per transfer; dummies carry it; `witness` rejects
a mix. The asset id's lane 3 holds the record's gated flag in bit 30 above 30
hash bits (123 hash bits in all), so the state script reads gated-ness off the
id. The state script now: applies `publicOut` to the vault only for BSV
(`vout -= isBsv * delta`); for a token that is minted (`delta < 0`) or gated it
requires, per transfer, the asset record and the issuer's Rabin signature over
SHA256 of the transfer's 56 lane bytes, and checks that the record hashes to the
asset id, that hash160 of the Rabin key is the record's first 20 bytes, and the
signature; burns pass freely. `IssuerAuth.sign(record, publics, p:, q:)` builds
the authorisation, `PoolTransfer(auth:)` carries it, the tool refuses a transfer
that needs one without it, and the chain reader moves the vault only for BSV.
Tested: a token mint trace with register and public-lane cheats
(`test/pool_spend_air_test.dart`) and, on chain, a gated mint, a gated transfer
and a mint signed by the wrong key that the state script refuses
(`test/shielded_pool_tool_test.dart`).

*Step 3 built.* ML-KEM-768 (FIPS 203) runs in the native crate through the
RustCrypto `ml-kem` crate (its only dependency; `zeroize` pinned to 1.8.1 for
Rust 1.84) behind three C functions, `sk_mlkem768_public_key`, `_encaps` and
`_decaps` (ABI version 3). Keys are never stored: both are regenerated from a
64-byte seed `d ‖ z`, so the Dart side only ever holds seeds, public keys and
ciphertexts; encapsulation re-encodes the key and refuses one that does not
round-trip (the standard's modulus check); decapsulation never fails (implicit
rejection). `lib/src/crypto/note_kem.dart` defines the KEM ids: 1 is X25519
alone, 2 (the default for new addresses and issuer keys) the hybrid whose
public key is the X25519 key followed by the ML-KEM encapsulation key
(32 + 1,184 bytes), whose ephemeral value is the X25519 ephemeral key followed by
the ML-KEM ciphertext (32 + 1,088 bytes), and whose shared secret is
`SHA256("tsl1-pool-hybrid" ‖ ss_ML ‖ ss_X ‖ eph_X ‖ pk_X)`, so both schemes must
fall and the secret is bound to the exchange. `KemKeyPair.fromSeed(seed, kem:)`
derives the X25519 pair from the 32-byte seed itself (a hybrid address's X25519
half is the X25519-only address of the same `(ivk, d)`) and the ML-KEM seed as
`SHA256("tsl1-pool-mlkem-d" ‖ seed) ‖ SHA256("tsl1-pool-mlkem-z" ‖ seed)`.
`NoteBundle` prefixes each KEM value with its id, which fixes its length; the
issuer copy has its own id (zero for none), so issuer keys may use either KEM.
A hybrid bundle is 1,827 bytes, 3,027 with a hybrid issuer copy; the note-data
output for two hybrid notes is 3,673 bytes, so a transfer's on-chain data grows
from about 7.5 KB to about 9.7 KB (about 2.8 MB for a 290-transfer round, well
inside 10 MB). Tested in `test/note_encryption_test.dart` (deterministic keys,
round trip, refused keys, tampering of either half opens nothing, X25519-only
addresses and issuer keys still work) and the chain-reader round now carries a
hybrid bundle.

## Open Items

- ~~**Deposits bloat the nullifier set.**~~ Done: the public `real1`/`real2` flags
  (pinned to the flag register) let the state script skip a dummy's insertion.
- **TSL1 integration.** Planned as PP1_SP above; `PoolCovenantGen` becomes the spend
  path of its state script.
- **Budget.** Under Teranode the 500 KB framing is obsolete; what matters is bytes
  per transfer and ops per script. Unclaimed cuts still apply to the verifier slot:
  Lagrange-form periodic evaluation (~20 KB), QM31-coefficient zero pins (~3 KB).
- **Prover performance.** 95 s in Dart at a 2²⁴ composition domain, single-threaded;
  FFTs and Merkle dominate now that grinding is short. Isolates, Uint32List QM31.
- **dartsv.** The FindAndDelete fix and the earlier interpreter changes are
  uncommitted in the local checkout; its own test runner is broken by an SDK/tooling
  mismatch, so it is validated through this repository's suite.
- **Shielding TSL1 fungible tokens.** FT tokens are locked to a `recipientPKH` and
  spent via `ModP2PKH`. A covenant cannot hold a key, so a pool cannot own an FT
  UTXO. Phase 1 shields satoshis; shielding FTs needs owner-as-script-hash support
  in the FT archetype.
- **Wallet scanning: the chain reader (built).** `PoolChainReader`
  (`lib/src/transaction/pool_chain_reader.dart`) rebuilds a `PoolLedger` from the
  transactions alone: `fromGenesis(genesisTx)` reads the header and vault from output
  0, `apply(roundTx)` reads each verifier slot's unlocking script (the selector is the
  last push, the 50 publics are the first pushes, decoded by
  `PoolPublicInputs.fromLanes` with the signed high limb), inserts the nullifiers and
  appends the round's leaves, then checks its model against what the round committed
  to: each result output against its slot's unlock, the append payload against the
  rebuilt subtree, the new header and vault against the rebuilt ledger, and the fresh
  slots against the generator's bytes. Nothing cryptographic is re-verified. A round
  that fails a check is refused before the model is touched. Leaves are placed by slot:
  transfer t's commitments sit at leaves 2t and 2t+1 of the subtree, an idle slot
  contributes two empty leaves, so a note's position is subtree × 32 + 2 × slot +
  which (`ShieldedPoolTool.roundLeaves`). This is the state script's own convention;
  the tool used to pack used slots first, which only agreed when slot 0 was used.
  Test `pool_chain_reader_test`: genesis, a deposit with the idle slot first, a spend,
  a tampered round refused, and a third round proved and built from a reader's ledger
  alone, every input verified. Wallets keep the full tree and the full transaction
  history: they keep every pool transaction offline anyway for SPV and Merkle proofs,
  so no pruning or frontier-only variant is planned (decision 2026-09-19).
- **Node policy.** Teranode defaults: 100 MB per script, 10 MB per transaction,
  1,000,000 ops per script, 100 MB stack memory; `MinMiningTxFee` 0.00000500 with the
  unit unstated. Policy dependencies ZEC never has.
- **Note encryption KEM.** Built as the X25519 + ML-KEM-768 hybrid (corporate
  step 3), so note privacy is post-quantum; the cost is about 1.1 KB more
  ciphertext per note.
