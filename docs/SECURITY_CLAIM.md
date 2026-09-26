# TSL1 Shielded Pool: Security Claim

**Status:** DRAFT, written 2026-09-26 against commit `bf80068`; updated the same day after deviation D1 was fixed (change `grind-binds-queries`, uncommitted at the time of writing). Authored by the project. Nothing in it has been independently reviewed. Its purpose is to state, precisely enough to be checked, what the pool's proof system and covenant layer claim, under which assumptions, and what evidence exists today. Where writing it down exposed a gap between the claim and the code, the gap is recorded in section 5 rather than papered over.

Every statement below carries one of these labels:

- **CLAIMED**: the authors assert it and argue it here or in the design record (`docs/ZK_SHIELDED_POOL_TSL1_DESIGN.md`, cited as "design §n").
- **TESTED**: a named test exercises it, including the attack it refuses.
- **MEASURED**: a number from a real run, with where it was run.
- **OPEN**: owed. Listed again in section 12 with an id.
- **DEVIATION**: the code does not match the claim as previously stated. Listed in section 5.

## 1. The claim in one paragraph

A TSL1_SP pool is a chain of Bitcoin SV transactions whose state output carries a 236-byte header (commitment root, nullifier root, a ring of four recent roots, tree size, balance, bundle hash). A round advances the header by spending the previous round's covenant outputs together with a verifier slot whose locking script is a Circle-STARK verifier in Bitcoin script. That script accepts one root proof, which recursively verifies one proof per level down to one masked spend proof per transfer. The claim is: **no round that moves value or advances the header can be mined unless every transfer in it satisfies the spend statement (section 8.1) against the pool's own recent roots, no nullifier is used twice, and the header after the round is the one the transfers imply**, and this holds against any coordinator, with soundness error at most 2^-102 under the conjecture named in section 4 (2^-58 under the proven bound), grinding included now that deviation D1 is fixed. A dishonest coordinator can freeze the pool; it cannot take from it (design §8.3). Separately, a spend proof reveals nothing about the spender's keys, notes or values beyond its public statement (section 7).

## 2. Assumptions, named

| Id | Assumption | Where it is used |
|---|---|---|
| A1 | SHA-256 is collision resistant and, as a chained 32-byte state, behaves as a random oracle for Fiat-Shamir | root-proof transcript and Merkle commitments; outHash; txids; the covenants' preimage hashes |
| A2 | The Poseidon2-M31 instance of section 6, truncated to 8 lanes (248 bits), is collision and preimage resistant as a compression function, and behaves as a random oracle for Fiat-Shamir in the inner levels | note commitments, nullifiers, both Merkle trees, inner-level transcripts and Merkle commitments, statement digests |
| A3 | Circle-FRI soundness. **Proven:** the Johnson-bound regime (proximity parameter 1 − sqrt(ρ) − η) as established for circle codes in the Circle STARKs paper. **Conjectured:** proximity gaps up to capacity (proximity parameter 1 − ρ − η), the conjecture the Circle STARKs paper and Haböck's FRI summary adopt for their "conjectured" columns | the query-count column of section 4 |
| A4 | The Fiat-Shamir transform of the multi-round protocol is sound in the random-oracle model, i.e. the non-interactive soundness is the interactive soundness up to the adversary's oracle queries | every proof |
| A5 | Bitcoin SV consensus as implemented by the node software miners run: sighash preimage layout, `OP_CODESEPARATOR` scriptCode semantics, post-Genesis script limits, and the policy limits the design relies on (100 MB per script, 10 MB per transaction, 1M ops per script) | every covenant; the root slot's size |
| A6 | The recursive verifier AIR (`lib/src/recursion/verifier_air.dart`, `verifier_program.dart`) enforces exactly what the reference verifier (`lib/src/crypto/stark_verifier_ref.dart`) enforces | every inner level; OPEN O4 |
| A7 | The emitted Bitcoin script (`lib/src/script_gen/stark_verifier_gen.dart` and the emitters it uses) enforces exactly what the reference verifier enforces, for every input it can be given | the root slot; OPEN O7 |

A2 is the assumption that most needs outside work: the round count is Plonky3's but the round constants are this project's (section 6). A3's conjectured form has had its strongest variants challenged in the literature; this document treats the proven column as the claim and the conjectured column as the design target, and O11 asks the reviewer to confirm the current status of both bounds for circle codes.

## 3. The proof system

**Field.** Mersenne-31, p = 2^31 − 1. Challenges, out-of-domain values and quotients live in the degree-4 extension QM31 (|QM31| ≈ 2^124).

**Domains.** A trace of 2^t rows is interpolated on a circle-group coset of size 2^t in twin layout (position i holds a point of the half coset, position M + i its conjugate) and committed on the half coset of size 2^(t' + b − 1), where b is the log blowup and t' = t + 1 when zero-knowledge masking is on (masked columns have degree up to 2^t). The field bounds t + 3 + b ≤ 30.

**Composition.** The constraint polynomial has 2^(t + 3) coefficients (logExpand 3, so constraint degree at most 8 over the trace; the Poseidon2 round constraint is degree 6). It is committed as 2^(3 − (t' − t)) blocks of trace-size coefficient ranges, four M31 limb columns per block, on the same commitment domain as the trace. The verifier recombines the blocks' values at the out-of-domain point z with the circle-basis multipliers and checks the result against the constraints evaluated at z from the opened trace values (at z and z·g) and the public inputs.

**DEEP and FRI.** Two DEEP quotient groups: every column at z (trace, aux, preprocessed, composition blocks) with weights that are powers of one challenge, and the trace columns at z·g with the same weights scaled by a second challenge. The two are folded once on the circle and then by line folds down to a final polynomial of degree 2^(logFinal − logBlowup), sent in the clear. Every layer's Merkle root enters the transcript before the next fold challenge.

**Queries.** Each query opens, at one index of the commitment domain, one leaf per commitment (trace, aux, preprocessed, composition) with its Merkle path, and the fold pairs along the path with theirs. Every field inverse the verifier needs is supplied as a hint and checked by multiplication. Query indices are drawn with replacement; the verifier does not require them to be distinct (a repeat is a wasted query, and the bound in section 4 is for draws with replacement).

**Commitments.** Binary Merkle trees of fixed depth equal to the index width. SHA-256 flavour: leaf = SHA256(lanes as little-endian u32), node = SHA256(left ‖ right). Poseidon2 flavour: leaf = chain of P(h ‖ chunk)[0..8] over zero-padded 8-lane chunks from h = 0^8, node = P(left ‖ right)[0..8]. Neither flavour tags leaves and nodes differently; the fixed depth is what rules out leaf/node confusion (OPEN O12 asks for that argument to be written).

**Two provers, one proof.** The FFT prover (Dart or native kernels) and the reference prover produce byte-identical proofs (TESTED, `test/stark_kernels_test.dart`, `test/stark_prover_test.dart`).

## 4. Parameters and soundness, per level

The production plan (`PoolAggregation.throughput`, `lib/src/recursion/pool_aggregator.dart`) is 16 × 4 × 2 × 2 = 256 transfers a round. Only the root is verified by a script; every other proof is verified inside the proof above it.

| Level | Proves | Flavour | log trace | ρ = 2^−b | queries | final poly coefs | line folds | index bits | grind bits as built |
|---|---|---|---|---|---|---|---|---|---|
| Spend (wallet) | one transfer, masked | Poseidon2 | 12 (13 masked) | 2^−8 | 11 | 32 | 7 | 20 | 14 |
| Level 1, ×16 | 16 spends + ring check | Poseidon2 | 20 | 2^−3 | 30 | 32 | 14 | 22 | 14 |
| Level 2, ×4 | 4 level-1 proofs + nullifier insertions | Poseidon2 | 21 | 2^−3 | 30 | 32 | 15 | 23 | 14 |
| Level 3, ×2 | 2 level-2 proofs | Poseidon2 | 20 | 2^−4 | 23 | 128 | 12 | 23 | 14 |
| Level 4, ×2 | 2 level-3 proofs | Poseidon2 | 19 | 2^−4 | 23 | 64 | 12 | 22 | 14 |
| Root, on chain | 1 level-4 proof + wide statement + tree update | SHA-256 | 19 | 2^−5 | 18 | 32 | 13 | 23 | 16 |

Parameter sets: `spendThroughputParams`, `innerParams20`, `innerParams21`, `narrowParams20`, `narrowParams19`, `rootParams19`, all in `pool_aggregator.dart`. "Grind bits as built" is 8 per grind byte in the SHA-256 flavour and 7 per grind byte in the Poseidon2 flavour (`Poseidon2Transcript.grindBits`); both use 2 grind bytes.

**Soundness per level.** The query error is (1 − θ)^q with θ the proximity parameter, plus additive terms in 1/|QM31| for the DEEP batching, the out-of-domain check and each fold, which at these domain sizes (≤ 2^23) and |QM31| ≈ 2^124 are below 2^−60 and are neglected here (O11 asks for them to be written out).

| Level | Queries, conjectured (θ = 1 − ρ): q · b | Queries, proven (θ = 1 − sqrt ρ): q · b / 2 | Grind | Claim: conjectured / proven | Before D1 was fixed |
|---|---|---|---|---|---|
| Spend | 88 | 44 | 14 | **102 / 58** | 88 / 44 |
| Level 1 | 90 | 45 | 14 | 104 / 59 | 90 / 45 |
| Level 2 | 90 | 45 | 14 | 104 / 59 | 90 / 45 |
| Level 3 | 92 | 46 | 14 | 106 / 60 | 92 / 46 |
| Level 4 | 92 | 46 | 14 | 106 / 60 | 92 / 46 |
| Root | 90 | 45 | 16 | **106 / 61** | 90 / 45 |

The grind counts because the query indices are squeezed from the grind digest (section 9, step 12), so every attempt at a fresh query set costs the grind again. Until 2026-09-26 it did not (D1), and the last column is what the system had.

**System soundness.** A forged round needs a forged proof at some level, so the system's soundness is the minimum over levels: **2^−102 conjectured, 2^−58 proven**, set by the spend level, assuming A6 (the AIR is a faithful verifier) for every inner level and A7 for the root.

**What the spec says.** `openspec/specs/stark-prover/spec.md` now states both columns and names the conjecture, and requires at least 100 bits in the conjectured column of every production set, which every set meets. The proven column is recorded, not required; whether to require it is a decision for the project (D3).

## 5. Deviations found while writing this document

### D1. The grinding nonce did not enter the state that derives the query indices

**FIXED 2026-09-26**, change `grind-binds-queries`. In both flavours a successful grind check now makes the grind digest the transcript state, and the query indices are squeezed from it; the script emitter keeps the hash as `ts` and the verifier AIR continues from the grind period. The attack below is now a test: a valid proof with its nonce replaced by the next nonce that also grinds is refused by the reference verifier at `query 0 index`, by the script at its index comparison, and has no verifier-AIR witness (`test/grind_binds_queries_test.dart`, `test/stark_verifier_pieces_test.dart`, `test/verifier_air_test.dart`). Every proof, template and localnet chain made before the fix is invalid against this code. The text below describes the code as it was.

**What the code did.** In all four implementations the transcript state S after absorbing the final polynomial is used twice: the grind check verifies that H(S ‖ nonce) has its low bits zero, and the query indices are then squeezed from S itself, not from H(S ‖ nonce). The state is deliberately not advanced:

- `TranscriptRef.checkGrinding` (`lib/src/script_gen/fiat_shamir_script_gen.dart`) computes the hash locally and leaves `state` unchanged; `squeezeIndices` then hashes `state`.
- `Poseidon2Transcript.checkGrinding` (`lib/src/crypto/proof_hash.dart`), whose doc comment says "the state is not advanced".
- `FiatShamirScriptGen.emitGrindingCheck` picks `ts`, hashes it with the nonce, checks the zero bytes and drops the result, leaving `ts` as it was.
- `VerifierProgram` (`lib/src/recursion/verifier_program.dart`) saves `stateBeforeGrind`, absorbs the nonce to check the grind lane, then restores `_cur = stateBeforeGrind` before squeezing indices.

The reference verifier `StarkVerifierRef.verify` does the same, so all implementations agree; this is a protocol weakness, not a mismatch.

**Why it matters.** Grinding is meant to make every attempt at a fresh query set cost 2^16 hashes. Here the indices are a function of S alone, so an adversary who wants a different query set changes something absorbed into S (the cheapest is a final-polynomial coefficient), reads the new indices at the cost of one hash, and grinds only once, for the S whose indices they like. The grind is a fixed 2^16 cost paid once, not a multiplier. Its 16 bits (14 in the inner levels) must not be counted toward soundness. This is why section 4's claim is 88 / 44 rather than the ~104 / ~106 in the code comments.

**Fix.** Derive the indices from the post-grind digest: set the state to H(S ‖ nonce) after checking its zero bits and squeeze indices from there (in `TranscriptRef`, `Poseidon2Transcript`, `emitGrindingCheck`, and `VerifierProgram`, where `_cur` becomes the grind period's output). The nonce search itself is unchanged. It is a protocol change: every existing proof, exported template, test vector and the localnet chains become invalid, and the protocol version must move. The cost in script is nil (the hash is already computed; it is kept instead of dropped). Done; O1 is closed.

### D2. The Poseidon2 flavour grinds 14 bits, not 16

`Poseidon2Transcript.grindBits` is 7 per grind byte because one bit-lane row per byte is what the AIR checks. Every inner level therefore grinds 14 bits. Code comments and the aggregation spec spoke of 16-bit grinding throughout; the `stark-prover` spec now says 14 for the Poseidon2 flavour and section 4 counts it so. Remaining: the comments in `pool_aggregator.dart` (O13).

### D3. The spec's security formula states the conjecture without naming it

See the end of section 4. `stark-prover/spec.md` counted queries × logBlowup + 8 × grindBytes without naming the conjecture, while the grind counted for nothing (D1). Since 2026-09-26 it states both columns with their assumptions and counts the Poseidon2 grind at 7 bits a byte. What remains a decision is whether the proven column should carry a requirement: no production set reaches 64 proven bits (the best is 61), and raising the root from 18 to 20 queries would add about 37,000 ops to a slot of about 647,000 (MEASURED, 256 transfers; `verifier-script/spec.md`) for 5 more. `verifier-script/spec.md` also still gives 14,360 public lanes for the aggregated slot; the lane reduction made it 8,392 (section 8.3).

## 6. The Poseidon2-M31 instance

`Poseidon2M31` in `lib/src/crypto/poseidon2_m31.dart`. Width 16, S-box x^5, 8 external rounds split 4 + 4 around 14 internal rounds, an initial external linear layer before the first round.

- **External matrix:** circ(2·M4, M4, M4, M4) with the Poseidon2 paper's M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]. Plonky3's.
- **Internal matrix:** J + diag(−2, 2^0, 2^1, …, 2^8, 2^10, 2^12, …, 2^16). Plonky3's Mersenne-31 diagonal.
- **Round constants:** this project's own. Derived by rejection sampling: for counter ctr = 0, 1, …, take SHA256(seed ‖ LE32(ctr)), read eight little-endian u32 words, mask each to 31 bits, keep those below p, until 8 × 16 + 14 = 142 constants are drawn; the first 128 are the external constants (16 per external round, in order), the last 14 the internal constants (added to lane 0 only). The seed is the ASCII string `TSL1-Poseidon2-M31-w16-RF8-RP14-v1`. Plonky3 has no canonical Mersenne-31 constants, so nothing interoperable was given up.
- **Modes of use.** Compression: P(left8 ‖ right8)[0..8] (Merkle nodes, statement chaining). Sponge-like chain from h = 0^8 over zero-padded 8-lane chunks (leaves, transcript absorb). Squeeze: P(s ‖ 0^8)[0..8]. Grind: P(s ‖ [nonce, 0, …])[0] low bits zero.
- **In circuit:** `Poseidon2Air` (`lib/src/script_gen/poseidon2_air.dart`), one round per row, 16 state columns, 32 rows per permutation, 19 periodic columns (16 round constants, three row-type selectors), one degree-6 constraint per lane.

**CLAIMED:** the instance has the security of Plonky3's Mersenne-31 instance, since only the constants differ and they are fixed, dense and derived from a public seed. **OPEN O3:** an algebraic analysis (Gröbner basis, interpolation, differential) of this exact instance confirming round-count margin. Note for the analyst that lane values are 31-bit and the compression truncates to 8 lanes (248-bit digest, so 124-bit collision resistance is the most A2 can give).

## 7. Zero-knowledge claim

**Who sees what.**

| Party | Sees | Does not see (CLAIMED) |
|---|---|---|
| Public (chain) | the root proof, the wide statement (section 8.3), the round's outputs, the ciphertext bundles, the header | any spend proof; any anchor; any note field, key, value or address; which round an input note came from beyond the ring of four |
| Coordinator | every spend proof and its full 56-lane statement (including anchor and commitments), everything the public sees | any witness of a spend proof: sk, nk, ivk, notes, rho, rcm, values, Merkle paths |
| Recipient with ivk | its own notes, via the bundles | others' notes |

**Revealed by design**, in the public statement of every transfer: both nullifiers, the signed public amount, outHash, the two real flags (so deposits and padding are distinguishable from spends), and the asset id (four lanes, public by the corporate-pool decision in `docs/LEGACY_ZK_SHIELDED_POOL_DESIGN.md`, "Settled for corporate use"). Withdrawal payees are in the round's outputs.

**Masking construction.** Spend proofs are proved with `zkRandomizers: 128`: every trace and aux column f is replaced by f' = f + v_N · r with r a uniformly random polynomial of degree < 128 and v_N the vanishing polynomial of the trace domain, so f' agrees with f on the trace domain and is uniform at up to 128 other points. `StarkParams.zkRandomizers`, `lib/src/crypto/stark_prover_ref.dart`.

**CLAIMED:** a spend proof at these parameters is statistically zero-knowledge with respect to everything but its statement. **OPEN O2:** the argument in the code (128 covers 2 × queries leaf openings) counts only the leaf openings. Each query also reveals the fold sibling at every FRI layer, and the final polynomial is sent in the clear; each of these is a further linear functional of the masked columns through the DEEP quotient. The claim needs a written count of the functionals revealed against the randomizer degrees of freedom across all columns, or a reduction to the standard zk-FRI argument, before it can be reviewed.

**Aggregation proofs are not masked** (zkRandomizers 0). CLAIMED this is fine because every witness they hold is either public (proof bytes, statements) or bound only through hashes: the anchors and commitments live in level-1 traces, which reach the public only as Poseidon2 digests inside higher proofs; the root's own trace holds the round's commitments (as witness for the tree update) and those are public anyway through the bundles. Level-1 to level-4 proofs never leave the coordinator's machines. The coordinator learns nothing from them it did not already learn from the spend statements.

## 8. Statements: what is bound, by what

### 8.1 The spend statement (56 lanes)

`PoolPublicInputs`, `lib/src/script_gen/pool_spend_air.dart`. Lane offsets: anchor 0..7, nullifier 1 8..15, nullifier 2 16..23, commitment 1 24..31, commitment 2 32..39, public amount low limb 40 and signed high limb 41, outHash 42..49 (SHA-256 of W_t ‖ c_t masked to 31-bit lanes), real flags 50 and 51, asset 52..55.

The circuit (`PoolSpendAir`, spec `pool-spend-circuit`) enforces: ivk = H(sk, tagIvk) and nk = H(sk, tagNk) from the sk register; pk_d = H(ivk, d); each real input note's commitment sits under the anchor at depth 32 and both real inputs share the anchor; nullifier_i = H(nk, rho_i) for real inputs; dummy inputs have value zero and no path; both output commitments are Poseidon2 hashes of (pk_d, value, rho, rcm, asset); inputs = outputs + publicOut in one asset; every value fits 56 bits as two 28-bit limbs; the asset lanes equal the asset registers in all four notes. The statement is absorbed first in the transcript, so the proof is bound to outHash without the circuit reading it.

### 8.2 Level statements

Digest mode (levels 1 to 4): the public input is one 8-lane Poseidon2 digest over the inner statements, each inner statement covering the inner AIR's publics and its preprocessed root. Level 1 additionally checks every real-input spend's anchor is in the round's ring of four, and its digest covers the ring and every spend's anchor and commitments (`verifier-recursion` spec, "Level-1 anchor check"). Level 2 additionally inserts each real input's nullifier into the keyed sparse nullifier tree (62 levels; slot = the nullifier's first two lanes as one 62-bit key; the all-ones lane pattern is forbidden so a zero lane has one decomposition) and absorbs the set's root before and after plus each transfer's nf1, nf2 and real-flag chunks (design §10.1).

### 8.3 The root's wide statement (what the chain sees)

`PoolStatement`, `lib/src/script_gen/pool_verifier_gen.dart`. For T transfers and S receipt slots:

| Offset (lanes) | Content |
|---|---|
| 0 .. 32T | per transfer, 32 lanes: nullifier 1 (8), nullifier 2 (8), then spend-statement lanes 40..55 (public amount 2, outHash 8, real flags 2, asset 4). Anchor and both commitments are **not** here |
| 32T + 0 | rootBefore (8): commitment root before the round |
| 32T + 8 | rootAfter (8) |
| 32T + 16 | first subtree index (one chunk) |
| 32T + 24 | ring (4 × 8), newest first |
| 32T + 56 | nfBefore (8), nfAfter (8) |
| 32T + 72 | S receipt slots, each: commitment (8), amount chunk (8) |

Production: T = 256, S = 8, 8,392 lanes. The root program derives the level-1 digests from these lanes and the ring in-circuit, proves that appending the round's commitments (witness values bound to the level-1 digests) as 32-leaf subtrees at the index takes rootBefore to rootAfter, and verifies the level-4 proof.

### 8.4 What the scripts check against the statement

**V** (the verifier slot, design §5.5, `PoolVerifierGen`) embeds header_N and reads header_{N+1} from the round's pushes. It checks: rootBefore = header_N.cmRoot; the statement ring = header_N.ring; nfBefore = header_N.nfRoot; index = header_N.size / 32; rootAfter = header_{N+1}.cmRoot; header_{N+1}.ring = [rootAfter, header_N.ring[0..2]]; header_{N+1}.size = header_N.size + leaves appended; nfAfter = header_{N+1}.nfRoot; header_{N+1}.balance = header_N.balance − Σ signed amounts, BSV only, and PP3_{N+1}'s value equals it; every transfer taking money out has exactly the next withdrawal output for exactly its amount and outHash_t = SHA256(W_t ‖ c_t); header_{N+1}.outHash = SHA256(c_0 ‖ … ‖ c_{T−1}); each receipt slot is used by the next receipt output with the slot's commitment and minus its amount, or is zero; every lane read as bytes or a number is in [0, p); the fixed-size pushes have their fixed sizes; the round's outputs (change, PP1 with header_{N+1}, PP2, PP3, metadata, receipts, withdrawals) rebuilt whole equal hashOutputs; and the owner's SIGHASH_ALL signature. PP1's and PP3's programs are constants of V's body.

**PP1** in the witness (design §5.2): the bundles hash to header.outHash; the pinned slot Y holds this pool's verifier body (by `verifierBodyHash`) initialised with this round's header and signer, rebuilt byte for byte to the pinned txid with yInput's length checked; PP3 names that slot and holds the header's balance; the round spent the previously pinned slot at input 2. **PP3** at mining time (design §5.4): hashPrevouts names the funding, witness, pinned slot, itself, the next anchor and the deposit covenants in order; output 3 runs its own program with the next slot (the forward covenant).

### 8.5 Not bound by the wide statement, and by what instead

- **Anchors and commitments:** bound in-circuit through the level-1 digests (spec `verifier-recursion`, "Substituted commitment"). Commitments reach the chain through the tree update and the bundles.
- **Ciphertext bundle bytes:** bound per transfer by c_t inside outHash_t (checked by V) and per round by header.outHash (checked by PP1 in the witness). Their meaning is not bound: bundles that do not decrypt are griefing (design §9).
- **Withdrawal payees:** bound through W_t in outHash_t.
- **PP2 and the metadata script:** not bound by V. CLAIMED that a wrong one can only stop the pool (design §5.5 step 6 lists whether V should pin them as open). OPEN O9 asks the covenant reviewer to confirm.

## 9. Transcript, in order

Both flavours run the same schedule; the state is 32 bytes (SHA-256) or 8 lanes (Poseidon2), initially zero. There are no domain-separation tags: separation is positional, and the fixed proof layout per parameter set is what makes each absorbed item's role unambiguous (OPEN O12 asks for that argument). Reference: `StarkVerifierRef.verify`; script: `FiatShamirScriptGen` (`emitAbsorb`, `emitAbsorbLimbs`, `emitSqueezeQM31`, `emitGrindingCheck`) driven by `StarkVerifierGen`; circuit: `VerifierProgram` (`_absorb`, `squeeze4`, `squeeze1`).

| # | Step | SHA-256 flavour | Poseidon2 flavour |
|---|---|---|---|
| 1 | absorb statement | publics as LE u32 (if any), then preRoot (if any), each as state = H(state ‖ bytes) | publics zero-padded to 64 lanes as 8 chunks, then preRoot or 8 zero lanes, each as s = P(s ‖ chunk)[0..8] |
| 2 | absorb trace root | H(state ‖ root) | P(s ‖ root)[0..8] |
| 3 | squeeze interaction challenges | numChallenges × QM31 (none for the spend AIR; the verifier AIR's LogUp bus has them) | same |
| 4 | absorb aux root | only if the AIR has aux columns | same |
| 5 | squeeze β (constraint batching) | one QM31 | same |
| 6 | absorb composition root | | |
| 7 | squeeze t; z = ((1 − t²)/(1 + t²), 2t/(1 + t²)) with the inverse as a hint | one QM31 | same |
| 8 | absorb out-of-domain values | trace at z, trace at z·g, composition blocks at z, as limbs | same, as lanes |
| 9 | squeeze λ_B, λ_C, α_circle (DEEP weights and circle-fold challenge) | three QM31 | same |
| 10 | per FRI layer l | absorb root_l; squeeze α_l | same |
| 11 | absorb final polynomial coefficients | as limbs | as lanes |
| 12 | grind | h = H(state ‖ nonce4) has grindBytes leading zero bytes; **state = h** (since D1 was fixed; before, the state was left unchanged) | d = P(s ‖ [nonce, 0…]) has lane 0's low 7·grindBytes bits zero; **s = d[0..8]** (likewise) |
| 13 | squeeze query indices | state = H(state); eight indices per squeeze from the u32 words, each mod 2^a | s = P(s ‖ 0^8); one index per squeeze from lane 0 masked to a bits |

A QM31 squeeze takes four 32-bit words, masks each to 31 bits and reduces mod p, so 0 is drawn with probability 2/2^31 and every other value 1/2^31; the bias is negligible. Query indices are exact draws (a ≤ 31). A proof in one flavour presented to a verifier of the other fails structurally (CLAIMED; `test/stark_hash_flavour_test.dart` covers determinism and distinct digests per flavour, not a cross-flavour verification attempt).

OPEN O5 is the reviewer's reconstruction of this table from the emitted root script alone.

## 10. The covenant layer

Argued in design §8 and attacked in design §9, §11.15, §16. Since 2026-09-26 also MODEL-CHECKED at the level of what each script enforces: `formal/tla/PoolRounds.tla` holds four safety invariants with every protection on, reproduces the attacks of §11.15 vectors 1 and 5, §5.6, §5.4 and §16 when the matching protection is switched off, and shows that an honest coordinator always has a next step (a possibility property checked as an invariant), which V without a signer breaks (design §21, `formal/tla/README.md`). Bytes and parsing are below that model. Stated here as claims for the covenant reviewer (OPEN O9):

- **C1, one chain per tokenId.** Every round's PP1 (executed in the witness) demands a parent chain that terminates at the funding outpoint whose txid is the tokenId, spent once. A header written into a fresh output can be mined but never advanced. TESTED: `test/pool_lineage_attack_test.dart` (a lookalike PP1 mined on localnet, refused by the proven-round check), `test/pool_evidence_test.dart` group "the forgery, against the ledger".
- **C2, every mined round was verified before it was mined.** PP3_N is spendable only beside Y_N:0, whose script is V carrying header_N, certified by PP1_N in witness N, which must exist for PP3_N to be spendable. The base case is PP1_0's create branch certifying Y_0 (design §11.15 vector 5). TESTED: `test/sp_token_test.dart`, `test/pool_round_v_test.dart`.
- **C3, a dishonest coordinator can freeze, not take.** V gates the value at mining time; PP3's forward covenant fixes the program holding it; the deposit covenants bind their receipts with SIGHASH_SINGLE. TESTED: `test/pool_verifier_test.dart` (an honest round, 28 attacks, and nine checks each removed in turn letting their attack through), `test/pool_deposit_test.dart` (refusals by name).
- **Script-level facts the reviewer should attack:** the wide 4-byte varint parsing with 0xff refused and a checked input limit (design §5.5, "What wiring it found"); yInput's length check (design §5.2); V's fixed-size push checks (design §5.5, "Built"); `OP_CODESEPARATOR` placement in V so that both checksigs' scriptCode is the two-opcode tail (design §11.6); PP3's scriptCode being its whole 49 KB program for the forward covenant; and any coordinator-chosen bytes (PP2, metadata, unlock padding, bundle segments) that a parse could land in.

## 11. Evidence today, and what is missing

**Tests.** 793 tests in 84 files at `bf80068`. The adversarial ones relevant here: the attack groups in `test/pool_verifier_test.dart`, `test/sp_token_test.dart`, `test/pool_deposit_test.dart`, `test/pool_round_v_test.dart`, `test/pool_lineage_attack_test.dart`; tampered openings, siblings, indices and hints in `test/m31_fri_script_gen_test.dart`; nullifier replay in `test/nullifier_aggregation_test.dart` and `test/pool_aggregation_test.dart`; 10,000-mutation runs against the chain reader (`test/pool_evidence_test.dart`) and the protocol codecs (`test/pool_protocol_test.dart`, `test/pool_catch_up_test.dart`). No mutation run exists against V or the root script (OPEN O6).

**Measured.** 256-transfer round proved end to end at production parameters in about 220 s, peak under 16 GB, on one 12-core machine (spec `pool-aggregation`). Root slot about 1.6 MB and 647,000 ops, accepted by the dartsv interpreter (spec `pool-state-script`). A production-shape round validated by SV Node 1.2.2 on regtest in 963 ms against its 1,000 ms limit (localnet harness run, 2026-09-22; the production mining times are in design §15, the validation time is not yet in the design record); ARC's scriptSig cap of 1,636,802 bytes currently blocks production witnesses from being submitted through ARC. No mainnet evidence exists (OPEN O10).

**Not evidence.** `docs/SECURITY_REVIEW.md` (2026-03-08) is a code-quality pass over the token builders and says nothing about the proof system.

## 12. Open items

| Id | Item | Kind | Owner |
|---|---|---|---|
| O1 | CLOSED 2026-09-26: D1 fixed in all four implementations, templates regenerated, negative tests added (change `grind-binds-queries`). The wire protocol did not move; the package's next release is a major version instead, since there is no proof-format version to bump | protocol change | project |
| O2 | Written zero-knowledge argument counting every functional the FRI phase reveals (section 7) | analysis | project, then reviewer |
| O3 | Algebraic cryptanalysis of the Poseidon2-M31 instance of section 6 | external | symmetric cryptanalyst |
| O4 | Constraint-by-constraint review of the verifier AIR against the reference verifier: Merkle direction bits bound to the index, every commitment absorbed before its challenge, out-of-domain values checked against the constraints, final polynomial degree bounded | external | STARK reviewer |
| O5 | Reconstruction of section 9 from the emitted root script alone | external | STARK reviewer |
| O6 | Mutation fuzzing of V and the root script: every bit of a valid root proof, then structural mutations (swap siblings, reorder queries, replay a leaf, rebind the header) | testing | project |
| O7 | Differential test of the emitted script against the reference verifier on a corpus of valid and invalid proofs; a range argument for the lazy M31/QM31 emitters (`StackEmitter.reduce`, `lib/src/script_gen/m31_script_gen.dart`) covering every input range they can meet | testing + analysis | project, then reviewer |
| O8 | Cross-implementation verification against an independent Circle-STARK verifier (stwo adapted to this transcript and the Poseidon2 flavour) | testing | project |
| O9 | Covenant-layer review of section 10 by a BSV script specialist, adding rows to design §9. The TLA+ model (design §21) is the starting point for the ordering half; the byte-level half (varints, yInput, fixed-size pushes) is not modelled | external | script reviewer |
| O10 | Production-size rounds on mainnet under miners' actual policy, over weeks, including a reorg; validation time measured on miners' node software with a stated margin | deployment | project |
| O11 | Confirm the current literature status of the proven and conjectured circle-FRI bounds, and write out the additive 1/|QM31| terms neglected in section 4 | analysis | reviewer |
| O12 | Write the arguments that positional transcript separation and fixed-depth Merkle trees rule out the classic ambiguities (section 3, section 9) | analysis | project |
| O13 | Correct `stark-prover/spec.md` (D3), `verifier-script/spec.md` (lane count) and the code comments carrying ~104 / ~106 | documentation | project |

## 13. Change log

- 2026-09-26: first draft. Found D1, D2 and D3 while writing sections 4 and 9.
- 2026-09-26, later: D1 fixed (change `grind-binds-queries`); section 4 counts the grind, D3 narrowed to the proven-column decision, O1 closed.
- 2026-09-26, later still: TLA+ model of the round state machine added (`formal/tla`), section 10 marked model-checked; liveness (honest coordinator can always advance) added as a possibility property.
