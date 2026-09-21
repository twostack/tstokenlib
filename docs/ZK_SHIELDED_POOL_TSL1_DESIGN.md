# Shielded Pool as a TSL1 State Machine Token

Speculative design for hosting the Circle-STARK shielded pool inside an unmodified TSL1 transaction structure: five outputs, PP1 inductive proof, PP2 witness bridge, PP3 partial SHA-256 lock, and a witness transaction per round. It replaces the PP1_SP archetype on `feature/shielded-pool`, which dropped PP2, PP3 and the witness and was shown to be cloneable.

**Status:** design only. Nothing here is built. Every size is an estimate assembled from measured parts unless the text says it was measured whole. Section 11 lists what is unknown and what would break the design if it turned out the wrong way. Section 12 gives the two tests that would settle it.

Companions: [ARCHITECTURE.md](ARCHITECTURE.md) for TSL1 itself, [ZK_SHIELDED_POOL_DESIGN.md](ZK_SHIELDED_POOL_DESIGN.md) for the pool's circuits, prover, aggregation and the measured history, including the section that records the clone.

---

## Table of Contents

1. [Why this document exists](#1-why-this-document-exists)
2. [Where bytes are paid in TSL1](#2-where-bytes-are-paid-in-tsl1)
3. [Design in one paragraph](#3-design-in-one-paragraph)
4. [Transactions per round](#4-transactions-per-round)
5. [Header and script changes](#5-header-and-script-changes)
6. [Round lifecycle](#6-round-lifecycle)
7. [Deposits, withdrawals, and what a wallet needs](#7-deposits-withdrawals-and-what-a-wallet-needs)
8. [Security argument](#8-security-argument)
9. [Attack pass](#9-attack-pass)
10. [Cost estimate](#10-cost-estimate)
11. [Unknowns and unproven assumptions](#11-unknowns-and-unproven-assumptions)
12. [What would settle it](#12-what-would-settle-it)
13. [Relation to existing code](#13-relation-to-existing-code)

---

## 1. Why this document exists

The PP1_SP state script checks its successor: the next round must spend the right outpoints and produce the right outputs. It never checks its parent. A phase-1 header written into an ordinary transaction's output, with the slot scripts copied beside it, advanced a round in the interpreter with all four inputs accepted and no genesis behind it (`tool/scratch/clone_the_chain.dart`, 2026-09-20). Because the nullifier set is per chain, a cloned chain is a double spend.

TSL1 does not have this problem. Its three locks and the witness make every link a spend, and the chain of spends terminates at an outpoint that can be spent once. Section 8 restates that argument for the pool. The reason it was not used from the start is cost: PP1 receives the parent transaction as raw bytes in the witness, and a pool round was 1.7 MB in direct-slot mode and 8.24 MB with 256 aggregated transfers. A witness that pushes 8 MB beside an 8 MB round is at the 10 MB policy limit for a single transaction.

Two fixes were costed and rejected: keeping the pool shape and hashing each round in a recursive SHA-256 proof (12 to 33 prover nodes per round, serial between rounds), or paying the witness as is. This document takes a third route. It keeps TSL1 exactly and changes where the pool's bytes live, so the witness has little to push.

## 2. Where bytes are paid in TSL1

Every byte in a token transaction is paid three times. It is mined once. PP1 rebuilds the transaction's outputs from pushed bytes in this round's witness to check them against its own txid. PP1 of the next round pushes the whole transaction, inputs and their unlocking scripts included, as the parent. So a token transaction's inputs are as expensive as its outputs, and anything that pushes a large blob inside a token transaction is re-pushed twice more.

A witness transaction is paid once. PP3 verifies it by resuming SHA-256 from a midstate over its last few blocks, and the next token transaction spends its single 35-byte output with an ordinary signature. Nothing in the protocol ever holds a witness's full bytes on a stack. Its size is bounded only by policy.

This is the whole design principle. Keep every token transaction small. Put every large thing either in the witness's unlocking data or in a separate transaction whose bytes are pushed once, in a witness.

The things that are large, for 256 transfers, from the measurements on the branch:

| Item | Size | Where it lives today |
|---|---|---|
| Root verifier slot script | 1.57 MB (before lane reduction, lower now) | round output, re-pushed in the next round's unlock |
| State script body (nullifier insertions in script) | 1.41 MB | round output, and again as the preimage's scriptCode |
| Nullifier insertion witnesses | 1.13 MB (512 x 2,306 B) | round unlock |
| Per-note ciphertext bundles | 917 KB (512 x 1,827 B hybrid KEM) | round outputs (extras) |
| Root proof | 230 KB | round unlock |

## 3. Design in one paragraph

The pool is one PP1_SM token. Its tokenId is the funding txid of the genesis round. Its mutable header is the pool state. Each round is one token transfer: five standard outputs, then a witness. The STARK verifier is not an output of any round. It is the single output of a small separate transaction, made before the round it serves, whose outpoint PP3 embeds and whose bytes the witness's PP1 checks. The nullifier tree leaves the state script and goes into the aggregation circuit. The ciphertext bundles leave the round's outputs and are published as unlocking data in the witness, bound to a hash in the header. What remains in a round is a few tens of kilobytes of scripts, a proof, and the withdrawals.

## 4. Transactions per round

Round N+1 is built from the products of round N. Three transactions are involved.

A measured walk-through of two consecutive rounds, with every transaction's inputs and outputs and the sizes this repository actually produces, is in [pool_round_anatomy.html](pool_round_anatomy.html). Its numbers come from `tool/scratch/two_round_probe.dart`.

**Naming.** A script is named for the output it locks, and it executes only when a later transaction spends that output. Those are two different positions with two different indices, and this document keeps them apart. PP3_N is the script locking **round N's output 3**; it executes when **round N+1 spends it at input 3**. (Every other TSL1 archetype spends PP3 at input 2; the pool moved it so that SIGHASH_SINGLE covers PP3's successor, see 5.4.) Writing "PP3_N (input 3)" would merge the two and state the wrong index as the script's identity.

### 4.1 Slot transaction Y_N

Created before round N by anyone, funded by anyone. Its content is fixed by round N's header, which the coordinator knows once round N's proof exists.

| | |
|---|---|
| Inputs | any funding |
| out0 | `V_N` = pushes of header_N, then the verifier body. 1 satoshi |

**Exactly one input and one output is a requirement, not a convention.** It is what forces V to be output 0: PP1 rebuilds Y from its parts rather than parsing it, so with the counts fixed at one a forged Y cannot park the real verifier somewhere inert and put an `OP_TRUE` where the round looks. The coordinator builds Y, so meeting the shape costs nothing. See 11.11 for why the alternative was dropped.

### 4.2 Round N+1, the token transaction

| Input | Spends | Unlocking data |
|---|---|---|
| 0 | coordinator funding | signature |
| 1 | witness_N out0 (ModP2PKH) | coordinator signature |
| 2 | Y_N out0 (V_N) | preimage (small, see 5.5), proof, round N+1's outputs for the hashOutputs rebuild |
| 3 | round N out3 (PP3_N) | SIGHASH_SINGLE preimage carrying PP3's whole script, midstate of witness_N, remainder blocks, output 3's value and slot |
| 4.. | deposit covenants | preimage only |

Inputs 2 and 3 are the other way round from every other TSL1 archetype, where PP3 is input 2. PP3's forward covenant signs SIGHASH_SINGLE, which covers the output at the spending input's own index, and the output it constrains is output 3. See 5.4.

| Output | Script | Value |
|---|---|---|
| 0 | change P2PKH | remainder |
| 1 | PP1_SM pool variant, header_{N+1} | 1 sat |
| 2 | PP2, unchanged | 1 sat |
| 3 | PP3 with `nextSlot` = (Y_{N+1}, 0), **the same program as PP3_N**, which PP3_N's covenant enforces | **the pool balance** |
| 4 | metadata, carried forward | 0 |
| 5.. | deposit receipts, `OP_FALSE OP_RETURN cm value` | 0 |
| then | withdrawals, P2PKH | as proved |

The pool balance lives in PP3's value. PP3 is spent only on the transfer path, into the next round. This removes the separate vault output and gives V a single value to check.

### 4.3 Witness N+1

| Input | Spends | Unlocking data |
|---|---|---|
| | coordinator funding | signature |
| | round N+1 out1 (PP1) | preimage, lhs of round N+1, round N raw (parent), round N+1's rebuilt outputs, **(Y_{N+1}, 0)**, **Y_{N+1}'s single input**, **the verifier body**, **the ciphertext bundles of round N+1**, padding, action flag |
| | round N+1 out2 (PP2) | preimage and fields as today |

Single output: ModP2PKH to the coordinator, as today. Input order is whatever the existing tool uses to keep PP3's remainder small; see 11.3.

Y_{N+1} is pushed as its outpoint plus its one input rather than whole, because PP1 rebuilds it rather than parsing it; see 5.2.

## 5. Header and script changes

### 5.1 Header

**BUILT 2026-09-20.** The state machine's nine-field header is gone and PP1_SP now carries the pool's own, as `PoolHeader` in `lib/src/shielded_pool/pool_header.dart`.

The mutable state is 236 bytes:

| Field | Offset | Bytes | Meaning |
|---|---|---|---|
| cmRoot | 0 | 32 | commitment tree root after this round |
| nfRoot | 32 | 32 | spent-nullifier tree root after this round (keyed sparse tree, 10.1) |
| ring | 64 | 4 x 32 | recent cmRoots that spend proofs may anchor to, newest first |
| size | 192 | 4 | leaves in the commitment tree, LE32 |
| balance | 196 | 8 | satoshis held by PP3, LE64 |
| outHash | 204 | 32 | hash of this round's ciphertext bundles |

It is **one push, not six**. Both places that touch the header want it whole. PP1's rebuild replaces the entire region in a single fixed-window substitution instead of threading six push prefixes through the altstack, which is what made the state machine's rebuild the longest routine in the generator. And V embeds the same blob, so binding V to header_{N+1} is one rebuild of `push(header) + body` and one hash comparison, rather than reassembling six pushes in the right order. Fields that script needs individually, `balance` and `outHash`, are read by splitting the blob at the offsets above.

The ring rotation is a circuit constraint, not a script one. The proof relates header_N to header_{N+1}, so V is what checks that the new ring is `[cmRoot_{N+1}, ring_N[0..2]]`. PP1 carries the field and never interprets it.

The script header is therefore:

```
[0:1]     0x14       [1:21]    ownerPKH         (20,  mutable)
[21:22]   0x20       [22:54]   tokenId          (32,  immutable)
[54:55]   0x20       [55:87]   verifierBodyHash (32,  immutable)
[87:89]   0x4c 0xec  [89:325]  genesisHeader    (236, immutable)
[325:327] 0x4c 0xec  [327:563] header           (236, mutable)
[563:]    script body (immutable)
```

Both header pushes carry a two-byte `OP_PUSHDATA1` prefix, because 236 is past the 75-byte direct-push limit. Everything else is a direct push.

**Why genesisHeader is carried in full.** It was first baked into the create branch as a 32-byte SHA-256 commitment, which is 200 bytes cheaper per round. That was wrong on two counts. A depositor needs to know the pool opened on an empty commitment tree before putting money in, and with only a commitment they have to be handed the preimage and trust it; carried in full, the opening state is readable straight off the chain. And a commitment in the body makes every pool's body different, so no single template can serve them, and `templates/sp/pp1_sp.json` would have to be regenerated per pool. The 236 bytes buy a publicly checkable genesis and one template. They are paid three times per round under section 2's rule, about 700 bytes against a 1.5 MB verifier.

What the field does not buy is honesty: a coordinator still picks their own genesis. It fixes it at issuance and publishes it, which is what lets anyone else check it.

`verifierBodyHash` is SHA-256 of the verifier script body, without its header push. It is a header field for the second of the two reasons above: baked into the body it would give every circuit configuration its own template. It says which verifier this pool's rounds must be checked by, which is the other thing a depositor wants to be able to read.

Immutable: `tokenId`, carried in PP1 as in every TSL1 token, plus `verifierBodyHash` and `genesisHeader`.

`balance` is the value PP3 actually holds, not a bookkeeping figure, and PP1 checks the two are equal on every round. A pool therefore opens holding one satoshi, the dust PP3's output needs to exist, rather than zero: opening at zero would either make the invariant false from the start or leave an output nobody can spend.

**No Rabin key.** For a state machine token the Rabin attestation binds the token to a registered issuer identity. For a pool, who the coordinator is *is* `ownerPKH`, and what makes the chain unique is the funding outpoint that create anchors to (11.5). Attesting the coordinator's off-chain identity, if a deployment wants it, belongs in the metadata output rather than in the covenant. Dropping it removes four parameters and five phases from the create branch.

**Two branches, not seven.** `OP_0` create and `OP_1` round. The state machine's enroll, confirm, convert, settle and timeout are escrow lifecycle with no meaning for a pool, and burn is removed for the reason in 5.6; the dispatch fails on any other selector rather than falling through. `PP1SmScriptGen` is untouched, so the state machine archetype still has all of them.

**Measured.** Script 14,652 bytes since the per-transfer outHash loop (5.5), before it 10,310 bytes: 563 header, 9,747 body, with the verifier checks of 5.2 and the variable output tail of 5.7 included. Before the tail it was 3,319 bytes, so the shape check is two thirds of the program; that is what refusing an opaque length costs. The state machine it came from was 10,537 bytes, of which 10,376 was body.

Tests: `test/sp_token_test.dart`, 58 of them, covering the codec roundtrip including a balance past 32 bits, the byte offsets against the constants, an issuance that opens on a state other than genesis, a round whose witness claims a header the round did not build, a round witness signed by someone other than the owner, a selector that names no branch, and the output tail cases of 5.7.

### 5.2 PP1, pool variant

**BUILT 2026-09-21.** The round branch does the ordinary TSL1 inductive transfer, rebuilding round N+1 byte for byte from the witness's pushes and checking the result hashes to its own outpoint's txid, plus four pool checks. `_emitRebuildPP1Pool` is two fixed-window substitutions where the state machine's was four, because the header is one push.

**The idea the branch turns on.** PP1 is the locking script on round N+1's output 1. It does not execute when that round is mined; it executes later, when witness N+1 spends it. By then the round is confirmed and its withdrawal outputs are already spendable. PP1 can therefore never gate its own round's money, and that is why the round branch aims every check one round ahead.

That leaves two scripts, each holding exactly what the other lacks:

- **PP3_{N+1}** locks round N+1's output 3, the one holding the pool balance. It names the outpoint round N+2 must spend at input 2, and that demand is enforced when round N+2 is mined, before any of its money moves. What PP3 cannot do is look at the outpoint it named. It knows the address, not the tenant.
- **PP1_{N+1}** can look. It executes when witness N+1 spends round N+1's output 1, and it is handed Y_{N+1}'s parts, rebuilds that transaction and the script locking its output 0, and certifies that the slot holds this pool's verifier carrying header_{N+1}. What it cannot do is arrive in time for its own round.

Put together, PP3 supplies the timing and PP1 supplies the sight: round N+2 can only be mined beside a verifier that already knows the state it must check against.

The ordering is what makes the pairing safe. Round N+2 spends witness N+1's output 0, so witness N+1 is always confirmed first and the certificate is in place before the pin it describes is ever tested.

The checks, in the order the script does them:

1. **The round's ciphertext bundles hash to header_{N+1}.outHash.** The bundles are what lets a recipient find and open their note. They are pushed in the witness rather than written to an output because of where TSL1 pays for bytes (section 2): an output's bytes are paid three times, a witness's once, and no script needs to read inside them. Riding in a mined witness is what publishes them; this check is what binds them to the round.

2. **The slot PP3 will pin holds this pool's verifier, initialised with header_{N+1}**, as `PP1SpScriptGen.emitVerifySlotIsVerifier`. Rather than parse Y to find its output, which needs variable-length walking over inputs and outputs, it **rebuilds** Y from parts, the pattern used everywhere else in TSL1:

```
V = OP_PUSHDATA1 0xec ‖ header_{N+1} ‖ body
Y = version=1 ‖ 0x01 ‖ yInput ‖ 0x01 ‖ output(V, 1 sat) ‖ nLockTime=0
SHA256(body) == verifierBodyHash
SHA256d(Y)   == nextSlot[0:32]      and      nextSlot[32:36] == 0
```

Only `yInput` and `body` are free; the script emits every structural byte, reusing `PP1FtScriptGen.emitBuildOutput` for the value and varint. Requiring exactly one input and one output is what makes it sound: V is then necessarily output 0, so a forged Y cannot park the real verifier somewhere inert and put an `OP_TRUE` at output 0. The coordinator builds Y, so the shape costs nothing.

Checking the body alone would not be enough, and this is the check that earns the header's single-push layout. A slot can hold a genuine, correct, spendable copy of the pool's verifier that was simply initialised with some other round's header. Round N+2's proof would then be verified against publics that are not the state it follows. Rebuilding V from `header_{N+1}` and comparing the txid closes it, and costs one `OP_CAT` over a value the branch already has on the stack. There is a test for exactly that case: the right verifier, the wrong header.

The txid is what binds every part of the claim. Supplying the genuine body alongside a Y that does not contain it fails, because the rebuild then hashes to a different txid.

3. **PP3_{N+1} names that slot and holds header_{N+1}.balance.** Neither is a separate comparison. The rebuild produces PP3 from the pinned slot and the header's balance field, and the rebuilt output goes into the transaction the script hashes against its own outpoint's txid, so a round whose PP3 names a different slot or holds a different amount simply cannot be spent afterwards. `emitRebuildPP3WithNextSlot` does the substitution and `_emitBuildOutputWithRawValue` splices the balance in as raw LE64 rather than round-tripping it through `OP_BIN2NUM` and `OP_NUM2BIN`.

4. **Round N+1 spent, at input 2, the slot PP3_N pinned**, as `emitVerifySpentPinnedSlot`. PP3_N already enforces this at mining time by folding `nextSlot` into the `hashPrevouts` it demands, so this is deliberately redundant: a second, independent binding in a different script, so that the covenant on the money and the covenant on the token both have to agree the round brought the verifier it was told to. The outpoint is read out of the round's own left-hand side, which the inductive proof has already tied to the round's txid, so it is not the spender's word for what input 2 was.

**Outputs after the five.** The rebuild emits the round's withdrawals and deposit receipts as a shape-checked tail, so the output count is no longer the literal 5 every other archetype writes. See 5.7 for what replaces it and why a length would not have done.

**Authorisation** is the owner's signature, as in every other archetype's transfer branch. That says the coordinator wants this round; it is not what makes the round correct, and it is not what protects depositors. A coordinator who signs a round that the verifier would reject simply cannot produce the next one.

Measured: the four checks cost 291 script bytes, 2,465 to 2,756 of body.

Tests in `test/sp_token_test.dart`: the whole lifecycle end to end, plus bundles that do not hash to `outHash`, a slot whose verifier was built for another header, a slot holding a decoy, the verifier falsely claimed for a decoy slot, a round whose PP3 names a slot other than the certified one, and `emitVerifySpentPinnedSlot` driven directly against a hand-built left-hand side.

### 5.3 PP2

Unchanged.

### 5.4 PP3, pool variant

**BUILT 2026-09-20; burn branch removed and forward covenant added 2026-09-21.** `WitnessCheckScriptGen.generate` takes exactly one of `ownerPKH` and a 36-byte `nextSlot`, and which one it gets decides the kind: an owner makes an ordinary token's PP3, with its burn path, and a slot makes a pool's, with no owner, no selector dispatch and no burn path. The builder has a separate `PartialWitnessLockBuilder.forPool(nextSlot)` so the two cannot be mixed, and the generator throws if given both. PP3 already pinned the spending transaction to exactly three inputs in order, by requiring

```
hashPrevouts == SHA256d(fundingOutpoint ‖ (witnessTxId, 0) ‖ myOutpoint)
```

where `myOutpoint` is PP3's own outpoint read from its preimage. The pool variant adds two terms and moves its own:

```
hashPrevouts == SHA256d(fundingOutpoint ‖ (witnessTxId, 0) ‖ nextSlot ‖ myOutpoint ‖ extraPrevouts)
```

`nextSlot` is embedded in the locking script, so input 2 is fixed at the time the round before it was built, and PP3 itself is input 3. `extraPrevouts` is supplied in the unlock and covers inputs 4 and up, the deposit covenants. Those stay opaque to PP3 on purpose: each covenant enforces itself through its own SIGHASH_SINGLE binding, V's balance equation accounts for them, and no input can create a token output. This is not the `extraPrevouts` weakness of the legacy PP1_SP, where extra inputs were invisible to a script that was supposed to be authorising them.

A pool PP3 is laid out

```
[0]      0x24
[1:37]   nextSlot
[37]     OP_TOALTSTACK
[38:]    the witness check
```

`nextSlot` is pushed once, at the front, and parked on the altstack for the body to use. That single-copy property is not cosmetic. PP1 rebuilds PP3 by fixed-window substitution, so a second copy buried in the body would be left stale by the rebuild, and the round after it would pin the wrong slot. A first attempt did emit it twice, once at the front for `parse` and once inline where it is used, and the rebuild silently produced a script whose first 58 bytes were right and whose body still named the old slot. There is a test asserting the byte pattern occurs exactly once.

**The rebuild.** `PP1SpScriptGen.emitRebuildPP3WithNextSlot` produces

```
rebuilt = parent[0:1] ‖ newSlot ‖ parent[37:]
```

One window. There used to be two, `parent[0:1] ‖ newPKH ‖ parent[21:22] ‖ newSlot ‖ parent[58:]`, because PP3 carried the owner's pubkey hash; the only thing that ever read it was the burn path. With that gone, PP3's code is byte-identical across a coordinator key rotation, and the owner lives only in PP1 and PP2. The rebuild is tested against the builder's own output: the in-script result must equal `PartialWitnessLockBuilder.forPool(newSlot)` byte for byte.

**The rebuild is not enough on its own.** It copies the parent's program, but PP1 checks that in the witness, after the round is mined, and create never looks at PP3 at all. So removing burn from the generator made the canonical program safe without making it mandatory: a coordinator could swap a burnable PP3 into any round and be refused only by a witness that no longer mattered.

**The forward covenant, BUILT 2026-09-21.** So PP3 enforces its own successor at mining time. When round N+1 spends PP3_N, PP3_N requires

```
SHA256d(nextValue ‖ varint ‖ 0x24 ‖ nextSlotOut ‖ myCode[37:]) == hashOutputs
```

where `myCode` is its own script, read from the preimage's scriptCode, and `hashOutputs`, under SIGHASH_SINGLE, is SHA256d of output 3 alone. A round whose output 3 runs any other program, or holds PP3 anywhere but output 3, cannot be mined. It is `WitnessCheckScriptGen._emitPoolForwardCovenant`, appended to the witness check rather than replacing it: PP3 still proves witness N exists and spent round N's PP2, and still pins the round's inputs.

Three things had to change to make it possible, and each is the price of one property:

- **No OP_CODESEPARATOR** before PP3's checksig, so that scriptCode is the whole script and PP3 can read its own program. The separator was an optimisation to keep TSL1 small, and it kept this unlock at 361 bytes; without it the preimage carries PP3's 49 KB.
- **SIGHASH_SINGLE instead of SIGHASH_ALL** (`CheckPreimageOCS` gained a sighash parameter, 0x43 here and 0x41 everywhere else). Under ALL, checking output 3 means pushing every other output of the round, about 12 KB plus the tail. Under SINGLE, hashOutputs is output 3 alone. PP3 reads only hashPrevouts [4:36] and its outpoint [68:104] from the preimage, both at fixed offsets and both still committed under SINGLE, so nothing PP3 already checked is lost.
- **PP3 moves to input 3**, swapping with the verifier slot, because SINGLE ties output index to input index. PP3's own index appears in exactly one place, the order of the hashPrevouts terms above; PP1 reads the parent link at `poolPP3Input` and the slot at `poolSlotInput`. The witness assertion does not depend on it at all: it pins input 1 to `(witnessTxId, 0)` and checks the witness's last input is `(myTxId, 2)`, using only the txid half of PP3's outpoint. Every non-pool archetype is untouched.

**Its security is two length checks.** The comparison is between byte strings, and an output's serialization fixes where its script starts only through the varint. If `nextValue` could be longer than 8 bytes, a spender could push `value8 ‖ theirVarint ‖ OP_1 OP_RETURN` as the value: the same bytes hash identically and parse as an output whose script begins with an anyone-can-spend prefix, the real program never executing. So `nextValue` must be exactly 8 bytes and `nextSlotOut` exactly 36, and the script requires its own scriptCode's varint to be three bytes, which fails closed if PP3 ever outgrows 65,535 bytes and the fixed split points would move. There is a test that builds the smuggling round and checks, in Dart, that its bytes really do hash to hashOutputs; with the 8-byte check removed from the generator, the interpreter accepts it.

**What it does not do.** It does not check the value; the new balance is the proof's to say, and V checks it (PP1 checks it again in the witness). A test pins that down so nobody mistakes the covenant for the money gate. And the induction needs a base case: the covenant guarantees every PP3 after a canonical one is canonical, but nothing on chain makes the genesis PP3 canonical, since PP1's create check runs in witness 0, which a non-canonical PP3_0 need not require. A depositor closes that by checking the PP3 their covenant names, `(round N, 3)`, against the canonical program, one hash with the slot window masked; the covenant then guarantees the PP3 their deposit lands in. Wallets have to vet the verifier body hash and the PP1 template already, so this is one more comparison, not a new kind of step.

**Measured**, from `tool/scratch/two_round_probe.dart`. The PP3 unlock went from 361 to 49,591 bytes. A round went from about 61.7 KB to 110.9 KB, and a steady-state witness from 75.4 KB to 173.9 KB, since it carries both its own round's lhs and its parent: about 148 KB a round in all, because a round's bytes are paid three times. Against the ~5.2 MB round of section 10 that is 2.8%, and section 10 had already budgeted about 40 KB for this unlock, so against the plan it is closer to half a percent. Staying at input 2 under SIGHASH_ALL would have cost about 4%.

With an owner and no slot the script is byte-identical to before, so every other archetype is untouched: `test/template_sync_test.dart` checks the NFT and FT templates against generator output and passes. PP3's hashed-tail geometry is unchanged (11.3): `getInOutSize` 111, hashed tail 115 of 119, 4 bytes of headroom.

Tests in `test/sp_token_test.dart`, group "SP PP3 pins the verifier slot": a round spending the named slot at input 2 is accepted; the same round without it is rejected; a partial hash that does not lead to the witness is rejected; output 3 as a burnable PP3, as a P2PKH paying the balance out, or with the real PP3 parked at output 4, each makes the round unmineable; an unlock that misstates the slot is rejected; a truthful dust value is accepted and a misstated one rejected; the smuggled anyone-can-spend prefix is rejected; `nextSlot` occurs exactly once; the in-script rebuild matches the builder byte for byte; the coordinator's burn spend is rejected while the identical spend of an ordinary token's PP3 is accepted; the script carries no owner; and an owner and a slot cannot be combined.

### 5.5 V, the verifier slot script

One header push, then the existing verifier program, then a tail that:

1. Checks hashPrevouts contains (round N, 3) at input 3, so V_N can only be spent beside PP3_N.
2. Rebuilds round N+1's outputs from pushed bytes and checks hashOutputs. From them it reads header_{N+1}, PP3_{N+1}'s value, the withdrawal outputs and the deposit receipts.
3. Verifies the proof against publics: header_N (embedded), header_{N+1}, the receipt list, the withdrawal list.
4. Checks PP3_{N+1}.value = header_N.balance + sum(receipt values) − sum(withdrawal values).
5. Ends with OP_CODESEPARATOR before its checksig so the preimage's scriptCode is the tail, not the 1.5 MB program. `CheckPreimageOCS` already supports this (`useCodeSeparator`, default true).
6. **Does not need to pin PP3_{N+1}'s program; PP3 does.** DECIDED 2026-09-21. The program of the output holding the pool balance must be fixed at mining time, and there were two candidates: V, through the output rebuild of step 2 at the cost of one hash comparison, or PP3_N itself as a forward covenant at about 148 KB a round. PP3 was chosen, because it does not depend on V: the property holds now, before V exists, and it keeps holding if V's own checks are ever wrong. The cost is 2.8% of a round; see 5.4. V still gates the value (step 4), which PP3 cannot know. Whether V should also pin PP1's and PP2's programs is open. Substituting either looks, on reading the scripts, like it ends in the pool dying at the next witness rather than funds moving, but that is the kind of argument that breaks quietly, and in V it costs a hash each.

**What the proof states, and what V still has to derive.** Mapped 2026-09-21 against the root's wide statement (`AggregationTree.widePublics`):

| Header field | Root proof | V's check |
|---|---|---|
| cmRoot | rootAfter | equal; and rootBefore equal to header_N's |
| ring | the ring lanes | equal to header_N's ring, then the rotation `[cmRoot_{N+1}, ring_N[0..2]]` in script |
| size | index | `index = size_N / 32`, `size_{N+1} = size_N + leavesAppended` |
| nfRoot | nfBefore, nfAfter | equal to header_N's and header_{N+1}'s (10.1) |
| balance | each transfer's signed amount | summed in script, BSV only, then step 4 |
| outHash | each transfer's outHash lanes | V takes the 32-byte bundle hash of every transfer, checks their hash is the header's and that each transfer's lanes are `SHA256(W_t ‖ c_t)` (below) |
| (receipts) | receipt slots | per used slot, the receipt output's cm equals the slot's and its value equals minus the slot's amount; unused slots zero (7.1) |

**outHash, redefined 2026-09-21.** In the legacy pool a transfer's outHash was SHA-256 of its extra outputs, payees and ciphertext output together, and the spend proof binds it by absorbing it. This design moved the ciphertexts into the witness, so the two halves are hashed apart (`PoolOutHash` in `lib/src/shielded_pool/pool_out_hash.dart`):

```
c_t            = SHA256(bundle_t)             transfer t's note bundles
outHash_t      = SHA256(W_t ‖ c_t)             W_t its 28-byte withdrawal record, or nothing
header.outHash = SHA256(c_0 ‖ … ‖ c_{n-1})
```

PP1 in witness N+1 computes header.outHash from the published bundles, pushed as 2-byte-length-prefixed segments, one unrolled step per transfer up to 256 (`emitRoundOutHash`, 4,359 bytes, PP1 now 14,652 bytes; about 13 KB a round once paid three times). V needs 32 bytes per transfer, not the bundles: it checks the c_t list against header_{N+1}.outHash and each transfer's lanes against its withdrawal output and c_t. So neither a withdrawal's payee nor a recipient's ciphertext can be changed after the spender proved. Every BSV transfer taking money out has exactly one withdrawal, the next in tail order, for exactly its amount; no other transfer has one. Assets other than BSV moving in or out are refused until V carries them. `PoolOutHash.check` is that rule in Dart, tested in `test/pool_out_hash_test.dart`, and is what V's script will implement.

With that, every field of the header and every output of the round has a source in the proof's statement, and V can be written.

V does not push round N. It knows header_N because it embeds it, and it knows header_N is real because PP1_N checked the embedding in witness N, and PP3_N being spendable proves witness N exists.

The shape is now fixed by 5.2, which rebuilds V as `OP_PUSHDATA1 0xec ‖ header ‖ body` and requires `SHA256(body) == verifierBodyHash`. So the header is exactly one push at the front, and everything after it is the same bytes in every round of a pool. The verifier reads its own header by splitting that push at the offsets in 5.1.

### 5.6 Burn

TSL1's burn spends PP1, PP2 and PP3 with the owner's signature. For the pool the owner is the coordinator and PP3 holds everyone's money. The burn branch is removed from all three pool variants. If a shutdown path is wanted it must be a proved transition to an empty pool, not a signature.

**DONE for PP1 2026-09-20**, along with the state machine's enroll, confirm, convert, settle and timeout, which are escrow lifecycle with no pool meaning. The dispatch now recognises only `OP_0` create and `OP_1` round and fails on anything else, rather than falling through to a branch the spender did not name; there is a test for that.

**DONE for PP3 2026-09-21.** Measured first, because the gap was worse than this section read: `WitnessCheckScriptGen._emitBurnPath` verified `hash160(pubkey) == ownerPKH` and a signature, nothing else, and `tool/scratch/pp3_freeze_probe.dart` spent a round's PP3 holding 500,000 satoshis of pool balance through it with the coordinator's key alone. The pool variant now has no burn path, no owner and no selector (5.4), and the same probe's spend is rejected. There is a test making the identical spend against an ordinary token's PP3, which succeeds, so the rejection is known to be about the branch and not about the transaction.

That closed the branch in the canonical program but did not make the program mandatory, because nothing pinned PP3's program when a round was mined. PP3's forward covenant (5.4, same day) does: a round whose PP3 is anything else cannot be mined.

**Not done for PP2, deliberately; this departs from the sentence above that says all three.** PP2 holds one satoshi. Its burn path lets the coordinator spend PP2 before the witness can, which makes the witness impossible, which freezes PP3. That is the pool dying, and the coordinator already holds that power without it: the round branch needs the owner's signature, so a coordinator who stops building witnesses kills the pool just as surely. So the branch adds no capability. Removing it would also not be enforceable. PP1 checks four push-length bytes of PP2 and then hashes the rest into a value it drops, which is TSL1-wide rather than a slip in the clone (the NFT generator does the same, with the comment "individual field checks provide sufficient validation"). PP2's program is therefore whatever the coordinator writes, and only V can pin it. Revisit if a recovery path is ever added for abandoned pools, because then a burn that forecloses recovery would be a new power.

### 5.7 Variable inputs and outputs inside PP1's rebuild

PP1 does not inspect the round from the outside. It rebuilds the round it lives in, byte for byte, from data pushed in the witness: the lhs (version and every input, each with its full unlocking script), the outputs it reconstructs, and nLockTime. It hashes that and requires equality with its own outpoint's txid. This is what lets it assert that the round spent the right ancestor: input 2's outpoint is read out of a byte string whose hash the chain has already fixed. Anything variable in the round therefore has to be handled inside this rebuild, and every byte of it is push data in the witness.

**Inputs.** The lhs is pushed as one blob and parsed in script by walking the input list: each input is a 36-byte outpoint, a varint script length, the script, and a 4-byte sequence. Outpoints come first in each input, so reading input k's outpoint means skipping k inputs, each by its varint. PP1 reads input 0 (issuance). The pool variant reads input 3 for the parent PP3, rather than TSL1's input 2, and input 2 for V_N; see 5.4 for why they swapped. Deposit covenants sit at inputs 4 and up, after everything PP1 needs, so PP1 never walks them; their contents are hashed as part of the blob and asserted about by nothing in PP1. That is correct: deposits are checked in the round by V and by the covenants themselves, and no input can create a token output. The cost is that input 2's unlocking script, the 230 KB proof, and input 3's, PP3's 49 KB unlock, are inside the lhs and are pushed in this witness and again in the next as part of the parent. Section 10 counts them.

**Outputs. BUILT 2026-09-21**, in `PP1SpScriptGen.emitBuildOutputTail`, with tests in the `SP the variable output tail` group.

Every other TSL1 archetype writes a literal output count of 5. That literal is a security property, not a convenience: it is what makes it impossible for a round to carry a second PP1 with the same tokenId, which would fork the chain through the sanctioned path. A pool has to pay withdrawals and acknowledge deposits, so the count has to move, and taking the tail as an opaque blob would hand back exactly what the literal was defending. So the count moved and the shape did not:

1. The counts are **not pushed**. The witness pushes two flat blobs, withdrawals as 28-byte records and receipts as 40-byte records, and PP1 divides the blob sizes to get w and r. There is no second number a spender could make disagree with what is actually emitted: the count in the varint and the outputs in the tail come from the same bytes. The varint is written with `emitWriteVarint` rather than a single byte, because 5 + 256 does not fit in one.
2. Each extra output is rebuilt from a template with only its variable bytes free. A withdrawal is `value8 ‖ 0x19 ‖ OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`, 34 bytes, of which the 20-byte hash and the value come from the record. A receipt is eight zero bytes of value, then `OP_FALSE OP_RETURN <cm> <value>`, 53 bytes, of which the 32-byte commitment and the 8-byte amount come from the record. The receipt's amount is pushed as eight raw bytes rather than as a minimally encoded script number, so the script is 44 bytes whatever the amount is and the shape check does not have to know about encoding length.
3. The maxima, 256 withdrawals and 8 receipts, are enforced by running out of unrolled steps: both blobs must be empty when the loops finish, and leftover bytes are the same thing as a count nobody checked. A blob that is not a whole number of records dies on the same check.

**Receipts are written before withdrawals.** A deposit covenant proves its receipt with SIGHASH_SINGLE, which ties output index to input index, and a depositor building that covenant cannot know how many withdrawals the round will end up carrying. How many deposits the round takes is something they can be told in advance. Withdrawals have no index constraint at all, so they go last. See the open point in 11.12 about what this costs on the input side.

**Measured.** `emitBuildOutputTail` is 6,981 bytes, which takes the PP1_SP lock from 3,329 to 10,310 bytes. A round witness is 74,675 bytes with an empty tail and 81,843 bytes at 256 withdrawals, against the stub verifier. The tail does not touch PP3's hashed geometry: `getInOutSize` is still 111 and the hashed tail still 115 of 119, with 4 bytes of headroom, at every tail size (11.3).

With that, the only outputs a round can carry are the five TSL1 outputs, P2PKH payouts and data receipts. Nothing in the tail can be spent as a token, so the induction is exactly as strong as it was with five outputs. `tool/scratch/output_tail_probe.dart` builds the round the whole exercise is about, one carrying a second copy of its own PP1_SP output, and the witness refuses it whether it calls the extra output a payout or does not mention it at all.

**A pinned slot cannot be taken back.** PP1 certifies the next round's slot in this round's witness, which is built after this round is mined. A round that pins a slot PP1 will refuse therefore mines fine and then cannot produce a witness, and PP3's unlock path needs that witness, so the pool balance is frozen. Permanently: PP1 rebuilds Y from its parts and compares HASH256 against the pin, so a passing preimage means breaking SHA-256. There is a second way in with the same ending, worth naming because it needs a different guard: PP1 never checks that Y is on chain, only that it hashes right, so a slot whose content is correct but whose funding outpoint was spent elsewhere lets the witness be built and leaves round N+2 with nothing to spend at input 2. Broadcast Y before the round.

Because none of that is recoverable on chain, the checks run in Dart first. `ShieldedPoolTool.checkSlotIsCertifiable` runs PP1's four checks, in PP1's order, and `createRoundTxn` refuses to build a round without them unless the caller passes `uncheckedNextSlot`, which is how the negative tests build a round that kills its own witness. It cannot check that Y will be mined; nothing offline can.

**What this rules out.** Outputs of arbitrary script in a round, including a second vault, a covenant, or any future output type, unless PP1 is regenerated to know its shape. The design accepts this. A round is a token transfer; anything else belongs in another transaction.

## 6. Round lifecycle

1. Coordinator aggregates round N+1's transfers, obtaining the proof and header_{N+1}.
2. Coordinator (or anyone) publishes Y_{N+1} with V_{N+1} = header_{N+1} ‖ body. This must exist before round N+1 because PP3_{N+1} embeds its txid.
3. Coordinator publishes round N+1: spends witness_N out0, PP3_N, Y_N out0 and the deposit covenants that named (round N, 3). V_N verifies the proof and the value equation. PP3_N verifies witness N and that Y_N out0 is spent.
4. Coordinator publishes witness N+1: PP1_{N+1} verifies round N+1's structure, the parent link, Y_{N+1}, the balance, and publishes the ciphertext bundles.
5. Depositors for round N+2 create covenants naming (round N+1, 3).

Rounds chain at zero confirmations as TSL1 transfers do. Y transactions are content-fixed given a header and can be prepared the moment a proof finishes.

## 7. Deposits, withdrawals, and what a wallet needs

### 7.1 Mechanism

**Withdrawals** are P2PKH outputs of the round. The proof's publics carry the (pkh, amount) list; V rebuilds the outputs and checks the list is present exactly. A coordinator fee can be a withdrawal to the coordinator, proved like any other.

**Deposits** are covenant outputs made by the depositor. The covenant, spent at input i of a round, requires with SIGHASH_SINGLE that output i be the receipt `OP_FALSE OP_RETURN cm_d value_d` for its own commitment and value, and requires hashPrevouts to contain (round N, 3) for the round it targets. An OR branch refunds the depositor after a timelock. Unlocking data is a preimage only.

**The receipt is proved against its note, BUILT 2026-09-21.** The root pins up to eight receipt slots after the nullifier roots, each `[cm]` and `[lo, hi, used]`, and proves every used slot is exactly one transfer's: its first output commitment, its signed amount, the BSV asset, and two dummy inputs, with no transfer behind two slots (`AggregationTree.receiptSlots`, `_receipts` in `verifier_program.dart`). A selector bit per slot and transfer picks it, the technique the anchor ring check uses. So a coordinator cannot take a deposit and mint its note to someone else: the depositor's covenant forces a receipt naming their commitment, and the proof forces that commitment into the tree.

**Deposits spend no real note.** A deposit is public: the depositor's input, the amount and the commitment are all on chain. Real inputs in the same transfer would put the depositor's name on those notes too, and on the earlier history their nullifiers close. The circuit refuses a receipt whose transfer has any real input. Wallets therefore deposit with two dummy inputs and put the new note in the first output. The rule binds exactly the transfers that back receipts, which every user deposit does through its covenant; a coordinator paying in without a receipt is donating, and only exposes itself.

**Why slots and not a public commitment per transfer.** Publishing the commitments costs no privacy, since every commitment is already in plaintext in the note bundles for wallets to build paths from. It costs script: pinning cmOut1 for all 256 transfers measured +203 KB of root verifier, paid twice a round. Eight slots measured +12.7 KB (1,595,294 to 1,607,962 B) and 16 root periods.

V requires the balance to move by exactly the receipt total. If the coordinator omits a deposit from the receipt list, that covenant's SIGHASH_SINGLE check fails and the round is invalid. If the coordinator adds a receipt with no matching deposit input, the balance must still rise by that amount and consensus requires the coordinator's funding input to cover it. The coordinator can donate but not take.

A deposit proof mints no nullifier. As recorded in the design notes, a replayed deposit proof costs the replayer and produces a duplicate commitment sharing a nullifier. That is unchanged here.

### 7.2 Where the gate on a payout actually is

It is easy to read 5.2 and conclude that withdrawals are gated by PP3's forward-looking pin. They are not, and the difference decides what a recipient has to be sent.

A withdrawal is an unconditional P2PKH output of round N+1. Once that round is accepted the money is spendable by its recipient and nothing later can claw it back. So the gate cannot be anywhere downstream, and it is not: it is **V, in the same transaction as the payout**.

| Script | Locks | Executes when | Does what |
|---|---|---|---|
| **V_N** | Y_N out0 | round N+1 spends it at input 2 | verifies the proof, rebuilds round N+1's outputs against `hashOutputs`, checks the withdrawal list against the proof's publics and the balance equation in 5.5 |
| **PP3_N** | round N out3 | round N+1 spends it at input 3 | requires round N+1's input 2 to be the outpoint it named, so V cannot simply be left out, and round N+1's output 3 to run PP3's own program, so the balance cannot be moved into a weaker one |
| **PP1_N** | round N out1 | witness N spends it at input 1 | certified, one round earlier, that the outpoint PP3_N names holds this pool's verifier carrying header_N |

V checks, PP3 makes V unskippable, PP1 makes V trustworthy. Remove any one and the other two are worthless. Only PP1's certificate looks forward; the gate on money is contemporaneous with the money, which is the property that makes the wallet story below as short as it is.

### 7.3 What each kind of recipient has to fetch

Wallets on BSV do not scan the chain, so the coordinator has to deliver the evidence. What it has to deliver differs by what the participant received, because of where 2's rule put each piece.

**A withdrawal recipient needs one transaction.** Round N+1 and a merkle proof to a block header. That is sufficient because every input script of a mined transaction ran, V among them, so acceptance of the round *is* the statement that the proof verified and this payout was in its publics. The recipient does not need the witness, the earlier rounds, the proof itself, or any trust in the coordinator. They are receiving satoshis in a P2PKH output, and its provenance does not change what it is worth.

**A shielded-note recipient needs two.** The ciphertext bundle that lets them find and open their note is in **witness N+1**, not in the round, because a witness's bytes are paid once and an output's three times (section 2). The `outHash` that binds the bundles to the round is in **round N+1's PP1 output**. So the coordinator must send both transactions and both merkle proofs, and the wallet checks `SHA256(bundles) == header_{N+1}.outHash` before trusting what it decrypts.

| Participant | Needs | Why |
|---|---|---|
| Withdrawal recipient | round N+1, one merkle proof | the payout is an output of that round and V ran inside it |
| Note recipient | witness N+1 and round N+1, two merkle proofs | the bundle rides in the witness, `outHash` binds it from the round |
| Depositor | round N+1, one merkle proof | their receipt is `OP_FALSE OP_RETURN cm value` in the round |

**Timing.** The chain alternates round, witness, round, ordered by dependency and not by confirmation depth. There is no maturity rule and no waiting: all three can sit in one block. So the coordinator can send a withdrawal notice the moment the round is broadcast, with finality arriving on confirmation like any other payment. A note recipient's evidence is only complete once the witness exists, which is one transaction later but not one round later.

**Withdrawals survive the pool dying.** If witness N+1 is never built, PP3_{N+1} can never be spent and the pool is bricked with its balance locked, but withdrawals round N+1 already paid stay paid. A recipient's claim does not depend on the pool continuing.

**Build state.** Half of this is exercisable. A round can now carry withdrawals and deposit receipts and produce a valid witness, because PP1 has the variable shape-checked tail of 5.7 as of 2026-09-21. What is still missing is the gate: V is the stub described in 5.2, so the `hashOutputs` and balance checks are designed and not built. Withdrawals are therefore ungated rather than impossible, which is the weaker of the two states but the one that can be tested. 5.5 gives V its checks and is next.

## 8. Security argument

### 8.1 One chain per tokenId

This is TSL1's argument, unchanged, restated with the pool's names.

Round N+1 spends PP3_N at input 3 (TSL1's input 2; the pool swapped it with the verifier slot, see 5.4), and PP1_{N+1} (in witness N+1) checks that input 3's txid is the hash of the pushed parent and that the parent's out3 is a PP3. PP3_N running proves witness N exists and that its last input was PP2_N. PP2_N running proved all of witness N's inputs came from round N, including PP1_N. PP1_N running proved round N was well formed with tokenId T, and that round N's input 3 was PP3_{N-1}. The same argument repeats until PP1_0, whose issuance branch requires input 0 to be the funding outpoint whose txid is T. That outpoint was spent once.

A forger who writes header bytes into an output has produced a transaction with a PP3 that no witness can ever satisfy, because the witness's PP1 demands a parent chain, and every candidate parent needs one too, down to an outpoint already spent. The forged round can be mined. It cannot be advanced.

### 8.2 Every mined round was verified before it was mined

V_N is an input of round N+1. PP3_N refuses to be spent without it. PP1_N established in witness N that the outpoint PP3_N names carries V with header_N, and witness N must exist for PP3_N to be spendable. So when round N+1 is validated, the interpreter runs a real verifier against the real previous header and the real new outputs. Withdrawals cannot be paid on a claim that was never checked.

This is why V cannot run in the witness. If it did, a round could pay out and then simply never be witnessed. Verification must gate the transaction that moves money.

### 8.3 The failure mode of a dishonest coordinator is death, not theft

**Holds once V is built, and not before.** Three things had to be true. The canonical PP3 had to carry no burn branch; until 2026-09-21 it did, and the coordinator could spend the pool balance on a signature. Fixed (5.6). The canonical program had to be the only one a round can carry; PP3's forward covenant enforces that at mining time, from any canonical PP3 onward (5.4). And the value in it has to be the one the proof says, which is V's (5.5, steps 2 and 4). V is still the `OP_DROP OP_1` stub, so today a coordinator can still pay the balance out through a round's other outputs. The argument below is the design's.

Every check PP1 performs in the witness is on a round already mined. A round that fails any of them (wrong Y content, balance not matching the header, bundles not matching outHash, malformed outputs) can never be witnessed, so the pool cannot advance and every note in it is frozen. That is the same failure mode as any TSL1 owner who builds a bad transfer. It is a griefing vector against the pool's users, and it exists today in the PP1_SP design too, where only the coordinator can advance a round. It does not move money, because money only moves in a round, and every round is gated by V and by the deposit covenants.

## 9. Attack pass

| Attack | What stops it | Outcome |
|---|---|---|
| Clone the state into a fresh output and advance it | PP1 in the clone's witness needs a parent chain to (T, 1) | clone is stuck at its first witness |
| Skip V and write any header | PP3_N requires (Y_N, 0) at input 2 | round invalid |
| Carry the balance forward in a PP3 with a way out | PP3_N's forward covenant requires output 3 to run its own program | round invalid |
| Smuggle an anyone-can-spend prefix through the covenant's value | the covenant requires the value to be exactly 8 bytes | round invalid |
| Point PP3_N at a Y_N whose out0 is P2PKH | PP1_N checked Y_N's bytes in witness N | witness N impossible, pool dies at round N |
| Embed a wrong header_N in V_N (e.g. higher balance) | same check | same |
| Set PP3_{N+1}'s value below the header's balance and take the difference as change | V reads the real value from the rebuilt outputs | round invalid |
| Omit a deposit from the receipts | that covenant's SIGHASH_SINGLE check | round invalid |
| Add a receipt with no deposit | balance equation plus consensus | coordinator pays |
| Spend V_N somewhere other than round N+1 | V checks hashPrevouts for (round N, 3) | invalid |
| Two competing rounds N+1 | PP3_N and V_N are each spendable once | one wins |
| Publish bundles that do not decrypt | nothing; outHash binds bytes, not meaning | griefing, unchanged from today |
| Withhold witness N+1 | nothing | pool frozen, no theft |

## 10. Cost estimate

For 256 aggregated transfers. Measured numbers are from `tool/scratch/agg_round_breakdown.dart` and the branch's recorded runs. Estimated numbers are marked.

| Item | Size | Basis |
|---|---|---|
| V body | 1.5 MB | measured 1.57 MB before lane reduction |
| Y_N | 1.5 MB | V plus one input |
| Round outputs | ~80 KB | PP1 ~25 KB (est., SM is 11 to 15 KB), PP2 a few KB, PP3 ~38 KB, withdrawals 34 B each |
| PP3_N unlock | 49.6 KB | measured 2026-09-21: the forward covenant needs PP3's whole script as scriptCode, so the separator is gone (5.4) |
| V_N unlock | ~310 KB | proof 230 KB measured, outputs rebuild ~80 KB, preimage small |
| Round total | ~0.43 MB | est. |
| Witness PP1 unlock | ~3.3 MB | lhs ~0.35 MB, parent 0.43 MB, rebuild 0.08 MB, Y 1.5 MB, bundles 0.92 MB measured, preimage ~25 KB |
| Witness total | ~3.3 MB | est. |
| **Per round** | **~5.2 MB** | Y + round + witness |
| Today | 8.24 MB | measured, one transaction, no witness, cloneable |

Per transfer: about 20 KB against 33 KB today. Largest single transaction: the witness at 3.3 MB against a 10 MB policy limit.

Where the saving comes from, in order: the nullifier tree leaving the state script (1.41 MB body, 1.41 MB preimage copy, 1.13 MB witnesses, all gone); the ciphertext bundles being paid once instead of once as output and twice as re-push; the state script being 25 KB rather than 1.41 MB. The verifier bytes cost the same as today, twice. The witness itself is the price of the guarantee: roughly the parent plus Y, about 2 MB per round.

The nullifier move is not optional. With the insertions left in script the SM output is 1.5 MB, the witness pushes it as the parent and again in the rebuild, and the round goes back over 3 MB with the witness near 7 MB.

### 10.1 Nullifier set: in-circuit Merkle or RSA accumulator

**BUILT 2026-09-21, and not as first assumed.** The set is a sparse Poseidon2 Merkle tree 62 levels deep, `NullifierTree` in `lib/src/crypto/nullifier_tree.dart`, and level 2 of the aggregation inserts into it.

**A keyed tree, not a sorted one.** A nullifier's slot is its first two lanes read as one 62-bit key. Absence is one path to an empty slot, and insertion is the same path to a filled one. The sorted tree assumed here before needs adjacency proofs, which means ordering comparisons of eight 31-bit lanes in circuit, range checks included. A keyed slot needs only the key's bits, and a Merkle walk already takes those. Two nullifiers sharing 62 bits would block the later spend. That takes around 2^31 nullifiers by chance, and nobody can aim a nullifier at another's slot, because it is a hash of a key only the spender holds. So the cost of dropping ordering is a DoS on a birthday bound, not a double spend.

**The key's bits must be canonical.** 31 bits can spell p = 2^31 - 1 as well as every lane value, and p is 0 again, so a lane of 0 has two decompositions. Left open, a nullifier ground to have a zero lane (about 2^31 work) would have two slots and could be spent twice. The circuit forbids the all-ones pattern per lane.

**Why level 2, measured.** Level 1 is full: 31,876 of 32,768 periods. Level 2 had 24,812 free periods in each of its four nodes, and 64 transfers need 128 walks of about 128 periods each. Its trace is 2^21 rows whatever it holds, so the walks cost almost no proving time and no extra node. The production plan compiled with them: level 2 goes from 40,724 to 57,046 of 65,536 periods and from 408K to 559K VM rows. So one walk costs about 128 periods and 1,180 VM rows. The earlier estimate of one more 2^20 node per round was pessimistic by that whole node.

**How it reaches the statement.** Each level-2 node absorbs into its public digest, after its inner digests, the set's root before and after its insertions and three statement chunks per transfer: nf1, nf2, and the chunk holding the real flags. The root pins those chunks for every transfer already, so it rebuilds each level-2 digest from its own copies. That is what makes the lanes a node inserts the lanes the spend proofs were verified against. The four nodes' roots chain from nfRoot_N to nfRoot_{N+1}, which are pinned after the ring. The root grows from 11,644 to 12,422 periods and the wide statement by 16 lanes. A dummy input walks its slot and writes the empty leaf back, so it changes nothing, but the slot must be empty.

**Tests.** `test/nullifier_tree_test.dart` covers the native tree. `test/nullifier_aggregation_test.dart` covers level 2 against a set that already holds spends: the honest round, a nullifier spent in an earlier round, the same nullifier twice in one round, a misstated root after, and a zero lane. It also covers the root end to end through a real proof and the generated script, including a transfer's nullifier lanes other than the ones level 2 inserted. `test/pool_aggregation_test.dart` covers `aggregate` with the set, including a replayed round.

The paragraphs below are the original comparison, kept because the accumulator route is still the alternative if the tree ever has to leave the circuit.

The design assumed nfRoot is a sorted-leaf Poseidon2 Merkle tree updated in the aggregation circuit: 512 insertions with non-membership by adjacency, roughly 33,000 permutations, in the region of one more 2^20 node per round on the measured prover. This uses only the AIR that exists.

[ACCUMULATORS_AND_SIGMA_PROTOCOLS.md](ACCUMULATORS_AND_SIGMA_PROTOCOLS.md) section 4.12 proposes an RSA accumulator instead and leaves open where the check would run. In this design it would run inside V: batched non-membership with a proof of exponentiation (Boneh, Bünz and Fisch, 2019) is a handful of 128-bit modexps, about 30 KB of script, and the state field is 256 bytes instead of 32. The costs are hash-to-prime for every nullifier, which has to be proved in the spend circuit and is estimated to multiply that circuit by four, and the strong RSA assumption over a modulus nobody has factored. Neither is needed for identity; TSL1 supplies that. The Merkle route is preferred until the accumulator's circuit cost is measured.

There is also a policy limit that bears directly on the accumulator route: `MaxScriptNumLengthPolicy` defaults to 10,000 bytes. Batched non-membership forms the product of the batch's primes in script, and 512 nullifiers at 256 bits each is a 16 KB number, over the limit. The batch would have to be split at about 312 nullifiers per product, or the product taken modulo the challenge prime incrementally, which changes the proof's shape. The Merkle route has no equivalent constraint.

## 11. Unknowns and unproven assumptions

Each item says what is assumed, what breaks if the assumption is wrong, and how to find out.

### 11.1 A single push of ~1.5 MB is accepted

**Assumed:** witness N's PP1 unlock can push Y_N raw as one element, and round N+1's V unlock can push a 230 KB proof and an 80 KB rebuild.
**If wrong:** the design is dead as written. The verifier's identity can only be established by hashing its bytes, and native SHA-256 needs them as a stack element.
**Find out:** Teranode policy on maximum script element size and maximum unlocking script size. The branch's existing 1.57 MB slot outputs were accepted as outputs; whether the same bytes are accepted as a single push in an input has not been tested. A regtest submission of a 2 MB push settles it.
**Checked 2026-09-20** against the Teranode policy settings reference (https://bsv-blockchain.github.io/teranode/references/settings/policy_settings/): no element-size setting is listed. The limits that would bind are `MaxScriptSizePolicy` at 100 MB and `MaxStackMemoryUsagePolicy` at 100 MB, both far above 1.5 MB. This is now unlikely to be a problem, but "not listed" is not "no limit", so the regtest submission stays on the list.

### 11.2 The witness can be 3.3 MB

**Assumed:** policy accepts a 3.3 MB witness transaction.
**If wrong:** the bundles (0.92 MB) can move back to round outputs at a cost of about 1.8 MB per round, and the design survives. If even that is over, Y can be split.
**Find out:** the 10 MB per-transaction figure recorded in the Teranode policy memory; confirm it applies to a transaction whose size is almost entirely one input's unlocking script.
**Checked 2026-09-20:** `MaxTxSizePolicy` defaults to 10,485,760 bytes and the reference draws no distinction by where the bytes sit. A 3.3 MB witness is a third of the limit.

### 11.3 PP3's partial hash is independent of the witness's size

**RESOLVED 2026-09-20, measured. Re-measured 2026-09-21** against a pool witness carrying the verifier checks of 5.2, whose PP1 unlock is five times larger. `tool/scratch/witness_tail_probe.dart`, listing each input by the output it spends:

```
ROUND WITNESS: 60723 B, 3 inputs, 1 outputs
  input 0  spends coordinator funding    serialized   147 B   unlock   106 B
  input 1  spends round N+1 out1 (PP1)   serialized 60456 B   unlock 60413 B
  input 2  spends round N+1 out2 (PP2)   serialized    75 B   unlock    34 B
  output 0 ModP2PKH to the owner         serialized    35 B
  getInOutSize (last input + count varint + outputs) = 111 B
  lastInputStart = 60608 ; % 64 = 0  ALIGNED
  hashed tail = 115 B + 9 B minimum SHA padding = 124 of 128   headroom 4 B
```

The hashed tail begins at the last input, so the unlock spending PP1 is excluded from it entirely and a 1.5 MB push there costs PP3 nothing. That is now demonstrated rather than assumed: the unlock grew from 11,004 to 60,413 bytes between the two measurements and `getInOutSize` did not move off 111. The assumption holds and the design's witness shape is sound.

**But the measurement exposes a hard constraint that was not in the design.** `TransactionUtils.computePartialHash` always takes the last 128 bytes, and `calculatePaddingBytes` aligns `lastInputStart` to a 64-byte boundary, so the remainder must cover exactly:

```
last input (36 + varint + unlock + 4) + output-count varint + ALL outputs + nLockTime + SHA padding = 128
```

SHA padding is at least 9 bytes (0x80 plus the 8-byte length), so everything before it has a ceiling of **119 bytes**. Today it is 115: PP2's input at 75, the count varint at 1, one 35-byte ModP2PKH output, and 4 bytes of nLockTime. **There are 4 bytes of headroom.**

Three consequences for the pool:

1. The witness carries exactly one output, 35 bytes, as section 4.3 already specifies. It cannot also carry a coordinator change output or an OP_RETURN. Fee change has to come from the funding input's own change, which means the funding input must be exact, or from a separate transaction.
2. The last input's unlock must stay at or under PP2's 34 bytes. Any pool-specific data added to PP2's unlock breaks the alignment.
3. `getInOutSize` hardcodes `inputs[2]` and `outputs[0]`. A pool witness with a different input count needs that generalised to "last input" and "all outputs", which is a small change but a required one.

None of this touches the round transaction. The 128-byte rule applies only to the witness being verified, so the round's variable tail of withdrawals and receipts (section 5.7) is unconstrained by PP3.

### 11.4 PP1_SM accepts a variable tail of outputs

**RESOLVED 2026-09-21, built and measured.** The rebuild takes a variable, shape-checked tail at the maxima the design asked for, and it is smaller than the estimate: 6,981 bytes unrolled rather than the order of 10 KB, taking the PP1_SP lock to 10,310 bytes. The counts turned out not to need pushing at all, which removed the one number a spender could have lied about; see 5.7. The lhs parser already reached input 3 from the slot work.

The one thing the build changed about the plan: the tail order. Receipts go first, not withdrawals, because a deposit covenant's SIGHASH_SINGLE check ties its receipt's output index to its own input index and a depositor cannot know the withdrawal count in advance. That leaves a real open point on the input side, 11.12.

### 11.5 PP1's issuance branch checks the funding vout

**RESOLVED 2026-09-20, measured. The answer is neither option, and it invalidates section 8.1's base case.**

The create branch (`_emitCreateFunnel`, and identically `_emitIssueToken` in the NFT generator) never looks at the token transaction's inputs. Its stack is `[preImage, fundingOutpoint, witnessPadding, rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey]`, with no lhs and no parent raw transaction, so it cannot rebuild the token transaction and does not try. What it checks is:

1. A Rabin signature over `SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId)` against the header's `rabinPubKeyHash`.
2. That the **witness's** `hashPrevouts` equals `SHA256d(fundingOutpoint ‖ (tokenTxId, 1) ‖ (tokenTxId, 2))`, which pins the witness's three inputs.

Nothing ties `tokenId` to an outpoint that was spent. `tokenId = tokenFundingTx.hash` is assigned off chain by the tool and then only ever carried forward. The Rabin signature is the sole gate, and it is replayable: its message contains no outpoint, no nonce and nothing else specific to one issuance, and it is published on chain in the first witness's unlocking script.

Measured with `tool/scratch/double_issue_probe.dart`:

```
A issuance ...  funded by opFunding:1
  A witness PP1 create: ACCEPTED
B issuance ...  funded by cpFunding:1, SAME tokenId, replayed Rabin sig
  B PP1 script identical to A: true
  B witness PP1 create: ACCEPTED
C issuance ...  SAME tokenId, attacker is owner+operator
  C PP1 script identical to A: false
  C witness PP1 create: ACCEPTED
```

B is a second token with the same tokenId funded by an unrelated UTXO. C goes further: the attacker writes their own PKH into `ownerPKH` and `operatorPKH`, keeps the victim's `tokenId`, replays the issuer's signature, and is accepted. The counterfeit carries the genuine issuer's identity attestation, because that is what the signature covers.

**What this does and does not mean.** It does not let anyone spend an existing token; C is a separate UTXO chain that shares a label, not coins. It does mean `tokenId` is not a unique identifier, so "same tokenId implies same token" is false, and any holder or indexer relying on it can be shown a counterfeit that verifies. Only the create witness was measured; whether chain C then advances through enroll and settle was not tested, though the transfer branches only check parent structure and tokenId continuity, so there is no obvious reason it would not.

**Consequence for this design.** Section 8.1 terminates the induction at "issuance requires input 0 to spend the funding outpoint whose txid is T, and that outpoint is spendable once". That sentence describes what [ARCHITECTURE.md](ARCHITECTURE.md) claims and not what the generator does. As implemented the induction has no anchor, so a forged pool root is creatable and the clone this whole design exists to prevent returns at the base case.

**FIXED in TSL1_SP 2026-09-20.** `_emitCreateFunnel` gained a Phase 0 that anchors the base case. It turned out not to need the output rebuild: pushing the token transaction's own raw bytes and checking `SHA256d(tokenRawTx) == preImage[68:100]` is enough, because that preimage field is the outpoint txid of the PP1 output this witness is spending, which is the token transaction itself. Phase 0 then walks `tokenRawTx` past nVersion and the input-count varint and requires input 0's 36-byte outpoint to equal `tokenId ‖ LE32(1)`.

`tokenRawTx` is pushed at the bottom of the create stack, so every index the later phases use is unchanged, and Phase 0 consumes it and restores the original 8-item layout. The input-count varint is required to be a single byte (fewer than 253 inputs) so the offset to input 0 is fixed; without that check an attacker could shift the parse with a 3-byte varint. The vout is pinned to 1, matching the protocol convention that issuance is funded from output 1, so `(tokenId, 1)` can be spent once. `ShieldedPoolTool.createTokenIssuanceTxn` now throws on any other `fundingVout` rather than building an issuance whose witness could never be created.

Re-running the probe against the fixed archetype:

```
A witness PP1 create: ACCEPTED
B witness PP1 create: rejected (SCRIPT_ERR_EQUALVERIFY)
C witness PP1 create: rejected (SCRIPT_ERR_EQUALVERIFY)
```

B is conclusive on its own: its PP1 script is byte-identical to A's and A passes, so the only difference is the funding outpoint. Both cases are now regression tests in `test/sp_token_test.dart` under "SP create anchors the base case", since the probe itself lives in git-excluded scratch.

**Section 8.1 now holds as written.** The induction terminates at a base case that requires input 0 to spend `(tokenId, 1)`, an outpoint spendable once.

**Still open in TSL1 proper.** PP1_SM, PP1_NFT, PP1_FT, PP1_RFT, PP1_RNFT and PP1_AT are unchanged and all carry the original unanchored create branch. Fixing them alters their script bytes, which changes every deployed token's locking script, so it is a protocol decision rather than a code change. Flagged in [ARCHITECTURE.md](ARCHITECTURE.md).

### 11.6 V's OP_CODESEPARATOR preimage is sound

**RESOLVED 2026-09-20. It already works, at this exact size, in tested code.**

`SlotScript` in `slot_script_common.dart` ends every slot with `<pubkey> OP_CODESEPARATOR OP_CHECKSIG`, and its own comment says "so its scriptCode in the preimage is that one CHECKSIG". The legacy verifier slot is 1.57 MB and the append slot 684 KB, both built that way, and both are exercised end to end by `verifier_slot_test`, `subtree_append_slot_test`, `pp1_sp_legacy_aggregated_test` and `pool_chain_reader_test`, which passes with real proofs. So a multi-megabyte script with a tail-only preimage is not a hypothesis, it is the shipped mechanism.

Soundness, stated properly: with the separator, the scriptCode no longer identifies which script is running, but the preimage's 36-byte `outpoint` field does. One input spends one outpoint, which carries exactly one locking script, and `OP_CHECKSIG` computes the real sighash independently, so a preimage from another input or another transaction cannot be substituted. Not committing to the script text is harmless because the outpoint commits to the UTXO.

By contrast every PP1 generator passes `useCodeSeparator: false` deliberately. PP1 reads its own script out of the preimage's scriptCode to rebuild output 1 without pushing its template separately. That is a saving, not an oversight, and the pool's PP1 must keep it. V has no equivalent need, because its identity comes from PP1's byte check of Y_N, so V takes the separator.

**Two corrections to section 5.5 that came out of this.**

1. **V must use SIGHASH_ALL (0x41), not the slots' SIGHASH_SINGLE (0x43).** The legacy slots use SINGLE because each binds only its own result output at a matching index. V has to read the state header, PP3's value, the withdrawals and the receipts, which means `hashOutputs` must cover all outputs. The legacy state script already uses `sighashAll = 0x41` for that reason. The OCS construction takes the sighash type as a parameter, so ALL and the separator compose without difficulty.
2. **V may contain exactly one `OP_CODESEPARATOR`, the one in its tail.** Consensus takes the scriptCode from the most recently *executed* separator, while dartsv's `createSighashPreImage` strips to the *first* one in the script. Those agree only when there is one. The verifier program generators emit none today, which was checked, but it is now a constraint on anything added to V.

### 11.7 The nullifier tree update fits the aggregation circuit at acceptable cost

**RESOLVED 2026-09-21, measured: no extra node.** The insertions fit inside level 2's existing 2^21 traces, see 10.1.

**Assumed:** about one extra 2^20-row node per round.
**If wrong:** the round interval grows; at the measured 12 s per L1 node this is minor, but the sorted-insertion AIR does not exist yet and its real row count is a guess.
**Find out:** build the AIR and measure, as was done for SHA-256.

### 11.8 The ciphertext bundles may lag the round

**Assumed:** recipients tolerate learning their notes when witness N+1 lands rather than when round N+1 lands. The two are seconds apart when the coordinator is honest.
**If wrong:** bundles return to round outputs, +1.8 MB per round.
**Find out:** a product decision, not a technical one.

### 11.9 Y_N's fixed header does not create a race

**Assumed:** header_{N+1} is known before Y_{N+1} is needed, because it is the output of round N+1's proof, and Y_{N+1} is needed only when round N+1 is built. No circularity.
**If wrong:** none identified.

### 11.10 Sizes in section 10 are assembled, not measured

Every line marked est. is arithmetic over parts. The PP1 pool variant has not been generated. The V tail has not been generated. The round and witness have not been built. Section 12 is the remedy.

### 11.11 Which slot mode

**DECIDED 2026-09-21: aggregated only.** Direct-slot mode is dropped from this design. Every deployment runs a coordinator with a prover, so the pool has one shape and Y_N has one output.

Direct-slot mode put K user spend proofs in K verifier outputs on Y_N, plus an append slot, and the coordinator proved nothing. Four things settled it:

1. **The one-output shape is load-bearing.** It is what forces V to be output 0 (4.1), and `emitVerifySlotIsVerifier` enforces it with a test behind it. Direct-slot's K+1 outputs cannot satisfy that check, so keeping both modes meant either weakening the property or maintaining a second PP1.
2. **Its justification expired.** Direct-slot existed for deployments whose coordinator had no prover. The recursive prover is built and measured: about 356 s for a 256-transfer round on one machine, later about 220 s.
3. **Cost.** Per-transfer cost was dominated by Y, 1.7 MB at K=2.
4. **It would have landed on the variable output tail.** PP1 reads the slot at input 3 (input 2 since PP3's forward covenant swapped the two later the same day; the argument is unchanged) and treats inputs 4 and up as opaque deposit covenants. K+1 slots would put deposits at input K+4, so PP1 would have to know K, inside the same lhs-walking code 5.7 is about to change.

**The choice is free from the wallet's side, which is why it could be made on covenant cost alone.** `nk = H(sk, tagNk)` and `nf = H(nk, rho)`, so only the holder of a spending key can produce a nullifier and the coordinator cannot build a spend proof on anyone's behalf in either mode. The proof is produced at the edge regardless; the mode only decides what the coordinator does with a proof it has been handed. A wallet therefore does one read and one submission with no handshake, in either mode. What buys that is the ring: a spend may anchor to any of the four recent `cmRoot`s the header carries, so a proof stays valid for roughly four rounds and never races a round close. That is an argument against ever shrinking the ring to save header bytes.

**What would bring it back.** A deployment whose coordinator genuinely cannot run a prover. It would return as a separate archetype with its own PP1, not as a mode of this one, so that it never constrains PP1_SP's covenant.

### 11.12 A deposit covenant's input index can match its receipt's output index

**Open, and created by 5.7.** A deposit covenant proves it was paid by requiring, with SIGHASH_SINGLE, that the output at its own input index be its receipt. Receipts start at output 5. But a round has four fixed inputs, funding, the previous witness, PP3 and the verifier slot, so the first free input index is 4, not 5. The indices are off by one and SIGHASH_SINGLE has no way to bridge it.

**Options, none chosen:** give the round a fifth fixed input, which is honest but wastes an outpoint every round; move the metadata output to the end of the tail, which aligns the two at the cost of breaking the TSL1 five-output convention the parent parser reads by position; or have the covenant prove its receipt some other way than SIGHASH_SINGLE, which means pushing the whole output list and paying for it.

**Find out:** this is the first thing the deposit work has to settle, before the covenant is written. Nothing in the output tail depends on the answer, because receipts being first is right under all three options.

### 11.13 The root's commitment-tree update did not bind its two walks

**FOUND AND FIXED 2026-09-21.** The root proves a subtree appended by two Merkle walks: one shows the slot empty under rootBefore, the other climbs from the new subtree to rootAfter. Both took their siblings as free witness and nothing tied the two sets together. So the second walk could climb over siblings of the coordinator's choosing and reach the root of any tree with the new subtree in place: one with earlier notes replaced by notes the coordinator could then spend and withdraw. `tool/scratch/cm_sibling_probe.dart` showed it with a real constraint check: one honest subtree already in the pool, the round's slot shown empty under the real root, then a climb over the siblings of a pool with one earlier note swapped, and the root's constraints accepted the forged rootAfter. It had been so since the aggregated root was built.

**The fix** needed no AIR change. The AIR can already pin a period's low input half to its row-0 operands and its high half to row 1's, so every chained walk period now publishes both. The sibling is the high half when the level's bit is 0 and the low half when it is 1. The program requires the two walks' siblings to agree at every level, and the second walk's bits to be the first's. That is `_walkPair` in `verifier_program.dart`, which the nullifier insertions of 10.1 use as well. It adds VM rows but no periods, and every production level still fits. `test/recursion_tree_test.dart` carries the forged case.

### 11.14 A one-lane wire read by a VM multiply on port A (closed)

**CLOSED 2026-09-21.** Three main constraints `ak1 · a[k] = 0` (k = 1..3) now pin the upper limbs of a K1 operand to zero at the row that reads it. Before them, a trace with a nonzero upper limb at such a row was accepted by the constraint check; `test/recursion_tree_test.dart` keeps that trace and now sees it refused by constraint 77 to 79. No program column changed, so no preprocessed root moved, and the native kernel and the script verifier take the constraints from the same source. Whether the gap was exploitable into a false inner proof was never tried: closing it was cheaper than finding out.

What follows is the original note. The bus binds a K1 wire consumed on port A only in limb 0 (`ak1 · a[0]`). The VM's `mul` reads all four limbs of A. So in a product with a K1 operand, three extension limbs of that operand are free to the prover, and the product can be shifted by any combination of i·B, u·B and iu·B. The query-point computation multiplies swap bits this way (`verifier_program.dart`, the `px`/`py` update in `_verifyInner`). Whether that can be turned into a false inner proof has not been tried. The new code of 10.1 and 11.13 avoids the pattern by lifting every bit through `limb(x, 0)` first.

**Find out:** build the forged witness, or close it without trying: three AIR constraints `ak1 · a[k] = 0` for k = 1..3 cost nothing measurable, and the verifier scripts regenerate from the AIR.

## 12. What would settle it

Two experiments, both cheap next to what has been built:

1. **Generate the pool PP1 and PP3 variants and a V tail, build one round and one witness in the interpreter, and re-run `clone_the_chain.dart` against them.** The clone must fail at the forged round's witness with PP1 rejecting the parent. This is the test that found the current flaw and it is the only evidence that counts.
2. **Size the witness.** Build witness N with a real Y_N push and real bundles and report its byte count and whether the interpreter and a regtest node accept it.

Until both are done this document is arithmetic.

## 13. Relation to existing code

Carries over unchanged: the spend circuit, key hierarchy, aggregation levels and prover pool, the verifier program and `ProgramScriptGen`, the append slot, `PoolChainReader`'s leaf placement, the hybrid KEM bundles.

Carries over with changes: `PartialWitnessLockBuilder` gains `nextSlot` and the input-3 check (DONE); the verifier slot generator gains the header embedding and the tail in 5.5; `ShieldedPoolTool` builds Y (`buildSlotTxn`, DONE) and the deposit covenant as well as the two transaction pairs.

The pool archetype is `PP1SpScriptGen`, cloned from `PP1SmScriptGen` and since diverged: its own header (5.1, DONE), two branches instead of seven (5.1 and 5.6, DONE), the anchored base case (11.5, DONE) and the verifier checks (5.2, DONE). What is left in PP1 is the variable output tail of 5.7. `PP1SmScriptGen` itself is untouched, so the state machine archetype keeps its full lifecycle.

Retired: the original pool scripts, now `PP1SpLegacyScriptGen` and `ShieldedPoolLegacyTool`, along with their in-script nullifier insertion and their `extraPrevouts` weakness. The Rabin create funnel is retired from the pool only; every other archetype keeps it.

Not started: the sorted-insertion nullifier AIR, the deposit covenant script, the variable output tail (5.7), and V itself, which is stubbed as a header push followed by `OP_DROP OP_1` so the covenant around it can be exercised.
