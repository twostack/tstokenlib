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

**Naming.** A script is named for the output it locks, and it executes only when a later transaction spends that output. Those are two different positions with two different indices, and this document keeps them apart. PP3_N is the script locking **round N's output 3**; it executes when **round N+1 spends it at input 2**. Writing "PP3_N (input 2)" would merge the two and state the wrong index as the script's identity.

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
| 2 | round N out3 (PP3_N) | preimage, midstate of witness_N, remainder blocks |
| 3 | Y_N out0 (V_N) | preimage (small, see 5.4), proof, round N+1's outputs for the hashOutputs rebuild |
| 4.. | deposit covenants | preimage only |

| Output | Script | Value |
|---|---|---|
| 0 | change P2PKH | remainder |
| 1 | PP1_SM pool variant, header_{N+1} | 1 sat |
| 2 | PP2, unchanged | 1 sat |
| 3 | PP3 with `nextSlot` = (Y_{N+1}, 0) | **the pool balance** |
| 4 | metadata, carried forward | 0 |
| 5.. | withdrawals, P2PKH | as proved |
| then | deposit receipts, `OP_FALSE OP_RETURN cm value` | 0 |

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
| nfRoot | 32 | 32 | sorted nullifier tree root after this round |
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

**Measured.** Script 3,319 bytes: 563 header, 2,756 body, with the verifier checks of 5.2 included. The state machine it came from was 10,537 bytes, of which 10,376 was body.

Tests: `test/sp_token_test.dart`, 45 of them, covering the codec roundtrip including a balance past 32 bits, the byte offsets against the constants, an issuance that opens on a state other than genesis, a round whose witness claims a header the round did not build, a round witness signed by someone other than the owner, and a selector that names no branch.

### 5.2 PP1, pool variant

**BUILT 2026-09-21.** The round branch does the ordinary TSL1 inductive transfer, rebuilding round N+1 byte for byte from the witness's pushes and checking the result hashes to its own outpoint's txid, plus four pool checks. `_emitRebuildPP1Pool` is two fixed-window substitutions where the state machine's was four, because the header is one push.

**The idea the branch turns on.** PP1 is the locking script on round N+1's output 1. It does not execute when that round is mined; it executes later, when witness N+1 spends it. By then the round is confirmed and its withdrawal outputs are already spendable. PP1 can therefore never gate its own round's money, and that is why the round branch aims every check one round ahead.

That leaves two scripts, each holding exactly what the other lacks:

- **PP3_{N+1}** locks round N+1's output 3, the one holding the pool balance. It names the outpoint round N+2 must spend at input 3, and that demand is enforced when round N+2 is mined, before any of its money moves. What PP3 cannot do is look at the outpoint it named. It knows the address, not the tenant.
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

4. **Round N+1 spent, at input 3, the slot PP3_N pinned**, as `emitVerifySpentPinnedSlot`. PP3_N already enforces this at mining time by folding `nextSlot` into the `hashPrevouts` it demands, so this is deliberately redundant: a second, independent binding in a different script, so that the covenant on the money and the covenant on the token both have to agree the round brought the verifier it was told to. The outpoint is read out of the round's own left-hand side, which the inductive proof has already tied to the round's txid, so it is not the spender's word for what input 3 was.

Still to add: deposit receipts and withdrawals as a variable tail of outputs, see 5.7 and 11.4.

**Authorisation** is the owner's signature, as in every other archetype's transfer branch. That says the coordinator wants this round; it is not what makes the round correct, and it is not what protects depositors. A coordinator who signs a round that the verifier would reject simply cannot produce the next one.

Measured: the four checks cost 291 script bytes, 2,465 to 2,756 of body.

Tests in `test/sp_token_test.dart`: the whole lifecycle end to end, plus bundles that do not hash to `outHash`, a slot whose verifier was built for another header, a slot holding a decoy, the verifier falsely claimed for a decoy slot, a round whose PP3 names a slot other than the certified one, and `emitVerifySpentPinnedSlot` driven directly against a hand-built left-hand side.

### 5.3 PP2

Unchanged.

### 5.4 PP3, pool variant

**BUILT 2026-09-20.** `WitnessCheckScriptGen.generate` takes an optional 36-byte `nextSlot`. PP3 already pinned the spending transaction to exactly three inputs in order, by requiring

```
hashPrevouts == SHA256d(fundingOutpoint ‖ (witnessTxId, 0) ‖ myOutpoint)
```

where `myOutpoint` is PP3's own outpoint read from its preimage. The pool variant appends two more terms:

```
hashPrevouts == SHA256d(fundingOutpoint ‖ (witnessTxId, 0) ‖ myOutpoint ‖ nextSlot ‖ extraPrevouts)
```

`nextSlot` is embedded in the locking script, so input 3 is fixed at the time the round before it was built. `extraPrevouts` is supplied in the unlock and covers inputs 4 and up, the deposit covenants. Those stay opaque to PP3 on purpose: each covenant enforces itself through its own SIGHASH_SINGLE binding, V's balance equation accounts for them, and no input can create a token output. This is not the `extraPrevouts` weakness of the legacy PP1_SP, where extra inputs were invisible to a script that was supposed to be authorising them.

`nextSlot` is pushed once, at the front, and parked on the altstack for the body to use. That single-copy property is not cosmetic. PP1 rebuilds PP3 by fixed-window substitution, so a second copy buried in the body would be left stale by the rebuild, and the round after it would pin the wrong slot. A first attempt did emit it twice, once at the front for `parse` and once inline where it is used, and the rebuild silently produced a script whose first 58 bytes were right and whose body still named the old slot. There is a test asserting the byte pattern occurs exactly once.

**The rebuild.** `PP1SpScriptGen.emitRebuildPP3WithNextSlot` produces

```
rebuilt = parent[0:1] ‖ newPKH ‖ parent[21:22] ‖ newSlot ‖ parent[58:]
```

which is the same shape of surgery `PP1FtScriptGen._emitRebuildPP3WithPP2Idx` already does for the split-transfer case, so the pattern is established. It is tested against the builder's own output: the in-script result must equal `PartialWitnessLockBuilder(newPKH, nextSlot: newSlot)` byte for byte.

Measured: PP3 grows from 49,110 to 49,156 bytes, 46 bytes. With `nextSlot` null the script is byte-identical to before, so every other archetype is untouched; the NFT, FT, RFT, RNFT, AT and SM suites pass unchanged.

Tests in `test/sp_token_test.dart`, group "SP PP3 pins the verifier slot": a round spending the named slot at input 3 is accepted, the same round with that input removed is rejected, the 46 bytes are asserted, `nextSlot` occurs exactly once, and the in-script rebuild matches the builder byte for byte.

The burn branch removal is still pending; see 5.6.

### 5.5 V, the verifier slot script

One header push, then the existing verifier program, then a tail that:

1. Checks hashPrevouts contains (round N, 3) at input 2, so V_N can only be spent beside PP3_N.
2. Rebuilds round N+1's outputs from pushed bytes and checks hashOutputs. From them it reads header_{N+1}, PP3_{N+1}'s value, the withdrawal outputs and the deposit receipts.
3. Verifies the proof against publics: header_N (embedded), header_{N+1}, the receipt list, the withdrawal list.
4. Checks PP3_{N+1}.value = header_N.balance + sum(receipt values) − sum(withdrawal values).
5. Ends with OP_CODESEPARATOR before its checksig so the preimage's scriptCode is the tail, not the 1.5 MB program. `CheckPreimageOCS` already supports this (`useCodeSeparator`, default true).

V does not push round N. It knows header_N because it embeds it, and it knows header_N is real because PP1_N checked the embedding in witness N, and PP3_N being spendable proves witness N exists.

The shape is now fixed by 5.2, which rebuilds V as `OP_PUSHDATA1 0xec ‖ header ‖ body` and requires `SHA256(body) == verifierBodyHash`. So the header is exactly one push at the front, and everything after it is the same bytes in every round of a pool. The verifier reads its own header by splitting that push at the offsets in 5.1.

### 5.6 Burn

TSL1's burn spends PP1, PP2 and PP3 with the owner's signature. For the pool the owner is the coordinator and PP3 holds everyone's money. The burn branch is removed from all three pool variants. If a shutdown path is wanted it must be a proved transition to an empty pool, not a signature.

**DONE for PP1 2026-09-20**, along with the state machine's enroll, confirm, convert, settle and timeout, which are escrow lifecycle with no pool meaning. The dispatch now recognises only `OP_0` create and `OP_1` round and fails on anything else, rather than falling through to a branch the spender did not name; there is a test for that. Removing burn from PP2 and PP3 is still open.

### 5.7 Variable inputs and outputs inside PP1's rebuild

PP1 does not inspect the round from the outside. It rebuilds the round it lives in, byte for byte, from data pushed in the witness: the lhs (version and every input, each with its full unlocking script), the outputs it reconstructs, and nLockTime. It hashes that and requires equality with its own outpoint's txid. This is what lets it assert that the round spent the right ancestor: input 2's outpoint is read out of a byte string whose hash the chain has already fixed. Anything variable in the round therefore has to be handled inside this rebuild, and every byte of it is push data in the witness.

**Inputs.** The lhs is pushed as one blob and parsed in script by walking the input list: each input is a 36-byte outpoint, a varint script length, the script, and a 4-byte sequence. Outpoints come first in each input, so reading input k's outpoint means skipping k inputs, each by its varint. Today PP1 reads input 0 (issuance) and input 2 (parent PP3). The pool variant also reads input 3 (V_N). Deposit covenants sit at inputs 4 and up, after everything PP1 needs, so PP1 never walks them; their contents are hashed as part of the blob and asserted about by nothing in PP1. That is correct: deposits are checked in the round by V and by the covenants themselves, and no input can create a token output. The cost is that input 3's unlocking script, the 230 KB proof, and input 2's, PP3's unlock, are inside the lhs and are pushed in this witness and again in the next as part of the parent. Section 10 counts them.

**Outputs.** Today PP1 rebuilds exactly five outputs from templates and header pushes, and the output-count varint is fixed at 5. That fixed count is a security property, not a convenience: it is what makes it impossible for a round to carry a second PP1 with the same tokenId, which would fork the chain through the sanctioned path. The pool variant needs outputs after the five, and it must not take them as an opaque blob for the same reason. The rebuild must:

1. Take a withdrawal count w and a receipt count r from the witness, with fixed maxima (256 and 8 are the numbers the aggregation is sized for), and emit the output-count varint as 5 + w + r.
2. Rebuild each withdrawal as an 8-byte value plus a 25-byte P2PKH script whose only free bytes are the 20-byte hash, and each receipt as a zero value plus `OP_FALSE OP_RETURN` with a 32-byte push and an 8-byte push. Each is an unrolled step of a few dozen script bytes; at the maxima the unrolled tail check is on the order of 10 KB.
3. Refuse any other script shape in the tail.

With that, the only outputs a round can carry are the five TSL1 outputs, P2PKH payouts and data receipts. Nothing in the tail can be spent as a token, so the induction is exactly as strong as with five outputs. PP1_SP's `roundOutputs(..., extras)` already rebuilds a variable extras region for the pool; the difference is that here it happens inside the SM generator's rebuild, and with a shape check rather than a length.

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

V requires the balance to move by exactly the receipt total. If the coordinator omits a deposit from the receipt list, that covenant's SIGHASH_SINGLE check fails and the round is invalid. If the coordinator adds a receipt with no matching deposit input, the balance must still rise by that amount and consensus requires the coordinator's funding input to cover it. The coordinator can donate but not take.

A deposit proof mints no nullifier. As recorded in the design notes, a replayed deposit proof costs the replayer and produces a duplicate commitment sharing a nullifier. That is unchanged here.

### 7.2 Where the gate on a payout actually is

It is easy to read 5.2 and conclude that withdrawals are gated by PP3's forward-looking pin. They are not, and the difference decides what a recipient has to be sent.

A withdrawal is an unconditional P2PKH output of round N+1. Once that round is accepted the money is spendable by its recipient and nothing later can claw it back. So the gate cannot be anywhere downstream, and it is not: it is **V, in the same transaction as the payout**.

| Script | Locks | Executes when | Does what |
|---|---|---|---|
| **V_N** | Y_N out0 | round N+1 spends it at input 3 | verifies the proof, rebuilds round N+1's outputs against `hashOutputs`, checks the withdrawal list against the proof's publics and the balance equation in 5.5 |
| **PP3_N** | round N out3 | round N+1 spends it at input 2 | requires round N+1's input 3 to be the outpoint it named, so V cannot simply be left out |
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

**Build state.** None of this is exercisable yet. V is still the stub described in 5.2, so the `hashOutputs` and balance checks are designed and not built, and PP1 still emits a fixed output count of 5, so a round carrying a withdrawal output cannot produce a valid witness at all. Withdrawals are not merely ungated today, they are impossible. 5.7 gives PP1 the variable tail and 5.5 gives V its checks, in that order.

## 8. Security argument

### 8.1 One chain per tokenId

This is TSL1's argument, unchanged, restated with the pool's names.

Round N+1 spends PP3_N at input 2, and PP1_{N+1} (in witness N+1) checks that input 2's txid is the hash of the pushed parent and that the parent's out3 is a PP3. PP3_N running proves witness N exists and that its last input was PP2_N. PP2_N running proved all of witness N's inputs came from round N, including PP1_N. PP1_N running proved round N was well formed with tokenId T, and that round N's input 2 was PP3_{N-1}. The same argument repeats until PP1_0, whose issuance branch requires input 0 to be the funding outpoint whose txid is T. That outpoint was spent once.

A forger who writes header bytes into an output has produced a transaction with a PP3 that no witness can ever satisfy, because the witness's PP1 demands a parent chain, and every candidate parent needs one too, down to an outpoint already spent. The forged round can be mined. It cannot be advanced.

### 8.2 Every mined round was verified before it was mined

V_N is an input of round N+1. PP3_N refuses to be spent without it. PP1_N established in witness N that the outpoint PP3_N names carries V with header_N, and witness N must exist for PP3_N to be spendable. So when round N+1 is validated, the interpreter runs a real verifier against the real previous header and the real new outputs. Withdrawals cannot be paid on a claim that was never checked.

This is why V cannot run in the witness. If it did, a round could pay out and then simply never be witnessed. Verification must gate the transaction that moves money.

### 8.3 The failure mode of a dishonest coordinator is death, not theft

Every check PP1 performs in the witness is on a round already mined. A round that fails any of them (wrong Y content, balance not matching the header, bundles not matching outHash, malformed outputs) can never be witnessed, so the pool cannot advance and every note in it is frozen. That is the same failure mode as any TSL1 owner who builds a bad transfer. It is a griefing vector against the pool's users, and it exists today in the PP1_SP design too, where only the coordinator can advance a round. It does not move money, because money only moves in a round, and every round is gated by V and by the deposit covenants.

## 9. Attack pass

| Attack | What stops it | Outcome |
|---|---|---|
| Clone the state into a fresh output and advance it | PP1 in the clone's witness needs a parent chain to (T, 1) | clone is stuck at its first witness |
| Skip V and write any header | PP3_N requires (Y_N, 0) at input 3 | round invalid |
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
| PP3_N unlock | ~40 KB | preimage carries PP3's script as scriptCode unless it also uses a separator |
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

The design assumes nfRoot is a sorted-leaf Poseidon2 Merkle tree updated in the aggregation circuit: 512 insertions with non-membership by adjacency, roughly 33,000 permutations, in the region of one more 2^20 node per round on the measured prover. This uses only the AIR that exists.

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

**Assumed:** the SM generator's output rebuild (Phase 15 in `pp1_sm_script_gen.dart`) can be extended as section 5.7 describes: a counted, shape-checked tail after the five fixed outputs, and an lhs parser that reaches input 3. The shape check is what preserves the fixed-count security property; an opaque tail would let a round carry a second PP1 and fork the chain.
**If wrong:** if the rebuild cannot be made to take a variable count, withdrawals and receipts move to a fixed count per round, padded with empty outputs. Ugly, not fatal. If the shape check turns out to be too large to unroll at the chosen maxima, the maxima come down.
**Find out:** read `_emitInductiveProofSettle` for how the output count and the input walk are emitted today, then generate the pool variant and measure it.

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
4. **It would have landed on the variable output tail.** PP1 reads the slot at input 3 and treats inputs 4 and up as opaque deposit covenants. K+1 slots would put deposits at input K+4, so PP1 would have to know K, inside the same lhs-walking code 5.7 is about to change.

**The choice is free from the wallet's side, which is why it could be made on covenant cost alone.** `nk = H(sk, tagNk)` and `nf = H(nk, rho)`, so only the holder of a spending key can produce a nullifier and the coordinator cannot build a spend proof on anyone's behalf in either mode. The proof is produced at the edge regardless; the mode only decides what the coordinator does with a proof it has been handed. A wallet therefore does one read and one submission with no handshake, in either mode. What buys that is the ring: a spend may anchor to any of the four recent `cmRoot`s the header carries, so a proof stays valid for roughly four rounds and never races a round close. That is an argument against ever shrinking the ring to save header bytes.

**What would bring it back.** A deployment whose coordinator genuinely cannot run a prover. It would return as a separate archetype with its own PP1, not as a mode of this one, so that it never constrains PP1_SP's covenant.

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
