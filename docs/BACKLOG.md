# Backlog

Work that is understood and specified but not scheduled. Each item states what is wrong, what the fix is, what it costs, and what it breaks. Items move out of here by being done or by being decided against, in which case the decision and its reason stay.

---

## 1. Anchor the issuance base case in the remaining archetypes

**Severity:** high. **Status:** fixed in PP1_SP only. **Decision needed from:** the protocol owner, because it changes script bytes.

### What is wrong

TSL1's inductive proof has no base case on chain. The issuance branch never inspects the token transaction's own inputs, so `tokenId` is bound to nothing. It is assigned off chain as `fundingTx.hash` and thereafter only carried forward.

What issuance actually checks is a Rabin signature over `SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId)` plus the *witness's* `hashPrevouts`. That message contains no outpoint and no nonce, and the signature is published on chain in the first witness's unlocking script, so anyone who has seen an issuance can replay it and mint a token carrying the same `tokenId` with their own `ownerPKH`.

Measured before the PP1_SP fix, with `tool/scratch/double_issue_probe.dart`: a genuine issuance, a second token with a byte-identical PP1 script funded by an unrelated UTXO, and a counterfeit naming the attacker as owner and operator. All three create witnesses were accepted by the interpreter.

This does not let anyone spend an existing token. A counterfeit is a separate UTXO chain that shares a label, not coins. It does mean `tokenId` is not a unique identifier, so any holder, indexer or wallet deciding authenticity from `tokenId` alone can be shown a counterfeit that verifies against the genuine issuer's attestation.

Background: [ARCHITECTURE.md](ARCHITECTURE.md), the note under "The Inductive Argument". Reference implementation and its rationale: [ZK_SHIELDED_POOL_TSL1_DESIGN.md](ZK_SHIELDED_POOL_TSL1_DESIGN.md) section 11.5.

### Affected

| Archetype | Issuance branch | Main stack at issuance | `tokenRawTx` index (D) |
|---|---|---|---|
| PP1_NFT | `_emitIssueToken` | 8 items | 8 |
| PP1_FT | `_emitMintToken` | 8 items | 8 |
| PP1_RFT | `_emitMintToken` | 8 items | 8 |
| PP1_RNFT | `_emitIssueToken` | 8 items | 8 |
| PP1_SM | `_emitCreateFunnel` | 8 items | 8 |
| PP1_AT | `_emitIssueToken` | 10 items | 10 |
| PP1_SP | `_emitCreateFunnel` | 9 items | **done** |

All six have `ownerPKH` on top of the altstack with `tokenId` directly beneath it at issuance, and five of the six have an identical main stack. The work is therefore close to mechanical.

### The fix

Push the token transaction's own raw bytes in the issuance unlock and add a Phase 0 to the branch that does two things:

```
SHA256d(tokenRawTx) == preImage[68:100]
tokenRawTx input 0 outpoint == tokenId ‖ LE32(1)
```

The first check needs no output rebuild, which is the part that makes this cheap. `preImage[68:100]` is the outpoint txid of the PP1 output the witness is spending, which is the token transaction itself, so hashing the pushed bytes and comparing is sufficient to prove they are that transaction. The second then reads input 0's outpoint straight out of bytes the chain has already fixed.

Pinning the index to 1 matches the protocol convention that issuance is funded from output 1 of the funding transaction, and it is what makes `(tokenId, 1)` spendable once. Checking only the txid would let a funding transaction with two unspent outputs produce two issuances under one `tokenId`.

Take `_emitCreateFunnel` Phase 0 in `lib/src/script_gen/pp1_sp_script_gen.dart` as the reference. Three properties of it are deliberate and should be preserved when transplanting:

1. **`tokenRawTx` is pushed at the bottom of the issuance stack**, so no later phase's `OP_PICK` index moves. Phase 0 consumes it and restores the original layout, which keeps the diff purely additive.
2. **The input-count varint must be a single byte.** Without that check an attacker uses 253 or more inputs to make the varint three bytes and shifts the parse off the real outpoint. The check appends `0x00` before `OP_BIN2NUM`, because a bare `0xfd` byte reads as negative under script-number encoding and would pass a naive comparison.
3. **All four depth constants are D**, the size of that archetype's issuance stack. The `pushInt(3); OP_ROLL` in the outpoint comparison is relative to a small working set and stays 3 everywhere.

So for five archetypes the block transplants verbatim, and for PP1_AT the four occurrences of `8` become `10`.

### Per archetype, the work

1. **Script generator.** Insert Phase 0 at the top of the issuance branch, with D set from the table. About 45 lines.
2. **Unlock builder.** Push `tokenRawTx` first in the issuance case, so it lands at the bottom. One line, plus a comment saying why it is first.
3. **Tool.** Supply the token transaction's own serialized bytes to the issuance unlock, not the parent's. The witness builders already receive the token transaction, so this is local. Take care not to change the dual-signature or transfer paths, which legitimately need the parent's bytes.
4. **Funding vout guard.** Each tool's issuance entry point must reject a `fundingVout` other than 1, so a caller gets a clear error rather than an issuance whose witness can never be created. Verify each tool's current default.
5. **Tests.** Two negative tests per archetype, mirroring `test/sp_token_test.dart` group "SP create anchors the base case": a second token with a byte-identical script funded by an unrelated UTXO, and a counterfeit naming the attacker as owner. The first is the conclusive one, because a byte-identical script that passes for the genuine issuance and fails here can only be failing on the funding outpoint.

### Templates

`templates/nft/pp1_nft.json`, `templates/ft/pp1_ft.json` and `templates/sm/pp1_sm.json` embed the script body and must be regenerated. There are no RFT, RNFT or AT templates today.

`test/template_sync_test.dart` round-trips the NFT and FT templates against generator output, so those tests fail until the templates are regenerated. `templates/sm/pp1_sm.json` is not covered by that test and would go stale silently, which is worth fixing at the same time by adding it to the expected-files list.

`tool/scratch/regen_sp_template.dart` shows the approach used for PP1_SP: keep the header placeholder string, replace the body with fresh hex from the generator, and correct the `metadata.generatedBy` and `metadata.sourceFile` fields.

### What this breaks

Existing deployed tokens are **not** invalidated. A UTXO carries its own locking script, so tokens already on chain keep working exactly as before.

What does change:

- **New issuances get a different PP1 script.** Anything matching on a template prefix or a script hash needs updating, including the lock builders' `parse` methods, which currently validate against a template prefix.
- **Tokens issued under the old script stay unanchored permanently.** There is no retrofit, which is an argument for doing this sooner rather than later.
- **The JVM backport** ([JVM_BACKPORT_ROADMAP.md](JVM_BACKPORT_ROADMAP.md), monocelo) needs the same change or the two implementations diverge on a security property.
- **Downstream consumers** (libspiffy, overnode_v2) need checking for anywhere `tokenId` is treated as a unique key, since that assumption is what the defect breaks and what the fix restores.

### Effort

Roughly half a day for the six archetypes, given PP1_SP as a worked reference: the script change is a transplant with one constant, and the test is a copy with different fixtures. Template regeneration and the downstream sweep are the larger unknowns.

### Open questions

- Should the vout be pinned to 1, or become an immutable header field? Pinning is simpler and matches the stated convention, but it forecloses funding issuance from any other index. The header field costs 4 or 5 bytes and a layout change in every archetype.
- Should the Rabin message itself also absorb the funding outpoint? That would make the attestation non-replayable at its source rather than relying on the outpoint check alone. It is defence in depth, and it changes the issuer signing flow, so it is a separate decision.
- PP1_SP pins the index inside the script. If the header-field route is taken later, PP1_SP should follow so the archetypes stay consistent.
