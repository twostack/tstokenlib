# TSL1 Token Protocol — Architecture Guide

This document describes the internal architecture of the TSL1 Token Protocol, a fully miner-validated token system on Bitcoin (BSV). The protocol achieves double-spend protection equivalent to native satoshis without requiring indexers, back-to-genesis tracing, or transaction bloating on successive transfers.

---

## Table of Contents

1. [5-Output Transaction Structure](#5-output-transaction-structure)
2. [Inductive Proof Mechanism (PP1)](#inductive-proof-mechanism-pp1)
3. [Partial SHA256 Witness Mechanism](#partial-sha256-witness-mechanism)
4. [Transaction Relationships](#transaction-relationships)
5. [Transaction Flow Diagrams](#transaction-flow-diagrams)
6. [Design Principle: Where Bytes Are Paid](#design-principle-where-bytes-are-paid)

---

## 5-Output Transaction Structure

Every token transaction (issuance or transfer) produces exactly five outputs. Together, these outputs form a proof-carrying UTXO that miners can validate without external state.

```
Token Transaction
+-------------------------------------------------------------------+
| Output[0]: Change (P2PKH)                                         |
| Output[1]: PP1    — Inductive Proof                               |
| Output[2]: PP2    — Witness Bridge                                |
| Output[3]: PP3    — Partial SHA256 Witness Lock                   |
| Output[4]: Metadata — OP_RETURN                                   |
+-------------------------------------------------------------------+
```

### Output[0] — Change (P2PKH)

Standard P2PKH output returning unspent satoshis to the current owner. This is the change output from the funding input after subtracting fees and the dust amounts locked in outputs 1-3.

### Output[1] — PP1 (Inductive Proof Locking Script)

The core of the token's validity chain. PP1 is a compiled sCrypt contract that embeds two critical data elements:

- **recipientPKH** — The pubkey hash of the token recipient. The token is locked to this address.
- **tokenId** — The unique identifier for this token, assigned at issuance (derived from the hash of the initial funding transaction).

PP1 enforces the structural integrity of the token chain by verifying that each new token transaction carries forward the correct output structure from its parent. It is spent by the witness transaction.

Value: 1 satoshi (dust).

### Output[2] — PP2 (Witness Bridge)

PP2 bridges the connection between PP1 (inductive proof) and PP3 (partial SHA256 witness). It contains four embedded parameters:

- **fundingOutpoint** — The outpoint (txid + vout) that will fund the witness transaction. This is a 36-byte value consisting of the 32-byte witness funding txid and the 4-byte little-endian output index.
- **witnessChangePKH** — The pubkey hash to which the witness transaction output will be locked.
- **changeAmount** — The satoshi amount locked by the witness output.
- **ownerPKH** — The pubkey hash of the current token owner (used for the burn path).

PP2 validates that all witness transaction outpoints spend from the correct token transaction. It does so by performing an in-script rebuild of the sighash preimage and verifying the witness transaction's output is locked to the correct owner via `ModP2PKH`.

Value: 1 satoshi (dust).

### Output[3] — PP3 (Partial SHA256 Witness Lock)

The partial SHA256 locking script that verifies the structure of the witness transaction without requiring the full transaction data in script. Contains one embedded parameter:

- **ownerPKH** — The pubkey hash of the current token owner (used for the burn path).

PP3 uses a partial SHA256 technique (described in detail below) to verify that the witness transaction conforms to the expected structure. It is spent during a token transfer, where the next token transaction must prove knowledge of the previous witness transaction's structure.

Value: 1 satoshi (dust).

### Output[4] — Metadata (OP_RETURN)

An `OP_RETURN` output carrying token metadata. This output holds zero satoshis and is unspendable. On issuance, it may contain:

- Arbitrary metadata bytes, or
- Issuer identity data in MAP format (identity transaction ID and ED25519 signature).

On transfer, the metadata script is carried forward verbatim from the parent token transaction, preserving the token's identity information across the entire chain of ownership.

Value: 0 satoshis.

---

## Inductive Proof Mechanism (PP1)

PP1 is the mechanism that eliminates the need for back-to-genesis tracing. Instead of verifying the entire history of a token, each transfer only needs to verify its immediate parent — the validity of the chain is maintained inductively.

### How It Works

**On issuance:**

```
tokenId = hash(fundingTx)
```

The token ID is set to the transaction ID of the funding transaction used in the initial issuance. This value is embedded in the PP1 locking script and remains constant for the lifetime of the token.

**On transfer:**

PP1 in the new token transaction verifies that:

1. The spending transaction (witness tx) carries forward the correct PP2 output structure from the parent token transaction.
2. The PP2 output bytes from the parent are provided in the unlocking script and match the expected format.
3. The token ID remains consistent — the same value embedded at issuance is carried through every subsequent transfer.
4. Outputs[1-4] of the new token transaction maintain the correct structure (PP1 with same tokenId, PP2 with correct parameters, PP3 with owner PKH, metadata carried forward).

### The Inductive Argument

```
Base case:    Issuance — tokenId is set, outputs[1-4] are constructed correctly.
Inductive step: Transfer — PP1 verifies the parent had valid outputs[1-4],
                therefore the new transaction inherits validity without
                checking the grandparent or any earlier ancestor.
```

> **The base case does not currently anchor (measured 2026-09-20).**
> The issuance branch (`_emitIssueToken`, and `_emitCreateFunnel` in the SM
> generator) never inspects the token transaction's own inputs. It has no lhs
> and no parent raw transaction on its stack, so it cannot rebuild the token
> transaction. It checks a Rabin signature over
> `SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId)` and pins the *witness's*
> inputs via `hashPrevouts == SHA256d(fundingOutpoint ‖ (tokenTxId,1) ‖ (tokenTxId,2))`.
> `tokenId = hash(fundingTx)` is assigned off chain and never verified on chain.
>
> Because that Rabin message contains no outpoint and no nonce, and the
> signature is published in the first witness's unlocking script, anyone can
> replay it to issue a second token carrying the same `tokenId`, with their own
> `ownerPKH` and `operatorPKH`. Reproduced in
> `tool/scratch/double_issue_probe.dart`: three issuances, one genuine and two
> counterfeit, all three create witnesses accepted by the interpreter.
>
> This does not allow spending an existing token. A counterfeit is a separate
> UTXO chain that shares a label, not coins. It does mean `tokenId` is not a
> unique identifier and cannot be used alone to decide authenticity.
>
> The fix is cheaper than the transfer branches' machinery and needs no output
> rebuild: push the token transaction's own raw bytes, check
> `SHA256d(tokenRawTx) == preImage[68:100]` (that field is the outpoint txid of
> the PP1 output the witness is spending, so it is this token transaction), then
> require input 0's outpoint inside those bytes to equal `tokenId ‖ LE32(1)`.
> That ties the base case to an outpoint that can be spent once and makes the
> replay useless.
>
> **Implemented in PP1_SP only** (`_emitCreate`, Phase 0), on the
> shielded-pool branch, with regression tests in `test/sp_token_test.dart`.
> PP1_SM, PP1_NFT, PP1_FT, PP1_RFT, PP1_RNFT and PP1_AT are unchanged and still
> carry the unanchored branch. Fixing them changes their script bytes and so the
> locking script of every deployed token, which is a protocol decision.

This means a verifier (miner) only needs to evaluate the script for the current transaction. If PP1 succeeds, the token is valid — no SPV proof chain, no indexer lookup, no scanning back to genesis.

### PP1 Unlock Data

When spending PP1 (in the witness transaction), the unlock script provides:

- The sighash preimage of the witness transaction
- The serialized PP2 output from the token transaction
- The owner's public key
- The token change PKH and change amount
- The left-hand side (LHS) of the token transaction (version + inputs)
- The serialized parent token transaction bytes (empty on issuance)
- Padding bytes for SHA256 block alignment
- The token action flag (ISSUANCE or TRANSFER)
- The funding transaction hash

---

## Partial SHA256 Witness Mechanism

The partial SHA256 mechanism allows PP3 to verify the structure of the witness transaction without pushing the entire transaction into script. This is critical because the witness transaction can be large, and Bitcoin script has practical limits on data pushes.

### The Core Idea

SHA256 processes data in 64-byte (512-bit) blocks. The partial SHA256 technique exploits this block structure:

1. The witness transaction is padded so that a specific boundary (the start of the last input + output region) aligns to a 64-byte SHA256 block boundary.
2. All SHA256 blocks up to the last 2 blocks are hashed externally, producing an intermediate hash state (the **partial hash** or **IV**).
3. Only the last 2 blocks (128 bytes) — the **remainder** — are provided to the script.
4. The script resumes SHA256 from the intermediate state, hashing the remainder to produce the final hash.
5. The script verifies this final hash matches the expected transaction ID.

### Transaction Padding

The `TransactionUtils.calculatePaddingBytes()` method computes the exact number of padding bytes needed:

```
SHA256_BLOCK_SIZE = 64 bytes

lastInputStart = txSize - (lastInputSize + outputsSize + LOCKTIME_SIZE)

Pad so that lastInputStart falls on a 64-byte boundary.
```

The padding bytes are inserted into the witness transaction's unlock script. The transaction is built twice: once with placeholder padding to determine the size, then again with the correctly computed padding.

### Partial Hash Computation

The `TransactionUtils.computePartialHash()` method:

1. Takes the full serialized witness transaction bytes.
2. Pads them according to SHA256 rules.
3. Hashes all blocks except the final `excludeBlocks` (typically 2) blocks.
4. Returns a tuple: `(partialHash, remainder)` where:
   - `partialHash` is the intermediate SHA256 state (8 x 32-bit words).
   - `remainder` is the final 128 bytes (2 blocks) that PP3 will verify in script.

### PP3 In-Script Verification

During a token transfer, PP3 is spent by the new token transaction (input[2]). The unlock script provides:

- The sighash preimage of the new token transaction
- The partial hash (intermediate SHA256 state)
- The witness partial preimage (remainder bytes)
- The funding transaction hash

PP3's locking script then:

1. Resumes SHA256 from the partial hash over the remainder bytes.
2. Verifies the resulting hash matches the witness transaction ID referenced in the spending transaction.
3. Confirms the witness output is locked to the expected owner.

### Why This Works

The partial SHA256 approach ensures:

- The witness transaction genuinely exists and has the claimed structure.
- Only 128 bytes of the witness transaction need to appear in script, not the full transaction.
- The verification is performed entirely by miners during script evaluation — no external oracle or indexer.

---

## Transaction Relationships

The protocol uses three distinct transaction types that work together:

### Token Transaction

The token UTXO itself. Contains the 5-output structure described above. This is the on-chain representation of the token.

- **Inputs:** Funding UTXO (on issuance), or Funding UTXO + previous witness output + previous PP3 (on transfer).
- **Outputs:** Change, PP1, PP2, PP3, Metadata (5 outputs).

### Witness Transaction

Proves ownership of a token. Created immediately after a token transaction. Spends PP1 and PP2 from the token transaction to demonstrate that the token holder controls the private key.

- **Inputs:** Funding UTXO, PP1 (from token tx, output[1]), PP2 (from token tx, output[2]).
- **Outputs:** Single output locked to the current token holder via `ModP2PKH`.

The `ModP2PKH` script is a modified P2PKH template:

```
OP_SWAP OP_DUP OP_HASH160 <pubkeyHash> OP_EQUALVERIFY OP_CHECKSIG
```

This differs from standard P2PKH by using `OP_SWAP` at the beginning, which expects the public key and signature in reversed order on the stack (`<pubkey> <sig>` instead of `<sig> <pubkey>`). This allows the witness transaction output to remain compact (35 bytes) while still being spendable with standard key pairs.

### Funding Transaction

A standard P2PKH UTXO that provides satoshis for transaction fees. The protocol expects the funding output to be at index 1 (`output[1]`) of the funding transaction. Each token operation (issuance, transfer, witness creation) requires its own funding input.

---

## Transaction Flow Diagrams

### Issuance Flow

A new token is created from a funding transaction, then immediately witnessed.

```
                         Token Transaction (5 outputs)
                        +-----------------------------+
                        | out[0]: Change (P2PKH)      |
  Funding Tx            | out[1]: PP1 (tokenId, PKH)  |
 +-----------+          | out[2]: PP2 (bridge)        |
 | out[1]  --+--------->| out[3]: PP3 (partial SHA)   |
 +-----------+  in[0]   | out[4]: Metadata (OP_RETURN)|
                        +-----------------------------+
                              |  out[1]     |  out[2]
                              |  (PP1)      |  (PP2)
                              v             v
                        +-----------------------------+
  Witness Funding Tx    |                             |
 +-----------+          |    Witness Transaction      |
 | out[1]  --+--------->|                             |
 +-----------+  in[0]   | out[0]: ModP2PKH (owner)    |
                        +-----------------------------+

  tokenId = hash(FundingTx)
```

### Transfer Flow

The current owner transfers the token to a new recipient. The new token transaction spends the previous witness output and the previous PP3 output, proving ownership. A new witness transaction is then created.

```
  Previous Witness Tx        Previous Token Tx
 +------------------+       +------------------+
 | out[0] (ModP2PKH)|       | out[3] (PP3)     |
 +--------+---------+       +--------+---------+
          |  in[1]                    |  in[2]
          v                           v
        +---------------------------------------+
        |     New Token Transaction (5 outputs) |
        |                                       |
  Funding Tx                                    |
 +-----------+    | out[0]: Change (P2PKH)      |
 | out[1]  --+--->| out[1]: PP1 (tokenId, PKH)  |
 +-----------+    | out[2]: PP2 (bridge)        |
       in[0]      | out[3]: PP3 (partial SHA)   |
                  | out[4]: Metadata (carried)  |
                  +---------------------------------------+
                        |  out[1]     |  out[2]
                        |  (PP1)      |  (PP2)
                        v             v
                  +-----------------------------+
  New Witness     |                             |
  Funding Tx      |   New Witness Transaction   |
 +-----------+    |                             |
 | out[1]  --+--->| out[0]: ModP2PKH (recipient)|
 +-----------+    +-----------------------------+
       in[0]

  tokenId remains unchanged from issuance.
  Metadata (out[4]) is carried forward from the previous token tx.
  PP1 validates the parent's PP2 output structure inductively.
  PP3 validates the previous witness tx via partial SHA256.
```

### Burn Flow

The token owner destroys the token by spending all proof outputs (PP1, PP2, PP3) simultaneously. The burn path is embedded in each locking script and requires the owner's signature against the embedded `ownerPKH`.

```
  Token Transaction
 +------------------+
 | out[1]: PP1    --+------+
 | out[2]: PP2    --+------+----> Burn Transaction
 | out[3]: PP3    --+------+     +------------------+
 +------------------+            | out[0]: Change   |
                                 |   (P2PKH, owner) |
  Funding Tx                     +------------------+
 +-----------+                        ^
 | out[1]  --+------------------------+
 +-----------+           in[0]

  All proof outputs are consumed.
  Only a single change output remains.
  The token ceases to exist in the UTXO set.
```

---

## Design Principle: Where Bytes Are Paid

TSL1 alternates two kinds of transaction. A token transaction spends the previous witness's output and the previous PP3; a witness spends the token transaction's PP1 and PP2. The two are not symmetric in what they cost, and the asymmetry is a design tool for anything built on top of the protocol.

### A token transaction is paid three times

1. It is mined.
2. Its own PP1, running in its witness, rebuilds it from pushed data: the lhs (version and every input, each with its full unlocking script), the outputs it reconstructs from templates and header fields, and nLockTime. It hashes the result and requires equality with its own outpoint's txid. This is how PP1 knows which ancestor the transaction spent: input 2's outpoint is read from a byte string whose hash the chain has already fixed.
3. The next token transaction's PP1, running in the next witness, pushes it whole as the parent and hashes it again to match input 2's outpoint.

Because the lhs carries the unlocking scripts, a token transaction's inputs cost as much as its outputs. Any large blob placed in a token transaction, whether as an output script or as unlocking data, is pushed twice more after it is mined.

### A witness is paid once

PP3 verifies the witness by resuming SHA-256 from a midstate over its last few blocks. The next token transaction spends the witness's single 35-byte output with an ordinary signature. Nothing in the protocol ever holds a witness's full bytes on a stack. Its size is bounded only by policy, and its cost is its size.

The one constraint is that the witness's tail must stay within the block count PP3 unrolls, so a bulky input must not be the last input. The witness builder already computes padding by building the transaction twice, so an ordering that works exists.

### The rule

Keep every token transaction small. Put every large thing either in a witness's unlocking data, or in a separate transaction whose bytes are pushed once, in a witness, to establish what it is.

Two things follow from where each script runs.

- **Money moves in the token transaction, so anything that gates money must be an input of it.** A check that runs in the witness runs after the token transaction is mined. It can refuse to continue the chain, which freezes the token, but it cannot undo a payout. A witness-side check turns a dishonest owner's failure into death of the chain, never theft. That is acceptable for structural checks and fatal for value checks.
- **Data that must be published and bound, but not inspected at spend time, belongs in the witness.** Commit its hash in the token's header; have PP1 check the pushed bytes against that hash in the witness. The bytes are on chain once and never re-pushed.

### Worked example

The shielded pool round is the case that found this. A round carried a 1.5 MB verifier as an output and a 1.4 MB state script, so the round was 8.24 MB and a witness beside it would have pushed the same again. Moving the verifier to a separate transaction that PP3 pins by outpoint and PP1 checks by bytes, moving the ciphertext bundles to the witness, and moving the nullifier work into the proof, leaves a round of about 0.4 MB with a 3.3 MB witness. The verifier still runs in the round, as an input, because it gates withdrawals. See [ZK_SHIELDED_POOL_TSL1_DESIGN.md](ZK_SHIELDED_POOL_TSL1_DESIGN.md), sections 2 and 10.

---

## Summary of Key Invariants

| Property | Enforcement |
|---|---|
| Token ID immutability | PP1 embeds tokenId at issuance; every transfer must carry the same value |
| Ownership | PP1 and PP2 are locked to the recipient's PKH; only the key holder can create a valid witness |
| No back-to-genesis | PP1's inductive proof validates only the immediate parent |
| No transaction bloat | Each token tx is a fixed 5-output structure regardless of transfer depth |
| Double-spend protection | Token outputs are standard UTXOs; miners enforce single-spend rules natively |
| Metadata persistence | Output[4] is copied verbatim from parent token tx on every transfer |
| Burn authorization | PP1, PP2, and PP3 each contain the ownerPKH; burn requires the owner's signature on all three |
