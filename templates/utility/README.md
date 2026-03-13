# Utility Templates

General-purpose Bitcoin script templates used by the TSL1 protocol.

## mod_p2pkh.json — Modified P2PKH

A variant of standard Pay-to-Public-Key-Hash that uses `OP_SWAP` before `OP_DUP OP_HASH160`. This is used as the token value carrier output (index 0) in all TSL1 token transactions.

### Use Cases
- Token value output in every TSL1 transaction
- Carries the satoshi value that backs the token
- Spendable by the token owner via standard signature

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | 20-byte pubkey hash of the owner |

### Script Structure

```
OP_SWAP OP_DUP OP_HASH160 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
```

Hex: `7c76a914{{ownerPKH}}88ac`

### Why Modified?

The `OP_SWAP` at the start allows the signature and public key to be passed in reverse order on the stack compared to standard P2PKH. This is required by the TSL1 transaction builder which places the signature before the public key in the scriptSig.

---

## hodl.json — Time-Lock Script (HODL)

A Rabin-signature-verified time-lock script that prevents spending until a specified block height. Uses on-chain Rabin signature verification rather than OP_CHECKLOCKTIMEVERIFY.

### Use Cases
- Vesting schedules for token allocations
- Time-locked savings (enforced by the chain)
- Deferred payment releases
- Any scenario requiring provable time-gating

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPubkeyHash` | varies | `script_pushdata` | 20-byte owner pubkey hash with pushdata prefix |
| `lockHeight` | varies | `script_number` | Block height when funds become spendable |

### Format

This template uses **ASM format** (not hex). Parse it with `SVScript.fromASM()` or equivalent.

### Encoding

Both parameters use their Bitcoin-native encoding:
- `ownerPubkeyHash`: pushdata prefix + raw bytes (e.g., `14` + 20 bytes for a 20-byte hash)
- `lockHeight`: Bitcoin script number encoding (see `encoding/scriptnum.md`)

### Example

```python
# Lock until block 800,000
# 800000 = 0x0C3500 → LE = 00 35 0C → script_number = "0300350c"
hodl_asm = template["asm"]
hodl_asm = hodl_asm.replace("{{ownerPubkeyHash}}", "14" + owner_pkh_hex)
hodl_asm = hodl_asm.replace("{{lockHeight}}", "0300350c")
```
