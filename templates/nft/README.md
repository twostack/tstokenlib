# NFT Templates

Templates for non-fungible token scripts in the TSL1 protocol. Each template generates a Bitcoin locking script via simple variable substitution.

## pp1_nft.json — NFT Inductive Proof

The core NFT locking script. Enforces token ownership and validates the parent output structure using an inductive proof chain. Each spend must reconstruct the parent transaction and verify it via SHA256d.

### Use Cases
- Digital collectibles with provable ownership history
- Event tickets, certificates, or receipts
- Any unique, transferable on-chain asset

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the current token owner |
| `tokenId` | 32 | `hex` | Unique token identifier (genesis txid) |
| `rabinPubKeyHash` | 20 | `hex` | Hash160 of the Rabin public key for identity anchoring |

### Header Layout (75 bytes)

```
[0:1]   0x14 prefix
[1:21]  ownerPKH        (mutable — changes on transfer)
[21:22] 0x20 prefix
[22:54] tokenId          (immutable)
[54:55] 0x14 prefix
[55:75] rabinPubKeyHash  (immutable)
[75:]   script body      (immutable)
```

### Example (Python)

```python
import json

with open("pp1_nft.json") as f:
    tpl = json.load(f)

script_hex = tpl["hex"]
script_hex = script_hex.replace("{{ownerPKH}}", owner_pkh_hex)          # 40 hex chars
script_hex = script_hex.replace("{{tokenId}}", token_id_hex)            # 64 hex chars
script_hex = script_hex.replace("{{rabinPubKeyHash}}", rabin_hash_hex)  # 40 hex chars

raw_bytes = bytes.fromhex(script_hex)
```

### Transaction Topology

A standard NFT token transaction has 4 outputs:
1. **Output 0** — ModP2PKH (token value carrier)
2. **Output 1** — PP1_NFT (this script, the inductive proof)
3. **Output 2** — PP2 (witness bridge)
4. **Output 3** — PP3 (partial SHA256 witness check)

---

## pp1_rnft.json — Restricted NFT

Extends PP1_NFT with a 4-byte flags bitfield that controls transfer, burn, and companion restrictions. The script body enforces the flags at the protocol level.

### Use Cases
- Soulbound tokens (non-transferable credentials)
- Tokens that require issuer approval to transfer
- Companion-locked tokens (must travel with a partner token)
- Burn-restricted tokens (cannot be destroyed)

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the current token owner |
| `tokenId` | 32 | `hex` | Unique token identifier (genesis txid) |
| `rabinPubKeyHash` | 20 | `hex` | Hash160 of the Rabin public key |
| `flags` | 4 | `le_uint32` | Restriction flags (4-byte little-endian) |

### Header Layout (80 bytes)

```
[0:1]   0x14 prefix
[1:21]  ownerPKH          (mutable)
[21:22] 0x20 prefix
[22:54] tokenId            (immutable)
[54:55] 0x14 prefix
[55:75] rabinPubKeyHash    (immutable)
[75:76] 0x04 prefix
[76:80] flags              (immutable)
[80:]   script body        (immutable)
```

### Flags Encoding

```
bytes[0] = flags & 0xFF
bytes[1] = (flags >> 8) & 0xFF
bytes[2] = (flags >> 16) & 0xFF
bytes[3] = (flags >> 24) & 0xFF
```

### Note

This is the **no-companion** variant. A with-companion variant adds a 32-byte `companionTokenId` field after flags (at bytes 81-113), which is not covered by this template.

---

## pp1_at.json — Appendable Token (Loyalty/Stamp Card)

A token that accumulates stamps from an authorized issuer. Tracks a rolling hash of all stamp data and a counter. When the stamp count reaches the threshold, the token can be redeemed.

### Use Cases
- Loyalty stamp cards (buy 10, get 1 free)
- Progressive achievement badges
- Multi-step verification processes
- Coupon booklets with incremental redemption

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the token owner |
| `tokenId` | 32 | `hex` | Unique token identifier (genesis txid) |
| `issuerPKH` | 20 | `hex` | Pubkey hash of the authorized stamp issuer |
| `stampCount` | 4 | `le_uint32` | Current stamp count (mutable, incremented per stamp) |
| `threshold` | 4 | `le_uint32` | Stamps needed for redemption (immutable) |
| `stampsHash` | 32 | `hex` | Rolling SHA256 hash of all stamp data (mutable) |

### Header Layout (118 bytes)

```
[0:1]     0x14 prefix
[1:21]    ownerPKH      (mutable — changes on transfer)
[21:22]   0x20 prefix
[22:54]   tokenId        (immutable)
[54:55]   0x14 prefix
[55:75]   issuerPKH      (immutable)
[75:76]   0x04 prefix
[76:80]   stampCount     (mutable)
[80:81]   0x04 prefix
[81:85]   threshold      (immutable)
[85:86]   0x20 prefix
[86:118]  stampsHash     (mutable)
[118:]    script body    (immutable)
```

### Mutable Fields

On each stamp operation:
- `stampCount` increments by 1
- `stampsHash` updates to `SHA256(prevHash || SHA256(stampData))`
- `ownerPKH` may change on transfer

---

## pp2.json — NFT Witness Bridge

Connects the partial SHA256 witness output (PP3) to the inductive proof in PP1. This script validates the sighash preimage and reconstructs the witness transaction to verify its structure.

### Use Cases
- Required companion script for every NFT/RNFT/AT token transaction
- Bridges the off-chain signature verification to on-chain proof

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `outpoint` | varies | `script_pushdata` | 36-byte funding outpoint (txid + index) with pushdata prefix |
| `witnessChangePKH` | varies | `script_pushdata` | 20-byte witness change pubkey hash with pushdata prefix |
| `witnessChangeAmount` | varies | `script_number` | Satoshi amount for witness change output |
| `ownerPKH` | varies | `script_pushdata` | 20-byte owner pubkey hash with pushdata prefix |

### Encoding Note

All parameters use `script_pushdata` or `script_number` encoding, meaning they include their own length prefix. See `encoding/scriptnum.md` for details.

---

## pp3_witness.json — NFT Partial SHA256 Witness

Validates the witness transaction via partial SHA256 completion. This is the script that enforces the final hash comparison between the reconstructed transaction and the actual transaction ID.

### Use Cases
- Required companion for every NFT token transaction
- Provides the burn path (owner can spend directly with P2PKH)

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the token owner (used for burn path) |

### Note

The PP2 output index (2) is baked into the script body for the NFT standard position. For fungible tokens, use `pp3_ft_witness.json` instead (PP2 at index 3).
