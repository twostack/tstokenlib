# Fungible Token Templates

Templates for fungible token scripts in the TSL1 protocol. These templates support divisible, amount-bearing tokens with conservation rules enforced on-chain.

## pp1_ft.json — Fungible Token Inductive Proof

The core fungible token locking script. Enforces amount conservation across all operations (mint, transfer, split, merge, burn). The script verifies that total input amounts equal total output amounts during splits and merges.

### Use Cases
- On-chain currencies and stablecoins
- Reward points and in-game currencies
- Divisible vouchers and credits
- Any asset where fractional ownership matters

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the current token owner |
| `tokenId` | 32 | `hex` | Unique token identifier (genesis txid) |
| `amount` | 8 | `le_uint56` | Token amount (7 bytes LE value + high byte with bit 7 clear) |

### Header Layout (63 bytes)

```
[0:1]   0x14 prefix
[1:21]  ownerPKH  (mutable)
[21:22] 0x20 prefix
[22:54] tokenId   (immutable)
[54:55] 0x08 prefix
[55:63] amount    (mutable — changes on split/merge)
[63:]   script body (immutable)
```

### Amount Encoding (`le_uint56`)

```
bytes[0..6] = value & 0x00FFFFFFFFFFFFFF  (7 bytes, little-endian)
bytes[7]    = (value >> 56) & 0x7F         (high byte, bit 7 always clear)
```

Maximum representable value: 2^55 - 1 (approximately 36 quadrillion).

### Operations

| Operation | Description |
|-----------|-------------|
| Transfer | Move full amount to a new owner |
| Split | Divide into multiple outputs (amounts must sum to input) |
| Merge | Combine multiple inputs into one output |
| Burn | Owner destroys the token |

---

## pp1_rft.json — Restricted Fungible Token

Extends PP1_FT with a 4-byte flags bitfield for transfer and burn restrictions. Combines the restriction model of PP1_RNFT with the amount conservation of PP1_FT.

### Use Cases
- Regulated securities tokens (transfer restrictions)
- Vesting tokens (cannot be sold until conditions met)
- Burn-restricted reward points
- KYC-gated currencies

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the current token owner |
| `tokenId` | 32 | `hex` | Unique token identifier (genesis txid) |
| `rabinPubKeyHash` | 20 | `hex` | Hash160 of the Rabin public key |
| `flags` | 4 | `le_uint32` | Restriction flags (4-byte little-endian) |
| `amount` | 8 | `le_uint56` | Token amount |

### Header Layout (89 bytes)

```
[0:1]   0x14 prefix
[1:21]  ownerPKH          (mutable)
[21:22] 0x20 prefix
[22:54] tokenId            (immutable)
[54:55] 0x14 prefix
[55:75] rabinPubKeyHash    (immutable)
[75:76] 0x04 prefix
[76:80] flags              (immutable)
[80:81] 0x08 prefix
[81:89] amount             (mutable)
[89:]   script body        (immutable)
```

---

## pp2_ft.json — FT Witness Bridge

Extends the NFT witness bridge (PP2) with additional parameters for variable output indexing. Fungible token transactions may have different output positions for PP1_FT and PP2-FT due to split/merge topologies.

### Use Cases
- Required companion for every FT/RFT token transaction

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `outpoint` | varies | `script_pushdata` | 36-byte funding outpoint with pushdata prefix |
| `witnessChangePKH` | varies | `script_pushdata` | 20-byte witness change pubkey hash |
| `witnessChangeAmount` | varies | `script_number` | Satoshi amount for witness change |
| `ownerPKH` | varies | `script_pushdata` | 20-byte owner pubkey hash |
| `pp1FtOutputIndex` | varies | `script_number` | Output index of the PP1_FT output |
| `pp2OutputIndex` | varies | `script_number` | Output index of the PP2-FT output |

---

## pp3_ft_witness.json — FT Partial SHA256 Witness

Identical to the NFT PP3 witness script, but with PP2 output index set to 3 (the FT standard position, since FT transactions have an extra output for amount).

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Pubkey hash of the token owner (used for burn path) |

### Note

PP2 output index 3 is baked into the script body. For NFTs (PP2 at index 2), use `nft/pp3_witness.json`.
