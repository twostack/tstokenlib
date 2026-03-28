# TSL1 Bitcoin Script Templates

Language-agnostic script templates for the TSL1 Token Protocol. These templates allow any language to construct valid Bitcoin locking scripts via simple variable substitution into JSON descriptors.

## Templates

### NFT (`nft/`)

| Template | Description | Parameters |
|----------|-------------|------------|
| [pp1_nft.json](nft/README.md#pp1_nftjson--nft-inductive-proof) | NFT inductive proof | ownerPKH, tokenId, rabinPubKeyHash |
| [pp1_rnft.json](nft/README.md#pp1_rnftjson--restricted-nft) | Restricted NFT with flags | ownerPKH, tokenId, rabinPubKeyHash, flags |
| [pp1_at.json](nft/README.md#pp1_atjson--appendable-token-loyaltystamp-card) | Appendable token (loyalty card) | ownerPKH, tokenId, issuerPKH, stampCount, threshold, stampsHash |
| [pp2.json](nft/README.md#pp2json--nft-witness-bridge) | NFT witness bridge | outpoint, witnessChangePKH, witnessChangeAmount, ownerPKH |
| [pp3_witness.json](nft/README.md#pp3_witnessjson--nft-partial-sha256-witness) | NFT partial SHA256 witness | ownerPKH |

### Fungible Tokens (`ft/`)

| Template | Description | Parameters |
|----------|-------------|------------|
| [pp1_ft.json](ft/README.md#pp1_ftjson--fungible-token-inductive-proof) | Fungible token proof | ownerPKH, tokenId, amount |
| [pp1_rft.json](ft/README.md#pp1_rftjson--restricted-fungible-token) | Restricted FT with flags | ownerPKH, tokenId, rabinPubKeyHash, flags, amount |
| [pp2_ft.json](ft/README.md#pp2_ftjson--ft-witness-bridge) | FT witness bridge | outpoint, witnessChangePKH, witnessChangeAmount, ownerPKH, pp1FtOutputIndex, pp2OutputIndex |
| [pp3_ft_witness.json](ft/README.md#pp3_ft_witnessjson--ft-partial-sha256-witness) | FT partial SHA256 witness | ownerPKH |

### State Machine (`sm/`)

| Template | Description | Parameters |
|----------|-------------|------------|
| [pp1_sm.json](sm/README.md) | State machine token (7 ops) | ownerPKH, tokenId, operatorPKH, counterpartyPKH, currentState, checkpointCount, commitmentHash, transitionBitmask, timeoutDelta |

### Utility (`utility/`)

| Template | Description | Parameters |
|----------|-------------|------------|
| [mod_p2pkh.json](utility/README.md#mod_p2pkhjson--modified-p2pkh) | Modified P2PKH (token value output) | ownerPKH |
| [hodl.json](utility/README.md#hodljson--time-lock-script-hodl) | Time-lock script | ownerPubkeyHash, lockHeight |

### Encoding Reference (`encoding/`)

| File | Description |
|------|-------------|
| [scriptnum.md](encoding/scriptnum.md) | Bitcoin script number and pushdata encoding spec |

## Template Format

Each `.json` descriptor contains:

```json
{
  "name": "PP1_NFT",
  "version": "1.3.0",
  "description": "...",
  "parameters": [
    { "name": "ownerPKH", "size": 20, "encoding": "hex", "description": "..." }
  ],
  "hex": "14{{ownerPKH}}20{{tokenId}}...",
  "metadata": { "sourceFile": "...", "note": "..." }
}
```

## Parameter Encodings

| Encoding | Used By | Description |
|----------|---------|-------------|
| `hex` | PP1_NFT, PP1_FT, PP1_RNFT, PP1_RFT, PP1_AT, PP1_SM, PP3, ModP2PKH | Raw hex bytes. Pushdata prefix is in the static hex. |
| `hex_byte` | PP1_SM (currentState, checkpointCount, transitionBitmask) | Single byte as 2 hex chars. Prefix `0x01` is in static hex. |
| `le_uint32` | PP1_RNFT/RFT flags, PP1_AT stampCount/threshold, PP1_SM timeoutDelta | 4-byte little-endian unsigned integer. |
| `le_uint56` | PP1_FT/RFT amount | 8-byte LE, bit 63 clear. Max: 2^55 - 1. |
| `script_pushdata` | PP2, PP2-FT, HODL | Includes Bitcoin pushdata length prefix. |
| `script_number` | PP2, PP2-FT, HODL | Bitcoin script number encoding (OP_0..OP_16, or LE with sign bit). |

See each subdirectory's README for detailed encoding examples and header layouts.

## Quick Start

```python
import json

with open("templates/nft/pp1_nft.json") as f:
    tpl = json.load(f)

script_hex = tpl["hex"]
script_hex = script_hex.replace("{{ownerPKH}}", owner_pkh_hex)
script_hex = script_hex.replace("{{tokenId}}", token_id_hex)
script_hex = script_hex.replace("{{rabinPubKeyHash}}", rabin_hash_hex)

raw_bytes = bytes.fromhex(script_hex)
```

## Regenerating Templates

```bash
dart run tool/export_templates.dart
```

Templates are generated from the Dart script generators and stay in sync with the hand-optimized source code.
