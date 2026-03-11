# TSL1 Bitcoin Script Templates

Language-agnostic script templates for the TSL1 Token Protocol. These templates allow any language to construct valid Bitcoin locking scripts via simple variable substitution.

## Template Format

Each `.json` file is a descriptor containing:

```json
{
  "name": "PP1",
  "version": "1.3.0",
  "description": "...",
  "parameters": [ ... ],
  "hex": "14{{ownerPKH}}20{{tokenId}}..."
}
```

### Fields

| Field | Description |
|-------|-------------|
| `name` | Script identifier |
| `version` | TSL1 protocol version |
| `description` | What the script does |
| `parameters` | Array of substitution parameters |
| `hex` | Hex-encoded script with `{{param}}` placeholders |
| `asm` | (HODL only) ASM-encoded script with placeholders |
| `metadata` | Source file, generation notes |

## Parameter Encodings

### `hex` (fixed-size, Category A scripts: PP1_NFT, PP1_FT, PP3, ModP2PKH)

The pushdata length prefix (e.g., `0x14` for 20 bytes, `0x20` for 32 bytes) is already part of the static hex surrounding the placeholder. You only need to substitute the **raw hex bytes** of the parameter value.

Example for PP1:
```
Static hex: 14{{ownerPKH}}20{{tokenId}}14{{rabinPubKeyHash}}6e6e6e...
                                                              ^^^^^^ script body
Substitute:  14<40 hex chars>20<64 hex chars>14<40 hex chars>6e6e6e...
```

### `le_uint56` (PP1_FT amount)

8-byte little-endian encoding with bit 63 always clear:
```
bytes[0..6] = value & 0x00FFFFFFFFFFFFFF (7 bytes LE)
bytes[7]    = (value >> 56) & 0x7F
```

Maximum representable value: 2^55 - 1.

### `script_pushdata` (Category B scripts: PP2, PP2-FT, HODL)

The parameter value must include its Bitcoin pushdata prefix. This is what `ScriptBuilder.addData()` produces:

| Data size | Prefix |
|-----------|--------|
| 1-75 bytes | Single byte = length |
| 76-255 bytes | `0x4c` + 1-byte length |
| 256-65535 bytes | `0x4d` + 2-byte LE length |

Example: 20-byte pubkey hash → prefix `0x14` + 20 raw bytes = 21 bytes total, 42 hex chars.

### `script_number` (Category B scripts: PP2, PP2-FT, HODL)

Bitcoin script number encoding, as produced by `ScriptBuilder.number()`:

| Value | Encoding |
|-------|----------|
| 0 | `00` (OP_0) |
| 1-16 | `51`-`60` (OP_1 through OP_16) |
| -1 | `4f` (OP_1NEGATE) |
| Other | `<len><LE bytes>` with sign bit handling |

See `encoding/scriptnum.md` for full specification.

## Directory Structure

```
templates/
  nft/
    pp1_nft.json            # NFT inductive proof
    pp2.json            # NFT witness bridge
    pp3_witness.json    # NFT partial SHA256 witness
  ft/
    pp1_ft.json            # Fungible token proof
    pp2_ft.json         # FT witness bridge
    pp3_ft_witness.json # FT partial SHA256 witness
  utility/
    mod_p2pkh.json      # Modified P2PKH (token value output)
    hodl.json           # Time-lock script
  encoding/
    scriptnum.md        # Bitcoin script number encoding spec
```

## Usage Example (pseudocode)

```python
import json

# Load template
with open("templates/nft/pp1_nft.json") as f:
    tpl = json.load(f)

# Substitute parameters (raw hex bytes, no pushdata prefix needed)
script_hex = tpl["hex"]
script_hex = script_hex.replace("{{ownerPKH}}", owner_pkh_hex)      # 40 hex chars
script_hex = script_hex.replace("{{tokenId}}", token_id_hex)        # 64 hex chars
script_hex = script_hex.replace("{{rabinPubKeyHash}}", rabin_hash)  # 40 hex chars

# script_hex is now a complete Bitcoin locking script
raw_bytes = bytes.fromhex(script_hex)
```

## Regenerating Templates

Templates are generated from the Dart source code:

```bash
dart run tool/export_templates.dart
```

This ensures templates stay in sync with the hand-optimized script generators.
