# Bitcoin Script Number Encoding

This document specifies how to encode integers for use in `script_number` template parameters.

## Overview

Bitcoin script numbers are little-endian, sign-magnitude encoded byte arrays with a minimal-length requirement. This encoding is used by `ScriptBuilder.number()` in dartsv and equivalent functions in other Bitcoin libraries.

## Encoding Rules

### Special opcodes (most efficient)

| Value | Hex encoding | Opcode |
|-------|-------------|--------|
| 0 | `00` | OP_0 |
| -1 | `4f` | OP_1NEGATE |
| 1 | `51` | OP_1 |
| 2 | `52` | OP_2 |
| 3 | `53` | OP_3 |
| ... | ... | ... |
| 16 | `60` | OP_16 |

### General encoding (values outside -1..16)

1. Take the absolute value
2. Encode as little-endian bytes (minimum bytes needed)
3. If the highest bit of the last byte is set, append a sign byte:
   - `0x00` for positive numbers
   - `0x80` for negative numbers
4. If the number is negative and the highest bit is NOT set, set the highest bit of the last byte
5. Prefix with the byte count as a pushdata opcode

### Examples

| Value | LE bytes | With sign | Pushdata prefix | Full hex |
|-------|----------|-----------|----------------|----------|
| 127 | `7f` | `7f` | `01` | `017f` |
| 128 | `80` | `8000` | `02` | `028000` |
| 255 | `ff` | `ff00` | `02` | `02ff00` |
| 256 | `0001` | `0001` | `02` | `020001` |
| 1000 | `e803` | `e803` | `02` | `02e803` |
| -127 | `7f` → `ff` | `ff` | `01` | `01ff` |
| -128 | `80` → `8080` | `8080` | `02` | `028080` |
| 50000 | `50c3` | `50c300` | `03` | `0350c300` |

## Pushdata Encoding for Byte Arrays

When a parameter uses `script_pushdata` encoding, the raw bytes must be prefixed with their length:

| Length | Prefix format |
|--------|--------------|
| 0 | `00` (OP_0) |
| 1-75 | Single byte = length value |
| 76-255 | `4c` + 1-byte length |
| 256-65535 | `4d` + 2-byte LE length |
| 65536+ | `4e` + 4-byte LE length |

### Example: 20-byte pubkey hash

```
Length = 20 = 0x14
Prefix = 14
Full = 14 + <20 raw bytes> = 42 hex characters total
```

### Example: 36-byte outpoint

```
Length = 36 = 0x24
Prefix = 24
Full = 24 + <36 raw bytes> = 74 hex characters total
```

## Pseudocode Implementation

```
function encodeScriptNumber(value):
    if value == 0:
        return [0x00]  // OP_0
    if value == -1:
        return [0x4f]  // OP_1NEGATE
    if 1 <= value <= 16:
        return [0x50 + value]  // OP_1 through OP_16

    negative = value < 0
    absValue = abs(value)

    // Encode as LE bytes
    result = []
    while absValue > 0:
        result.append(absValue & 0xFF)
        absValue >>= 8

    // Handle sign
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80

    // Prepend pushdata length
    return [len(result)] + result


function encodePushdata(bytes):
    n = len(bytes)
    if n == 0:
        return [0x00]
    if n <= 75:
        return [n] + bytes
    if n <= 255:
        return [0x4c, n] + bytes
    if n <= 65535:
        return [0x4d, n & 0xFF, (n >> 8) & 0xFF] + bytes
    return [0x4e, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF] + bytes
```
