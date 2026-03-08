# SHA256 Script Generator: Future Optimizations with New BSV Opcodes

## Current State

The hand-optimized SHA256 script generator (`sha256_script_gen.dart`) produces **~30.7KB per block** (~61.4KB for two blocks), down from ~100KB with the sCrypt-compiled template. This was achieved by:

- Programmatic Dart generator emitting fully-unrolled Bitcoin Script
- LE state words during compression (eliminating reverseBytes4 from additions)
- BE blobs for message schedule (sigma functions use OP_LSHIFT/OP_RSHIFT natively)

The original optimization target was **25KB per block**. Six new BSV opcodes can close the remaining ~5.4KB gap.

---

## New Opcodes

### OP_LSHIFTNUM (0xb6) / OP_RSHIFTNUM (0xb7)

**Numerical bit shifts** that operate on script numbers (LE), unlike OP_LSHIFT/OP_RSHIFT which operate on big-endian byte arrays.

```
Inputs:  a (number), b (shift amount)
Output:  a shifted left/right by b bits (preserving sign)
```

### OP_SUBSTR (0xb3)

Returns a substring by start index and length, replacing the current multi-opcode extraction pattern.

```
Inputs:  string, start_index, length
Output:  string[start_index .. start_index + length - 1]
```

### OP_LEFT (0xb4)

Returns the leftmost N bytes of a string.

```
Inputs:  string, length
Output:  string[0 .. length - 1]
```

### OP_RIGHT (0xb5)

Returns the rightmost N bytes of a string.

```
Inputs:  string, length
Output:  string[len - length .. len - 1]
```

### OP_2MUL (0x8d) / OP_2DIV (0x8e)

Multiply/divide the top stack number by 2 in a single opcode.

---

## Optimization 1: All-LE Pipeline via LSHIFTNUM/RSHIFTNUM

**Estimated savings: ~4.0 KB per block**

### Problem

The current pipeline is split: compression uses LE state words (cheap additions), but sigma functions still require BE byte arrays for OP_LSHIFT/OP_RSHIFT. Each sigma call wraps with `reverseBytes4` in/out (24 bytes overhead). The message schedule stays entirely BE, paying full conversion costs on every addition.

### Solution

OP_LSHIFTNUM and OP_RSHIFTNUM enable **arithmetic rotations directly on script numbers**, eliminating all BE byte arrays from the pipeline.

**ROTR(n, x) as a pure number operation:**

```
DUP                          // x x
push n, OP_RSHIFTNUM         // (x>>n) x        — upper bits
SWAP                         // x (x>>n)
push 2^n, OP_MOD             // (x mod 2^n) (x>>n)  — lower n bits
push (32-n), OP_LSHIFTNUM   // (lower << (32-n)) (x>>n)
OP_ADD                       // ROTR(n, x)
```

Cost: 10-14 bytes per rotation (varies by push sizes for 2^n).
No overflow: bit ranges don't overlap, so ADD is equivalent to OR.

**Impact on sigma functions:**

| Function | Current (BE + wrapper) | With LSHIFTNUM | Change |
|----------|----------------------|----------------|--------|
| σ0 (msg schedule) | 23B (BE only, no wrapper) | ~42B (number-based) | +19B |
| σ1 (msg schedule) | 24B | ~44B | +20B |
| Σ0 (compression) | 56B (32B + 24B wrapper) | ~55B (no wrapper) | -1B |
| Σ1 (compression) | 55B (31B + 24B wrapper) | ~54B (no wrapper) | -1B |

Sigma functions themselves get slightly more expensive (MOD operations), but the real win is elsewhere:

**Savings breakdown:**

| Source | Savings |
|--------|---------|
| Message schedule switches to LE additions (48 steps × 60B) | +2,880B |
| Sigma cost increase in message schedule (96 calls × ~7B) | -672B |
| Eliminate reverseBytes4 in K/W fetch (128 × 12B) | +1,536B |
| Eliminate \_emitConvertWordsToLE at block boundaries | +288B |
| **Net** | **~4,032B** |

### Required changes

1. Add OP_LSHIFTNUM / OP_RSHIFTNUM to dartsv interpreter
2. Rewrite σ0, σ1, Σ0, Σ1 to use RSHIFTNUM + MOD + LSHIFTNUM + ADD
3. Switch message schedule from BE to all-LE
4. Store K and W blobs as LE (change `kConstantsBlob` endianness)
5. Remove all reverseBytes4 calls from compression and message schedule
6. Input conversion: 16 BE block words → LE at entry (one-time, 192B)
7. Output conversion: 8 LE result words → BE at exit (one-time, 96B)

---

## Optimization 2: OP_SUBSTR for Blob Extraction

**Estimated savings: ~1.0 KB per block**

### Problem

Extracting a 4-byte word from the W or K blob currently requires 4 opcodes:

```
push offset             // 1-3B
OP_SPLIT                // 1B    — split at offset
OP_NIP                  // 1B    — drop prefix
OP_4, OP_SPLIT          // 2B    — split at 4 bytes
OP_DROP                 // 1B    — drop suffix
                        // Total: 6-8 bytes
```

### Solution

OP_SUBSTR extracts a substring by index and length in one opcode:

```
push offset             // 1-3B
OP_4                    // 1B
OP_SUBSTR               // 1B
                        // Total: 3-5 bytes
```

Savings: ~3 bytes per extraction.

### Extraction count per block

| Context | Extractions |
|---------|-------------|
| Message schedule (σ0 word, σ1 word, W[t-7], W[t-16] × 48 steps) | 192 |
| Compression rounds (K[t] + W[t] × 64 rounds) | 128 |
| **Total** | **320** |

320 extractions × ~3B savings = **~960B**.

### Required changes

1. Add OP_SUBSTR to dartsv interpreter
2. Replace `emitExtractWord` body with SUBSTR-based implementation
3. Replace `emitExtractWordKeep` similarly (DUP + SUBSTR)

---

## Optimization 3: OP_LEFT in truncate32

**Estimated savings: ~420B per block**

### Problem

`truncate32` serializes a number to 5 bytes and takes the lower 4:

```
OP_5, OP_NUM2BIN        // 2B — serialize to 5 bytes
OP_4, OP_SPLIT          // 2B — split at 4
OP_DROP                 // 1B — drop overflow byte
                        // Total: 5 bytes
```

### Solution

OP_LEFT takes the first N bytes directly:

```
OP_5, OP_NUM2BIN        // 2B — serialize to 5 bytes
OP_4, OP_LEFT           // 2B — take first 4 bytes
                        // Total: 4 bytes
```

Savings: 1 byte per call × ~420 calls per block = **~420B**.

### Required changes

1. Add OP_LEFT to dartsv interpreter
2. Update `OpcodeHelpers.truncate32` to use LEFT instead of SPLIT + DROP

---

## Optimization 4: OP_2MUL / OP_2DIV

**Estimated savings: negligible for SHA256**

These save 1 byte over `push 2, OP_MUL` for doubling/halving. SHA256 rotation amounts (2, 3, 6, 7, 10, 11, 13, 14, 17, 18, 19, 22, 25) don't benefit from repeated doubling. May be useful in non-SHA256 parts of the contract (e.g., outpoint verification arithmetic).

---

## Optimization 5: OP_RIGHT

**Estimated savings: negligible for SHA256**

Could replace a few `OP_SPLIT + OP_NIP` patterns, but OP_SUBSTR covers those cases more effectively. May be useful for extracting fixed-size suffixes in the contract wrapper (e.g., last 4 bytes of a preimage field).

---

## Summary

| Optimization | Opcode(s) | Savings/block | Cumulative |
|---|---|---|---|
| Current hand-optimized generator | — | baseline | 30.7 KB |
| All-LE pipeline | LSHIFTNUM, RSHIFTNUM | ~4.0 KB | ~26.7 KB |
| Blob extraction | SUBSTR | ~1.0 KB | ~25.7 KB |
| Truncation | LEFT | ~0.4 KB | ~25.3 KB |
| 2MUL/2DIV, RIGHT | 2MUL, 2DIV, RIGHT | ~0 KB | ~25.3 KB |

**Projected final size: ~25.3 KB per block (~50.6 KB for two blocks)**

This represents a **75% reduction** from the original 100KB sCrypt template and meets the original 25KB/block optimization target.

---

## Implementation Order

1. **Add opcodes to dartsv** — LSHIFTNUM, RSHIFTNUM, SUBSTR, LEFT, RIGHT, 2MUL, 2DIV
2. **OP_SUBSTR + OP_LEFT** — Low-risk, high-confidence savings (~1.4KB). Change `emitExtractWord` and `truncate32`.
3. **All-LE pipeline with LSHIFTNUM/RSHIFTNUM** — Larger refactor (~4KB savings). Rewrite sigma functions, switch message schedule to LE, change blob endianness.
4. **Verify** — Run all 23+ SHA256 tests against dartsv interpreter with new opcodes. Compare output against reference implementation.

---

## Prerequisites

- New opcodes must be added to dartsv's `OpCodes` constants and `Interpreter` switch cases
- dartsv is locally modifiable at `../../dartsv/`
- All existing tests must continue to pass after changes
- Script size assertions should be updated to reflect new targets
