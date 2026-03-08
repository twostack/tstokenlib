# TSL1 Partial SHA256: Hand-Optimization Guide

## 1. Problem Statement

The TSL1 token protocol uses an in-script partial SHA256 computation to verify the Witness transaction's identity and spending relationships. This computation currently compiles to approximately **100KB of Bitcoin Script** via the sCrypt compiler, making it the dominant cost of the entire Token transaction (~110KB total).

The partial SHA256 works by:

1. Precomputing a SHA256 midstate off-chain over all Witness TX data except the last 128 bytes
2. Pushing the 32-byte midstate + 128-byte tail into the Verifier output's scriptSig
3. Completing the SHA256 in-script (two 64-byte block rounds) to produce the Witness txid
4. Checking the txid matches the outpoint spent by the Token TX
5. Parsing the 128-byte tail to extract and verify the Witness's input outpoints

The goal is to reduce the in-script SHA256 from ~100KB to ~25KB through hand-optimization, while keeping the identical TSL1 architecture and security properties.

---

## 2. Root Cause Analysis

Disassembly of the sCrypt-compiled SHA256 code reveals a repeating 158-byte block for each message schedule step. The breakdown per step:

| Component | Bytes | Percentage | Description |
|-----------|-------|------------|-------------|
| σ0 / σ1 computation | 53 | 34% | The actual cryptographic work: shifts, rotations, XORs |
| Byte-reversal | 60 | 38% | Big-endian ↔ little-endian conversion (5 occurrences × 12 bytes) |
| BIN2NUM conversion | 36 | 23% | Converting byte arrays to script number format (4 × 18 bytes, less overlap) |
| Stack cleanup (NIP×8) | 8 | 5% | Removing intermediate values left on stack |
| Addition + truncation | 12 | — | Included above; adding 4 words and truncating to 32 bits |

**Key finding: 66% of the compiled script is format conversion overhead, not cryptographic computation.**

The sCrypt compiler converts between big-endian byte arrays and little-endian script numbers at every type boundary. Since SHA256 uses big-endian words but Bitcoin Script arithmetic is little-endian, the compiler inserts conversion code at every operation boundary. Each conversion involves splitting a 4-byte value into individual bytes, reversing their order via SWAP+CAT, appending a 0x00 sign byte, and calling BIN2NUM.

This conversion pattern is repeated identically in every single round of both the message schedule (48 steps) and the compression function (64 rounds), resulting in massive code duplication.

---

## 3. Optimization Strategy

### 3.1 Principle: Convert Once, Work in Little-Endian

Store all 32-bit words as 4-byte little-endian byte strings throughout the computation. Perform byte-reversal exactly twice total:

- **Input:** Reverse the 16 input words (64 bytes) from big-endian to little-endian once at the start
- **Output:** Reverse the 8 hash state words from little-endian to big-endian once at the end

This eliminates all intermediate byte-reversals. Cost: 24 reversals × 12 bytes = 288 bytes total, versus the current approach which performs reversals hundreds of times.

### 3.2 Principle: Minimize BIN2NUM/NUM2BIN Conversions

The sCrypt compiler treats byte arrays and script numbers as distinct types, inserting conversion code at every boundary. In hand-optimized code, values are kept as 4-byte little-endian byte strings and only converted to script numbers immediately before arithmetic operations (OP_ADD, OP_LSHIFT, OP_RSHIFT), then converted back immediately after.

The conversion to a script number is: `OP_BIN2NUM` (1 byte).
The conversion back to a 4-byte value is: `OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP` (5 bytes).

The 5-byte NUM2BIN followed by splitting to 4 bytes handles 32-bit overflow: additions can produce values up to 33 bits, so we serialize to 5 bytes then truncate.

### 3.3 Principle: Use Altstack for Intermediate Results

Instead of leaving intermediate computation results on the main stack and cleaning up with chains of OP_NIP, stash intermediate results on the altstack with OP_TOALTSTACK and retrieve them with OP_FROMALTSTACK. This eliminates the 8-byte NIP cleanup blocks.

### 3.4 Principle: Pack Constants as Blobs

The 64 SHA256 round constants K[0..63] are stored as a single 256-byte data push. Individual constants are extracted using OP_SPLIT at the appropriate offset:

```
<K_blob> <offset> OP_SPLIT OP_DROP OP_4 OP_SPLIT <remaining> OP_TOALTSTACK
```

This avoids 64 individual 4-byte data pushes with their associated push-length opcodes.

---

## 4. SHA256 Internals Reference

### 4.1 Message Schedule Expansion

For rounds t = 16 to 63, compute:

```
W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
```

Where:

```
σ0(x) = ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)
σ1(x) = ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)
```

And ROTR(n, x) on a 32-bit word is: `(x >> n) | (x << (32 - n))`

### 4.2 Compression Function

For rounds t = 0 to 63, with state variables a, b, c, d, e, f, g, h:

```
Σ1(e)  = ROTR(6, e) XOR ROTR(11, e) XOR ROTR(25, e)
Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]

Σ0(a)  = ROTR(2, a) XOR ROTR(13, a) XOR ROTR(22, a)
Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
T2 = Σ0(a) + Maj(a,b,c)

h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
```

---

## 5. Optimized Script Patterns

### 5.1 ROTR(n, x) — Bitwise Rotation

**Precondition:** x is on top of stack as a script number (via BIN2NUM).

```
OP_DUP <n> OP_RSHIFT          ; x >> n
OP_OVER <32-n> OP_LSHIFT      ; x << (32-n)
OP_OR                          ; combine = ROTR(n, x)
```

Cost: 7 bytes (including the push-data bytes for n and 32-n).

When n ≤ 16, the shift amount fits in OP_1..OP_16 (1 byte each). When n > 16, it requires PUSH_1 + byte (2 bytes). Same for (32-n).

### 5.2 σ0(x) — Message Schedule Sigma-Zero

```
; x is on top of stack as script number
OP_DUP OP_7 OP_RSHIFT                    ; x >> 7
OP_OVER <0x19> OP_LSHIFT                  ; x << 25
OP_OR                                      ; ROTR(7, x)
OP_OVER <0x12> OP_RSHIFT                  ; x >> 18
OP_2 OP_PICK <0x0e> OP_LSHIFT            ; x << 14
OP_OR OP_XOR                              ; ROTR(18, x), XOR with ROTR(7)
OP_SWAP OP_3 OP_RSHIFT                    ; SHR(3, x) — note: SHR not ROTR
OP_XOR                                    ; final XOR → σ0 result
```

Cost: 27 bytes. Consumes x, produces σ0(x).

Note: OP_SWAP before the final SHR(3) moves the original x to the top (consuming the last copy from the OP_OVER/OP_PICK chain) so it can be shifted and XORed without leaving x on the stack.

### 5.3 σ1(x) — Message Schedule Sigma-One

```
; x is on top of stack as script number
OP_DUP <0x11> OP_RSHIFT                  ; x >> 17
OP_OVER <0x0f> OP_LSHIFT                 ; x << 15
OP_OR                                      ; ROTR(17, x)
OP_OVER <0x13> OP_RSHIFT                  ; x >> 19
OP_2 OP_PICK <0x0d> OP_LSHIFT            ; x << 13
OP_OR OP_XOR                              ; ROTR(19, x), XOR with ROTR(17)
OP_SWAP <0x0a> OP_RSHIFT                  ; SHR(10, x)
OP_XOR                                    ; final XOR → σ1 result
```

Cost: 28 bytes.

### 5.4 Σ0(a) — Compression Sigma-Zero

```
; a is on top of stack as script number
OP_DUP OP_2 OP_RSHIFT                    ; a >> 2
OP_OVER <0x1e> OP_LSHIFT                 ; a << 30
OP_OR                                      ; ROTR(2, a)
OP_OVER <0x0d> OP_RSHIFT                 ; a >> 13
OP_2 OP_PICK <0x13> OP_LSHIFT            ; a << 19
OP_OR OP_XOR                              ; ROTR(13, a), XOR
OP_SWAP <0x16> OP_RSHIFT                 ; a >> 22
OP_2 OP_PICK <0x0a> OP_LSHIFT            ; a << 10  ← need original a, use PICK before SWAP consumed it
OP_OR OP_XOR                              ; ROTR(22, a), XOR → Σ0 result
```

Cost: ~30 bytes. Note: the third rotation requires careful stack management since the original value has been consumed by SWAP. An alternative is to OP_DUP the original value at the start and stash a copy.

**Alternative structure (cleaner stack management):**

```
OP_DUP OP_TOALTSTACK                     ; stash copy of a
; compute ROTR(2) XOR ROTR(13) as in σ0 pattern
OP_DUP OP_2 OP_RSHIFT
OP_OVER <0x1e> OP_LSHIFT
OP_OR
OP_OVER <0x0d> OP_RSHIFT
OP_2 OP_PICK <0x13> OP_LSHIFT
OP_OR OP_XOR
OP_SWAP OP_DROP                           ; remove consumed a
OP_FROMALTSTACK                           ; recover original a
OP_DUP <0x16> OP_RSHIFT
OP_OVER <0x0a> OP_LSHIFT
OP_OR                                      ; ROTR(22, a)
OP_SWAP OP_DROP                           ; remove a
OP_XOR                                    ; final XOR → Σ0 result
```

Cost: ~33 bytes. Trades 3 extra bytes for clearer stack state.

### 5.5 Σ1(e) — Compression Sigma-One

Same pattern as Σ0 with rotation amounts 6, 11, 25.

```
OP_DUP OP_TOALTSTACK
OP_DUP OP_6 OP_RSHIFT
OP_OVER <0x1a> OP_LSHIFT
OP_OR
OP_OVER <0x0b> OP_RSHIFT
OP_2 OP_PICK <0x15> OP_LSHIFT
OP_OR OP_XOR
OP_SWAP OP_DROP
OP_FROMALTSTACK
OP_DUP <0x19> OP_RSHIFT
OP_OVER OP_7 OP_LSHIFT
OP_OR
OP_SWAP OP_DROP
OP_XOR
```

Cost: ~33 bytes.

### 5.6 Ch(e, f, g) — Choice Function

```
; Stack: ... g f e  (e on top)
OP_DUP OP_ROT                            ; ... g e e f
OP_AND                                    ; ... g e (e AND f)
OP_SWAP OP_INVERT                         ; ... g (e AND f) (NOT e)
OP_ROT                                    ; ... (e AND f) (NOT e) g
OP_AND                                    ; ... (e AND f) ((NOT e) AND g)
OP_XOR                                    ; ... Ch(e,f,g)
```

Cost: 7 bytes.

Note: OP_INVERT on BSV performs bitwise NOT. For 32-bit values stored as 4-byte little-endian, this works correctly. Ensure values are 4 bytes exactly (pad if needed after BIN2NUM).

### 5.7 Maj(a, b, c) — Majority Function

```
; Stack: ... c b a  (a on top)
OP_2 OP_PICK                              ; ... c b a b
OP_OVER                                   ; ... c b a b a
OP_AND                                    ; ... c b a (a AND b)
OP_SWAP                                   ; ... c b (a AND b) a
OP_2 OP_PICK                              ; ... c b (a AND b) a c  [note: c is now at index 4]
OP_AND                                    ; ... c b (a AND b) (a AND c)
OP_XOR                                    ; ... c b ((a AND b) XOR (a AND c))
OP_SWAP OP_ROT                            ; ... ((a AND b) XOR (a AND c)) c b  [reorder to get b,c adjacent]
OP_AND                                    ; ... ((a AND b) XOR (a AND c)) (b AND c)
OP_XOR                                    ; ... Maj(a,b,c)
```

Cost: 11 bytes.

Alternative using the identity `Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)`.

### 5.8 32-bit Addition with Truncation

Adding two 32-bit values and truncating to 32 bits:

```
; Stack: ... x y  (both as script numbers via BIN2NUM)
OP_ADD                                    ; x + y (may be up to 33 bits)
OP_5 OP_NUM2BIN                           ; serialize to 5 bytes
OP_4 OP_SPLIT                             ; split: 4 bytes (result) + 1 byte (overflow)
OP_DROP                                   ; discard overflow byte
```

Cost: 5 bytes per addition.

For chained additions (e.g., T1 = h + Σ1 + Ch + K + W):

```
OP_ADD OP_ADD OP_ADD OP_ADD               ; 4 additions
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP    ; truncate once at end
```

Cost: 4 + 5 = 9 bytes for summing 5 values.

Note: intermediate sums can exceed 32 bits, but Bitcoin Script integers can handle up to ~2^31 natively and larger with explicit byte handling. For safety, truncate after every 2 additions if overflow is a concern, or work with 5-byte representations throughout the addition chain.

### 5.9 Byte-Reversal (Big-Endian ↔ Little-Endian)

Used only at input and output, never internally:

```
; 4-byte value on top of stack (big-endian)
OP_1 OP_SPLIT                             ; byte0 | bytes1-3
OP_1 OP_SPLIT                             ; byte0 | byte1 | bytes2-3
OP_1 OP_SPLIT                             ; byte0 | byte1 | byte2 | byte3
OP_SWAP OP_CAT                            ; byte0 | byte1 | byte3byte2
OP_SWAP OP_CAT                            ; byte0 | byte3byte2byte1
OP_SWAP OP_CAT                            ; byte3byte2byte1byte0 (little-endian)
```

Cost: 12 bytes per word. Used 16 times at input + 8 times at output = 288 bytes total for the entire SHA256 computation.

---

## 6. Optimized Message Schedule Step

Each step computes `W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]`.

The stack holds W[0]..W[15] as 4-byte little-endian byte strings, with W[15] on top (index 0). The sliding window replaces W[0] (the oldest, at index 15) with the new W[t] each step.

```
; --- Compute σ0(W[t-15]) ---
OP_15 OP_PICK                             ; get W[t-15] (index 14 = second from bottom)
OP_BIN2NUM                                ; convert to script number
; [σ0 computation as in section 5.2: 27 bytes]
OP_TOALTSTACK                             ; stash σ0 result

; --- Compute σ1(W[t-2]) ---
OP_1 OP_PICK                              ; get W[t-2] (index 1 = second from top)
OP_BIN2NUM                                ; convert to script number
; [σ1 computation as in section 5.3: 28 bytes]

; --- Sum all four components ---
OP_8 OP_PICK OP_BIN2NUM                   ; get W[t-7], convert
OP_ADD                                    ; σ1 + W[t-7]
OP_FROMALTSTACK                           ; retrieve σ0
OP_ADD                                    ; + σ0
OP_15 OP_PICK OP_BIN2NUM                  ; get W[t-16], convert
OP_ADD                                    ; + W[t-16] = W[t]
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP    ; truncate to 32 bits

; --- Update sliding window ---
OP_16 OP_ROLL OP_DROP                     ; remove oldest word (W[t-16]) from bottom
; W[t] is now on top, window is W[t-15]..W[t]
```

**Total per step: 73 bytes** (vs 158 bytes in sCrypt-compiled version).

This step is repeated identically 48 times (for t = 16 to 63), contributing 3,504 bytes total.

---

## 7. Optimized Compression Round

Each of the 64 rounds processes the 8 state variables (a..h) with one message word W[t] and one round constant K[t].

### 7.1 State Variable Layout

State variables a..h are kept as 8 separate 4-byte little-endian byte strings on the stack. For the compression function, the message schedule words W[0..63] should be accessible — either kept on the altstack or packed as a blob.

**Recommended layout:**

- Main stack: h g f e d c b a (a on top, h deepest)
- Altstack or blob: W[0..63], K[0..63]

Alternatively, store state as a packed 32-byte blob and extract via OP_SPLIT. This trades per-access extraction cost against the deep OP_PICK cost of 8-deep stack access.

### 7.2 Compression Round Script

```
; Stack: h g f e d c b a  (a on top)
; K[t] and W[t] available (fetched from blob or altstack)

; --- Compute Σ1(e) ---
OP_3 OP_PICK OP_BIN2NUM                   ; get e (index 3), to number
; [Σ1 computation: ~33 bytes, result on stack]
OP_TOALTSTACK                             ; stash Σ1(e)

; --- Compute Ch(e, f, g) ---
OP_5 OP_PICK                              ; g
OP_5 OP_PICK                              ; f
OP_5 OP_PICK                              ; e
OP_BIN2NUM OP_SWAP OP_BIN2NUM OP_SWAP     ; convert e, f to numbers
OP_ROT OP_BIN2NUM OP_ROT                  ; convert g to number, reorder
; [Ch computation: 7 bytes]

; --- Compute T1 = h + Σ1(e) + Ch + K[t] + W[t] ---
OP_7 OP_PICK OP_BIN2NUM                   ; get h, to number
OP_FROMALTSTACK                            ; get Σ1(e)
OP_ADD                                     ; h + Σ1
OP_ADD                                     ; + Ch
<fetch K[t]> OP_BIN2NUM OP_ADD            ; + K[t]
<fetch W[t]> OP_BIN2NUM OP_ADD            ; + W[t]
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP    ; truncate T1 to 32 bits
OP_TOALTSTACK                             ; stash T1

; --- Compute Σ0(a) ---
OP_DUP OP_BIN2NUM                         ; a is on top, convert to number
; [Σ0 computation: ~33 bytes]
OP_TOALTSTACK                             ; stash Σ0(a)

; --- Compute Maj(a, b, c) ---
OP_2 OP_PICK OP_BIN2NUM                   ; c
OP_2 OP_PICK OP_BIN2NUM                   ; b
OP_2 OP_PICK OP_BIN2NUM                   ; a
; [Maj computation: 11 bytes]

; --- Compute T2 = Σ0(a) + Maj ---
OP_FROMALTSTACK                           ; get Σ0(a)
OP_ADD                                    ; Σ0 + Maj
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP   ; truncate T2

; --- State rotation ---
; Current stack: h g f e d c b a T2
; Need:          new_h new_g new_f new_e new_d new_c new_b new_a
; Where: new_a=T1+T2, new_b=a, new_c=b, new_d=c, new_e=d+T1, new_f=e, new_g=f, new_h=g

OP_FROMALTSTACK                           ; get T1
OP_DUP OP_ROT OP_ADD                      ; T2 is below T1 → compute T1+T2 = new_a
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP   ; truncate new_a

; Now need to compute new_e = d + T1 and rearrange:
; [state rearrangement: ~15-20 bytes of ROLL/SWAP operations]
; Drop old h, shift g→h, f→g, e→f, insert new_e, shift d→skip, c→d, b→c, a→b, push new_a
```

**Estimated per round: ~125 bytes.**

The exact byte count depends on the state variable access strategy (individual stack items vs packed blob) and the K[t]/W[t] fetch mechanism. The estimate of 125 bytes per round is based on individual stack items with OP_PICK for access.

### 7.3 Fetching K[t] from Constant Blob

The 64 round constants are stored as a single 256-byte push at the beginning of the script and kept on the altstack or at a known stack position:

```
; K_blob is on stack, t is the round index
; Extract K[t] (4 bytes at offset t*4)
OP_DUP                                    ; duplicate blob
<t*4> OP_SPLIT                            ; left | right
OP_SWAP OP_DROP                           ; right (from offset t*4 onwards)
OP_4 OP_SPLIT                             ; K[t] | remainder
OP_SWAP OP_DROP                           ; K[t] only
```

Cost: ~8 bytes per fetch. Since t is unrolled (each round is inline), the offset is a literal.

In practice, for rounds where `t*4 ≤ 16`, the offset fits in OP_1..OP_16 (1 byte). For larger offsets, it requires a 2-byte push (PUSH_1 + byte). Maximum offset is 63×4 = 252, which fits in one byte.

---

## 8. Complete Cost Estimate

### 8.1 Per-Block Costs

| Component | Calculation | Bytes |
|-----------|------------|-------|
| Input byte-reversal | 16 words × 12 bytes | 192 |
| Message schedule | 48 steps × 73 bytes | 3,504 |
| K constants blob | 64 × 4 bytes + push overhead | 260 |
| Compression rounds | 64 rounds × 125 bytes | 8,000 |
| Initial hash state | 8 × 4 bytes + setup | 100 |
| Final state addition | 8 additions + truncation + reversal | 200 |
| **Total per block** | | **~12,250** |

### 8.2 Two-Block Partial SHA256 (TSL1 Requirement)

| Component | Bytes | KB |
|-----------|-------|----|
| First SHA256 block | 12,250 | 12.0 |
| Second SHA256 block | 12,250 | 12.0 |
| Double-hash wrapper (SHA256 of SHA256) | ~200 | 0.2 |
| Txid comparison + outpoint verification | ~100 | 0.1 |
| **Total partial SHA256** | **~24,800** | **~24.3** |

### 8.3 Comparison

| Version | Size | Reduction |
|---------|------|-----------|
| Current sCrypt-compiled | ~100 KB | — |
| Hand-optimized (current opcodes) | ~25 KB | 75% |
| Hand-optimized + Chronicle OP_SUBSTR | ~18-20 KB | 80-82% |

---

## 9. Implementation Notes

### 9.1 Endianness Convention

SHA256 is specified in big-endian. Bitcoin Script arithmetic is little-endian. The hand-optimized implementation works entirely in little-endian internally:

- **Input:** The 64-byte message block arrives as big-endian bytes. Reverse each 4-byte word once (16 × 12 = 192 bytes of script). All subsequent operations treat words as little-endian.
- **OP_LSHIFT / OP_RSHIFT:** These operate on the script number representation, which is little-endian. The shift amounts remain the same regardless of endianness because we're shifting the numeric value, not the byte representation.
- **OP_AND / OP_OR / OP_XOR:** These are bitwise on byte vectors. For multi-byte values, ensure both operands are the same length (4 bytes). Pad with OP_NUM2BIN if needed after arithmetic.
- **Output:** The final 8 hash state words are reversed back to big-endian before concatenation into the 32-byte hash.

### 9.2 Handling OP_LSHIFT/OP_RSHIFT with BIN2NUM

OP_LSHIFT and OP_RSHIFT on BSV operate on script numbers. A 4-byte little-endian byte string must be converted to a script number via OP_BIN2NUM before shifting. After the shift-OR-XOR pattern of a rotation, the result is a script number. It must be converted back to a 4-byte byte string for storage:

```
; After rotation, result is a script number on stack
OP_4 OP_NUM2BIN                           ; convert to 4-byte LE byte string
```

However, if the rotation result feeds immediately into another arithmetic operation (e.g., addition), keep it as a script number and skip the conversion.

### 9.3 OP_INVERT Behavior

OP_INVERT flips all bits in a byte vector. For the Ch function's `(NOT e) AND g`, ensure both operands are exactly 4 bytes. After OP_BIN2NUM, a value like 0x00000000 becomes an empty byte vector. Use OP_4 OP_NUM2BIN before OP_INVERT to guarantee 4-byte length.

### 9.4 32-bit Overflow in Addition Chains

When summing multiple 32-bit values (e.g., T1 = h + Σ1 + Ch + K + W), intermediate sums can exceed 32 bits. Bitcoin Script integers are nominally limited to 4 bytes (signed 31-bit), but BSV has restored large number support. Nevertheless, truncation after every 2 additions is safest:

```
OP_ADD OP_ADD                             ; sum of 3 values (max ~33 bits)
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP   ; truncate
OP_BIN2NUM                                ; back to number for next additions
OP_ADD OP_ADD                             ; add 2 more
OP_5 OP_NUM2BIN OP_4 OP_SPLIT OP_DROP   ; final truncate
```

This costs an extra 6 bytes per T1 computation but ensures correctness. Profile against the alternative of summing all 5 values and truncating once.

### 9.5 Script Size vs Stack Depth Tradeoff

The message schedule maintains a 16-word sliding window. With individual stack items, the deepest access is OP_15 OP_PICK (2 bytes). With a packed 64-byte blob, each access requires OP_DUP + offset + OP_SPLIT + OP_4 OP_SPLIT + cleanup (~8 bytes), but the stack only has 1 item instead of 16, simplifying state management.

For the message schedule, individual stack items are likely more efficient since accesses are frequent and the window is only 16 deep. For the compression function's 8 state variables, the tradeoff is closer — measure both approaches.

### 9.6 Chronicle Opcodes (Future Optimization)

When OP_SUBSTR, OP_LEFT, OP_RIGHT become available:

- **Blob extraction:** `<blob> <offset> <length> OP_SUBSTR` replaces the SPLIT-SPLIT-DROP pattern, saving ~3 bytes per extraction
- **Word update in blob:** Extract left portion, skip old word, extract right portion, insert new word, concatenate — OP_LEFT and OP_RIGHT make this more direct
- **Estimated additional savings:** 5-7 KB reduction from the hand-optimized baseline, bringing total to ~18-20 KB

---

## 10. Validation Approach

### 10.1 Test Vectors

Use NIST SHA256 test vectors to validate the hand-optimized implementation. Test with the specific partial-hash scenario used in TSL1:

1. Compute SHA256 midstate for a known message prefix using an off-chain SHA256 implementation
2. Provide midstate + remaining bytes to the in-script implementation
3. Verify the output matches the expected full SHA256 hash

### 10.2 Step-by-Step Verification

Since the implementation is unrolled (no loops in Bitcoin Script), each round can be verified independently:

1. Compute the expected state after each message schedule step off-chain
2. Insert OP_VERIFY checks at round boundaries during testing
3. Remove verification opcodes for production deployment

### 10.3 Integration Testing

Test within the full TSL1 Verifier output context:

1. Construct a Witness TX with known structure
2. Compute the partial SHA256 midstate off-chain
3. Verify the in-script completion produces the correct Witness txid
4. Verify the outpoint extraction from the 128-byte tail matches expected values
