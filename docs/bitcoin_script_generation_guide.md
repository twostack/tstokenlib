# Hand-Optimized Bitcoin Script Generation with Dart

## A Guide for LLM Coding Agents

This guide teaches how to generate optimized Bitcoin Script programmatically using Dart and the `dartsv` library's `ScriptBuilder`. The technique replaces large compiled sCrypt templates with more compact, hand-optimized scripts while maintaining identical on-chain behavior.

The approach was developed for BSV (Bitcoin SV), which restored the full original Bitcoin opcode set after the Genesis upgrade, including `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT`, `OP_CAT`, `OP_SPLIT`, and others.

---

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [ScriptBuilder API](#scriptbuilder-api)
3. [Common Idioms and Patterns](#common-idioms-and-patterns)
4. [Stack and Altstack Management](#stack-and-altstack-management)
5. [Numeric Encoding and Endianness](#numeric-encoding-and-endianness)
6. [Composing Complex Scripts](#composing-complex-scripts)
7. [Testing with the dartsv Interpreter](#testing-with-the-dartsv-interpreter)
8. [Debugging Techniques](#debugging-techniques)
9. [Worked Example: 4-Byte Endian Reversal](#worked-example-4-byte-endian-reversal)
10. [BSV Opcode Reference](#bsv-opcode-reference)

---

## Core Concepts

### What is Bitcoin Script?

Bitcoin Script is a stack-based, Forth-like language embedded in every Bitcoin transaction. Each UTXO (unspent transaction output) has a **locking script** (scriptPubKey) that defines the spending conditions. To spend it, a transaction provides an **unlocking script** (scriptSig) whose data, combined with the locking script, must leave `TRUE` on the stack.

### Why Generate Script Programmatically?

High-level languages like sCrypt compile to Bitcoin Script but produce verbose output. Hand-optimization allows:
- **Smaller scripts**: 30-40% size reduction by eliminating compiler overhead
- **No compilation step**: scripts are generated at runtime in Dart
- **Precise control**: exact stack layout, optimal opcode sequences
- **Dynamic parameterization**: constructor params embedded at known byte offsets

### The Technique

Instead of compiling sCrypt source to a hex template and doing string replacement, we build the script opcode-by-opcode using `ScriptBuilder`:

```dart
var b = ScriptBuilder();
b.addData(Uint8List.fromList(ownerPKH));  // push 20-byte data
b.opCode(OpCodes.OP_HASH160);            // hash the top stack item
b.opCode(OpCodes.OP_EQUALVERIFY);        // verify equality
b.opCode(OpCodes.OP_CHECKSIG);           // check signature
var script = b.build();                   // → SVScript
```

This produces the same bytecode as a compiled P2PKH script, but is readable, testable, and composable in Dart.

---

## ScriptBuilder API

### Key Methods

| Method | Purpose | Example |
|--------|---------|---------|
| `opCode(int)` | Push a single opcode | `b.opCode(OpCodes.OP_DUP)` |
| `addData(Uint8List)` | Push raw bytes with correct pushdata encoding | `b.addData(Uint8List.fromList([0x01, 0x02]))` |
| `smallNum(int)` | Push 0-16 as OP_0..OP_16 (1 byte each) | `b.smallNum(5)` → `OP_5` |
| `number(int)` | Push any integer with minimal encoding | `b.number(1000)` |
| `build()` | Finalize to `SVScript` | `var script = b.build()` |

### Important: addData Gotcha

`ScriptBuilder.addData()` in dartsv has a quirk: single-byte values 1-16 get mapped to `OP_N` opcodes. If you need the literal byte `0x02` as data (not as `OP_2`), use `smallNum(2)` instead, which correctly creates a `ScriptChunk(null, 0, OP_2)`. Using `addData(Uint8List.fromList([0x02]))` creates a chunk with both a buffer and an OP_N opcode, which causes an `IllegalArgumentException` during serialization.

```dart
// WRONG — will throw during build():
b.addData(Uint8List.fromList([0x02]));

// CORRECT — produces OP_2 (0x52):
b.smallNum(2);
```

### Composable Functions

Structure your generators as static methods that accept and return `ScriptBuilder`:

```dart
static ScriptBuilder reverseBytes4(ScriptBuilder b) {
  return b
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT);
}
```

This allows chaining: `reverseBytes4(truncate32(b))`.

---

## Common Idioms and Patterns

### Pushing Integer Values

Script numbers are little-endian with a sign bit in the MSB of the last byte. Values > 127 need care:

```dart
static ScriptBuilder pushInt(ScriptBuilder b, int value) {
  if (value >= 0 && value <= 16) {
    return b.smallNum(value);  // OP_0..OP_16 (1 byte)
  }
  // Encode as minimal LE byte array with positive sign
  var bytes = <int>[];
  int v = value;
  while (v > 0) {
    bytes.add(v & 0xFF);
    v >>= 8;
  }
  // If high bit set, append 0x00 to keep number positive
  if (bytes.last & 0x80 != 0) {
    bytes.add(0x00);
  }
  return b.addData(Uint8List.fromList(bytes));
}
```

### Truncate to 32 Bits

After arithmetic, results may exceed 4 bytes. Truncate:

```dart
// Stack: [value(script number)] → [value(4-byte LE)]
static ScriptBuilder truncate32(ScriptBuilder b) {
  return b
    .opCode(OpCodes.OP_5).opCode(OpCodes.OP_NUM2BIN)  // serialize to 5 bytes
    .opCode(OpCodes.OP_4).opCode(OpCodes.OP_SPLIT)     // split at byte 4
    .opCode(OpCodes.OP_DROP);                           // drop overflow byte
}
```

### Convert Between Byte Strings and Numbers

```dart
// 4-byte LE → script number
b.opCode(OpCodes.OP_BIN2NUM);       // 1 byte

// Script number → 4-byte LE
b.opCode(OpCodes.OP_4);
b.opCode(OpCodes.OP_NUM2BIN);       // 2 bytes
```

### Extract Bytes from a Blob

Use `OP_SPLIT` to slice at offsets:

```dart
// Stack: [blob] → [bytes_at_offset(4 bytes)]
pushInt(b, offset + 4);
b.opCode(OpCodes.OP_SPLIT);     // [left(offset+4), right]
b.opCode(OpCodes.OP_DROP);      // [left(offset+4)]
pushInt(b, offset);
b.opCode(OpCodes.OP_SPLIT);     // [prefix(offset), target(4B)]
b.opCode(OpCodes.OP_NIP);       // [target(4B)]
```

To preserve the blob, `OP_DUP` it first.

### Unsigned 32-bit Values

Values with bit 31 set (e.g., `0xFFFFFFFF`) become negative script numbers. Handle by appending a `0x00` sign byte after converting to LE:

```dart
// Stack: [value(4B BE)] → [unsigned_script_number]
reverseBytes4(b);                           // BE → LE
b.addData(Uint8List.fromList([0x00]));      // append positive sign byte
b.opCode(OpCodes.OP_CAT);                  // 5-byte LE
b.opCode(OpCodes.OP_BIN2NUM);              // unsigned number
```

This mirrors sCrypt's `unpack(reverseBytes(a, 4) + b'00')` pattern.

---

## Stack and Altstack Management

### The Main Stack

Bitcoin Script uses a single evaluation stack. Operations consume and produce items from the top. The key challenge is managing item positions when you need values deep in the stack.

**Item Access:**
- `OP_DUP` — copy top item
- `OP_OVER` — copy second item to top
- `OP_PICK` — copy item N deep to top (0-indexed from top)
- `OP_ROLL` — move item N deep to top (removes from original position)
- `OP_SWAP` — swap top two items
- `OP_ROT` — rotate top three items left

**Critical Rule: PICK/ROLL indices shift when items are pushed.**
If you push a value between two PICK operations, subsequent PICK indices increase by 1:

```
Stack: [a, b, c]     — c is at index 0, b at 1, a at 2
Push x: [a, b, c, x] — now c is at index 1, b at 2, a at 3
```

### The Altstack

The altstack is a secondary stack accessed via `OP_TOALTSTACK` and `OP_FROMALTSTACK`. It has **LIFO** (last-in-first-out) semantics.

**Use cases:**
- Temporary storage during complex computations
- Order reversal (push N items, pop in reverse)
- Stashing values when main stack is too deep for PICK

**Critical Rule: LIFO reverses order.**
If you push A, B, C to altstack, you get C, B, A back:

```dart
// Push: A(bottom), B, C(top) → altstack
b.opCode(OpCodes.OP_TOALTSTACK);  // pushes C
b.opCode(OpCodes.OP_TOALTSTACK);  // pushes B
b.opCode(OpCodes.OP_TOALTSTACK);  // pushes A

// Pop: A(first), B, C(last) — reversed!
b.opCode(OpCodes.OP_FROMALTSTACK);  // gets A
b.opCode(OpCodes.OP_FROMALTSTACK);  // gets B
b.opCode(OpCodes.OP_FROMALTSTACK);  // gets C
```

**Always document altstack state.** Use comments at function boundaries:

```dart
/// Pre:  Stack: [preImage, partialHash, witnessPreImage]
///       Altstack: [fundingTxId]
/// Post: Stack: [witnessHash(32B)]
///       Altstack: [fundingTxId, witnessPartialOutpoint, preImage]
```

### Zero Net Altstack Effect

Design functions with zero net altstack impact when possible. `emitOneBlock` temporarily uses 3 altstack slots (midstate copy, W blob, K blob) but pops all three before returning. This makes composition predictable.

---

## Numeric Encoding and Endianness

### Script Number Format

Bitcoin Script numbers are:
- **Little-endian** byte order
- **Variable length** (minimal encoding)
- **Sign bit** in MSB of last byte (0x80 = negative)

Examples:
| Value | Script Number Bytes |
|-------|-------------------|
| 0 | `[]` (empty) or OP_0 |
| 1 | OP_1 (single opcode) |
| 127 | `[0x7F]` |
| 128 | `[0x80, 0x00]` (need sign byte) |
| 255 | `[0xFF, 0x00]` |
| -1 | `[0x81]` (0x01 with sign bit set) |
| 256 | `[0x00, 0x01]` |

### Endianness in SHA256

SHA256 operates on 32-bit big-endian words. BSV's `OP_LSHIFT`/`OP_RSHIFT` also operate on big-endian byte arrays. This is convenient — SHA256 rotations work natively in BE.

However, arithmetic (`OP_ADD`, `OP_MUL`) requires script numbers, which are LE. The conversion pattern is:

```
BE word → reverseBytes4 → LE bytes → [0x00] CAT → BIN2NUM → script number
  (do arithmetic)
script number → truncate32 → LE word → reverseBytes4 → BE word
```

**Optimization:** Keep intermediate state as LE words when multiple arithmetic operations are needed. This saves 12 bytes per conversion (reverseBytes4 costs 12 bytes, but can be skipped if already LE).

---

## Composing Complex Scripts

### Function Selector Pattern

Implement multiple contract functions in a single script using a selector:

```dart
static SVScript generate({required List<int> ownerPKH}) {
  var b = ScriptBuilder();

  // Push constructor params (for parseability)
  b.addData(Uint8List.fromList(ownerPKH));

  // Selector from scriptSig is on top of stack
  b.opCode(OpCodes.OP_SWAP);    // [ownerPKH, selector] → [selector, ownerPKH]... wait
  // Actually: [args..., selector, ownerPKH] → [args..., ownerPKH, selector]
  b.opCode(OpCodes.OP_NOTIF);   // selector=OP_0 (falsy) → path A

  _emitPathA(b);

  b.opCode(OpCodes.OP_ELSE);    // selector=OP_1 (truthy) → path B

  _emitPathB(b);

  b.opCode(OpCodes.OP_ENDIF);
  return b.build();
}
```

The unlock script pushes the selector as the last item:
```dart
result.addData(preImage);
result.addData(fundingTxId);
result.opCode(OpCodes.OP_0);    // selector for path A
```

### Conditional Block Processing

Handle variable-length inputs using `OP_IF`:

```dart
// Process 1 or 2 SHA256 blocks based on data size
b.opCode(OpCodes.OP_DUP);
b.opCode(OpCodes.OP_SIZE);
b.opCode(OpCodes.OP_NIP);      // [data, size]

b.opCode(OpCodes.OP_IF);       // size > 0
  _emitProcessBlock(b);        // process second block
b.opCode(OpCodes.OP_ELSE);
  b.opCode(OpCodes.OP_DROP);   // drop empty data
b.opCode(OpCodes.OP_ENDIF);
```

### Constructor Params at Known Offsets

Place substitutable parameters at the start of the script:

```dart
b.addData(Uint8List.fromList(ownerPKH));  // byte 0: 0x14, bytes 1-20: PKH
// byte 21+: script body (never changes)
```

This allows parent contracts to rebuild child scripts by slicing and substituting:
```scrypt
// In sCrypt parent contract:
bytes rebuiltScript = parentScript[:1] + newPKH + parentScript[21:];
```

---

## Testing with the dartsv Interpreter

### Test Setup

The dartsv library includes a full Bitcoin Script interpreter. Testing requires constructing a minimal transaction context:

```dart
import 'package:dartsv/dartsv.dart';

Transaction _createDummyTx(SVScript scriptSig) {
  var fundingTx = Transaction();
  fundingTx.version = 1;
  fundingTx.addOutput(TransactionOutput(BigInt.from(1000), SVScript()));

  var spendingTx = Transaction();
  spendingTx.version = 1;
  spendingTx.addInput(TransactionInput(
    fundingTx.hash.toString(),
    0,
    scriptSig,
    TransactionInput.MAX_SEQ_NUMBER,
  ));
  spendingTx.addOutput(TransactionOutput(BigInt.from(999), SVScript()));

  return spendingTx;
}
```

### The Core Test Pattern

```dart
void _verifyScript(SVScript scriptSig, SVScript scriptPubKey) {
  var tx = _createDummyTx(scriptSig);
  var interp = Interpreter();
  interp.correctlySpends(
    scriptSig,
    scriptPubKey,
    tx,
    0,                                    // input index
    {VerifyFlag.UTXO_AFTER_GENESIS},      // enable all restored opcodes
    Coin.valueOf(BigInt.from(1000)),       // UTXO value
  );
}
```

`correctlySpends` throws a `ScriptException` if verification fails. Use `expect(() => ..., returnsNormally)` in tests.

### Writing Unit Tests

**Pattern: Operation + Expected Result + OP_EQUALVERIFY + OP_1**

```dart
test('reverseBytes4 swaps endianness', () {
  // Unlock script: push input
  var unlock = ScriptBuilder();
  unlock.addData(Uint8List.fromList([0x01, 0x02, 0x03, 0x04]));

  // Lock script: operation + verify result
  var lock = ScriptBuilder();
  OpcodeHelpers.reverseBytes4(lock);
  lock.addData(Uint8List.fromList([0x04, 0x03, 0x02, 0x01]));  // expected
  lock.opCode(OpCodes.OP_EQUALVERIFY);
  lock.opCode(OpCodes.OP_1);  // leave TRUE on stack

  _verifyScript(unlock.build(), lock.build());
});
```

### Testing Multi-Step Operations

For complex operations (like SHA256 compression), verify against a reference implementation:

```dart
test('emitOneBlock matches reference SHA256', () {
  var block = Uint8List(64);
  // SHA256 padding for empty message
  block[0] = 0x80;
  block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
  block[60] = 0; block[61] = 0; block[62] = 0; block[63] = 0;

  var initHash = PartialSha256.STD_INIT_VECTOR;  // reference IV

  // Build unlock: push midstate(32B) + block(64B)
  var unlock = ScriptBuilder();
  unlock.addData(Uint8List.fromList(initHash));   // midstate below
  unlock.addData(Uint8List.fromList(block));       // block on top

  // Build lock: compute + compare
  var lock = ScriptBuilder();
  Sha256ScriptGen.emitOneBlock(lock);

  // Expected: SHA256("") hash
  var expected = hex.decode(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  lock.addData(Uint8List.fromList(expected));
  lock.opCode(OpCodes.OP_EQUALVERIFY);
  lock.opCode(OpCodes.OP_1);

  _verifyScript(unlock.build(), lock.build());
});
```

### Testing Real Contract Spending

For full integration tests, build actual token transactions:

```dart
test('PP3 burn spending verifies', () {
  // 1. Build a real token transaction with PP3 output
  var mintTx = await service.createFungibleMintTxn(...);

  // 2. Build a burn transaction that spends PP3
  var burnTx = service.createFungibleBurnTxn(mintTx, ...);

  // 3. Verify PP3 spending through the interpreter
  var interp = Interpreter();
  var verifyFlags = {
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  expect(
    () => interp.correctlySpends(
      burnTx.inputs[3].script!,       // scriptSig (PP3 burn unlock)
      mintTx.outputs[3].script,       // scriptPubKey (PP3 lock)
      burnTx,
      3,                               // input index
      verifyFlags,
      Coin.valueOf(mintTx.outputs[3].satoshis),
    ),
    returnsNormally,
  );
});
```

---

## Debugging Techniques

### 1. Enhanced Error Messages in dartsv

Modify `dartsv`'s interpreter to show hex values on `EQUALVERIFY` failures. In `lib/src/exceptions.dart`, add `toString()` to `ScriptException`. In the interpreter's `OP_EQUALVERIFY` handler, include the hex of both values:

```
ScriptException(SCRIPT_ERR_EQUALVERIFY): OpCodes.OP_EQUALVERIFY: non-equal data
  got:      a1b2c3d4 (4B)
  expected: d4c3b2a1 (4B)
  stack remaining: 3 items
```

This immediately shows endianness mismatches, truncation issues, and offset errors.

### 2. Incremental Build-and-Test

Don't write the entire script and then test. Build incrementally:

1. Start with the simplest possible script that does one thing
2. Test it
3. Add the next operation
4. Test again
5. Repeat

When a test fails, the bug is in the most recently added code.

### 3. Isolate Sections

If a large script fails, isolate the failing section by building a minimal test that exercises just that part:

```dart
// Instead of testing the full 62KB witness check script,
// test just the DER encoding section:
test('DER encoding produces valid signature', () {
  var unlock = ScriptBuilder();
  unlock.addData(someTestSValue);  // push test s value

  var lock = ScriptBuilder();
  WitnessCheckScriptGen._emitDerEncode(lock);
  // ... verify result
});
```

### 4. Stack Depth Tracking

When debugging complex scripts, count stack items at each step. Add comments:

```dart
// Stack: [partialHash, witnessPreImage]
b.opCode(OpCodes.OP_DUP);
// Stack: [partialHash, witnessPreImage, witnessPreImage]
pushInt(b, 36);
// Stack: [partialHash, witnessPreImage, witnessPreImage, 36]
b.opCode(OpCodes.OP_SPLIT);
// Stack: [partialHash, witnessPreImage, first36, rest]
```

### 5. Print Script Hex

Inspect the generated script hex to verify structure:

```dart
var script = b.build();
print('Script hex: ${script.toHex()}');
print('Script length: ${script.toHex().length ~/ 2} bytes');
print('Chunks: ${script.chunks.length}');
```

### 6. Diff Two Generated Scripts

To find where a parameterized script changes, generate two variants and compare:

```dart
var script2 = generate(ownerPKH: pkh, pp2OutputIndex: 2);
var script5 = generate(ownerPKH: pkh, pp2OutputIndex: 5);
var hex2 = script2.toHex();
var hex5 = script5.toHex();

for (var i = 0; i < hex2.length; i += 2) {
  if (hex2.substring(i, i+2) != hex5.substring(i, i+2)) {
    print('Diff at byte ${i~/2}: ${hex2.substring(i,i+2)} vs ${hex5.substring(i,i+2)}');
  }
}
```

### 7. Common Failure Modes

| Error | Likely Cause |
|-------|-------------|
| `SCRIPT_ERR_EQUALVERIFY` with reversed bytes | Endianness mismatch (BE vs LE) |
| `SCRIPT_ERR_EQUALVERIFY` with offset data | Wrong SPLIT position or PICK index |
| `SCRIPT_ERR_INVALID_STACK_OPERATION` | Stack underflow — consumed an item you needed |
| `SCRIPT_ERR_SIG_DER` | DER encoding error, or `[sig, pubKey]` in wrong order |
| `SCRIPT_ERR_EVAL_FALSE` | Script completed but left FALSE/empty on stack |
| `IllegalArgumentException` in `build()` | `addData` with single-byte 1-16 (use `smallNum` instead) |
| Negative number where positive expected | Bit 31 set without 0x00 sign byte |

### 8. Verify Flag: UTXO_AFTER_GENESIS

Always include `VerifyFlag.UTXO_AFTER_GENESIS` when testing scripts that use restored opcodes (OP_CAT, OP_SPLIT, OP_MUL, etc.). Without this flag, the interpreter rejects these opcodes as disabled.

---

## Worked Example: 4-Byte Endian Reversal

This example demonstrates the full workflow: design, implement, test, and debug.

### Goal

Reverse the byte order of a 4-byte value on the stack: `[A, B, C, D]` → `[D, C, B, A]`.

### Design

Split into individual bytes, then reassemble in reverse:

```
[ABCD]
  OP_1 OP_SPLIT → [A] [BCD]
  OP_1 OP_SPLIT → [A] [B] [CD]
  OP_1 OP_SPLIT → [A] [B] [C] [D]
  OP_SWAP OP_CAT → [A] [B] [DC]
  OP_SWAP OP_CAT → [A] [DCB]
  OP_SWAP OP_CAT → [DCBA]
```

### Implementation

```dart
// File: lib/src/script_gen/opcode_helpers.dart

static ScriptBuilder reverseBytes4(ScriptBuilder b) {
  return b
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_1).opCode(OpCodes.OP_SPLIT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT)
    .opCode(OpCodes.OP_SWAP).opCode(OpCodes.OP_CAT);
}
```

Cost: 12 bytes of script (12 single-byte opcodes).

### Test

```dart
test('reverseBytes4 converts BE to LE', () {
  var unlock = ScriptBuilder();
  unlock.addData(Uint8List.fromList([0x01, 0x02, 0x03, 0x04]));

  var lock = ScriptBuilder();
  OpcodeHelpers.reverseBytes4(lock);
  lock.addData(Uint8List.fromList([0x04, 0x03, 0x02, 0x01]));
  lock.opCode(OpCodes.OP_EQUALVERIFY);
  lock.opCode(OpCodes.OP_1);

  var tx = _createDummyTx(unlock.build());
  var interp = Interpreter();
  interp.correctlySpends(
    unlock.build(), lock.build(), tx, 0,
    {VerifyFlag.UTXO_AFTER_GENESIS},
    Coin.valueOf(BigInt.from(1000)),
  );
});
```

### Extension: 32-Byte Reversal

The same pattern scales to 32 bytes (31 splits + 31 swap-cats = 124 bytes):

```dart
static ScriptBuilder reverseBytes32(ScriptBuilder b) {
  for (int i = 0; i < 31; i++) {
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);
  }
  for (int i = 0; i < 31; i++) {
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
  }
  return b;
}
```

---

## BSV Opcode Reference

All opcodes available in Bitcoin SV after the Genesis upgrade. Opcodes marked **(restored)** were disabled in BTC/BCH but re-enabled in BSV.

### Constants

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x00` | `OP_0` / `OP_FALSE` | Push empty byte array (falsy) |
| `0x01`-`0x4b` | *Pushdata N* | Next N bytes are data to push |
| `0x4c` | `OP_PUSHDATA1` | Next 1 byte = length, then that many bytes of data |
| `0x4d` | `OP_PUSHDATA2` | Next 2 bytes (LE) = length, then data |
| `0x4e` | `OP_PUSHDATA4` | Next 4 bytes (LE) = length, then data |
| `0x4f` | `OP_1NEGATE` | Push -1 |
| `0x51` | `OP_1` / `OP_TRUE` | Push 1 |
| `0x52`-`0x60` | `OP_2`-`OP_16` | Push 2-16 |

### Flow Control

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x61` | `OP_NOP` | No operation |
| `0x63` | `OP_IF` | Execute next block if top is truthy (consumes top) |
| `0x64` | `OP_NOTIF` | Execute next block if top is falsy (consumes top) |
| `0x67` | `OP_ELSE` | Execute if preceding IF/NOTIF was not taken |
| `0x68` | `OP_ENDIF` | End IF/ELSE block |
| `0x69` | `OP_VERIFY` | Fail if top is not truthy (consumes top) |
| `0x6a` | `OP_RETURN` | Terminate; top value is result |

### Stack Operations

| Hex | Opcode | Stack Effect | Description |
|-----|--------|-------------|-------------|
| `0x6b` | `OP_TOALTSTACK` | main→alt | Move top to altstack |
| `0x6c` | `OP_FROMALTSTACK` | alt→main | Move altstack top to main |
| `0x6d` | `OP_2DROP` | `a b →` | Drop top two |
| `0x6e` | `OP_2DUP` | `a b → a b a b` | Duplicate top two |
| `0x6f` | `OP_3DUP` | `a b c → a b c a b c` | Duplicate top three |
| `0x70` | `OP_2OVER` | `a b c d → a b c d a b` | Copy 3rd and 4th to top |
| `0x71` | `OP_2ROT` | `a b c d e f → c d e f a b` | Move 5th and 6th to top |
| `0x72` | `OP_2SWAP` | `a b c d → c d a b` | Swap top two pairs |
| `0x73` | `OP_IFDUP` | `a → a (a)` | Duplicate if non-zero |
| `0x74` | `OP_DEPTH` | `→ n` | Push stack depth |
| `0x75` | `OP_DROP` | `a →` | Remove top |
| `0x76` | `OP_DUP` | `a → a a` | Duplicate top |
| `0x77` | `OP_NIP` | `a b → b` | Remove second |
| `0x78` | `OP_OVER` | `a b → a b a` | Copy second to top |
| `0x79` | `OP_PICK` | `... n → ... item_n` | Copy item n-deep to top |
| `0x7a` | `OP_ROLL` | `... n → ... item_n` | Move item n-deep to top |
| `0x7b` | `OP_ROT` | `a b c → b c a` | Rotate top 3 left |
| `0x7c` | `OP_SWAP` | `a b → b a` | Swap top two |
| `0x7d` | `OP_TUCK` | `a b → b a b` | Copy top before second |

### Splice / Data Manipulation (restored)

| Hex | Opcode | Stack Effect | Description |
|-----|--------|-------------|-------------|
| `0x7e` | `OP_CAT` | `a b → ab` | Concatenate two byte strings |
| `0x7f` | `OP_SPLIT` | `x n → x[:n] x[n:]` | Split byte string at position n |
| `0x80` | `OP_NUM2BIN` | `a n → bytes` | Convert number a to n-byte LE byte string |
| `0x81` | `OP_BIN2NUM` | `bytes → a` | Convert byte string to minimal script number |
| `0x82` | `OP_SIZE` | `x → x len` | Push length of top (without consuming it) |

### Bitwise Logic (restored)

| Hex | Opcode | Stack Effect | Description |
|-----|--------|-------------|-------------|
| `0x83` | `OP_INVERT` | `x → ~x` | Flip all bits |
| `0x84` | `OP_AND` | `a b → a&b` | Bitwise AND |
| `0x85` | `OP_OR` | `a b → a\|b` | Bitwise OR |
| `0x86` | `OP_XOR` | `a b → a^b` | Bitwise XOR |
| `0x87` | `OP_EQUAL` | `a b → bool` | Push 1 if equal, 0 otherwise |
| `0x88` | `OP_EQUALVERIFY` | `a b →` | Fail if not equal |

### Arithmetic

| Hex | Opcode | Stack Effect | Description |
|-----|--------|-------------|-------------|
| `0x8b` | `OP_1ADD` | `a → a+1` | Add 1 |
| `0x8c` | `OP_1SUB` | `a → a-1` | Subtract 1 |
| `0x8f` | `OP_NEGATE` | `a → -a` | Flip sign |
| `0x90` | `OP_ABS` | `a → \|a\|` | Absolute value |
| `0x91` | `OP_NOT` | `a → !a` | Logical NOT (0→1, 1→0, else→0) |
| `0x92` | `OP_0NOTEQUAL` | `a → bool` | 0→0, nonzero→1 |
| `0x93` | `OP_ADD` | `a b → a+b` | Add |
| `0x94` | `OP_SUB` | `a b → a-b` | Subtract |
| `0x95` | `OP_MUL` | `a b → a*b` | Multiply **(restored)** |
| `0x96` | `OP_DIV` | `a b → a/b` | Integer divide **(restored)** |
| `0x97` | `OP_MOD` | `a b → a%b` | Modulo **(restored)** |
| `0x98` | `OP_LSHIFT` | `x n → x<<n` | Logical left shift on byte array **(restored)** |
| `0x99` | `OP_RSHIFT` | `x n → x>>n` | Logical right shift on byte array **(restored)** |
| `0x9a` | `OP_BOOLAND` | `a b → bool` | Both non-zero → 1 |
| `0x9b` | `OP_BOOLOR` | `a b → bool` | Either non-zero → 1 |
| `0x9c` | `OP_NUMEQUAL` | `a b → bool` | Numeric equality |
| `0x9d` | `OP_NUMEQUALVERIFY` | `a b →` | Fail if not numerically equal |
| `0x9e` | `OP_NUMNOTEQUAL` | `a b → bool` | Numeric inequality |
| `0x9f` | `OP_LESSTHAN` | `a b → bool` | a < b |
| `0xa0` | `OP_GREATERTHAN` | `a b → bool` | a > b |
| `0xa1` | `OP_LESSTHANOREQUAL` | `a b → bool` | a ≤ b |
| `0xa2` | `OP_GREATERTHANOREQUAL` | `a b → bool` | a ≥ b |
| `0xa3` | `OP_MIN` | `a b → min` | Smaller of two |
| `0xa4` | `OP_MAX` | `a b → max` | Larger of two |
| `0xa5` | `OP_WITHIN` | `x min max → bool` | min ≤ x < max |

### Cryptographic

| Hex | Opcode | Stack Effect | Description |
|-----|--------|-------------|-------------|
| `0xa6` | `OP_RIPEMD160` | `x → hash` | RIPEMD-160 hash (20 bytes) |
| `0xa7` | `OP_SHA1` | `x → hash` | SHA-1 hash (20 bytes) |
| `0xa8` | `OP_SHA256` | `x → hash` | SHA-256 hash (32 bytes) |
| `0xa9` | `OP_HASH160` | `x → hash` | SHA-256 then RIPEMD-160 (20 bytes) |
| `0xaa` | `OP_HASH256` | `x → hash` | Double SHA-256 (32 bytes) |
| `0xab` | `OP_CODESEPARATOR` | — | Signature checks use script after this point |
| `0xac` | `OP_CHECKSIG` | `sig pk → bool` | Verify ECDSA signature |
| `0xad` | `OP_CHECKSIGVERIFY` | `sig pk →` | Verify signature, fail if invalid |
| `0xae` | `OP_CHECKMULTISIG` | `sigs pks → bool` | Verify multiple signatures |
| `0xaf` | `OP_CHECKMULTISIGVERIFY` | `sigs pks →` | Verify multiple signatures, fail if invalid |

### Locktime

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0xb1` | `OP_NOP2` / `OP_CHECKLOCKTIMEVERIFY` | NOP (validates absolute locktime for pre-genesis) |
| `0xb2` | `OP_NOP3` / `OP_CHECKSEQUENCEVERIFY` | NOP (validates relative locktime for pre-genesis) |

### Reserved / NOP

| Hex | Opcode | Description |
|-----|--------|-------------|
| `0x50` | `OP_RESERVED` | Invalid unless in unexecuted OP_IF branch |
| `0x89` | `OP_RESERVED1` | Invalid unless in unexecuted OP_IF branch |
| `0x8a` | `OP_RESERVED2` | Invalid unless in unexecuted OP_IF branch |
| `0xb0` | `OP_NOP1` | No operation (ignored) |
| `0xb3`-`0xb9` | `OP_NOP4`-`OP_NOP10` | No operation (ignored) |

### Key BSV Notes

- **OP_LSHIFT / OP_RSHIFT** operate on byte arrays in big-endian order (MSB at byte 0). The shift amount is in bits. Sign data is discarded.
- **OP_RETURN** (post-Genesis): does NOT invalidate the transaction. It terminates script execution with the top stack value as the result.
- **Script size limits**: BSV has no script size limit after Genesis. Scripts can be megabytes.
- **Number size limits**: No limit on numeric operand sizes after Genesis (sCrypt uses this for secp256k1 arithmetic).

---

## Key Lessons Learned

1. **Sign bit is the #1 source of bugs.** Any value with bit 7 of the last byte set becomes negative. Always append `0x00` for unsigned values.

2. **LIFO altstack reverses order.** When pushing state words a,b,c,d,e,f,g,h for later recovery, push in reverse order (h first) so they pop in the correct order (a first).

3. **PICK/ROLL indices shift.** After pushing a value, all PICK indices increase by 1. Track this carefully in compression rounds.

4. **Test incrementally.** Build 10 opcodes, test. Build 10 more, test. Don't write 60KB of script and debug from the final error.

5. **Endianness consistency matters.** Pick BE or LE for your working format and minimize conversions. SHA256 is BE-native, but LE addition saves 36 bytes per 32-bit add.

6. **Document stack state.** Every function should have pre/post stack comments. Complex scripts are undebuggable without them.

7. **Use the interpreter.** dartsv's `Interpreter.correctlySpends()` runs your script exactly as a BSV node would. If it passes the interpreter, it will work on-chain.
