# State Machine Token Template

## pp1_sm.json — State Machine Inductive Proof

A multi-party stateful token supporting 7 operations across a defined lifecycle. The script enforces state transitions, dual-signature authorization, rolling commitment hashes, and nLockTime-based timeouts entirely on-chain.

### Use Cases
- Escrow agreements with checkpoint-based releases
- Service contracts (freelance, SLA-backed)
- Layaway / installment purchase plans
- Insurance claim workflows
- Any two-party agreement with observable progress

### Lifecycle

```
CREATED(0) → ENROLLED(1) → PROGRESSING(2) → CONVERTING(3) → SETTLED(4)
                ↓                ↓                              ↑
             EXPIRED(5)      EXPIRED(5)                    (terminal)
```

### Operations

| Op Code | Operation | Auth | Description |
|---------|-----------|------|-------------|
| OP_0 | Create | preimage (OCS) | Initialize the token from a funding UTXO |
| OP_1 | Enroll | operator sig | Counterparty enrolls, operator approves |
| OP_2 | Confirm | dual sig | Record a checkpoint (operator + counterparty) |
| OP_3 | Convert | dual sig | Move to settlement phase |
| OP_4 | Settle | operator sig | Distribute rewards and payment (7 outputs) |
| OP_5 | Timeout | operator sig | Refund on expiration via nLockTime (6 outputs) |
| OP_6 | Burn | owner sig | Destroy token in terminal state (P2PKH spend) |

### Parameters

| Name | Size | Encoding | Description |
|------|------|----------|-------------|
| `ownerPKH` | 20 | `hex` | Current owner / next expected actor (mutable) |
| `tokenId` | 32 | `hex` | Unique token identifier, genesis txid (immutable) |
| `operatorPKH` | 20 | `hex` | Operator pubkey hash (immutable) |
| `counterpartyPKH` | 20 | `hex` | Counterparty pubkey hash (immutable) |
| `currentState` | 1 | `hex_byte` | State value 0x00-0x05 (mutable) |
| `checkpointCount` | 1 | `hex_byte` | Checkpoint counter, incremented on confirm (mutable) |
| `commitmentHash` | 32 | `hex` | Rolling SHA256 commitment hash (mutable) |
| `transitionBitmask` | 1 | `hex_byte` | Enables/disables transitions (immutable) |
| `timeoutDelta` | 4 | `le_uint32` | nLockTime timeout delta in blocks/seconds (immutable) |

### Header Layout (140 bytes)

```
Offset  Prefix  Field              Mutability
[0:1]   0x14    —
[1:21]          ownerPKH           mutable
[21:22] 0x20    —
[22:54]         tokenId            immutable
[54:55] 0x14    —
[55:75]         operatorPKH        immutable
[75:76] 0x14    —
[76:96]         counterpartyPKH        immutable
[96:97] 0x01    —
[97:98]         currentState       mutable
[98:99] 0x01    —
[99:100]        checkpointCount     mutable
[100:101] 0x20  —
[101:133]       commitmentHash     mutable
[133:134] 0x01  —
[134:135]       transitionBitmask  immutable
[135:136] 0x04  —
[136:140]       timeoutDelta       immutable
[140:]          script body        immutable
```

### Mutable Regions

On each state transition, 4 header regions are rewritten:
- `ownerPKH` [1:21] — set to the next expected actor
- `currentState` [97:98] — post-transition state value
- `checkpointCount` [99:100] — incremented on confirm operations
- `commitmentHash` [101:133] — `SHA256(prevHash || SHA256(sig(s) || eventData))`

### Encoding Details

**`hex_byte`**: A single byte encoded as 2 hex characters. The pushdata prefix `0x01` is already part of the surrounding static hex — substitute only the raw byte value.

```python
# Example: set currentState to ENROLLED (0x01)
script_hex = script_hex.replace("{{currentState}}", "01")

# Example: set transitionBitmask to enable all transitions (0x3F)
script_hex = script_hex.replace("{{transitionBitmask}}", "3f")
```

**`le_uint32`**: 4-byte little-endian unsigned integer.

```python
# Example: timeoutDelta = 86400 (seconds)
import struct
timeout_hex = struct.pack('<I', 86400).hex()  # "80510100"
script_hex = script_hex.replace("{{timeoutDelta}}", timeout_hex)
```

### Transition Bitmask

| Bit | Transition |
|-----|------------|
| 0 | Enroll (CREATED → ENROLLED) |
| 1 | Confirm from ENROLLED |
| 2 | Confirm from PROGRESSING |
| 3 | Convert (PROGRESSING → CONVERTING) |
| 4 | Settle (CONVERTING → SETTLED) |
| 5 | Timeout (any non-terminal → EXPIRED) |

Value `0x3F` (binary `00111111`) enables all transitions.

### Output Topologies

| Operation | Outputs |
|-----------|---------|
| Standard (create, enroll, confirm, convert) | 5: change, PP1_SM, PP2, PP3, metadata |
| Timeout | 6: change, operatorRecovery(P2PKH), PP1_SM, PP2, PP3, metadata |
| Settle | 7: change, counterpartyShare(P2PKH), operatorShare(P2PKH), PP1_SM, PP2, PP3, metadata |
