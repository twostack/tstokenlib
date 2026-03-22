
## Overview
The TSL1 Token Protocol allows for the creation of P2P tokens on Bitcoin (BSV) that have the following features:

- Fully miner-validated tokens
- No indexers are required to track token state or to guard against double-spends
- No back-to-genesis tracing within the UTXO set
- No transaction bloating with successive token transfers
- Double-spend protection with the same level of security as the native token units (satoshis)
- On-chain identity anchoring via Rabin signature verification
- Hand-optimized partial SHA-256 witness verification (~24KB per block)

[Download a copy of the whitepaper for a full technical explanation](https://github.com/twostack/tsl1)

The library supports six token archetypes:

| Type | API Class | Use Case |
|------|-----------|----------|
| **NFT** | `TokenTool` | Unique, indivisible tokens (1:1 ownership) |
| **Fungible** | `FungibleTokenTool` | Divisible token amounts (split, merge, transfer) |
| **Restricted NFT** | `RestrictedTokenTool` | NFT with transfer policy flags and redemption |
| **Restricted Fungible** | `RestrictedFungibleTokenTool` | Fungible token with transfer policy restrictions |
| **Appendable** | `AppendableTokenTool` | Stamp-accumulating token with threshold redemption (e.g., loyalty cards) |
| **State Machine** | `StateMachineTool` | Multi-party workflows with explicit state transitions and milestones |

All token types support the full lifecycle: minting, witness creation, transfers, and burns.
Fungible types additionally support splitting and merging. Restricted types add transfer policy
enforcement and redemption. Appendable tokens support issuer-controlled stamping. State machine
tokens model complex multi-party workflows with state transition rules.

Code contributions are welcome and encouraged.

## Transaction Sizes and Fees

Approximate on-chain sizes for core token operations. The PP3 witness verifier
(~49KB, containing two rounds of hand-optimized partial SHA-256) dominates the
transaction size. The transfer witness carries the full serialized parent token
transaction (`parentRawTx`) as required by the inductive proof — this is constant-size
and does not grow with successive transfers.

### NFT

| Transaction | Size | Fee @ 1 sat/KB | Fee @ 100 sat/KB |
|-------------|-----:|---------------:|-----------------:|
| Issuance Tx | ~55 KB | 55 sats | 5,500 sats |
| Issuance Witness | ~1 KB | 1 sat | 100 sats |
| **Issuance pair** | **~56 KB** | **56 sats** | **5,600 sats** |
| Transfer Tx | ~55 KB | 55 sats | 5,500 sats |
| Transfer Witness | ~56 KB | 56 sats | 5,600 sats |
| **Transfer pair** | **~111 KB** | **111 sats** | **11,100 sats** |

### Fungible Token

| Transaction | Size | Fee @ 1 sat/KB | Fee @ 100 sat/KB |
|-------------|-----:|---------------:|-----------------:|
| Mint Tx | ~61 KB | 61 sats | 6,100 sats |
| Mint Witness | ~1 KB | 1 sat | 100 sats |
| **Mint pair** | **~62 KB** | **62 sats** | **6,200 sats** |
| Transfer Tx | ~61 KB | 61 sats | 6,100 sats |
| Transfer Witness | ~62 KB | 62 sats | 6,200 sats |
| **Transfer pair** | **~123 KB** | **123 sats** | **12,300 sats** |

Sizes are approximate and vary slightly with key sizes, padding, and metadata.
Split transactions (8 outputs with two triplets) are roughly 1.5x the transfer size.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  tstokenlib:
    git:
      url: https://github.com/twostack/tstokenlib
```

## NFT Tokens

The primary API is the `TokenTool` class. For a full working example, see
[`example/token_lifecycle_example.dart`](example/token_lifecycle_example.dart).

### Issuing a New NFT

Token issuance creates a transaction with 5 outputs:

| Output | Purpose |
|--------|---------|
| output[0] | Change output (remaining satoshis back to issuer) |
| output[1] | PP1 — Proof Point 1 (inductive proof locked to owner, embeds tokenId and Rabin pubkey hash) |
| output[2] | PP2 — Proof Point 2 (validates witness funding outpoint and owner PKH) |
| output[3] | PP3 — Witness verifier (enables transfer authorization via partial SHA-256) |
| output[4] | Metadata — OP_RETURN output carrying optional metadata or issuer identity |

```dart
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';

var issuerPrivateKey = SVPrivateKey.fromWIF("your_WIF_here");
var issuerPubKey = issuerPrivateKey.publicKey;
var issuerAddress = Address.fromPublicKey(issuerPubKey, NetworkType.TEST);

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
var fundingSigner = TransactionSigner(sigHashAll, issuerPrivateKey);

var fundingTx = Transaction.fromHex("...");  // from the blockchain

// Generate a Rabin keypair for identity anchoring
var rabinKeyPair = Rabin.generateKeyPair(1024);
var rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
var rabinPubKeyHash = hash160(rabinNBytes);  // 20-byte hash embedded in PP1

var service = TokenTool();
var issuanceTx = await service.createTokenIssuanceTxn(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress, fundingTx.hash,
    rabinPubKeyHash,
);
```

#### Issuance with Metadata

```dart
var issuanceTx = await service.createTokenIssuanceTxn(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress, fundingTx.hash,
    rabinPubKeyHash,
    metadataBytes: utf8.encode('{"name": "MyToken", "supply": 1}'),
);
```

#### Issuance with Issuer Identity

To cryptographically anchor the token to an issuer identity:

```dart
import 'package:cryptography/cryptography.dart';

var algorithm = Ed25519();
var keyPair = await algorithm.newKeyPair();
var wand = await algorithm.newSignatureWandFromKeyPair(keyPair);

var identityBuilder = IdentityAnchorBuilder({'name': 'My Issuer', 'org': 'My Org'});
var identityTx = await identityBuilder.buildTransaction(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress, wand,
);

var issuanceTx = await service.createTokenIssuanceTxn(
    issuanceFundingTx, fundingSigner, issuerPubKey, issuerAddress, issuanceFundingTx.hash,
    rabinPubKeyHash,
    identityTxId: identityTx.hash,
    issuerWand: wand,
);

// Verify the identity link
var isValid = await IdentityVerification.verifyIssuanceIdentity(issuanceTx, identityTx);
```

### NFT Witness

After issuance (or after a transfer), a **witness transaction** proves ownership by spending
PP1 and PP2 from the token transaction.

For **issuance witnesses**, a Rabin signature over `sha256(identityTxId || ed25519PubKey)` must
be provided to prove the issuer is authorized by the identity anchor:

```dart
// Compute Rabin signature for identity binding (tokenId prevents replay attacks)
var identityTxId = ...;       // 32-byte identity anchor txid
var ed25519PubKey = ...;      // 32-byte ED25519 public key from identity anchor
var tokenId = fundingTx.hash; // 32-byte token ID (funding tx hash)
var messageHash = Rabin.sha256ToScriptInt([...identityTxId, ...ed25519PubKey, ...tokenId]);
var rabinSig = Rabin.sign(messageHash, rabinKeyPair.p, rabinKeyPair.q);

var witnessTx = service.createWitnessTxn(
    fundingSigner, fundingTx, issuanceTx,
    List<int>.empty(),      // empty for issuance (no parent)
    issuerPubKey,
    issuerAddress.pubkeyHash160,
    TokenAction.ISSUANCE,
    rabinN: rabinNBytes,
    rabinS: Rabin.bigIntToScriptNum(rabinSig.s).toList(),
    rabinPadding: rabinSig.padding,
    identityTxId: identityTxId,
    ed25519PubKey: ed25519PubKey,
);
```

For a **transfer witness**, provide the full serialized parent token transaction:

```dart
var transferWitnessTx = service.createWitnessTxn(
    recipientFundingSigner, recipientFundingTx, transferredTokenTx,
    hex.decode(parentTokenTx.serialize()),
    recipientPubKey,
    senderPubkeyHash,
    TokenAction.TRANSFER,
);
```

### NFT Transfer

```dart
var pp1 = PP1NftLockBuilder.fromScript(currentTokenTx.outputs[1].script);
var tokenId = pp1.tokenId ?? [];

var transferTx = service.createTokenTransferTxn(
    currentWitnessTx, currentTokenTx,
    currentOwnerPubKey, recipientAddress,
    transferFundingTx, currentOwnerFundingSigner, currentOwnerPubKey,
    recipientFundingTx.hash, tokenId,
);
```

### NFT Burn

```dart
var burnTx = service.createBurnTokenTxn(
    currentTokenTx, ownerSigner, ownerPubKey,
    burnFundingTx, fundingSigner, fundingPubKey,
);
```

## Fungible Tokens

The primary API is the `FungibleTokenTool` class. For a full working example, see
[`example/fungible_token_lifecycle_example.dart`](example/fungible_token_lifecycle_example.dart).

Fungible tokens use a "triplet" of outputs (PP1_FT, PP2-FT, PP3-FT) that carries the token
amount, owner PKH, and tokenId. The amount is embedded in the PP1_FT locking script and
enforced by the Bitcoin Script interpreter at spending time.

### Minting Fungible Tokens

Creates a new fungible token with a specified amount. The tokenId is derived from the
funding transaction hash.

| Output | Purpose |
|--------|---------|
| output[0] | Change (remaining satoshis) |
| output[1] | PP1_FT — embeds ownerPKH, tokenId, and amount |
| output[2] | PP2-FT — validates witness funding outpoint |
| output[3] | PP3-FT — enables transfer via partial SHA-256 |
| output[4] | Metadata — OP_RETURN |

```dart
var tokenTool = FungibleTokenTool();

var mintTx = await tokenTool.createFungibleMintTxn(
    fundingTx, fundingSigner, ownerPubKey, ownerAddress,
    fundingTx.hash,   // becomes the tokenId
    1000,             // amount to mint
);

var pp1Ft = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
var tokenId = pp1Ft.tokenId;
var amount = pp1Ft.amount;  // 1000
```

### Fungible Token Witness

After any fungible token operation (mint, transfer, split, merge), a witness must be created.

```dart
// Mint witness (no parent tx)
var mintWitnessTx = tokenTool.createFungibleWitnessTxn(
    ownerSigner, fundingTx, mintTx,
    ownerPubKey, ownerPubkeyHash,
    FungibleTokenAction.MINT,
);

// Transfer witness (requires parent tx bytes)
var transferWitnessTx = tokenTool.createFungibleWitnessTxn(
    recipientSigner, recipientFundingTx, transferTx,
    recipientPubKey, changePubkeyHash,
    FungibleTokenAction.TRANSFER,
    parentTokenTxBytes: hex.decode(parentTx.serialize()),
    parentOutputCount: 5,
);
```

### Fungible Token Transfer

Transfers the full token amount to a new owner.

```dart
var transferTx = tokenTool.createFungibleTransferTxn(
    witnessTx, tokenTx,
    currentOwnerPubKey, recipientAddress,
    fundingTx, fundingSigner, fundingPubKey,
    recipientFundingTx.hash, tokenId, 1000,
);
```

### Split

Divides a token into two outputs: a recipient amount and change. Creates an 8-output
transaction with two triplets (recipient at indices 1-3, change at indices 4-6).

```dart
var splitTx = tokenTool.createFungibleSplitTxn(
    witnessTx, tokenTx,
    ownerPubKey, recipientAddress, 700,       // send 700 to recipient
    fundingTx, fundingSigner, fundingPubKey,
    recipientWitnessFundingTx.hash,           // recipient's witness funding
    changeWitnessFundingTx.hash,              // change witness funding
    tokenId, 1000,                            // total amount before split
);

// Both triplets need separate witnesses
var recipientWitnessTx = tokenTool.createFungibleWitnessTxn(
    recipientSigner, recipientFundingTx, splitTx,
    recipientPubKey, changePubkeyHash,
    FungibleTokenAction.SPLIT_TRANSFER,
    parentTokenTxBytes: hex.decode(parentTx.serialize()),
    parentOutputCount: 5,
    tripletBaseIndex: 1,     // recipient triplet
);

var changeWitnessTx = tokenTool.createFungibleWitnessTxn(
    changeSigner, changeFundingTx, splitTx,
    changePubKey, changePubkeyHash,
    FungibleTokenAction.SPLIT_TRANSFER,
    parentTokenTxBytes: hex.decode(parentTx.serialize()),
    parentOutputCount: 5,
    tripletBaseIndex: 4,     // change triplet
);
```

### Merge

Combines two token UTXOs (same tokenId, same owner) into a single output.
PP3-FT inputs are burned via P2PKH rather than fully unlocked.

```dart
var mergeTx = tokenTool.createFungibleMergeTxn(
    witnessA, tokenTxA,                       // first UTXO
    witnessB, tokenTxB,                       // second UTXO
    ownerPubKey, ownerSigner,
    fundingTx, fundingSigner, fundingPubKey,
    mergedWitnessFundingTx.hash,
    tokenId, 1000,                            // total = amountA + amountB
    prevTripletBaseIndexA: 1,
    prevTripletBaseIndexB: 4,
);

// Merge witness requires both parent tx bytes
var mergeWitnessTx = tokenTool.createFungibleWitnessTxn(
    ownerSigner, fundingTx, mergeTx,
    ownerPubKey, ownerPubkeyHash,
    FungibleTokenAction.MERGE,
    parentTokenTxBytes: hex.decode(tokenTxA.serialize()),
    parentTokenTxBytesB: hex.decode(tokenTxB.serialize()),
    parentOutputCount: 8,
    parentOutputCountB: 8,
    parentPP1FtIndexA: 1,
    parentPP1FtIndexB: 4,
);
```

### Fungible Token Burn

```dart
var burnTx = tokenTool.createFungibleBurnTxn(
    tokenTx, ownerSigner, ownerPubKey,
    fundingTx, fundingSigner, fundingPubKey,
);
```

## Restricted NFT Tokens

The `RestrictedTokenTool` class adds transfer policy enforcement via a flags byte and
supports redemption with an optional one-time-use flag.

### Issuing a Restricted NFT

```dart
var tool = RestrictedTokenTool();

var issuanceTx = await tool.createTokenIssuanceTxn(
    fundingTx, fundingSigner, ownerPubKey, ownerAddress,
    fundingTx.hash,       // tokenId
    rabinPubKeyHash,
    flags: 0x01,          // transfer policy flags
);
```

### RNFT Transfer, Witness, Burn, Redeem

```dart
// Transfer (enforces policy flags)
var transferTx = tool.createTokenTransferTxn(
    witnessTx, tokenTx,
    ownerPubKey, recipientAddress,
    fundingTx, fundingSigner, fundingPubKey,
    recipientFundingTx.hash, tokenId,
);

// Redeem (may destroy if one-time-use flag is set)
var redeemTx = tool.createRedeemTokenTxn(
    tokenTx, ownerSigner, ownerPubKey,
    fundingTx, fundingSigner, fundingPubKey,
);
```

## Restricted Fungible Tokens

The `RestrictedFungibleTokenTool` class combines balance conservation of FT with policy
enforcement of RNFT. Supports mint, transfer, split, merge, burn, and redeem.

```dart
var tool = RestrictedFungibleTokenTool();

var mintTx = await tool.createFungibleMintTxn(
    fundingTx, fundingSigner, ownerPubKey, ownerAddress,
    fundingTx.hash, 1000,
    rabinPubKeyHash,
    flags: 0x01,
);
```

Split, merge, transfer, witness, burn, and redeem follow the same patterns as
`FungibleTokenTool` with additional policy flag enforcement.

## Appendable Tokens

The `AppendableTokenTool` class supports tokens that accumulate stamps toward a threshold.
Uses a dual authority model: the issuer controls stamping, the owner controls transfer/redeem/burn.
Stamps build a rolling SHA-256 hash chain.

### Issuing an Appendable Token

```dart
var tool = AppendableTokenTool();

var issuanceTx = await tool.createTokenIssuanceTxn(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress,
    fundingTx.hash,
    rabinPubKeyHash,
    stampThreshold: 10,    // stamps needed for redemption
);
```

### Stamping

Each stamp is added by the issuer, incrementing the stamp count and updating the
rolling hash chain:

```dart
var stampTx = tool.createTokenStampTxn(
    witnessTx, tokenTx,
    issuerPubKey, ownerAddress,
    fundingTx, fundingSigner, fundingPubKey,
    ownerFundingTx.hash, tokenId,
    currentStampCount: 3,
    currentStampsHash: previousHash,   // rolling SHA-256 chain
);
```

### Redemption

When the stamp threshold is met, the owner can redeem:

```dart
var redeemTx = tool.createRedeemTokenTxn(
    tokenTx, ownerSigner, ownerPubKey,
    fundingTx, fundingSigner, fundingPubKey,
);
```

## State Machine Tokens

The `StateMachineTool` class models multi-party workflows with explicit state transitions.
It supports merchant/customer actors, transition rules via bitmask, milestone tracking,
and timeout handling via nLockTime.

### State Machine Lifecycle

States: INIT (0) -> ACTIVE (1) -> CONFIRMED (2) -> CONVERTED (3) -> SETTLED (4)

```dart
var tool = StateMachineTool();

// Create — merchant issues in INIT state
var createTx = await tool.createTokenIssuanceTxn(
    fundingTx, fundingSigner, merchantPubKey, merchantAddress,
    fundingTx.hash,
    rabinPubKeyHash,
    initialState: 0,               // INIT
    transitionBitmask: 0x1F,       // allowed transitions
    timeoutHeight: 800000,         // nLockTime for timeout
);

// Enroll — customer takes ownership (INIT -> ACTIVE)
var enrollTx = tool.createEnrollTxn(
    witnessTx, tokenTx,
    merchantPubKey, customerAddress,
    fundingTx, fundingSigner, fundingPubKey,
    customerFundingTx.hash, tokenId,
);

// Confirm — dual-sig transition (ACTIVE -> CONFIRMED)
var confirmWitnessTx = tool.createDualWitnessTxn(
    merchantSigner, customerSigner,
    fundingTx, tokenTx,
    merchantPubKey, customerPubKey,
    merchantPubkeyHash,
    StateMachineAction.CONFIRM,
);

// Transition — generic state change with commitment hash
var transitionTx = tool.createTransitionTxn(
    witnessTx, tokenTx,
    ownerPubKey, ownerAddress,
    fundingTx, fundingSigner, fundingPubKey,
    ownerFundingTx.hash, tokenId,
    newState: 3,
    commitmentHash: sha256(eventData),   // audit trail
);

// Timeout — single-sig, requires nLockTime
var timeoutWitnessTx = tool.createWitnessTxn(
    merchantSigner, fundingTx, tokenTx,
    merchantPubKey, merchantPubkeyHash,
    StateMachineAction.TIMEOUT,
);
```

## On-Chain Identity Anchoring (Rabin Signatures)

All token types enforce issuer identity on-chain using Rabin signature verification. During
issuance, the PP1 locking script verifies that:

1. `hash160(rabinN) == rabinPubKeyHash` — the Rabin public key matches the hash embedded in PP1
2. `s^2 mod n == sha256(identityTxId || ed25519PubKey) + padding` — the signature is valid

This ensures that only the holder of the Rabin private key (the issuer) can create tokens
linked to a given identity anchor.

The `rabinPubKeyHash` is preserved across transfers as part of the PP1 constructor parameters,
alongside `ownerPKH` and `tokenId`.

### Rabin Key Generation

```dart
import 'package:tstokenlib/src/crypto/rabin.dart';

// Generate a keypair (1024-bit is sufficient; 2048-bit for production)
var keyPair = Rabin.generateKeyPair(1024);

// Encode the public key for use in scripts
var rabinNBytes = Rabin.bigIntToScriptNum(keyPair.n).toList();
var rabinPubKeyHash = hash160(rabinNBytes);

// Sign a message
var messageHash = Rabin.sha256ToScriptInt(messageBytes);
var sig = Rabin.sign(messageHash, keyPair.p, keyPair.q);

// Verify (in Dart, for testing)
var isValid = Rabin.verify(messageHash, sig, keyPair.n);
```

## Cross-Language Support

TSL1 script templates are exported as JSON for use by implementations in other languages.
A companion JVM library ([tstokenlib4j](https://github.com/AgenTSL/tstokenlib4j)) consumes
these templates for Java/Kotlin integration.

Templates are regenerated via:

```bash
dart run tool/export_templates.dart
dart run tool/export_test_vectors.dart
```

## Error Handling

The library throws `ScriptException` (from the `dartsv` package) for invalid inputs:

- **Wrong-length pubkey hash (PKH)**: Must be exactly 20 bytes (40 hex characters).
- **Wrong-length tokenId**: Must be exactly 32 bytes.
- **Wrong-length Rabin pubkey hash**: Must be exactly 20 bytes (hash160 of the encoded Rabin public key).
- **Invalid outpoint format**: Witness funding outpoints must be 36 bytes.

```dart
try {
    var tx = await service.createTokenIssuanceTxn(...);
} on ScriptException catch (e) {
    print('Script error: ${e.error} - ${e.cause}');
}
```

## License

Apache License 2.0
