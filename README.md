
## Overview
The TSL1 Token Protocol allows for the creation of P2P tokens on Bitcoin (BSV) that have the following features:

- Fully miner-validated tokens
- No indexers are required to track token state or to guard against double-spends
- No back-to-genesis tracing within the UTXO set
- No transaction bloating with successive token transfers
- Double-spend protection with the same level of security as the native token units (satoshis)
- On-chain identity anchoring via Rabin signature verification (NFT)

[Download a copy of the whitepaper for a full technical explanation](https://github.com/twostack/tsl1)

The library supports two token types:

| Type | API Class | Use Case |
|------|-----------|----------|
| **NFT** | `TokenTool` | Unique, indivisible tokens (1:1 ownership) |
| **Fungible** | `FungibleTokenTool` | Divisible token amounts (split, merge, transfer) |

Both token types support the full lifecycle: minting, witness creation, transfers, and burns.
Fungible tokens additionally support splitting a token into two amounts and merging two UTXOs back into one.

Code contributions are welcome and encouraged.

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
| output[3] | PartialWitness — enables transfer authorization via partial SHA-256 |
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
// Compute Rabin signature for identity binding
var identityTxId = ...;       // 32-byte identity anchor txid
var ed25519PubKey = ...;      // 32-byte ED25519 public key from identity anchor
var messageHash = Rabin.sha256ToScriptInt([...identityTxId, ...ed25519PubKey]);
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
var pp1 = PP1LockBuilder.fromScript(currentTokenTx.outputs[1].script);
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

Fungible tokens use a "triplet" of outputs (PP5, PP2-FT, PP3-FT) that carries the token
amount, owner PKH, and tokenId. The amount is embedded in the PP5 locking script and
enforced by the Bitcoin Script interpreter at spending time.

### Minting Fungible Tokens

Creates a new fungible token with a specified amount. The tokenId is derived from the
funding transaction hash.

| Output | Purpose |
|--------|---------|
| output[0] | Change (remaining satoshis) |
| output[1] | PP5 — embeds ownerPKH, tokenId, and amount |
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

var pp5 = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
var tokenId = pp5.tokenId;
var amount = pp5.amount;  // 1000
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
    parentPP5IndexA: 1,
    parentPP5IndexB: 4,
);
```

### Fungible Token Burn

```dart
var burnTx = tokenTool.createFungibleBurnTxn(
    tokenTx, ownerSigner, ownerPubKey,
    fundingTx, fundingSigner, fundingPubKey,
);
```

## On-Chain Identity Anchoring (Rabin Signatures)

NFT tokens enforce issuer identity on-chain using Rabin signature verification. During issuance,
the PP1 locking script verifies that:

1. `hash160(rabinN) == rabinPubKeyHash` — the Rabin public key matches the hash embedded in PP1
2. `s² mod n == sha256(identityTxId || ed25519PubKey) + padding` — the signature is valid

This ensures that only the holder of the Rabin private key (the issuer) can create tokens
linked to a given identity anchor. The verification adds only ~48 bytes to the PP1 script
(8 opcodes), keeping the total PP1 script size at ~2.5KB.

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
