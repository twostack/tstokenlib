
## Overview
The TSL1 Token Protocol allows for the creation of P2P tokens on Bitcoin (BSV) that have the following features:

- Fully miner-validated tokens
- No indexers are required to track token state or to guard against double-spends
- No back-to-genesis tracing within the UTXO set
- No transaction bloating with successive token transfers
- Double-spend protection with the same level of security as the native token units (satoshis)

[Download a copy of the whitepaper for a full technical explanation](https://github.com/twostack/tsl1)

### NOTE:
This library is an *Alpha Release* and is NOT PRODUCTION READY. It is intended as a technology demonstrator
and for early experimentation. The library now includes metadata support, issuer identity anchoring, token
transfers, and token burns, but the protocol and API surface may still change without notice.

Code contributions are welcome and encouraged.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  tstokenlib:
    git:
      url: https://github.com/twostack/tstokenlib
```

## Usage

The primary API is the `TokenTool` class, which provides methods for all token lifecycle operations.
For full working examples, refer to the unit tests in the library's source code repository.

### Issuing a New Token

Token issuance creates a transaction with 5 outputs:

| Output | Purpose |
|--------|---------|
| output[0] | Change output (remaining satoshis back to issuer) |
| output[1] | PP1 — Proof Point 1 (inductive proof locked to owner, embeds tokenId) |
| output[2] | PP2 — Proof Point 2 (validates witness funding outpoint and owner PKH) |
| output[3] | PartialWitness — enables transfer authorization via partial SHA-256 |
| output[4] | Metadata — OP_RETURN output carrying optional metadata or issuer identity |

```dart
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';

// 1. Set up keys and addresses
var issuerPrivateKey = SVPrivateKey.fromWIF("your_WIF_here");
var issuerPubKey = issuerPrivateKey.publicKey;
var issuerAddress = Address.fromPublicKey(issuerPubKey, NetworkType.TEST);

// 2. Set up a funding transaction signer
var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
var fundingSigner = TransactionSigner(sigHashAll, issuerPrivateKey);

// 3. Obtain a funding transaction (must have satoshis in output[1])
var fundingTx = Transaction.fromHex("...");  // from the blockchain

// 4. Create the token issuance transaction
var service = TokenTool();
var issuanceTx = await service.createTokenIssuanceTxn(
    fundingTx,           // funding transaction with satoshis at output[1]
    fundingSigner,       // signs the funding input
    issuerPubKey,        // issuer's public key (for the funding UTXO unlock)
    issuerAddress,       // recipient address (issuer receives the token initially)
    fundingTx.hash,      // witness funding txId (typically same as funding tx at issuance)
);

// The issuance transaction has 5 outputs
assert(issuanceTx.outputs.length == 5);
```

#### Issuance with Metadata

You can attach arbitrary metadata bytes to the issuance:

```dart
var issuanceTx = await service.createTokenIssuanceTxn(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress, fundingTx.hash,
    metadataBytes: utf8.encode('{"name": "MyToken", "supply": 1}'),
);
```

#### Issuance with Issuer Identity

To cryptographically anchor the token to an issuer identity:

```dart
import 'package:cryptography/cryptography.dart';

// Create an ED25519 keypair for identity signing
var algorithm = Ed25519();
var keyPair = await algorithm.newKeyPair();
var wand = await algorithm.newSignatureWandFromKeyPair(keyPair);

// First, create an identity anchor transaction on-chain
var identityBuilder = IdentityAnchorBuilder({'name': 'My Issuer', 'org': 'My Org'});
var identityTx = await identityBuilder.buildTransaction(
    fundingTx, fundingSigner, issuerPubKey, issuerAddress, wand,
);

// Then issue the token, linking it to the identity
var issuanceTx = await service.createTokenIssuanceTxn(
    issuanceFundingTx, fundingSigner, issuerPubKey, issuerAddress, issuanceFundingTx.hash,
    identityTxId: identityTx.hash,
    issuerWand: wand,
);

// Later, anyone can verify the identity link
var isValid = await IdentityVerification.verifyIssuanceIdentity(issuanceTx, identityTx);
```

### Creating a Witness

After issuance (or after a transfer), a **witness transaction** must be created to prove
ownership. The witness spends PP1 and PP2 from the token transaction and produces a single
output locked to the current owner.

```dart
// Create a witness for a newly issued token
var witnessTx = service.createWitnessTxn(
    fundingSigner,          // signs funding input and PP1
    fundingTx,              // funding transaction (output[1] provides satoshis)
    issuanceTx,             // the token transaction to witness
    List<int>.empty(),      // parentTokenTxBytes: empty for issuance (no parent)
    issuerPubKey,           // current owner's public key
    issuerAddress.pubkeyHash160,  // owner's pubkey hash (hex string)
    TokenAction.ISSUANCE,   // action type: ISSUANCE for newly minted tokens
);

// The witness transaction has 1 output (locked to the owner)
assert(witnessTx.outputs.length == 1);
```

For a **transfer witness** (witnessing a token that was received via transfer), provide the
full serialized bytes of the parent token transaction:

```dart
var transferWitnessTx = service.createWitnessTxn(
    recipientFundingSigner,
    recipientFundingTx,
    transferredTokenTx,
    hex.decode(parentTokenTx.serialize()),  // full serialized parent token tx bytes
    recipientPubKey,
    senderPubkeyHash,    // PKH used for token change in the transfer
    TokenAction.TRANSFER,
);
```

### Transferring a Token

Token transfer moves ownership from the current holder to a new recipient. It spends
the previous witness output and the PartialWitness (output[3]) from the current token transaction.

```dart
// Extract the tokenId from the current token transaction's PP1 output
var pp1 = PP1LockBuilder.fromScript(currentTokenTx.outputs[1].script);
var tokenId = pp1.tokenId ?? [];

// The recipient must have a funding transaction ready for their future witness
var recipientFundingTx = Transaction.fromHex("...");  // recipient's witness funding tx

// Create the transfer transaction
var transferTx = service.createTokenTransferTxn(
    currentWitnessTx,             // the existing witness transaction
    currentTokenTx,               // the current token transaction being spent
    currentOwnerPubKey,           // current owner's public key
    recipientAddress,             // recipient's address
    transferFundingTx,            // funding tx for this transfer (current owner funds it)
    currentOwnerFundingSigner,    // signer for the funding input
    currentOwnerPubKey,           // public key for the funding UTXO unlock
    recipientFundingTx.hash,      // recipient's witness funding txId (in raw tx byte order)
    tokenId,                      // the token identifier (carried forward from issuance)
);

// The transfer transaction preserves the 5-output structure
// Metadata (output[4]) is automatically carried forward from the parent token tx
```

After the transfer, the **recipient** must create a witness transaction for their new token:

```dart
var recipientWitnessTx = service.createWitnessTxn(
    recipientFundingSigner,
    recipientFundingTx,
    transferTx,
    hex.decode(currentTokenTx.serialize()),  // parent token tx bytes (the tx that was spent)
    recipientPubKey,
    currentOwnerAddress.pubkeyHash160,       // token change PKH from the transfer
    TokenAction.TRANSFER,
);
```

### Burning a Token

Burning permanently destroys a token by spending all three proof-point outputs (PP1, PP2,
PartialWitness) without creating new token outputs. Only the current owner can burn.

```dart
var burnTx = service.createBurnTokenTxn(
    currentTokenTx,       // the token transaction to burn
    ownerSigner,          // owner's transaction signer
    ownerPubKey,          // owner's public key
    burnFundingTx,        // funding transaction for the burn
    fundingSigner,        // signer for the funding input
    fundingPubKey,        // public key for the funding UTXO unlock
);

// The burn transaction has only 1 output (change back to the owner)
assert(burnTx.outputs.length == 1);
```

## Error Handling

The library's lock and unlock builders throw `ScriptException` (from the `dartsv` package) when
provided with invalid inputs. Common cases include:

- **Wrong-length pubkey hash (PKH)**: PKH values must be exactly 20 bytes (40 hex characters).
- **Wrong-length tokenId**: Token identifiers must be exactly 32 bytes.
- **Invalid outpoint format**: Witness funding outpoints must be 36 bytes (32-byte txId + 4-byte output index).

Catch `ScriptException` to handle these gracefully:

```dart
try {
    var tx = await service.createTokenIssuanceTxn(...);
} on ScriptException catch (e) {
    print('Script error: ${e.error} - ${e.cause}');
}
```

## Troubleshooting

### "Transaction verification fails"

- Ensure the **witness funding outpoint** matches exactly. The funding transaction must have satoshis at `output[1]`, and the txId used in PP2 must correspond to the actual witness funding transaction.
- Check that **padding bytes** are correct. The `createWitnessTxn` method calculates padding automatically, but if you are constructing transactions manually, the padding must align the witness transaction to a 64-byte SHA-256 block boundary.

### "PP1 spending fails on transfer"

- The `parentTokenTxBytes` parameter must be the **full serialized parent token transaction** bytes (via `hex.decode(parentTokenTx.serialize())`), not an empty list. Only issuance witnesses use an empty parent.
- Verify that the `tokenId` carried into the transfer matches the original tokenId from the issuance PP1 output.

### "Burn fails"

- Only the **current owner** (the key matching the `ownerPKH` embedded in PP2 and PartialWitness) can burn a token.
- The `ownerSigner` must use the same private key that corresponds to the public key embedded in the token's locking scripts.
- The funding transaction must have sufficient satoshis at `output[1]` to cover the burn transaction fee.

## License

Apache License 2.0
