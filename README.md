
## Overview
The TSL1 Token Protocol allows for the creation of P2P tokens on Bitcoin (BSV) that have the following features:

- Fully miner-validated tokens
- No indexers are required to track token state or to guard against double-spends
- No back-to-genesis tracing within the UTXO set
- No transaction bloating with successive token transfers
- Double-spend protection with the same level of security as the native token units (satoshis)

(Download a copy of the whitepaper for a full technical explanation)[https://github.com/twostack/tsl1]

### NOTE: 
This library is meant as a technology demonstrator. It is not at present time meant for production use.
There are key components missing from this library, most notably it lacks the attachment of token 
metadata and issuer identity. 
As such, it is at present an *Alpha Release* at best, NOT PRODUCTION READY, and useful for early experimentation. 

Code contributions are welcome and encouraged. 

## Usage
For more complete example code please refer to the unit tests within the library's source code repository. 

### Issuing a new token 

```dart 
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    var fundingTx = getBobFundingTx();
    var fundingTxSigner = TransactionSigner(sigHashAll, bobPrivateKey);

    var issuanceTxn = service.createTokenIssuanceTxn(fundingTx, fundingTxSigner, bobPub, bobAddress, fundingTx.hash);
```

### Transferring a newly issued token

```dart
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    var fundingTx = getBobFundingTx();
    var fundingTxSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTxn = service.createTokenIssuanceTxn(fundingTx, fundingTxSigner, bobPub, bobAddress, fundingTx.hash);
    //weak tests for now. stronger ones follow
    expect(issuanceTxn.outputs.length, 4);
    expect(issuanceTxn.inputs.length, 1);

    var witnessTx = service.createWitnessTxn(
      fundingTxSigner,
      fundingTx,
      issuanceTxn,
      List<int>.empty(),
      /*no issuance*/
      bobPub,
      //owner pubkey
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      //owner pubkey
      TokenAction.ISSUANCE,
    );
```
