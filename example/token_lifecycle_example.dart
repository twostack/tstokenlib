// Token Lifecycle Example
// Demonstrates: issuance, witness creation, transfer, and burn
//
// IMPORTANT: This is demonstrative code. It cannot run standalone because it
// requires real funding transactions from the BSV blockchain. The funding
// transaction hex strings used here are placeholders showing the expected
// structure.
//
// For runnable tests, see: test/plugpoint_spending_test.dart

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';

/// Simulates obtaining a funding transaction from the blockchain.
/// In production, this would come from a wallet or blockchain query.
/// The funding transaction MUST have satoshis available at output[1].
Transaction getFundingTx(String rawHex) {
  return Transaction.fromHex(rawHex);
}

/// Demonstrates the full token lifecycle:
///   1. Issuance — create a new token
///   2. Witness — prove ownership of the issued token
///   3. Transfer — send the token to a new owner
///   4. Witness (recipient) — recipient proves ownership
///   5. Burn — destroy the token
Future<void> main() async {
  // =========================================================================
  // KEY SETUP
  // =========================================================================
  // In a real application, keys would come from a wallet.
  // Each participant needs a private key and corresponding address.

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  // --- Issuer / Initial Owner (Bob) ---
  var bobPrivateKey = SVPrivateKey.fromWIF("cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS");
  var bobPubKey = bobPrivateKey.publicKey;
  var bobAddress = Address.fromPublicKey(bobPubKey, NetworkType.TEST);
  var bobSigner = TransactionSigner(sigHashAll, bobPrivateKey);

  // --- Recipient (Alice) ---
  var alicePrivateKey = SVPrivateKey.fromWIF("cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5");
  var alicePubKey = alicePrivateKey.publicKey;
  var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
  var aliceSigner = TransactionSigner(sigHashAll, alicePrivateKey);

  // --- Rabin Identity Keypair ---
  // A Rabin keypair is required for identity anchoring in PP1.
  // The Rabin signature proves identity binding during issuance witness creation.
  var rabinKeyPair = Rabin.generateKeyPair(1024);
  var rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n).toList();
  var rabinPubKeyHash = hash160(rabinNBytes);

  // Identity anchoring data (in production, use real identity anchor tx)
  var dummyIdentityTxId = List<int>.generate(32, (i) => i + 1);
  var dummyEd25519PubKey = List<int>.generate(32, (i) => i + 0x41);

  // Sign the identity binding message with the Rabin key
  var identityMessage = [...dummyIdentityTxId, ...dummyEd25519PubKey];
  var messageHash = Rabin.sha256ToScriptInt(identityMessage);
  var rabinSig = Rabin.sign(messageHash, rabinKeyPair.p, rabinKeyPair.q);
  var rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s).toList();

  // The TokenTool is the primary API for all token operations.
  var tokenTool = TokenTool(networkType: NetworkType.TEST);

  // =========================================================================
  // STEP 1: TOKEN ISSUANCE
  // =========================================================================
  // The issuer creates a new token. This produces a transaction with 5 outputs:
  //   output[0] = Change (remaining satoshis)
  //   output[1] = PP1 (Proof Point 1 — inductive proof, embeds tokenId)
  //   output[2] = PP2 (Proof Point 2 — validates witness funding outpoint)
  //   output[3] = PartialWitness (enables transfer via partial SHA-256)
  //   output[4] = Metadata (OP_RETURN — optional metadata or issuer identity)
  //
  // The funding transaction must have satoshis at output[1].

  var bobFundingTx = getFundingTx(
    "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c"
    "000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd98239"
    "9c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe"
    "9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278a"
    "f36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c4"
    "88ac65000000",
  );

  print("=== STEP 1: Token Issuance ===");

  var issuanceTx = await tokenTool.createTokenIssuanceTxn(
    bobFundingTx,      // funding transaction
    bobSigner,         // signs the funding input
    bobPubKey,         // issuer's public key
    bobAddress,        // recipient address (issuer receives token initially)
    bobFundingTx.hash, // witness funding txId (raw byte order)
    rabinPubKeyHash,   // hash160 of Rabin public key for identity anchoring
  );

  print("Issuance TxId: ${issuanceTx.id}");
  print("Issuance outputs: ${issuanceTx.outputs.length}"); // expect 5

  // =========================================================================
  // STEP 1b (OPTIONAL): ISSUANCE WITH ISSUER IDENTITY
  // =========================================================================
  // You can anchor the token to a verified issuer identity using ED25519
  // signatures. This creates a cryptographic link between the token and
  // an on-chain identity anchor transaction.

  var ed25519 = Ed25519();
  var identityKeyPair = await ed25519.newKeyPair();
  var identityWand = await ed25519.newSignatureWandFromKeyPair(identityKeyPair);

  // First, create an identity anchor transaction on-chain
  var identityBuilder = IdentityAnchorBuilder({
    'name': 'Example Token Issuer',
    'org': 'Example Organization',
  });

  var identityTx = await identityBuilder.buildTransaction(
    bobFundingTx, bobSigner, bobPubKey, bobAddress, identityWand,
  );
  print("\nIdentity Anchor TxId: ${identityTx.id}");

  // Then issue a token linked to this identity
  // (In practice you would use a separate funding tx for each on-chain tx)
  // var identityLinkedIssuance = await tokenTool.createTokenIssuanceTxn(
  //     anotherFundingTx, bobSigner, bobPubKey, bobAddress, anotherFundingTx.hash,
  //     identityTxId: identityTx.hash,
  //     issuerWand: identityWand,
  // );
  //
  // Verify the link later:
  // var isValid = await IdentityVerification.verifyIssuanceIdentity(
  //     identityLinkedIssuance, identityTx);

  // =========================================================================
  // STEP 2: CREATE WITNESS FOR ISSUANCE
  // =========================================================================
  // After issuance, a witness transaction must be created. The witness proves
  // that the owner controls the token by spending PP1 and PP2 from the token
  // transaction. The witness has a single output locked to the current owner.
  //
  // For issuance, parentTokenTxBytes is empty (there is no parent token).

  print("\n=== STEP 2: Witness for Issuance ===");

  var issuanceWitnessTx = tokenTool.createWitnessTxn(
    bobSigner,                  // signs funding input and PP1
    bobFundingTx,               // funding transaction (output[1])
    issuanceTx,                 // the token transaction to witness
    List<int>.empty(),          // no parent token tx bytes for issuance
    bobPubKey,                  // current owner's public key
    bobAddress.pubkeyHash160,   // owner's pubkey hash (hex string, 40 chars)
    TokenAction.ISSUANCE,       // this is an issuance witness
    rabinN: rabinNBytes,
    rabinS: rabinSBytes,
    rabinPadding: rabinSig.padding,
    identityTxId: dummyIdentityTxId,
    ed25519PubKey: dummyEd25519PubKey,
  );

  print("Issuance Witness TxId: ${issuanceWitnessTx.id}");
  print("Witness outputs: ${issuanceWitnessTx.outputs.length}"); // expect 1

  // =========================================================================
  // STEP 3: TRANSFER TOKEN (Bob -> Alice)
  // =========================================================================
  // To transfer a token, the current owner spends the witness output and the
  // PartialWitness output (output[3]) from the current token transaction.
  //
  // The recipient must have a funding transaction ready — this will be used
  // for the recipient's future witness transaction.
  //
  // The tokenId is extracted from PP1 and carried forward across transfers.

  print("\n=== STEP 3: Transfer (Bob -> Alice) ===");

  // Extract tokenId from the issuance PP1 output
  var pp1 = PP1NftLockBuilder.fromScript(issuanceTx.outputs[1].script);
  var tokenId = pp1.tokenId ?? [];
  print("TokenId: ${hex.encode(tokenId)}");

  // Alice's funding transaction (for her future witness)
  var aliceFundingTx = getFundingTx(
    "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e"
    "000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28"
    "a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d406"
    "44772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3"
    "807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c3"
    "5288ac6b000000",
  );

  // Bob funds the transfer using his own funding tx
  var transferFundingTx = bobFundingTx; // In practice, use a fresh funding tx

  var transferTx = tokenTool.createTokenTransferTxn(
    issuanceWitnessTx,        // previous witness transaction
    issuanceTx,               // previous token transaction
    bobPubKey,                // current owner's public key
    aliceAddress,             // recipient's address
    transferFundingTx,        // funding tx for this transfer (Bob pays)
    bobSigner,                // signs the funding input
    bobPubKey,                // public key for funding UTXO unlock
    aliceFundingTx.hash,      // Alice's witness funding txId (raw byte order)
    tokenId,                  // token identifier (carried from issuance)
  );

  print("Transfer TxId: ${transferTx.id}");
  print("Transfer outputs: ${transferTx.outputs.length}"); // expect 5+change
  // Note: metadata (output[4]) is automatically carried forward from the parent tx

  // =========================================================================
  // STEP 4: CREATE WITNESS FOR TRANSFER (Alice witnesses her token)
  // =========================================================================
  // After receiving a token via transfer, the recipient must create a witness.
  //
  // Key differences from issuance witness:
  //   - parentTokenTxBytes must contain the FULL serialized parent token tx
  //   - action is TokenAction.TRANSFER (not ISSUANCE)
  //   - The signer is the recipient (Alice), not the original issuer

  print("\n=== STEP 4: Witness for Transfer (Alice) ===");

  var aliceWitnessTx = tokenTool.createWitnessTxn(
    aliceSigner,                              // Alice signs
    aliceFundingTx,                           // Alice's funding transaction
    transferTx,                               // the token tx Alice received
    hex.decode(issuanceTx.serialize()),        // full serialized parent token tx
    alicePubKey,                              // Alice's public key
    bobAddress.pubkeyHash160,                 // token change PKH (Bob's, from the transfer)
    TokenAction.TRANSFER,                     // this is a transfer witness
  );

  print("Alice Witness TxId: ${aliceWitnessTx.id}");

  // =========================================================================
  // STEP 5: BURN TOKEN
  // =========================================================================
  // Burning destroys the token permanently. It spends PP1, PP2, and
  // PartialWitness outputs without creating new token outputs.
  //
  // Only the current owner can burn. The burn transaction has a single
  // output — change returned to the owner.

  print("\n=== STEP 5: Burn Token ===");

  // To burn the issuance token (if Bob hadn't transferred it):
  var burnFundingTx = bobFundingTx; // In practice, use a fresh funding tx

  var burnTx = tokenTool.createBurnTokenTxn(
    issuanceTx,       // the token transaction to burn
    bobSigner,        // owner's transaction signer
    bobPubKey,        // owner's public key
    burnFundingTx,    // funding transaction for the burn
    bobSigner,        // signer for the funding input
    bobPubKey,        // public key for funding UTXO unlock
  );

  print("Burn TxId: ${burnTx.id}");
  print("Burn outputs: ${burnTx.outputs.length}"); // expect 1 (change only)

  // =========================================================================
  // VERIFICATION (Optional)
  // =========================================================================
  // You can verify that script spending conditions are met using the
  // Interpreter class from dartsv. This is useful for testing and debugging.

  print("\n=== Verification ===");

  var interp = Interpreter();
  var verifyFlags = <VerifyFlag>{
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  // Verify PP1 spending in the issuance witness
  try {
    var scriptSig = issuanceWitnessTx.inputs[1].script!;
    var scriptPubKey = issuanceTx.outputs[1].script;
    var outputSats = issuanceTx.outputs[1].satoshis;
    interp.correctlySpends(
      scriptSig, scriptPubKey, issuanceWitnessTx, 1, verifyFlags, Coin.valueOf(outputSats),
    );
    print("PP1 spending verification: PASS");
  } on ScriptException catch (e) {
    print("PP1 spending verification: FAIL - ${e.error}: ${e.cause}");
  }

  // Verify PP2 spending in the issuance witness
  try {
    var scriptSig = issuanceWitnessTx.inputs[2].script!;
    var scriptPubKey = issuanceTx.outputs[2].script;
    var outputSats = issuanceTx.outputs[2].satoshis;
    interp.correctlySpends(
      scriptSig, scriptPubKey, issuanceWitnessTx, 2, verifyFlags, Coin.valueOf(outputSats),
    );
    print("PP2 spending verification: PASS");
  } on ScriptException catch (e) {
    print("PP2 spending verification: FAIL - ${e.error}: ${e.cause}");
  }

  print("\nToken lifecycle example complete.");
}
