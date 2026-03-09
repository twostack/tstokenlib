// Fungible Token Lifecycle Example
// Demonstrates: minting, witness creation, transfer, split, merge, and burn
//
// IMPORTANT: This is demonstrative code. It cannot run standalone because it
// requires real funding transactions from the BSV blockchain. The funding
// transaction hex strings used here are from the test suite and work only
// with the corresponding private keys.
//
// For runnable tests, see: test/fungible_token_test.dart

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/tstokenlib.dart';

/// Simulates obtaining a funding transaction from the blockchain.
/// In production, this would come from a wallet or blockchain query.
/// The funding transaction MUST have satoshis available at output[1].
Transaction getFundingTx(String rawHex) {
  return Transaction.fromHex(rawHex);
}

/// Demonstrates the full fungible token lifecycle:
///   1. Mint — create a new fungible token with a specified amount
///   2. Witness — prove ownership of the minted token
///   3. Transfer — send the full token amount to a new owner
///   4. Witness — recipient proves ownership
///   5. Split — divide a token into two amounts (recipient + change)
///   6. Witness — witnesses for both split outputs
///   7. Merge — combine two token UTXOs back into one
///   8. Witness — prove ownership of the merged token
///   9. Burn — destroy the token permanently
Future<void> main() async {
  // =========================================================================
  // KEY SETUP
  // =========================================================================
  // Each participant needs a private key and corresponding address.

  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  // --- Issuer / Initial Owner (Bob) ---
  var bobPrivateKey = SVPrivateKey.fromWIF("cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS");
  var bobPubKey = bobPrivateKey.publicKey;
  var bobAddress = Address.fromPublicKey(bobPubKey, NetworkType.TEST);
  var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";
  var bobSigner = TransactionSigner(sigHashAll, bobPrivateKey);

  // --- Recipient (Alice) ---
  var alicePrivateKey = SVPrivateKey.fromWIF("cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5");
  var alicePubKey = alicePrivateKey.publicKey;
  var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
  var aliceSigner = TransactionSigner(sigHashAll, alicePrivateKey);

  // The FungibleTokenTool is the primary API for all fungible token operations.
  var tokenTool = FungibleTokenTool(networkType: NetworkType.TEST);

  // Funding transactions (in practice, each operation needs a fresh funding tx)
  var bobFundingTx = getFundingTx(
    "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c"
    "000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd98239"
    "9c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe"
    "9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278a"
    "f36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c4"
    "88ac65000000",
  );

  var aliceFundingTx = getFundingTx(
    "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e"
    "000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28"
    "a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d406"
    "44772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3"
    "807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c3"
    "5288ac6b000000",
  );

  // =========================================================================
  // STEP 1: MINT FUNGIBLE TOKENS
  // =========================================================================
  // Minting creates a new fungible token with a specified amount. This produces
  // a transaction with 5 outputs (the "triplet" pattern):
  //   output[0] = Change (remaining satoshis from funding)
  //   output[1] = PP5 (Proof Point 5 — embeds ownerPKH, tokenId, amount)
  //   output[2] = PP2-FT (validates witness funding outpoint)
  //   output[3] = PP3-FT (enables transfer via partial SHA-256)
  //   output[4] = Metadata (OP_RETURN — token metadata)
  //
  // The tokenId is derived from the funding transaction hash.

  print("=== STEP 1: Mint 1000 Fungible Tokens ===");

  var mintTx = await tokenTool.createFungibleMintTxn(
    bobFundingTx,         // funding transaction
    bobSigner,            // signs the funding input
    bobPubKey,            // minter's public key
    bobAddress,           // minter's address (receives the token)
    bobFundingTx.hash,    // becomes the tokenId
    1000,                 // amount to mint
  );

  // Extract token metadata from the PP5 output
  var pp5Lock = PP5LockBuilder.fromScript(mintTx.outputs[1].script);
  var tokenId = pp5Lock.tokenId;

  print("Mint TxId: ${mintTx.id}");
  print("Token ID: ${hex.encode(tokenId)}");
  print("Amount: ${pp5Lock.amount}");
  print("Outputs: ${mintTx.outputs.length}"); // expect 5

  // =========================================================================
  // STEP 2: CREATE MINT WITNESS
  // =========================================================================
  // After minting, a witness transaction proves the owner controls the token.
  // The witness spends PP5 and PP2-FT from the mint transaction.
  //
  // For minting, no parent token tx bytes are needed (this is the genesis).

  print("\n=== STEP 2: Mint Witness ===");

  var mintWitnessTx = tokenTool.createFungibleWitnessTxn(
    bobSigner,              // signs funding and PP5 inputs
    bobFundingTx,           // funding transaction
    mintTx,                 // the token transaction to witness
    bobPubKey,              // owner's public key
    bobPubkeyHash,          // owner's pubkey hash (hex string)
    FungibleTokenAction.MINT,
  );

  print("Mint Witness TxId: ${mintWitnessTx.id}");
  print("Witness outputs: ${mintWitnessTx.outputs.length}"); // expect 1

  // =========================================================================
  // STEP 3: TRANSFER (Bob -> Alice)
  // =========================================================================
  // Transfer sends the full token amount to a new owner. The transaction
  // spends the previous witness output and PP3-FT from the token tx.
  //
  // The transfer creates a new triplet (PP5, PP2-FT, PP3-FT) locked to
  // the recipient. Metadata is carried forward automatically.

  print("\n=== STEP 3: Transfer 1000 tokens (Bob -> Alice) ===");

  var transferTx = tokenTool.createFungibleTransferTxn(
    mintWitnessTx,          // previous witness transaction
    mintTx,                 // previous token transaction
    bobPubKey,              // current owner's public key
    aliceAddress,           // recipient's address
    bobFundingTx,           // funding tx (Bob pays the fee)
    bobSigner,              // signs the funding input
    bobPubKey,              // funding UTXO public key
    aliceFundingTx.hash,    // Alice's witness funding txId
    tokenId,                // token identifier
    1000,                   // full amount being transferred
  );

  print("Transfer TxId: ${transferTx.id}");
  print("Transfer outputs: ${transferTx.outputs.length}"); // expect 5

  // Verify the PP5 output has Alice as the new owner
  var transferPP5 = PP5LockBuilder.fromScript(transferTx.outputs[1].script);
  print("New owner PKH: ${hex.encode(transferPP5.recipientPKH)}");
  print("Amount: ${transferPP5.amount}");

  // =========================================================================
  // STEP 4: TRANSFER WITNESS (Alice proves ownership)
  // =========================================================================
  // The recipient must create a witness to prove ownership. This requires
  // the full serialized bytes of the PARENT token transaction.

  print("\n=== STEP 4: Transfer Witness (Alice) ===");

  var transferWitnessTx = tokenTool.createFungibleWitnessTxn(
    aliceSigner,                                // Alice signs
    aliceFundingTx,                             // Alice's funding tx
    transferTx,                                 // the transfer tx to witness
    alicePubKey,                                // Alice's public key
    bobPubkeyHash,                              // token change PKH
    FungibleTokenAction.TRANSFER,
    parentTokenTxBytes: hex.decode(mintTx.serialize()),  // serialized parent tx
    parentOutputCount: 5,                       // parent had 5 outputs
  );

  print("Transfer Witness TxId: ${transferWitnessTx.id}");

  // =========================================================================
  // STEP 5: SPLIT (Alice splits 1000 into 700 + 300)
  // =========================================================================
  // Split divides a token into two outputs: a recipient amount and change.
  // This creates an 8-output transaction with two triplets:
  //   Recipient triplet: outputs [1,2,3] — PP5(700), PP2-FT, PP3-FT
  //   Change triplet:    outputs [4,5,6] — PP5(300), PP2-FT, PP3-FT
  //   output[0] = Change (satoshis)
  //   output[7] = Metadata
  //
  // Both triplets need separate witness funding transactions.

  print("\n=== STEP 5: Split 1000 -> 700 (Bob) + 300 (Alice change) ===");

  var splitTx = tokenTool.createFungibleSplitTxn(
    transferWitnessTx,        // previous witness
    transferTx,               // previous token tx
    alicePubKey,              // current owner (Alice)
    bobAddress,               // recipient gets 700
    700,                      // send amount
    aliceFundingTx,           // funding tx
    aliceSigner,              // funding signer
    alicePubKey,              // funding public key
    bobFundingTx.hash,        // recipient's witness funding txId
    aliceFundingTx.hash,      // change witness funding txId
    tokenId,                  // token identifier
    1000,                     // total amount before split
  );

  print("Split TxId: ${splitTx.id}");
  print("Split outputs: ${splitTx.outputs.length}"); // expect 8

  var recipientPP5 = PP5LockBuilder.fromScript(splitTx.outputs[1].script);
  var changePP5 = PP5LockBuilder.fromScript(splitTx.outputs[4].script);
  print("Recipient (Bob) amount: ${recipientPP5.amount}");   // 700
  print("Change (Alice) amount: ${changePP5.amount}");        // 300

  // =========================================================================
  // STEP 6: SPLIT WITNESSES
  // =========================================================================
  // After a split, BOTH triplets need witnesses.
  // The recipient triplet has base index 1, the change triplet has base index 4.

  print("\n=== STEP 6: Witnesses for both split outputs ===");

  // Witness for recipient triplet (Bob, base index 1)
  var recipientWitnessTx = tokenTool.createFungibleWitnessTxn(
    bobSigner, bobFundingTx, splitTx,
    bobPubKey, bobPubkeyHash,
    FungibleTokenAction.SPLIT_TRANSFER,
    parentTokenTxBytes: hex.decode(transferTx.serialize()),
    parentOutputCount: 5,
    tripletBaseIndex: 1,     // recipient triplet
  );

  // Witness for change triplet (Alice, base index 4)
  var changeWitnessTx = tokenTool.createFungibleWitnessTxn(
    aliceSigner, aliceFundingTx, splitTx,
    alicePubKey, bobPubkeyHash,
    FungibleTokenAction.SPLIT_TRANSFER,
    parentTokenTxBytes: hex.decode(transferTx.serialize()),
    parentOutputCount: 5,
    tripletBaseIndex: 4,     // change triplet
  );

  print("Recipient Witness TxId: ${recipientWitnessTx.id}");
  print("Change Witness TxId: ${changeWitnessTx.id}");

  // =========================================================================
  // STEP 7: MERGE (700 + 300 = 1000)
  // =========================================================================
  // Merge combines two token UTXOs (from the same token) into a single output.
  // Both UTXOs must have the same tokenId and be owned by the same key.
  //
  // The merge transaction has 5 inputs:
  //   input[0] = Funding
  //   input[1] = Witness A (ModP2PKH)
  //   input[2] = Witness B (ModP2PKH)
  //   input[3] = PP3-FT A burn (P2PKH — burned, not fully unlocked)
  //   input[4] = PP3-FT B burn
  //
  // PP3 inputs are burned via P2PKH rather than unlocked, because PP3-FT's
  // hashPrevOuts check hardcodes 3 inputs and cannot work with 5.
  // Security is maintained: PP5 verifies outpoints reference the parent txs.

  print("\n=== STEP 7: Merge 700 + 300 = 1000 ===");

  // Both split outputs belong to different owners in this example.
  // For merge to work, both must be owned by the same key.
  // In practice, Bob would merge two UTXOs he owns.
  // Here we use Bob's recipient (700) and pretend he also owns the change (300).

  var mergeTx = tokenTool.createFungibleMergeTxn(
    recipientWitnessTx,       // witness for UTXO A (700)
    splitTx,                  // token tx A (contains both UTXOs)
    changeWitnessTx,          // witness for UTXO B (300)
    splitTx,                  // token tx B (same tx in this case)
    bobPubKey,                // owner (must own both UTXOs)
    bobSigner,                // owner's signer
    bobFundingTx,             // funding tx
    bobSigner,                // funding signer
    bobPubKey,                // funding public key
    bobFundingTx.hash,        // merged witness funding txId
    tokenId,                  // token identifier
    1000,                     // total merged amount (700 + 300)
    prevTripletBaseIndexA: 1, // UTXO A at triplet base 1
    prevTripletBaseIndexB: 4, // UTXO B at triplet base 4
  );

  print("Merge TxId: ${mergeTx.id}");
  print("Merge outputs: ${mergeTx.outputs.length}"); // expect 5

  var mergedPP5 = PP5LockBuilder.fromScript(mergeTx.outputs[1].script);
  print("Merged amount: ${mergedPP5.amount}"); // 1000

  // =========================================================================
  // STEP 8: MERGE WITNESS
  // =========================================================================
  // The merge witness requires BOTH parent token tx bytes.

  print("\n=== STEP 8: Merge Witness ===");

  var splitTxBytes = hex.decode(splitTx.serialize());

  var mergeWitnessTx = tokenTool.createFungibleWitnessTxn(
    bobSigner, bobFundingTx, mergeTx,
    bobPubKey, bobPubkeyHash,
    FungibleTokenAction.MERGE,
    parentTokenTxBytes: splitTxBytes,       // parent A bytes
    parentTokenTxBytesB: splitTxBytes,      // parent B bytes (same tx here)
    parentOutputCount: 8,                   // parent A had 8 outputs
    parentOutputCountB: 8,                  // parent B had 8 outputs
    parentPP5IndexA: 1,                     // PP5 A at output index 1
    parentPP5IndexB: 4,                     // PP5 B at output index 4
  );

  print("Merge Witness TxId: ${mergeWitnessTx.id}");

  // =========================================================================
  // STEP 9: BURN TOKEN
  // =========================================================================
  // Burning destroys the token permanently. It spends PP5, PP2-FT, and PP3-FT
  // without creating new token outputs. Only the current owner can burn.
  // The burn transaction has a single output — change returned to the owner.

  print("\n=== STEP 9: Burn Token ===");

  var burnTx = tokenTool.createFungibleBurnTxn(
    mergeTx,            // the token transaction to burn
    bobSigner,          // owner's signer
    bobPubKey,          // owner's public key
    bobFundingTx,       // funding transaction
    bobSigner,          // funding signer
    bobPubKey,          // funding public key
  );

  print("Burn TxId: ${burnTx.id}");
  print("Burn outputs: ${burnTx.outputs.length}"); // expect 1 (change only)

  // =========================================================================
  // VERIFICATION
  // =========================================================================
  // You can verify script spending conditions using the Interpreter.
  // This is useful for testing and debugging.

  print("\n=== Verification ===");

  var interp = Interpreter();
  var verifyFlags = <VerifyFlag>{
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  // Verify PP5 burn spending
  try {
    interp.correctlySpends(
      burnTx.inputs[1].script!, mergeTx.outputs[1].script,
      burnTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis),
    );
    print("PP5 burn verification: PASS");
  } on ScriptException catch (e) {
    print("PP5 burn verification: FAIL - $e");
  }

  // Verify PP5 merge witness spending
  try {
    interp.correctlySpends(
      mergeWitnessTx.inputs[1].script!, mergeTx.outputs[1].script,
      mergeWitnessTx, 1, verifyFlags, Coin.valueOf(mergeTx.outputs[1].satoshis),
    );
    print("PP5 merge witness verification: PASS");
  } on ScriptException catch (e) {
    print("PP5 merge witness verification: FAIL - $e");
  }

  print("\nFungible token lifecycle example complete.");
}
