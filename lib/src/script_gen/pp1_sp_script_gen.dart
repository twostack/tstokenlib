/*
  Copyright 2024 - Stephan M. February

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import '../shielded_pool/pool_header.dart';
import '../shielded_pool/pool_out_hash.dart';
import '../shielded_pool/pool_outputs.dart';
import 'opcode_helpers.dart';
import 'check_preimage_ocs.dart';
import 'pp1_ft_script_gen.dart';

/// Generates the complete PP1_SP (shielded pool) locking script.
///
/// PP1_SP began as a clone of PP1_SM and carried the state machine's nine-field
/// header. A pool has no escrow lifecycle, no counterparty and no timeout, so
/// that header is gone. What is left is the smallest thing a TSL1 token needs
/// plus the pool's own state:
///
/// ```
/// [0:1]     0x14       [1:21]    ownerPKH         (20,  mutable)
/// [21:22]   0x20       [22:54]   tokenId          (32,  immutable)
/// [54:55]   0x20       [55:87]   verifierBodyHash (32,  immutable)
/// [87:89]   0x4c 0xec  [89:325]  genesisHeader    (236, immutable)
/// [325:327] 0x4c 0xec  [327:563] header           (236, mutable)  see [PoolHeader]
/// [563:]    script body (immutable)
/// ```
///
/// Each 236-byte header needs OP_PUSHDATA1, hence a two-byte prefix where every
/// other field has one. A header is one push rather than six fields because
/// both places that touch it want it whole: PP1's rebuild substitutes the
/// entire region in a single fixed window, and the verifier slot script V
/// embeds the same blob, so PP1 can bind V to `header_{N+1}` by rebuilding
/// `push(header) + body` and comparing one hash.
///
/// `genesisHeader` is carried in full rather than as a hash, which costs 236
/// bytes in every round. What it buys is that the state a pool opened on is
/// readable straight off the chain. A depositor can check that the commitment
/// tree started empty before putting money in; with only a commitment they
/// would have to be handed the preimage and trust it. It also keeps the script
/// body identical across pools, so one template serves all of them.
///
/// `verifierBodyHash` is a header field for the same second reason: baked into
/// the body it would give every circuit configuration its own template. It
/// identifies which verifier this pool's rounds must be checked by.
///
/// Two branches, dispatched on a selector left on top of the stack:
///
/// - **OP_0 create**: TSL1 issuance. Anchors `tokenId` to the funding outpoint
///   and requires the header to equal `genesisHeader`.
/// - **OP_1 round**: the inductive transfer, one round of the pool. Rebuilds
///   the round it lives in and substitutes `ownerPKH` and `header`.
///
/// There is no burn branch. TSL1's burn spends PP1, PP2 and PP3 on the owner's
/// signature alone; here the owner is the coordinator and PP3 holds every
/// depositor's money, so a signature must not be able to release it. A shutdown
/// path, if one is wanted, has to be a proved transition to an empty pool.
///
/// There is also no Rabin issuer attestation. For an SM token it binds the
/// token to a registered issuer identity; for a pool, who the coordinator is
/// *is* `ownerPKH`, and what makes the chain unique is the funding outpoint the
/// create branch anchors to. Attesting the coordinator's identity, if a
/// deployment wants it, belongs in the metadata output, not in the covenant.
class PP1SpScriptGen {

  static const int pkhDataStart = 1;
  static const int pkhDataEnd = 21;
  static const int tokenIdDataStart = 22;
  static const int tokenIdDataEnd = 54;
  static const int verifierBodyHashDataStart = 55;
  static const int verifierBodyHashDataEnd = 87;

  /// Each header push is `OP_PUSHDATA1 0xec`, two bytes, so its data starts two
  /// bytes after the push rather than one.
  static const int genesisPushStart = verifierBodyHashDataEnd;  // 87
  static const int genesisDataStart = genesisPushStart + 2;     // 89
  static const int genesisDataEnd = genesisDataStart + PoolHeader.byteSize; // 325

  static const int headerPushStart = genesisDataEnd;        // 325
  static const int headerDataStart = headerPushStart + 2;   // 327
  static const int headerDataEnd = headerDataStart + PoolHeader.byteSize; // 563
  static const int scriptBodyStart = headerDataEnd;

  /// The immutable run between the mutable ownerPKH and the mutable header: the
  /// tokenId push, the verifier body hash, the genesis header push, and the
  /// header's own two-byte prefix. The rebuild copies it across untouched.
  static const int immutableMidStart = pkhDataEnd;          // 21
  static const int immutableMidLength = headerDataStart - pkhDataEnd; // 306

  /// A pool PP3 begins `<0x24> nextSlot(36) OP_TOALTSTACK ...`, so the
  /// outpoint it pins the next round to is a fixed window at offset 1. It has
  /// no owner push: a pool PP3 has no burn path, so there is nobody to name.
  static const int pp3NextSlotStart = 1;
  static const int pp3NextSlotEnd = 37;

  /// Where a pool round spends its verifier slot and its parent's PP3.
  ///
  /// Every other TSL1 archetype spends PP3 at input 2. A pool swaps the two,
  /// because PP3's forward covenant signs SIGHASH_SINGLE, whose hashOutputs
  /// covers the output at the spending input's own index, and the output PP3
  /// has to constrain is its successor at output 3.
  static const int poolSlotInput = 2;
  static const int poolPP3Input = 3;

  static const int pp2FundingOutpointStart = 117;
  static const int pp2WitnessChangePKHStart = 154;
  static const int pp2ChangeAmountStart = 175;
  static const int pp2OwnerPKHStart = 176;
  static const int pp2ScriptCodeStart = 197;

  /// Builds a PP1_SP locking script.
  ///
  /// [genesisHeader] is immutable and carried by every round of a given pool.
  /// The create branch requires the opening header to equal it, so the state a
  /// pool started from is fixed at issuance and published. Without that, a
  /// coordinator could open a pool whose commitment tree already held notes
  /// nobody deposited for, and the first spend against that tree would drain a
  /// PP3 that never received the money.
  static SVScript generate({
    required List<int> ownerPKH,
    required List<int> tokenId,
    required List<int> verifierBodyHash,
    required List<int> header,
    required List<int> genesisHeader,
  }) {
    if (ownerPKH.length != 20) {
      throw ArgumentError.value(ownerPKH.length, 'ownerPKH', 'must be 20 bytes');
    }
    if (tokenId.length != 32) {
      throw ArgumentError.value(tokenId.length, 'tokenId', 'must be 32 bytes');
    }
    if (verifierBodyHash.length != 32) {
      throw ArgumentError.value(
          verifierBodyHash.length, 'verifierBodyHash', 'must be a 32-byte SHA256');
    }
    if (header.length != PoolHeader.byteSize) {
      throw ArgumentError.value(
          header.length, 'header', 'must be ${PoolHeader.byteSize} bytes');
    }
    if (genesisHeader.length != PoolHeader.byteSize) {
      throw ArgumentError.value(genesisHeader.length, 'genesisHeader',
          'must be ${PoolHeader.byteSize} bytes');
    }

    var b = ScriptBuilder();

    b.addData(Uint8List.fromList(ownerPKH));
    b.addData(Uint8List.fromList(tokenId));
    b.addData(Uint8List.fromList(verifierBodyHash));
    b.addData(Uint8List.fromList(genesisHeader));
    b.addData(Uint8List.fromList(header));

    // Alt bottom to top: [header, genesisHeader, verifierBodyHash, tokenId, ownerPKH]
    // Pop order therefore: ownerPKH, tokenId, verifierBodyHash, genesisHeader, header
    for (var i = 0; i < 5; i++) {
      b.opCode(OpCodes.OP_TOALTSTACK);
    }

    _emitDispatch(b);
    return b.build();
  }

  // =========================================================================
  // Dispatch
  // =========================================================================

  /// Stack on entry: [..., selector]
  static void _emitDispatch(ScriptBuilder b) {
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_NOTIF);           // selector == 0
      b.opCode(OpCodes.OP_DROP);
      _emitCreate(b);
    b.opCode(OpCodes.OP_ELSE);
      // Any selector other than 1 fails here rather than falling through to a
      // branch it did not name.
      b.opCode(OpCodes.OP_1);
      b.opCode(OpCodes.OP_EQUALVERIFY);
      _emitRound(b);
    b.opCode(OpCodes.OP_ENDIF);
  }

  // =========================================================================
  // create (selector=0)
  // =========================================================================

  /// Stack: [tokenRawTx, preImage, fundingOutpoint, witnessPadding]
  /// Altstack pop order: ownerPKH, tokenId, verifierBodyHash, genesisHeader, header
  static void _emitCreate(ScriptBuilder b) {
    // Stack indices from the top:
    //   witnessPadding=0, fundingOutpoint=1, preImage=2, tokenRawTx=3

    // --- Phase 0: anchor the base case to a once-spendable outpoint ---
    //
    // Without this, create would check nothing about the token transaction's
    // own inputs, so tokenId would be bound to nothing on chain and anyone
    // could mint a second pool carrying the same tokenId. Measured against the
    // pre-fix script in tool/scratch/double_issue_probe.dart.
    //
    // Two checks close it:
    //   SHA256d(tokenRawTx) == preImage[68:100]     the bytes are this token tx
    //   tokenRawTx input 0 outpoint == tokenId || LE32(1)
    //
    // tokenRawTx is pushed at the BOTTOM of the create stack so every index the
    // later phases use is unchanged. This phase consumes it and restores the
    // layout it found.

    // SHA256d(tokenRawTx) must equal the outpoint txid in our own preimage,
    // which is the token transaction whose PP1 output this witness is spending.
    OpcodeHelpers.pushInt(b, 3);
    b.opCode(OpCodes.OP_PICK);           // copy tokenRawTx
    b.opCode(OpCodes.OP_HASH256);        // computed txid
    OpcodeHelpers.pushInt(b, 3);
    b.opCode(OpCodes.OP_PICK);           // copy preImage (shifted by the push above)
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Walk tokenRawTx to input 0's 36-byte outpoint: skip nVersion, then the
    // input-count varint, which must be a single byte so the offset is fixed.
    OpcodeHelpers.pushInt(b, 3);
    b.opCode(OpCodes.OP_PICK);           // copy tokenRawTx
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);   // drop nVersion
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);          // [countByte, rest], rest on top
    b.opCode(OpCodes.OP_SWAP);           // countByte on top
    b.addData(Uint8List.fromList([0x00]));
    b.opCode(OpCodes.OP_CAT);            // unsigned: 0xfd..0xff must not read as negative
    b.opCode(OpCodes.OP_BIN2NUM);
    OpcodeHelpers.pushInt(b, 0xfd);
    b.opCode(OpCodes.OP_LESSTHAN);
    b.opCode(OpCodes.OP_VERIFY);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP); // input 0 outpoint

    // outpoint == tokenId || LE32(1). TSL1 funds issuance from output 1 of the
    // funding transaction, so pinning the index makes (tokenId, 1) spendable once.
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);   // tokenId
    b.opCode(OpCodes.OP_DUP);
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);            // expected outpoint
    OpcodeHelpers.pushInt(b, 3);
    b.opCode(OpCodes.OP_ROLL);           // bring the real outpoint up
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_TOALTSTACK);     // tokenId back
    b.opCode(OpCodes.OP_TOALTSTACK);     // ownerPKH back

    // Drop tokenRawTx; the stack is now exactly what the phases below expect.
    OpcodeHelpers.pushInt(b, 3);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_DROP);
    // Stack: [witnessPadding, fundingOutpoint, preImage]

    // --- Phase 1: the witness padding must be non-empty ---
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);
    // Stack: [fundingOutpoint, preImage]

    // --- Phase 2: the pool must open on its declared genesis header ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // ownerPKH
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId, checked above
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // verifierBodyHash
    b.opCode(OpCodes.OP_FROMALTSTACK);                            // genesisHeader
    b.opCode(OpCodes.OP_FROMALTSTACK);                            // header
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // Alt: []

    // --- Phase 3: bind this witness to the token transaction ---
    b.opCode(OpCodes.OP_TOALTSTACK);    // save fundingOutpoint

    // hashPrevouts = preImage[4:36]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    // currentTxId = preImage[68:100]
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);

    b.opCode(OpCodes.OP_FROMALTSTACK);  // currentTxId
    b.opCode(OpCodes.OP_FROMALTSTACK);  // hashPrevouts
    b.opCode(OpCodes.OP_FROMALTSTACK);  // fundingOutpoint (36 bytes, from scriptSig)
    // pp1Outpoint
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_CAT);
    // pp2Outpoint
    b.opCode(OpCodes.OP_ROT);
    b.addData(Uint8List.fromList([0x02, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_1);
  }

  // =========================================================================
  // round (selector=1)
  // =========================================================================

  /// One round of the pool: the ordinary TSL1 inductive transfer, with the
  /// pool header substituted instead of the state machine's fields, plus the
  /// four checks that make the next round's verification unavoidable.
  ///
  /// Stack: [withdrawals, receipts, preImage, pp2Out, ownerPK, changePkh,
  ///         changeAmt, ownerSig, newOwnerPKH, newHeader, nextSlot, slotParts,
  ///         vBody, bundles, scriptLHS, parentRawTx, padding]
  /// Altstack pop order: ownerPKH, tokenId, verifierBodyHash, genesisHeader, header
  ///
  /// withdrawals and receipts are the round's variable output tail. They are
  /// pushed first so they land at the bottom, which leaves every other stack
  /// index in this branch unchanged.
  ///
  /// The owner signature says the coordinator wants this round. What makes the
  /// round *correct* is the verifier, and PP1 cannot run it: PP1 lives in the
  /// witness, which is built after the round is mined and its withdrawals are
  /// paid. So the job here is to make the verification the *next* round cannot
  /// skip. PP3_{N+1} pins the outpoint round N+2 must spend, and this branch
  /// certifies that the script at that outpoint is the pool's verifier holding
  /// header_{N+1}. The two together mean round N+2 can only be mined beside a
  /// verifier that already knows the true state it must check against.
  ///
  /// The certification is deliberately forward-looking. PP3's pin is enforced
  /// at mining time but says nothing about what sits at the pinned outpoint;
  /// only a witness can inspect that, and by then the round it belongs to has
  /// already been paid. Doing it one round early is what closes the gap, and it
  /// is safe because round N+2 spends witness N+1's output, so witness N+1
  /// always exists first.
  static void _emitRound(ScriptBuilder b) {
    // Stack indices from the top (15):
    //   pad=0, rawTx=1, lhs=2, bundles=3, vBody=4, slotParts=5, nextSlot=6,
    //   newHeader=7, newOwnerPKH=8, ownerSig=9, chgAmt=10, chgPkh=11,
    //   ownerPK=12, pp2=13, preImg=14

    // --- Owner authorisation ---
    b.opCode(OpCodes.OP_FROMALTSTACK);   // ownerPKH, everything shifts by one
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);                            // ownerPK
    b.opCode(OpCodes.OP_HASH160);
    b.opCode(OpCodes.OP_OVER);                            // ownerPKH
    b.opCode(OpCodes.OP_EQUALVERIFY);
    OpcodeHelpers.pushInt(b, 10);
    b.opCode(OpCodes.OP_PICK);                            // ownerSig
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_PICK);                            // ownerPK, +1 for the sig push
    b.opCode(OpCodes.OP_CHECKSIG); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_DROP);                            // drop ownerPKH

    // --- Drain the immutable fields, keeping verifierBodyHash ---
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // tokenId
    b.opCode(OpCodes.OP_FROMALTSTACK);                            // verifierBodyHash
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // genesisHeader
    // The parent header is not read here. Nothing in PP1 relates it to
    // newHeader: that is the proof's job, and the proof runs in the verifier
    // slot this branch is busy certifying.
    b.opCode(OpCodes.OP_FROMALTSTACK); b.opCode(OpCodes.OP_DROP); // header
    // Alt: []
    // Stack (18): vbh=0, pad=1, rawTx=2, lhs=3, bundles=4, vBody=5, slotParts=6,
    //   nextSlot=7, newHeader=8, newOwnerPKH=9, ownerSig=10, chgAmt=11,
    //   chgPkh=12, ownerPK=13, pp2=14, preImg=15, receipts=16, withdrawals=17

    // --- Park the variable output tail until the rebuild needs it ---
    //
    // These two are wanted in phase 12b, most of a branch away, and the
    // altstack is the only place they can wait without moving every index in
    // between. Pushed withdrawals first so the pops come out receipts first,
    // which is the order they are written into the round.
    OpcodeHelpers.pushInt(b, 17);
    b.opCode(OpCodes.OP_ROLL); b.opCode(OpCodes.OP_TOALTSTACK);   // withdrawals
    OpcodeHelpers.pushInt(b, 16);
    b.opCode(OpCodes.OP_ROLL); b.opCode(OpCodes.OP_TOALTSTACK);   // receipts
    // Alt: [withdrawals, receipts]
    // Stack (16): vbh=0, pad=1, rawTx=2, lhs=3, bundles=4, vBody=5, slotParts=6,
    //   nextSlot=7, newHeader=8, newOwnerPKH=9, ownerSig=10, chgAmt=11,
    //   chgPkh=12, ownerPK=13, pp2=14, preImg=15

    // --- The round's ciphertext bundles hash to header.outHash ---
    //
    // The bundles are what lets a recipient find and open their note. They are
    // pushed here rather than written to an output because of where TSL1 pays
    // for bytes: an output's bytes are paid three times, a witness's once, and
    // nothing in script needs to read inside them. Being in a mined witness is
    // what publishes them; this check is what binds them to the round.
    // header.outHash is a hash of per-transfer bundle hashes, which is what
    // lets V hold each transfer's proof to its own ciphertexts with 32 bytes
    // a transfer (see PoolOutHash).
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // bundles
    emitRoundOutHash(b);
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // newHeader
    OpcodeHelpers.pushInt(b, PoolHeader.outHashOffset);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL); b.opCode(OpCodes.OP_DROP);   // bundles consumed
    // Stack (15): vbh=0, pad=1, rawTx=2, lhs=3, vBody=4, slotParts=5, nextSlot=6,
    //   newHeader=7, newOwnerPKH=8, ownerSig=9, chgAmt=10, chgPkh=11,
    //   ownerPK=12, pp2=13, preImg=14

    // --- The slot PP3 will pin holds this pool's verifier, for this header ---
    // emitVerifySlotIsVerifier wants, bottom to top:
    //   slotParts, vBody, bodyHash, header, nextSlot
    OpcodeHelpers.pushInt(b, 5);
    b.opCode(OpCodes.OP_ROLL);           // slotParts
    OpcodeHelpers.pushInt(b, 5);
    b.opCode(OpCodes.OP_ROLL);           // vBody
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_ROLL);           // verifierBodyHash
    OpcodeHelpers.pushInt(b, 7);
    b.opCode(OpCodes.OP_PICK);           // newHeader, kept for the rebuild
    OpcodeHelpers.pushInt(b, 7);
    b.opCode(OpCodes.OP_PICK);           // nextSlot, kept for PP3
    emitVerifySlotIsVerifier(b);
    // Stack (12): pad=0, rawTx=1, lhs=2, nextSlot=3, newHeader=4,
    //   newOwnerPKH=5, ownerSig=6, chgAmt=7, chgPkh=8, ownerPK=9, pp2=10,
    //   preImg=11

    // --- Park what the inductive proof needs, in the order it wants them ---
    // Pop order: newHeader (the PP1 rebuild), nextSlot (the PP3 rebuild),
    // balance (the PP3 output's value).
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // newHeader
    OpcodeHelpers.pushInt(b, PoolHeader.balanceOffset + 8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, PoolHeader.balanceOffset);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // balance, 8 bytes LE
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nextSlot
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_ROLL);
    b.opCode(OpCodes.OP_TOALTSTACK);     // newHeader
    // Stack (10): pad=0, rawTx=1, lhs=2, newOwnerPKH=3, ownerSig=4,
    //   chgAmt=5, chgPkh=6, ownerPK=7, pp2=8, preImg=9
    // Alt: [withdrawals, receipts, balance, nextSlot, newHeader]

    // --- newOwnerPKH on top, which is the inductive proof's precondition ---
    b.opCode(OpCodes.OP_3);
    b.opCode(OpCodes.OP_ROLL);

    _emitInductiveProofRound(b);
  }

  // =========================================================================
  // Round: the 5-output inductive proof
  // =========================================================================

  /// Phases 2-16 of the standard TSL1 5-output topology.
  ///
  /// Pre: Stack (10): [preImg, pp2, mPK, chgPkh, chgAmt, mSig,
  ///                   lhs, rawTx, pad, newOwnerPKH]
  ///      idx: newOwnerPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
  ///           chgAmt=5, chgPkh=6, mPK=7, pp2=8, preImg=9
  ///      Alt: [withdrawals, receipts, balance, nextSlot, newHeader]
  static void _emitInductiveProofRound(ScriptBuilder b) {
    // Phase 2: Validate padding and parentRawTx
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_PICK);  // padding
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // rawTx
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN); b.opCode(OpCodes.OP_VERIFY);

    // Phase 3: Extract preImage fields
    // currentTxId = preImage[68:100]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    OpcodeHelpers.pushInt(b, 100);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, 68);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // currentTxId → alt

    // nLocktime = preImage[len-8:len-4]
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_PICK);
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);     // nLocktime → alt

    // Phase 4: checkPreimageOCS
    b.opCode(OpCodes.OP_9); b.opCode(OpCodes.OP_ROLL);
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    b.opCode(OpCodes.OP_VERIFY);
    // Stack (9): pp2=8→7, mPK=7→6, chgPkh=6→5, chgAmt=5→4, mSig=4→3,
    //            lhs=3→2, rawTx=2→1, pad=1→0... wait, preImage was at 9.
    // After ROLL 9 removes preImage: stack shifts down.
    // Stack (9): newOwnerPKH=0, pad=1, rawTx=2, lhs=3, mSig=4,
    //            chgAmt=5, chgPkh=6, mPK=7, pp2=8

    // Phase 5: Parse parentRawTx outputs
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // rawTx
    PP1FtScriptGen.emitSkipInputs(b);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitSkipNOutputs(b);
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp1S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp2S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // pp3S → alt
    PP1FtScriptGen.emitReadOneOutputScript(b);
    b.opCode(OpCodes.OP_TOALTSTACK);     // metaS → alt
    b.opCode(OpCodes.OP_DROP);           // drop remaining

    // Phase 6: Validate metadata 006a
    b.opCode(OpCodes.OP_FROMALTSTACK);   // metaS
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00, 0x6a]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 7: Get parent scripts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp3S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp2S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // pp1S
    b.opCode(OpCodes.OP_FROMALTSTACK);   // nLocktime
    b.opCode(OpCodes.OP_FROMALTSTACK);   // currentTxId
    // Alt: [eventDigest]
    // Stack (15): currentTxId=0, nLocktime=1, pp1S=2, pp2S=3, pp3S=4, metaS=5,
    //   newOwnerPKH=6, pad=7, rawTx=8, lhs=9, mSig=10, chgAmt=11,
    //   chgPkh=12, mPK=13, pp2Out=14

    // Phase 7b: the round spent the verifier slot its parent named
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // pp3S
    OpcodeHelpers.pushInt(b, 10);
    b.opCode(OpCodes.OP_PICK);           // scriptLHS, +1 for the push above
    emitVerifySpentPinnedSlot(b);

    // Phase 8: rebuild PP1 with the new owner and the new header
    //
    // The SM hashed an event digest into a rolling commitment here. A pool
    // replaces its whole state each round, so there is nothing to fold: the
    // new header arrives as one push and the rebuild substitutes the region.
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_PICK);  // pp1S
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // newOwnerPKH (+1)
    b.opCode(OpCodes.OP_FROMALTSTACK);                  // newHeader
    _emitRebuildPP1Pool(b);
    // Stack (16): [..., pp1S, nLocktime, currentTxId, rebuiltPP1Script]

    // Phase 9: Build PP1 output (1 sat)
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 10: Build PP3 output
    //
    // Two things differ from a plain TSL1 transfer. PP3 carries the slot the
    // next round must spend, so the rebuild substitutes it, and it carries no
    // owner key, because a pool PP3 has no burn path; and PP3 holds the pool
    // balance rather than a dust satoshi, so its
    // value comes from the header. Both are enforced by the same thing as
    // everything else here: the rebuilt output goes into the transaction this
    // script hashes against its own outpoint's txid, so a round whose PP3 names
    // a different slot or holds a different amount cannot be spent afterwards.
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);  // pp3S
    b.opCode(OpCodes.OP_FROMALTSTACK);                  // nextSlot
    emitRebuildPP3WithNextSlot(b);
    b.opCode(OpCodes.OP_FROMALTSTACK);                  // balance, 8 bytes LE
    _emitBuildOutputWithRawValue(b);

    // Phase 11: Build metadata output (0 sats)
    b.opCode(OpCodes.OP_7); b.opCode(OpCodes.OP_PICK);  // metaS
    b.opCode(OpCodes.OP_0);
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 12: Build change output
    // idx: metaOut=0, pp3Out=1, pp1Out=2, currentTxId=3, nLocktime=4,
    //   pp1S=5, pp2S=6, pp3S=7, metaS=8, newOwnerPKH=9,
    //   pad=10, rawTx=11, lhs=12, mSig=13, chgAmt=14, chgPkh=15,
    //   mPK=16, pp2Out=17
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // changePkh
    PP1FtScriptGen.emitBuildP2PKHScript(b);
    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // changeAmt (+1)
    PP1FtScriptGen.emitBuildOutput(b);

    // Phase 12b: Build the variable output tail
    //
    // This is where withdrawals and deposit receipts enter the round. Both
    // come out of the altstack as flat blobs of fixed-size records, and leave
    // as the bytes of the outputs themselves plus the output-count varint.
    b.opCode(OpCodes.OP_FROMALTSTACK);   // receipts
    b.opCode(OpCodes.OP_FROMALTSTACK);   // withdrawals
    emitBuildOutputTail(b);
    // Stack: [..., changeOut, countVarint, tail]
    b.opCode(OpCodes.OP_TOALTSTACK);     // the tail waits for its turn below

    // Phase 13: Reconstruct fullTx
    // idx: countVarint=0, changeOut=1, metaOut=2, pp3Out=3, pp1Out=4,
    //   currentTxId=5, nLocktime=6, pp1S=7, pp2S=8, pp3S=9, metaS=10,
    //   newOwnerPKH=11, pad=12, rawTx=13, lhs=14, mSig=15, chgAmt=16,
    //   chgPkh=17, mPK=18, pp2Out=19
    OpcodeHelpers.pushInt(b, 14);
    b.opCode(OpCodes.OP_PICK);  // scriptLHS
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);   // lhs + varint(5 + receipts + withdrawals)
    // From here the stack is what a fixed five-output round had.
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);   // + changeOut

    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash metaOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_TOALTSTACK);  // stash pp3Out
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);   // + pp1Out

    OpcodeHelpers.pushInt(b, 15);
    b.opCode(OpCodes.OP_PICK);  // pp2Out
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_FROMALTSTACK);  // pp3Out
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // metaOut
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);  // the variable tail
    b.opCode(OpCodes.OP_CAT);

    // nLocktime
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);

    // Phase 14: Verify SHA256d(fullTx) == currentTxId
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Phase 15: Validate PP2
    b.opCode(OpCodes.OP_DROP);  // drop pp1S
    OpcodeHelpers.pushInt(b, 11);
    b.opCode(OpCodes.OP_PICK);  // pp2Out
    b.opCode(OpCodes.OP_8);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitReadVarint(b);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SWAP);
    _emitValidatePP2NFT(b);

    // Phase 16: Verify parent chain
    b.opCode(OpCodes.OP_DROP); // pp3S
    b.opCode(OpCodes.OP_DROP); // metaS
    b.opCode(OpCodes.OP_DROP); // newOwnerPKH
    b.opCode(OpCodes.OP_DROP); // padding

    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SHA256); b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);  // rawTx
    // A pool round spends its parent's PP3 at input 3, not the TSL1 input 2:
    // PP3 signs SIGHASH_SINGLE so that its forward covenant sees output 3,
    // and SINGLE ties output index to input index.
    PP1FtScriptGen.emitReadOutpoint(b, poolPP3Input);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_1);
  }


  // =========================================================================
  // Rebuild PP1_SP
  // =========================================================================

  /// Rebuilds this script with a new owner and a new header.
  ///
  /// ```
  /// rebuilt = parent[0:1] + newPKH + parent[21:327] + newHeader + parent[563:]
  /// ```
  ///
  /// Two mutable fields separated by one immutable run, so the surgery is two
  /// substitutions in fixed windows. The state machine's version had to thread
  /// four windows through the same altstack, which is most of what the pool
  /// header buys by being one push: `parent[21:327]` is the tokenId push, the
  /// verifier body hash, the immutable genesis header, and the live header's
  /// OP_PUSHDATA1 prefix.
  ///
  /// Pre:  [..., pp1S, newPKH, newHeader]   (newHeader on top)
  /// Post: [..., rebuiltScript]
  static void _emitRebuildPP1Pool(ScriptBuilder b) {
    // Bring pp1S to the top: [..., newPKH, newHeader, pp1S]
    b.opCode(OpCodes.OP_ROT);

    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);            // seg0 = pp1S[0:1], rest = pp1S[1:]
    OpcodeHelpers.pushInt(b, pkhDataEnd - pkhDataStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);   // drop the old ownerPKH
    OpcodeHelpers.pushInt(b, immutableMidLength);
    b.opCode(OpCodes.OP_SPLIT);            // seg1 = pp1S[21:327], rest = pp1S[327:]
    OpcodeHelpers.pushInt(b, PoolHeader.byteSize);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);   // drop the old header
    // Stack: [..., newPKH, newHeader, seg0, seg1, seg2]  (seg2 = pp1S[563:])

    b.opCode(OpCodes.OP_TOALTSTACK);       // seg2
    b.opCode(OpCodes.OP_TOALTSTACK);       // seg1
    // Stack: [..., newPKH, newHeader, seg0]; alt pop order: seg1, seg2

    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);      // newPKH to the top
    b.opCode(OpCodes.OP_CAT);              // seg0 + newPKH
    b.opCode(OpCodes.OP_FROMALTSTACK);     // seg1
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);             // newHeader to the top
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);     // seg2
    b.opCode(OpCodes.OP_CAT);
  }

  // =========================================================================
  // Validate PP2
  // =========================================================================

  /// Verifies that the slot outpoint PP3 pins holds the verifier for a given
  /// header.
  ///
  /// PP3 only proves that *something* at that outpoint was spent by the round.
  /// Anything would do, including an OP_TRUE, which would let a coordinator
  /// satisfy the pin while skipping verification entirely. This closes that by
  /// rebuilding the slot transaction from its parts and matching its txid
  /// against the pinned one, then checking the script it carries.
  ///
  /// The slot transaction Y is required to be canonical:
  ///
  ///   version=1 ‖ 0x01 ‖ yInput ‖ 0x02 ‖ output(V, 1 sat) ‖
  ///   output(P2PKH anchorPKH, 1 sat) ‖ nLockTime=0
  ///
  /// Only yInput, V and the anchor's key hash are free; this script emits
  /// every structural byte. V is output 0, so a forged Y cannot park the real
  /// verifier somewhere inert and put an OP_TRUE where the next round looks.
  /// Output 1 is the anchor the round that pins this slot has to spend (PP3
  /// enforces that spend, see `WitnessCheckScriptGen._emitPoolHashPrevOuts`),
  /// which is what makes that round impossible to mine without Y. The
  /// coordinator builds Y, so meeting this shape costs nothing.
  ///
  /// **yInput's own length is checked, and that is not tidiness.** The pin is
  /// a HASH256 over bytes, and bytes only mean something through a parse.
  /// yInput is `outpoint ‖ varint ‖ scriptSig ‖ sequence`, and if its varint
  /// could claim a longer scriptSig than yInput actually holds, the real
  /// transaction's scriptSig would run on past it, swallowing the output
  /// count, V and the start of the anchor as one data push. The parse would
  /// then resume inside the anchor's key hash, which is 20 bytes of the
  /// spender's choosing: enough for a sequence, an output count of 1 and an
  /// output whose script is `OP_1 OP_1 OP_EQUALVERIFY OP_CHECKSIG` with the
  /// anchor's own `88 ac` as its tail. That Y has one output, spendable with
  /// the attacker's own signature, and hashes exactly as PP1 would rebuild
  /// it. Requiring `SIZE(yInput) == 41 + scriptSigLength`, with a one-byte
  /// varint, makes PP1's parse the only parse. Before the anchor, the bytes
  /// after yInput were all fixed or hash-checked, which is why the gap did
  /// not matter until now.
  ///
  /// yInput and the anchor's key hash arrive as one push, `yInput ‖
  /// anchorPKH`, split here 20 bytes from the end. That keeps every other
  /// index in the round branch where it was.
  ///
  /// V itself is required to be `OP_PUSHDATA1 0xec ‖ header ‖ body`. That is
  /// what makes the check bind *state* and not just code: the body hash says
  /// the slot runs the pool's verifier, and the header push says that verifier
  /// was initialised with this header. Checking only the body would leave a
  /// coordinator free to point the next round at a verifier holding some other
  /// round's state, which would verify a proof against the wrong publics.
  ///
  /// Pre:  [slotParts, vBody, bodyHash, header, nextSlot]   (nextSlot on top)
  /// Post: []   (all five consumed; the script fails if anything mismatches)
  static void emitVerifySlotIsVerifier(ScriptBuilder b) {
    // The pin must name output 0, which is where the canonical shape puts V.
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x00, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    // Keep the pinned txid for the end.
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_TOALTSTACK);
    // [yInput, vBody, bodyHash, header]

    // The script at that output runs the pool's verifier, not something that
    // merely returns true.
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);   // vBody to the top
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_3); b.opCode(OpCodes.OP_ROLL);   // bodyHash to the top
    b.opCode(OpCodes.OP_EQUALVERIFY);
    // [yInput, header, vBody]

    // V = OP_PUSHDATA1 0xec ‖ header ‖ body
    b.opCode(OpCodes.OP_SWAP);
    b.addData(Uint8List.fromList([0x4c, PoolHeader.byteSize]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // [yInput, V]

    // output = value(8 LE) ‖ varint(len) ‖ V, at the protocol dust value.
    b.opCode(OpCodes.OP_1);
    PP1FtScriptGen.emitBuildOutput(b);
    // [slotParts, vOut]

    // slotParts = yInput ‖ anchorPKH. A slotParts shorter than 20 bytes
    // makes the SPLIT fail, so the key hash is exactly 20 bytes.
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_SIZE);
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SUB);
    b.opCode(OpCodes.OP_SPLIT);
    // [vOut, yInput, anchorPKH]

    // anchor = 1 sat ‖ 0x19 ‖ OP_DUP OP_HASH160 <anchorPKH> OP_EQUALVERIFY OP_CHECKSIG
    b.addData(Uint8List.fromList(
        [0x01, 0, 0, 0, 0, 0, 0, 0, 0x19, 0x76, 0xa9, 0x14]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.addData(Uint8List.fromList([0x88, 0xac]));
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    // [vOut, anchorOut, yInput]

    // yInput is exactly one input: outpoint(36) ‖ varint ‖ scriptSig ‖
    // sequence(4), with a one-byte varint that accounts for every byte.
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    b.addData(Uint8List.fromList([0x00]));       // unsigned
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_BIN2NUM);                // scriptSig length
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, 0xfd);
    b.opCode(OpCodes.OP_LESSTHAN);
    b.opCode(OpCodes.OP_VERIFY);                 // a one-byte varint
    OpcodeHelpers.pushInt(b, 41);
    b.opCode(OpCodes.OP_ADD);
    b.opCode(OpCodes.OP_OVER);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);

    // Y = version ‖ inputCount ‖ yInput ‖ outputCount ‖ vOut ‖ anchorOut ‖ nLockTime
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00, 0x01]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // OP_2 rather than addData([0x02]): dartsv rejects a single-byte push in
    // 1..16 as non-minimal, and OP_2 puts the same [0x02] on the stack.
    b.opCode(OpCodes.OP_2);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_ROT);
    b.opCode(OpCodes.OP_CAT);                    // ... ‖ vOut
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);                    // ... ‖ anchorOut
    b.addData(Uint8List.fromList([0x00, 0x00, 0x00, 0x00]));
    b.opCode(OpCodes.OP_CAT);

    b.opCode(OpCodes.OP_HASH256);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_EQUALVERIFY);
  }

  /// Builds a transaction output from a script and an 8-byte little-endian
  /// value, where [PP1FtScriptGen.emitBuildOutput] takes a script number.
  ///
  /// The pool needs this because PP3's value is the pool balance, which lives
  /// in the header as raw LE64. Round-tripping it through OP_BIN2NUM and
  /// OP_NUM2BIN would give the same bytes back, but only because the balance
  /// cannot set the sign bit; splicing the bytes in avoids relying on that.
  ///
  /// Pre:  [script, value8]   Post: [outputBytes]
  static void _emitBuildOutputWithRawValue(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);           // [value8, script]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    PP1FtScriptGen.emitWriteVarint(b);   // [value8, script, varint]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);            // [value8, varint+script]
    b.opCode(OpCodes.OP_CAT);
  }

  // =========================================================================
  // The variable output tail
  // =========================================================================

  /// Builds the round's withdrawal and receipt outputs, and the output-count
  /// varint that has to precede all of them.
  ///
  /// Every other TSL1 archetype writes a literal 5 here, and that literal is a
  /// security property rather than a convenience: it is what makes it
  /// impossible for a round to carry a second PP1 with the same tokenId and
  /// fork the chain through the sanctioned path. A pool has to carry payouts
  /// and deposit receipts, so the count has to move. Taking the tail as an
  /// opaque blob of the spender's choosing would hand back exactly what the
  /// fixed count was defending, so instead each extra output is rebuilt here
  /// from a template with only its variable bytes free:
  ///
  /// * a withdrawal is `value8 ‖ 0x19 ‖ OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY
  ///   OP_CHECKSIG`, 34 bytes, of which only the 20-byte hash and the value
  ///   come from the witness;
  /// * a receipt is eight zero bytes of value, then `OP_FALSE OP_RETURN <cm>
  ///   <value>`, 53 bytes, of which only the 32-byte commitment and the
  ///   8-byte amount come from the witness.
  ///
  /// So the only outputs a round can carry are the five TSL1 outputs, P2PKH
  /// payouts and data receipts. Nothing in the tail is spendable as a token
  /// and the induction is exactly as strong as it was with five outputs.
  ///
  /// The counts are not pushed. They are derived from the blob sizes, which
  /// means there is no second number for a spender to disagree with: the count
  /// in the varint and the number of outputs actually emitted come from the
  /// same bytes. The maxima are enforced by running out of unrolled steps and
  /// then requiring both blobs to be empty.
  ///
  /// Receipts are written before withdrawals. A deposit covenant proves its
  /// receipt with SIGHASH_SINGLE, which matches output index to input index,
  /// and a depositor building that covenant cannot know how many withdrawals
  /// the round will end up carrying. Their own count they can agree in advance.
  ///
  /// Pre:  [receipts, withdrawals]   (withdrawals on top)
  /// Post: [countVarint, tailBytes]
  static void emitBuildOutputTail(ScriptBuilder b) {
    _emitBuildOutputTail(b);
  }

  /// header.outHash from the witness's bundles push: `SHA256(c_0 ‖ … ‖
  /// c_{n-1})` with `c_t = SHA256(bundle_t)`, the push being each bundle
  /// behind a 2-byte little-endian length ([PoolOutHash.encodeBundles]).
  ///
  /// Up to [PoolOutHash.maxTransfers] segments, one unrolled step each,
  /// skipped once the push is used up; then it must be empty. A length that
  /// runs past the push fails OP_SPLIT, so a malformed push cannot parse as
  /// anything. The count is not stated anywhere: V hashes its own transfers'
  /// bundle hashes into the same header field, so a different count cannot
  /// meet it.
  ///
  /// Pre:  [bundles]
  /// Post: [outHash32]
  static void emitRoundOutHash(ScriptBuilder b) {
    b.opCode(OpCodes.OP_0);                          // bundles acc
    b.opCode(OpCodes.OP_SWAP);                       // acc bundles
    for (int i = 0; i < PoolOutHash.maxTransfers; i++) {
      b.opCode(OpCodes.OP_SIZE);
      b.opCode(OpCodes.OP_IF);
      OpcodeHelpers.pushInt(b, PoolOutHash.lengthBytes);
      b.opCode(OpCodes.OP_SPLIT);                    // acc len rest
      b.opCode(OpCodes.OP_SWAP);
      b.addData(Uint8List.fromList([0x00]));         // unsigned
      b.opCode(OpCodes.OP_CAT);
      b.opCode(OpCodes.OP_BIN2NUM);                  // acc rest n
      b.opCode(OpCodes.OP_SPLIT);                    // acc seg rest'
      b.opCode(OpCodes.OP_SWAP);
      b.opCode(OpCodes.OP_SHA256);                   // acc rest' c
      b.opCode(OpCodes.OP_ROT);
      b.opCode(OpCodes.OP_SWAP);
      b.opCode(OpCodes.OP_CAT);                      // rest' acc'
      b.opCode(OpCodes.OP_SWAP);                     // acc' rest'
      b.opCode(OpCodes.OP_ENDIF);
    }
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_NOT);
    b.opCode(OpCodes.OP_VERIFY);                     // more than the maximum
    b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_SHA256);
  }

  static void _emitBuildOutputTail(ScriptBuilder b) {
    // --- The counts, from the sizes ---
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, PoolWithdrawal.recordSize);
    b.opCode(OpCodes.OP_MOD);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_NUMEQUALVERIFY);
    OpcodeHelpers.pushInt(b, PoolWithdrawal.recordSize);
    b.opCode(OpCodes.OP_DIV);
    b.opCode(OpCodes.OP_TOALTSTACK);     // w
    b.opCode(OpCodes.OP_SWAP);           // [withdrawals, receipts]
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, PoolReceipt.recordSize);
    b.opCode(OpCodes.OP_MOD);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_NUMEQUALVERIFY);
    OpcodeHelpers.pushInt(b, PoolReceipt.recordSize);
    b.opCode(OpCodes.OP_DIV);            // r
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_ADD);
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_ADD);            // 5 + r + w
    // Five plus the tail can pass 252, so the count needs a real varint and
    // not the single byte every fixed-count archetype gets away with.
    PP1FtScriptGen.emitWriteVarint(b);
    b.opCode(OpCodes.OP_ROT); b.opCode(OpCodes.OP_ROT);
    // Stack: [countVarint, withdrawals, receipts]

    // --- The outputs ---
    b.opCode(OpCodes.OP_0);              // the accumulator starts empty
    b.opCode(OpCodes.OP_SWAP);
    // Stack: [countVarint, withdrawals, tail, receipts]
    for (var i = 0; i < PoolReceipt.maxPerRound; i++) {
      _emitOneTailOutput(b, PoolReceipt.recordSize, _receiptSteps);
    }
    _emitBlobIsEmpty(b);
    b.opCode(OpCodes.OP_SWAP);
    // Stack: [countVarint, tail, withdrawals]
    for (var i = 0; i < PoolWithdrawal.maxPerRound; i++) {
      _emitOneTailOutput(b, PoolWithdrawal.recordSize, _withdrawalSteps);
    }
    _emitBlobIsEmpty(b);
    // Stack: [countVarint, tail]
  }

  /// One unrolled step of a tail loop: if the blob still has bytes, take
  /// [recordSize] of them, turn them into an output with [build], and append
  /// it to the accumulator.
  ///
  /// The step is a no-op once the blob is empty, which is how one unrolled
  /// body serves every count up to the maximum. A blob whose length is not a
  /// multiple of the record size cannot reach here: the size check in
  /// [emitBuildOutputTail] rejects it, and the OP_SPLIT would fail anyway.
  ///
  /// Pre:  [tail, blob]   Post: [tail', blob']
  static void _emitOneTailOutput(
      ScriptBuilder b, int recordSize, void Function(ScriptBuilder) build) {
    b.opCode(OpCodes.OP_SIZE);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_GREATERTHAN);
    b.opCode(OpCodes.OP_IF);
    OpcodeHelpers.pushInt(b, recordSize);
    b.opCode(OpCodes.OP_SPLIT);          // [tail, record, rest]
    b.opCode(OpCodes.OP_TOALTSTACK);     // rest waits
    build(b);                            // [tail, outputBytes]
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_ENDIF);
  }

  /// `value8 ‖ 0x19 ‖ 76 a9 14 ‖ pkh ‖ 88 ac`.
  ///
  /// Pre: [record28]   Post: [outputBytes34]
  static void _withdrawalSteps(ScriptBuilder b) {
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SPLIT);          // [pkh, value8]
    b.addData(Uint8List.fromList([0x19, 0x76, 0xa9, 0x14]));
    b.opCode(OpCodes.OP_CAT);            // [pkh, value8+prefix]
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.addData(Uint8List.fromList([0x88, 0xac]));
    b.opCode(OpCodes.OP_CAT);
  }

  /// Eight zero bytes of value, then `0x2c ‖ 00 6a 20 ‖ cm ‖ 08 ‖ value8`.
  ///
  /// The script is 44 bytes whatever the amount is, because the amount is
  /// pushed as eight bytes rather than as a script number. A minimally encoded
  /// number would change length with the value and the shape check would have
  /// to know about that; this way it does not.
  ///
  /// Pre: [record40]   Post: [outputBytes53]
  static void _receiptSteps(ScriptBuilder b) {
    OpcodeHelpers.pushInt(b, 32);
    b.opCode(OpCodes.OP_SPLIT);          // [cm, value8]
    b.opCode(OpCodes.OP_8);              // the push opcode for the value
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);            // [cm, 08+value8]
    b.opCode(OpCodes.OP_CAT);
    b.addData(Uint8List.fromList(
        [0, 0, 0, 0, 0, 0, 0, 0, 0x2c, 0x00, 0x6a, 0x20]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
  }

  /// Requires the blob on top to have been used up, and drops it.
  ///
  /// This is what enforces the maxima. A witness carrying more records than
  /// there are unrolled steps leaves bytes behind, and leftover bytes are the
  /// same thing as a count nobody checked.
  ///
  /// Pre: [blob]   Post: []
  static void _emitBlobIsEmpty(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SIZE); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_0); b.opCode(OpCodes.OP_NUMEQUALVERIFY);
  }

  /// Checks that a round spent, at input 2, the verifier slot its parent's PP3
  /// pinned.
  ///
  /// PP3 already enforces this when the round is mined, by folding `nextSlot`
  /// into the `hashPrevouts` it demands. Checking it again here is a second,
  /// independent binding in a different script: the covenant on the money and
  /// the covenant on the token both have to agree that the round brought the
  /// verifier it was told to, rather than one of its own.
  ///
  /// The outpoint is read out of the round's own left-hand side, which the
  /// inductive proof has already tied to the round's txid, so it is not the
  /// spender's word for what input 2 was.
  ///
  /// Pre:  [parentPP3Script, scriptLHS]   (scriptLHS on top)
  /// Post: []
  static void emitVerifySpentPinnedSlot(ScriptBuilder b) {
    PP1FtScriptGen.emitReadOutpoint(b, poolSlotInput);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, pp3NextSlotEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp3NextSlotStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_EQUALVERIFY);
  }

  /// Rebuilds a pool PP3 script with a new nextSlot.
  ///
  /// A pool PP3 begins `<0x24> nextSlot(36) OP_TOALTSTACK ...`, so the slot
  /// the next round must spend is a fixed 36-byte window at offset 1, and it
  /// is the only thing that changes from one round to the next:
  ///
  ///   rebuilt = parent[0:1] + newSlot + parent[37:]
  ///
  /// There used to be a second window, the owner's pubkey hash, which only the
  /// burn path read. The pool variant has no burn path, so PP3's code is now
  /// identical across a coordinator key rotation and the owner lives only in
  /// PP1 and PP2.
  ///
  /// Note what this does and does not enforce. The rest of the parent is
  /// copied, so every PP3 in a pool's chain runs the same program as the
  /// genesis PP3, but PP1 only checks that in the witness, after the round is
  /// mined. A round that swaps in a different PP3 program is caught one
  /// witness too late to stop it being spent. Pinning the program at mining
  /// time is V's job, in its hashOutputs rebuild; see the design's 5.5.
  ///
  /// Pre:  [parentPP3Script, newNextSlot]  (newNextSlot on top)
  /// Post: [rebuiltPP3Script]
  static void emitRebuildPP3WithNextSlot(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);           // newSlot, parent
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);          // newSlot, slotPushOp, rest
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);            // newSlot, slotPushOp, tail
    b.opCode(OpCodes.OP_ROT);            // slotPushOp, tail, newSlot
    b.opCode(OpCodes.OP_ROT);            // tail, newSlot, slotPushOp
    b.opCode(OpCodes.OP_SWAP);           // tail, slotPushOp, newSlot
    b.opCode(OpCodes.OP_CAT);            // tail, slotPushOp+newSlot
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);            // + tail
  }

  static void _emitValidatePP2NFT(ScriptBuilder b) {
    b.opCode(OpCodes.OP_SWAP);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x24]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2WitnessChangePKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2ChangeAmountStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x51]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart + 1);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2OwnerPKHStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.addData(Uint8List.fromList([0x14]));
    b.opCode(OpCodes.OP_EQUALVERIFY);

    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_TOALTSTACK);

    b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT);
    OpcodeHelpers.pushInt(b, pp2ScriptCodeStart - pp2FundingOutpointStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_DROP);
  }
}
