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

  /// A pool PP3 begins `<0x14> ownerPKH(20) <0x24> nextSlot(36) OP_DROP ...`,
  /// so the outpoint it pins the next round to is a fixed window.
  static const int pp3NextSlotStart = 22;
  static const int pp3NextSlotEnd = 58;

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
  /// Stack: [preImage, pp2Out, ownerPK, changePkh, changeAmt, ownerSig,
  ///         newOwnerPKH, newHeader, nextSlot, yInput, vBody, bundles,
  ///         scriptLHS, parentRawTx, padding]
  /// Altstack pop order: ownerPKH, tokenId, verifierBodyHash, genesisHeader, header
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
    //   pad=0, rawTx=1, lhs=2, bundles=3, vBody=4, yInput=5, nextSlot=6,
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
    // Stack (16): vbh=0, pad=1, rawTx=2, lhs=3, bundles=4, vBody=5, yInput=6,
    //   nextSlot=7, newHeader=8, newOwnerPKH=9, ownerSig=10, chgAmt=11,
    //   chgPkh=12, ownerPK=13, pp2=14, preImg=15

    // --- The round's ciphertext bundles hash to header.outHash ---
    //
    // The bundles are what lets a recipient find and open their note. They are
    // pushed here rather than written to an output because of where TSL1 pays
    // for bytes: an output's bytes are paid three times, a witness's once, and
    // nothing in script needs to read inside them. Being in a mined witness is
    // what publishes them; this check is what binds them to the round.
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_PICK);           // bundles
    b.opCode(OpCodes.OP_SHA256);
    b.opCode(OpCodes.OP_9);
    b.opCode(OpCodes.OP_PICK);           // newHeader
    OpcodeHelpers.pushInt(b, PoolHeader.outHashOffset);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_EQUALVERIFY);
    b.opCode(OpCodes.OP_4);
    b.opCode(OpCodes.OP_ROLL); b.opCode(OpCodes.OP_DROP);   // bundles consumed
    // Stack (15): vbh=0, pad=1, rawTx=2, lhs=3, vBody=4, yInput=5, nextSlot=6,
    //   newHeader=7, newOwnerPKH=8, ownerSig=9, chgAmt=10, chgPkh=11,
    //   ownerPK=12, pp2=13, preImg=14

    // --- The slot PP3 will pin holds this pool's verifier, for this header ---
    // emitVerifySlotIsVerifier wants, bottom to top:
    //   yInput, vBody, bodyHash, header, nextSlot
    OpcodeHelpers.pushInt(b, 5);
    b.opCode(OpCodes.OP_ROLL);           // yInput
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
    // Alt: [balance, nextSlot, newHeader]

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
  ///      Alt: [balance, nextSlot, newHeader]
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
    // next round must spend, so the rebuild substitutes it as well as the owner
    // key; and PP3 holds the pool balance rather than a dust satoshi, so its
    // value comes from the header. Both are enforced by the same thing as
    // everything else here: the rebuilt output goes into the transaction this
    // script hashes against its own outpoint's txid, so a round whose PP3 names
    // a different slot or holds a different amount cannot be spent afterwards.
    b.opCode(OpCodes.OP_5); b.opCode(OpCodes.OP_PICK);  // pp3S
    b.opCode(OpCodes.OP_8); b.opCode(OpCodes.OP_PICK);  // newOwnerPKH
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

    // Phase 13: Reconstruct fullTx
    // idx: changeOut=0, metaOut=1, pp3Out=2, pp1Out=3, currentTxId=4, nLocktime=5,
    //   pp1S=6, pp2S=7, pp3S=8, metaS=9, newOwnerPKH=10,
    //   pad=11, rawTx=12, lhs=13, mSig=14, chgAmt=15, chgPkh=16,
    //   mPK=17, pp2Out=18
    OpcodeHelpers.pushInt(b, 13);
    b.opCode(OpCodes.OP_PICK);  // scriptLHS
    b.opCode(OpCodes.OP_5);
    b.opCode(OpCodes.OP_1); b.opCode(OpCodes.OP_NUM2BIN);
    b.opCode(OpCodes.OP_CAT);   // lhs + varint(5)
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
    PP1FtScriptGen.emitReadOutpoint(b, 2);
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
  ///   version=1 ‖ 0x01 ‖ yInput ‖ 0x01 ‖ output(V, 1 sat) ‖ nLockTime=0
  ///
  /// Only yInput and V are free; this script emits every structural byte. One
  /// input and one output means V is necessarily output 0, so a forged Y cannot
  /// park the real verifier somewhere inert and put an OP_TRUE at output 0. The
  /// coordinator builds Y, so meeting this shape costs nothing.
  ///
  /// V itself is required to be `OP_PUSHDATA1 0xec ‖ header ‖ body`. That is
  /// what makes the check bind *state* and not just code: the body hash says
  /// the slot runs the pool's verifier, and the header push says that verifier
  /// was initialised with this header. Checking only the body would leave a
  /// coordinator free to point the next round at a verifier holding some other
  /// round's state, which would verify a proof against the wrong publics.
  ///
  /// Pre:  [yInput, vBody, bodyHash, header, nextSlot]   (nextSlot on top)
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

    // Y = version ‖ inputCount ‖ yInput ‖ outputCount ‖ output ‖ nLockTime
    b.opCode(OpCodes.OP_SWAP);
    b.addData(Uint8List.fromList([0x01, 0x00, 0x00, 0x00, 0x01]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
    // OP_1 rather than addData([0x01]): dartsv rejects a single-byte push in
    // 1..16 as non-minimal, and OP_1 puts the same [0x01] on the stack.
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_CAT);
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
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

  /// Checks that a round spent, at input 3, the verifier slot its parent's PP3
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
  /// spender's word for what input 3 was.
  ///
  /// Pre:  [parentPP3Script, scriptLHS]   (scriptLHS on top)
  /// Post: []
  static void emitVerifySpentPinnedSlot(ScriptBuilder b) {
    PP1FtScriptGen.emitReadOutpoint(b, 3);
    b.opCode(OpCodes.OP_SWAP);
    OpcodeHelpers.pushInt(b, pp3NextSlotEnd);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_DROP);
    OpcodeHelpers.pushInt(b, pp3NextSlotStart);
    b.opCode(OpCodes.OP_SPLIT); b.opCode(OpCodes.OP_NIP);
    b.opCode(OpCodes.OP_EQUALVERIFY);
  }

  /// Rebuilds a pool PP3 script with a new ownerPKH **and** a new nextSlot.
  ///
  /// A pool PP3 begins `<0x14> ownerPKH(20) <0x24> nextSlot(36) OP_DROP ...`,
  /// so the slot the next round must spend is a fixed 36-byte window at
  /// offset 22. Each round names a different slot, so unlike the plain
  /// [PP1FtScriptGen.emitRebuildPP3] the rebuild has to substitute two fields:
  ///
  ///   rebuilt = parent[0:1] + newPKH + parent[21:22] + newSlot + parent[58:]
  ///
  /// Pre:  [parentPP3Script, newOwnerPKH, newNextSlot]  (newNextSlot on top)
  /// Post: [rebuiltPP3Script]
  static void emitRebuildPP3WithNextSlot(ScriptBuilder b) {
    b.opCode(OpCodes.OP_ROT);            // parent, newSlot, newPKH

    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);          // rest1, pkhPushOp, ...
    OpcodeHelpers.pushInt(b, 20);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);            // drop the old ownerPKH
    // parent[21:], pkhPushOp, newSlot, newPKH

    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_SPLIT);          // rest3, slotPushOp, ...
    OpcodeHelpers.pushInt(b, 36);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_NIP);            // drop the old nextSlot
    // tail, slotPushOp, pkhPushOp, newSlot, newPKH

    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);   // pkhPushOp up
    b.opCode(OpCodes.OP_4); b.opCode(OpCodes.OP_ROLL);   // newPKH up
    b.opCode(OpCodes.OP_CAT);            // pkhPushOp + newPKH
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);   // slotPushOp up
    b.opCode(OpCodes.OP_CAT);            // + slotPushOp
    b.opCode(OpCodes.OP_2); b.opCode(OpCodes.OP_ROLL);   // newSlot up
    b.opCode(OpCodes.OP_CAT);            // + newSlot
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
