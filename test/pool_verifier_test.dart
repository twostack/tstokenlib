import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pool_verifier_gen.dart';
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/shielded_pool/pool_header.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';

final ownerKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
final strangerKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

List<int> pkhOf(SVPrivateKey k) => hex.decode(k.publicKey.toAddress(NetworkType.TEST).pubkeyHash160);

/// V's tail on bare public lanes, for a round of four transfers: two
/// withdrawals, one deposit through receipt slot 0, one padding transfer.
/// Every field is mutable so that each test breaks exactly one thing.
class VRound {
  static const stmt = PoolStatement(transfers: 4, receiptSlots: 2);
  // Stand-in programs: any bytes V carries as constants, as long as they
  // parse as script, so non-push opcodes only.
  static List<int> ops(int n, int seed) => List<int>.generate(n, (i) => 0x51 + (i * seed + 3) % 0x2d);
  static final pp1Program = ops(15015, 7);
  static final pp3Program = ops(49158, 13);
  static final gen = PoolVerifierGen(stmt, pp1Program: pp1Program, pp3Program: pp3Program);

  final rng = Random(7);
  List<int> lanes8() => List.generate(8, (_) => rng.nextInt(M31.p));
  List<int> bytes(int n) => List.generate(n, (_) => rng.nextInt(256));

  late List<PoolPublicInputs> transfers;
  late List<List<int>> bundleHashes;
  late List<PoolWithdrawal> withdrawals;
  late List<PoolReceipt> receipts;
  late List<int> rootBefore, rootAfter, nfBefore, nfAfter;
  late List<List<int>> ring;
  int index = 3;
  List<int> receiptTransfers = [1];
  final Map<int, int> laneOverride = {};

  late List<int> h0, h1;
  List<int> signerPKH = pkhOf(ownerKey);
  SVPrivateKey signer = ownerKey;
  List<int> changePKH = pkhOf(strangerKey);
  BigInt changeSats = BigInt.from(4321);
  late List<int> pp1Prefix, pp2, slot;
  List<int> meta = [0x00, 0x6a];

  // what the transaction carries, when a test makes it disagree with the unlock
  List<PoolWithdrawal>? txWithdrawals;
  List<PoolReceipt>? txReceipts;
  BigInt? pp3Sats;
  List<int>? txPP1Program;
  List<TransactionOutput> extraOutputs = [];
  List<int>? chgRecord, changeScript;
  /// Replaces the transaction's outputs, for an attack that frames the same
  /// bytes as other outputs.
  List<TransactionOutput> Function(List<TransactionOutput> outs)? reframe;
  /// Changes the transaction the signer signed, not the one that is spent.
  void Function(Transaction tx)? tamperSignedTx;

  VRound() {
    final a = pkhOf(ownerKey), b = pkhOf(strangerKey);
    List<int> zero8() => List.filled(8, 0);
    PoolPublicInputs transfer(int out, {bool r1 = false, bool r2 = false}) =>
        PoolPublicInputs(lanes8(), lanes8(), lanes8(), lanes8(), lanes8(), out,
            outHash: zero8(), real1: r1, real2: r2, asset: PoolHash.bsvAsset);
    transfers = [transfer(30000, r1: true), transfer(-50000), transfer(0), transfer(12345, r1: true, r2: true)];
    withdrawals = [PoolWithdrawal(a, BigInt.from(30000)), PoolWithdrawal(b, BigInt.from(12345))];
    bundleHashes = [for (int t = 0; t < 4; t++) PoolOutHash.bundleHash(bytes(100 + t))];
    final wOf = {0: withdrawals[0], 3: withdrawals[1]};
    for (int t = 0; t < 4; t++) {
      transfers[t] = transfers[t].copyWith(outHash: PoolOutHash.transferLanes(bundleHashes[t], withdrawal: wOf[t]));
    }
    receipts = [PoolReceipt(SlotScript.lanesBytes(transfers[1].cmOut1), BigInt.from(50000))];
    rootBefore = lanes8();
    rootAfter = lanes8();
    nfBefore = lanes8();
    nfAfter = lanes8();
    ring = [rootBefore, lanes8(), lanes8(), lanes8()];
    final hdr0 = PoolHeader(
        cmRoot: SlotScript.lanesBytes(rootBefore),
        nfRoot: SlotScript.lanesBytes(nfBefore),
        ring: [for (final r in ring) SlotScript.lanesBytes(r)],
        size: 32 * index,
        balance: BigInt.from(1000000),
        outHash: bytes(32));
    h0 = hdr0.encode();
    h1 = hdr0
        .advance(
            cmRoot: SlotScript.lanesBytes(rootAfter),
            nfRoot: SlotScript.lanesBytes(nfAfter),
            size: 32 * index + stmt.leavesAppended,
            balance: BigInt.from(1000000 - 30000 + 50000 - 12345),
            outHash: PoolOutHash.roundOutHash(bundleHashes))
        .encode();
    pp1Prefix = [...ops(PoolVerifierGen.pp1PrefixSize - 2, 5), OpCodes.OP_PUSHDATA1, PoolHeader.byteSize];
    pp2 = ops(1366, 11);
    slot = bytes(36);
  }

  List<int> publics() {
    final out = <int>[];
    for (final p in transfers) {
      final l = p.toLanes();
      for (int c = 0; c < PoolStatement.spendChunks; c++) {
        if (PoolStatement.freeChunks.contains(c)) continue;
        out.addAll(l.sublist(8 * c, 8 * c + 8));
      }
    }
    out.addAll([...rootBefore, ...rootAfter, index, ...List.filled(7, 0)]);
    for (final r in ring) {
      out.addAll(r);
    }
    out.addAll([...nfBefore, ...nfAfter]);
    for (int r = 0; r < stmt.receiptSlots; r++) {
      if (r < receiptTransfers.length) {
        final l = transfers[receiptTransfers[r]].toLanes();
        out.addAll(l.sublist(PoolPublicInputs.idxCm1, PoolPublicInputs.idxCm1 + 8));
        out.addAll([l[PoolPublicInputs.idxPubLo], l[PoolPublicInputs.idxPubHi], 1, 0, 0, 0, 0, 0]);
      } else {
        out.addAll(List.filled(16, 0));
      }
    }
    expect(out.length, stmt.numPublics);
    laneOverride.forEach((i, v) => out[i] = v);
    return out;
  }

  static TransactionOutput output(BigInt sats, List<int> script) =>
      TransactionOutput(sats, SVScript.fromByteArray(Uint8List.fromList(script)));

  Transaction tx() {
    final t = Transaction();
    for (int i = 0; i < 5; i++) {
      t.addInputs([TransactionInput(hex.encode(List.filled(32, 0x10 + i)), i == 4 ? 1 : 0, TransactionInput.MAX_SEQ_NUMBER)]);
    }
    t.addOutputs([
      output(changeSats, changeScript ?? [0x76, 0xa9, 0x14, ...changePKH, 0x88, 0xac]),
      output(BigInt.one, [...pp1Prefix, ...h1, ...(txPP1Program ?? pp1Program)]),
      output(BigInt.one, pp2),
      output(pp3Sats ?? PoolHeader.decode(h1).balance, [0x24, ...slot, ...pp3Program]),
      output(BigInt.zero, meta),
      for (final r in txReceipts ?? receipts) TransactionOutput(BigInt.zero, r.lockingScript),
      for (final w in txWithdrawals ?? withdrawals) TransactionOutput(w.satoshis, w.lockingScript),
      ...extraOutputs,
    ]);
    if (reframe != null) {
      final outs = reframe!(t.outputs);
      t.outputs.clear();
      t.addOutputs(outs);
    }
    return t;
  }

  Uint8List preimage(Transaction t) =>
      Sighash().createSighashPreImage(t, PoolVerifierGen.sighashType, 2, PoolVerifierGen.scriptCode, BigInt.one)!;

  List<int> sign(Transaction t) {
    final signed = Transaction.fromHex(t.serialize());
    tamperSignedTx?.call(signed);
    final sig = DefaultTransactionSigner(PoolVerifierGen.sighashType, signer).signPreimage(preimage(signed));
    return hex.decode(sig.toTxFormat());
  }

  /// The V being run, and what its unlock carries below the tail: the bare
  /// lanes here, the root proof in [pool_verifier_proof_test.dart].
  PoolVerifierGen get v => gen;
  List<int> belowTail() => PoolVerifierGen.barePublics(publics());

  SVScript unlock(Transaction t) {
    final tail = List<int>.of(PoolVerifierGen.unlockTail(
        bundleHashes: bundleHashes,
        withdrawals: withdrawals,
        receipts: receipts,
        changePKH: changePKH,
        changeSatoshis: changeSats,
        pp1Prefix: pp1Prefix,
        header1: h1,
        pp2Script: pp2,
        nextSlot: slot,
        metadataScript: meta,
        signerSig: sign(t),
        signerPubKey: hex.decode(signer.publicKey.toHex()),
        preimage: preimage(t)));
    if (chgRecord != null) _replacePush(tail, PoolWithdrawal(changePKH, changeSats).encodeRecord(), chgRecord!);
    return SVScript.fromByteArray(Uint8List.fromList([...belowTail(), ...tail]));
  }

  /// Swaps the push of [from] in [script] for a push of [to], both under 76 bytes.
  static void _replacePush(List<int> script, List<int> from, List<int> to) {
    final needle = [from.length, ...from];
    for (int i = 0; i + needle.length <= script.length; i++) {
      if (List.generate(needle.length, (j) => script[i + j]).join(',') == needle.join(',')) {
        script.replaceRange(i, i + needle.length, [to.length, ...to]);
        return;
      }
    }
    throw StateError('push not found');
  }

  void run() {
    final t = tx();
    final lock = SVScript.fromByteArray(v.lock(h0, signerPKH));
    Interpreter().correctlySpends(unlock(t), lock, t, 2, verifyFlags, Coin.valueOf(BigInt.one));
  }
}

void refused(VRound r) => expect(() => r.run(), throwsA(isA<ScriptException>()));

void main() {
  group('V on bare publics', () {
    test('accepts the honest round', () {
      VRound().run();
      print('V body at 4 transfers, 2 receipt slots: ${VRound.gen.body().length} B '
          '(PP1 and PP3 programs ${VRound.pp1Program.length + VRound.pp3Program.length} B of it)');
    });

    group('the signer', () {
      test('refuses a stranger\'s key', () {
        refused(VRound()..signer = strangerKey);
      });
      test('refuses the owner\'s signature over another transaction', () {
        refused(VRound()
          ..tamperSignedTx = (t) => t.outputs[0] = VRound.output(BigInt.from(4320), t.outputs[0].script.buffer));
      });
    });

    group('header_N against the statement', () {
      test('rootBefore', () => refused(VRound()..laneOverride[VRound.stmt.roundOffset] = 1));
      test('the ring', () => refused(VRound()..laneOverride[VRound.stmt.ringOffset + 8] = 1));
      test('nfBefore', () => refused(VRound()..laneOverride[VRound.stmt.nullifierOffset] = 1));
      test('the subtree index', () => refused(VRound()..index = 4));
      test('a non-canonical lane that encodes the header\'s bytes', () {
        // lane p is the field's 0, but its four bytes are ff ff ff 7f. With a
        // header written to match, only the canonical check refuses it.
        final r = VRound();
        final h = List<int>.from(r.h0)..setRange(0, 4, [0xff, 0xff, 0xff, 0x7f]);
        r
          ..h0 = h
          ..laneOverride[VRound.stmt.roundOffset] = M31.p;
        refused(r);
      });
    });

    group('header_{N+1} against the statement', () {
      PoolHeader h1(VRound r) => PoolHeader.decode(r.h1);
      List<int> with1(VRound r, int off, List<int> v) => List<int>.from(r.h1)..setRange(off, off + v.length, v);
      test('cmRoot is rootAfter', () {
        final r = VRound();
        r.h1 = with1(r, PoolHeader.cmRootOffset, [...h1(r).cmRoot.sublist(0, 31), h1(r).cmRoot[31] ^ 1]);
        refused(r);
      });
      test('the ring is rotated', () {
        final r = VRound();
        r.h1 = with1(r, PoolHeader.ringOffset + 32, r.h0.sublist(PoolHeader.ringOffset + 64, PoolHeader.ringOffset + 96));
        refused(r);
      });
      test('the size grows by exactly the leaves appended', () {
        final r = VRound();
        r.h1 = with1(r, PoolHeader.sizeOffset, [32 * 3 + 64, 0, 0, 0]);
        refused(r);
      });
      test('nfRoot is nfAfter', () {
        final r = VRound();
        r.h1 = with1(r, PoolHeader.nfRootOffset, List.filled(32, 7));
        refused(r);
      });
      test('outHash covers the bundle hashes', () {
        final r = VRound();
        r.h1 = with1(r, PoolHeader.outHashOffset, List.filled(32, 7));
        refused(r);
      });
      test('the balance, with PP3 holding it', () {
        final r = VRound();
        final more = PoolHeader.decode(r.h1).balance + BigInt.from(1000);
        final le = [for (int i = 0; i < 8; i++) ((more >> (8 * i)) & BigInt.from(0xff)).toInt()];
        r.h1 = with1(r, PoolHeader.balanceOffset, le);
        refused(r);
      });
    });

    group('withdrawals', () {
      test('one paying more than its transfer took', () {
        final r = VRound();
        r.withdrawals = [PoolWithdrawal(pkhOf(ownerKey), BigInt.from(30001)), r.withdrawals[1]];
        refused(r);
      });
      test('one the spender\'s own proof commits to, paying more than it took', () {
        // The circuit only absorbs outHash, so a spender can hash any record
        // they like into it. What stops them hashing in a bigger payout than
        // their note paid is the amount check, not the outHash check.
        final r = VRound();
        final w = PoolWithdrawal(pkhOf(ownerKey), BigInt.from(30001));
        r.withdrawals = [w, r.withdrawals[1]];
        r.transfers[0] = r.transfers[0].copyWith(outHash: PoolOutHash.transferLanes(r.bundleHashes[0], withdrawal: w));
        refused(r);
      });
      test('one paying someone the spender did not name', () {
        final r = VRound();
        r.withdrawals = [PoolWithdrawal(pkhOf(strangerKey), BigInt.from(30000)), r.withdrawals[1]];
        refused(r);
      });
      test('one no transfer pays for', () {
        final r = VRound();
        r.withdrawals = [...r.withdrawals, PoolWithdrawal(pkhOf(strangerKey), BigInt.from(5))];
        refused(r);
      });
      test('a transfer taking money out with its withdrawal left off', () {
        final r = VRound();
        r.withdrawals = [r.withdrawals[0]];
        refused(r);
      });
      test('an asset other than BSV moving value', () {
        // Minting 7 of another asset, with the header and PP3 written as if
        // it were BSV, so that only the asset check is left to refuse it.
        final r = VRound();
        r.transfers[2] = r.transfers[2].copyWith(publicOut: -7, asset: [2, 0, 0, 0]);
        final more = PoolHeader.decode(r.h1).balance + BigInt.from(7);
        r.h1 = List<int>.from(r.h1)
          ..setRange(PoolHeader.balanceOffset, PoolHeader.balanceOffset + 8,
              [for (int i = 0; i < 8; i++) ((more >> (8 * i)) & BigInt.from(0xff)).toInt()]);
        refused(r);
      });
      test('a ciphertext swapped after the spender proved', () {
        final r = VRound();
        r.bundleHashes[2] = List.filled(32, 9);
        r.h1 = (List<int>.from(r.h1)
          ..setRange(PoolHeader.outHashOffset, PoolHeader.outHashOffset + 32, PoolOutHash.roundOutHash(r.bundleHashes)));
        refused(r);
      });
    });

    group('receipts', () {
      test('one naming another commitment', () {
        final r = VRound();
        r.receipts = [PoolReceipt(List.filled(32, 3), BigInt.from(50000))];
        refused(r);
      });
      test('one claiming more than the deposit added', () {
        final r = VRound();
        r.receipts = [PoolReceipt(r.receipts[0].commitment, BigInt.from(50001))];
        refused(r);
      });
      test('a used slot with no receipt', () => refused(VRound()..receipts = []));
      test('a receipt with no slot', () {
        final r = VRound();
        r.receipts = [...r.receipts, PoolReceipt(List.filled(32, 3), BigInt.one)];
        refused(r);
      });
    });

    group('the fixed-size pushes', () {
      test('a header shifted one byte into PP1\'s prefix', () {
        // The same output bytes, split one byte earlier: V would check
        // header' = ec ‖ H[0..235) while PP1 carries H forward, whose
        // balance and roots are header' read one byte on. Only possible when
        // header'.cmRoot starts with ec, the prefix's last byte, which a
        // coordinator can grind for. The header is then 237 bytes, which
        // the outHash read refuses as well as the size check: it reads to
        // the end of the push, so 33 bytes never equal a SHA256.
        VRound ground() {
          final r = VRound();
          r.rootAfter[0] = (r.rootAfter[0] & ~0xff) | PoolHeader.byteSize;
          final root = SlotScript.lanesBytes(r.rootAfter);
          r.h1 = List<int>.from(r.h1)
            ..setRange(PoolHeader.cmRootOffset, PoolHeader.cmRootOffset + 32, root)
            ..setRange(PoolHeader.ringOffset, PoolHeader.ringOffset + 32, root);
          expect(r.h1[0], r.pp1Prefix.last);
          return r;
        }

        ground().run();
        final r = ground();
        r.pp3Sats = PoolHeader.decode(r.h1).balance;
        r.pp1Prefix = r.pp1Prefix.sublist(0, r.pp1Prefix.length - 1);
        r.h1 = [...r.h1, 0x51];
        refused(r);
      });
      // A push between two of V's constants cannot move a byte to its
      // neighbour, so a wrong size makes its output a byte longer than the
      // length V wrote. The spilled byte, and V's own bytes after it, then
      // have to read as outputs of their own, which an opaque push after
      // them (PP2, the metadata) can be shaped to finish: 7 zeros and a
      // length, so V's varint for it becomes the next output's value.
      List<int> finisher(int n) => [...List.filled(7, 0), n - 8, ...VRound.ops(n - 8, 3)];

      test('PP1\'s prefix one byte long, the spill framed as two outputs', () {
        final r = VRound();
        final prog = VRound.pp1Program;
        r.pp1Prefix = [OpCodes.OP_NOP, ...r.pp1Prefix];
        r.pp2 = finisher(40);
        r.reframe = (outs) => [
              outs[0],
              VRound.output(BigInt.one, [...r.pp1Prefix, ...r.h1, ...prog.sublist(0, prog.length - 1)]),
              VRound.output(BigInt.from(prog.last + 0x100), []),
              VRound.output(BigInt.from(40), r.pp2.sublist(8)),
              ...outs.sublist(3),
            ];
        refused(r);
      });
      test('the next slot one byte long, the spill framed as two outputs', () {
        final r = VRound();
        final prog = VRound.pp3Program;
        r.slot = [...r.slot, OpCodes.OP_NOP];
        r.meta = finisher(40);
        r.reframe = (outs) => [
              ...outs.sublist(0, 3),
              VRound.output(outs[3].satoshis, [0x24, ...r.slot, ...prog.sublist(0, prog.length - 1)]),
              VRound.output(BigInt.from(prog.last), []),
              VRound.output(BigInt.from(40), r.meta.sublist(8)),
              ...outs.sublist(5),
            ];
        refused(r);
      });
      test('a change record one byte long, making output 0 a bare push', () {
        // value ‖ 1a, then 19 76a914 pkh 88ac, parses as an output whose
        // script pushes the P2PKH script as data: spendable by anyone.
        final r = VRound();
        final v = ByteData(8)..setUint64(0, r.changeSats.toInt(), Endian.little);
        r.chgRecord = [...r.changePKH, ...v.buffer.asUint8List(), 0x1a];
        r.changeScript = [0x19, 0x76, 0xa9, 0x14, ...r.changePKH, 0x88, 0xac];
        refused(r);
      });
    });

    group('the outputs against hashOutputs', () {
      test('PP3 holding less than the header says', () => refused(VRound()..pp3Sats = BigInt.from(1000)));
      test('another PP1 program', () {
        refused(VRound()..txPP1Program = [...VRound.pp1Program.sublist(1), 0x51]);
      });
      test('an extra output', () {
        refused(VRound()..extraOutputs = [VRound.output(BigInt.from(99), [0x51])]);
      });
      test('a withdrawal in the transaction V did not rebuild', () {
        final r = VRound();
        r.txWithdrawals = [PoolWithdrawal(pkhOf(strangerKey), BigInt.from(30000)), r.withdrawals[1]];
        refused(r);
      });
      test('a receipt in the transaction V did not rebuild', () {
        final r = VRound();
        r.txReceipts = [PoolReceipt(r.receipts[0].commitment, BigInt.from(49999))];
        refused(r);
      });
    });
  });
}
