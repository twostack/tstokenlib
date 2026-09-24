import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart' show BlockFold;
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart' show StarkParams;
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
import 'package:tstokenlib/src/shielded_pool/pool_evidence.dart';
import 'package:tstokenlib/src/shielded_pool/pool_protocol.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_chain_reader.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_ledger.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_note_scanner.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_transfer.dart';

import 'pool_test_chain.dart';

/// The wallet-to-coordinator messages, built from the test chain: each
/// kind round-trips byte for byte, decodes as hostile input, carries no
/// secret, and is a pointer to the chain rather than a fact.
void main() {
  late PoolTestChain c;
  late StarkParams spendP;
  late ShieldedPoolLayout layout;
  late PoolSubmission deposit, spend;
  late PoolReply refused, accepted, expired;
  late PoolDescriptor descriptor;
  late PoolAnnouncement announcement1, announcement2;
  late List<int> block1, block2;
  final id = List.generate(16, (i) => 0xa0 + i);

  setUpAll(() async {
    c = await PoolTestChain.build();
    spendP = c.f.agg.spendP;
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
    final d = c.f.transfers1[0];
    deposit = PoolSubmission.of(ShieldedTransfer(d.publics, d.proof, d.bundle, depositOutpoint: c.depositOutpoint), spendP,
        depositTx: c.depositTx, rng: Random(1));
    spend = PoolSubmission(id, c.f.transfers2[0].encode(spendP));
    refused = PoolReply.refused(id, RefusalReason.nullifierPending, 'another pending transfer spends the same note');
    accepted = PoolReply.accepted(id, 2);
    expired = PoolReply.expired(id, 'the anchor left the ring');
    descriptor = PoolDescriptor.forPool(network: NetworkType.TEST, issuance: c.r0, witness0: c.w0, slot0: c.y0.tx, plan: c.f.agg);
    final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
    block1 = l.apply(c.r1, c.w1, c.y1.tx).blockRoot;
    block2 = l.apply(c.r2, c.w2, c.y2.tx).blockRoot;
    announcement1 = PoolAnnouncement.of(1, c.f.h1, c.r1, c.w1, c.y1.tx, blockRoot: block1);
    announcement2 = PoolAnnouncement.of(2, c.f.h2, c.r2, c.w2, c.y2.tx, blockRoot: block2);
  });

  List<PoolMessage> every() => [deposit, spend, refused, accepted, expired, descriptor, announcement1, announcement2];

  group('message kinds', () {
    test('a deposit submission carries the transfer, the deposit transaction and the id, and decodes to the same three', () {
      final back = PoolSubmission.decode(deposit.encode());
      expect(back.id, deposit.id);
      expect(back.transferBytes, deposit.transferBytes);
      expect(back.depositTx, deposit.depositTx);
      expect(back.transfer(spendP).encode(spendP), deposit.transferBytes);
      expect(back.depositTransaction()!.id, c.depositTx.id);
      expect(back.transfer(spendP).depositOutpoint, c.depositOutpoint);
      expect(spend.depositTx, isNull);
      expect(PoolSubmission.decode(spend.encode()).depositTransaction(), isNull);
    });

    test('a reply to a refused transfer carries the id, the outcome, the reason number and sentence, and nothing else', () {
      final bytes = refused.encode();
      final sentence = 'another pending transfer spends the same note'.codeUnits;
      expect(bytes.length, 2 + 16 + 1 + 2 + 2 + sentence.length);
      expect(bytes.sublist(2, 18), id);
      expect(bytes[18], ReplyOutcome.refused.number);
      expect(bytes[19] | (bytes[20] << 8), RefusalReason.nullifierPending.number);
      expect(bytes.sublist(23), sentence);
      final back = PoolReply.decode(bytes);
      expect(back.outcome, ReplyOutcome.refused);
      expect(back.reason, RefusalReason.nullifierPending);
      expect(back.sentence, 'another pending transfer spends the same note');
      expect(back.round, isNull);
      expect(PoolReply.decode(accepted.encode()).round, 2);
      expect(PoolReply.decode(expired.encode()).sentence, 'the anchor left the ring');
    });

    test('the reason numbers are fixed', () {
      expect([for (final r in RefusalReason.values) r.number], List.generate(RefusalReason.values.length, (i) => i + 1));
      expect(RefusalReason.of(RefusalReason.proof.number), RefusalReason.proof);
      expect(RefusalReason.of(99), isNull);
    });

    test('an announcement has what a reader applies: round 2\'s txids and header 2', () {
      final a = PoolAnnouncement.decode(announcement2.encode());
      expect(a.round, 2);
      expect(a.roundId, c.r2.id);
      expect(a.witnessId, c.w2.id);
      expect(a.slotId, c.y2.tx.id);
      expect(a.header.encode(), c.f.h2.encode());
      expect(announcement2.encode().length, 2 + 4 + 236 + 3 * 32 + 32);
    });

    test('an announcement carries its block root', () {
      final a = PoolAnnouncement.decode(announcement2.encode());
      expect(a.blockRoot, block2);
      expect(a.blockRoot.length, 32);
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      expect(a.blockRoot, l.apply(c.r2, c.w2, c.y2.tx).blockRoot);
      expect(announcement1.blockRoot, isNot(a.blockRoot));
    });

    test('a descriptor opens a ledger and gives the layout a reader uses', () {
      final d = PoolDescriptor.decode(descriptor.encode());
      expect(d.network, NetworkType.TEST);
      expect(hex.encode(d.issuance), c.r0.id);
      expect(hex.encode(d.witness0), c.w0.id);
      expect(hex.encode(d.slot0), c.y0.tx.id);
      expect(d.arities, [2, 2]);
      expect(d.nullifierLevel, 1);
      expect(d.receiptSlots, 2);
      expect(d.transfers, 4);
      expect(d.spendP.logTrace, spendP.logTrace);
      expect(d.spendP.numQueries, spendP.numQueries);
      expect(d.spendP.zkRandomizers, spendP.zkRandomizers);
      final l = ShieldedLedger.open(d.layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      expect(l.apply(c.r1, c.w1, c.y1.tx).header.encode(), c.f.h1.encode());
    });

    test('a descriptor a wallet can act on alone: the leaf count, the tokenId and the genesis header', () {
      final d = PoolDescriptor.decode(descriptor.encode());
      expect(d.leavesPerRound, 32);
      expect(d.blockLevel, 5);
      expect(d.leavesPerRound, d.layout.leavesPerRound);
      // the tokenId is the one the issuance's PP1 carries, read through the
      // body check
      final (fields, _) = PoolEvidence.readPP1Of(c.r0, PoolEvidence.pp1Vout);
      expect(d.tokenId, fields!.tokenId);
      expect(d.genesisHeader, c.f.g.encode());

      // everything a payee needs to call a round this pool's, with no
      // lookup: the descriptor's own three fields go straight into the
      // evidence check
      final (proven, why) = PoolEvidence.provenRound(
          round: c.r2,
          witness: c.w2,
          tokenId: d.tokenId,
          verifierBodyHash: fields.verifierBodyHash,
          genesisHeader: d.genesisHeader);
      expect(why, isNull);
      expect(proven!.header.encode(), c.f.h2.encode());

      // and a descriptor whose leaf count is not the plan's is refused
      // where it is written
      expect(
          () => PoolDescriptor(
              network: NetworkType.TEST,
              issuance: descriptor.issuance,
              witness0: descriptor.witness0,
              slot0: descriptor.slot0,
              arities: const [2, 2],
              nullifierLevel: 1,
              receiptSlots: 2,
              spendP: spendP,
              leavesPerRound: 64,
              tokenId: d.tokenId,
              genesisHeader: d.genesisHeader),
          throwsA(isA<ArgumentError>()));
    });

    test('a descriptor stays small: the production plan under 512 bytes', () {
      final production = PoolDescriptor(
          network: NetworkType.MAIN,
          issuance: descriptor.issuance,
          witness0: descriptor.witness0,
          slot0: descriptor.slot0,
          arities: const [16, 4, 2, 2],
          nullifierLevel: 1,
          receiptSlots: 8,
          spendP: spendP,
          leavesPerRound: 512,
          tokenId: descriptor.tokenId,
          genesisHeader: descriptor.genesisHeader);
      expect(production.transfers, 256);
      expect(production.blockLevel, 9);
      final bytes = production.encode();
      print('  a production descriptor is ${bytes.length} bytes');
      expect(bytes.length, lessThan(512));
      expect(PoolDescriptor.decode(bytes), production);

      // 300 transfers a round would append 608 leaves, which is not a power
      // of two: the descriptor refuses it, as the plan does
      expect(
          () => PoolDescriptor(
              network: NetworkType.MAIN,
              issuance: descriptor.issuance,
              witness0: descriptor.witness0,
              slot0: descriptor.slot0,
              arities: const [15, 5, 4],
              nullifierLevel: 1,
              receiptSlots: 8,
              spendP: spendP,
              leavesPerRound: 608,
              tokenId: descriptor.tokenId,
              genesisHeader: descriptor.genesisHeader),
          throwsA(isA<ArgumentError>().having((e) => e.message.toString(), 'message', contains('608'))));
    });
  });

  group('catch-up', () {
    // a block a head proof points into: four transactions, the witness
    // third, with the merkle root computed here the plain way
    List<int> dsha(List<int> b) => crypto.sha256.convert(crypto.sha256.convert(b).bytes).bytes;
    List<int> internal(String txid) => hex.decode(txid).reversed.toList();

    ({List<int> root, int index, List<List<int>> branch}) blockOf(String witnessId) {
      final ids = [
        List.filled(32, 0x11),
        List.filled(32, 0x22),
        internal(witnessId),
        List.filled(32, 0x44),
      ];
      const index = 2;
      final a = dsha([...ids[0], ...ids[1]]);
      final b = dsha([...ids[2], ...ids[3]]);
      final root = dsha([...a, ...b]);
      // the witness is the left child of b, whose sibling is ids[3]; b's
      // sibling is a
      return (root: root.reversed.toList(), index: index, branch: [
        ids[3].reversed.toList(),
        a.reversed.toList(),
      ]);
    }

    test('three kinds of request, and an unknown kind is refused naming it', () {
      final requests = [
        PoolCatchUpRequest.blockRoots(from: 1, count: 1024),
        PoolCatchUpRequest.frontier(),
        PoolCatchUpRequest.head(),
      ];
      for (final q in requests) {
        final bytes = q.encode();
        final back = PoolCatchUpRequest.decode(bytes);
        expect(back.what, q.what);
        expect(back.from, q.from);
        expect(back.count, q.count);
        expect(back.encode(), bytes);
        expect(PoolMessage.decode(bytes), q);
      }
      // version 3: version, kind, a 16-byte id, then the kind byte at 18
      final bad = requests.first.encode()..[18] = 9;
      expect(() => PoolMessage.decode(bad),
          throwsA(isA<ProtocolRefusal>().having((r) => r.reason, 'reason', contains('kind 9'))));
      // a frontier or head request names no rounds
      final noisy = requests[1].encode()..[19] = 7;
      expect(() => PoolMessage.decode(noisy), throwsA(isA<ProtocolRefusal>()));
    });

    test('block roots in a range fold to the round\'s commitment root', () {
      final reply = PoolCatchUpReply.blockRoots(from: 1, roots: [block1, block2]);
      final back = PoolCatchUpReply.decode(reply.encode()) ;
      expect(back.what, CatchUpKind.blockRoots);
      expect(back.from, 1);
      expect(back.roots.length, 2);
      expect(back.roots[0], block1);
      expect(back.roots[1], block2);

      final fold = BlockFold(descriptor.leavesPerRound);
      for (int i = 0; i < back.roots.length; i++) {
        fold.fold(back.from + i, back.roots[i]);
      }
      expect(fold.cmRoot, c.f.h2.cmRoot);
      expect(fold.rounds, 2);
    });

    test('a range outside the published set is refused, naming it', () {
      expect(descriptor.catchUpRange, 1024);
      descriptor.requireRange(PoolCatchUpRequest.blockRoots(from: 1, count: 1024));
      descriptor.requireRange(PoolCatchUpRequest.blockRoots(from: 1025, count: 1024));
      descriptor.requireRange(PoolCatchUpRequest.frontier());
      for (final q in [
        PoolCatchUpRequest.blockRoots(from: 2, count: 1024),
        PoolCatchUpRequest.blockRoots(from: 1, count: 2),
        PoolCatchUpRequest.blockRoots(from: 1000, count: 1024),
      ]) {
        expect(() => descriptor.requireRange(q),
            throwsA(isA<ProtocolRefusal>()
                .having((r) => r.field, 'field', 'range')
                .having((r) => r.reason, 'reason', contains('${q.from}'))));
      }
    });

    test('a frontier reproduces the root, and a follower built from it folds on', () {
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      final f = l.frontier();
      expect(f.round, 1);
      final reply = PoolCatchUpReply.frontier(round: f.round, blockRoot: f.blockRoot, left: f.left);
      final back = PoolCatchUpReply.decode(reply.encode());
      expect(back.round, 1);
      expect(back.blockRoot, block1);
      expect(back.left, f.left);

      // the follower a new wallet builds from it stands where the pool does
      final fold = BlockFold.at(
          leavesPerRound: descriptor.leavesPerRound, round: back.round, blockRoot: back.blockRoot!, left: back.left);
      expect(fold.cmRoot, c.f.h1.cmRoot, reason: 'the frontier reproduces round 1\'s commitment root');

      // and it folds round 2 as a follower that had been there all along
      final applied = l.apply(c.r2, c.w2, c.y2.tx);
      expect(fold.fold(2, applied.blockRoot, cmRoot: applied.header.cmRoot), c.f.h2.cmRoot);

      // a frontier of another tree does not reproduce the root
      final wrong = PoolCatchUpReply.frontier(round: 1, blockRoot: block2, left: f.left);
      final off = BlockFold.at(
          leavesPerRound: descriptor.leavesPerRound, round: 1, blockRoot: wrong.blockRoot!, left: wrong.left);
      expect(off.cmRoot, isNot(c.f.h1.cmRoot));
    });

    test('a head proof checks out, and its branch reaches the block\'s merkle root', () {
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      final applied = l.apply(c.r2, c.w2, c.y2.tx);
      final b = blockOf(c.w2.id);
      final reply = PoolCatchUpReply.head(
          round: 2,
          roundTx: hex.decode(c.r2.serialize()),
          witnessTx: hex.decode(c.w2.serialize()),
          blockHash: List.filled(32, 0xbb),
          txIndex: b.index,
          branch: b.branch);
      final back = PoolCatchUpReply.decode(reply.encode());
      expect(back.round, 2);
      expect(back.computedMerkleRoot(), b.root,
          reason: 'the branch reaches the block\'s merkle root, which only the wallet\'s headers can confirm');

      // and the round it carries is this pool's, by the evidence check
      final (fields, _) = PoolEvidence.readPP1Of(c.r0, PoolEvidence.pp1Vout);
      final (proven, why) = PoolEvidence.provenRound(
          round: ShieldedLedger.parse(back.roundTx!),
          witness: ShieldedLedger.parse(back.witnessTx!),
          tokenId: descriptor.tokenId,
          verifierBodyHash: fields!.verifierBodyHash,
          genesisHeader: descriptor.genesisHeader);
      expect(why, isNull);
      expect(proven!.cmRoot, applied.header.cmRoot);
      print('  a head proof at test parameters is ${reply.encode().length} bytes');
    });

    test('a reply carries no asker, and replies are bounded', () {
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      final f = l.frontier();
      final replies = [
        PoolCatchUpReply.blockRoots(from: 1, roots: [block1]),
        PoolCatchUpReply.frontier(round: f.round, blockRoot: f.blockRoot, left: f.left),
      ];
      final asker = List.generate(16, (i) => 0xc0 + i);
      for (final r in replies) {
        expect(_contains(r.encode(), asker), isFalse);
        expect(_contains(r.encode(), id), isFalse);
      }

      // a reply that claims more roots than the bound is refused before
      // anything is allocated
      final tooMany = PoolCatchUpReply.blockRoots(from: 1, roots: [block1]).encode();
      final over = [...tooMany];
      // version, kind, id 16, what, status, from 4: the count is at 24
      over[24] = 0xff;
      over[25] = 0xff;
      over[26] = 0xff;
      over[27] = 0x7f;
      expect(
          () => PoolCatchUpReply.decode(over),
          throwsA(isA<ProtocolRefusal>()
              .having((r) => r.field, 'field', 'roots')
              .having((r) => r.reason, 'reason', contains('${PoolMessage.maxBlockRoots}'))));
      expect(() => PoolCatchUpReply.blockRoots(from: 1, roots: List.generate(PoolMessage.maxBlockRoots + 1, (_) => block1)),
          throwsA(isA<ArgumentError>()));
    });

    test('10,000 mutated catch-up messages end in a message or a named refusal', () {
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      final f = l.frontier();
      final seeds = <List<int>>[
        PoolCatchUpRequest.blockRoots(from: 1, count: 1024).encode(),
        PoolCatchUpRequest.frontier().encode(),
        PoolCatchUpRequest.head().encode(),
        PoolCatchUpReply.blockRoots(from: 1, roots: [block1, block2]).encode(),
        PoolCatchUpReply.frontier(round: f.round, blockRoot: f.blockRoot, left: f.left).encode(),
        PoolCatchUpReply.head(
                round: 1,
                roundTx: hex.decode(c.r1.serialize()),
                witnessTx: hex.decode(c.w1.serialize()),
                blockHash: List.filled(32, 0xbb),
                txIndex: 3,
                branch: [List.filled(32, 0x55)])
            .encode(),
      ];
      final rng = Random(2609);
      var refusals = 0, decoded = 0;
      for (int i = 0; i < 10000; i++) {
        final seed = seeds[rng.nextInt(seeds.length)];
        final bytes = [...seed];
        final hits = 1 + rng.nextInt(3);
        for (int h = 0; h < hits; h++) {
          bytes[rng.nextInt(bytes.length)] = rng.nextInt(256);
        }
        if (rng.nextBool() && bytes.length > 4) bytes.length = 2 + rng.nextInt(bytes.length - 2);
        try {
          PoolMessage.decode(bytes);
          decoded++;
        } on ProtocolRefusal {
          refusals++;
        }
      }
      expect(refusals + decoded, 10000);
      print('  10,000 mutated catch-up messages: $refusals refused, $decoded still decoded');
    });
  });

  group('encoding', () {
    test('round trip of every kind, byte for byte', () {
      for (final m in every()) {
        final bytes = m.encode();
        final back = PoolMessage.decode(bytes);
        expect(back.kind, m.kind);
        expect(back, m, reason: '${m.kind.name} decodes to an equal message');
        expect(back.encode(), bytes, reason: '${m.kind.name} re-encodes to the same bytes');
        expect(PoolMessage.kindOf(bytes), m.kind);
      }
    });

    test('another version, older or newer, is refused as unknown', () {
      expect(PoolMessage.formatVersion, 3);
      for (final m in every()) {
        for (final v in [2, 4]) {
          final bytes = m.encode()..[0] = v;
          expect(() => PoolMessage.decode(bytes), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'version')),
              reason: '${m.kind.name} at version $v');
        }
      }
    });

    test('a truncated encoding and a trailing byte are refused', () {
      for (final m in every()) {
        final bytes = m.encode();
        expect(() => PoolMessage.decode(bytes.sublist(0, bytes.length - 1)), throwsA(isA<ProtocolRefusal>()),
            reason: '${m.kind.name} cut short');
        expect(() => PoolMessage.decode([...bytes, 0]), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'end')),
            reason: '${m.kind.name} with a byte after the last field');
      }
    });

    test('a message of one kind is refused by another kind\'s decoder', () {
      expect(() => PoolReply.decode(announcement1.encode()), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'kind')));
      expect(() => PoolSubmission.decode(announcement1.encode()), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'kind')));
      // a submission is over the bound every other kind has, so it is refused on size first
      expect(() => PoolReply.decode(deposit.encode()), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'size')));
    });
  });

  group('untrusted input', () {
    test('an oversized submission is refused as too large without being parsed', () {
      final big = Uint8List(1024 * 1024);
      big[0] = PoolMessage.formatVersion;
      big[1] = PoolMessageKind.submission.number;
      final sw = Stopwatch()..start();
      expect(() => PoolSubmission.decode(big), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'size')));
      expect(() => PoolMessage.decode(big), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'size')));
      expect(sw.elapsedMilliseconds, lessThan(50));
      final other = Uint8List(PoolMessage.maxOther + 1);
      other[0] = PoolMessage.formatVersion;
      other[1] = PoolMessageKind.announcement.number;
      expect(() => PoolAnnouncement.decode(other), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'size')));
    });

    test('a deposit transaction over its bound is refused before it is read', () {
      final bytes = BytesBuilder()
        ..add(spend.encode().sublist(0, spend.encode().length - 2))
        ..add(PoolMessage.u16(PoolMessage.maxDepositTx + 1));
      expect(() => PoolSubmission.decode(bytes.toBytes()),
          throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'depositTx').having((r) => r.reason, 'reason', contains('at most'))));
    });

    test('10,000 random strings and 10,000 single-byte mutations of each kind end in a message or a named refusal', () {
      final rng = Random(9);
      var messages = 0, refusals = 0;
      void outcome(List<int> bytes, PoolMessage Function(List<int>) decode) {
        try {
          decode(bytes);
          messages++;
        } on ProtocolRefusal catch (e) {
          expect(e.field, isNotEmpty);
          refusals++;
        }
      }

      final kinds = <(PoolMessage, PoolMessage Function(List<int>))>[
        (deposit, PoolSubmission.decode),
        (refused, PoolReply.decode),
        (descriptor, PoolDescriptor.decode),
        (announcement1, PoolAnnouncement.decode),
      ];
      for (final (m, decode) in kinds) {
        final valid = m.encode();
        for (int i = 0; i < 10000; i++) {
          final n = rng.nextInt(i % 100 == 0 ? 2 * valid.length : 64);
          outcome(List.generate(n, (_) => rng.nextInt(256)), decode);
          outcome(List.generate(n, (_) => rng.nextInt(256)), PoolMessage.decode);
        }
        for (int i = 0; i < 10000; i++) {
          final at = rng.nextInt(valid.length);
          final mutated = Uint8List.fromList(valid)..[at] = (valid[at] + 1 + rng.nextInt(255)) & 0xff;
          outcome(mutated, decode);
        }
        // a length field zeroed or maxed, which one flipped byte rarely does
        for (int at = 0; at + 4 <= valid.length; at++) {
          for (final fill in [0x00, 0xff]) {
            outcome(Uint8List.fromList(valid)..fillRange(at, at + 4, fill), decode);
          }
        }
      }
      expect(messages, greaterThan(0), reason: 'a mutation of an id or a sentence still decodes');
      expect(refusals, greaterThan(0));
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  group('no secrets and nothing trusted', () {
    test('a wallet\'s submission holds no key material of the wallet', () async {
      // the wallet's spent note comes off the chain, as the wallet found it
      final r = ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      r.read([(round: c.r1, witness: c.w1, nextSlot: c.y1.tx)]);
      final scanner = ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]);
      await scanner.scan(r.rounds.single);
      final note = scanner.notes.single.note;
      final w = c.f.wallet;
      final secrets = {
        'sk': w.sk,
        'ivk': w.ivk,
        'nk': w.nk,
        'ovk': w.ovk,
        'rho': note.rho,
        'rcm': note.rcm,
        'd': c.f.walletD,
      };
      final bytes = spend.encode();
      for (final e in secrets.entries) {
        final needle = SlotScript.lanesBytes(e.value);
        expect(_contains(bytes, needle), isFalse, reason: 'the submission contains the wallet\'s ${e.key}');
      }
      // the same transfer without the bundle would still name nothing: the
      // nullifier is a hash of nk and rho, not either
      expect(_contains(bytes, SlotScript.lanesBytes(c.f.transfers2[0].publics.nf1)), isTrue);
    });

    test('a lying announcement is caught when the round is read', () {
      final lie = PoolAnnouncement(
          round: 2,
          header: c.f.h1,
          roundTxId: announcement2.roundTxId,
          witnessTxId: announcement2.witnessTxId,
          slotTxId: announcement2.slotTxId,
          blockRoot: block2);
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      l.apply(c.r1, c.w1, c.y1.tx);
      // the wallet fetched the three transactions the lie names
      final applied = l.apply(c.r2, c.w2, c.y2.tx);
      expect(lie.disagreement(applied), contains('another header'));
      expect(announcement2.disagreement(applied), isNull);
      final wrongNumber = PoolAnnouncement(
          round: 3,
          header: c.f.h2,
          roundTxId: announcement2.roundTxId,
          witnessTxId: announcement2.witnessTxId,
          slotTxId: announcement2.slotTxId,
          blockRoot: block2);
      expect(wrongNumber.disagreement(applied), contains('round 2'));
      // and a block root that is not the round's is caught the same way
      final wrongBlock = PoolAnnouncement(
          round: 2,
          header: c.f.h2,
          roundTxId: announcement2.roundTxId,
          witnessTxId: announcement2.witnessTxId,
          slotTxId: announcement2.slotTxId,
          blockRoot: [...block1]);
      expect(wrongBlock.disagreement(applied), contains('another block root'));
    });
  });
}

bool _contains(List<int> hay, List<int> needle) {
  outer:
  for (int i = 0; i + needle.length <= hay.length; i++) {
    for (int j = 0; j < needle.length; j++) {
      if (hay[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
