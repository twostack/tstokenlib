import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart' show StarkParams;
import 'package:tstokenlib/src/script_gen/slot_script_common.dart';
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
    announcement1 = PoolAnnouncement.of(1, c.f.h1, c.r1, c.w1, c.y1.tx);
    announcement2 = PoolAnnouncement.of(2, c.f.h2, c.r2, c.w2, c.y2.tx);
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
      expect(announcement2.encode().length, 2 + 4 + 236 + 3 * 32);
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
      final l = ShieldedLedger.open(d.layout, c.r0, c.w0, c.y0.tx);
      expect(l.apply(c.r1, c.w1, c.y1.tx).header.encode(), c.f.h1.encode());
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

    test('a newer version is refused as unknown', () {
      for (final m in every()) {
        final bytes = m.encode()..[0] = 2;
        expect(() => PoolMessage.decode(bytes), throwsA(isA<ProtocolRefusal>().having((r) => r.field, 'field', 'version')));
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
      final r = ShieldedChainReader.open(layout, c.r0, c.w0, c.y0.tx);
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
          round: 2, header: c.f.h1, roundTxId: announcement2.roundTxId, witnessTxId: announcement2.witnessTxId, slotTxId: announcement2.slotTxId);
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx);
      l.apply(c.r1, c.w1, c.y1.tx);
      // the wallet fetched the three transactions the lie names
      final applied = l.apply(c.r2, c.w2, c.y2.tx);
      expect(lie.disagreement(applied), contains('another header'));
      expect(announcement2.disagreement(applied), isNull);
      final wrongNumber = PoolAnnouncement(
          round: 3, header: c.f.h2, roundTxId: announcement2.roundTxId, witnessTxId: announcement2.witnessTxId, slotTxId: announcement2.slotTxId);
      expect(wrongNumber.disagreement(applied), contains('round 2'));
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
