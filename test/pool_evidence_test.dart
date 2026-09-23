import 'dart:io';
import 'dart:math';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/shielded_pool/pool_evidence.dart';

import 'pool_forgery.dart';
import 'pool_test_chain.dart';

/// What a payee checks before believing a payment: that a round is this
/// pool's, and that a note is in that round.
///
/// Nothing here verifies a STARK and nothing here holds a key. The round was
/// mined, which means the chain ran PP1's script over the witness that spends
/// it; what a payee does is read bytes. Which is exactly why the body check
/// matters: the offsets carry no authority, the script body does.
void main() {
  late PoolTestChain c;
  late ShieldedPoolLayout layout;
  late ShieldedRound round1, round2;
  late ShieldedLedger ledger;
  final strangerAddr = Address.fromPublicKey(SVPrivateKey().publicKey, NetworkType.TEST);

  setUpAll(() async {
    c = await PoolTestChain.build();
    layout = ShieldedPoolLayout.forArities([2, 2], nullifierLevel: 1, receiptSlots: 2);
    ledger = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
    round1 = ledger.apply(c.r1, c.w1, c.y1.tx);
    round2 = ledger.apply(c.r2, c.w2, c.y2.tx);
  });

  (ProvenRound?, EvidenceRefusal?) check(Transaction round, Transaction witness, {List<int>? tokenId}) =>
      PoolEvidence.provenRound(
          round: round,
          witness: witness,
          tokenId: tokenId ?? c.tokenId,
          verifierBodyHash: c.identity.verifierBodyHash,
          genesisHeader: c.genesisHeader);

  /// The fixture wallet's note from round 1, as a payee holds it: the
  /// opening it was sent, its position, and its path against the round it
  /// arrived in.
  Future<({ScannedNote note, List<int> pkd, MerklePath path})> wallet1() async {
    final scanner = ShieldedNoteScanner.forWallet(c.f.wallet, [c.f.walletD]);
    final found = await scanner.scan(round1);
    expect(found, isNotEmpty, reason: 'the fixture pays the wallet in round 1');
    final note = found.first;
    final addr = await NoteAddress.derive(c.f.wallet.ivk, note.d);
    // the path as the pool gave it when round 1 was mined
    final at1 = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
    at1.apply(c.r1, c.w1, c.y1.tx);
    return (note: note, pkd: addr.pkd, path: at1.tree.path(note.position));
  }

  group('a proven round', () {
    test('a round of the test chain is proven, with its header and commitment root', () {
      final (proven, why) = check(c.r2, c.w2);
      expect(why, isNull, reason: '$why');
      expect(proven!.header.encode(), c.f.h2.encode());
      expect(proven.cmRoot, round2.header.cmRoot);
      expect(proven.ownerPKH, c.identity.ownerPKH);
      // round 1 is proven too, and it is a different round: the check says
      // the round happened, never that it is the latest
      final (first, _) = check(c.r1, c.w1);
      expect(first!.cmRoot, round1.header.cmRoot);
      expect(first.cmRoot, isNot(proven.cmRoot));
    });

    test('a witness that spends another round is refused, and reports nothing', () {
      final (proven, why) = check(c.r2, c.w1);
      expect(proven, isNull);
      expect(why!.step, 'witness spends PP1');
      expect(why.reason, contains(c.r2.id));
    });

    test('another pool\'s tokenId is refused, naming both', () {
      final other = List<int>.generate(32, (i) => (i * 13 + 5) & 0xff);
      final (proven, why) = check(c.r2, c.w2, tokenId: other);
      expect(proven, isNull);
      expect(why!.step, 'tokenId');
      expect(why.reason, contains(hex.encode(c.tokenId.take(8).toList())));
      expect(why.reason, contains(hex.encode(other.take(8).toList())));
    });

    test('a descriptor checks a round with nothing else', () {
      final d = PoolDescriptor.forPool(
          network: NetworkType.TEST, issuance: c.r0, witness0: c.w0, slot0: c.y0.tx, plan: c.f.agg);
      final (proven, why) = d.provenRound(round: c.r2, witness: c.w2);
      expect(why, isNull);
      expect(proven!.cmRoot, round2.header.cmRoot);
    });
  });

  group('a proven note', () {
    test('a note of the test chain is present, with its value', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      final (note, why) = PoolEvidence.provenNote(
          round: proven!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
      expect(why, isNull, reason: '$why');
      expect(note!.value, w.note.value);
      expect(note.position, w.note.position);
      expect(note.commitment, hex.decode(hex.encode(_bytes(w.note.cm))));
    });

    test('an opening that is not the holder\'s is refused, naming the path', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      final stranger = await NoteAddress.at(PoolWalletKeys(List.generate(5, (i) => i + 1)).ivk, 0);
      final (note, why) = PoolEvidence.provenNote(
          round: proven!, opening: w.note.note, pkd: stranger.pkd, position: w.note.position, path: w.path.siblings);
      expect(note, isNull);
      expect(why!.step, 'path', reason: 'a commitment under another key is not in the tree');
    });

    test('a path to another root is refused, naming both', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      final bent = [for (final s in w.path.siblings) [...s]];
      bent[0][0] ^= 1;
      final (note, why) = PoolEvidence.provenNote(
          round: proven!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: bent);
      expect(note, isNull);
      expect(why!.step, 'path');
      expect(why.reason, contains(hex.encode(proven.cmRoot.take(8).toList())));
    });

    test('a note under a root a follower folded reaches the same verdict', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      final (byRound, why1) = PoolEvidence.provenNote(
          round: proven!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
      // the root a follower holds for round 1, from folding its block root
      final fold = BlockFold(layout.leavesPerRound);
      fold.fold(1, round1.blockRoot, cmRoot: round1.header.cmRoot);
      final (byFold, why2) = PoolEvidence.noteUnderRoot(
          cmRoot: fold.cmRoot, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
      expect(why1, isNull);
      expect(why2, isNull);
      expect(byFold!.value, byRound!.value);
      expect(byFold.commitment, byRound.commitment);
      // and a root that is not that round's is refused, not believed
      expect(
          PoolEvidence.noteUnderRoot(
                  cmRoot: round2.header.cmRoot,
                  opening: w.note.note,
                  pkd: w.pkd,
                  position: w.note.position,
                  path: w.path.siblings)
              .$2!
              .step,
          'path');
      expect(
          PoolEvidence.noteUnderRoot(
                  cmRoot: const [1, 2, 3],
                  opening: w.note.note,
                  pkd: w.pkd,
                  position: w.note.position,
                  path: w.path.siblings)
              .$2!
              .step,
          'commitment root');
    });

    test('a path of the wrong shape, a position outside the tree and a lane outside the field are refused by name', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      (ProvenNote?, EvidenceRefusal?) at({int? position, List<List<int>>? path, List<int>? pkd}) => PoolEvidence.provenNote(
          round: proven!,
          opening: w.note.note,
          pkd: pkd ?? w.pkd,
          position: position ?? w.note.position,
          path: path ?? w.path.siblings);
      expect(at(path: w.path.siblings.sublist(1)).$2!.step, 'path');
      expect(at(position: -1).$2!.step, 'position');
      expect(at(position: 1 << 32).$2!.step, 'position');
      expect(at(pkd: List.filled(8, 0x7fffffff)).$2!.step, 'pk_d');
      expect(at(pkd: List.filled(7, 0)).$2!.step, 'pk_d');
    });
  });

  group('the forgery, against the ledger', () {
    /// A round of this pool whose PP1 output carries the real script's first
    /// 563 bytes over a body that spends on a signature.
    Transaction forgedRound() => withOutputScript(c.r2, 1, lookalikePP1(c.r2.outputs[1].script, strangerAddr));

    test('reads as this pool by offset, and is refused by the body check', () {
      final forged = forgedRound();
      // by offset it is this pool, field for field
      final parsed = PP1SpLockBuilder.fromScript(forged.outputs[1].script);
      expect(parsed.tokenId, c.tokenId);
      expect(parsed.genesisHeader, c.genesisHeader);
      // through the body check it is not a PP1_SP at all
      final (fields, why) = PoolEvidence.readPP1Of(forged, 1);
      expect(fields, isNull);
      expect(why!.step, 'PP1 is this pool\'s script');
      expect(why.reason, contains('not its body'));
    });

    test('a forged round offered to a ledger is refused at output 1, before any header is read', () {
      final forged = forgedRound();
      // a witness of the forger's own, so the tip checks pass and the round
      // reaches the header read
      final w = witnessFor(forged, strangerAddr);
      final at1 = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      at1.apply(c.r1, c.w1, c.y1.tx);
      final before = at1.snapshot();
      expect(
          () => at1.apply(forged, w, c.y2.tx),
          throwsA(isA<LedgerRefusal>()
              .having((e) => e.check, 'check', 'header')
              .having((e) => e.reason, 'reason', contains('output 1 is not a PP1_SP'))));
      expect(at1.snapshot(), before, reason: 'a refused round leaves the ledger as it was');
    });

    test('a round cannot be applied over a real tip anyway', () {
      // the spend chain holds on its own: a forgery that does not spend the
      // tip's PP3 never reaches the body check
      final loose = Transaction()
        ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
        ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
        ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
        ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
        ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
        ..addOutputs([
          for (int k = 0; k < 5; k++)
            TransactionOutput(BigInt.one, k == 1 ? lookalikePP1(c.r2.outputs[1].script, strangerAddr) : SVScript.fromString('OP_1'))
        ]);
      final at1 = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      at1.apply(c.r1, c.w1, c.y1.tx);
      expect(() => at1.apply(loose, witnessFor(loose, strangerAddr), c.y2.tx),
          throwsA(isA<LedgerRefusal>().having((e) => e.check, 'check', 'tip')));
    });

    test('a forged genesis is refused, naming the tokenId', () {
      // the same triple, opened with the descriptor of another pool: what a
      // forger's own genesis looks like to a wallet that knows which pool it
      // meant
      final other = List<int>.generate(32, (i) => (i * 3 + 9) & 0xff);
      expect(
          () => ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: other, genesisHeader: c.genesisHeader),
          throwsA(isA<LedgerRefusal>()
              .having((e) => e.check, 'check', 'genesis')
              .having((e) => e.reason, 'reason', contains(hex.encode(other)))));

      // and a genesis whose PP1 is a lookalike is refused before that
      final forged = withOutputScript(c.r0, 1, lookalikePP1(c.r0.outputs[1].script, strangerAddr));
      expect(
          () => ShieldedLedger.open(layout, forged, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader),
          throwsA(isA<LedgerRefusal>().having((e) => e.reason, 'reason', contains('not a PP1_SP'))));

      // a genesis header that is not the one published is refused too
      final otherGenesis = [...c.genesisHeader]..[100] ^= 1;
      expect(
          () => ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: otherGenesis),
          throwsA(isA<LedgerRefusal>().having((e) => e.reason, 'reason', contains('different state'))));
    });

    test('the test pool opens at round 0 as before', () {
      final l = ShieldedLedger.open(layout, c.r0, c.w0, c.y0.tx, tokenId: c.tokenId, genesisHeader: c.genesisHeader);
      expect(l.round, 0);
      expect(l.size, 0);
      expect(l.header.encode(), c.f.g.encode());
    });
  });

  group('untrusted input, no trust, no requests', () {
    test('10,000 mutated rounds, witnesses, openings, positions and paths: named refusals, never proven', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      final roundBytes = hex.decode(c.r1.serialize()), witnessBytes = hex.decode(c.w1.serialize());
      final rng = Random(1609);
      var refused = 0, passed = 0;
      for (int i = 0; i < 10000; i++) {
        try {
          if (i.isEven) {
            // the transactions
            final which = rng.nextBool();
            final bytes = [...(which ? roundBytes : witnessBytes)];
            for (int h = 0; h < 1 + rng.nextInt(3); h++) {
              bytes[rng.nextInt(bytes.length)] = rng.nextInt(256);
            }
            final Transaction tx;
            try {
              tx = ShieldedLedger.parse(bytes);
            } on LedgerRefusal {
              refused++;
              continue;
            }
            final (ok, why) = check(which ? tx : c.r1, which ? c.w1 : tx);
            if (ok == null) {
              expect(why!.step, isNotEmpty);
              refused++;
            } else {
              // a mutation the chain would not have accepted can still leave
              // the PP1 and the spends intact; what must never happen is a
              // forged PP1 reading as proven
              expect(ok.header.encode(), c.f.h1.encode());
              passed++;
            }
          } else {
            // the opening, the position and the path
            final bent = [for (final s in w.path.siblings) [...s]];
            var position = w.note.position;
            switch (rng.nextInt(3)) {
              case 0:
                bent[rng.nextInt(bent.length)][rng.nextInt(8)] = rng.nextInt(0x7fffffff);
              case 1:
                position = rng.nextInt(1 << 20);
              default:
                bent[rng.nextInt(bent.length)] = List.generate(rng.nextInt(10), (_) => rng.nextInt(1 << 31));
            }
            final (note, why) = PoolEvidence.provenNote(
                round: proven!, opening: w.note.note, pkd: w.pkd, position: position, path: bent);
            if (note == null) {
              expect(why!.step, isNotEmpty);
              refused++;
            } else {
              expect(position, w.note.position);
              passed++;
            }
          }
        } on EvidenceRefusal {
          fail('a refusal escaped as an exception');
        }
      }
      expect(refused + passed, 10000);
      print('  10,000 mutations: $refused refused by name, $passed still checked out');
    }, timeout: const Timeout(Duration(minutes: 5)));

    test('checking makes no request of any kind', () async {
      final w = await wallet1();
      await HttpOverrides.runZoned(() async {
        await IOOverrides.runZoned(() async {
          final (proven, why) = check(c.r2, c.w2);
          expect(why, isNull);
          final (note, _) = PoolEvidence.provenNote(
              round: (check(c.r1, c.w1)).$1!,
              opening: w.note.note,
              pkd: w.pkd,
              position: w.note.position,
              path: w.path.siblings);
          expect(note, isNotNull);
          expect(proven, isNotNull);
        },
            createFile: (p) => throw StateError('a check opened the file $p'),
            createDirectory: (p) => throw StateError('a check opened the directory $p'),
            socketConnect: (host, port, {sourceAddress, sourcePort = 0, timeout}) =>
                throw StateError('a check opened a socket to $host'));
      }, createHttpClient: (_) => throw StateError('a check made an HTTP request'));
    });

    test('two parties reach the same verdict from the same bytes, and a failure leaves nothing', () async {
      final w = await wallet1();
      final a = check(c.r2, c.w2), b = check(ShieldedLedger.parse(hex.decode(c.r2.serialize())), c.w2);
      expect(a.$1!.header.encode(), b.$1!.header.encode());
      expect(a.$1!.cmRoot, b.$1!.cmRoot);

      // and a failure is the same failure every time it is asked
      for (int i = 0; i < 3; i++) {
        final (note, why) = PoolEvidence.provenNote(
            round: a.$1!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
        expect(note, isNull, reason: 'round 2\'s root is not round 1\'s');
        expect(why!.step, 'path');
      }
    });

    test('a proven round and a proven note together cost under 20 ms', () async {
      final w = await wallet1();
      final (proven, _) = check(c.r1, c.w1);
      // warm
      for (int i = 0; i < 3; i++) {
        check(c.r1, c.w1);
        PoolEvidence.provenNote(
            round: proven!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
      }
      const runs = 20;
      final sw = Stopwatch()..start();
      for (int i = 0; i < runs; i++) {
        final (r, _) = check(c.r1, c.w1);
        final (n, _) = PoolEvidence.provenNote(
            round: r!, opening: w.note.note, pkd: w.pkd, position: w.note.position, path: w.path.siblings);
        expect(n, isNotNull);
      }
      final per = sw.elapsedMicroseconds / runs / 1000;
      print('  a proven round and a proven note: ${per.toStringAsFixed(2)} ms the pair');
      expect(per, lessThan(20));
    });
  });
}

List<int> _bytes(List<int> lanes) =>
    [for (final l in lanes) ...[l & 0xff, (l >> 8) & 0xff, (l >> 16) & 0xff, (l >> 24) & 0xff]];
