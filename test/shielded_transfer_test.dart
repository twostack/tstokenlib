import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';
import 'package:tstokenlib/src/shielded_pool/shielded_transfer.dart';

import 'pool_verifier_proof_test.dart' show spendP;

/// A wallet's spend of one 500 note into a 200 change note to itself, a 0
/// note to a stranger and a withdrawal of 300, and a deposit of 500, both
/// with real hybrid bundles and proved at test parameters.
class _Wallet {
  final PoolWalletKeys keys;
  final List<int> d;
  final NoteAddress address;
  _Wallet(this.keys, this.d, this.address);

  static Future<_Wallet> of(List<int> sk) async {
    final keys = PoolWalletKeys(sk);
    final d = PoolHash.diversifier(keys.ivk, 0);
    return _Wallet(keys, d, await NoteAddress.derive(keys.ivk, d));
  }
}

void main() {
  final rng = Random(11);
  List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));

  late _Wallet wallet, stranger;
  late SpendNote spent;
  late ShieldedTransfer real, deposit, padding;
  late List<int> b1, b2; // the real transfer's two note bundles
  final withdrawal = PoolWithdrawal(List.generate(20, (i) => i + 1), BigInt.from(300));

  NotePlaintext plain(List<int> d, int value) =>
      NotePlaintext(asset: PoolHash.bsvAsset, d: d, value: value, rho: lanes(3), rcm: lanes(4));

  ShieldedTransfer prove(PoolSpendWitness w, List<int> bundle, {PoolWithdrawal? withdrawal, List<int>? outpoint}) =>
      ShieldedTransfer(w.publics,
          StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: Random(1), hash: const Poseidon2ProofHash()), bundle,
          withdrawal: withdrawal, depositOutpoint: outpoint);

  setUpAll(() async {
    wallet = await _Wallet.of(lanes(5));
    stranger = await _Wallet.of(lanes(5));

    // the note being spent, the only leaf of a tree
    final n500 = plain(wallet.d, 500);
    final tree = NoteCommitmentTree()..append(n500.cmUnder(wallet.address.pkd));
    final path = tree.path(0);
    spent = SpendNote(
        sk: wallet.keys.sk, d: wallet.d, value: 500, rho: n500.rho, rcm: n500.rcm, siblings: path.siblings, position: path.position);

    final change = plain(wallet.d, 200), zero = plain(stranger.d, 0);
    b1 = (await NoteEncryption.encrypt(change, wallet.address, wallet.keys.ovk, rng: rng)).bytes;
    b2 = (await NoteEncryption.encrypt(zero, stranger.address, wallet.keys.ovk, rng: rng)).bytes;
    final bundle = [...b1, ...b2];
    real = prove(
        PoolSpendAir.witness(spent, SpendNote.dummy(sk: lanes(5), rho: lanes(3)), change.toOutputNote(wallet.address.pkd),
            zero.toOutputNote(stranger.address.pkd), 300,
            outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(bundle), withdrawal: withdrawal)),
        bundle,
        withdrawal: withdrawal);

    final d500 = plain(wallet.d, 500), d0 = plain(stranger.d, 0);
    final dBundle = [
      ...(await NoteEncryption.encrypt(d500, wallet.address, wallet.keys.ovk, rng: rng)).bytes,
      ...(await NoteEncryption.encrypt(d0, stranger.address, wallet.keys.ovk, rng: rng)).bytes,
    ];
    deposit = prove(
        PoolSpendAir.witness(SpendNote.dummy(sk: lanes(5), rho: lanes(3)), SpendNote.dummy(sk: lanes(5), rho: lanes(3)),
            d500.toOutputNote(wallet.address.pkd), d0.toOutputNote(stranger.address.pkd), -500,
            outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(dBundle)), anchor: List.filled(8, 0)),
        dBundle,
        outpoint: List.generate(36, (i) => 0xa0 + i));
    padding = ShieldedTransfer.padding(spendP, rng: Random(2));
  });

  /// [t] with its outHash recomputed for [bundle] and [withdrawal], so the
  /// outHash rule holds and whatever else is wrong is what gets reported.
  /// The proof is left as it is: none of these checks reads it.
  ShieldedTransfer consistent(ShieldedTransfer t, {List<int>? bundle, PoolWithdrawal? withdrawal, bool noWithdrawal = false, PoolPublicInputs? publics}) {
    final b = bundle ?? t.bundle;
    final w = noWithdrawal ? null : (withdrawal ?? t.withdrawal);
    final p = (publics ?? t.publics).copyWith(outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(b), withdrawal: w));
    return ShieldedTransfer(p, t.proof, b, withdrawal: w, depositOutpoint: t.depositOutpoint);
  }

  group('contents', () {
    test('a real transfer holds its proof, publics, two note bundles and its withdrawal, and no deposit', () {
      expect(real.proof, isNotNull);
      expect(real.publics.toLanes().length, PoolPublicInputs.count);
      expect(real.notes.length, 2);
      expect(real.notes[0].cm, real.publics.cmOut1);
      expect(real.notes[1].cm, real.publics.cmOut2);
      expect(real.withdrawal!.satoshis, BigInt.from(300));
      expect(real.depositOutpoint, isNull);
      expect(real.refusal(), isNull);
      expect(real.verifyProof(spendP), isNull);
    });

    test('a padding transfer carries no bundle and pays the padding note twice', () {
      expect(padding.bundle, isEmpty);
      expect(padding.isPadding, isTrue);
      expect(padding.commitments, [ShieldedTransfer.paddingCm, ShieldedTransfer.paddingCm]);
      expect(padding.refusal(), isNull);
      expect(padding.verifyProof(spendP), isNull);
    });
  });

  group('self-consistency, each refusal naming its rule without the proof', () {
    test('a consistent transfer with someone else\'s proof passes: the checks never read the proof', () {
      final t = ShieldedTransfer(real.publics, padding.proof, real.bundle, withdrawal: real.withdrawal);
      expect(t.refusal(), isNull);
      expect(t.verifyProof(spendP), isNotNull, reason: 'only verification catches it, which is the pool\'s job');
    });

    test('outHash: a bundle other than the one the proof committed to', () {
      final t = ShieldedTransfer(real.publics, real.proof, deposit.bundle, withdrawal: real.withdrawal);
      expect(t.refusal()!.field, 'outHash');
    });

    test('outHash: a withdrawal to another payee', () {
      final t = ShieldedTransfer(real.publics, real.proof, real.bundle, withdrawal: PoolWithdrawal(List.filled(20, 9), BigInt.from(300)));
      expect(t.refusal()!.field, 'outHash');
    });

    test('withdrawal: a transfer taking 300 out with a withdrawal of 301', () {
      final r = consistent(real, withdrawal: PoolWithdrawal(withdrawal.pubkeyHash, BigInt.from(301))).refusal()!;
      expect(r.field, 'withdrawal');
      expect(r.reason, contains('301'));
    });

    test('withdrawal: a transfer taking 300 out with none', () {
      expect(consistent(real, noWithdrawal: true).refusal()!.field, 'withdrawal');
    });

    test('withdrawal: a transfer taking nothing out with one', () {
      expect(consistent(padding, withdrawal: withdrawal).refusal()!.field, 'withdrawal');
    });

    test('publics: an asset other than BSV moving in', () {
      final other = consistent(deposit, publics: deposit.publics.copyWith(asset: [7, 0, 0, 0]));
      final r = ShieldedTransfer(other.publics, other.proof, other.bundle).refusal()!;
      expect(r.field, 'publics');
    });

    test('bundle: the two note bundles in the wrong order name other commitments', () {
      final r = consistent(real, bundle: [...b2, ...b1]).refusal()!;
      expect(r.field, 'bundle');
      expect(r.reason, contains('does not match the proof'));
    });

    test('bundle: a note bundle whose commitment was replaced', () {
      final forged = Uint8List.fromList(b1);
      forged[1] ^= 1; // the first byte of cm
      expect(consistent(real, bundle: [...forged, ...b2]).refusal()!.reason, contains('does not match the proof'));
    });

    test('bundle: bytes that are not two note bundles', () {
      expect(consistent(real, bundle: b1).refusal()!.field, 'bundle');
      expect(consistent(real, bundle: [...b1, ...b2, 0]).refusal()!.field, 'bundle');
      expect(consistent(real, bundle: List.filled(100, 7)).refusal()!.field, 'bundle');
    });

    test('bundle: an empty bundle on a real transfer', () {
      final r = consistent(real, bundle: const []).refusal()!;
      expect(r.field, 'bundle');
      expect(r.reason, contains('not padding'));
    });

    test('bundle: an empty bundle on a padding transfer that does not pay the padding note', () {
      final p = PoolPublicInputs(List.filled(8, 0), lanes(8), lanes(8), lanes(8), lanes(8), 0, real1: false, real2: false);
      final r = consistent(padding, publics: p).refusal()!;
      expect(r.field, 'bundle');
      expect(r.reason, contains('padding note'));
    });
  });

  group('deposit shape', () {
    test('a well-formed deposit of 500 implies the receipt of its first commitment and 500', () {
      expect(deposit.refusal(), isNull);
      final r = deposit.receipt!;
      expect(r.satoshis, BigInt.from(500));
      expect(bytesToLanes(r.commitment), deposit.publics.cmOut1);
      expect(real.receipt, isNull);
    });

    test('a transfer naming a deposit outpoint but spending a real note is refused', () {
      final t = ShieldedTransfer(real.publics, real.proof, real.bundle, withdrawal: real.withdrawal, depositOutpoint: List.filled(36, 1));
      final r = t.refusal()!;
      expect(r.field, 'deposit');
      expect(r.reason, contains('real note'));
    });

    test('a deposit outpoint on a transfer bringing nothing in is refused', () {
      final t = ShieldedTransfer(padding.publics, padding.proof, padding.bundle, depositOutpoint: List.filled(36, 1));
      expect(t.refusal()!.field, 'deposit');
    });

    test('a deposit outpoint of the wrong length is refused', () {
      final t = ShieldedTransfer(deposit.publics, deposit.proof, deposit.bundle, depositOutpoint: List.filled(35, 1));
      expect(t.refusal()!.field, 'deposit');
    });
  });

  group('wire format', () {
    void same(ShieldedTransfer a, ShieldedTransfer b) {
      expect(b.publics.toLanes(), a.publics.toLanes());
      expect(b.bundle, a.bundle);
      expect(b.withdrawal?.encodeRecord(), a.withdrawal?.encodeRecord());
      expect(b.depositOutpoint, a.depositOutpoint);
      expect(ShieldedTransfer.codec(spendP).encode(b.proof), ShieldedTransfer.codec(spendP).encode(a.proof));
      expect(b.encode(spendP), a.encode(spendP));
    }

    test('round trip of a withdrawal, a deposit and a padding transfer, the proofs still verifying', () {
      for (final t in [real, deposit, padding]) {
        final back = ShieldedTransfer.decode(t.encode(spendP), spendP);
        same(t, back);
        expect(back.refusal(), isNull);
        expect(back.verifyProof(spendP), isNull);
      }
    });

    test('an unknown version, a truncated encoding and a trailing byte are refused', () {
      final e = real.encode(spendP);
      expect(() => ShieldedTransfer.decode([2, ...e.sublist(1)], spendP),
          throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'version').having((r) => r.reason, 'reason', contains('unknown version 2'))));
      expect(() => ShieldedTransfer.decode(e.sublist(0, e.length - 1), spendP), throwsA(isA<TransferRefusal>()));
      expect(() => ShieldedTransfer.decode([...e, 0], spendP), throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'end')));
    });

    test('unknown flags are refused', () {
      final e = real.encode(spendP)..[1] |= 4;
      expect(() => ShieldedTransfer.decode(e, spendP), throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'flags')));
    });
  });

  group('untrusted input', () {
    int at(String field) => {'proofLength': 2 + 4 * PoolPublicInputs.count}[field]!;

    test('a 7 MB byte string is refused as too large without being parsed', () {
      final big = Uint8List(7 * 1024 * 1024)..[0] = ShieldedTransfer.formatVersion;
      expect(() => ShieldedTransfer.decode(big, spendP), throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'size')));
    });

    test('an encoding declaring a 4 GB bundle is refused on that field', () {
      final e = real.encode(spendP);
      final bundleAt = at('proofLength') + 4 + ShieldedTransfer.codec(spendP).bytes;
      e.setAll(bundleAt, [0xff, 0xff, 0xff, 0xff]);
      expect(() => ShieldedTransfer.decode(e, spendP),
          throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'bundle').having((r) => r.reason, 'reason', contains('at most'))));
    });

    test('a proof length other than the one the parameters fix is refused before any proof byte is read', () {
      final e = real.encode(spendP);
      e.setAll(at('proofLength'), [0xff, 0xff, 0xff, 0xff]);
      expect(() => ShieldedTransfer.decode(e, spendP), throwsA(isA<TransferRefusal>().having((r) => r.field, 'field', 'proof')));
    });

    test('10,000 random byte strings and 10,000 single-byte mutations each end in a transfer or a named refusal', () {
      final r = Random(99);
      final valid = real.encode(spendP);
      var decoded = 0, refused = 0;
      final fields = <String, int>{};
      void run(List<int> bytes) {
        try {
          ShieldedTransfer.decode(bytes, spendP);
          decoded++;
        } on TransferRefusal catch (e) {
          refused++;
          fields[e.field] = (fields[e.field] ?? 0) + 1;
        }
      }

      for (int i = 0; i < 10000; i++) {
        final n = r.nextInt(2 * valid.length);
        final s = List.generate(n, (_) => r.nextInt(256));
        // half of them past the version and flags, so the later fields are reached
        if (i.isOdd && n >= 2) s.setAll(0, [ShieldedTransfer.formatVersion, r.nextInt(4)]);
        run(s);
      }
      for (int i = 0; i < 10000; i++) {
        final m = Uint8List.fromList(valid);
        final k = r.nextInt(m.length);
        m[k] = (m[k] + 1 + r.nextInt(255)) & 0xff;
        run(m);
      }
      print('  $decoded decoded, $refused refused: $fields');
      expect(decoded + refused, 20000);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });

  test('the encoding holds no key material', () {
    final e = real.encode(spendP);
    bool contains(List<int> needle) {
      outer:
      for (int i = 0; i + needle.length <= e.length; i++) {
        for (int j = 0; j < needle.length; j++) {
          if (e[i + j] != needle[j]) continue outer;
        }
        return true;
      }
      return false;
    }

    final secrets = {
      'spending key': wallet.keys.sk,
      'ivk': wallet.keys.ivk,
      'ovk': wallet.keys.ovk,
      'nk': wallet.keys.nk,
      'spent rho': spent.rho,
      'spent rcm': spent.rcm,
      'diversifier': wallet.d,
    };
    for (final s in secrets.entries) {
      expect(contains(lanesToBytes(s.value)), isFalse, reason: 'the ${s.key} is in the encoding');
    }
    // the check can find what it looks for
    expect(contains(lanesToBytes(real.publics.nf1)), isTrue);
  });
}
