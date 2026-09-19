import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_encryption.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

void main() {
  final rng = Random(7);
  List<int> lanes(int n) => List.generate(n, (_) => rng.nextInt(M31.p));
  final alice = PoolWalletKeys(lanes(5)), bob = PoolWalletKeys(lanes(5));
  late NoteAddress bob0, bob3;
  late AssetRecord record;

  setUpAll(() async {
    bob0 = await NoteAddress.at(bob.ivk, 0);
    bob3 = await NoteAddress.at(bob.ivk, 3);
    record = AssetRecord(issuerKeyHash: List.filled(20, 9), nonce: List.generate(32, (i) => i), flags: AssetRecord.flagGated);
  });

  test('keys and addresses derive deterministically from the viewing key', () async {
    expect(bob.ivk, PoolHash.ivk(bob.sk));
    expect(bob.ovk, isNot(bob.ivk));
    final again = await NoteAddress.at(bob.ivk, 0);
    expect(again.bytes, bob0.bytes);
    expect(bob0.pkd, PoolHash.pkd(bob.sk, bob0.d));
    expect(bob0.epk, isNot(bob3.epk));
    expect(NoteAddress.parse(bob3.bytes).bytes, bob3.bytes);
  });

  test('asset ids: BSV is the constant, others come from the record', () {
    final id = record.id;
    expect(id.length, PoolHash.assetLanes);
    expect(id, isNot(PoolHash.bsvAsset));
    for (final l in id) {
      expect(l, lessThan(1 << 31));
    }
    final other = AssetRecord(issuerKeyHash: record.issuerKeyHash, nonce: record.nonce, flags: 0);
    expect(other.id, isNot(id));
    expect(record.gated, isTrue);
    expect(other.gated, isFalse);
  });

  test('the asset is part of the commitment', () {
    final pkd = lanes(8), rho = lanes(3), rcm = lanes(4);
    final a = PoolHash.commit(pkd, 5, rho, rcm).$2;
    final b = PoolHash.commit(pkd, 5, rho, rcm, asset: record.id).$2;
    expect(a, isNot(b));
    expect(PoolHash.commit(pkd, 5, rho, rcm, asset: PoolHash.bsvAsset).$2, a);
  });

  test('the recipient opens the note with the viewing key, at the right address only', () async {
    final note = NotePlaintext(asset: PoolHash.bsvAsset, d: bob3.d, value: 123456789, rho: lanes(3), rcm: lanes(4), memo: NotePlaintext.memoOf('invoice 42'));
    final bundle = await NoteEncryption.encrypt(note, bob3, alice.ovk, rng: rng);
    expect(bundle.cm, note.cmUnder(bob3.pkd));
    expect(NoteBundle.parse(bundle.bytes).bytes, bundle.bytes);
    expect(await NoteEncryption.decryptIncoming(bundle, bob.ivk, bob0.d), isNull);
    final got = await NoteEncryption.decryptIncoming(bundle, bob.ivk, bob3.d);
    expect(got, isNotNull);
    expect(got!.bytes, note.bytes);
    expect(String.fromCharCodes(got.memo.takeWhile((c) => c != 0)), 'invoice 42');
    expect(got.toOutputNote(bob3.pkd).cm, bundle.cm);
    // a viewer enumerating the wallet's addresses finds it
    final found = await NoteEncryption.scanIncoming(bundle, bob.ivk, [for (int i = 0; i < 5; i++) PoolHash.diversifier(bob.ivk, i)]);
    expect(found?.$2, bob3.d);
    // the wrong wallet cannot
    expect(await NoteEncryption.decryptIncoming(bundle, alice.ivk, PoolHash.diversifier(alice.ivk, 3)), isNull);
  });

  test("the sender's auditor opens the outgoing copy; the issuer copy needs the issuer's key", () async {
    final issuerPair = await X25519().newKeyPairFromSeed(List.generate(32, (i) => 100 + i));
    final issuerEpk = Uint8List.fromList((await issuerPair.extractPublicKey()).bytes);
    final note = NotePlaintext(asset: record.id, d: bob0.d, value: 77, rho: lanes(3), rcm: lanes(4));
    final bundle = await NoteEncryption.encrypt(note, bob0, alice.ovk, issuerEpk: issuerEpk, rng: rng);
    expect(bundle.hasIssuerCopy, isTrue);
    expect(NoteBundle.parse(bundle.bytes).bytes, bundle.bytes);
    final out = await NoteEncryption.decryptOutgoing(bundle, alice.ovk);
    expect(out, isNotNull);
    expect(out!.$1.bytes, note.bytes);
    expect(out.$2, bob0.pkd);
    expect(await NoteEncryption.decryptOutgoing(bundle, bob.ovk), isNull);
    final iss = await NoteEncryption.decryptAsIssuer(bundle, issuerPair);
    expect(iss?.$1.value, 77);
    final otherPair = await X25519().newKeyPairFromSeed(List.generate(32, (i) => 200 + i));
    expect(await NoteEncryption.decryptAsIssuer(bundle, otherPair), isNull);
  });

  test('a tampered bundle, or one claiming another commitment, does not open', () async {
    final note = NotePlaintext(asset: PoolHash.bsvAsset, d: bob0.d, value: 5, rho: lanes(3), rcm: lanes(4));
    final bundle = await NoteEncryption.encrypt(note, bob0, alice.ovk, rng: rng);
    final ct = Uint8List.fromList(bundle.ciphertext)..[10] ^= 1;
    expect(await NoteEncryption.decryptIncoming(NoteBundle(bundle.cm, bundle.kem, bundle.ephemeral, ct, bundle.outgoing), bob.ivk, bob0.d), isNull);
    final otherCm = [...bundle.cm]..[0] ^= 1;
    expect(await NoteEncryption.decryptIncoming(NoteBundle(otherCm, bundle.kem, bundle.ephemeral, bundle.ciphertext, bundle.outgoing), bob.ivk, bob0.d), isNull);
    expect(await NoteEncryption.decryptOutgoing(NoteBundle(otherCm, bundle.kem, bundle.ephemeral, bundle.ciphertext, bundle.outgoing), alice.ovk), isNull);
  });

  test('a note-data output round-trips and other outputs are ignored', () async {
    final n1 = NotePlaintext(asset: PoolHash.bsvAsset, d: bob0.d, value: 1, rho: lanes(3), rcm: lanes(4));
    final n2 = NotePlaintext(asset: PoolHash.bsvAsset, d: bob3.d, value: 2, rho: lanes(3), rcm: lanes(4));
    final b1 = await NoteEncryption.encrypt(n1, bob0, alice.ovk, rng: rng);
    final b2 = await NoteEncryption.encrypt(n2, bob3, alice.ovk, rng: rng);
    final out = NoteBundle.output([b1, b2]);
    // value 0, then the varint length, then the script
    expect(out.sublist(0, 8), List.filled(8, 0));
    expect(out[8], 0xfd);
    final len = out[9] | (out[10] << 8);
    final script = out.sublist(11);
    expect(script.length, len);
    final back = NoteBundle.fromScript(script)!;
    expect(back.length, 2);
    expect(back[0].bytes, b1.bytes);
    expect(back[1].bytes, b2.bytes);
    expect(NoteBundle.fromScript([0x76, 0xa9]), isNull);
    print('  note bundle ${b1.bytes.length} B, note-data output for two notes ${out.length} B');
  });
}
