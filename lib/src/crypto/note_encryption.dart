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

import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart' show OpCodes;
import '../script_gen/pool_spend_air.dart';
import '../script_gen/slot_script_common.dart';
import 'note_kem.dart';

/// The wallet's keys. The spending key derives the two keys the circuit
/// uses (ivk behind addresses, nk behind nullifiers) and the outgoing
/// viewing key that keys the sender's copy of each note. Any of ivk, nk and
/// ovk can be handed to a viewer; none of them can spend.
class PoolWalletKeys {
  final List<int> sk;
  PoolWalletKeys(this.sk) {
    if (sk.length != PoolHash.skLanes) throw ArgumentError('sk lanes');
  }
  late final List<int> ivk = PoolHash.ivk(sk);
  late final List<int> nk = PoolHash.nk(sk);
  late final List<int> ovk = PoolHash.ovk(sk);
}

/// Lanes as little-endian 4-byte words.
Uint8List lanesToBytes(List<int> lanes) {
  final b = ByteData(4 * lanes.length);
  for (int i = 0; i < lanes.length; i++) {
    b.setUint32(4 * i, lanes[i], Endian.little);
  }
  return b.buffer.asUint8List();
}

List<int> bytesToLanes(List<int> bytes) {
  final b = ByteData.view(Uint8List.fromList(bytes).buffer);
  return [for (int i = 0; i < bytes.length ~/ 4; i++) b.getUint32(4 * i, Endian.little)];
}

/// A diversified address: the diversifier, pk_d = H(ivk, d), and the
/// public key of the note-encryption KEM (see [NoteKem]) whose key pair is
/// derived from (ivk, d), so the viewing key alone opens notes sent to
/// every address of the wallet. Addresses default to the X25519 + ML-KEM
/// hybrid; an X25519-only address of the same (ivk, d) shares its X25519
/// key.
class NoteAddress {
  static const kemX25519 = NoteKem.x25519, kemHybrid = NoteKem.hybrid;
  final List<int> d;
  final List<int> pkd;
  final int kem;
  final Uint8List epk;
  NoteAddress(this.d, this.pkd, this.kem, this.epk) {
    if (d.length != PoolHash.dLanes || pkd.length != PoolHash.digestLanes) throw ArgumentError('address lanes');
    if (!NoteKem.isKem(kem) || epk.length != NoteKem.publicKeyLength(kem)) throw ArgumentError('KEM $kem key of ${epk.length} bytes');
  }
  KemPublicKey get kemKey => KemPublicKey(kem, epk);

  /// The KEM seed of address [d] of the wallet behind [ivk].
  static Uint8List kemSeed(List<int> ivk, List<int> d) =>
      Uint8List.fromList(crypto.sha256.convert([...'tsl1-pool-kem'.codeUnits, ...lanesToBytes(ivk), ...lanesToBytes(d)]).bytes);

  static Future<KemKeyPair> kemKeyPair(List<int> ivk, List<int> d, {int kem = NoteKem.defaultKem}) =>
      KemKeyPair.fromSeed(kemSeed(ivk, d), kem: kem);

  static Future<NoteAddress> derive(List<int> ivk, List<int> d, {int kem = NoteKem.defaultKem}) async {
    final pub = await (await kemKeyPair(ivk, d, kem: kem)).publicKey();
    return NoteAddress(d, PoolHash.pkdFromIvk(ivk, d), kem, pub.bytes);
  }

  /// Address [index] of the wallet (see [PoolHash.diversifier]).
  static Future<NoteAddress> at(List<int> ivk, int index, {int kem = NoteKem.defaultKem}) =>
      derive(ivk, PoolHash.diversifier(ivk, index), kem: kem);

  Uint8List get bytes => Uint8List.fromList([kem, ...lanesToBytes(d), ...lanesToBytes(pkd), ...epk]);
  static NoteAddress parse(List<int> b) {
    if (b.isEmpty || !NoteKem.isKem(b[0]) || b.length != 45 + NoteKem.publicKeyLength(b[0])) throw FormatException('address length');
    return NoteAddress(bytesToLanes(b.sublist(1, 13)), bytesToLanes(b.sublist(13, 45)), b[0], Uint8List.fromList(b.sublist(45)));
  }
}

/// What the recipient learns: everything needed to spend the note, plus
/// the memo. [asset] is the note's asset id, [d] the recipient's
/// diversifier (so the wallet knows which of its addresses was paid).
class NotePlaintext {
  static const version = 1;
  static const memoLength = 512;
  static const length = 1 + 16 + 12 + 7 + 12 + 16 + memoLength;
  final List<int> asset, d, rho, rcm;
  final int value;
  final Uint8List memo;
  NotePlaintext({
    required this.asset,
    required this.d,
    required this.value,
    required this.rho,
    required this.rcm,
    Uint8List? memo,
  }) : memo = memo ?? Uint8List(memoLength) {
    if (asset.length != PoolHash.assetLanes || d.length != PoolHash.dLanes) throw ArgumentError('lanes');
    if (rho.length != PoolHash.rhoLanes || rcm.length != PoolHash.rcmLanes) throw ArgumentError('lanes');
    if (this.memo.length != memoLength) throw ArgumentError('memo is $memoLength bytes');
    if (value < 0 || value >= PoolHash.maxValue) throw ArgumentError('value');
  }

  /// A memo from text, zero padded.
  static Uint8List memoOf(String text) {
    final u = text.codeUnits;
    if (u.length > memoLength) throw ArgumentError('memo too long');
    return Uint8List.fromList([...u, ...List.filled(memoLength - u.length, 0)]);
  }

  Uint8List get bytes {
    final v = ByteData(8)..setUint64(0, value, Endian.little);
    return Uint8List.fromList([
      version,
      ...lanesToBytes(asset),
      ...lanesToBytes(d),
      ...v.buffer.asUint8List(0, 7),
      ...lanesToBytes(rho),
      ...lanesToBytes(rcm),
      ...memo,
    ]);
  }

  static NotePlaintext parse(List<int> b) {
    if (b.length != length || b[0] != version) throw FormatException('note plaintext');
    var o = 1;
    List<int> lanes(int n) {
      final l = bytesToLanes(b.sublist(o, o + 4 * n));
      o += 4 * n;
      return l;
    }
    final asset = lanes(4), d = lanes(3);
    var value = 0;
    for (int i = 6; i >= 0; i--) {
      value = (value << 8) | b[o + i];
    }
    o += 7;
    final rho = lanes(3), rcm = lanes(4);
    return NotePlaintext(asset: asset, d: d, value: value, rho: rho, rcm: rcm, memo: Uint8List.fromList(b.sublist(o)));
  }

  /// The commitment this note has under [pkd].
  List<int> cmUnder(List<int> pkd) => PoolHash.commit(pkd, value, rho, rcm, asset: asset).$2;
  OutputNote toOutputNote(List<int> pkd) => OutputNote(pkd: pkd, value: value, rho: rho, rcm: rcm, asset: asset);
}

/// The ciphertexts one output note carries in the round transaction:
///   * the recipient ciphertext: KEM to the address's key, note key
///     K = HKDF(secret, cm), AEAD over the plaintext with cm as the
///     associated data;
///   * the outgoing copy: (secret ‖ pk_d) under HKDF(ovk, cm), so the
///     sender's auditor recovers the note key;
///   * for a gated asset, the issuer copy: (secret ‖ pk_d) under a key
///     encapsulated to the issuer's KEM key.
/// [cm] rides along so a reader matches bundles to commitments directly.
/// Each KEM value is preceded by its KEM id (see [NoteKem]), which fixes
/// its length; a zero issuer id means no issuer copy.
class NoteBundle {
  static const version = 1;
  static const secretLength = 32, macLength = 16;
  static const outLength = secretLength + 32 + macLength; // secret ‖ pk_d, sealed
  static const ctLength = NotePlaintext.length + macLength;
  final List<int> cm;
  final int kem;
  final Uint8List ephemeral; // the sender's KEM value
  final Uint8List ciphertext;
  final Uint8List outgoing;
  final int? issuerKem;
  final Uint8List? issuerEphemeral, issuerCopy;
  NoteBundle(this.cm, this.kem, this.ephemeral, this.ciphertext, this.outgoing, {this.issuerKem, this.issuerEphemeral, this.issuerCopy}) {
    if (cm.length != 8 || !NoteKem.isKem(kem) || ephemeral.length != NoteKem.ephemeralLength(kem)) throw ArgumentError('bundle');
    if (ciphertext.length != ctLength || outgoing.length != outLength) throw ArgumentError('bundle lengths');
    if ((issuerKem == null) != (issuerCopy == null) || (issuerEphemeral == null) != (issuerCopy == null)) throw ArgumentError('issuer copy');
    if (issuerCopy != null) {
      if (!NoteKem.isKem(issuerKem!) || issuerEphemeral!.length != NoteKem.ephemeralLength(issuerKem!)) throw ArgumentError('issuer KEM');
      if (issuerCopy!.length != outLength) throw ArgumentError('issuer copy');
    }
  }
  bool get hasIssuerCopy => issuerCopy != null;

  Uint8List get bytes => Uint8List.fromList([
        version,
        ...lanesToBytes(cm),
        kem,
        ...ephemeral,
        ...ciphertext,
        ...outgoing,
        issuerKem ?? 0,
        if (hasIssuerCopy) ...issuerEphemeral!,
        if (hasIssuerCopy) ...issuerCopy!,
      ]);

  /// The size in bytes of a bundle under [kem] with, when [issuerKem] is
  /// given, an issuer copy under it.
  static int sizeOf(int kem, {int? issuerKem}) =>
      1 + 32 + 1 + NoteKem.ephemeralLength(kem) + ctLength + outLength + 1 + (issuerKem == null ? 0 : NoteKem.ephemeralLength(issuerKem) + outLength);

  static int lengthOf(List<int> b, int at) {
    if (b.length < at + 34 || b[at] != version || !NoteKem.isKem(b[at + 33])) throw FormatException('note bundle');
    final kem = b[at + 33];
    final flag = at + sizeOf(kem) - 1;
    if (b.length <= flag) throw FormatException('note bundle');
    final issuerKem = b[flag];
    if (issuerKem != 0 && !NoteKem.isKem(issuerKem)) throw FormatException('note bundle issuer KEM');
    return sizeOf(kem, issuerKem: issuerKem == 0 ? null : issuerKem);
  }

  static NoteBundle parse(List<int> b, [int at = 0]) {
    final n = lengthOf(b, at);
    if (b.length < at + n) throw FormatException('note bundle');
    var o = at + 1;
    final cm = bytesToLanes(b.sublist(o, o + 32));
    o += 32;
    final kem = b[o++];
    final el = NoteKem.ephemeralLength(kem);
    final eph = Uint8List.fromList(b.sublist(o, o + el));
    o += el;
    final ct = Uint8List.fromList(b.sublist(o, o + ctLength));
    o += ctLength;
    final out = Uint8List.fromList(b.sublist(o, o + outLength));
    o += outLength;
    final ik = b[o++];
    Uint8List? ie, ic;
    if (ik != 0) {
      final il = NoteKem.ephemeralLength(ik);
      ie = Uint8List.fromList(b.sublist(o, o + il));
      o += il;
      ic = Uint8List.fromList(b.sublist(o, o + outLength));
      o += outLength;
    }
    if (o != at + n) throw FormatException('note bundle');
    return NoteBundle(cm, kem, eph, ct, out, issuerKem: ik == 0 ? null : ik, issuerEphemeral: ie, issuerCopy: ic);
  }

  // ---- the note-data output of a transfer ----
  static const magic = [0x54, 0x53, 0x4c, 0x4e]; // 'TSLN'

  /// `OP_RETURN 'TSLN' <bundles>` as an output, the first extra output of
  /// a transfer (so its outHash covers the ciphertexts).
  static Uint8List output(List<NoteBundle> bundles) {
    final payload = [...magic, for (final b in bundles) ...b.bytes];
    final push = payload.length < 0x100
        ? [OpCodes.OP_PUSHDATA1, payload.length]
        : [OpCodes.OP_PUSHDATA2, payload.length & 0xff, payload.length >> 8];
    return SlotScript.output([OpCodes.OP_RETURN, ...push, ...payload]);
  }

  /// The bundles of a note-data output script, or null for any other script.
  static List<NoteBundle>? fromScript(List<int> script) {
    if (script.isEmpty || script[0] != OpCodes.OP_RETURN || script.length < 2) return null;
    int o;
    if (script[1] == OpCodes.OP_PUSHDATA1) {
      o = 3;
    } else if (script[1] == OpCodes.OP_PUSHDATA2) {
      o = 4;
    } else {
      return null;
    }
    if (script.length < o + 4) return null;
    for (int i = 0; i < 4; i++) {
      if (script[o + i] != magic[i]) return null;
    }
    o += 4;
    final out = <NoteBundle>[];
    while (o < script.length) {
      out.add(parse(script, o));
      o += lengthOf(script, o);
    }
    return out;
  }
}

/// Encrypts and decrypts [NoteBundle]s.
class NoteEncryption {
  static final _aead = Chacha20.poly1305Aead();
  static final _nonce = List<int>.filled(12, 0); // keys are unique per (secret, cm)

  static Future<SecretKey> _noteKey(List<int> secret, List<int> cm, String info) =>
      Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(secretKey: SecretKey(secret), nonce: lanesToBytes(cm), info: info.codeUnits);

  static Future<Uint8List> _seal(SecretKey k, List<int> clear, List<int> aad) async {
    final box = await _aead.encrypt(clear, secretKey: k, nonce: _nonce, aad: aad);
    return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
  }

  static Future<List<int>?> _open(SecretKey k, List<int> sealed, List<int> aad) async {
    try {
      final n = sealed.length - NoteBundle.macLength;
      return await _aead.decrypt(SecretBox(sealed.sublist(0, n), nonce: _nonce, mac: Mac(sealed.sublist(n))), secretKey: k, aad: aad);
    } on SecretBoxAuthenticationError {
      return null;
    }
  }

  /// The bundle for [note] sent to [to], with the sender's copy under
  /// [ovk] and, when [issuer] (the issuer's KEM key) is given, the
  /// issuer's copy.
  static Future<NoteBundle> encrypt(NotePlaintext note, NoteAddress to, List<int> ovk, {KemPublicKey? issuer, Random? rng}) async {
    rng ??= Random.secure();
    final cm = note.cmUnder(to.pkd);
    final cmBytes = lanesToBytes(cm);
    final (eph, secret) = await NoteKem.encaps(to.kemKey, rng);
    final ct = await _seal(await _noteKey(secret, cm, 'note'), note.bytes, cmBytes);
    final copy = [...secret, ...lanesToBytes(to.pkd)];
    final out = await _seal(await _noteKey(ovk, cm, 'out'), copy, cmBytes);
    Uint8List? ie, ic;
    if (issuer != null) {
      final (ieph, isecret) = await NoteKem.encaps(issuer, rng);
      ie = ieph;
      ic = await _seal(await _noteKey(isecret, cm, 'issuer'), copy, cmBytes);
    }
    return NoteBundle(cm, to.kem, eph, ct, out, issuerKem: issuer?.kem, issuerEphemeral: ie, issuerCopy: ic);
  }

  static Future<NotePlaintext?> _openNote(NoteBundle b, List<int> secret, List<int> pkd) async {
    final clear = await _open(await _noteKey(secret, b.cm, 'note'), b.ciphertext, lanesToBytes(b.cm));
    if (clear == null) return null;
    final note = NotePlaintext.parse(clear);
    final cm = note.cmUnder(pkd);
    for (int i = 0; i < 8; i++) {
      if (cm[i] != b.cm[i]) return null;
    }
    return note;
  }

  /// As the recipient: the note if [b] was sent to address [d] of the
  /// wallet behind [ivk] (and its plaintext commits to [b.cm]), else null.
  /// The bundle's KEM picks which of the address's key pairs is used.
  static Future<NotePlaintext?> decryptIncoming(NoteBundle b, List<int> ivk, List<int> d) async {
    final pair = await NoteAddress.kemKeyPair(ivk, d, kem: b.kem);
    final secret = await NoteKem.decaps(pair, b.ephemeral);
    return _openNote(b, secret, PoolHash.pkdFromIvk(ivk, d));
  }

  /// As the recipient with several addresses: the first that opens [b].
  static Future<(NotePlaintext, List<int>)?> scanIncoming(NoteBundle b, List<int> ivk, Iterable<List<int>> diversifiers) async {
    for (final d in diversifiers) {
      final n = await decryptIncoming(b, ivk, d);
      if (n != null) return (n, d);
    }
    return null;
  }

  static Future<(NotePlaintext, List<int>)?> _fromCopy(NoteBundle b, List<int>? copy) async {
    if (copy == null) return null;
    final secret = copy.sublist(0, NoteBundle.secretLength), pkd = bytesToLanes(copy.sublist(NoteBundle.secretLength));
    final note = await _openNote(b, secret, pkd);
    return note == null ? null : (note, pkd);
  }

  /// As the sender's auditor: the note and the recipient's pk_d if [ovk]
  /// opens the outgoing copy.
  static Future<(NotePlaintext, List<int>)?> decryptOutgoing(NoteBundle b, List<int> ovk) async =>
      _fromCopy(b, await _open(await _noteKey(ovk, b.cm, 'out'), b.outgoing, lanesToBytes(b.cm)));

  /// As the asset's issuer, holding the KEM key pair the sender
  /// encrypted the issuer copy to.
  static Future<(NotePlaintext, List<int>)?> decryptAsIssuer(NoteBundle b, KemKeyPair issuerPair) async {
    if (!b.hasIssuerCopy || b.issuerKem != issuerPair.kem) return null;
    final secret = await NoteKem.decaps(issuerPair, b.issuerEphemeral!);
    return _fromCopy(b, await _open(await _noteKey(secret, b.cm, 'issuer'), b.issuerCopy!, lanesToBytes(b.cm)));
  }
}
