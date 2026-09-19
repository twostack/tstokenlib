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
import 'stark_kernels.dart';

/// The key-encapsulation mechanisms note ciphertexts are keyed by.
///
///   * id 1, X25519 alone: a 32-byte public key, a 32-byte ephemeral value;
///   * id 2, the X25519 + ML-KEM-768 hybrid (the default): the public key
///     is the X25519 key followed by the ML-KEM encapsulation key
///     (32 + 1184 bytes), the ephemeral value the X25519 ephemeral key
///     followed by the ML-KEM ciphertext (32 + 1088 bytes), and the shared
///     secret SHA256 over a label, both raw secrets, the X25519 ephemeral
///     and the X25519 public key, so an attacker must break both schemes
///     and the secret is bound to the exchange.
///
/// ML-KEM runs in the native crate (`native/stark_kernels`); the hybrid
/// throws a [StateError] when the library is not built. X25519 is the
/// `cryptography` package, so every operation is asynchronous.
class NoteKem {
  static const x25519 = 1, hybrid = 2;
  static const defaultKem = hybrid;
  static const mlPublicKeyLength = StarkKernels.mlkem768PublicKeyLength;
  static const mlCiphertextLength = StarkKernels.mlkem768CiphertextLength;

  static bool isKem(int kem) => kem == x25519 || kem == hybrid;

  static int publicKeyLength(int kem) => switch (kem) {
        x25519 => 32,
        hybrid => 32 + mlPublicKeyLength,
        _ => throw ArgumentError('KEM $kem'),
      };

  static int ephemeralLength(int kem) => switch (kem) {
        x25519 => 32,
        hybrid => 32 + mlCiphertextLength,
        _ => throw ArgumentError('KEM $kem'),
      };

  static final _x = X25519();

  static StarkKernels get native =>
      StarkKernels.tryLoad() ?? (throw StateError('ML-KEM needs the native crate: cargo build --release --manifest-path native/stark_kernels/Cargo.toml'));

  static Uint8List _random32(Random rng) => Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));

  static Uint8List _combine(List<int> ssX, List<int> ssMl, List<int> ephX, List<int> pkX) =>
      Uint8List.fromList(crypto.sha256.convert([...'tsl1-pool-hybrid'.codeUnits, ...ssMl, ...ssX, ...ephX, ...pkX]).bytes);

  /// Encapsulates to [key]: (the ephemeral value, the shared secret).
  static Future<(Uint8List, Uint8List)> encaps(KemPublicKey key, Random rng) async {
    final pkX = key.bytes.sublist(0, 32);
    final pair = await _x.newKeyPairFromSeed(_random32(rng));
    final ephX = Uint8List.fromList((await pair.extractPublicKey()).bytes);
    final ssX = await (await _x.sharedSecretKey(keyPair: pair, remotePublicKey: SimplePublicKey(pkX, type: KeyPairType.x25519))).extractBytes();
    if (key.kem == x25519) return (ephX, Uint8List.fromList(ssX));
    final ml = native.mlkem768Encaps(key.bytes.sublist(32), _random32(rng)) ?? (throw ArgumentError('invalid ML-KEM encapsulation key'));
    return (Uint8List.fromList([...ephX, ...ml.$1]), _combine(ssX, ml.$2, ephX, pkX));
  }

  /// Decapsulates [ephemeral] with [pair]. Never fails: a malformed value
  /// yields a secret that opens nothing.
  static Future<Uint8List> decaps(KemKeyPair pair, Uint8List ephemeral) async {
    if (ephemeral.length != ephemeralLength(pair.kem)) throw ArgumentError('ephemeral length for KEM ${pair.kem}');
    final ephX = ephemeral.sublist(0, 32);
    final ssX = await (await _x.sharedSecretKey(keyPair: pair.x, remotePublicKey: SimplePublicKey(ephX, type: KeyPairType.x25519))).extractBytes();
    if (pair.kem == x25519) return Uint8List.fromList(ssX);
    final ssMl = native.mlkem768Decaps(pair.mlSeed!, ephemeral.sublist(32));
    return _combine(ssX, ssMl, ephX, (await pair.publicKey()).bytes.sublist(0, 32));
  }
}

/// A KEM public key: the id and the encoded key.
class KemPublicKey {
  final int kem;
  final Uint8List bytes;
  KemPublicKey(this.kem, this.bytes) {
    if (!NoteKem.isKem(kem) || bytes.length != NoteKem.publicKeyLength(kem)) throw ArgumentError('KEM $kem key of ${bytes.length} bytes');
  }
  Uint8List get encoded => Uint8List.fromList([kem, ...bytes]);
  static KemPublicKey parse(List<int> b) {
    if (b.isEmpty) throw FormatException('KEM key');
    return KemPublicKey(b[0], Uint8List.fromList(b.sublist(1)));
  }
}

/// A KEM key pair, generated from a 32-byte seed: the X25519 pair from the
/// seed itself (so a hybrid pair's X25519 half is the X25519-only pair of
/// the same seed), the ML-KEM pair from d ‖ z = SHA256 of the seed under
/// two labels. Only the seed is ever kept; ML-KEM keys are regenerated in
/// the native crate on each use.
class KemKeyPair {
  final int kem;
  final Uint8List seed;
  final SimpleKeyPair x;
  final Uint8List? mlSeed;
  KemKeyPair._(this.kem, this.seed, this.x, this.mlSeed);

  static Uint8List mlSeedOf(List<int> seed) => Uint8List.fromList([
        ...crypto.sha256.convert([...'tsl1-pool-mlkem-d'.codeUnits, ...seed]).bytes,
        ...crypto.sha256.convert([...'tsl1-pool-mlkem-z'.codeUnits, ...seed]).bytes,
      ]);

  static Future<KemKeyPair> fromSeed(List<int> seed, {int kem = NoteKem.defaultKem}) async {
    if (!NoteKem.isKem(kem)) throw ArgumentError('KEM $kem');
    if (seed.length != 32) throw ArgumentError('seed is 32 bytes');
    final x = await X25519().newKeyPairFromSeed(seed);
    return KemKeyPair._(kem, Uint8List.fromList(seed), x, kem == NoteKem.hybrid ? mlSeedOf(seed) : null);
  }

  Future<KemPublicKey> publicKey() async {
    final pkX = (await x.extractPublicKey()).bytes;
    if (kem == NoteKem.x25519) return KemPublicKey(kem, Uint8List.fromList(pkX));
    return KemPublicKey(kem, Uint8List.fromList([...pkX, ...NoteKem.native.mlkem768PublicKey(mlSeed!)]));
  }
}
