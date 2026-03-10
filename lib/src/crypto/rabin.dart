import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// A Rabin signature keypair.
class RabinKeyPair {
  final BigInt n; // public key (n = p * q)
  final BigInt p; // private: first prime, p ≡ 3 (mod 4)
  final BigInt q; // private: second prime, q ≡ 3 (mod 4)

  RabinKeyPair(this.n, this.p, this.q);
}

/// A Rabin signature: (s, padding) where s² mod n == message + padding.
class RabinSignature {
  final BigInt s;
  final int padding;

  RabinSignature(this.s, this.padding);
}

/// Rabin signature scheme utilities for Bitcoin Script verification.
///
/// Rabin signatures are ideal for in-script verification because the
/// verification formula `s² mod n == hash` compiles to just 3 opcodes
/// (OP_DUP OP_MUL, OP_MOD), making it far more compact than ECDSA or
/// Ed25519 verification in script.
class Rabin {
  static final _secureRandom = Random.secure();

  /// Generate a Rabin keypair with the given bit length.
  ///
  /// Both primes p and q satisfy p ≡ 3 (mod 4), which enables efficient
  /// square root computation via s = m^((p+1)/4) mod p.
  static RabinKeyPair generateKeyPair(int bitLength) {
    final halfBits = bitLength ~/ 2;
    final p = _generateBlumPrime(halfBits);
    final q = _generateBlumPrime(halfBits);
    final n = p * q;
    return RabinKeyPair(n, p, q);
  }

  /// Sign a message hash (as BigInt) using the Rabin private key.
  ///
  /// If the hash is not a quadratic residue mod n, increments by 1
  /// until a residue is found. Returns (s, padding) where
  /// s² mod n == hash + padding.
  static RabinSignature sign(BigInt messageHash, BigInt p, BigInt q) {
    final n = p * q;

    for (int padding = 0; padding < 256; padding++) {
      final m = messageHash + BigInt.from(padding);

      // Check if m is a quadratic residue mod p and mod q
      // Using Euler's criterion: m^((p-1)/2) mod p == 1
      if (_isQuadraticResidue(m, p) && _isQuadraticResidue(m, q)) {
        // Compute square roots mod p and mod q
        // Since p ≡ 3 (mod 4): sqrt(m) mod p = m^((p+1)/4) mod p
        final sp = m.modPow((p + BigInt.one) >> 2, p);
        final sq = m.modPow((q + BigInt.one) >> 2, q);

        // Combine using Chinese Remainder Theorem
        final s = _crt(sp, sq, p, q, n);

        // Verify
        assert((s * s) % n == m % n);

        return RabinSignature(s, padding);
      }
    }

    throw StateError('Could not find quadratic residue within 256 padding values');
  }

  /// Verify a Rabin signature: s² mod n == messageHash + padding.
  static bool verify(BigInt messageHash, RabinSignature sig, BigInt n) {
    final expected = (messageHash + BigInt.from(sig.padding)) % n;
    final actual = (sig.s * sig.s) % n;
    return actual == expected;
  }

  /// Convert a SHA256 hash (32 bytes, big-endian) to a BigInt.
  ///
  /// Interprets the bytes in standard big-endian order (MSB first).
  static BigInt hashToInt(List<int> hashBytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < hashBytes.length; i++) {
      result = (result << 8) | BigInt.from(hashBytes[i]);
    }
    return result;
  }

  /// Compute SHA256 of arbitrary bytes and return as BigInt (big-endian).
  static BigInt sha256ToInt(List<int> data) {
    final hash = sha256.convert(data);
    return hashToInt(hash.bytes);
  }

  /// Compute SHA256 and return as BigInt matching Bitcoin Script interpretation.
  ///
  /// In script, OP_SHA256 produces 32 raw bytes which, when converted to a
  /// script number via `0x00 OP_CAT OP_BIN2NUM`, are interpreted as
  /// little-endian unsigned. This method produces the same BigInt value
  /// that the script will compute.
  static BigInt sha256ToScriptInt(List<int> data) {
    final hash = sha256.convert(data);
    return hashBytesToScriptInt(hash.bytes);
  }

  /// Convert raw hash bytes to the BigInt that Bitcoin Script would produce.
  ///
  /// The script appends 0x00 (positive sign byte) and interprets as LE
  /// sign-magnitude. This is equivalent to reading the bytes as unsigned LE.
  static BigInt hashBytesToScriptInt(List<int> hashBytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < hashBytes.length; i++) {
      result |= BigInt.from(hashBytes[i]) << (8 * i);
    }
    return result;
  }

  /// Encode a BigInt as sign-magnitude little-endian bytes (Bitcoin Script number format).
  static Uint8List bigIntToScriptNum(BigInt value) {
    if (value == BigInt.zero) return Uint8List(0);

    final isNegative = value < BigInt.zero;
    var abs = isNegative ? -value : value;

    // Convert to little-endian unsigned bytes
    var bytes = <int>[];
    while (abs > BigInt.zero) {
      bytes.add((abs & BigInt.from(0xff)).toInt());
      abs >>= 8;
    }

    // If the MSB has the sign bit set, add a sign byte
    if (bytes.last & 0x80 != 0) {
      bytes.add(isNegative ? 0x80 : 0x00);
    } else if (isNegative) {
      bytes[bytes.length - 1] |= 0x80;
    }

    return Uint8List.fromList(bytes);
  }

  // --- Private helpers ---

  /// Generate a prime p where p ≡ 3 (mod 4) (a "Blum prime").
  static BigInt _generateBlumPrime(int bitLength) {
    while (true) {
      var candidate = _generateRandomOdd(bitLength);

      // Ensure candidate ≡ 3 (mod 4)
      if (candidate % BigInt.from(4) != BigInt.from(3)) {
        candidate += BigInt.from(4) - (candidate % BigInt.from(4)) + BigInt.from(3);
        // Re-check it's odd (it will be since 3 mod 4 is odd)
      }

      if (_isProbablePrime(candidate, 20)) {
        return candidate;
      }
    }
  }

  /// Generate a random odd number of approximately [bitLength] bits.
  static BigInt _generateRandomOdd(int bitLength) {
    final byteLen = (bitLength + 7) ~/ 8;
    final bytes = List<int>.generate(byteLen, (_) => _secureRandom.nextInt(256));

    // Set the MSB to ensure the number has the right bit length
    bytes[0] |= 0x80;
    // Set the LSB to ensure it's odd
    bytes[byteLen - 1] |= 0x01;

    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  /// Miller-Rabin primality test.
  static bool _isProbablePrime(BigInt n, int rounds) {
    if (n < BigInt.two) return false;
    if (n == BigInt.two || n == BigInt.from(3)) return true;
    if (n.isEven) return false;

    // Write n-1 as 2^r * d
    var d = n - BigInt.one;
    int r = 0;
    while (d.isEven) {
      d >>= 1;
      r++;
    }

    // Witness loop
    for (int i = 0; i < rounds; i++) {
      final a = _randomInRange(BigInt.two, n - BigInt.two);
      var x = a.modPow(d, n);

      if (x == BigInt.one || x == n - BigInt.one) continue;

      bool found = false;
      for (int j = 0; j < r - 1; j++) {
        x = x.modPow(BigInt.two, n);
        if (x == n - BigInt.one) {
          found = true;
          break;
        }
      }
      if (!found) return false;
    }
    return true;
  }

  /// Generate a random BigInt in range [min, max].
  static BigInt _randomInRange(BigInt min, BigInt max) {
    final range = max - min + BigInt.one;
    final bytesNeeded = (range.bitLength + 7) ~/ 8;
    while (true) {
      final bytes = List<int>.generate(bytesNeeded, (_) => _secureRandom.nextInt(256));
      BigInt value = BigInt.zero;
      for (final b in bytes) {
        value = (value << 8) | BigInt.from(b);
      }
      value = value % range;
      if (value + min <= max) return value + min;
    }
  }

  /// Check if m is a quadratic residue mod p using Euler's criterion.
  static bool _isQuadraticResidue(BigInt m, BigInt p) {
    final mMod = m % p;
    if (mMod == BigInt.zero) return true;
    return mMod.modPow((p - BigInt.one) >> 1, p) == BigInt.one;
  }

  /// Chinese Remainder Theorem to combine square roots.
  static BigInt _crt(BigInt sp, BigInt sq, BigInt p, BigInt q, BigInt n) {
    // Extended GCD to find coefficients
    final gcdResult = _extendedGcd(p, q);
    final yp = gcdResult.$2;
    final yq = gcdResult.$3;

    // s = (sp * yq * q + sq * yp * p) mod n
    var s = (sp * yq * q + sq * yp * p) % n;
    if (s < BigInt.zero) s += n;
    return s;
  }

  /// Extended Euclidean algorithm. Returns (gcd, x, y) where a*x + b*y = gcd.
  static (BigInt, BigInt, BigInt) _extendedGcd(BigInt a, BigInt b) {
    if (a == BigInt.zero) return (b, BigInt.zero, BigInt.one);
    final result = _extendedGcd(b % a, a);
    final g = result.$1;
    final x1 = result.$2;
    final y1 = result.$3;
    return (g, y1 - (b ~/ a) * x1, x1);
  }
}
