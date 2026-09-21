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

import 'package:crypto/crypto.dart' as crypto;

import '../script_gen/pool_spend_air.dart' show PoolPublicInputs, PoolHash;
import 'pool_outputs.dart';

/// What a transfer's outHash and the header's outHash commit to in the TSL1
/// pool, and the check V makes with them.
///
/// A spend proof carries eight lanes of outHash and no constraint reads
/// them: absorbing them into the transcript is what binds the proof to
/// them. In the legacy pool they were SHA-256 of the transfer's extra
/// outputs, payees and ciphertext output together. The TSL1 pool moved the
/// ciphertexts out of the round and into the witness, where bytes are paid
/// once instead of three times, so the two halves are now hashed apart:
///
///   c_t          = SHA256(bundle_t)          the transfer's note bundles
///   outHash_t    = SHA256(W_t ‖ c_t)          W_t its 28-byte withdrawal
///                                             record, or nothing
///   header.outHash = SHA256(c_0 ‖ … ‖ c_{n-1})
///
/// PP1 checks the header's from the bundles the witness publishes; V checks
/// each transfer's from the c_t list and the round's withdrawal outputs,
/// and the list against the header. So a coordinator can neither swap a
/// recipient's ciphertext nor redirect a withdrawal: both are under the
/// spender's proof, and V needs only 32 bytes per transfer, not the
/// bundles.
class PoolOutHash {
  /// Bundles PP1 will hash: the aggregation's transfers per round.
  static const maxTransfers = 256;

  /// A segment's length prefix, little-endian.
  static const lengthBytes = 2;
  static const maxBundle = (1 << (8 * lengthBytes)) - 1;

  /// The witness's bundles push: each transfer's bundle bytes behind a
  /// 2-byte length. A padding transfer's bundle is empty.
  static Uint8List encodeBundles(List<List<int>> perTransfer) {
    if (perTransfer.length > maxTransfers) throw ArgumentError('at most $maxTransfers transfers');
    final out = BytesBuilder();
    for (final b in perTransfer) {
      if (b.length > maxBundle) throw ArgumentError('a bundle is at most $maxBundle bytes');
      out.add([b.length & 0xff, b.length >> 8]);
      out.add(b);
    }
    return out.toBytes();
  }

  static List<List<int>> decodeBundles(List<int> blob) {
    final out = <List<int>>[];
    var at = 0;
    while (at < blob.length) {
      if (at + lengthBytes > blob.length) throw const FormatException('a bundle length is cut short');
      final n = blob[at] | (blob[at + 1] << 8);
      at += lengthBytes;
      if (at + n > blob.length) throw const FormatException('a bundle is cut short');
      out.add(blob.sublist(at, at + n));
      at += n;
    }
    return out;
  }

  static List<int> bundleHash(List<int> bundle) => crypto.sha256.convert(bundle).bytes;

  /// header.outHash for the transfers' bundle hashes, in transfer order.
  static List<int> roundOutHash(List<List<int>> bundleHashes) {
    if (bundleHashes.any((c) => c.length != 32)) throw ArgumentError('32-byte bundle hashes');
    return crypto.sha256.convert([for (final c in bundleHashes) ...c]).bytes;
  }

  /// header.outHash straight from the bundles.
  static List<int> roundOutHashOf(List<List<int>> perTransfer) => roundOutHash([for (final b in perTransfer) bundleHash(b)]);

  /// A transfer's outHash lanes, as its spend proof carries them.
  static List<int> transferLanes(List<int> bundleHash, {PoolWithdrawal? withdrawal}) {
    final h = Uint8List.fromList(crypto.sha256.convert([...?withdrawal?.encodeRecord(), ...bundleHash]).bytes);
    final bd = ByteData.view(h.buffer);
    return [for (int k = 0; k < 8; k++) bd.getUint32(4 * k, Endian.little) & 0x7fffffff];
  }

  /// V's check of a round's transfers against its withdrawals and bundle
  /// hashes, in Dart; null when it holds, else why not. [transfers] are
  /// the transfers' full statement lanes in order, [withdrawals] the
  /// round's withdrawal outputs in tail order. Every BSV transfer taking
  /// money out has exactly one withdrawal, the next in order, for exactly
  /// its amount; no other transfer has one; each transfer's outHash is its
  /// withdrawal record and bundle hash; the bundle hashes are the header's.
  static String? check(
      {required List<List<int>> transfers,
      required List<PoolWithdrawal> withdrawals,
      required List<List<int>> bundleHashes,
      required List<int> headerOutHash}) {
    if (bundleHashes.length != transfers.length) return 'one bundle hash per transfer';
    if (!_eq(roundOutHash(bundleHashes), headerOutHash)) return 'the bundle hashes are not the header\'s outHash';
    var next = 0;
    for (int t = 0; t < transfers.length; t++) {
      final p = PoolPublicInputs.fromLanes(transfers[t]);
      final bsv = _eq(p.asset, PoolHash.bsvAsset);
      if (!bsv && p.publicOut != 0) return 'transfer $t moves an asset other than BSV in or out, which this pool does not carry yet';
      PoolWithdrawal? w;
      if (p.publicOut > 0) {
        if (next >= withdrawals.length) return 'transfer $t takes ${p.publicOut} out and has no withdrawal';
        w = withdrawals[next++];
        if (w.satoshis != BigInt.from(p.publicOut)) return 'transfer $t takes ${p.publicOut} out, its withdrawal pays ${w.satoshis}';
      }
      if (!_eq(transferLanes(bundleHashes[t], withdrawal: w), p.outHash)) {
        return 'transfer $t\'s proof commits to another payee or other ciphertexts';
      }
    }
    if (next != withdrawals.length) return '${withdrawals.length - next} withdrawals no transfer pays for';
    return null;
  }

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
