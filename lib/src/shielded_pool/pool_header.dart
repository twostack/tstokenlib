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

/// The mutable state a shielded pool carries in its PP1_SP output.
///
/// The six fields are encoded as one contiguous 236-byte blob rather than six
/// separate pushes, for two reasons. PP1's rebuild replaces the whole of it in
/// a single fixed-window substitution, instead of interleaving six push
/// prefixes; and the verifier slot script V embeds the same blob as one push,
/// so PP1 can bind V to `header_{N+1}` by rebuilding V as `push(header) + body`
/// and comparing one hash. Fields that script needs individually are read by
/// splitting the blob at the offsets below.
///
/// ```
/// [0:32]    cmRoot    commitment tree root after this round
/// [32:64]   nfRoot    sorted nullifier tree root after this round
/// [64:192]  ring      4 x 32, recent cmRoots a spend proof may anchor to
/// [192:196] size      leaves in the commitment tree, LE32
/// [196:204] balance   satoshis held by PP3, LE64
/// [204:236] outHash   hash of this round's ciphertext bundles
/// ```
///
/// `ring` is ordered newest first. The rotation on a round boundary is a
/// circuit constraint checked by the verifier, not a script one: PP1 carries
/// the field and never interprets it.
class PoolHeader {
  static const int cmRootOffset = 0;
  static const int nfRootOffset = 32;
  static const int ringOffset = 64;
  static const int ringEntries = 4;
  static const int sizeOffset = 192;
  static const int balanceOffset = 196;
  static const int outHashOffset = 204;

  /// Total encoded size. Over 75 bytes, so the push carries an OP_PUSHDATA1
  /// prefix of two bytes rather than one; see `PP1SpScriptGen.headerDataStart`.
  static const int byteSize = 236;

  final List<int> cmRoot;
  final List<int> nfRoot;
  final List<List<int>> ring;
  final int size;
  final BigInt balance;
  final List<int> outHash;

  PoolHeader({
    required this.cmRoot,
    required this.nfRoot,
    required this.ring,
    required this.size,
    required this.balance,
    required this.outHash,
  }) {
    _require(cmRoot.length == 32, 'cmRoot must be 32 bytes');
    _require(nfRoot.length == 32, 'nfRoot must be 32 bytes');
    _require(ring.length == ringEntries, 'ring must hold $ringEntries roots');
    for (var i = 0; i < ring.length; i++) {
      _require(ring[i].length == 32, 'ring[$i] must be 32 bytes');
    }
    _require(size >= 0 && size <= 0xFFFFFFFF, 'size must fit in 4 bytes');
    _require(!balance.isNegative && balance.bitLength <= 64,
        'balance must fit in 8 unsigned bytes');
    _require(outHash.length == 32, 'outHash must be 32 bytes');
  }

  /// The header a pool is issued with: an empty tree whose roots the caller
  /// supplies, no leaves, no bundles, and nothing in it but the dust its PP3
  /// output needs in order to exist.
  ///
  /// The balance is one satoshi rather than zero because `balance` is not a
  /// bookkeeping figure, it is the value PP3 actually holds, and PP1 checks the
  /// two are equal on every round. Opening at zero would either make the
  /// invariant false from the start or leave an unspendable output.
  ///
  /// The empty-tree roots are Poseidon2 values that depend on the pool's tree
  /// depth, so they come from the pool's configuration rather than from here.
  /// The ring is filled with [emptyCmRoot] so that a spend proof in round 1 has
  /// a legitimate anchor.
  factory PoolHeader.genesis({
    required List<int> emptyCmRoot,
    required List<int> emptyNfRoot,
  }) {
    return PoolHeader(
      cmRoot: emptyCmRoot,
      nfRoot: emptyNfRoot,
      ring: List.generate(ringEntries, (_) => List<int>.from(emptyCmRoot)),
      size: 0,
      balance: BigInt.one,
      outHash: List.filled(32, 0),
    );
  }

  Uint8List encode() {
    var out = Uint8List(byteSize);
    out.setRange(cmRootOffset, cmRootOffset + 32, cmRoot);
    out.setRange(nfRootOffset, nfRootOffset + 32, nfRoot);
    for (var i = 0; i < ringEntries; i++) {
      out.setRange(ringOffset + i * 32, ringOffset + (i + 1) * 32, ring[i]);
    }
    for (var i = 0; i < 4; i++) {
      out[sizeOffset + i] = (size >> (8 * i)) & 0xFF;
    }
    for (var i = 0; i < 8; i++) {
      out[balanceOffset + i] = ((balance >> (8 * i)) & BigInt.from(0xFF)).toInt();
    }
    out.setRange(outHashOffset, outHashOffset + 32, outHash);
    return out;
  }

  factory PoolHeader.decode(List<int> buf) {
    _require(buf.length == byteSize, 'header must be $byteSize bytes');
    var balance = BigInt.zero;
    for (var i = 7; i >= 0; i--) {
      balance = (balance << 8) | BigInt.from(buf[balanceOffset + i]);
    }
    return PoolHeader(
      cmRoot: buf.sublist(cmRootOffset, cmRootOffset + 32),
      nfRoot: buf.sublist(nfRootOffset, nfRootOffset + 32),
      ring: List.generate(ringEntries,
          (i) => buf.sublist(ringOffset + i * 32, ringOffset + (i + 1) * 32)),
      size: buf[sizeOffset] |
          (buf[sizeOffset + 1] << 8) |
          (buf[sizeOffset + 2] << 16) |
          (buf[sizeOffset + 3] << 24),
      balance: balance,
      outHash: buf.sublist(outHashOffset, outHashOffset + 32),
    );
  }

  /// The header for the next round, with the ring rotated so the new cmRoot is
  /// the newest anchor and the oldest is dropped.
  PoolHeader advance({
    required List<int> cmRoot,
    required List<int> nfRoot,
    required int size,
    required BigInt balance,
    required List<int> outHash,
  }) {
    return PoolHeader(
      cmRoot: cmRoot,
      nfRoot: nfRoot,
      ring: [List<int>.from(cmRoot), ...ring.sublist(0, ringEntries - 1)],
      size: size,
      balance: balance,
      outHash: outHash,
    );
  }

  static void _require(bool ok, String message) {
    if (!ok) throw ArgumentError(message);
  }
}
