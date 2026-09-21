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

import 'package:dartsv/dartsv.dart';

/// The two kinds of output a round may carry after the five TSL1 outputs.
///
/// PP1 used to emit a fixed output count of 5, which made withdrawals
/// impossible rather than merely ungated. The fixed count was not a
/// convenience: it is what made it impossible for a round to carry a second
/// PP1 with the same tokenId and fork the chain through the sanctioned path.
/// So the tail that replaces it is shape checked rather than counted. PP1
/// rebuilds every extra output from a fixed template with only a few bytes
/// free, and refuses anything else. These two classes are that template, on
/// the Dart side: [encodeRecord] is what the witness pushes and [lockingScript]
/// is what the round must carry, and the script rebuilds the second from the
/// first.
///
/// Nothing in the tail can be spent as a token, so the induction is exactly as
/// strong as it was with five outputs.

/// A payout from the pool: an ordinary P2PKH output of the round.
///
/// The witness record is 28 bytes, the 20-byte hash followed by the value as
/// 8-byte little endian, in that order because PP1 splits the hash off the
/// front and the value is what the rebuilt output starts with.
class PoolWithdrawal {
  /// Bytes of one withdrawal in the witness blob.
  static const int recordSize = 28;

  /// How many withdrawals a round may carry. Beyond this the script's unrolled
  /// tail runs out of steps and the leftover blob fails the emptiness check.
  static const int maxPerRound = 256;

  final List<int> pubkeyHash;
  final BigInt satoshis;

  PoolWithdrawal(this.pubkeyHash, this.satoshis) {
    if (pubkeyHash.length != 20) {
      throw ArgumentError('A withdrawal needs a 20-byte pubkey hash');
    }
  }

  PoolWithdrawal.toAddress(Address address, BigInt satoshis)
      : this(_hexBytes(address.pubkeyHash160), satoshis);

  /// `pubkeyHash ‖ value`, the 28 bytes PP1 reads.
  Uint8List encodeRecord() {
    var out = Uint8List(recordSize);
    out.setAll(0, pubkeyHash);
    out.buffer.asByteData().setUint64(20, satoshis.toInt(), Endian.little);
    return out;
  }

  /// The 25-byte P2PKH script PP1 rebuilds from the record.
  SVScript get lockingScript => SVScript.fromByteArray(Uint8List.fromList(
      [0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]));

  static Uint8List encodeAll(List<PoolWithdrawal> withdrawals) {
    var out = Uint8List(withdrawals.length * recordSize);
    for (var i = 0; i < withdrawals.length; i++) {
      out.setAll(i * recordSize, withdrawals[i].encodeRecord());
    }
    return out;
  }
}

/// A deposit receipt: a zero-value `OP_FALSE OP_RETURN` naming the note
/// commitment the deposit created and the amount it added to the pool.
///
/// A depositor's covenant spends at some input of the round and requires, with
/// SIGHASH_SINGLE, that the output at its own index be exactly this. So the
/// receipts sit at the front of the tail, at indices that depend only on how
/// many receipts there are: a depositor building a covenant cannot know how
/// many withdrawals the round will carry, so withdrawals must not come first.
class PoolReceipt {
  /// Bytes of one receipt in the witness blob.
  static const int recordSize = 40;

  /// How many deposits a round may take in.
  static const int maxPerRound = 8;

  final List<int> commitment;
  final BigInt satoshis;

  PoolReceipt(this.commitment, this.satoshis) {
    if (commitment.length != 32) {
      throw ArgumentError('A receipt needs a 32-byte commitment');
    }
  }

  /// `commitment ‖ value`, the 40 bytes PP1 reads.
  Uint8List encodeRecord() {
    var out = Uint8List(recordSize);
    out.setAll(0, commitment);
    out.buffer.asByteData().setUint64(32, satoshis.toInt(), Endian.little);
    return out;
  }

  /// `OP_FALSE OP_RETURN <commitment> <value>`, 44 bytes.
  ///
  /// The value is pushed as 8 bytes rather than as a script number so that the
  /// shape is fixed whatever the amount is. PP1 checks the shape, not the
  /// number.
  SVScript get lockingScript {
    var value = Uint8List(8);
    value.buffer.asByteData().setUint64(0, satoshis.toInt(), Endian.little);
    return SVScript.fromByteArray(Uint8List.fromList(
        [0x00, 0x6a, 0x20, ...commitment, 0x08, ...value]));
  }

  static Uint8List encodeAll(List<PoolReceipt> receipts) {
    var out = Uint8List(receipts.length * recordSize);
    for (var i = 0; i < receipts.length; i++) {
      out.setAll(i * recordSize, receipts[i].encodeRecord());
    }
    return out;
  }
}

List<int> _hexBytes(String value) {
  var out = <int>[];
  for (var i = 0; i < value.length; i += 2) {
    out.add(int.parse(value.substring(i, i + 2), radix: 16));
  }
  return out;
}
