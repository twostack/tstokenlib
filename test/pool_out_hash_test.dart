import 'dart:math';
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/src/shielded_pool/pool_out_hash.dart';
import 'package:tstokenlib/src/shielded_pool/pool_outputs.dart';

/// The TSL1 pool's outHash: PP1's per-transfer bundle hashing, and the
/// check V will make of each transfer's proof against its withdrawal and
/// ciphertexts.
void main() {
  final rng = Random(71);
  List<int> bytes(int n) => List.generate(n, (_) => rng.nextInt(256));

  /// PP1's loop on [blob]: the hash it leaves, or null when the script fails.
  List<int>? inScript(List<int> blob) {
    final lock = ScriptBuilder();
    PP1SpScriptGen.emitRoundOutHash(lock);
    final sig = ScriptBuilder()..addData(Uint8List.fromList(blob));
    // leave the hash for inspection: compare against each candidate outside
    final expected = (() {
      try {
        return PoolOutHash.roundOutHashOf(PoolOutHash.decodeBundles(blob));
      } catch (_) {
        return List<int>.filled(32, 0);
      }
    })();
    lock.addData(Uint8List.fromList(expected));
    lock.opCode(OpCodes.OP_EQUAL);
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0;
    final sigScript = sig.build();
    tx.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sigScript)));
    tx.outputs.add(TransactionOutput(BigInt.from(1), SVScript()));
    try {
      Interpreter().correctlySpends(sigScript, lock.build(), tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1)));
      return expected;
    } catch (_) {
      return null;
    }
  }

  /// Whether PP1's loop runs to the end on [blob], whatever it hashes to.
  bool parses(List<int> blob) {
    final lock = ScriptBuilder();
    PP1SpScriptGen.emitRoundOutHash(lock);
    lock.opCode(OpCodes.OP_DROP);
    lock.opCode(OpCodes.OP_1);
    final sigScript = (ScriptBuilder()..addData(Uint8List.fromList(blob))).build();
    final tx = Transaction()
      ..version = 1
      ..nLockTime = 0;
    tx.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(sigScript)));
    tx.outputs.add(TransactionOutput(BigInt.from(1), SVScript()));
    try {
      Interpreter().correctlySpends(sigScript, lock.build(), tx, 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1)));
      return true;
    } catch (_) {
      return false;
    }
  }

  group('PP1 hashes the bundles per transfer', () {
    test('matches the Dart definition for rounds of 1, 3 and 256 transfers, empty bundles included', () {
      for (final shape in [
        [bytes(40)],
        [bytes(1827), <int>[], bytes(300)],
        [for (int i = 0; i < PoolOutHash.maxTransfers; i++) bytes(i % 5)],
      ]) {
        expect(inScript(PoolOutHash.encodeBundles(shape)), PoolOutHash.roundOutHashOf(shape));
      }
    });

    test('is not the hash of the concatenation: each transfer is hashed apart', () {
      final a = [bytes(10), bytes(10)];
      expect(PoolOutHash.roundOutHashOf(a), isNot(PoolOutHash.roundOutHashOf([[...a[0], ...a[1]]])));
      expect(PoolOutHash.roundOutHashOf(a), isNot(PoolOutHash.roundOutHashOf([a[1], a[0]])));
    });

    test('refuses a push that does not parse', () {
      final ok = PoolOutHash.encodeBundles([bytes(20), bytes(7)]);
      expect(parses(ok), isTrue);
      expect(parses([...ok, 0x05]), isFalse, reason: 'a lone byte where a length should be');
      expect(parses([...ok, 0x09, 0x00, 1, 2]), isFalse, reason: 'a segment shorter than its length');
      expect(parses(ok.sublist(0, ok.length - 1)), isFalse, reason: 'cut short');
    });

    test('refuses more than the maximum number of transfers', () {
      final many = [for (int i = 0; i < PoolOutHash.maxTransfers + 1; i++) <int>[]];
      final blob = [for (final _ in many) ...[0, 0]];
      expect(parses(blob.sublist(2)), isTrue, reason: 'the maximum itself');
      expect(parses(blob), isFalse);
    });
  });

  group('V\'s check of the transfers against withdrawals and ciphertexts', () {
    int r31() => rng.nextInt(M31.p);
    List<int> lanes(int n) => List.generate(n, (_) => r31());
    final payee = PoolWithdrawal(bytes(20), BigInt.from(1234));
    final bundles = [bytes(50), bytes(60), <int>[], bytes(70)];
    final hashes = [for (final b in bundles) PoolOutHash.bundleHash(b)];
    final header = PoolOutHash.roundOutHash(hashes);
    List<int> transfer(int publicOut, List<int> outHash, {List<int>? asset}) => PoolPublicInputs(
            lanes(8), lanes(8), lanes(8), lanes(8), lanes(8), publicOut,
            outHash: outHash, real1: publicOut >= 0, real2: false, asset: asset ?? PoolHash.bsvAsset)
        .toLanes();
    // a transfer, a withdrawal of 1234, a padding transfer, a deposit
    List<List<int>> round({List<int>? withdrawOutHash, int withdrawn = 1234}) => [
          transfer(0, PoolOutHash.transferLanes(hashes[0])),
          transfer(withdrawn, withdrawOutHash ?? PoolOutHash.transferLanes(hashes[1], withdrawal: payee)),
          transfer(0, PoolOutHash.transferLanes(hashes[2])),
          transfer(-900, PoolOutHash.transferLanes(hashes[3])),
        ];

    test('an honest round passes', () {
      expect(PoolOutHash.check(transfers: round(), withdrawals: [payee], bundleHashes: hashes, headerOutHash: header), isNull);
    });

    test('a withdrawal redirected to another payee is refused', () {
      final thief = PoolWithdrawal(bytes(20), BigInt.from(1234));
      expect(PoolOutHash.check(transfers: round(), withdrawals: [thief], bundleHashes: hashes, headerOutHash: header), isNotNull);
    });

    test('a withdrawal paying other than the proof\'s amount is refused', () {
      final short = PoolWithdrawal(payee.pubkeyHash, BigInt.from(1000));
      expect(PoolOutHash.check(transfers: round(), withdrawals: [short], bundleHashes: hashes, headerOutHash: header), isNotNull);
    });

    test('a withdrawal left out, or one no transfer pays for, is refused', () {
      expect(PoolOutHash.check(transfers: round(), withdrawals: [], bundleHashes: hashes, headerOutHash: header), isNotNull);
      expect(PoolOutHash.check(transfers: round(), withdrawals: [payee, payee], bundleHashes: hashes, headerOutHash: header), isNotNull);
    });

    test('a recipient\'s ciphertexts swapped for others are refused', () {
      final swapped = [...hashes]..[0] = PoolOutHash.bundleHash(bytes(50));
      // consistent with a header built from the swapped list, still refused by the proof's outHash
      expect(
          PoolOutHash.check(
              transfers: round(), withdrawals: [payee], bundleHashes: swapped, headerOutHash: PoolOutHash.roundOutHash(swapped)),
          isNotNull);
      // and the true list against a header of other bundles is refused too
      expect(PoolOutHash.check(transfers: round(), withdrawals: [payee], bundleHashes: hashes, headerOutHash: bytes(32)), isNotNull);
    });

    test('an asset other than BSV moving in or out is refused for now', () {
      final t = round();
      t[1] = transfer(1234, PoolOutHash.transferLanes(hashes[1], withdrawal: payee), asset: [5, 0, 0, 0]);
      expect(PoolOutHash.check(transfers: t, withdrawals: [payee], bundleHashes: hashes, headerOutHash: header), isNotNull);
    });
  });
}
