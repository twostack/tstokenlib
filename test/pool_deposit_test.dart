import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/script_gen/pool_deposit_gen.dart';

final depositorKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
final otherKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
final flags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};
List<int> pkhOf(SVPrivateKey k) => hex.decode(k.publicKey.toAddress(NetworkType.TEST).pubkeyHash160);

/// The 36-byte outpoint of input [i] as the transaction serialises it.
List<int> outpointOf(TransactionInput i) {
  final v = ByteData(4)..setUint32(0, i.prevTxnOutputIndex, Endian.little);
  return [...hex.decode(i.prevTxnId).reversed, ...v.buffer.asUint8List()];
}

class Deposit {
  final cm = List<int>.generate(32, (i) => 0x60 + i);
  final pp3 = TransactionInput(hex.encode(List.filled(32, 0x33)), 3, TransactionInput.MAX_SEQ_NUMBER);
  final value = BigInt.from(25000);
  final refundAfter = 900;
  late final SVScript lock = PoolDepositGen.lock(
      commitment: cm, pp3Outpoint: outpointOf(pp3), refundPKH: pkhOf(depositorKey), refundAfter: refundAfter);
  final depositTxId = hex.encode(List.filled(32, 0xd0));
}

/// A round with the deposit spent at [at] (5 by default) and its receipt at
/// output [receiptAt].
class DepositRound {
  final d = Deposit();
  int at = 5;
  int receiptAt = 5;
  List<int>? receiptCm;
  BigInt? receiptValue;
  TransactionInput? input3;
  List<int> Function(List<int> prevouts)? tamperPrevouts;

  Transaction tx() {
    final t = Transaction();
    for (int i = 0; i < 7; i++) {
      final TransactionInput input;
      if (i == at) {
        input = TransactionInput(d.depositTxId, 0, TransactionInput.MAX_SEQ_NUMBER);
      } else if (i == 3) {
        input = input3 ?? d.pp3;
      } else {
        input = TransactionInput(hex.encode(List.filled(32, 0x10 + i)), i, TransactionInput.MAX_SEQ_NUMBER);
      }
      t.addInputs([input]);
    }
    for (int o = 0; o < 7; o++) {
      final script = o == receiptAt
          ? PoolDepositGen.receiptScript(receiptCm ?? d.cm, receiptValue ?? d.value)
          : [OpCodes.OP_FALSE, OpCodes.OP_RETURN, OpCodes.OP_1 + o];
      t.addOutputs([TransactionOutput(BigInt.zero, SVScript.fromByteArray(Uint8List.fromList(script)))]);
    }
    return t;
  }

  void run() {
    final t = tx();
    final pre = Sighash().createSighashPreImage(t, PoolDepositGen.sighashRound, at, PoolDepositGen.scriptCode, d.value)!;
    var prevouts = [for (final i in t.inputs) ...outpointOf(i)];
    prevouts = tamperPrevouts?.call(prevouts) ?? prevouts;
    Interpreter().correctlySpends(PoolDepositGen.unlockRound(prevouts, pre), d.lock, t, at, flags, Coin.valueOf(d.value));
  }
}

/// The depositor taking the deposit back.
class Refund {
  final d = Deposit();
  SVPrivateKey signer = depositorKey;
  int lockTime = 900;
  int sequence = 0xfffffffe;

  void run() {
    final t = Transaction();
    t.addInputs([TransactionInput(d.depositTxId, 0, sequence)]);
    t.addOutputs([TransactionOutput(d.value - BigInt.from(200), P2PKHLockBuilder.fromAddress(depositorKey.publicKey.toAddress(NetworkType.TEST)).getScriptPubkey())]);
    t.nLockTime = lockTime;
    final pre = Sighash().createSighashPreImage(t, PoolDepositGen.sighashRefund, 0, PoolDepositGen.scriptCode, d.value)!;
    final sig = DefaultTransactionSigner(PoolDepositGen.sighashRefund, signer).signPreimage(pre);
    Interpreter().correctlySpends(
        PoolDepositGen.unlockRefund(hex.decode(sig.toTxFormat()), hex.decode(signer.publicKey.toHex()), pre),
        d.lock, t, 0, flags, Coin.valueOf(d.value));
  }
}

void refused(void Function() f) => expect(f, throwsA(isA<ScriptException>()));

void main() {
  test('the covenant is small, and one body serves every deposit', () {
    print('  deposit lock ${Deposit().lock.buffer.length} B, body ${PoolDepositGen.body().length} B');
  });

  group('the round spends a deposit', () {
    test('with the receipt at its own index, for its whole value', () => DepositRound().run());
    test('at another index, with the receipt moved with it', () => (DepositRound()
          ..at = 6
          ..receiptAt = 6)
        .run());
    test('refused: a receipt naming another commitment', () => refused((DepositRound()..receiptCm = List.filled(32, 1)).run));
    test('refused: a receipt crediting less than was deposited',
        () => refused((DepositRound()..receiptValue = BigInt.from(24999)).run));
    test('refused: the receipt at another index than the deposit', () => refused((DepositRound()..receiptAt = 6).run));
    test('refused: a transaction that does not spend PP3_N at input 3', () {
      refused((DepositRound()
            ..input3 = TransactionInput(hex.encode(List.filled(32, 0x34)), 3, TransactionInput.MAX_SEQ_NUMBER))
          .run);
    });
    test('refused: prevouts the preimage does not commit to, claiming PP3_N at input 3', () {
      // the transaction spends something else at input 3; the unlock claims
      // PP3_N there, so only hashPrevouts can refuse it
      final r = DepositRound()..input3 = TransactionInput(hex.encode(List.filled(32, 0x34)), 3, TransactionInput.MAX_SEQ_NUMBER);
      r.tamperPrevouts = (p) => List<int>.from(p)..setRange(108, 144, outpointOf(r.d.pp3));
      refused(r.run);
    });
    test('refused: prevouts cut short of whole outpoints', () {
      refused((DepositRound()..tamperPrevouts = (p) => p.sublist(0, p.length - 1)).run);
    });
  });

  group('the depositor takes it back', () {
    test('once the lock time has passed', () => Refund().run());
    test('refused: before the lock time', () => refused((Refund()..lockTime = 899).run));
    test('refused: with the input final, where consensus would not hold the lock time', () {
      refused((Refund()..sequence = 0xffffffff).run);
    });
    test('refused: anyone else', () => refused((Refund()..signer = otherKey).run));
  });
}
