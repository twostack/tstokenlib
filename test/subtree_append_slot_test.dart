import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/script_gen/subtree_append_slot_gen.dart';

final verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

/// A round transaction skeleton: input 0 the state (a dummy here), input 1
/// the slot; outputs 0 a dummy state, 1 the slot's result.
Transaction roundTx(String parentTxid, Uint8List resultOutput, {List<TransactionInput> extraInputs = const []}) {
  final t = Transaction();
  t.version = 1;
  t.nLockTime = 0;
  t.inputs.add(TransactionInput(parentTxid, 0, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript())));
  t.inputs.add(TransactionInput(parentTxid, 1, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript())));
  t.inputs.addAll(extraInputs);
  t.outputs.add(TransactionOutput(BigInt.from(5000), SVScript.fromHex('76a914${'11' * 20}88ac')));
  // resultOutput = value(8) ‖ varint(1) ‖ script
  t.outputs.add(TransactionOutput(BigInt.zero, SVScript.fromByteArray(resultOutput.sublist(9))));
  return t;
}

/// Every outpoint after input 0, serialised as in hashPrevouts.
List<int> prevoutsTail(Transaction t) => [
      for (final i in t.inputs.skip(1)) ...[
        ...hex.decode(i.prevTxnId).reversed,
        ...(ByteData(4)..setUint32(0, i.prevTxnOutputIndex, Endian.little)).buffer.asUint8List(),
      ]
    ];

void main() {
  final rng = Random(44);
  List<int> lanes(int k) => List.generate(k, (_) => rng.nextInt(M31.p));
  final gen = SubtreeAppendSlotGen();
  late SVScript lock;
  setUpAll(() => lock = gen.lock());

  (int, int) cost(SVScript s) {
    int ops = 0;
    for (final c in s.chunks) {
      if (c.opcodenum > OpCodes.OP_16) ops++;
    }
    return (s.buffer.length, ops);
  }

  test('a partial round appends a subtree: the slot signs the result the state expects', () {
    final tree = NoteCommitmentTree();
    tree.appendSubtree([for (int i = 0; i < NoteCommitmentTree.subtreeLeaves; i++) lanes(8)]);
    tree.appendSubtree([lanes(8), lanes(8), lanes(8)]);
    final rootBefore = tree.root;
    final j = tree.nextSubtree;
    expect(j, 2);
    final siblings = tree.subtreePath(j);
    final cms = [for (int i = 0; i < 5; i++) lanes(8)]; // 5 of 16 slots used
    tree.appendSubtree(cms);
    final rootAfter = tree.root;
    expect(NoteCommitmentTree.mainRoot(NoteCommitmentTree.subtreeRoot(cms), siblings, j), rootAfter);
    expect(NoteCommitmentTree.mainRoot(MerkleFrontier.emptyRoots[NoteCommitmentTree.subtreeDepth], siblings, j), rootBefore);

    final payload = SubtreeAppendSlotGen.payload(rootBefore, rootAfter, j, cms);
    final out = SubtreeAppendSlotGen.resultOutput(payload);
    final tx = roundTx('ab' * 32, out);
    final pre = Sighash().createSighashPreImage(tx, SubtreeAppendSlotGen.sighashType, 1, lock, BigInt.one)!;
    expect(pre.length, lessThan(200), reason: 'scriptCode is only what follows the code separator');
    final unlock = gen.unlock(pre, prevoutsTail(tx), j, rootBefore, siblings, cms);
    final sw = Stopwatch()..start();
    Interpreter().correctlySpends(unlock, lock, tx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    final (bytes, ops) = cost(lock);
    print('  append slot: lock $bytes B, $ops ops; unlock ${unlock.buffer.length} B; interpreter ${sw.elapsedMilliseconds} ms');
    expect(ops, lessThan(1000000));

    // rejections
    void rejects(String why, SVScript u, Transaction t) =>
        expect(() => Interpreter().correctlySpends(u, lock, t, 1, verifyFlags, Coin.valueOf(BigInt.one)),
            throwsA(isA<ScriptException>()), reason: why);
    // a result claiming a different root after
    final badOut = SubtreeAppendSlotGen.resultOutput(SubtreeAppendSlotGen.payload(rootBefore, lanes(8), j, cms));
    final badTx = roundTx('ab' * 32, badOut);
    rejects('wrong rootAfter', gen.unlock(Sighash().createSighashPreImage(badTx, 0x43, 1, lock, BigInt.one)!, prevoutsTail(badTx), j, rootBefore, siblings, cms), badTx);
    // a commitment swapped for another under the same claimed result
    final cms2 = [...cms]..[2] = lanes(8);
    rejects('other commitments', gen.unlock(pre, prevoutsTail(tx), j, rootBefore, siblings, cms2), tx);
    // siblings of another slot: the empty walk misses rootBefore
    rejects('wrong index', gen.unlock(pre, prevoutsTail(tx), j + 1, rootBefore, siblings, cms), tx);
    // a transaction that does not spend the state as input 0
    final loose = roundTx('cd' * 32, out);
    loose.inputs[1] = TransactionInput('ab' * 32, 1, TransactionInput.MAX_SEQ_NUMBER, scriptBuilder: DefaultUnlockBuilder.fromScript(SVScript()));
    final preL = Sighash().createSighashPreImage(loose, 0x43, 1, lock, BigInt.one)!;
    rejects('state not co-spent', gen.unlock(preL, prevoutsTail(loose), j, rootBefore, siblings, cms), loose);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('a full subtree on an empty tree', () {
    final tree = NoteCommitmentTree();
    final rootBefore = tree.root;
    final siblings = tree.subtreePath(0);
    final cms = [for (int i = 0; i < NoteCommitmentTree.subtreeLeaves; i++) lanes(8)];
    tree.appendSubtree(cms);
    final out = SubtreeAppendSlotGen.resultOutput(SubtreeAppendSlotGen.payload(rootBefore, tree.root, 0, cms));
    final tx = roundTx('ef' * 32, out);
    final pre = Sighash().createSighashPreImage(tx, 0x43, 1, lock, BigInt.one)!;
    Interpreter().correctlySpends(gen.unlock(pre, prevoutsTail(tx), 0, rootBefore, siblings, cms), lock, tx, 1, verifyFlags, Coin.valueOf(BigInt.one));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
