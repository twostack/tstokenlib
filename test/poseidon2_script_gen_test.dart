import 'dart:math';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/poseidon2_m31.dart';
import 'package:tstokenlib/src/script_gen/m31_script_gen.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';
import 'package:tstokenlib/src/script_gen/poseidon2_script_gen.dart';

Transaction _tx(SVScript sig) {
  var t = Transaction();
  t.version = 1;
  t.nLockTime = 0;
  t.inputs.add(TransactionInput('aa' * 32, 0, TransactionInput.MAX_SEQ_NUMBER,
      scriptBuilder: DefaultUnlockBuilder.fromScript(sig)));
  t.outputs.add(TransactionOutput(BigInt.from(1000), SVScript()));
  return t;
}

void _run(SVScript sig, SVScript lock) => Interpreter()
    .correctlySpends(sig, lock, _tx(sig), 0, {VerifyFlag.UTXO_AFTER_GENESIS}, Coin.valueOf(BigInt.from(1000)));

SVScript _unlock(List<int> vals) {
  final b = ScriptBuilder();
  for (final v in vals) {
    if (v <= 16) {
      b.smallNum(v);
    } else {
      b.number(v);
    }
  }
  return b.build();
}

(int, int) _cost(SVScript s) {
  int ops = 0;
  for (final c in s.chunks) {
    if (c.opcodenum > OpCodes.OP_16) ops++;
  }
  return (s.buffer.length, ops);
}

void main() {
  final rng = Random(31);
  List<int> lanes(int k) => List.generate(k, (_) => rng.nextInt(M31.p));
  final names = List.generate(16, (k) => 's$k');

  test('the permutation matches Poseidon2M31.permute, and its cost', () {
    final input = lanes(16);
    final expected = Poseidon2M31.permute(input);
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: names);
    Poseidon2ScriptGen.emitPushP(e);
    final before = b.build().buffer.length;
    Poseidon2ScriptGen.emitPermute(e, names);
    final permBytes = b.build().buffer.length - before;
    for (int k = 15; k >= 0; k--) {
      e.roll('s$k');
      e.numEqualVerifyConst(expected[k]);
    }
    e.dropAll();
    e.pushConst(1);
    final lock = b.build();
    _run(_unlock(input), lock);
    final (bytes, ops) = _cost(lock);
    print('  permutation: $permBytes B of script; whole check $bytes B, $ops ops');
    expect(permBytes, lessThan(12000));
    // a wrong input fails
    final bad = [...input]..[3] ^= 1;
    expect(() => _run(_unlock(bad), lock), throwsA(isA<ScriptException>()));
  });

  test('a Merkle node matches PoolHash.node, edge lanes included', () {
    final l = lanes(8), r = lanes(8);
    l[0] = 0;
    r[7] = M31.p - 1;
    final expected = PoolHash.node(l, r);
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: names);
    Poseidon2ScriptGen.emitPushP(e);
    final out = List.generate(8, (k) => 'o$k');
    Poseidon2ScriptGen.emitNode(e, names.sublist(0, 8), names.sublist(8), out);
    for (int k = 7; k >= 0; k--) {
      e.roll('o$k');
      e.numEqualVerifyConst(expected[k]);
    }
    e.dropAll();
    e.pushConst(1);
    _run(_unlock([...l, ...r]), b.build());
  });

  test('a chain of nodes: the empty-subtree roots', () {
    // emptyRoots[l+1] = node(emptyRoots[l], emptyRoots[l]) for l = 0..3, from the zero leaf
    final b = ScriptBuilder();
    final e = StackEmitter(b, initial: names);
    Poseidon2ScriptGen.emitPushP(e);
    var cur = names.sublist(0, 8);
    e.dropNamed('s8');
    for (final n in names.sublist(9)) {
      e.dropNamed(n);
    }
    for (int l = 0; l < 4; l++) {
      final copy = List.generate(8, (k) => 'c${l}_$k');
      for (int k = 0; k < 8; k++) {
        e.pick(cur[k], as: copy[k]);
      }
      final out = List.generate(8, (k) => 'r${l}_$k');
      Poseidon2ScriptGen.emitNode(e, cur, copy, out);
      cur = out;
    }
    final expected = PoolHash.root(List.filled(8, 0), List.generate(4, (l) => List.filled(8, 0)), 0);
    // the level-4 empty root equals walking the zero leaf up 4 levels with zero siblings? No:
    // siblings are the empty roots of each level, so compare with the frontier's table instead.
    final table = <List<int>>[List.filled(8, 0)];
    for (int l = 0; l < 4; l++) {
      table.add(PoolHash.node(table[l], table[l]));
    }
    expect(table[1], isNot(equals(expected)));
    for (int k = 7; k >= 0; k--) {
      e.roll(cur[k]);
      e.numEqualVerifyConst(table[4][k]);
    }
    e.dropAll();
    e.pushConst(1);
    _run(_unlock(List.filled(16, 0)), b.build());
  });
}
