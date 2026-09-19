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

import 'air_ring.dart';
import 'deep_quotient_script_gen.dart' show limbNames;
import 'm31_script_gen.dart';

/// Compiles a straight-line [Program] (QM31 arithmetic recorded by
/// [ExprRing]) to script: every node is four canonical limbs on the stack,
/// each operand is rolled (consumed) at its last use and picked otherwise,
/// so the live set stays small. This is how an AIR whose constraints are
/// written once against a [Ring] gets its script emitter for free.
class ProgramScriptGen {
  /// Emit [prog]. [inputs] maps every input name to its limb names on the
  /// stack: four limbs for a QM31, or one limb for a base-field value
  /// (embedded as (x, 0, 0, 0)). Inputs named in [consume] are consumed
  /// (rolled at their last use, dropped when unused); the rest are only
  /// picked. Leaves the outputs as canonical limbs named [out][j].
  static void emit(StackEmitter e, Program prog, Map<String, List<String>> inputs, List<List<String>> out,
      {Set<String> consume = const {}}) {
    if (out.length != prog.outputs.length) throw ArgumentError('${prog.outputs.length} outputs expected');
    final nIn = prog.numInputs;
    // reachability from the outputs, and use counts (outputs count as uses)
    final live = List<bool>.filled(prog.numNodes, false);
    final uses = List<int>.filled(prog.numNodes, 0);
    for (final o in prog.outputs) {
      live[o] = true;
      uses[o]++;
    }
    for (int i = prog.ops.length - 1; i >= 0; i--) {
      final n = nIn + i;
      if (!live[n]) continue;
      final op = prog.ops[i];
      if (op.a >= 0) {
        live[op.a] = true;
        uses[op.a]++;
      }
      if (op.b >= 0) {
        live[op.b] = true;
        uses[op.b]++;
      }
    }
    // the limb names of every node; inputs materialised lazily
    final names = List<List<String>?>.filled(prog.numNodes, null);
    final consumable = List<bool>.filled(prog.numNodes, false);
    var tmp = 0;
    List<String> fresh() => limbNames('_pn${tmp++}');
    for (int k = 0; k < nIn; k++) {
      final nm = prog.inputNames[k];
      final l = inputs[nm];
      if (l == null) throw ArgumentError('no stack names for input "$nm"');
      if (l.length == 4) {
        names[k] = l;
        consumable[k] = consume.contains(nm);
      } else if (l.length == 1) {
        if (!live[k]) continue;
        // embed the base-field value
        final t = fresh();
        if (consume.contains(nm)) {
          e.roll(l[0], as: t[0]);
        } else {
          e.pick(l[0], as: t[0]);
        }
        for (int j = 1; j < 4; j++) {
          e.pushConst(0, as: t[j]);
        }
        names[k] = t;
        consumable[k] = true;
      } else {
        throw ArgumentError('input "$nm" needs 1 or 4 limbs');
      }
    }

    /// The operand's limbs for one use, and whether this use may consume
    /// them (its last use, and the node is consumable).
    (List<String>, bool) operand(int n) {
      uses[n]--;
      return (names[n]!, uses[n] == 0 && consumable[n]);
    }

    void take(String l, bool consume) {
      if (consume) {
        e.roll(l);
      } else {
        e.pick(l);
      }
    }

    void dropAll(List<String> l) {
      for (final x in l) {
        e.dropNamed(x);
      }
    }

    void limbwise(int a, int b, bool add, List<String> dst) {
      final (la, ca) = operand(a);
      final (lb, cb) = operand(b);
      final same = a == b;
      for (int j = 0; j < 4; j++) {
        take(la[j], !same && ca);
        take(lb[j], !same && cb);
        if (add) {
          e.add();
        } else {
          e.sub();
        }
        e.reduce();
        e.nameTop(dst[j]);
      }
      if (same && cb) dropAll(la);
    }

    for (int i = 0; i < prog.ops.length; i++) {
      final n = nIn + i;
      if (!live[n]) continue;
      final op = prog.ops[i];
      final dst = fresh();
      switch (op.kind) {
        case ProgKind.constant:
          for (int j = 0; j < 4; j++) {
            e.pushConst(op.imm.limbs[j], as: dst[j]);
          }
        case ProgKind.add:
          limbwise(op.a, op.b, true, dst);
        case ProgKind.sub:
          limbwise(op.a, op.b, false, dst);
        case ProgKind.scale:
          final (la, ca) = operand(op.a);
          for (int j = 0; j < 4; j++) {
            take(la[j], ca);
            e.mulConst(op.imm.c0.a);
            e.reduce();
            e.nameTop(dst[j]);
          }
        case ProgKind.mul:
          final (la, ca) = operand(op.a);
          final (lb, cb) = operand(op.b);
          final same = op.a == op.b;
          M31Ops.qm31Mul(e, la, lb, dst, consumeA: !same && ca, consumeB: !same && cb);
          if (same && cb) dropAll(la);
      }
      names[n] = dst;
      consumable[n] = true;
    }
    // outputs: the last reference moves, earlier ones copy
    for (int j = 0; j < out.length; j++) {
      final (l, c) = operand(prog.outputs[j]);
      for (int k = 0; k < 4; k++) {
        take(l[k], c);
        e.nameTop(out[j][k]);
      }
    }
    // consumable inputs that nothing used
    for (int k = 0; k < nIn; k++) {
      final nm = prog.inputNames[k];
      if (!consume.contains(nm)) continue;
      for (final l in inputs[nm]!) {
        if (e.has(l)) e.dropNamed(l);
      }
    }
  }
}
