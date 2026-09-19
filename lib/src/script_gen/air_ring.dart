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

import '../crypto/m31.dart';

/// The arithmetic an AIR's constraints are written against, so that one
/// formulation serves several evaluators: [QM31Ring] computes values (the
/// executable spec), [ExprRing] records the computation as a straight-line
/// [Program], which is how a verifier *inside a circuit* evaluates another
/// AIR's constraints at the out-of-domain point.
abstract class Ring<T> {
  const Ring();
  T get zero;
  T get one;

  /// An M31 constant.
  T constM31(int m);

  /// A QM31 constant.
  T constQ(QM31 c);
  T add(T a, T b);
  T sub(T a, T b);
  T mul(T a, T b);

  /// Multiply by an M31 constant.
  T scale(T a, int m);

  T neg(T a) => sub(zero, a);
  T addConst(T a, int m) => add(a, constM31(m));

  /// Σ_j a_j scaled by M31 coefficients (zeros skipped).
  T linear(List<T> xs, List<int> coefs, {int constant = 0}) {
    T? acc;
    for (int j = 0; j < xs.length; j++) {
      if (coefs[j] == 0) continue;
      final term = coefs[j] == 1 ? xs[j] : scale(xs[j], coefs[j]);
      acc = acc == null ? term : add(acc, term);
    }
    if (constant != 0) acc = acc == null ? constM31(constant) : addConst(acc, constant);
    return acc ?? zero;
  }

  /// Horner: Σ_j x^j c_j.
  T horner(List<T> c, T x) {
    var acc = c.last;
    for (int j = c.length - 2; j >= 0; j--) {
      acc = add(mul(acc, x), c[j]);
    }
    return acc;
  }

  /// x^e by square and multiply.
  T pow(T x, int e) {
    var r = one, b = x;
    for (; e > 0; e >>= 1) {
      if (e & 1 == 1) r = mul(r, b);
      b = mul(b, b);
    }
    return r;
  }

  /// c0 + c1 i + c2 u + c3 iu (see `Air.composeLimbs`).
  T composeLimbs(List<T> c) => add(add(c[0], mul(c[1], constQ(QM31.i))),
      add(mul(c[2], constQ(QM31.u)), mul(c[3], constQ(QM31.i * QM31.u))));
}

/// Plain QM31 arithmetic.
class QM31Ring extends Ring<QM31> {
  const QM31Ring();
  static const instance = QM31Ring();
  @override
  QM31 get zero => QM31.zero;
  @override
  QM31 get one => QM31.one;
  @override
  QM31 constM31(int m) => QM31.fromLimbs(m, 0, 0, 0);
  @override
  QM31 constQ(QM31 c) => c;
  @override
  QM31 add(QM31 a, QM31 b) => a + b;
  @override
  QM31 sub(QM31 a, QM31 b) => a - b;
  @override
  QM31 mul(QM31 a, QM31 b) => a * b;
  @override
  QM31 scale(QM31 a, int m) => a.scale(m);
}

enum ProgKind { add, sub, mul, scale, constant }

/// One straight-line operation over node ids.
class ProgOp {
  final ProgKind kind;
  final int a, b;
  final QM31 imm;
  const ProgOp(this.kind, this.a, this.b, this.imm);
  @override
  String toString() => switch (kind) {
        ProgKind.add => 'add n$a n$b',
        ProgKind.sub => 'sub n$a n$b',
        ProgKind.mul => 'mul n$a n$b',
        ProgKind.scale => 'scale n$a ${imm.c0.a}',
        ProgKind.constant => 'const $imm',
      };
}

/// A straight-line program: inputs (nodes 0..numInputs-1), then one node per
/// operation; [outputs] name the nodes whose values are the result.
class Program {
  final List<String> inputNames;
  final List<ProgOp> ops;
  final List<int> outputs;
  Program(this.inputNames, this.ops, this.outputs);

  int get numInputs => inputNames.length;
  int get numNodes => numInputs + ops.length;

  /// Evaluate over QM31; returns every node's value.
  List<QM31> run(List<QM31> inputs) {
    if (inputs.length != numInputs) throw ArgumentError('${numInputs} inputs expected');
    final v = List<QM31>.filled(numNodes, QM31.zero);
    v.setRange(0, numInputs, inputs);
    for (int i = 0; i < ops.length; i++) {
      final op = ops[i];
      v[numInputs + i] = switch (op.kind) {
        ProgKind.add => v[op.a] + v[op.b],
        ProgKind.sub => v[op.a] - v[op.b],
        ProgKind.mul => v[op.a] * v[op.b],
        ProgKind.scale => v[op.a].scale(op.imm.c0.a),
        ProgKind.constant => op.imm,
      };
    }
    return v;
  }

  List<QM31> runOutputs(List<QM31> inputs) {
    final v = run(inputs);
    return [for (final o in outputs) v[o]];
  }

  int get numMuls => ops.where((o) => o.kind == ProgKind.mul).length;
}

/// Records arithmetic as a [Program]; values are node ids. Constants are
/// shared and trivial scalings are folded.
class ExprRing extends Ring<int> {
  final List<String> _inputs = [];
  final List<ProgOp> _ops = [];
  final Map<QM31, int> _consts = {};
  final Set<int> _isConst = {};
  final Map<int, QM31> _constValue = {};

  int input(String name) {
    _inputs.add(name);
    return _inputs.length - 1;
  }

  List<int> inputs(String prefix, int n) => [for (int k = 0; k < n; k++) input('$prefix$k')];

  int _emit(ProgOp op) {
    _ops.add(op);
    return _inputs.length + _ops.length - 1;
  }

  Program program(List<int> outputs) => Program(List.of(_inputs), List.of(_ops), outputs);

  @override
  int get zero => constQ(QM31.zero);
  @override
  int get one => constQ(QM31.one);
  @override
  int constM31(int m) => constQ(QM31.fromLimbs(m, 0, 0, 0));

  @override
  int constQ(QM31 c) => _consts.putIfAbsent(c, () {
        final id = _emit(ProgOp(ProgKind.constant, -1, -1, c));
        _isConst.add(id);
        _constValue[id] = c;
        return id;
      });

  QM31? _c(int id) => _constValue[id];

  @override
  int add(int a, int b) {
    final ca = _c(a), cb = _c(b);
    if (ca != null && cb != null) return constQ(ca + cb);
    if (ca == QM31.zero) return b;
    if (cb == QM31.zero) return a;
    return _emit(ProgOp(ProgKind.add, a, b, QM31.zero));
  }

  @override
  int sub(int a, int b) {
    final ca = _c(a), cb = _c(b);
    if (ca != null && cb != null) return constQ(ca - cb);
    if (cb == QM31.zero) return a;
    return _emit(ProgOp(ProgKind.sub, a, b, QM31.zero));
  }

  @override
  int mul(int a, int b) {
    final ca = _c(a), cb = _c(b);
    if (ca != null && cb != null) return constQ(ca * cb);
    if (ca == QM31.zero || cb == QM31.zero) return zero;
    if (ca == QM31.one) return b;
    if (cb == QM31.one) return a;
    if (ca != null && ca.c0.b == 0 && ca.c1 == CM31.zero) return scale(b, ca.c0.a);
    if (cb != null && cb.c0.b == 0 && cb.c1 == CM31.zero) return scale(a, cb.c0.a);
    return _emit(ProgOp(ProgKind.mul, a, b, QM31.zero));
  }

  @override
  int scale(int a, int m) {
    if (m == 0) return zero;
    if (m == 1) return a;
    final ca = _c(a);
    if (ca != null) return constQ(ca.scale(m));
    return _emit(ProgOp(ProgKind.scale, a, -1, QM31.fromLimbs(m, 0, 0, 0)));
  }
}
