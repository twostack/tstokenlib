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

/// Reference implementation of the Mersenne-31 field, its complex (CM31)
/// and quartic (QM31) extensions, and the circle group over M31.
///
/// This is the off-chain side of the STARK verifier prototype: it defines
/// the exact arithmetic the script emitters in `m31_script_gen.dart` must
/// reproduce, and it is used by tests to generate expected values.
///
/// Conventions follow Stwo / Plonky3:
///   CM31 = M31[i] / (i^2 + 1)
///   QM31 = CM31[u] / (u^2 - (2 + i))
library;

/// Mersenne-31 prime field arithmetic on plain Dart ints.
///
/// All values are canonical in [0, p). Products of two field elements are
/// below 2^62 and fit in a signed 64-bit Dart int.
class M31 {
  static const int p = 0x7fffffff; // 2^31 - 1

  static int reduce(int x) {
    final r = x % p;
    return r < 0 ? r + p : r;
  }

  static int add(int a, int b) => reduce(a + b);
  static int sub(int a, int b) => reduce(a - b);
  static int mul(int a, int b) => reduce(a * b);
  static int neg(int a) => a == 0 ? 0 : p - a;

  static int pow(int base, int exp) {
    var result = 1;
    var b = base;
    var e = exp;
    while (e > 0) {
      if (e & 1 == 1) result = mul(result, b);
      b = mul(b, b);
      e >>= 1;
    }
    return result;
  }

  /// Multiplicative inverse via Fermat: a^(p-2).
  static int inv(int a) {
    if (a == 0) throw ArgumentError('inverse of zero');
    return pow(a, p - 2);
  }
}

/// Complex extension: a + b*i with i^2 = -1.
class CM31 {
  final int a, b;
  const CM31(this.a, this.b);

  static const zero = CM31(0, 0);
  static const one = CM31(1, 0);

  CM31 operator +(CM31 o) => CM31(M31.add(a, o.a), M31.add(b, o.b));
  CM31 operator -(CM31 o) => CM31(M31.sub(a, o.a), M31.sub(b, o.b));
  CM31 operator *(CM31 o) => CM31(
        M31.sub(M31.mul(a, o.a), M31.mul(b, o.b)),
        M31.add(M31.mul(a, o.b), M31.mul(b, o.a)),
      );
  CM31 scale(int m) => CM31(M31.mul(a, m), M31.mul(b, m));

  /// Multiply by (2 + i): (a + bi)(2 + i) = (2a - b) + (a + 2b)i
  CM31 mulByTwoPlusI() => CM31(
        M31.sub(M31.add(a, a), b),
        M31.add(a, M31.add(b, b)),
      );

  CM31 get conj => CM31(a, M31.neg(b));

  /// (a + bi)^-1 = (a - bi) / (a^2 + b^2)
  CM31 get inv {
    final n = M31.add(M31.mul(a, a), M31.mul(b, b));
    return conj.scale(M31.inv(n));
  }

  @override
  bool operator ==(Object o) => o is CM31 && o.a == a && o.b == b;
  @override
  int get hashCode => Object.hash(a, b);
  @override
  String toString() => 'CM31($a, $b)';
}

/// Quartic extension: c0 + c1*u with u^2 = 2 + i, c0, c1 in CM31.
///
/// Limb order used throughout (and by the script emitters): [c0.a, c0.b, c1.a, c1.b].
class QM31 {
  final CM31 c0, c1;
  const QM31(this.c0, this.c1);

  QM31.fromLimbs(int a0, int a1, int a2, int a3)
      : c0 = CM31(a0, a1),
        c1 = CM31(a2, a3);

  static const zero = QM31(CM31.zero, CM31.zero);
  static const one = QM31(CM31.one, CM31.zero);

  List<int> get limbs => [c0.a, c0.b, c1.a, c1.b];

  QM31 operator +(QM31 o) => QM31(c0 + o.c0, c1 + o.c1);
  QM31 operator -(QM31 o) => QM31(c0 - o.c0, c1 - o.c1);

  /// (c0 + c1 u)(d0 + d1 u) = (c0 d0 + c1 d1 (2+i)) + (c0 d1 + c1 d0) u
  QM31 operator *(QM31 o) => QM31(
        c0 * o.c0 + (c1 * o.c1).mulByTwoPlusI(),
        c0 * o.c1 + c1 * o.c0,
      );

  /// Multiply by a base-field scalar.
  QM31 scale(int m) => QM31(c0.scale(m), c1.scale(m));

  /// Conjugation u -> -u: the automorphism of QM31 = CM31[u] fixing CM31.
  /// This is the conjugate used by the DEEP quotient (as in Stwo); it must
  /// commute with evaluating M31-coefficient polynomials, which negating the
  /// i-components would not (u² = 2 + i is not fixed by i -> -i).
  QM31 get conj => QM31(c0, CM31.zero - c1);

  /// (c0 + c1 u)^-1 = (c0 - c1 u) / (c0^2 - c1^2 (2+i))
  QM31 get inv {
    final n = c0 * c0 - (c1 * c1).mulByTwoPlusI();
    final ni = n.inv;
    return QM31(c0 * ni, (CM31.zero - c1) * ni);
  }

  static const i = QM31(CM31(0, 1), CM31.zero);
  static const u = QM31(CM31.zero, CM31(1, 0));

  @override
  bool operator ==(Object o) => o is QM31 && o.c0 == c0 && o.c1 == c1;
  @override
  int get hashCode => Object.hash(c0, c1);
  @override
  String toString() => 'QM31$limbs';
}

/// A point on the unit circle x^2 + y^2 = 1 over M31.
///
/// The circle group has order 2^31. Group law is complex multiplication:
///   (x1, y1) * (x2, y2) = (x1 x2 - y1 y2, x1 y2 + x2 y1)
class CirclePoint {
  final int x, y;
  const CirclePoint(this.x, this.y);

  /// Generator of the full circle group (order 2^31), as used by Stwo.
  static const generator = CirclePoint(2, 1268011823);
  static const identity = CirclePoint(1, 0);

  CirclePoint operator *(CirclePoint o) => CirclePoint(
        M31.sub(M31.mul(x, o.x), M31.mul(y, o.y)),
        M31.add(M31.mul(x, o.y), M31.mul(o.x, y)),
      );

  /// Doubling: (2x^2 - 1, 2xy)
  CirclePoint double_() => CirclePoint(
        M31.sub(M31.mul(2, M31.mul(x, x)), 1),
        M31.mul(2, M31.mul(x, y)),
      );

  CirclePoint pow(int e) {
    var result = identity;
    var b = this;
    var k = e;
    while (k > 0) {
      if (k & 1 == 1) result = result * b;
      b = b.double_();
      k >>= 1;
    }
    return result;
  }

  /// Generator of the subgroup of order 2^logSize.
  static CirclePoint subgroupGen(int logSize) =>
      generator.pow(1 << (31 - logSize));

  bool get isOnCircle =>
      M31.add(M31.mul(x, x), M31.mul(y, y)) == 1;

  @override
  bool operator ==(Object o) => o is CirclePoint && o.x == x && o.y == y;
  @override
  int get hashCode => Object.hash(x, y);
  @override
  String toString() => 'CirclePoint($x, $y)';
}

/// A half-coset of the circle group in Stwo's canonical layout, in natural
/// order: point i = initial * step^i.
///
/// For size n = 2^logSize:
///   initial = generator of the subgroup of order 2^(logSize+2)
///   step    = generator of the subgroup of order 2^logSize
///
/// Properties used by the FRI fold:
///   * x(i + n/2) = -x(i)                  (pair partner for fold_line)
///   * x(i + n/4) = ±y(i)                 (so x(i + n/4)^2 = y(i)^2)
///   * doubling every point yields the half-coset of size n/2 in natural order
class HalfCoset {
  final int logSize;
  final CirclePoint initial;
  final CirclePoint step;

  HalfCoset(this.logSize)
      : initial = CirclePoint.subgroupGen(logSize + 2),
        step = CirclePoint.subgroupGen(logSize);

  int get size => 1 << logSize;

  CirclePoint at(int i) => initial * step.pow(i);

  List<CirclePoint> get points =>
      List.generate(size, (i) => at(i), growable: false);

  /// The half-coset obtained by doubling every point.
  HalfCoset get doubled => HalfCoset(logSize - 1);
}
