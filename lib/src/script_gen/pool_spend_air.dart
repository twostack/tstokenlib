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
import '../crypto/m31.dart';
import '../crypto/stark_prover_ref.dart';
import '../crypto/poseidon2_m31.dart';
import 'poseidon2_chain_air.dart';

/// The pool's hash definitions, shared by wallets, the prover and the tests.
/// Every hash is the Poseidon2 permutation on 16 M31 lanes truncated to its
/// first 8 lanes (248 bits). Lane widths: sk 5 (155-bit key), d 3, rho 3,
/// rcm 4, pk_d and digests 8; values are two 28-bit limbs (56-bit sats).
class PoolHash {
  static const skLanes = 5, dLanes = 3, rhoLanes = 3, rcmLanes = 4, digestLanes = 8;
  static const limbBits = 28;
  static const maxValue = 1 << (2 * limbBits);

  static List<int> _perm8(List<int> in16) {
    if (in16.length != 16) throw ArgumentError('permutation input must be 16 lanes');
    return Poseidon2M31.permute(in16).sublist(0, digestLanes);
  }

  static List<int> _pad(List<int> v, int n) => [...v, ...List.filled(n - v.length, 0)];

  static (int, int) limbs(int value) {
    if (value < 0 || value >= maxValue) throw ArgumentError('value out of range');
    return (value & ((1 << limbBits) - 1), value >> limbBits);
  }

  /// The public balance may be negative (a deposit): lo in [0, 2^28) and a
  /// signed hi, so that lo + 2^28 hi = value. The circuit only ever sees the
  /// lanes modulo p, and the covenant decodes residues above (p-1)/2 as
  /// negative; the balance constraints fix both limbs exactly either way.
  static (int, int) signedLimbs(int value) {
    if (value <= -maxValue || value >= maxValue) throw ArgumentError('value out of range');
    final lo = value & ((1 << limbBits) - 1);
    return (lo, (value - lo) >> limbBits);
  }

  /// A signed limb as its M31 lane.
  static int laneOf(int signed) => signed % M31.p;

  /// pk_d = H(sk, d): the diversified address.
  static List<int> pkd(List<int> sk, List<int> d) => _perm8(_pad([...sk, ...d], 16));

  /// Two-block note commitment: s = H(pk_d, value, rho), cm = H(s, rcm).
  static (List<int>, List<int>) commit(List<int> pkd, int value, List<int> rho, List<int> rcm) {
    final (lo, hi) = limbs(value);
    final s = _perm8(_pad([...pkd, lo, hi, ...rho], 16));
    return (s, _perm8(_pad([...s, ...rcm], 16)));
  }

  /// nf = H(sk, rho).
  static List<int> nullifier(List<int> sk, List<int> rho) => _perm8(_pad([...sk, ...rho], 16));

  static List<int> node(List<int> left, List<int> right) => _perm8([...left, ...right]);

  /// Merkle root of [leaf] at [position] given its [siblings], leaf level first.
  static List<int> root(List<int> leaf, List<List<int>> siblings, int position) {
    var h = leaf;
    for (int i = 0; i < siblings.length; i++) {
      final right = (position >> i) & 1 == 1;
      h = right ? node(siblings[i], h) : node(h, siblings[i]);
    }
    return h;
  }
}

/// A note being spent: its secrets and its Merkle path.
///
/// A [dummy] note fills the second input slot of a one-input spend. It has
/// value zero and no Merkle path; the circuit's flag lane switches its anchor
/// pin off and forces both value limbs to zero. Its nullifier H(sk, rho) is
/// published like any other, so [rho] must be fresh for every dummy.
class SpendNote {
  final List<int> sk, d, rho, rcm;
  final int value;
  final List<List<int>> siblings;
  final int position;
  final bool dummy;
  SpendNote({
    required this.sk,
    required this.d,
    required this.value,
    required this.rho,
    required this.rcm,
    required this.siblings,
    required this.position,
  }) : dummy = false {
    if (sk.length != PoolHash.skLanes || d.length != PoolHash.dLanes) throw ArgumentError('key lanes');
    if (rho.length != PoolHash.rhoLanes || rcm.length != PoolHash.rcmLanes) throw ArgumentError('note lanes');
    if (siblings.length != PoolSpendAir.depth) throw ArgumentError('path depth');
  }

  SpendNote.dummy({required this.sk, required this.rho})
      : d = List.filled(PoolHash.dLanes, 0),
        rcm = List.filled(PoolHash.rcmLanes, 0),
        value = 0,
        siblings = List.generate(PoolSpendAir.depth, (_) => List.filled(PoolHash.digestLanes, 0)),
        position = 0,
        dummy = true {
    if (sk.length != PoolHash.skLanes || rho.length != PoolHash.rhoLanes) throw ArgumentError('lanes');
  }
  List<int> get pkd => PoolHash.pkd(sk, d);
  List<int> get cm => PoolHash.commit(pkd, value, rho, rcm).$2;
  List<int> get nullifier => PoolHash.nullifier(sk, rho);
  List<int> get root => PoolHash.root(cm, siblings, position);
}

/// A note being created.
class OutputNote {
  final List<int> pkd, rho, rcm;
  final int value;
  OutputNote({required this.pkd, required this.value, required this.rho, required this.rcm});
  List<int> get cm => PoolHash.commit(pkd, value, rho, rcm).$2;
}

/// What the verifier is told, supplied at spend time below the proof in the
/// unlocking script (see [Air.numPublics]). [publicOut] is the value leaving
/// the pool: fee plus unshielded amount. The locking script does not depend
/// on these values; the covenant binds them to the transaction.
class PoolPublicInputs {
  final List<int> anchor, nf1, nf2, cmOut1, cmOut2;
  final int publicOut;

  /// SHA256 of the transfer's extra outputs (the unshield payees), as eight
  /// 31-bit lanes (each 4-byte LE chunk masked to 31 bits). No constraint
  /// reads it: absorbing it into the transcript is what binds the proof to
  /// the recipients; the PP1_SP state script checks it against the outputs.
  final List<int> outHash;

  /// Whether input note 1 / 2 is real (1) or a dummy (0). Pinned to the
  /// circuit's flag register, so a dummy declared real fails the anchor pin
  /// and a real note declared dummy fails the zero-value pins. The pool's
  /// state script skips the nullifier insertion of a dummy: its nullifier
  /// protects nothing, and inserting it would grow the set by two leaves per
  /// deposit and one per one-input spend.
  final bool real1, real2;
  PoolPublicInputs(this.anchor, this.nf1, this.nf2, this.cmOut1, this.cmOut2, this.publicOut,
      {List<int>? outHash, this.real1 = true, this.real2 = true})
      : outHash = outHash ?? List.filled(8, 0);

  /// All-zero publics: the verifier script does not depend on the values.
  static PoolPublicInputs zero() {
    final z = List.filled(8, 0);
    return PoolPublicInputs(z, z, z, z, z, 0);
  }

  /// The [outHash] lanes of serialised extra outputs.
  static List<int> outHashLanes(List<int> extraOutputs) {
    final h = Uint8List.fromList(crypto.sha256.convert(extraOutputs).bytes);
    final bd = ByteData.view(h.buffer);
    return [for (int k = 0; k < 8; k++) bd.getUint32(4 * k, Endian.little) & 0x7fffffff];
  }

  // indices into [toLanes]
  static const idxAnchor = 0, idxNf1 = 8, idxNf2 = 16, idxCm1 = 24, idxCm2 = 32, idxPubLo = 40, idxPubHi = 41;
  static const idxOutHash = 42;
  static const idxReal1 = 50, idxReal2 = 51;
  static const count = 52;

  List<int> toLanes() {
    final (lo, hiSigned) = PoolHash.signedLimbs(publicOut);
    final hi = PoolHash.laneOf(hiSigned);
    return [...anchor, ...nf1, ...nf2, ...cmOut1, ...cmOut2, lo, hi, ...outHash, real1 ? 1 : 0, real2 ? 1 : 0];
  }

  /// The inverse of [toLanes]: decode the 50 lanes a verifier slot was
  /// unlocked with. The high limb is signed (residues above (p-1)/2 are
  /// negative), as the state script reads it; a deposit has a negative
  /// [publicOut].
  static PoolPublicInputs fromLanes(List<int> lanes) {
    if (lanes.length != count) throw ArgumentError('$count lanes expected');
    if (lanes.any((l) => l < 0 || l >= M31.p)) throw ArgumentError('lane out of range');
    List<int> at(int i) => lanes.sublist(i, i + 8);
    final lo = lanes[idxPubLo], hi = lanes[idxPubHi];
    if (lo >= 1 << PoolHash.limbBits) throw ArgumentError('low limb out of range');
    final hiSigned = hi > (M31.p - 1) ~/ 2 ? hi - M31.p : hi;
    if (hiSigned.abs() >= 1 << PoolHash.limbBits) throw ArgumentError('high limb out of range');
    if (lanes[idxReal1] > 1 || lanes[idxReal2] > 1) throw ArgumentError('real flags are not boolean');
    return PoolPublicInputs(at(idxAnchor), at(idxNf1), at(idxNf2), at(idxCm1), at(idxCm2), lo + (hiSigned << PoolHash.limbBits),
        outHash: at(idxOutHash), real1: lanes[idxReal1] == 1, real2: lanes[idxReal2] == 1);
  }

  PoolPublicInputs copyWith({List<int>? anchor, List<int>? nf1, int? publicOut, List<int>? outHash, bool? real1, bool? real2}) =>
      PoolPublicInputs(anchor ?? this.anchor, nf1 ?? this.nf1, nf2, cmOut1, cmOut2, publicOut ?? this.publicOut,
          outHash: outHash ?? this.outHash, real1: real1 ?? this.real1, real2: real2 ?? this.real2);
}

/// The prover's side: the full trace for [PoolSpendAir.air] of [publics].
class PoolSpendWitness {
  final List<List<int>> rows;
  final PoolPublicInputs publics;
  PoolSpendWitness(this.rows, this.publics);
}

/// The two-input, two-output spend as a program over [Poseidon2ChainAir].
///
/// Per half (one input note each), periods:
///   0        P(sk, d || pad)          -> pk_d          break; register = sk
///   1        P(pk_d || value, rho)    -> s             register = rho; balance += value
///   2        P(s || rcm)              -> cm
///   3..34    32 Merkle steps          -> root          pinned = anchor, gated by the flag
///   35       P(sk, rho || pad)        -> nf            break; register = sk, rho; nf public
///   36       P(pk_d' || value', rho') -> s'            break; balance -= value'
///   37       P(s' || rcm')            -> cm'           pinned public
///   38..63   filler
///
/// The proof is state-free: it names an anchor (any recent root the pool's
/// ring holds) and the commitments it creates; the PP1_SP round appends the
/// commitments in script (the subtree-append slot), so nothing here depends
/// on the tree at proving time and a lost race costs a rebuild, not a proof.
/// (The in-circuit paired append of an earlier version lives on as
/// [SiblingBinding] in the chain AIR, tested on its own.)
///
/// Values are two 28-bit limbs. The output value is range-checked by bit
/// decomposition in the free bit lanes of period 35 (rows 24..27 for the low
/// limb, 28..31 for the high one), gathered by two accumulator columns and
/// compared with the value lanes at the transition into period 36.
///
/// Balance is two cyclic register lanes (low and high limb) that jump by the
/// input value, by minus the output value, and at the closing row by minus
/// the public amount and minus carry * 2^28 (low) / plus carry (high). The
/// carry c in [-3, 4] is c + 3 written as three bits in the closing row's bit
/// lanes. Jumps around the cycle must sum to zero, which is the balance
/// equation over the integers because every term is far below p.
///
/// Dummy notes. A flag register lane (one value per half) is constrained
/// boolean at the input value row, where it also forces both value limbs to
/// zero when off; the anchor pins are multiplied by it. A real note therefore
/// has its Merkle root pinned to the anchor, while a dummy contributes nothing
/// to the balance and may carry any path. (Gating on the value itself would
/// be unsound: an unconstrained dummy could pick limbs lo = -hi mod p.) The
/// flag is also pinned to a public lane per note ([PoolPublicInputs.real1],
/// [PoolPublicInputs.real2]) so the pool can skip a dummy's nullifier.
class PoolSpendAir {
  static const logTrace = 12;

  /// The production FRI parameters (re-tuned 2026-09-19 for prover latency
  /// under Teranode's limits): blowup 32, 18 queries, 16-bit grinding, 106
  /// conjectured bits; verifier slot ~554 KB / 249 K ops, proof ~113 KB,
  /// prover ~5 s in Dart. Blowup 64 / 15 queries (494 KB, ~10 s) and 16 / 23
  /// queries (653 KB, ~3 s) bracket it.
  static const productionParams = StarkParams(
      logTrace: logTrace, logBlowup: 5, logExpand: 3, logFinal: 10, numQueries: 18, grindBytes: 2, zkRandomizers: 128);
  static const n = 1 << logTrace;
  static const depth = 32;
  static const pKey = 0, pCm1 = 1, pCm2 = 2, pMerkle = 3, pNf = 35, pOut1 = 36, pOut2 = 37;
  static const pRange = pOut1 - 1; // the period whose bit lanes hold the output value
  static const half = 64;

  // columns
  static const regSk = 16, regRho = regSk + PoolHash.skLanes; // 16..20, 21..23
  static const regBalLo = regRho + PoolHash.rhoLanes, regBalHi = regBalLo + 1; // 24, 25
  static const regFlag = regBalHi + 1; // 26: 1 for a real note, 0 for a dummy
  static const accLo = 27, accHi = 28;
  static const numCols = 29;

  // lanes inside the rows the register is tied to
  static const valueLo = 8, valueHi = 9;
  static const cm1RhoLane = 10;
  static const nfRhoLane = PoolHash.skLanes;

  // rows
  static const inValueRow = pCm1 << 5; // 32
  static const outValueRow = pOut1 << 5; // 1152
  static const rangeCompareRow = outValueRow - 1; // 1151
  static const closeRow = n - 2; // 4094

  static const carryLane0 = Poseidon2ChainAir.bitLane0, carryBits = 3, carryOffset = 3;

  static const _twoPow = 1 << PoolHash.limbBits; // 2^28
  static final int _halfPow = M31.mul(_twoPow, M31.inv(2)); // 2^27
  static final int _halfOne = M31.inv(2);

  /// Accumulator schedules: low limb over rows 24..27, high over 28..31.
  static AccumulatorSpec _acc(int first) => AccumulatorSpec(
        [for (int r = 0; r < 32; r++) r == first ? 0 : (r > first && r < first + 4 ? 128 : 1)],
        [for (int r = 0; r < 32; r++) r >= first && r < first + 4 ? 1 : 0],
      );

  static Poseidon2ChainAir air(PoolPublicInputs pub) {
    List<BoundaryExpr> pub8(int idxA, int idxB, {int gateCol = -1}) =>
        [for (int j = 0; j < 8; j++) BoundaryExpr.publicAt(j, idxA + j, idxB + j, gateCol: gateCol)];
    BoundaryExpr jump(int reg, int lane, {required bool minus}) => BoundaryExpr([
          BoundaryTerm(reg, next: true),
          BoundaryTerm(reg, coef: M31.p - 1),
          BoundaryTerm(lane, coef: minus ? 1 : M31.p - 1),
        ]);
    // closing jumps, applied on this side of the pair only via (1+s)/2:
    //   lo: next - cur + pub_lo + 2^28 * c,  hi: next - cur + pub_hi - c,
    //   c = b0 + 2 b1 + 4 b2 - 3
    List<BoundaryTerm> carry(int scale) => [
          for (int k = 0; k < carryBits; k++) ...[
            BoundaryTerm(carryLane0 + k, coef: M31.mul(scale, 1 << k)),
            BoundaryTerm(carryLane0 + k, coef: M31.mul(scale, 1 << k), timesS: true),
          ]
        ];
    final closeLo = BoundaryExpr(
      [BoundaryTerm(regBalLo, next: true), BoundaryTerm(regBalLo, coef: M31.p - 1), ...carry(_halfPow)],
      constA: M31.neg(M31.mul(carryOffset, _twoPow)),
      pubA: PoolPublicInputs.idxPubLo, pubB: -1, pubCoef: 1,
    );
    final closeHi = BoundaryExpr(
      [BoundaryTerm(regBalHi, next: true), BoundaryTerm(regBalHi, coef: M31.p - 1), ...carry(M31.neg(_halfOne))],
      constA: carryOffset,
      pubA: PoolPublicInputs.idxPubHi, pubB: -1, pubCoef: 1,
    );
    return Poseidon2ChainAir(
      logTrace,
      breakPeriods: const [pKey, pNf, pOut1],
      registers: [
        for (int i = 0; i < PoolHash.skLanes + PoolHash.rhoLanes; i++) const [n - 1],
        const [inValueRow, outValueRow, closeRow],
        const [inValueRow, outValueRow, closeRow],
        const [n - 1],
      ],
      accumulators: [_acc(24), _acc(28)],
      publics: pub.toLanes(),
      boundaries: [
        BoundaryGroup(Poseidon2ChainAir.outputRow(pMerkle + depth - 1),
            pub8(PoolPublicInputs.idxAnchor, PoolPublicInputs.idxAnchor, gateCol: regFlag)),
        BoundaryGroup(Poseidon2ChainAir.outputRow(pNf), pub8(PoolPublicInputs.idxNf1, PoolPublicInputs.idxNf2)),
        BoundaryGroup(Poseidon2ChainAir.outputRow(pOut2), pub8(PoolPublicInputs.idxCm1, PoolPublicInputs.idxCm2)),
        BoundaryGroup(Poseidon2ChainAir.inputRow(pKey),
            [for (int i = 0; i < PoolHash.skLanes; i++) BoundaryExpr.equal(regSk + i, i)]),
        BoundaryGroup(inValueRow, [
          for (int i = 0; i < PoolHash.rhoLanes; i++) BoundaryExpr.equal(regRho + i, cm1RhoLane + i),
          jump(regBalLo, valueLo, minus: false),
          jump(regBalHi, valueHi, minus: false),
          BoundaryExpr.boolean(regFlag),
          BoundaryExpr.publicAt(regFlag, PoolPublicInputs.idxReal1, PoolPublicInputs.idxReal2),
          BoundaryExpr.zeroUnless(valueLo, regFlag),
          BoundaryExpr.zeroUnless(valueHi, regFlag),
        ]),
        BoundaryGroup(Poseidon2ChainAir.inputRow(pNf), [
          for (int i = 0; i < PoolHash.skLanes; i++) BoundaryExpr.equal(regSk + i, i),
          for (int i = 0; i < PoolHash.rhoLanes; i++) BoundaryExpr.equal(regRho + i, nfRhoLane + i),
        ]),
        BoundaryGroup(rangeCompareRow, [
          BoundaryExpr([BoundaryTerm(valueLo, next: true), BoundaryTerm(accLo, next: true, coef: M31.p - 1)]),
          BoundaryExpr([BoundaryTerm(valueHi, next: true), BoundaryTerm(accHi, next: true, coef: M31.p - 1)]),
        ]),
        BoundaryGroup(outValueRow, [
          jump(regBalLo, valueLo, minus: true),
          jump(regBalHi, valueHi, minus: true),
        ]),
        BoundaryGroup(closeRow, [closeLo, closeHi]),
      ],
    );
  }

  static List<int> _pad(List<int> v, int n) => [...v, ...List.filled(n - v.length, 0)];

  static List<ChainStep> _halfProgram(SpendNote sn, OutputNote on) {
    final (lo, hi) = PoolHash.limbs(sn.value);
    final (olo, ohi) = PoolHash.limbs(on.value);
    return [
      ChainStep.fresh(_pad([...sn.sk, ...sn.d], 16)),
      ChainStep.chained(_pad([lo, hi, ...sn.rho], 8)),
      ChainStep.chained(_pad(sn.rcm, 8)),
      for (int i = 0; i < depth; i++) ChainStep.chained(sn.siblings[i], swap: (sn.position >> i) & 1 == 1),
      ChainStep.fresh(_pad([...sn.sk, ...sn.rho], 16)),
      ChainStep.fresh(_pad([...on.pkd, olo, ohi, ...on.rho], 16)),
      ChainStep.chained(_pad(on.rcm, 8)),
      for (int p = pOut2 + 1; p < half; p++) ChainStep.chained(List.filled(8, 0)),
    ];
  }

  /// Write a 28-bit limb into the bit lanes of rows [first]..[first]+3 of
  /// period [period], most significant 7-bit chunk first (the accumulator
  /// shifts left by 7 per row).
  static void _writeLimb(List<List<int>> rows, int period, int first, int limb) {
    for (int i = 0; i < 4; i++) {
      final chunk = (limb >> (7 * (3 - i))) & 127;
      final row = rows[(period << 5) + first + i];
      for (int k = 0; k < 7; k++) {
        row[Poseidon2ChainAir.bitLane0 + k] = (chunk >> k) & 1;
      }
    }
  }

  /// Build the trace for spending [a] and [b] into [oa] and [ob].
  ///
  /// A deposit is a spend of two dummies with a negative [publicOut]; the
  /// anchor pins are then off and [anchor] (any root the pool's ring holds)
  /// is what the pool's state script will see.
  static PoolSpendWitness witness(SpendNote a, SpendNote b, OutputNote oa, OutputNote ob, int publicOut,
      {List<int>? outHash, List<int>? anchor}) {
    final real = [a, b].where((s) => !s.dummy).toList();
    if (real.isEmpty && anchor == null) throw ArgumentError('two dummies need an anchor for the covenant');
    anchor = real.isEmpty ? anchor! : real.first.root;
    for (final s in real) {
      final root = s.root;
      for (int j = 0; j < 8; j++) {
        if (root[j] != anchor[j]) throw ArgumentError('the real input notes must be under the same anchor');
      }
    }
    if (a.value + b.value != oa.value + ob.value + publicOut) throw ArgumentError('values do not balance');

    final pub = PoolPublicInputs(anchor, a.nullifier, b.nullifier, oa.cm, ob.cm, publicOut,
        outHash: outHash, real1: !a.dummy, real2: !b.dummy);
    final chain = air(pub);
    final rows = chain.generateChain([..._halfProgram(a, oa), ..._halfProgram(b, ob)]);

    // key registers, per half
    for (int r = 0; r < n; r++) {
      final note = r < (n >> 1) ? a : b;
      for (int i = 0; i < PoolHash.skLanes; i++) {
        rows[r][regSk + i] = note.sk[i];
      }
      for (int i = 0; i < PoolHash.rhoLanes; i++) {
        rows[r][regRho + i] = note.rho[i];
      }
      rows[r][regFlag] = note.dummy ? 0 : 1;
    }

    // output value bits in the period before out1 of each half, then the accumulators
    for (final (base, out) in [(0, oa), (half, ob)]) {
      final (olo, ohi) = PoolHash.limbs(out.value);
      _writeLimb(rows, base + pRange, 24, olo);
      _writeLimb(rows, base + pRange, 28, ohi);
    }
    // carry: c = (lo_a + lo_b - olo_a - olo_b - pub_lo) / 2^28, written as c + 3
    final (la, ha) = PoolHash.limbs(a.value);
    final (lb, hb) = PoolHash.limbs(b.value);
    final (ola, oha) = PoolHash.limbs(oa.value);
    final (olb, ohb) = PoolHash.limbs(ob.value);
    final (pl, ph) = PoolHash.signedLimbs(publicOut);
    final loDiff = la + lb - ola - olb - pl;
    if (loDiff % _twoPow != 0) throw StateError('low limbs do not carry cleanly');
    final c = loDiff ~/ _twoPow;
    if (ha + hb - oha - ohb - ph + c != 0) throw StateError('high limbs do not balance');
    final cBits = c + carryOffset;
    if (cBits < 0 || cBits >= (1 << carryBits)) throw StateError('carry out of range');
    for (int k = 0; k < carryBits; k++) {
      rows[closeRow][carryLane0 + k] = (cBits >> k) & 1;
    }
    chain.fillAccumulators(rows);

    // balance registers: jumps at the value rows and the closing row
    int balLo = 0, balHi = 0;
    for (int r = 0; r < n; r++) {
      rows[r][regBalLo] = balLo;
      rows[r][regBalHi] = balHi;
      final inHalf = r < (n >> 1);
      if (r == inValueRow || r == inValueRow + (n >> 1)) {
        final (l, h) = inHalf ? (la, ha) : (lb, hb);
        balLo = M31.add(balLo, l);
        balHi = M31.add(balHi, h);
      } else if (r == outValueRow || r == outValueRow + (n >> 1)) {
        final (l, h) = inHalf ? (ola, oha) : (olb, ohb);
        balLo = M31.sub(balLo, l);
        balHi = M31.sub(balHi, h);
      } else if (r == closeRow) {
        balLo = M31.sub(balLo, M31.add(pl, M31.mul(c < 0 ? M31.p + c : c, _twoPow)));
        balHi = M31.sub(balHi, M31.sub(ph, c < 0 ? M31.p + c : c));
      }
    }
    if (balLo != 0 || balHi != 0) throw StateError('balance does not close');
    return PoolSpendWitness(rows, pub);
  }

}
