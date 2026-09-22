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
import 'dart:math';
import 'dart:typed_data';

import '../crypto/m31.dart';
import '../crypto/note_encryption.dart';
import '../crypto/note_kem.dart';
import '../crypto/proof_codec.dart';
import '../crypto/stark_prover.dart';
import '../crypto/stark_prover_ref.dart' show StarkParams, StarkProof;
import '../crypto/stark_verifier_ref.dart';
import '../recursion/pool_aggregator.dart' show PoolAggregation;
import '../script_gen/pool_spend_air.dart';
import '../script_gen/slot_script_common.dart';
import 'pool_out_hash.dart';
import 'pool_outputs.dart';

/// Why a transfer was not accepted: the field or rule that failed, and what
/// was wrong with it. Every way a transfer can be refused, whether it came
/// in as bytes or was built in memory, ends in one of these, so a
/// coordinator reading an inbox anyone can write to has one thing to catch.
class TransferRefusal implements Exception {
  final String field;
  final String reason;
  const TransferRefusal(this.field, this.reason);
  @override
  String toString() => 'transfer refused ($field): $reason';
}

/// One TSL1_SP transfer as a wallet hands it to a coordinator and a
/// coordinator puts it in a round: a spend proof, its 56 public lanes, the
/// ciphertext bundle of its two output notes, the withdrawal it pays when
/// it takes BSV out, and, when it backs a deposit, the covenant outpoint it
/// backs.
///
/// Everything a reader needs from a transfer is either in the round's
/// statement or in this bundle. The statement leaves the two output
/// commitments out (pinning them cost 203 KB of root verifier), so the
/// bundle is the only place a reader finds them. Nothing in the circuit
/// ties a bundle's commitments to the proof's: `outHash` ties the bundle's
/// bytes to the transfer, and the tree root ties the commitments to the
/// round. A transfer whose bundle names another commitment would pass V
/// and leave every reader unable to reach the round's root, which is why
/// [refusal] checks it before a coordinator accepts the transfer.
class ShieldedTransfer {
  /// The first byte of every encoding. A change to the encoding bumps it.
  static const formatVersion = 1;

  /// The largest encoding a decoder reads. A production transfer is about
  /// 67 KB (63,512 B of proof, 224 B of publics, two 1,827 B bundles).
  static const maxEncoded = 100 * 1024;

  /// The largest bundle: two note bundles of the largest kind, each with an
  /// issuer copy (2 x 3,027 B).
  static final int maxBundle = 2 * NoteBundle.sizeOf(NoteKem.hybrid, issuerKem: NoteKem.hybrid);

  /// Bytes of a deposit covenant outpoint: txid then LE32 vout.
  static const outpointSize = 36;

  static const _flagWithdrawal = 1, _flagDeposit = 2;

  /// The spend parameters of the production pool, which a transfer's proof
  /// is made and decoded at.
  static const productionParams = PoolAggregation.spendThroughputParams;

  final PoolPublicInputs publics;
  final StarkProof proof;

  /// The note bundle of output 1 followed by that of output 2, or empty
  /// for a padding transfer.
  final Uint8List bundle;
  final PoolWithdrawal? withdrawal;
  final Uint8List? depositOutpoint;

  ShieldedTransfer(this.publics, this.proof, List<int> bundle, {this.withdrawal, List<int>? depositOutpoint})
      : bundle = Uint8List.fromList(bundle),
        depositOutpoint = depositOutpoint == null ? null : Uint8List.fromList(depositOutpoint);

  /// The one note every padding transfer pays both its outputs to: zero
  /// value, the zero address, zero randomness. Its commitment is a public
  /// constant, so a reader knows a padding transfer's leaves without a
  /// bundle. Anyone can spend it, once, for nothing.
  static final paddingNote = OutputNote(
      pkd: List.filled(PoolHash.digestLanes, 0), value: 0, rho: List.filled(PoolHash.rhoLanes, 0), rcm: List.filled(PoolHash.rcmLanes, 0));
  static final List<int> paddingCm = paddingNote.cm;

  /// The witness of a padding transfer: two dummies of fresh random keys
  /// into two copies of [paddingNote], nothing in or out, an empty bundle.
  /// The ring check is waived when neither input is real, so it is proved
  /// against the zero anchor and fits any round.
  static PoolSpendWitness paddingWitness({Random? rng}) {
    final r = rng ?? Random.secure();
    List<int> lanes(int n) => List.generate(n, (_) => r.nextInt(M31.p));
    final a = SpendNote.dummy(sk: lanes(PoolHash.skLanes), rho: lanes(PoolHash.rhoLanes));
    final b = SpendNote.dummy(sk: lanes(PoolHash.skLanes), rho: lanes(PoolHash.rhoLanes));
    return PoolSpendAir.witness(a, b, paddingNote, paddingNote, 0,
        anchor: List.filled(PoolHash.digestLanes, 0), outHash: PoolOutHash.transferLanes(PoolOutHash.bundleHash(const [])));
  }

  /// A padding transfer, proved at [spendP] (about 1.2 s at production
  /// parameters).
  static ShieldedTransfer padding(StarkParams spendP, {Random? rng}) {
    final r = rng ?? Random.secure();
    final w = paddingWitness(rng: r);
    final proof = StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: r, hash: const Poseidon2ProofHash());
    return ShieldedTransfer(w.publics, proof, const []);
  }

  bool get isPadding => publics.isPadding;
  bool get isBsv => PoolHash.isBsv(publics.asset);
  List<int> get bundleHash => PoolOutHash.bundleHash(bundle);

  /// The two note bundles, in output order; empty for an empty bundle.
  /// Throws [TransferRefusal] when the bytes are not exactly two bundles.
  List<NoteBundle> get notes => bundle.isEmpty ? const [] : parseBundle(bundle);

  /// [bytes] as exactly two note bundles.
  static List<NoteBundle> parseBundle(List<int> bytes) {
    try {
      final first = NoteBundle.parse(bytes, 0);
      final at = NoteBundle.lengthOf(bytes, 0);
      final second = NoteBundle.parse(bytes, at);
      if (at + NoteBundle.lengthOf(bytes, at) != bytes.length) {
        throw const TransferRefusal('bundle', 'bytes remain after the second note bundle');
      }
      return [first, second];
    } on TransferRefusal {
      rethrow;
    } catch (e) {
      throw TransferRefusal('bundle', 'is not two note bundles ($e)');
    }
  }

  /// The two output commitments a reader places for this transfer: the
  /// bundle's, or the padding note's for an empty bundle. Only meaningful
  /// once [refusal] is null.
  List<List<int>> get commitments =>
      bundle.isEmpty ? [paddingCm, paddingCm] : [for (final n in notes) n.cm];

  /// The receipt a deposit transfer implies: its first output commitment
  /// and the value it brings in. Null for any other transfer.
  PoolReceipt? get receipt =>
      depositOutpoint == null ? null : PoolReceipt(SlotScript.lanesBytes(publics.cmOut1), BigInt.from(-publics.publicOut));

  /// Null when the transfer is well formed on its own, else the first rule
  /// it breaks. Uses hashing and parsing only: no key agreement, no proof
  /// verification and no pool state, so a coordinator can refuse cheaply
  /// before it spends a verification on the transfer.
  TransferRefusal? refusal() {
    final p = publics;
    // outHash commits to the withdrawal record and the bundle
    final lanes = PoolOutHash.transferLanes(bundleHash, withdrawal: withdrawal);
    if (!_eq(lanes, p.outHash)) {
      return const TransferRefusal('outHash', 'the proof commits to another bundle or another withdrawal');
    }
    // a withdrawal exactly when BSV leaves, for exactly that amount
    final takesBsvOut = isBsv && p.publicOut > 0;
    if (takesBsvOut != (withdrawal != null)) {
      return TransferRefusal(
          'withdrawal', takesBsvOut ? 'takes ${p.publicOut} out and carries no withdrawal' : 'carries a withdrawal but takes no BSV out');
    }
    if (withdrawal != null && withdrawal!.satoshis != BigInt.from(p.publicOut)) {
      return TransferRefusal('withdrawal', 'takes ${p.publicOut} out, its withdrawal pays ${withdrawal!.satoshis}');
    }
    if (!isBsv && p.publicOut != 0) {
      return const TransferRefusal('publics', 'moves an asset other than BSV in or out, which the pool does not carry');
    }
    // the bundle names the proof's commitments, or is the padding's
    if (bundle.isEmpty) {
      if (!isPadding) return const TransferRefusal('bundle', 'is empty on a transfer that is not padding, so no reader could place its commitments');
      if (!_eq(p.cmOut1, paddingCm) || !_eq(p.cmOut2, paddingCm)) {
        return const TransferRefusal('bundle', 'is empty but the outputs are not the padding note');
      }
    } else {
      final List<NoteBundle> n;
      try {
        n = parseBundle(bundle);
      } on TransferRefusal catch (e) {
        return e;
      }
      if (!_eq(n[0].cm, p.cmOut1) || !_eq(n[1].cm, p.cmOut2)) {
        return const TransferRefusal('bundle', 'names commitments other than the proof\'s, so it does not match the proof');
      }
    }
    return depositRefusal();
  }

  /// The deposit shape: null for a transfer that names no deposit, or one
  /// that backs it as the root proof requires (two dummy inputs, BSV, money
  /// in); else why not. Dummy inputs are a privacy rule: a deposit is
  /// public, and a real input beside it would name the depositor as the
  /// owner of an earlier note.
  TransferRefusal? depositRefusal() {
    final o = depositOutpoint;
    if (o == null) return null;
    final p = publics;
    if (o.length != outpointSize) return TransferRefusal('deposit', 'an outpoint is $outpointSize bytes, not ${o.length}');
    if (p.real1 || p.real2) return const TransferRefusal('deposit', 'spends a real note beside a deposit, which the root proof refuses');
    if (!isBsv) return const TransferRefusal('deposit', 'is not in BSV');
    if (p.publicOut >= 0) return const TransferRefusal('deposit', 'brings no money in');
    return null;
  }

  /// Null when the proof verifies against the publics at [spendP], else why
  /// not. The expensive step, run only after [refusal].
  String? verifyProof(StarkParams spendP) {
    try {
      return StarkVerifierRef(spendP, PoolSpendAir.air(publics), hash: const Poseidon2ProofHash()).check(proof);
    } catch (e) {
      return 'the proof does not verify ($e)';
    }
  }

  // ---- wire format ----
  //
  //   version        1
  //   flags          1   bit 0 withdrawal, bit 1 deposit
  //   publics        56 x 4, LE lanes
  //   proof length   4, LE; must be the codec's fixed length
  //   proof          ProofCodec bytes
  //   bundle length  4, LE; at most [maxBundle]
  //   bundle
  //   withdrawal     28, when flagged
  //   deposit        36, when flagged

  static ProofShape? _shape;
  static ProofCodec codec(StarkParams spendP) =>
      ProofCodec(spendP, _shape ??= ProofShape.of(PoolSpendAir.air(PoolPublicInputs.zero())), hash: const Poseidon2ProofHash());

  Uint8List encode(StarkParams spendP) {
    final proofBytes = codec(spendP).encode(proof);
    final out = BytesBuilder(copy: false)
      ..addByte(formatVersion)
      ..addByte((withdrawal != null ? _flagWithdrawal : 0) | (depositOutpoint != null ? _flagDeposit : 0))
      ..add(SlotScript.lanesBytes(publics.toLanes()))
      ..add(_u32(proofBytes.length))
      ..add(proofBytes)
      ..add(_u32(bundle.length))
      ..add(bundle);
    if (withdrawal != null) out.add(withdrawal!.encodeRecord());
    if (depositOutpoint != null) out.add(depositOutpoint!);
    return out.toBytes();
  }

  /// The transfer [bytes] encode, at [spendP]. The bytes are hostile: the
  /// total is checked before anything is read, and every length against the
  /// bytes left and its field's own bound before anything is allocated for
  /// it. Throws [TransferRefusal] naming the field, and nothing else.
  static ShieldedTransfer decode(List<int> bytes, StarkParams spendP) {
    if (bytes.length > maxEncoded) throw TransferRefusal('size', '${bytes.length} bytes, at most $maxEncoded');
    var field = 'version';
    try {
      final r = _Reader(bytes);
      final version = r.byte(field);
      if (version != formatVersion) throw TransferRefusal(field, 'unknown version $version');
      field = 'flags';
      final flags = r.byte(field);
      if (flags & ~(_flagWithdrawal | _flagDeposit) != 0) throw TransferRefusal(field, 'unknown flags 0x${flags.toRadixString(16)}');
      field = 'publics';
      final lanes = [for (int i = 0; i < PoolPublicInputs.count; i++) r.u32(field)];
      final PoolPublicInputs publics;
      try {
        publics = PoolPublicInputs.fromLanes(lanes);
      } on ArgumentError catch (e) {
        throw TransferRefusal(field, '${e.message}');
      }
      field = 'proof';
      final c = codec(spendP);
      final proofLength = r.u32(field);
      if (proofLength != c.bytes) throw TransferRefusal(field, 'declares $proofLength bytes, the spend parameters fix ${c.bytes}');
      final StarkProof proof;
      try {
        proof = c.decode(Uint8List.fromList(r.take(field, proofLength)));
      } on ProofCodecException catch (e) {
        throw TransferRefusal(field, e.what);
      }
      field = 'bundle';
      final bundleLength = r.u32(field);
      if (bundleLength > maxBundle) throw TransferRefusal(field, 'declares $bundleLength bytes, at most $maxBundle');
      final bundle = r.take(field, bundleLength);
      field = 'withdrawal';
      PoolWithdrawal? withdrawal;
      if (flags & _flagWithdrawal != 0) {
        final rec = r.take(field, PoolWithdrawal.recordSize);
        final value = ByteData.sublistView(Uint8List.fromList(rec), 20).getUint64(0, Endian.little);
        if (value < 0) throw TransferRefusal(field, 'the value is out of range');
        withdrawal = PoolWithdrawal(rec.sublist(0, 20), BigInt.from(value));
      }
      field = 'deposit';
      final deposit = flags & _flagDeposit != 0 ? r.take(field, outpointSize) : null;
      field = 'end';
      if (!r.done) throw TransferRefusal(field, '${r.left} bytes after the last field');
      return ShieldedTransfer(publics, proof, bundle, withdrawal: withdrawal, depositOutpoint: deposit);
    } on TransferRefusal {
      rethrow;
    } catch (e) {
      // anything the checks above did not foresee is still a refusal of the
      // field being read, never a crash of the caller
      throw TransferRefusal(field, 'malformed ($e)');
    }
  }

  static Uint8List _u32(int v) => Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.little);

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class _Reader {
  final List<int> b;
  int at = 0;
  _Reader(this.b);
  bool get done => at == b.length;
  int get left => b.length - at;

  List<int> take(String field, int n) {
    if (n < 0 || n > left) throw TransferRefusal(field, 'needs $n bytes, $left remain');
    final out = b.sublist(at, at + n);
    at += n;
    return out;
  }

  int byte(String field) => take(field, 1)[0];

  int u32(String field) {
    final x = take(field, 4);
    return x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
  }
}
