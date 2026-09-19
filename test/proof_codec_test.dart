import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/proof_codec.dart';
import 'package:tstokenlib/src/crypto/stark_prover.dart';
import 'package:tstokenlib/src/crypto/stark_prover_ref.dart';
import 'package:tstokenlib/src/crypto/stark_verifier_ref.dart';
import 'package:tstokenlib/src/recursion/verifier_program.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

/// The proof codec: a spend proof (SHA256 and Poseidon2 flavours) and a
/// verifier proof (Poseidon2) encoded, decoded and verified again, and
/// decoding refusing anything that is not exactly one encoding.
void main() {
  final rng = Random(41);
  int r31() => rng.nextInt(M31.p);
  List<int> lanes(int n) => List.generate(n, (_) => r31());
  const p2 = Poseidon2ProofHash();
  const sha = Sha256ProofHash();
  const spendP = StarkParams(
      logTrace: PoolSpendAir.logTrace, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1, zkRandomizers: 16);
  const levelP = StarkParams(logTrace: 16, logBlowup: 2, logExpand: 3, logFinal: 3, numQueries: 2, grindBytes: 1);

  /// One spend, proved with [hash].
  (PoolPublicInputs, StarkProof) spend(ProofHash hash) {
    final da = SpendNote.dummy(sk: lanes(5), rho: lanes(3)), db = SpendNote.dummy(sk: lanes(5), rho: lanes(3));
    final oa = OutputNote(pkd: lanes(8), value: 900, rho: lanes(3), rcm: lanes(4));
    final ob = OutputNote(pkd: lanes(8), value: 17, rho: lanes(3), rcm: lanes(4));
    final w = PoolSpendAir.witness(da, db, oa, ob, -917, anchor: lanes(8), outHash: PoolPublicInputs.outHashLanes(Uint8List(0)));
    return (w.publics, StarkProver.prove(spendP, PoolSpendAir.air(w.publics), w.rows, rng: rng, hash: hash));
  }

  /// A proof and the codec and verifier that belong to it.
  void roundTrips(String what, StarkParams params, air, StarkProof pf, ProofHash hash) {
    final codec = ProofCodec.forAir(params, air, hash: hash);
    final bytes = codec.encode(pf);
    expect(bytes.length, codec.bytes, reason: '$what: encoding length');
    print('  $what: ${bytes.length} B');
    final back = codec.decode(bytes);
    expect(StarkVerifierRef(params, air, hash: hash).verify(back), isTrue, reason: what);
    // the encoding is canonical: re-encoding the decoded proof is the same bytes
    expect(codec.encode(back), bytes, reason: '$what: re-encoding');
  }

  test('a spend proof round-trips in both flavours', () {
    for (final hash in [sha, p2]) {
      final (publics, pf) = spend(hash);
      roundTrips('spend (${hash.name})', spendP, PoolSpendAir.air(publics), pf, hash);
    }
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('a Poseidon2 verifier proof round-trips', () {
    final (publics, pf) = spend(p2);
    final shape = InnerShape(spendP, PoolSpendAir.air(publics));
    final prog = VerifierProgram.compile(shape, levelP.logTrace);
    final air = prog.air(VerifierProgram.nodeDigestOf(shape.air, const []));
    final node = StarkProver.prove(levelP, air, prog.witness(pf), rng: rng, hash: p2);
    roundTrips('level node (poseidon2)', levelP, air, node, p2);
  }, timeout: const Timeout(Duration(minutes: 20)));

  test('decoding rejects truncated and oversized encodings', () {
    final (publics, pf) = spend(p2);
    final air = PoolSpendAir.air(publics);
    final codec = ProofCodec.forAir(spendP, air, hash: p2);
    final bytes = codec.encode(pf);
    expect(() => codec.decode(Uint8List.sublistView(bytes, 0, bytes.length - 1)), throwsA(isA<ProofCodecException>()));
    expect(() => codec.decode(Uint8List.sublistView(bytes, 0, bytes.length ~/ 2)), throwsA(isA<ProofCodecException>()));
    expect(() => codec.decode(Uint8List(0)), throwsA(isA<ProofCodecException>()));
    expect(() => codec.decode(Uint8List.fromList([...bytes, 0])), throwsA(isA<ProofCodecException>()));
    // the right length but a lane outside the field: the trace root's first lane
    final bad = Uint8List.fromList(bytes);
    ByteData.sublistView(bad).setUint32(0, M31.p, Endian.little);
    expect(() => codec.decode(bad), throwsA(isA<ProofCodecException>()));
    // a shape that is not the proof's is refused rather than silently misread
    expect(() => ProofCodec(spendP, const ProofShape(numCols: 3), hash: p2).decode(bytes), throwsA(isA<ProofCodecException>()));
  }, timeout: const Timeout(Duration(minutes: 10)));
}
