import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tstokenlib/src/crypto/m31.dart';
import 'package:tstokenlib/src/crypto/note_commitment_tree.dart';
import 'package:tstokenlib/src/crypto/nullifier_tree.dart';
import 'package:tstokenlib/src/crypto/poseidon2_batch.dart';
import 'package:tstokenlib/src/crypto/stark_kernels.dart';
import 'package:tstokenlib/src/script_gen/pool_spend_air.dart';

void main() {
  final rng = Random(12);
  List<int> lane8() => List.generate(8, (_) => rng.nextInt(M31.p));

  tearDown(() => Poseidon2Batch.preferNative = true);

  test('the native batch compresses byte for byte as the Dart permutation and PoolHash.node', () {
    expect(StarkKernels.tryLoad(), isNotNull, reason: 'build native/stark_kernels to compare');
    for (final n in [0, 1, 15, 16, 53]) {
      final pairs = Uint32List.fromList(List.generate(16 * n, (_) => rng.nextInt(M31.p)));
      final native = Poseidon2Batch.compress(pairs);
      Poseidon2Batch.preferNative = false;
      final dart = Poseidon2Batch.compress(pairs);
      Poseidon2Batch.preferNative = true;
      expect(native, dart, reason: '$n pairs');
      for (int i = 0; i < n; i++) {
        expect(native.sublist(8 * i, 8 * i + 8), PoolHash.node(pairs.sublist(16 * i, 16 * i + 8), pairs.sublist(16 * i + 8, 16 * i + 16)));
      }
    }
  });

  for (final native in [true, false]) {
    group(native ? 'built natively' : 'built in Dart', () {
      setUp(() => Poseidon2Batch.preferNative = native);

      test('a commitment tree built from its leaves is the one appending them builds', () {
        for (final n in [0, 1, 2, 5, 32, 77]) {
          final leaves = [for (int i = 0; i < n; i++) lane8()];
          final a = NoteCommitmentTree();
          for (final l in leaves) {
            a.append(l);
          }
          final b = NoteCommitmentTree.fromLeaves(leaves);
          expect(b.size, n);
          expect(b.root, a.root, reason: '$n leaves');
          expect(b.frontier.root, a.frontier.root);
          for (int i = 0; i < n; i += 7) {
            expect(b.path(i).siblings, a.path(i).siblings);
          }
          // and they keep agreeing
          final more = [for (int i = 0; i < 40; i++) lane8()];
          if (n % 32 == 0) {
            a.appendSubtree(more.sublist(0, 32));
            b.appendSubtree(more.sublist(0, 32));
          } else {
            for (final l in more) {
              a.append(l);
              b.append(l);
            }
          }
          expect(b.root, a.root);
          expect(b.frontier.root, b.root);
        }
      });

      test('a nullifier tree built from its keys is the one inserting them builds', () {
        for (final n in [0, 1, 2, 9, 100]) {
          final nfs = [for (int i = 0; i < n; i++) lane8()];
          // two neighbours in one slot pair, to take the both-children path
          if (n >= 2) nfs[1] = [nfs[0][0] ^ 1, nfs[0][1], ...lane8().sublist(2)];
          final a = NullifierTree();
          for (final x in nfs) {
            a.insert(x);
          }
          final b = NullifierTree.fromNullifiers(nfs);
          expect(b.root, a.root, reason: '$n nullifiers');
          expect(b.size, n);
          for (final x in nfs) {
            expect(b.occupied(x), isTrue);
            expect(b.path(x), a.path(x));
          }
          final x = lane8();
          a.insert(x);
          b.insert(x);
          expect(b.root, a.root);
        }
      });

      test('a repeated nullifier is refused', () {
        final x = lane8();
        expect(() => NullifierTree.fromNullifiers([lane8(), x, lane8(), x]), throwsStateError);
      });
    });
  }
}
