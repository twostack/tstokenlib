import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// A single entry in a Merkle inclusion proof.
class MerkleProofEntry {
  /// The 32-byte SHA256 hash of the sibling node.
  final Uint8List sibling;

  /// True if the sibling is on the left side (i.e. the proven node is on the right).
  final bool isLeft;

  MerkleProofEntry({required this.sibling, required this.isLeft});
}

/// Constructs a binary Merkle tree from a list of 20-byte pubkey hashes and
/// provides root computation and inclusion proof generation.
///
/// Used by the PP1_RFT (Restricted Fungible Token) whitelist system.
///
/// Tree structure:
/// - Each leaf is `SHA256(pubkeyHash)`.
/// - Each internal node is `SHA256(left || right)`.
/// - If a level has an odd number of nodes, the last node is duplicated.
/// - Maximum depth: 16 levels (supports up to 65,536 entries).
class MerkleTree {
  static const int maxDepth = 16;
  static const int maxLeaves = 1 << maxDepth; // 65536

  /// All tree levels. Index 0 is the leaf level, last element is the root level.
  final List<List<Uint8List>> _levels;

  /// Constructs the Merkle tree from a list of 20-byte pubkey hashes.
  ///
  /// Throws [ArgumentError] if the list is empty, contains incorrectly sized
  /// entries, or exceeds the maximum number of leaves (65,536).
  MerkleTree(List<List<int>> pubkeyHashes) : _levels = [] {
    if (pubkeyHashes.isEmpty) {
      throw ArgumentError('Cannot build a Merkle tree from an empty list');
    }
    if (pubkeyHashes.length > maxLeaves) {
      throw ArgumentError(
          'Too many leaves: ${pubkeyHashes.length} exceeds maximum of $maxLeaves');
    }
    for (var i = 0; i < pubkeyHashes.length; i++) {
      if (pubkeyHashes[i].length != 20) {
        throw ArgumentError(
            'Pubkey hash at index $i has length ${pubkeyHashes[i].length}, expected 20');
      }
    }

    // Build leaf level: SHA256(pubkeyHash) for each entry.
    final leaves = pubkeyHashes
        .map((pkh) => Uint8List.fromList(sha256.convert(pkh).bytes))
        .toList();
    _levels.add(leaves);

    // Build successive levels until we reach a single root node.
    var current = leaves;
    while (current.length > 1) {
      final next = <Uint8List>[];
      // If odd, duplicate the last node.
      if (current.length.isOdd) {
        current = List<Uint8List>.from(current)..add(current.last);
      }
      for (var i = 0; i < current.length; i += 2) {
        final combined = Uint8List(64)
          ..setRange(0, 32, current[i])
          ..setRange(32, 64, current[i + 1]);
        next.add(Uint8List.fromList(sha256.convert(combined).bytes));
      }
      _levels.add(next);
      current = next;
    }
  }

  /// The 32-byte Merkle root hash.
  Uint8List get root => Uint8List.fromList(_levels.last.first);

  /// The number of leaves in the tree.
  int get leafCount => _levels.first.length;

  /// The depth of the tree (number of levels excluding the root level).
  int get depth => _levels.length - 1;

  /// Generates an inclusion proof for the leaf at [leafIndex].
  ///
  /// Returns a list of [MerkleProofEntry] objects from the leaf level up to
  /// (but not including) the root level.
  ///
  /// Throws [RangeError] if [leafIndex] is out of bounds.
  List<MerkleProofEntry> getProof(int leafIndex) {
    if (leafIndex < 0 || leafIndex >= _levels.first.length) {
      throw RangeError('leafIndex $leafIndex is out of range '
          '[0, ${_levels.first.length})');
    }

    final proof = <MerkleProofEntry>[];
    var idx = leafIndex;

    for (var level = 0; level < _levels.length - 1; level++) {
      var levelNodes = _levels[level];
      // If odd number of nodes, conceptually duplicate the last.
      if (levelNodes.length.isOdd) {
        levelNodes = List<Uint8List>.from(levelNodes)..add(levelNodes.last);
      }

      final siblingIdx = idx.isEven ? idx + 1 : idx - 1;
      final siblingIsLeft = idx.isOdd; // sibling is on the left if we are odd

      proof.add(MerkleProofEntry(
        sibling: Uint8List.fromList(levelNodes[siblingIdx]),
        isLeft: siblingIsLeft,
      ));

      // Move to the parent index.
      idx = idx ~/ 2;
    }

    return proof;
  }

  /// Verifies a Merkle inclusion proof.
  ///
  /// [leaf] is the raw 20-byte pubkey hash (not yet hashed).
  /// [proof] is the list of [MerkleProofEntry] from [getProof].
  /// [expectedRoot] is the expected 32-byte Merkle root.
  ///
  /// Returns true if the proof is valid.
  static bool verifyProof(
      List<int> leaf, List<MerkleProofEntry> proof, List<int> expectedRoot) {
    if (leaf.length != 20) {
      throw ArgumentError('Leaf must be 20 bytes (pubkey hash)');
    }
    if (expectedRoot.length != 32) {
      throw ArgumentError('Root must be 32 bytes');
    }

    // Start with SHA256 of the leaf data.
    var current = Uint8List.fromList(sha256.convert(leaf).bytes);

    for (final entry in proof) {
      final combined = Uint8List(64);
      if (entry.isLeft) {
        // Sibling is on the left.
        combined.setRange(0, 32, entry.sibling);
        combined.setRange(32, 64, current);
      } else {
        // Sibling is on the right.
        combined.setRange(0, 32, current);
        combined.setRange(32, 64, entry.sibling);
      }
      current = Uint8List.fromList(sha256.convert(combined).bytes);
    }

    // Compare computed root with expected root.
    if (current.length != expectedRoot.length) return false;
    for (var i = 0; i < current.length; i++) {
      if (current[i] != expectedRoot[i]) return false;
    }
    return true;
  }
}
