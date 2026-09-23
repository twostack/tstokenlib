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

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

import '../builder/pp1_sp_unlock_builder.dart';
import '../crypto/m31.dart';
import '../crypto/note_commitment_tree.dart';
import '../crypto/nullifier_tree.dart';
import '../recursion/pool_aggregator.dart';
import '../recursion/verifier_program.dart';
import '../script_gen/pool_spend_air.dart';
import '../script_gen/pool_verifier_gen.dart';
import '../script_gen/pp1_sp_script_gen.dart';
import '../script_gen/slot_script_common.dart';
import 'pool_evidence.dart';
import 'pool_header.dart';
import 'pool_out_hash.dart';
import 'pool_outputs.dart';
import 'script_pushes.dart';
import 'shielded_transfer.dart';

/// Why a round (or a snapshot) was not applied: what was checked, and what
/// was wrong. Every way the ledger refuses input ends in one of these and
/// leaves the ledger as it was.
class LedgerRefusal implements Exception {
  final String check;
  final String reason;
  const LedgerRefusal(this.check, this.reason);
  @override
  String toString() => 'round refused ($check): $reason';
}

/// The shape of a TSL1_SP pool's rounds as a reader needs it: how many
/// transfers a round carries, where each sits in the root proof's
/// statement, and where their commitments land in the tree.
///
/// A reader places leaves by calling the aggregation's own
/// [AggregationTree.subtreeLeavesOf], so it cannot drift from the builder
/// when the tree's shape changes. The placement and the statement layout
/// depend only on the arities, the ring, the nullifier level and the
/// receipt slots; the level programs and their preprocessed roots, which
/// take gigabytes to commit at production size, play no part. So the tree
/// is built here from those numbers alone, and [PoolStatement.of] checks
/// that its layout is the one V reads.
class ShieldedPoolLayout {
  final AggregationTree tree;
  final PoolStatement statement;
  ShieldedPoolLayout._(this.tree) : statement = PoolStatement.of(tree);

  /// The layout of an aggregation that is already built.
  factory ShieldedPoolLayout.of(AggregationTree tree) => ShieldedPoolLayout._(tree);

  /// The layout of a pool whose aggregation levels fold [arities] proofs
  /// each, with the nullifier walks at [nullifierLevel] and [receiptSlots]
  /// deposit receipts a round.
  factory ShieldedPoolLayout.forArities(List<int> arities, {required int nullifierLevel, required int receiptSlots}) {
    final shape = InnerShape(PoolAggregation.spendThroughputParams, PoolSpendAir.air(PoolPublicInputs.zero()));
    return ShieldedPoolLayout._(AggregationTree(
        PoolPublicInputs.count, const [], [for (final _ in arities) (shape, List.filled(8, 0))], arities,
        ring: PoolAggregation.anchorRing, nullifierLevel: nullifierLevel, receiptSlots: receiptSlots));
  }

  /// The production pool: 256 transfers (16 x 4 x 2 x 2), nullifiers at
  /// level 2, eight receipt slots.
  static final production = ShieldedPoolLayout.forArities(
      [for (final l in PoolAggregation.throughputLevels) l.arity],
      nullifierLevel: 1,
      receiptSlots: PoolReceipt.maxPerRound);

  int get transfers => tree.transfers;

  /// Leaves a round appends: a fixed power of two for the pool's life
  /// (512 at production parameters, 32 at test), asserted where the plan
  /// is built.
  int get leavesPerRound => tree.leavesAppended;

  /// log2 of [leavesPerRound]: the tree level whose nodes are whole
  /// rounds. Round N owns the node at this level, index N - 1, and that
  /// node is its block root.
  int get blockLevel => leavesPerRound.bitLength - 1;

  /// The statement V's unlock begins with: [PoolStatement.numPublics]
  /// pushes, each a minimal script number below p. Returns the lanes.
  /// Refuses an unlock that does not begin with them; V reads the same
  /// layout, so an unlock V accepted always parses.
  List<int> readStatement(List<int> unlock) {
    final n = statement.numPublics;
    final List<List<int>> pushes;
    try {
      pushes = ScriptPushes.read(unlock, max: n);
    } on FormatException catch (e) {
      throw LedgerRefusal('statement', 'V\'s unlock does not begin with the statement (${e.message})');
    }
    if (pushes.length != n) throw LedgerRefusal('statement', 'V\'s unlock has ${pushes.length} pushes, the statement is $n');
    try {
      return [for (final p in pushes) ScriptPushes.number(p, bound: M31.p)];
    } on FormatException catch (e) {
      throw LedgerRefusal('statement', 'a statement lane is not a lane (${e.message})');
    }
  }

  /// Transfer [t]'s pinned lanes in [statement] (in the order of
  /// [PoolPublicInputs.toReducedLanes]).
  List<int> transferLanes(List<int> statementLanes, int t) {
    final w = 8 * PoolStatement.pinnedChunks;
    return statementLanes.sublist(w * t, w * (t + 1));
  }

  /// The used receipt slots of [statementLanes]: each one's commitment and
  /// the amount it brings in.
  List<PoolReceipt> receiptSlots(List<int> statementLanes) {
    final out = <PoolReceipt>[];
    for (int r = 0; r < statement.receiptSlots; r++) {
      final at = statement.receiptOffset + 16 * r;
      final cm = statementLanes.sublist(at, at + 8), meta = statementLanes.sublist(at + 8, at + 16);
      if (meta[ReceiptSlot.usedLane] == 0) continue;
      final lanes = List.filled(PoolPublicInputs.count, 0)
        ..[PoolPublicInputs.idxPubLo] = meta[ReceiptSlot.loLane]
        ..[PoolPublicInputs.idxPubHi] = meta[ReceiptSlot.hiLane];
      final amount = PoolPublicInputs.fromLanes(lanes).publicOut;
      out.add(PoolReceipt(SlotScript.lanesBytes(cm), BigInt.from(-amount)));
    }
    return out;
  }
}

/// What applying one round found, as a wallet or a coordinator reports
/// it. Only [ShieldedLedger] makes these, and only for rounds it applied,
/// so a scanner given one decrypts bundles whose hashes already chain to
/// the header's outHash.
class ShieldedRound {
  /// The round's number: 1 for the first round after the issuance.
  final int number;
  final PoolHeader header;

  /// Every transfer's lanes as the ledger rebuilt them: the statement's,
  /// with the commitments from the bundles and a zero anchor, which the
  /// round does not publish.
  final List<PoolPublicInputs> transfers;

  /// Each transfer's bundle as the witness carried it.
  final List<Uint8List> bundles;

  /// The leaf positions of each transfer's two outputs.
  final List<(int, int)> positions;

  /// The nullifiers the round inserted, in transfer order.
  final List<List<int>> nullifiers;
  final List<PoolWithdrawal> withdrawals;
  final List<PoolReceipt> receipts;

  /// The round's block root: the tree node at the block level, index
  /// `number - 1`, in 32 bytes. This is the whole of what a party needs a
  /// round to publish in order to keep its own paths current, whatever the
  /// round's size (see [BlockFold]).
  final List<int> blockRoot;

  ShieldedRound._(this.number, this.header, this.transfers, this.bundles, this.positions, this.nullifiers, this.withdrawals,
      this.receipts, this.blockRoot);

  List<bool> get padding => [for (final t in transfers) t.isPadding];
}

/// The TSL1_SP pool's state as a coordinator or a wallet holds it: the
/// current header, the note commitment tree, the nullifier tree, and the
/// tip the next round must spend (Y_N, round N and witness N).
///
/// Its only inputs are mined transactions. It applies a round only when
/// what the round carries rebuilds exactly the header the round states,
/// so a wallet trusts nothing a coordinator says about the pool's state:
/// it can check any claim against a ledger it built itself. It does not
/// verify spend proofs. A mined round was verified by V; the ledger checks
/// that the round is consistent and is this pool's next one.
class ShieldedLedger {
  final ShieldedPoolLayout layout;
  PoolHeader _header;
  NoteCommitmentTree _tree;
  NullifierTree _nullifiers;
  List<List<int>> _spent; // nullifiers in insertion order, for snapshots
  Transaction _y, _round, _witness;
  int _number;
  String? _yId, _roundId, _witnessId;

  ShieldedLedger._(this.layout, this._header, this._tree, this._nullifiers, this._spent, this._y, this._round, this._witness,
      this._number);

  PoolHeader get header => _header;
  NoteCommitmentTree get tree => _tree;

  /// The block root of the round the ledger stands at: the node at the
  /// layout's block level, index `round - 1`, as [SlotScript.lanesBytes]
  /// writes it. Refuses at the genesis, which appended no block.
  List<int> get blockRoot {
    if (_number == 0) throw StateError('the genesis appends no leaves, so there is no block root before round 1');
    return SlotScript.lanesBytes(_tree.nodeAt(layout.blockLevel, _number - 1));
  }
  NullifierTree get nullifiers => _nullifiers;
  int get size => _tree.size;

  /// The block root of round [n], for any round the ledger has applied.
  List<int> blockRootOf(int n) {
    if (n < 1 || n > _number) throw RangeError.range(n, 1, _number, 'round');
    return SlotScript.lanesBytes(_tree.nodeAt(layout.blockLevel, n - 1));
  }

  /// What a new follower is given to join the pool where the ledger stands:
  /// the round, that round's block root, and the complete left subtrees
  /// above the block level, in level order (at most 23 nodes at production
  /// parameters, 736 bytes, whatever the pool's age).
  ///
  /// A follower built from this folds every later round exactly as one that
  /// had folded every round since the genesis. It is not trusted: the
  /// follower's root after restoring must be the `cmRoot` of a round the
  /// wallet has proved off the chain.
  ({int round, List<int> blockRoot, List<List<int>> left}) frontier() {
    if (_number == 0) throw StateError('the genesis appends no leaves, so there is no frontier before round 1');
    final m = _number - 1;
    final level = layout.blockLevel;
    return (
      round: _number,
      blockRoot: blockRoot,
      left: [
        for (int l = 0; l < NoteCommitmentTree.depth - level; l++)
          if ((m >> l) & 1 == 1) SlotScript.lanesBytes(_tree.nodeAt(level + l, (m >> l) ^ 1))
      ],
    );
  }

  /// Rounds applied since the issuance.
  int get round => _number;
  Transaction get tipSlot => _y;
  Transaction get tipRound => _round;
  Transaction get tipWitness => _witness;

  String get _tipYId => _yId ??= _y.id;
  String get _tipRoundId => _roundId ??= _round.id;
  String get _tipWitnessId => _witnessId ??= _witness.id;

  /// A ledger opened from a pool's [issuance], its [witness] (witness 0)
  /// and [slot] Y_0: the genesis header, empty trees, and that tip.
  ///
  /// [tokenId] and [genesisHeader] say **which pool** the triple is supposed
  /// to be, and come from the descriptor, out of band. They are required
  /// because without them opening checks only that the three transactions
  /// point at each other, which anyone can arrange for a pool of their own:
  /// a forger builds an issuance, a witness and a slot, mines them for the
  /// price of three transactions, and every round applied on top inherits the
  /// mistake. Only the caller knows which pool it meant.
  static ShieldedLedger open(ShieldedPoolLayout layout, Transaction issuance, Transaction witness, Transaction slot,
      {required List<int> tokenId, required List<int> genesisHeader}) {
    final empty = NoteCommitmentTree(), none = NullifierTree();
    final header = _guard('genesis', () {
      final fields = _pp1(issuance);
      final h = fields.header;
      _need(_eq(fields.tokenId, tokenId), 'genesis',
          'the issuance carries tokenId ${hex.encode(fields.tokenId)}, this pool is ${hex.encode(tokenId)}');
      _need(_eq(fields.genesisHeader, genesisHeader), 'genesis',
          'the issuance opened on a different state from the one this pool published');
      final slotId = slot.id, issuanceId = issuance.id;
      _need(_spends(issuance, 1, slotId, 1), 'genesis', 'the issuance does not spend Y_0\'s anchor at input 1');
      _need(_names(issuance, slot.hash), 'genesis', 'the issuance\'s PP3 does not name Y_0');
      _need(_spends(witness, 1, issuanceId, 1) && _spends(witness, 2, issuanceId, 2), 'genesis',
          'witness 0 does not spend the issuance\'s PP1 and PP2');
      _need(h.size == 0 && h.balance == BigInt.one, 'genesis', 'the issuance does not carry a genesis header');
      _need(_eq(h.cmRoot, SlotScript.lanesBytes(empty.root)) && _eq(h.nfRoot, SlotScript.lanesBytes(none.root)), 'genesis',
          'the genesis header\'s roots are not the empty trees\'');
      return h;
    });
    return ShieldedLedger._(layout, header, empty, none, [], slot, issuance, witness, 0);
  }

  /// Applies [round] (round N+1), its [witness] and the slot [nextSlot]
  /// (Y_{N+1}) that the round's PP3 pins, or refuses them. Everything is
  /// worked out on copies, and the ledger takes them only if every check
  /// holds, so a refused round leaves it exactly as it was.
  ShieldedRound apply(Transaction round, Transaction witness, Transaction nextSlot) =>
      _guard('malformed', () => _apply(round, witness, nextSlot));

  /// [apply] from raw transactions, as a wallet fetches them.
  ShieldedRound applyBytes(List<int> round, List<int> witness, List<int> nextSlot) =>
      apply(parse(round), parse(witness), parse(nextSlot));

  /// The transaction [bytes] hold, or a refusal.
  static Transaction parse(List<int> bytes) => _guard('malformed', () => Transaction.fromHex(hex.encode(bytes)));

  ShieldedRound _apply(Transaction round, Transaction witness, Transaction nextSlot) {
    final L = layout, stmt = L.statement, n = L.transfers;
    // dartsv rehashes a transaction on every id, and a witness is megabytes
    final roundId = round.id;

    // it extends this tip
    _need(round.inputs.length > 4 && round.outputs.length >= 5, 'tip', 'a round has at least five inputs and five outputs');
    _need(_spends(round, 3, _tipRoundId, 3), 'tip',
        'the round spends a PP3 other than the tip\'s, so it belongs to another chain or another point in this one');
    _need(_spends(round, 2, _tipYId, 0), 'tip', 'the round does not spend the tip\'s Y at input 2');
    _need(_spends(round, 1, _tipWitnessId, 0), 'tip', 'the round does not spend witness $_number\'s output 0 at input 1');
    _need(witness.inputs.length >= 3 && _spends(witness, 1, roundId, 1) && _spends(witness, 2, roundId, 2), 'tip',
        'the witness does not spend the round\'s PP1 and PP2');
    final nextHash = nextSlot.hash, nextSlotId = hex.encode(nextHash.reversed.toList());
    _need(_names(round, nextHash), 'tip', 'the round\'s PP3 does not name the slot given as Y_${_number + 1}');
    _need(_spends(round, 4, nextSlotId, 1), 'tip', 'the round does not spend Y_${_number + 1}\'s anchor at input 4');

    // the header the round carries
    final h = _pp1Header(round);

    // the transfers' lanes, from the statement at the bottom of V's unlock
    final lanes = L.readStatement(_unlock(round, 2));
    final reduced = [for (int t = 0; t < n; t++) L.transferLanes(lanes, t)];
    final List<PoolPublicInputs> stated;
    try {
      stated = [for (final r in reduced) PoolPublicInputs.fromReducedLanes(r)];
    } on ArgumentError catch (e) {
      throw LedgerRefusal('statement', 'a transfer\'s lanes do not decode (${e.message})');
    }

    // the round's output tail: receipts, then withdrawals
    final receipts = <PoolReceipt>[], withdrawals = <PoolWithdrawal>[];
    for (int k = 5; k < round.outputs.length; k++) {
      final o = round.outputs[k], s = o.script.buffer;
      if (s.length == 44 && s[0] == 0x00 && s[1] == 0x6a && s[2] == 0x20 && s[35] == 0x08) {
        _need(withdrawals.isEmpty, 'outputs', 'a receipt after a withdrawal');
        _need(o.satoshis == BigInt.zero, 'outputs', 'a receipt holding money');
        final v = ByteData.sublistView(Uint8List.fromList(s), 36).getUint64(0, Endian.little);
        _need(v >= 0, 'outputs', 'a receipt value out of range');
        receipts.add(PoolReceipt(s.sublist(3, 35), BigInt.from(v)));
      } else if (s.length == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) {
        withdrawals.add(PoolWithdrawal(s.sublist(3, 23), o.satoshis));
      } else {
        throw LedgerRefusal('outputs', 'output $k is neither a receipt nor a withdrawal');
      }
    }

    // the bundles the witness carries, against outHash
    final List<Uint8List> bundles;
    try {
      final pushes = PP1SpUnlockBuilder.readRound(_unlock(witness, 1));
      bundles = [for (final b in PoolOutHash.decodeBundles(pushes['bundles']!)) Uint8List.fromList(b)];
    } on FormatException catch (e) {
      throw LedgerRefusal('bundles', 'the witness\'s bundles do not parse (${e.message})');
    }
    _need(bundles.length == n, 'bundles', 'the witness carries ${bundles.length} bundles for $n transfers');
    final bundleHashes = [for (final b in bundles) PoolOutHash.bundleHash(b)];
    final why = PoolOutHash.check(
        transfers: [for (final p in stated) p.toLanes()],
        withdrawals: withdrawals,
        bundleHashes: bundleHashes,
        headerOutHash: h.outHash);
    if (why != null) throw LedgerRefusal('outHash', why);

    // the commitments, from the bundles or the padding note
    final full = <PoolPublicInputs>[];
    for (int t = 0; t < n; t++) {
      final List<List<int>> cms;
      if (bundles[t].isEmpty) {
        _need(stated[t].isPadding, 'commitments', 'transfer $t is not padding and its bundle is empty, so its commitments are unknown');
        cms = [ShieldedTransfer.paddingCm, ShieldedTransfer.paddingCm];
      } else {
        try {
          cms = [for (final b in ShieldedTransfer.parseBundle(bundles[t])) b.cm];
        } on TransferRefusal catch (e) {
          throw LedgerRefusal('commitments', 'transfer $t\'s bundle ${e.reason}');
        }
      }
      if (cms.any((c) => c.any((l) => l >= M31.p))) throw LedgerRefusal('commitments', 'transfer $t names a commitment outside the field');
      full.add(PoolPublicInputs.fromReducedLanes(reduced[t], cm1: cms[0], cm2: cms[1]));
    }
    final tree = _tree.copy();
    final before = tree.size;
    final fullLanes = [for (final p in full) p.toLanes()];
    for (int s = 0; s < L.tree.subtrees; s++) {
      tree.appendSubtree([for (final l in L.tree.subtreeLeavesOf(fullLanes, s)) l ?? MerkleFrontier.emptyLeaf]);
    }

    // the nullifiers
    final nf = _nullifiers.copy();
    final inserted = <List<int>>[];
    for (int t = 0; t < n; t++) {
      for (final (real, x) in [(full[t].real1, full[t].nf1), (full[t].real2, full[t].nf2)]) {
        if (!real) continue;
        _need(!nf.occupied(x), 'nullifiers', 'transfer $t spends a note already spent');
        nf.insert(x);
        inserted.add(x);
      }
    }

    // the new header is what they rebuild
    _need(_eq(SlotScript.lanesBytes(tree.root), h.cmRoot), 'roots', 'the commitments do not reach the header\'s commitment root');
    _need(_eq(SlotScript.lanesBytes(nf.root), h.nfRoot), 'roots', 'the nullifiers do not reach the header\'s nullifier root');
    _need(h.size == _header.size + stmt.leavesAppended && h.size == tree.size, 'header',
        'the size is ${h.size}, the tree holds ${tree.size}');
    final ring = [h.cmRoot, ..._header.ring.sublist(0, PoolHeader.ringEntries - 1)];
    for (int i = 0; i < PoolHeader.ringEntries; i++) {
      _need(_eq(h.ring[i], ring[i]), 'header', 'the ring is not the old one rotated with the new root first');
    }
    final moved = full.fold(BigInt.zero, (a, p) => a + BigInt.from(p.publicOut));
    _need(h.balance == _header.balance - moved, 'header', 'the balance is ${h.balance}, the transfers leave ${_header.balance - moved}');

    // the receipts are the deposits the root proved
    final slots = L.receiptSlots(lanes);
    _need(slots.length == receipts.length, 'receipts', 'the round carries ${receipts.length} receipts, the statement ${slots.length}');
    for (int r = 0; r < slots.length; r++) {
      _need(_eq(slots[r].commitment, receipts[r].commitment) && slots[r].satoshis == receipts[r].satoshis, 'receipts',
          'receipt $r is not the deposit the root proved');
      final backs = full.any((p) =>
          ReceiptSlot.refusal(p.toLanes()) == null &&
          _eq(SlotScript.lanesBytes(p.cmOut1), receipts[r].commitment) &&
          BigInt.from(-p.publicOut) == receipts[r].satoshis);
      _need(backs, 'receipts', 'receipt $r is not a deposit transfer\'s first commitment and value');
    }

    // leaf positions, read off the placement just made
    final positions = <(int, int)>[];
    final taken = <int>{};
    int find(List<int> cm) {
      for (int k = before; k < tree.size; k++) {
        if (!taken.contains(k) && _eq(tree.nodeAt(0, k), cm)) {
          taken.add(k);
          return k;
        }
      }
      throw StateError('a placed commitment is missing from the tree');
    }

    for (final p in full) {
      positions.add((find(p.cmOut1), find(p.cmOut2)));
    }

    // every check held: take the copies
    _header = h;
    _tree = tree;
    _nullifiers = nf;
    _spent = [..._spent, ...inserted];
    _y = nextSlot;
    _round = round;
    _witness = witness;
    _yId = nextSlotId;
    _roundId = roundId;
    _witnessId = null;
    _number++;
    return ShieldedRound._(_number, h, full, bundles, positions, inserted, withdrawals, receipts, blockRoot);
  }

  // ---- spending from the ledger ----

  /// The Merkle path of leaf [position] against the current commitment root.
  MerklePath path(int position) => _tree.path(position);

  /// How many of the coming rounds accept a spend anchored to [root] (32
  /// bytes): 4 for the current root, 0 for a root that has left the ring.
  /// Round N+1 checks anchors against header N's ring, and each round
  /// rotates one root out.
  int roundsLeftInRing(List<int> root) => roundsLeftIn(_header, root);

  /// [roundsLeftInRing] against [header].
  static int roundsLeftIn(PoolHeader header, List<int> root) {
    for (int i = 0; i < PoolHeader.ringEntries; i++) {
      if (_eq(header.ring[i], root)) return PoolHeader.ringEntries - i;
    }
    return 0;
  }

  // ---- snapshots ----
  //
  //   version      1
  //   header       236
  //   round        4, LE
  //   Y, round, witness of the tip, each as a 4-byte length and its bytes
  //   leaves       4-byte count, then 32 bytes each, in tree order
  //   nullifiers   4-byte count, then 32 bytes each, in insertion order
  //
  // Leaves and nullifiers rather than tree nodes: restoring rebuilds both
  // trees from them and checks the roots against the header, which is also
  // what refuses an edited file. The nullifier tree's nodes would be about
  // 23 million at 1,000 production rounds, some 740 MB. Everything is written in order, so two ledgers that
  // applied the same rounds write the same bytes.

  static const snapshotVersion = 1;

  Uint8List snapshot() {
    final out = BytesBuilder(copy: false)
      ..addByte(snapshotVersion)
      ..add(_header.encode())
      ..add(_u32(_number));
    for (final t in [_y, _round, _witness]) {
      final b = hex.decode(t.serialize());
      out
        ..add(_u32(b.length))
        ..add(b);
    }
    out.add(_u32(_tree.size));
    for (int i = 0; i < _tree.size; i++) {
      out.add(SlotScript.lanesBytes(_tree.nodeAt(0, i)));
    }
    out.add(_u32(_spent.length));
    for (final x in _spent) {
      out.add(SlotScript.lanesBytes(x));
    }
    return out.toBytes();
  }

  /// The ledger [bytes] hold, or a refusal: an unknown version, a
  /// malformed file, or leaves and nullifiers that do not rebuild the
  /// stored header's roots.
  static ShieldedLedger restore(ShieldedPoolLayout layout, List<int> bytes) => _guard('snapshot', () {
        var at = 0;
        List<int> take(int k) {
          if (k < 0 || k > bytes.length - at) throw const LedgerRefusal('snapshot', 'the file is cut short');
          final out = bytes.sublist(at, at + k);
          at += k;
          return out;
        }

        int u32() {
          final x = take(4);
          return x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
        }

        List<int> lanesOf(List<int> b) {
          final l = [for (int i = 0; i < 32; i += 4) b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)];
          if (l.any((x) => x >= M31.p)) throw const LedgerRefusal('snapshot', 'a lane outside the field');
          return l;
        }

        final version = take(1)[0];
        if (version != snapshotVersion) throw LedgerRefusal('snapshot', 'unknown version $version');
        final header = PoolHeader.decode(take(PoolHeader.byteSize));
        final number = u32();
        final txs = [for (int i = 0; i < 3; i++) Transaction.fromHex(hex.encode(take(u32())))];
        final leaves = u32();
        if (leaves != header.size) throw LedgerRefusal('snapshot', '$leaves leaves for a header of size ${header.size}');
        // both trees are rebuilt from the leaves up, a level at a time, so
        // each node is hashed once and in batches (see Poseidon2Batch)
        final tree = NoteCommitmentTree.fromLeaves([for (int i = 0; i < leaves; i++) lanesOf(take(32))]);
        final count = u32();
        final spent = [for (int i = 0; i < count; i++) lanesOf(take(32))];
        final NullifierTree nf;
        try {
          nf = NullifierTree.fromNullifiers(spent);
        } on StateError {
          throw const LedgerRefusal('snapshot', 'a nullifier twice');
        }
        if (at != bytes.length) throw LedgerRefusal('snapshot', '${bytes.length - at} bytes after the last field');
        if (!_eq(SlotScript.lanesBytes(tree.root), header.cmRoot) || !_eq(SlotScript.lanesBytes(nf.root), header.nfRoot)) {
          throw const LedgerRefusal('snapshot', 'the leaves and nullifiers do not rebuild the header\'s roots');
        }
        if (!_eq(_pp1Header(txs[1]).encode(), header.encode())) {
          throw const LedgerRefusal('snapshot', 'the tip round does not carry the stored header');
        }
        return ShieldedLedger._(layout, header, tree, nf, spent, txs[0], txs[1], txs[2], number);
      });

  // ---- helpers ----

  /// Runs [f], turning anything it throws other than a [LedgerRefusal]
  /// into one, so no input reaches the caller as any other failure.
  static T _guard<T>(String check, T Function() f) {
    try {
      return f();
    } on LedgerRefusal {
      rethrow;
    } catch (e) {
      throw LedgerRefusal(check, '$e');
    }
  }

  static void _need(bool ok, String check, String reason) {
    if (!ok) throw LedgerRefusal(check, reason);
  }

  /// The PP1_SP fields of [tx], read through the body check.
  ///
  /// Never by offset. A script carrying a PP1's first
  /// [PP1SpScriptGen.scriptBodyStart] bytes over a body that spends on a
  /// signature parses field for field and enforces nothing; only regenerating
  /// the script and comparing every byte tells the two apart. See
  /// [PoolEvidence.readPP1].
  static PP1Fields _pp1(Transaction tx) {
    _need(tx.outputs.length >= 5, 'header', 'a pool transaction has five outputs or more');
    final (fields, why) = PoolEvidence.readPP1Of(tx, PoolEvidence.pp1Vout);
    if (fields == null) throw LedgerRefusal('header', 'output 1 is not a PP1_SP (${why!.reason})');
    return fields;
  }

  static PoolHeader _pp1Header(Transaction tx) => _pp1(tx).header;

  static bool _spends(Transaction tx, int input, String txid, int vout) =>
      tx.inputs.length > input && tx.inputs[input].prevTxnId == txid && tx.inputs[input].prevTxnOutputIndex == vout;

  /// Whether [tx]'s PP3 pins output 0 of the slot whose hash is [slotHash].
  static bool _names(Transaction tx, List<int> slotHash) {
    final s = tx.outputs[3].script.buffer;
    if (s.length < PP1SpScriptGen.pp3NextSlotEnd) return false;
    final named = s.sublist(PP1SpScriptGen.pp3NextSlotStart, PP1SpScriptGen.pp3NextSlotEnd);
    return _eq(named, [...slotHash, 0, 0, 0, 0]);
  }

  static List<int> _unlock(Transaction tx, int input) => tx.inputs[input].script?.buffer ?? const [];

  static Uint8List _u32(int v) => Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.little);

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
