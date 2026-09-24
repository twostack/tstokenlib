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

import 'pool_protocol.dart';

/// A mined round and where its witness sits in a block: what a head, a
/// round reply and a mined-round notice carry.
class MinedRound {
  final int number;
  final List<int> roundTx, witnessTx;

  /// The block holding the witness, the witness's index in it and its
  /// merkle branch, 32-byte nodes from the leaf up, in the order a block's
  /// merkle tree hashes them.
  final List<int> blockHash;
  final int txIndex;
  final List<List<int>> branch;

  const MinedRound(
      {required this.number,
      required this.roundTx,
      required this.witnessTx,
      required this.blockHash,
      required this.txIndex,
      required this.branch});
}

/// A mined round's txids and where its witness sits: what a mined-round
/// notice carries, which a pool can give without reading the round's
/// transactions.
class RoundPlace {
  final int number;

  /// The round's and the witness's txids, display order.
  final List<int> roundTxId, witnessTxId;
  final List<int> blockHash;
  final int txIndex;
  final List<List<int>> branch;

  const RoundPlace(
      {required this.number,
      required this.roundTxId,
      required this.witnessTxId,
      required this.blockHash,
      required this.txIndex,
      required this.branch});
}

/// What a pool answers catch-up requests from. A coordinator backs it with
/// its ledger, its round store and its chain access; a test backs it with
/// the test chain.
abstract interface class CatchUpSource {
  /// The last mined round: every round up to it is mined, the next is not
  /// (or is not known to be). Zero before round 1 is mined. Every answer is
  /// pinned to it, so a head and a frontier asked for back to back stand at
  /// the same round unless a round is mined between them.
  int get minedTip;

  /// Round [round]'s block root, for 1 to [minedTip].
  List<int> blockRootOf(int round);

  /// The frontier at round [round], for 1 to [minedTip].
  ({int round, List<int> blockRoot, List<List<int>> left}) frontierAt(int round);

  /// Mined round [round] with its witness's place in a block, for 1 to
  /// [minedTip]; null or a throw when the source cannot say now.
  Future<MinedRound?> mined(int round);

  /// Mined round [round]'s txids and its witness's place in a block, for 1
  /// to [minedTip]; null or a throw when the source cannot say now.
  Future<RoundPlace?> placed(int round);
}

/// The rules for answering a catch-up request, in one place for every
/// pool: a range only when the descriptor publishes it, every answer at or
/// below the last mined round, and a refusal naming why for anything else,
/// so a wallet never waits out a timeout for an answer that will not come.
class PoolCatchUpResponder {
  final PoolDescriptor descriptor;
  final CatchUpSource source;

  PoolCatchUpResponder(this.descriptor, this.source);

  /// The reply to [request], echoing its id. Never throws: a source that
  /// fails is an [CatchUpRefusal.unavailable] refusal.
  Future<PoolCatchUpReply> answer(PoolCatchUpRequest request) async {
    final id = request.id, what = request.what;
    PoolCatchUpReply refuse(CatchUpRefusal why, String sentence) => PoolCatchUpReply.refused(what, why, sentence, id: id);
    try {
      final tip = source.minedTip;
      switch (what) {
        case CatchUpKind.blockRoots:
          if (!descriptor.publishesRange(request.from, request.count)) {
            return refuse(CatchUpRefusal.unpublishedRange,
                'rounds ${request.from} to ${request.from + request.count - 1} are not a published range '
                '(aligned runs of ${descriptor.catchUpRange} from round 1)');
          }
          if (tip < request.from) return refuse(CatchUpRefusal.notYet, 'round ${request.from} is not mined yet; the last mined is $tip');
          final last = tip < request.from + request.count - 1 ? tip : request.from + request.count - 1;
          return PoolCatchUpReply.blockRoots(
              from: request.from, roots: [for (int n = request.from; n <= last; n++) source.blockRootOf(n)], id: id);
        case CatchUpKind.frontier:
          if (tip == 0) return refuse(CatchUpRefusal.notYet, 'no round is mined yet');
          final f = source.frontierAt(tip);
          return PoolCatchUpReply.frontier(round: f.round, blockRoot: f.blockRoot, left: f.left, id: id);
        case CatchUpKind.head:
          if (tip == 0) return refuse(CatchUpRefusal.notYet, 'no round is mined yet');
          final m = await source.mined(tip);
          if (m == null) return refuse(CatchUpRefusal.unavailable, 'round $tip\'s place in its block cannot be read now');
          return PoolCatchUpReply.head(
              round: m.number,
              roundTx: m.roundTx,
              witnessTx: m.witnessTx,
              blockHash: m.blockHash,
              txIndex: m.txIndex,
              branch: m.branch,
              id: id);
        case CatchUpKind.round:
          final n = request.round;
          if (n > tip) return refuse(CatchUpRefusal.notYet, 'round $n is not mined yet; the last mined is $tip');
          final m = await source.mined(n);
          if (m == null) return refuse(CatchUpRefusal.unavailable, 'round $n\'s place in its block cannot be read now');
          return PoolCatchUpReply.round(
              round: m.number,
              roundTx: m.roundTx,
              witnessTx: m.witnessTx,
              blockHash: m.blockHash,
              txIndex: m.txIndex,
              branch: m.branch,
              id: id);
      }
    } catch (e) {
      return refuse(CatchUpRefusal.unavailable, 'the pool could not answer now: ${_short(e)}');
    }
  }

  /// The notice for submitters whose accepted submissions [ids] mined
  /// round [round] took in, or null when the source cannot say now.
  Future<PoolRoundMined?> notice(int round, List<List<int>> ids) async {
    final p = await source.placed(round);
    if (p == null) return null;
    return PoolRoundMined(
        ids: ids,
        round: p.number,
        roundTxId: p.roundTxId,
        witnessTxId: p.witnessTxId,
        blockHash: p.blockHash,
        txIndex: p.txIndex,
        branch: p.branch);
  }

  static String _short(Object e) {
    final s = '$e';
    return s.length > 200 ? '${s.substring(0, 200)}…' : s;
  }
}
