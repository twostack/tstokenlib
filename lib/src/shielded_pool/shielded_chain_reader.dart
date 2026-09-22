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
import 'package:dartsv/dartsv.dart';

import 'shielded_ledger.dart';

/// One round as a reader is handed it: round N+1, its witness, and the
/// slot transaction Y_{N+1} the round's PP3 pins.
typedef ShieldedRoundTxs = ({Transaction round, Transaction witness, Transaction nextSlot});

/// Rebuilds a TSL1_SP pool's ledger from its issuance, witness 0 and Y_0,
/// and every round since, using nothing else: no key, and nothing the
/// coordinator says. Two readers given the same transactions reach the
/// same ledger, byte for byte, so a wallet can check any claim about the
/// pool's state against its own.
///
/// It stops at the first round the ledger refuses and keeps everything it
/// applied before it. A reader that cannot reach a round's header does not
/// recover: the fault is the coordinator's (a transfer whose bundle names
/// another commitment passes V and strands every reader), and reporting
/// the round is what makes it visible.
class ShieldedChainReader {
  final ShieldedLedger ledger;

  /// What each applied round found, in order.
  final List<ShieldedRound> rounds = [];

  /// Why the reader stopped, if it did, and the round it stopped at.
  LedgerRefusal? refusal;
  int? refusedRound;

  ShieldedChainReader(this.ledger);

  /// A reader at the pool's genesis.
  factory ShieldedChainReader.open(ShieldedPoolLayout layout, Transaction issuance, Transaction witness0, Transaction slot0) =>
      ShieldedChainReader(ShieldedLedger.open(layout, issuance, witness0, slot0));

  /// The last round applied: 0 at genesis.
  int get lastRound => ledger.round;
  bool get stopped => refusal != null;

  /// Applies [txs] in order until one is refused; returns the rounds
  /// applied by this call. A stopped reader applies nothing more.
  List<ShieldedRound> read(Iterable<ShieldedRoundTxs> txs) {
    final out = <ShieldedRound>[];
    if (stopped) return out;
    for (final t in txs) {
      try {
        final r = ledger.apply(t.round, t.witness, t.nextSlot);
        rounds.add(r);
        out.add(r);
      } on LedgerRefusal catch (e) {
        refusal = e;
        refusedRound = ledger.round + 1;
        break;
      }
    }
    return out;
  }
}
