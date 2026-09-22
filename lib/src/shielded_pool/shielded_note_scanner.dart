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
import '../crypto/note_encryption.dart';
import '../script_gen/pool_spend_air.dart';
import 'shielded_ledger.dart';
import 'shielded_transfer.dart';

/// A note a scanner found for its wallet.
class ScannedNote {
  final NotePlaintext note;

  /// The diversifier of the address it was paid to.
  final List<int> d;
  final List<int> cm;
  final int position;

  /// The round it arrived in.
  final int round;

  /// Its nullifier, when the scanner holds the nullifier key.
  final List<int>? nullifier;

  /// The round its nullifier entered the tree, if it has.
  int? spentIn;

  ScannedNote(this.note, this.d, this.cm, this.position, this.round, this.nullifier);

  int get value => note.value;
  bool get spent => spentIn != null;
}

/// Finds a wallet's notes in the rounds its ledger applied.
///
/// It takes only [ShieldedRound]s, which only the ledger makes, so every
/// bundle it opens has a hash that chains to the header's outHash. It
/// needs nothing but those rounds and the wallet's keys: it makes no
/// request of anyone, so fetching whole rounds (as every wallet does) and
/// scanning them locally reveals nothing about which notes are whose.
///
/// Addresses are tried by [diversifiers], the ones the wallet handed out,
/// since the scanner cannot guess them; each costs one KEM decapsulation
/// per note bundle. With [nk] it also recognises spends, by each owned
/// note's nullifier `H(nk, rho)` among a round's insertions.
class ShieldedNoteScanner {
  final List<int> ivk;
  final List<List<int>> diversifiers;
  final List<int>? nk;
  final List<ScannedNote> notes = [];

  ShieldedNoteScanner({required this.ivk, required this.diversifiers, this.nk});

  factory ShieldedNoteScanner.forWallet(PoolWalletKeys keys, List<List<int>> diversifiers) =>
      ShieldedNoteScanner(ivk: keys.ivk, diversifiers: diversifiers, nk: keys.nk);

  /// The notes owned and not yet spent.
  List<ScannedNote> get unspent => [for (final n in notes) if (!n.spent) n];

  /// Scans [round]; returns the notes found in it. Spends are marked on
  /// notes found earlier: a note cannot be spent in the round that creates
  /// it, since a spend is anchored to a root the round starts from.
  Future<List<ScannedNote>> scan(ShieldedRound round) async {
    final spent = {for (final x in round.nullifiers) x.join(',')};
    for (final n in notes) {
      if (n.spentIn == null && n.nullifier != null && spent.contains(n.nullifier!.join(','))) n.spentIn = round.number;
    }
    final found = <ScannedNote>[];
    for (int t = 0; t < round.transfers.length; t++) {
      final bundle = round.bundles[t];
      if (bundle.isEmpty) continue;
      final parts = ShieldedTransfer.parseBundle(bundle);
      final positions = [round.positions[t].$1, round.positions[t].$2];
      for (int k = 0; k < 2; k++) {
        final hit = await NoteEncryption.scanIncoming(parts[k], ivk, diversifiers);
        if (hit == null) continue;
        final (note, d) = hit;
        final key = nk;
        found.add(ScannedNote(note, d, parts[k].cm, positions[k], round.number, key == null ? null : PoolHash.nullifierFromNk(key, note.rho)));
      }
    }
    notes.addAll(found);
    return found;
  }
}
