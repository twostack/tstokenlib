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

import '../crypto/m31.dart' show M31;
import '../crypto/note_commitment_tree.dart' show BlockFold;
import '../crypto/note_encryption.dart' show NotePlaintext;
import '../script_gen/pool_spend_air.dart' show PoolHash, PoolSpendAir;
import '../script_gen/pp1_sp_script_gen.dart';
import 'pool_header.dart';

/// Why a piece of evidence was refused: the check that caught it, and what it
/// saw. The step is named so a wallet can say which rule failed rather than
/// "invalid".
class EvidenceRefusal {
  final String step;
  final String reason;
  const EvidenceRefusal(this.step, this.reason);
  @override
  String toString() => '$step: $reason';
}

/// The fields of a PP1_SP output, read only after the script it came from was
/// shown to be a real PP1_SP: [PoolEvidence.readPP1] regenerates the script
/// from these and requires byte equality, so every field here was enforced by
/// the body that was on the chain, not merely written at the offset a PP1
/// keeps it at.
class PP1Fields {
  final List<int> ownerPKH, tokenId, verifierBodyHash, genesisHeader, headerBytes;
  final PoolHeader header;
  const PP1Fields(this.ownerPKH, this.tokenId, this.verifierBodyHash, this.genesisHeader, this.headerBytes, this.header);
}

/// A round that mined bytes place in a given pool: its pool header, and the
/// commitment root a note in it must reach.
///
/// The round's own number is not here because a pool header does not carry
/// one. A caller that needs it takes it from the announcement or from its own
/// count of applied rounds, and this check does not vouch for it.
class ProvenRound {
  final PoolHeader header;
  final List<int> ownerPKH;
  const ProvenRound(this.header, this.ownerPKH);

  List<int> get cmRoot => header.cmRoot;
}

/// A note a proven round holds: the value it moves and the commitment the
/// round's tree carries at the given position.
class ProvenNote {
  final int value;
  final int position;

  /// The commitment, in the 32 bytes a round's blob carries it in.
  final List<int> commitment;
  const ProvenNote(this.value, this.position, this.commitment);
}

/// What mined bytes have to show before a round counts as a given pool's.
///
/// The evidence a payee is handed is a round transaction and the witness that
/// spends it, together with a proof that the witness is in a block the payee
/// accepts. This class holds the part that is about the pool; block membership
/// is the caller's job and is established before these checks are worth
/// running.
///
/// Nothing here verifies a STARK. The round was mined, which means the chain
/// ran PP1's script over the witness that spends it, and PP1's round branch is
/// the induction: it rebuilds the round from its parent's bytes and refuses a
/// round the parent did not produce, back to a create branch anchored to a
/// once-spendable outpoint. So a witness that was mined spending a PP1 carrying
/// this pool's tokenId could only have come from this pool's own chain.
///
/// That argument has one load-bearing step which is easy to get wrong in a
/// reader, and which the lineage attack test exists to hold us to: **the script
/// in the round's PP1 output has to be a real PP1_SP script**, not merely a
/// script with the pool's tokenId at the offset a PP1 keeps its tokenId at.
/// [PP1SpLockBuilder.parse] reads every field by fixed offset and never looks
/// at the body, so a forger can put the pool's tokenId, verifier body hash and
/// genesis header at those offsets inside a script that spends on a signature
/// alone, mine a witness for it for the price of two transactions, and hand a
/// payee a payment proof for a pool state that never existed. The whole
/// induction runs in the script body; a reader that does not check the body is
/// reading a forgery's own account of itself. [provenRound] therefore
/// regenerates the script from the fields it parsed and requires it to be
/// byte-identical to what it was given.
class PoolEvidence {
  /// Where a round keeps its PP1 and PP2, and where a witness spends them.
  static const int pp1Vout = 1;
  static const int pp2Vout = 2;
  static const int witnessPP1Input = 1;
  static const int witnessPP2Input = 2;

  /// Whether [round] belongs to the pool identified by [tokenId] and
  /// [genesisHeader] (and [verifierBodyHash] when the caller has it), given
  /// the [witness] that spends it. Returns the proven round, or the first
  /// check that failed.
  ///
  /// The caller has already established that [witness] is mined in a block it
  /// accepts. Without that, every check here is about bytes a stranger chose.
  ///
  /// **What this establishes.** That a transaction carrying a real PP1_SP
  /// script, with this pool's tokenId, verifier body hash and genesis header,
  /// was accepted by the chain one hop back from a mined witness. The chain
  /// ran that PP1's round branch when the witness spent it, and that branch is
  /// the induction: it rebuilds the round from its parent's raw bytes and
  /// refuses a round the parent did not produce, terminating at a create
  /// branch anchored to an outpoint that can be spent once. tokenId sits in
  /// the immutable region the rebuild copies untouched, so a transaction the
  /// pool's own covenant did not produce cannot carry it.
  ///
  /// **What it does not establish.** The round's *number*: a pool header
  /// carries none, so a caller that needs one takes it from an announcement or
  /// from its own count, and this check does not vouch for it. Nor does it say
  /// the round is the pool's *latest*; it says the round happened. It does not
  /// inspect PP2 beyond the witness spending it, deliberately: PP1's body is
  /// what carries the induction. [verifierBodyHash] is optional because a
  /// descriptor does not carry it and it adds nothing once the tokenId matches
  /// — both sit in the same immutable region, bound together by the same
  /// create — but it is checked when the caller has it.
  ///
  /// The one-hop claim was attacked on localnet before it was relied on; see
  /// the design record, "The one-hop lineage claim, attacked".
  static (ProvenRound?, EvidenceRefusal?) provenRound({
    required Transaction round,
    required Transaction witness,
    required List<int> tokenId,
    required List<int> genesisHeader,
    List<int>? verifierBodyHash,
  }) {
    // 1. The witness spends this round's PP1 and PP2. This is the hop: a
    //    witness is what proves its round was accepted, so it has to be this
    //    round's witness and not some other transaction.
    final id = round.id;
    if (!_spends(witness, witnessPP1Input, id, pp1Vout)) {
      return (null, EvidenceRefusal('witness spends PP1',
          'input $witnessPP1Input does not spend ($id, $pp1Vout)'));
    }
    if (!_spends(witness, witnessPP2Input, id, pp2Vout)) {
      return (null, EvidenceRefusal('witness spends PP2',
          'input $witnessPP2Input does not spend ($id, $pp2Vout)'));
    }

    // 2. The round has a PP1 to read, and it is a real PP1_SP script rather
    //    than a lookalike: the fields below were enforced by a body the chain
    //    ran, not merely written at the offsets a PP1 keeps them at.
    final (fields, why) = readPP1Of(round, pp1Vout);
    if (fields == null) return (null, why);

    // 3. It is THIS pool. tokenId is immutable through the induction and is
    //    anchored by the create branch to an outpoint that can be spent once,
    //    so it is what separates this pool's chain from a well formed pool of
    //    somebody else's.
    if (!_eq(fields.tokenId, tokenId)) {
      return (null, EvidenceRefusal('tokenId',
          'the round carries ${_hex(fields.tokenId)}, this pool is ${_hex(tokenId)}'));
    }
    if (verifierBodyHash != null && !_eq(fields.verifierBodyHash, verifierBodyHash)) {
      return (null, EvidenceRefusal('verifier body hash',
          'the round carries ${_hex(fields.verifierBodyHash)}, this pool is ${_hex(verifierBodyHash)}'));
    }
    if (!_eq(fields.genesisHeader, genesisHeader)) {
      return (null, EvidenceRefusal('genesis header',
          'the round opened on a different state from the one this pool published'));
    }
    return (ProvenRound(fields.header, fields.ownerPKH), null);
  }

  /// Whether the note [opening] describes, held under [pkd], is in [round] at
  /// [position], given the [path] from that position to the round's
  /// commitment root. Returns the note, or the first check that failed.
  ///
  /// This is the payee's half of a payment proof. It needs no key: the payer
  /// hands over the opening, and the opening plus the payee's own `pk_d` is
  /// what makes the commitment. A note that commits under somebody else's
  /// `pk_d` is somebody else's note, and the check says so rather than
  /// reporting a value.
  ///
  /// Nothing here verifies a STARK either. The commitment is in a tree whose
  /// root a mined round carries, and the round was accepted by the chain; what
  /// remains is one hash of the opening and [PoolSpendAir.depth] hashes up the
  /// path.
  static (ProvenNote?, EvidenceRefusal?) provenNote({
    required ProvenRound round,
    required NotePlaintext opening,
    required List<int> pkd,
    required int position,
    required List<List<int>> path,
  }) =>
      noteUnderRoot(cmRoot: round.cmRoot, opening: opening, pkd: pkd, position: position, path: path);

  /// The same check against a commitment root the caller established some
  /// other way than by reading a round.
  ///
  /// There is one other way, and only one: a party following the pool folds a
  /// block root a round and checks the result against the `cmRoot` of a round
  /// it proved off the chain, so the root it holds for a round is as good as
  /// the round's own. That is what makes a short payment proof possible — the
  /// opening, the position and the path, about a kilobyte, against a root the
  /// payee already has. A root that arrived *inside* a proof is not such a
  /// root and must never be passed here.
  static (ProvenNote?, EvidenceRefusal?) noteUnderRoot({
    required List<int> cmRoot,
    required NotePlaintext opening,
    required List<int> pkd,
    required int position,
    required List<List<int>> path,
  }) {
    if (cmRoot.length != 32) {
      return (null, EvidenceRefusal('commitment root', 'is ${cmRoot.length} bytes, a root is 32'));
    }
    if (pkd.length != PoolHash.digestLanes || pkd.any(_outsideField)) {
      return (null, EvidenceRefusal('pk_d', 'is not ${PoolHash.digestLanes} lanes inside the field'));
    }
    if (position < 0 || position >= (1 << PoolSpendAir.depth)) {
      return (null, EvidenceRefusal('position', '$position is outside a tree of depth ${PoolSpendAir.depth}'));
    }
    if (path.length != PoolSpendAir.depth) {
      return (null, EvidenceRefusal('path', 'has ${path.length} siblings, a path is ${PoolSpendAir.depth}'));
    }
    for (int i = 0; i < path.length; i++) {
      if (path[i].length != PoolHash.digestLanes || path[i].any(_outsideField)) {
        return (null, EvidenceRefusal('path', 'sibling $i is not ${PoolHash.digestLanes} lanes inside the field'));
      }
    }

    final List<int> cm, reached;
    try {
      cm = PoolHash.commit(pkd, opening.value, opening.rho, opening.rcm, asset: opening.asset).$2;
      reached = PoolHash.root(cm, path, position);
    } catch (e) {
      return (null, EvidenceRefusal('commitment', 'the opening does not make a commitment ($e)'));
    }
    final reachedBytes = BlockFold.lanesToBytes(reached);
    if (!_eq(reachedBytes, cmRoot)) {
      return (null, EvidenceRefusal('path',
          'the commitment at $position reaches ${_hex(reachedBytes)}, the round\'s root is ${_hex(cmRoot)}'));
    }
    return (ProvenNote(opening.value, position, BlockFold.lanesToBytes(cm)), null);
  }

  static bool _outsideField(int lane) => lane < 0 || lane >= M31.p;

  /// The PP1_SP fields of [tx]'s output [vout], or the check that refused it.
  ///
  /// This is the only way the library reads a field out of a PP1. The offsets
  /// carry no authority: the script body does, and a forger can write any
  /// fields at the right offsets over a body that spends on a signature. So
  /// the fields are parsed, the script is regenerated from them, and the two
  /// are compared byte for byte.
  static (PP1Fields?, EvidenceRefusal?) readPP1Of(Transaction tx, int vout) {
    if (tx.outputs.length <= vout) {
      return (null, EvidenceRefusal('round shape',
          'the transaction has ${tx.outputs.length} outputs, too few to hold a PP1 at $vout'));
    }
    return readPP1(tx.outputs[vout].script.buffer, vout: vout);
  }

  /// The PP1_SP fields [script] carries, or the check that refused it.
  static (PP1Fields?, EvidenceRefusal?) readPP1(List<int> script, {int vout = pp1Vout}) {
    final List<int> ownerPKH, foundToken, foundVerifier, foundGenesis, foundHeader;
    try {
      _requireLayout(script, vout);
      ownerPKH = script.sublist(PP1SpScriptGen.pkhDataStart, PP1SpScriptGen.pkhDataEnd);
      foundToken = script.sublist(PP1SpScriptGen.tokenIdDataStart, PP1SpScriptGen.tokenIdDataEnd);
      foundVerifier = script.sublist(
          PP1SpScriptGen.verifierBodyHashDataStart, PP1SpScriptGen.verifierBodyHashDataEnd);
      foundGenesis =
          script.sublist(PP1SpScriptGen.genesisDataStart, PP1SpScriptGen.genesisDataEnd);
      foundHeader = script.sublist(PP1SpScriptGen.headerDataStart, PP1SpScriptGen.headerDataEnd);
    } on EvidenceRefusal catch (e) {
      return (null, e);
    }

    final List<int> rebuilt;
    try {
      rebuilt = PP1SpScriptGen.generate(
        ownerPKH: ownerPKH,
        tokenId: foundToken,
        verifierBodyHash: foundVerifier,
        header: foundHeader,
        genesisHeader: foundGenesis,
      ).buffer;
    } catch (e) {
      return (null, EvidenceRefusal('PP1 is this pool\'s script',
          'the fields do not rebuild a PP1_SP script ($e)'));
    }
    if (!_eq(rebuilt, script)) {
      return (null, EvidenceRefusal('PP1 is this pool\'s script',
          'the output at $vout carries the fields of a PP1_SP but not its body, '
          'so nothing was enforced when it was spent '
          '(${script.length} bytes given, ${rebuilt.length} rebuilt)'));
    }

    final PoolHeader header;
    try {
      header = PoolHeader.decode(foundHeader);
    } catch (e) {
      return (null, EvidenceRefusal('pool header', 'does not decode ($e)'));
    }
    return (PP1Fields(ownerPKH, foundToken, foundVerifier, foundGenesis, foundHeader, header), null);
  }

  /// The pushes a PP1_SP begins with, checked before any field is read so a
  /// short or differently shaped script is refused by name rather than by a
  /// range error.
  static void _requireLayout(List<int> s, int vout) {
    if (s.length < PP1SpScriptGen.scriptBodyStart) {
      throw EvidenceRefusal('PP1 is this pool\'s script',
          'the output at $vout is ${s.length} bytes, shorter than a PP1_SP\'s '
          '${PP1SpScriptGen.scriptBodyStart}-byte head');
    }
    if (s[0] != 0x14) {
      throw EvidenceRefusal('PP1 is this pool\'s script',
          'the output at $vout does not begin with a 20-byte push');
    }
    for (final at in [PP1SpScriptGen.genesisPushStart, PP1SpScriptGen.headerPushStart]) {
      if (s[at] != 0x4c || s[at + 1] != PoolHeader.byteSize) {
        throw EvidenceRefusal('PP1 is this pool\'s script',
            'the output at $vout has no ${PoolHeader.byteSize}-byte header push at $at');
      }
    }
  }

  static bool _spends(Transaction tx, int input, String txid, int vout) =>
      tx.inputs.length > input &&
      tx.inputs[input].prevTxnId == txid &&
      tx.inputs[input].prevTxnOutputIndex == vout;

  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _hex(List<int> b) {
    const d = '0123456789abcdef';
    final s = StringBuffer();
    for (final x in b.take(8)) {
      s.write(d[(x >> 4) & 15]);
      s.write(d[x & 15]);
    }
    return '$s...';
  }
}
