import 'package:dartsv/dartsv.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';

/// The lineage forgery, in one place, so every test that has to be refused
/// is refused for the same bytes.
///
/// [real] is a genuine PP1_SP locking script. The forgery keeps its first
/// [PP1SpScriptGen.scriptBodyStart] bytes verbatim — so the owner, tokenId,
/// verifier body hash, genesis header and header a reader looks up by offset
/// are the pool's — and replaces the body, which is where the induction
/// lives, with five drops and an ordinary P2PKH to [payTo]. It spends on a
/// signature, so it mines for the price of an ordinary transaction.
SVScript lookalikePP1(SVScript real, Address payTo) => SVScript.fromByteArray([
      ...real.buffer.sublist(0, PP1SpScriptGen.scriptBodyStart),
      for (var i = 0; i < 5; i++) OpCodes.OP_DROP,
      ...P2PKHLockBuilder.fromAddress(payTo).getScriptPubkey().buffer,
    ]);

/// [tx] with its output [vout]'s locking script replaced by [script], every
/// other byte the same. The result has a different txid, which is the whole
/// reason a forged round cannot be slipped under a real witness.
Transaction withOutputScript(Transaction tx, int vout, SVScript script) {
  final out = Transaction();
  for (final i in tx.inputs) {
    out.addInput(TransactionInput(i.prevTxnId, i.prevTxnOutputIndex, i.sequenceNumber,
        scriptBuilder: DefaultUnlockBuilder.fromScript(i.script ?? SVScript())));
  }
  for (int k = 0; k < tx.outputs.length; k++) {
    final o = tx.outputs[k];
    out.addOutput(TransactionOutput(o.satoshis, k == vout ? script : o.script));
  }
  return out;
}

/// A transaction with the three inputs a witness spends: funding at 0, the
/// round's PP1 at 1 and its PP2 at 2.
Transaction witnessFor(Transaction round, Address payTo, {int pp1Vout = 1, int pp2Vout = 2}) => Transaction()
  ..addInput(TransactionInput('11' * 32, 1, TransactionInput.MAX_SEQ_NUMBER))
  ..addInput(TransactionInput(round.id, pp1Vout, TransactionInput.MAX_SEQ_NUMBER))
  ..addInput(TransactionInput(round.id, pp2Vout, TransactionInput.MAX_SEQ_NUMBER))
  ..addOutputs([TransactionOutput(BigInt.one, P2PKHLockBuilder.fromAddress(payTo).getScriptPubkey())]);
