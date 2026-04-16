/// Isolated reproducer for the identity anchor signing bug.
///
/// IdentityAnchorBuilder builds in two steps: a preTx (without AIP output)
/// whose serialized bytes feed the AIP signature, then a fullTx (with AIP).
/// Historically both steps shared the same P2PKHUnlockBuilder, which is
/// append-only in its signatures list and always returns signatures[0] from
/// getScriptSig(). That meant the fullTx embedded the preTx's signature
/// (covering a different output set) and failed CHECKSIG on broadcast —
/// ARC error 461 (NULLFAIL).
///
/// This test spins up a funding tx, builds an identity anchor against it,
/// and runs Interpreter.correctlySpends on the anchor's P2PKH input. If the
/// sig fails to validate we reproduce the production failure in isolation.

import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

void main() {
  group('Baseline — plain P2PKH→P2PKH validates', () {
    test('vanilla P2PKH tx passes correctlySpends', () {
      const wif = 'cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS';
      final privKey = SVPrivateKey.fromWIF(wif);
      final pubKey = privKey.publicKey;
      final address = Address.fromPublicKey(pubKey, NetworkType.TEST);

      // Funding tx — output[1] is the one we'll spend.
      final fakePrev = List<int>.generate(32, (i) => i + 0x40);
      final funding = (TransactionBuilder()
            .spendFromOutpoint(
              TransactionOutpoint(hex.encode(fakePrev), 0,
                  BigInt.from(200000000),
                  P2PKHLockBuilder.fromAddress(address).getScriptPubkey()),
              TransactionInput.MAX_SEQ_NUMBER,
              P2PKHUnlockBuilder(pubKey))
            .spendToLockBuilder(
                P2PKHLockBuilder.fromAddress(address), BigInt.from(546))
            .spendToLockBuilder(
                P2PKHLockBuilder.fromAddress(address), BigInt.from(199999000))
            ..withOption(TransactionOption.DISABLE_DUST_OUTPUTS))
          .build(false);

      final signer = DefaultTransactionSigner(
        SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value,
        privKey,
      );

      // Simplest spending tx: P2PKH → P2PKH + change.
      final unlocker = P2PKHUnlockBuilder(pubKey);
      final spendTx = TransactionBuilder()
          .spendFromTxnWithSigner(
              signer, funding, 1, TransactionInput.MAX_SEQ_NUMBER, unlocker)
          .spendToLockBuilder(
              P2PKHLockBuilder.fromAddress(address), BigInt.from(1000))
          .sendChangeToPKH(address)
          .withFeePerKb(1)
          .build(false);

      final interp = Interpreter();
      expect(
        () => interp.correctlySpends(
          spendTx.inputs[0].script!,
          funding.outputs[1].script,
          spendTx,
          0,
          {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS},
          Coin.valueOf(funding.outputs[1].satoshis),
        ),
        returnsNormally,
        reason: 'Vanilla P2PKH signing pipeline should validate — if this '
            'fails, the bug is in dartsv, not IdentityAnchorBuilder.',
      );
    });
  });

  group('IdentityAnchorBuilder — signature validity', () {
    test('anchor input scriptSig passes correctlySpends (no artwork)', () async {
      final anchor = await _buildAnchorFromFunding(artwork: null);
      _verifyP2PKHInput(anchor);
    });

    test('anchor input scriptSig passes correctlySpends (with artwork)', () async {
      // 256 bytes — crosses the OP_PUSHDATA1 boundary.
      final art = List<int>.generate(256, (i) => i & 0xFF);
      final anchor = await _buildAnchorFromFunding(artwork: art);
      _verifyP2PKHInput(anchor);
    });
  });
}

/// Build a real funding P2PKH TX, then build the identity anchor spending
/// its output[1]. Returns (fullAnchorTx, fundingTx, pubKey).
class _AnchorBuild {
  final Transaction anchorTx;
  final Transaction fundingTx;
  final SVPublicKey pubKey;
  _AnchorBuild(this.anchorTx, this.fundingTx, this.pubKey);
}

Future<_AnchorBuild> _buildAnchorFromFunding({List<int>? artwork}) async {
  // Deterministic WIF so the test is stable.
  const wif = 'cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS';
  final privKey = SVPrivateKey.fromWIF(wif);
  final pubKey = privKey.publicKey;
  final address = Address.fromPublicKey(pubKey, NetworkType.TEST);

  // Synthesize a funding TX with output[1] = P2PKH to our address (what the
  // anchor builder expects — IdentityAnchorBuilder hardcodes vout=1).
  final fakePrev = List<int>.generate(32, (i) => i + 0x40);
  final fundingBuilder = TransactionBuilder()
      .spendFromOutpoint(
        TransactionOutpoint(
          hex.encode(fakePrev),
          0,
          BigInt.from(200000000),
          P2PKHLockBuilder.fromAddress(address).getScriptPubkey(),
        ),
        TransactionInput.MAX_SEQ_NUMBER,
        P2PKHUnlockBuilder(pubKey),
      )
      .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(546))
      .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(199999000));
  fundingBuilder.withOption(TransactionOption.DISABLE_DUST_OUTPUTS);
  final fundingTx = fundingBuilder.build(false);

  // Signer over the funding key. Same sighash flags libspiffy uses.
  final sigHashType =
      SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
  final signer = DefaultTransactionSigner(sigHashType, privKey);

  // Ed25519 wand (AIP signs the preTx hash).
  final seed = List<int>.generate(32, (i) => i);
  final ed25519 = Ed25519();
  final keypair = await ed25519.newKeyPairFromSeed(seed);
  final wand = await ed25519.newSignatureWandFromKeyPair(keypair);

  final identity = <String, String>{
    'name': 'Test Issuer',
    'description': 'anchor reproducer',
  };

  final builder = IdentityAnchorBuilder(
    identity,
    artworkBytes: artwork,
    artworkMimeType: artwork == null ? null : 'application/octet-stream',
  );

  final anchorTx = await builder.buildTransaction(
    fundingTx,
    signer,
    pubKey,
    address,
    wand,
  );

  return _AnchorBuild(anchorTx, fundingTx, pubKey);
}

/// Run Interpreter.correctlySpends on input[0] of [build.anchorTx] against
/// the funding TX's output[1]. Fails with the interpreter's error if the
/// P2PKH signature doesn't validate.
void _verifyP2PKHInput(_AnchorBuild build) {
  final input = build.anchorTx.inputs[0];
  expect(input.prevTxnId, equals(build.fundingTx.id));
  expect(input.prevTxnOutputIndex, equals(1));

  final prevOut = build.fundingTx.outputs[1];
  final scriptSig = input.script!;
  final scriptPubKey = prevOut.script;

  final interp = Interpreter();
  expect(
    () => interp.correctlySpends(
      scriptSig,
      scriptPubKey,
      build.anchorTx,
      0,
      {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS},
      Coin.valueOf(prevOut.satoshis),
    ),
    returnsNormally,
    reason: 'anchor input[0] scriptSig must validate against the funding '
        'output\'s P2PKH scriptPubKey. If this fails, the on-wire scriptSig '
        'embeds a signature that does not cover the final anchor TX shape '
        '(e.g. preTx sig leaking into fullTx). This is what causes ARC to '
        'reject with error 461 / NULLFAIL.',
  );
}
