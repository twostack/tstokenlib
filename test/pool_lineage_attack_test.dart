import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/script_gen/pp1_sp_script_gen.dart';
import 'package:tstokenlib/tstokenlib.dart';

import 'pool_forgery.dart';

/// Attacks on the claim every payment proof rests on: that a mined witness
/// spending a round's PP1 and PP2, with the pool's tokenId in that PP1, places
/// the round in the pool's own chain, one hop back to genesis.
///
/// The claim's strength is that PP1's round branch is the induction. It rebuilds
/// the round from its parent's bytes and refuses one the parent did not
/// produce, back to a create branch anchored to an outpoint that can be spent
/// once. A witness that was mined had that whole argument run over it by the
/// miners.
///
/// The claim's weakness is that a payee runs no script. It reads bytes. So the
/// attack here is not against the covenant, it is against the reader: put the
/// pool's identity at the offsets a PP1 keeps its identity at, inside a script
/// whose body enforces nothing, and spend it with a signature. That mines for
/// the price of two ordinary transactions.
void main() {
  final ownerKey = SVPrivateKey.fromWIF('cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS');
  final forgerKey = SVPrivateKey.fromWIF('cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5');
  final ownerAddr = Address.fromPublicKey(ownerKey.publicKey, NetworkType.TEST);
  final forgerAddr = Address.fromPublicKey(forgerKey.publicKey, NetworkType.TEST);
  final ownerPKH = hex.decode(ownerAddr.pubkeyHash160);
  final sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

  // The pool as a payee knows it from its descriptor: three immutable fields.
  final tokenId = List<int>.generate(32, (i) => (i * 7 + 1) & 0xff);
  final verifierBodyHash = List<int>.generate(32, (i) => (i * 11 + 3) & 0xff);
  final genesis = PoolHeader.genesis(
      emptyCmRoot: List.filled(32, 0), emptyNfRoot: List.filled(32, 0));
  final genesisHeader = genesis.encode().toList();

  /// A pool state of the forger's choosing: whatever commitment root makes the
  /// forger's own note appear to be in the pool.
  final forged = genesis.advance(
    cmRoot: List<int>.generate(32, (i) => (0xA0 + i) & 0xff),
    nfRoot: List.filled(32, 0),
    size: 512,
    balance: BigInt.from(100000000),
    outHash: List.filled(32, 0),
  );
  final forgedHeader = forged.encode().toList();

  SVScript realPP1(List<int> header) => PP1SpScriptGen.generate(
        ownerPKH: ownerPKH,
        tokenId: tokenId,
        verifierBodyHash: verifierBodyHash,
        header: header,
        genesisHeader: genesisHeader,
      );

  /// The forgery. Its first 563 bytes are the real PP1's own bytes, so every
  /// field a reader looks up by offset is the pool's; the body that follows
  /// spends on the forger's signature alone. It lives in `pool_forgery.dart`
  /// so the ledger and evidence tests are refused for the same bytes.
  SVScript forge(List<int> header) => lookalikePP1(realPP1(header), forgerAddr);

  /// A transaction shaped like a round: change at 0, PP1 at 1, PP2 at 2.
  Transaction roundShaped(SVScript pp1) => Transaction()
    ..addInput(TransactionInput('00' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
    ..addOutputs([
      TransactionOutput(
          BigInt.from(1000), P2PKHLockBuilder.fromAddress(forgerAddr).getScriptPubkey()),
      TransactionOutput(BigInt.one, pp1),
      TransactionOutput(BigInt.one, SVScript.fromString('OP_1')),
    ]);

  /// A witness shaped transaction: funding at 0, the round's PP1 at 1 and its
  /// PP2 at 2, exactly where a real witness spends them.
  Transaction witnessFor(Transaction round) => Transaction()
    ..addInput(TransactionInput('11' * 32, 1, TransactionInput.MAX_SEQ_NUMBER))
    ..addInput(TransactionInput(round.id, PoolEvidence.pp1Vout, TransactionInput.MAX_SEQ_NUMBER))
    ..addInput(TransactionInput(round.id, PoolEvidence.pp2Vout, TransactionInput.MAX_SEQ_NUMBER))
    ..addOutputs([
      TransactionOutput(BigInt.one, P2PKHLockBuilder.fromAddress(ownerAddr).getScriptPubkey())
    ]);

  (ProvenRound?, EvidenceRefusal?) check(Transaction round, Transaction witness) =>
      PoolEvidence.provenRound(
        round: round,
        witness: witness,
        tokenId: tokenId,
        verifierBodyHash: verifierBodyHash,
        genesisHeader: genesisHeader,
      );

  group('the control', () {
    test('a real round of this pool is proven, and its header read', () {
      final round = roundShaped(realPP1(forgedHeader));
      final (proven, refusal) = check(round, witnessFor(round));
      expect(refusal, isNull, reason: 'a genuine PP1_SP for this pool must pass');
      expect(proven!.header.encode().toList(), forgedHeader);
      expect(proven.ownerPKH, ownerPKH);
    });

    test('a witness that does not spend the round is refused', () {
      final round = roundShaped(realPP1(forgedHeader));
      final other = roundShaped(realPP1(genesisHeader));
      final (proven, refusal) = check(round, witnessFor(other));
      expect(proven, isNull);
      expect(refusal!.step, 'witness spends PP1');
    });

    test("another pool's tokenId is refused", () {
      final round = roundShaped(PP1SpScriptGen.generate(
        ownerPKH: ownerPKH,
        tokenId: List<int>.generate(32, (i) => i),
        verifierBodyHash: verifierBodyHash,
        header: forgedHeader,
        genesisHeader: genesisHeader,
      ));
      final (proven, refusal) = check(round, witnessFor(round));
      expect(proven, isNull);
      expect(refusal!.step, 'tokenId');
    });
  });

  group('ATTACK: a lookalike PP1', () {
    test("reads as this pool through the library's own parser", () {
      // The parser a wallet would reach for reads by offset and never looks at
      // the body, so the forgery is indistinguishable to it. This is the hole
      // the proven-round check has to close.
      final parsed = PP1SpLockBuilder.fromScript(forge(forgedHeader));
      expect(parsed.tokenId, tokenId, reason: "the forgery carries the pool's tokenId");
      expect(parsed.verifierBodyHash, verifierBodyHash);
      expect(parsed.genesisHeader, genesisHeader);
      expect(parsed.header!.encode().toList(), forgedHeader,
          reason: "and a pool state of the forger's choosing");
    });

    test('is refused by the proven-round check, naming the step', () {
      final round = roundShaped(forge(forgedHeader));
      final (proven, refusal) = check(round, witnessFor(round));
      expect(proven, isNull, reason: 'a forged round must never be proven');
      expect(refusal!.step, "PP1 is this pool's script");
      expect(refusal.reason, contains('not its body'));
    });

    test('spends on a signature alone, where a real PP1 does not', () {
      // Why the forgery is cheap: its witness is an ordinary spend, so it
      // mines. The real PP1 refuses the same unlock, which is the induction
      // doing its job and the reason a mined witness means anything at all.
      bool spendsWithASignature(SVScript lock) {
        final prev = Transaction()
          ..addInput(TransactionInput('22' * 32, 0, TransactionInput.MAX_SEQ_NUMBER))
          ..addOutputs([TransactionOutput(BigInt.from(1000), lock)]);
        final spend = (TransactionBuilder()
              ..spendFromTxnWithSigner(
                  DefaultTransactionSigner(sigHashAll, forgerKey),
                  prev,
                  0,
                  TransactionInput.MAX_SEQ_NUMBER,
                  P2PKHUnlockBuilder(forgerKey.publicKey))
              ..spendToPKH(forgerAddr, BigInt.from(800)))
            .build(false);
        try {
          Interpreter().correctlySpends(
              spend.inputs[0].script!,
              lock,
              spend,
              0,
              {VerifyFlag.UTXO_AFTER_GENESIS, VerifyFlag.SIGHASH_FORKID},
              Coin.valueOf(BigInt.from(1000)));
          return true;
        } catch (_) {
          return false;
        }
      }

      expect(spendsWithASignature(forge(forgedHeader)), isTrue,
          reason: 'the forgery is an ordinary spend, so its witness mines');
      expect(spendsWithASignature(realPP1(forgedHeader)), isFalse,
          reason: 'a real PP1 refuses an unlock that does not carry the induction');
    });
  });

  // The script-level attack above shows the forgery is an ordinary spend. This
  // shows a real node takes it: the forged round and its witness are mined on
  // regtest, so a payee really can be handed this and has nothing but the
  // proven-round check between it and a payment that never happened.
  group('ATTACK on localnet', () {
    test('the forged round and its witness are mined, and still refused', () async {
      final net = _Node();
      await net.ready();

      final funding = await net.fund(forgerAddr, BigInt.from(200000));
      final vout = funding.outputs.indexWhere((o) => _paysTo(o, hex.decode(forgerAddr.pubkeyHash160)));
      expect(vout, isNonNegative, reason: 'the node funded the forger');

      final signer = DefaultTransactionSigner(sigHashAll, forgerKey);
      final round = (TransactionBuilder()
            ..spendFromTxnWithSigner(signer, funding, vout, TransactionInput.MAX_SEQ_NUMBER,
                P2PKHUnlockBuilder(forgerKey.publicKey))
            ..spendToPKH(forgerAddr, BigInt.from(190000)) // 0: change, the witness's funding
            ..spendToLockBuilder(
                DefaultLockBuilder.fromScript(forge(forgedHeader)), BigInt.one) // 1: "PP1"
            ..spendToPKH(forgerAddr, BigInt.one) // 2: "PP2"
            ..withFee(BigInt.from(2000)))
          .build(false);
      await net.submit('round', round);

      final witness = (TransactionBuilder()
            ..spendFromTxnWithSigner(signer, round, 0, TransactionInput.MAX_SEQ_NUMBER,
                P2PKHUnlockBuilder(forgerKey.publicKey))
            ..spendFromTxnWithSigner(signer, round, PoolEvidence.pp1Vout,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(forgerKey.publicKey))
            ..spendFromTxnWithSigner(signer, round, PoolEvidence.pp2Vout,
                TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(forgerKey.publicKey))
            ..spendToPKH(forgerAddr, BigInt.from(188000))
            ..withFee(BigInt.from(2000)))
          .build(false);
      await net.submit('witness', witness);

      // Both are on the chain. A payee reading by offset sees a round of this
      // pool, mined, with a witness spending its PP1 and PP2.
      final parsed = PP1SpLockBuilder.fromScript(round.outputs[PoolEvidence.pp1Vout].script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.header!.encode().toList(), forgedHeader);

      final (proven, refusal) = check(round, witness);
      expect(proven, isNull, reason: 'mined is not the same as this pool\'s');
      expect(refusal!.step, "PP1 is this pool's script");
      print('localnet: forged round ${round.id} '
          '(${hex.decode(round.serialize()).length} B, ${round.inputs.length} input, '
          'PP1 ${round.outputs[PoolEvidence.pp1Vout].script.buffer.length} B) and witness '
          '${witness.id} (${hex.decode(witness.serialize()).length} B, '
          'PP1 unlock ${witness.inputs[PoolEvidence.pp1Vout].script!.buffer.length} B) mined, '
          'refused at "${refusal.step}"');
    }, timeout: Timeout(Duration(minutes: 3)));
  }, skip: Platform.environment['POOL_LOCALNET'] == '1' ? false : 'set POOL_LOCALNET=1');
}

bool _paysTo(TransactionOutput o, List<int> pkh) {
  final s = o.script.buffer;
  return s.length == 25 && s[0] == 0x76 && s[1] == 0xa9 && hex.encode(s.sublist(3, 23)) == hex.encode(pkh);
}

/// Just enough of the regtest node's RPC to mine a forgery, as ../localnet runs it.
class _Node {
  final _uri = Uri.parse(Platform.environment['LOCALNET_RPC'] ?? 'http://localhost:18332');
  final _http = HttpClient();

  Future<dynamic> rpc(String method, [List<dynamic> params = const []]) async {
    final req = await _http.postUrl(_uri);
    req.headers.set('Authorization', 'Basic ${base64.encode(utf8.encode('bitcoin:bitcoin'))}');
    req.headers.contentType = ContentType.json;
    req.persistentConnection = false;
    req.write(jsonEncode({'jsonrpc': '1.0', 'id': method, 'method': method, 'params': params}));
    final res = await req.close();
    final json = jsonDecode(await res.transform(utf8.decoder).join()) as Map<String, dynamic>;
    if (json['error'] != null) throw StateError('$method: ${json['error']}');
    return json['result'];
  }

  Future<void> mine([int n = 1]) async => rpc('generatetoaddress', [n, await rpc('getnewaddress')]);

  Future<void> ready() async {
    try {
      await rpc('getblockcount');
    } catch (e) {
      throw StateError('No regtest node at $_uri ($e). Start ../localnet.');
    }
    if ((await rpc('getbalance') as num) < 2) await mine(101);
  }

  Future<Transaction> fund(Address to, BigInt sats) async {
    final txid = await rpc('sendtoaddress', [to.toBase58(), sats.toInt() / 1e8]) as String;
    await mine();
    return Transaction.fromHex(await rpc('getrawtransaction', [txid, 0]) as String);
  }

  Future<void> submit(String name, Transaction tx) async {
    await rpc('sendrawtransaction', [tx.serialize()]);
    await mine();
    final info = await rpc('getrawtransaction', [tx.id, 1]) as Map<String, dynamic>;
    if ((info['confirmations'] ?? 0) < 1) {
      throw StateError('$name ${tx.id} was accepted but not mined');
    }
  }
}
