import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/script_gen/pp1_sm_script_gen.dart';

// Merchant identity (Bob)
var merchantWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey merchantPrivateKey = SVPrivateKey.fromWIF(merchantWif);
var merchantPub = merchantPrivateKey.publicKey;
Address merchantAddress = Address.fromPublicKey(merchantPub, NetworkType.TEST);
var merchantPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

// Customer identity (Alice)
var customerWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey customerPrivateKey = SVPrivateKey.fromWIF(customerWif);
SVPublicKey customerPub = customerPrivateKey.publicKey;
var customerAddress = Address.fromPublicKey(customerPub, NetworkType.TEST);
var customerPubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

Transaction getMerchantFundingTx() {
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

Transaction getCustomerFundingTx() {
  var rawTx =
      "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";
  return Transaction.fromHex(rawTx);
}

void main() {
  group('SM lock builder parse roundtrip', () {
    test('140-byte header roundtrip with initial state', () {
      var tokenId = List<int>.filled(32, 0xAA);
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var commitmentHash = List<int>.filled(32, 0x00);

      var builder = PP1SmLockBuilder(
          merchantAddress, tokenId, merchPKH, custPKH,
          0, 0, commitmentHash, 0x3F, 86400);
      var script = builder.getScriptPubkey();

      var parsed = PP1SmLockBuilder.fromScript(script);
      expect(parsed.tokenId, tokenId);
      expect(parsed.merchantPKH, merchPKH);
      expect(parsed.customerPKH, custPKH);
      expect(parsed.currentState, 0);
      expect(parsed.milestoneCount, 0);
      expect(parsed.commitmentHash, commitmentHash);
      expect(parsed.transitionBitmask, 0x3F);
      expect(parsed.timeoutDelta, 86400);
    });

    test('140-byte header roundtrip with active state', () {
      var tokenId = List<int>.filled(32, 0xBB);
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var commitmentHash = List<int>.generate(32, (i) => i + 1);

      var builder = PP1SmLockBuilder(
          customerAddress, tokenId, merchPKH, custPKH,
          1, 3, commitmentHash, 0x1F, 172800);
      var script = builder.getScriptPubkey();

      var parsed = PP1SmLockBuilder.fromScript(script);
      expect(parsed.currentState, 1);
      expect(parsed.milestoneCount, 3);
      expect(parsed.commitmentHash, commitmentHash);
      expect(parsed.transitionBitmask, 0x1F);
      expect(parsed.timeoutDelta, 172800);
    });

    test('script header byte offsets match constants', () {
      var tokenId = List<int>.filled(32, 0xCC);
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var commitmentHash = List<int>.filled(32, 0xFF);

      var builder = PP1SmLockBuilder(
          merchantAddress, tokenId, merchPKH, custPKH,
          2, 5, commitmentHash, 0x3F, 3600);
      var script = builder.getScriptPubkey();
      var buf = script.buffer;

      expect(buf[0], 0x14);
      expect(buf[21], 0x20);
      expect(buf[54], 0x14);
      expect(buf[75], 0x14);
      expect(buf[96], 0x01);
      expect(buf[98], 0x01);
      expect(buf[100], 0x20);
      expect(buf[133], 0x01);
      expect(buf[135], 0x04);

      expect(buf[97], 2);
      expect(buf[99], 5);
      expect(buf[134], 0x3F);
      expect(buf[136], 0x10);
      expect(buf[137], 0x0E);
      expect(buf[138], 0x00);
      expect(buf[139], 0x00);
    });

    test('validation rejects wrong-length tokenId', () {
      expect(() => PP1SmLockBuilder(
          merchantAddress, [1, 2, 3], hex.decode(merchantPubkeyHash),
          hex.decode(customerPubkeyHash), 0, 0, List<int>.filled(32, 0), 0x3F, 0),
          throwsA(isA<ScriptException>()));
    });

    test('validation rejects wrong-length merchantPKH', () {
      expect(() => PP1SmLockBuilder(
          merchantAddress, List<int>.filled(32, 0), [1, 2],
          hex.decode(customerPubkeyHash), 0, 0, List<int>.filled(32, 0), 0x3F, 0),
          throwsA(isA<ScriptException>()));
    });
  });

  group('SM script generation', () {
    test('generate produces script with correct header size', () {
      var script = PP1SmScriptGen.generate(
        ownerPKH: hex.decode(merchantPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        merchantPKH: hex.decode(merchantPubkeyHash),
        customerPKH: hex.decode(customerPubkeyHash),
        currentState: 0,
        milestoneCount: 0,
        commitmentHash: List<int>.filled(32, 0x00),
        transitionBitmask: 0x3F,
        timeoutDelta: 86400,
      );

      var buf = script.buffer;
      expect(buf.length > 140, true, reason: 'Script must be > 140 bytes (header + body)');
      expect(buf[0], 0x14);
      expect(buf[96], 0x01);
      expect(buf[97], 0x00);
    });
  });

  group('SM issuance transaction', () {
    test('creates 5-output issuance', () {
      var service = StateMachineTool();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var merchantFundingTx = getMerchantFundingTx();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400,
        merchantFundingTx.hash,
      );

      expect(issuanceTx.outputs.length, 5);
      expect(issuanceTx.inputs.length, 1);
      expect(issuanceTx.outputs[0].satoshis > BigInt.zero, true);
      expect(issuanceTx.outputs[1].satoshis, BigInt.one);
      expect(issuanceTx.outputs[2].satoshis, BigInt.one);
      expect(issuanceTx.outputs[3].satoshis, BigInt.one);
      expect(issuanceTx.outputs[4].satoshis, BigInt.zero);
    });

    test('PP1_SM output contains correct initial fields', () {
      var service = StateMachineTool();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var merchantFundingTx = getMerchantFundingTx();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400,
        merchantFundingTx.hash,
      );

      var pp1Lock = PP1SmLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(pp1Lock.tokenId, merchantFundingTx.hash);
      expect(pp1Lock.merchantPKH, merchPKH);
      expect(pp1Lock.customerPKH, custPKH);
      expect(pp1Lock.currentState, 0);
      expect(pp1Lock.milestoneCount, 0);
      expect(pp1Lock.commitmentHash, List<int>.filled(32, 0));
      expect(pp1Lock.transitionBitmask, 0x3F);
      expect(pp1Lock.timeoutDelta, 86400);
    });
  });

  group('SM burn', () {
    test('burn succeeds on SETTLED state token', () {
      // Build a token in SETTLED state (0x04)
      var pp1Script = PP1SmScriptGen.generate(
        ownerPKH: hex.decode(merchantPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        merchantPKH: hex.decode(merchantPubkeyHash),
        customerPKH: hex.decode(customerPubkeyHash),
        currentState: 4, // SETTLED
        milestoneCount: 3,
        commitmentHash: List<int>.filled(32, 0x11),
        transitionBitmask: 0x3F,
        timeoutDelta: 86400,
      );

      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(merchantSigner, getMerchantFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(merchantPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(merchantAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      var burnUnlocker = PP1SmUnlockBuilder.forBurn(merchantPub);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var burnTx = TransactionBuilder()
          .spendFromTxnWithSigner(customerSigner, customerFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(customerPub))
          .spendFromTxnWithSigner(merchantSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, burnUnlocker)
          .sendChangeToPKH(merchantAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = burnTx.inputs[1].script!;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, parentTx.outputs[1].script, burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });

    test('burn succeeds on EXPIRED state token', () {
      var pp1Script = PP1SmScriptGen.generate(
        ownerPKH: hex.decode(merchantPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        merchantPKH: hex.decode(merchantPubkeyHash),
        customerPKH: hex.decode(customerPubkeyHash),
        currentState: 5, // EXPIRED
        milestoneCount: 0,
        commitmentHash: List<int>.filled(32, 0x00),
        transitionBitmask: 0x3F,
        timeoutDelta: 86400,
      );

      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(merchantSigner, getMerchantFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(merchantPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(merchantAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      var burnUnlocker = PP1SmUnlockBuilder.forBurn(merchantPub);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var burnTx = TransactionBuilder()
          .spendFromTxnWithSigner(customerSigner, customerFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(customerPub))
          .spendFromTxnWithSigner(merchantSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, burnUnlocker)
          .sendChangeToPKH(merchantAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = burnTx.inputs[1].script!;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, parentTx.outputs[1].script, burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });

    test('burn fails on INIT state token', () {
      var pp1Script = PP1SmScriptGen.generate(
        ownerPKH: hex.decode(merchantPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        merchantPKH: hex.decode(merchantPubkeyHash),
        customerPKH: hex.decode(customerPubkeyHash),
        currentState: 0, // INIT — not terminal
        milestoneCount: 0,
        commitmentHash: List<int>.filled(32, 0x00),
        transitionBitmask: 0x3F,
        timeoutDelta: 86400,
      );

      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(merchantSigner, getMerchantFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(merchantPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(merchantAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      var burnUnlocker = PP1SmUnlockBuilder.forBurn(merchantPub);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var burnTx = TransactionBuilder()
          .spendFromTxnWithSigner(customerSigner, customerFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(customerPub))
          .spendFromTxnWithSigner(merchantSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, burnUnlocker)
          .sendChangeToPKH(merchantAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = burnTx.inputs[1].script!;
      var interp = Interpreter();
      expect(
          () => interp.correctlySpends(scriptSig, parentTx.outputs[1].script, burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()),
          reason: 'Burn should fail: state 0x00 < 0x04');
    });

    test('burn fails with wrong key', () {
      var pp1Script = PP1SmScriptGen.generate(
        ownerPKH: hex.decode(merchantPubkeyHash),
        tokenId: List<int>.filled(32, 0xAA),
        merchantPKH: hex.decode(merchantPubkeyHash),
        customerPKH: hex.decode(customerPubkeyHash),
        currentState: 4,
        milestoneCount: 0,
        commitmentHash: List<int>.filled(32, 0x00),
        transitionBitmask: 0x3F,
        timeoutDelta: 86400,
      );

      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var pp1Locker = DefaultLockBuilder.fromScript(pp1Script);
      var parentTx = TransactionBuilder()
          .spendFromTxnWithSigner(merchantSigner, getMerchantFundingTx(), 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(merchantPub))
          .spendToLockBuilder(P2PKHLockBuilder.fromAddress(merchantAddress), BigInt.from(999000000))
          .spendToLockBuilder(pp1Locker, BigInt.one)
          .build(false);

      // Try to burn with customer key (should fail — ownerPKH is merchantPKH)
      var burnUnlocker = PP1SmUnlockBuilder.forBurn(customerPub);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var burnTx = TransactionBuilder()
          .spendFromTxnWithSigner(customerSigner, customerFundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(customerPub))
          .spendFromTxnWithSigner(customerSigner, parentTx, 1, TransactionInput.MAX_SEQ_NUMBER, burnUnlocker)
          .sendChangeToPKH(customerAddress)
          .withFee(BigInt.from(135))
          .build(false);

      var scriptSig = burnTx.inputs[1].script!;
      var interp = Interpreter();
      expect(
          () => interp.correctlySpends(scriptSig, parentTx.outputs[1].script, burnTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          throwsA(isA<ScriptException>()),
          reason: 'Burn should fail: wrong key');
    });
  });

  group('SM create witness', () {
    test('create witness verifies with merchant signature', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);

      var merchantFundingTx = getMerchantFundingTx();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerFundingTx = getCustomerFundingTx();

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400,
        customerFundingTx.hash,
      );

      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var witnessTx = service.createWitnessTxn(
        customerSigner,
        customerFundingTx,
        issuanceTx,
        hex.decode(merchantFundingTx.serialize()),
        customerPub,
        customerPubkeyHash,
        StateMachineAction.CREATE,
      );

      // Verify PP1_SM create witness (input[1])
      var scriptSig = witnessTx.inputs[1].script!;
      var scriptPubKey = issuanceTx.outputs[1].script;
      var interp = Interpreter();
      interp.correctlySpends(scriptSig, scriptPubKey, witnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one));
    });
  });

  group('SM enroll', () {
    test('enroll lifecycle: issue → create witness → enroll → enroll witness', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();

      // Step 1: Issue token
      var merchantFundingTx = getMerchantFundingTx();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerFundingTx = getCustomerFundingTx();

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400,
        customerFundingTx.hash,
      );

      // Step 2: Create witness (merchant signs, dispatches OP_0)
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);
      var createWitnessTx = service.createWitnessTxn(
        customerSigner,
        customerFundingTx,
        issuanceTx,
        hex.decode(merchantFundingTx.serialize()),
        customerPub,
        customerPubkeyHash,
        StateMachineAction.CREATE,
      );

      // Verify create witness passes interpreter
      expect(
          () => interp.correctlySpends(
              createWitnessTx.inputs[1].script!, issuanceTx.outputs[1].script,
              createWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Create witness should verify');

      // Step 3: Enroll (merchant signs, spending PP3 from issuance)
      var enrollFundingTx = getMerchantFundingTx(); // reuse for simplicity
      var enrollWitnessFundingTx = getCustomerFundingTx();
      var eventData = List<int>.generate(20, (i) => i + 0x10);

      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        enrollFundingTx, merchantSigner, merchantPub,
        enrollWitnessFundingTx.hash, eventData,
      );

      expect(enrollTx.outputs.length, 5); // change, PP1, PP2, PP3, metadata

      // Verify PP1_SM header in enroll tx
      var enrollPP1 = PP1SmLockBuilder.fromScript(enrollTx.outputs[1].script);
      expect(enrollPP1.currentState, 1); // ACTIVE
      expect(enrollPP1.milestoneCount, 0);
      expect(enrollPP1.merchantPKH, merchPKH);
      expect(enrollPP1.customerPKH, custPKH);

      // Verify commitment hash = SHA256(parentCH || SHA256(eventData))
      var parentCH = List<int>.filled(32, 0); // initial
      var eventDigest = crypto.sha256.convert(eventData).bytes;
      var expectedCH = crypto.sha256.convert([...parentCH, ...eventDigest]).bytes;
      expect(enrollPP1.commitmentHash, List<int>.from(expectedCH));

      // Verify PP3 spending (PartialWitness) in enroll tx
      expect(
          () => interp.correctlySpends(
              enrollTx.inputs[2].script!, issuanceTx.outputs[3].script,
              enrollTx, 2, verifyFlags, Coin.valueOf(issuanceTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in enroll should verify');

      // Step 4: Enroll witness (merchant signs PP1_SM with OP_1 dispatch)
      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner,
        enrollWitnessFundingTx,
        enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub,
        merchantPubkeyHash,
        StateMachineAction.ENROLL,
        eventData: eventData,
      );

      // Verify enroll witness PP1_SM spending passes interpreter
      expect(
          () => interp.correctlySpends(
              enrollWitnessTx.inputs[1].script!, enrollTx.outputs[1].script,
              enrollWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Enroll witness should verify PP1_SM spending');
    });
  });

  group('SM confirm', () {
    test('confirm lifecycle: issue → create → enroll → confirm (dual-sig)', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();

      // Step 1: Issue
      var merchantFundingTx = getMerchantFundingTx();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400,
        customerFundingTx.hash,
      );

      // Step 2: Create witness
      var createWitnessTx = service.createWitnessTxn(
        customerSigner, customerFundingTx, issuanceTx,
        hex.decode(merchantFundingTx.serialize()),
        customerPub, customerPubkeyHash,
        StateMachineAction.CREATE,
      );

      // Step 3: Enroll
      var enrollFundingTx = getMerchantFundingTx();
      var enrollWitnessFundingTx = getCustomerFundingTx();
      var enrollEventData = List<int>.generate(20, (i) => i + 0x10);

      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        enrollFundingTx, merchantSigner, merchantPub,
        enrollWitnessFundingTx.hash, enrollEventData,
      );

      // Step 4: Enroll witness
      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner, enrollWitnessFundingTx, enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub, merchantPubkeyHash,
        StateMachineAction.ENROLL,
        eventData: enrollEventData,
      );

      // Step 5: Confirm (dual-sig, ACTIVE→PROGRESSING)
      var confirmFundingTx = getMerchantFundingTx();
      var confirmWitnessFundingTx = getCustomerFundingTx();
      var milestoneData = List<int>.generate(16, (i) => i + 0x20);

      var confirmTx = service.createTransitionTxn(
        enrollWitnessTx, enrollTx, merchantPub,
        confirmFundingTx, merchantSigner, merchantPub,
        confirmWitnessFundingTx.hash,
        2, // POST-transition state: PROGRESSING
        custPKH, // customer remains next actor
        incrementMilestone: true,
        eventData: milestoneData,
      );

      expect(confirmTx.outputs.length, 5);
      var confirmPP1 = PP1SmLockBuilder.fromScript(confirmTx.outputs[1].script);
      expect(confirmPP1.currentState, 2);
      expect(confirmPP1.milestoneCount, 1);

      // Verify PP3 spending in confirm
      expect(
          () => interp.correctlySpends(
              confirmTx.inputs[2].script!, enrollTx.outputs[3].script,
              confirmTx, 2, verifyFlags, Coin.valueOf(enrollTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in confirm should verify');

      // Step 6: Confirm witness (dual-sig)
      var confirmWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        confirmWitnessFundingTx, confirmTx,
        hex.decode(enrollTx.serialize()),
        merchantPub, customerPub,
        merchantPubkeyHash,
        StateMachineAction.CONFIRM,
        milestoneData,
      );

      // Verify confirm witness PP1_SM spending
      expect(
          () => interp.correctlySpends(
              confirmWitnessTx.inputs[1].script!, confirmTx.outputs[1].script,
              confirmWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Confirm witness should verify PP1_SM spending');
    });
  });

  group('SM convert', () {
    test('convert lifecycle: ...confirm → convert (dual-sig)', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();

      // Abbreviated setup: issue → create → enroll → enroll witness → confirm → confirm witness
      var merchantFundingTx = getMerchantFundingTx();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerFundingTx = getCustomerFundingTx();
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);

      var issuanceTx = service.createTokenIssuanceTxn(
        merchantFundingTx, merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400, customerFundingTx.hash);

      var createWitnessTx = service.createWitnessTxn(
        customerSigner, customerFundingTx, issuanceTx,
        hex.decode(merchantFundingTx.serialize()),
        customerPub, customerPubkeyHash, StateMachineAction.CREATE);

      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, List<int>.generate(20, (i) => i));

      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub, merchantPubkeyHash, StateMachineAction.ENROLL,
        eventData: List<int>.generate(20, (i) => i));

      var confirmTx = service.createTransitionTxn(
        enrollWitnessTx, enrollTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash,
        2, custPKH, incrementMilestone: true,
        eventData: List<int>.generate(16, (i) => i + 0x20));

      var confirmWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), confirmTx,
        hex.decode(enrollTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONFIRM,
        List<int>.generate(16, (i) => i + 0x20));

      // Step: Convert (PROGRESSING→CONVERTING, dual-sig)
      var conversionData = List<int>.generate(12, (i) => i + 0x30);
      var convertTx = service.createTransitionTxn(
        confirmWitnessTx, confirmTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash,
        3, // POST-transition: CONVERTING
        merchPKH, // merchant takes over for settlement phase
        eventData: conversionData);

      var convertPP1 = PP1SmLockBuilder.fromScript(convertTx.outputs[1].script);
      expect(convertPP1.currentState, 3);
      expect(convertPP1.milestoneCount, 1); // unchanged from confirm

      // Verify PP3 spending
      expect(
          () => interp.correctlySpends(
              convertTx.inputs[2].script!, confirmTx.outputs[3].script,
              convertTx, 2, verifyFlags, Coin.valueOf(confirmTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in convert should verify');

      // Convert witness (dual-sig)
      var convertWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), convertTx,
        hex.decode(confirmTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONVERT, conversionData);

      expect(
          () => interp.correctlySpends(
              convertWitnessTx.inputs[1].script!, convertTx.outputs[1].script,
              convertWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Convert witness should verify PP1_SM spending');
    });
  });

  group('SM settle', () {
    test('settle lifecycle: ...convert → settle (single-sig, 7-output)', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();

      // Setup: issue → create → enroll → enroll witness → confirm → confirm witness → convert → convert witness
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);

      var issuanceTx = service.createTokenIssuanceTxn(
        getMerchantFundingTx(), merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400, getCustomerFundingTx().hash);

      var createWitnessTx = service.createWitnessTxn(
        customerSigner, getCustomerFundingTx(), issuanceTx,
        hex.decode(getMerchantFundingTx().serialize()),
        customerPub, customerPubkeyHash, StateMachineAction.CREATE);

      var enrollEventData = List<int>.generate(20, (i) => i);
      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, enrollEventData);

      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub, merchantPubkeyHash, StateMachineAction.ENROLL,
        eventData: enrollEventData);

      var milestoneData = List<int>.generate(16, (i) => i + 0x20);
      var confirmTx = service.createTransitionTxn(
        enrollWitnessTx, enrollTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, 2, custPKH,
        incrementMilestone: true, eventData: milestoneData);

      var confirmWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), confirmTx,
        hex.decode(enrollTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONFIRM, milestoneData);

      var conversionData = List<int>.generate(12, (i) => i + 0x30);
      var convertTx = service.createTransitionTxn(
        confirmWitnessTx, confirmTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, 3, merchPKH,
        eventData: conversionData);

      var convertWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), convertTx,
        hex.decode(confirmTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONVERT, conversionData);

      // Step: Settle (CONVERTING→SETTLED, single-sig, 7-output)
      var settlementData = List<int>.generate(10, (i) => i + 0x40);
      var custRewardAmount = BigInt.from(1000);
      var merchPayAmount = BigInt.from(2000);
      var settleTx = service.createSettleTxn(
        convertWitnessTx, convertTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash,
        custRewardAmount, merchPayAmount,
        eventData: settlementData);

      // Settle tx has 7 outputs: change(0), custReward(1), merchPay(2),
      //   PP1(3), PP2(4), PP3(5), metadata(6)
      expect(settleTx.outputs.length, 7);
      var settlePP1 = PP1SmLockBuilder.fromScript(settleTx.outputs[3].script);
      expect(settlePP1.currentState, 4);

      // Verify PP3 spending (PP3 from convertTx is at output 3)
      expect(
          () => interp.correctlySpends(
              settleTx.inputs[2].script!, convertTx.outputs[3].script,
              settleTx, 2, verifyFlags, Coin.valueOf(convertTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in settle should verify');

      // Settle witness (single-sig, PP1 at output 3, PP2 at output 4)
      var settleWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), settleTx,
        hex.decode(convertTx.serialize()),
        merchantPub, merchantPubkeyHash,
        StateMachineAction.SETTLE,
        eventData: settlementData,
        custRewardAmount: custRewardAmount,
        merchPayAmount: merchPayAmount,
        pp1OutputIndex: 3,
        pp2OutputIndex: 4);

      expect(
          () => interp.correctlySpends(
              settleWitnessTx.inputs[1].script!, settleTx.outputs[3].script,
              settleWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Settle witness should verify PP1_SM spending');
    });
  });

  group('SM timeout', () {
    test('timeout lifecycle: ...enroll → timeout (single-sig, 6-output)', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();

      // Setup: issue → create → enroll → enroll witness
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);

      var issuanceTx = service.createTokenIssuanceTxn(
        getMerchantFundingTx(), merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400, getCustomerFundingTx().hash);

      var createWitnessTx = service.createWitnessTxn(
        TransactionSigner(sigHashAll, customerPrivateKey),
        getCustomerFundingTx(), issuanceTx,
        hex.decode(getMerchantFundingTx().serialize()),
        customerPub, customerPubkeyHash, StateMachineAction.CREATE);

      var enrollEventData = List<int>.generate(20, (i) => i);
      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, enrollEventData);

      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub, merchantPubkeyHash, StateMachineAction.ENROLL,
        eventData: enrollEventData);

      // Timeout (ENROLLED→EXPIRED, single-sig, 6-output)
      var refundAmount = BigInt.from(1500);
      var timeoutNLockTime = 86400; // must be >= timeoutDelta
      var timeoutTx = service.createTimeoutTxn(
        enrollWitnessTx, enrollTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash,
        refundAmount, timeoutNLockTime);

      // Timeout tx has 6 outputs: change(0), merchRefund(1), PP1(2), PP2(3), PP3(4), metadata(5)
      expect(timeoutTx.outputs.length, 6);
      var timeoutPP1 = PP1SmLockBuilder.fromScript(timeoutTx.outputs[2].script);
      expect(timeoutPP1.currentState, 5);
      expect(timeoutTx.nLockTime, timeoutNLockTime);

      // Verify PP3 spending (PP3 from enrollTx is at output 3)
      expect(
          () => interp.correctlySpends(
              timeoutTx.inputs[2].script!, enrollTx.outputs[3].script,
              timeoutTx, 2, verifyFlags, Coin.valueOf(enrollTx.outputs[3].satoshis)),
          returnsNormally,
          reason: 'PartialWitness spending in timeout should verify');

      // Timeout witness (single-sig, PP1 at output 2, PP2 at output 3)
      var timeoutWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), timeoutTx,
        hex.decode(enrollTx.serialize()),
        merchantPub, merchantPubkeyHash,
        StateMachineAction.TIMEOUT,
        refundAmount: refundAmount,
        nLockTime: timeoutNLockTime,
        pp1OutputIndex: 2,
        pp2OutputIndex: 3);

      expect(
          () => interp.correctlySpends(
              timeoutWitnessTx.inputs[1].script!, timeoutTx.outputs[2].script,
              timeoutWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally,
          reason: 'Timeout witness should verify PP1_SM spending');
    });
  });

  group('SM full lifecycle', () {
    test('create → enroll → confirm → convert → settle → burn', () {
      var service = StateMachineTool();
      var merchPKH = hex.decode(merchantPubkeyHash);
      var custPKH = hex.decode(customerPubkeyHash);
      var interp = Interpreter();
      var merchantSigner = TransactionSigner(sigHashAll, merchantPrivateKey);
      var customerSigner = TransactionSigner(sigHashAll, customerPrivateKey);

      // Step 1: Issue (CREATE state)
      var issuanceTx = service.createTokenIssuanceTxn(
        getMerchantFundingTx(), merchantSigner, merchantPub, merchantAddress,
        merchPKH, custPKH, 0x3F, 86400, getCustomerFundingTx().hash);
      var issuePP1 = PP1SmLockBuilder.fromScript(issuanceTx.outputs[1].script);
      expect(issuePP1.currentState, 0, reason: 'Issue: state=CREATED');

      // Step 2: Create witness
      var createWitnessTx = service.createWitnessTxn(
        customerSigner, getCustomerFundingTx(), issuanceTx,
        hex.decode(getMerchantFundingTx().serialize()),
        customerPub, customerPubkeyHash, StateMachineAction.CREATE);
      expect(
          () => interp.correctlySpends(
              createWitnessTx.inputs[1].script!, issuanceTx.outputs[1].script,
              createWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally, reason: 'Create witness');

      // Step 3: Enroll (CREATED→ENROLLED)
      var enrollEventData = List<int>.generate(20, (i) => i);
      var enrollTx = service.createEnrollTxn(
        createWitnessTx, issuanceTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, enrollEventData);
      var enrollPP1 = PP1SmLockBuilder.fromScript(enrollTx.outputs[1].script);
      expect(enrollPP1.currentState, 1, reason: 'Enroll: state=ENROLLED');

      // Step 4: Enroll witness
      var enrollWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), enrollTx,
        hex.decode(issuanceTx.serialize()),
        merchantPub, merchantPubkeyHash, StateMachineAction.ENROLL,
        eventData: enrollEventData);
      expect(
          () => interp.correctlySpends(
              enrollWitnessTx.inputs[1].script!, enrollTx.outputs[1].script,
              enrollWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally, reason: 'Enroll witness');

      // Step 5: Confirm (ENROLLED→PROGRESSING, dual-sig, milestone++)
      var milestoneData = List<int>.generate(16, (i) => i + 0x20);
      var confirmTx = service.createTransitionTxn(
        enrollWitnessTx, enrollTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, 2, custPKH,
        incrementMilestone: true, eventData: milestoneData);
      var confirmPP1 = PP1SmLockBuilder.fromScript(confirmTx.outputs[1].script);
      expect(confirmPP1.currentState, 2, reason: 'Confirm: state=PROGRESSING');
      expect(confirmPP1.milestoneCount, 1, reason: 'Confirm: milestone=1');

      // Step 6: Confirm witness (dual-sig)
      var confirmWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), confirmTx,
        hex.decode(enrollTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONFIRM, milestoneData);
      expect(
          () => interp.correctlySpends(
              confirmWitnessTx.inputs[1].script!, confirmTx.outputs[1].script,
              confirmWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally, reason: 'Confirm witness');

      // Step 7: Convert (PROGRESSING→CONVERTING, dual-sig)
      var conversionData = List<int>.generate(12, (i) => i + 0x30);
      var convertTx = service.createTransitionTxn(
        confirmWitnessTx, confirmTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash, 3, merchPKH,
        eventData: conversionData);
      var convertPP1 = PP1SmLockBuilder.fromScript(convertTx.outputs[1].script);
      expect(convertPP1.currentState, 3, reason: 'Convert: state=CONVERTING');

      // Step 8: Convert witness (dual-sig)
      var convertWitnessTx = service.createDualWitnessTxn(
        merchantSigner, customerPrivateKey,
        getCustomerFundingTx(), convertTx,
        hex.decode(confirmTx.serialize()),
        merchantPub, customerPub, merchantPubkeyHash,
        StateMachineAction.CONVERT, conversionData);
      expect(
          () => interp.correctlySpends(
              convertWitnessTx.inputs[1].script!, convertTx.outputs[1].script,
              convertWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally, reason: 'Convert witness');

      // Step 9: Settle (CONVERTING→SETTLED, single-sig, 7-output)
      var settlementData = List<int>.generate(10, (i) => i + 0x40);
      var custRewardAmount = BigInt.from(1000);
      var merchPayAmount = BigInt.from(2000);
      var settleTx = service.createSettleTxn(
        convertWitnessTx, convertTx, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        getCustomerFundingTx().hash,
        custRewardAmount, merchPayAmount,
        eventData: settlementData);
      var settlePP1 = PP1SmLockBuilder.fromScript(settleTx.outputs[3].script);
      expect(settlePP1.currentState, 4, reason: 'Settle: state=SETTLED');
      expect(settleTx.outputs.length, 7, reason: 'Settle: 7 outputs');

      // Step 10: Settle witness
      var settleWitnessTx = service.createWitnessTxn(
        merchantSigner, getCustomerFundingTx(), settleTx,
        hex.decode(convertTx.serialize()),
        merchantPub, merchantPubkeyHash,
        StateMachineAction.SETTLE,
        eventData: settlementData,
        custRewardAmount: custRewardAmount,
        merchPayAmount: merchPayAmount,
        pp1OutputIndex: 3, pp2OutputIndex: 4);
      expect(
          () => interp.correctlySpends(
              settleWitnessTx.inputs[1].script!, settleTx.outputs[3].script,
              settleWitnessTx, 1, verifyFlags, Coin.valueOf(BigInt.one)),
          returnsNormally, reason: 'Settle witness');

      // Step 11: Burn (SETTLED→burned, owner spends with P2PKH)
      // After settle: PP1 at 3, PP2 at 4, PP3 at 5
      var burnTx = service.createBurnTokenTxn(
        settleTx, merchantSigner, merchantPub,
        getMerchantFundingTx(), merchantSigner, merchantPub,
        pp1OutputIndex: 3, pp2OutputIndex: 4, pp3OutputIndex: 5);
      expect(
          () => interp.correctlySpends(
              burnTx.inputs[1].script!, settleTx.outputs[3].script,
              burnTx, 1, verifyFlags, Coin.valueOf(settleTx.outputs[3].satoshis)),
          returnsNormally, reason: 'Burn should spend PP1_SM');
    });
  });
}
