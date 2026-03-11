import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

var aliceWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey alicePrivateKey = SVPrivateKey.fromWIF(aliceWif);
SVPublicKey alicePubKey = alicePrivateKey.publicKey;
var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
var alicePubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

Transaction getBobFundingTx() {
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

Transaction getAliceFundingTx() {
  var rawTx =
      "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";
  return Transaction.fromHex(rawTx);
}

/// Opcode name lookup for readable output.
String opName(int op) {
  const names = {
    0: 'OP_0', 76: 'OP_PUSHDATA1', 77: 'OP_PUSHDATA2', 78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE', 81: 'OP_1', 82: 'OP_2', 83: 'OP_3', 84: 'OP_4',
    85: 'OP_5', 86: 'OP_6', 87: 'OP_7', 88: 'OP_8', 89: 'OP_9',
    90: 'OP_10', 91: 'OP_11', 92: 'OP_12', 93: 'OP_13', 94: 'OP_14',
    95: 'OP_15', 96: 'OP_16',
    97: 'OP_NOP', 99: 'OP_IF', 100: 'OP_NOTIF', 103: 'OP_ELSE',
    104: 'OP_ENDIF', 105: 'OP_VERIFY', 106: 'OP_RETURN',
    107: 'OP_TOALTSTACK', 108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP', 110: 'OP_2DUP', 111: 'OP_3DUP',
    112: 'OP_2OVER', 113: 'OP_2ROT', 114: 'OP_2SWAP',
    115: 'OP_IFDUP', 116: 'OP_DEPTH', 117: 'OP_DROP', 118: 'OP_DUP',
    119: 'OP_NIP', 120: 'OP_OVER', 121: 'OP_PICK', 122: 'OP_ROLL',
    123: 'OP_ROT', 124: 'OP_SWAP', 125: 'OP_TUCK',
    126: 'OP_CAT', 127: 'OP_SPLIT', 128: 'OP_NUM2BIN', 129: 'OP_BIN2NUM',
    130: 'OP_SIZE',
    135: 'OP_EQUAL', 136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD', 140: 'OP_1SUB', 141: 'OP_2MUL', 142: 'OP_2DIV',
    143: 'OP_NEGATE', 144: 'OP_ABS', 145: 'OP_NOT', 146: 'OP_0NOTEQUAL',
    147: 'OP_ADD', 148: 'OP_SUB', 149: 'OP_MUL', 150: 'OP_DIV',
    151: 'OP_MOD', 152: 'OP_LSHIFT', 153: 'OP_RSHIFT',
    154: 'OP_BOOLAND', 155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL', 157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN', 160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL', 162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN', 164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160', 167: 'OP_SHA1', 168: 'OP_SHA256',
    169: 'OP_HASH160', 170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR', 172: 'OP_CHECKSIG', 173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG', 175: 'OP_CHECKMULTISIGVERIFY',
  };
  if (op >= 1 && op <= 75) return 'PUSH_${op}B';
  return names[op] ?? 'OP_$op';
}

/// Compact representation of a stack item.
String stackItemStr(List<int> item) {
  if (item.isEmpty) return '[]';
  var h = hex.encode(item);
  if (h.length <= 16) return '${item.length}B:$h';
  return '${item.length}B:${h.substring(0, 8)}..${h.substring(h.length - 8)}';
}

/// Ring buffer that keeps the last N trace entries.
class ScriptTracer {
  final int capacity;
  final List<String> _entries = [];

  ScriptTracer({this.capacity = 30});

  void record(int chunkIdx, int opcode, List<List<int>> stack, List<List<int>> altstack) {
    var stackStr = stack.reversed.map(stackItemStr).join(', ');
    var altStr = altstack.reversed.map(stackItemStr).join(', ');
    var entry = '[${chunkIdx.toString().padLeft(4)}] ${opName(opcode).padRight(18)} '
        'stk(${stack.length}): [$stackStr]  alt(${altstack.length}): [$altStr]';
    _entries.add(entry);
    if (_entries.length > capacity) {
      _entries.removeAt(0);
    }
  }

  void dump() {
    print('\n=== SCRIPT TRACE (last ${_entries.length} ops) ===');
    for (var e in _entries) {
      print(e);
    }
    print('=== END TRACE ===\n');
  }
}

void main() {
  test('Diagnostic: standard transfer + interpreter verify with trace',
      timeout: Timeout(Duration(minutes: 2)), () async {
    var service = FungibleTokenTool();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);

    // Step 1: Mint
    var bobFundingTx = getBobFundingTx();
    var mintTx = await service.createFungibleMintTxn(
      bobFundingTx, bobFundingSigner, bobPub, bobAddress,
      bobFundingTx.hash, 1000,
    );
    var pp1FtLock = PP1FtLockBuilder.fromScript(mintTx.outputs[1].script);
    var tokenId = pp1FtLock.tokenId;

    // Step 2: Mint witness
    var mintWitnessTx = service.createFungibleWitnessTxn(
      bobFundingSigner, bobFundingTx, mintTx, bobPub, bobPubkeyHash,
      FungibleTokenAction.MINT,
    );

    // Step 3: Transfer
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx();
    var transferTx = service.createFungibleTransferTxn(
      mintWitnessTx, mintTx, bobPub, aliceAddress,
      transferFundingTx, bobFundingSigner, bobPub,
      aliceFundingTx.hash, tokenId, 1000,
    );

    // Step 4: Transfer witness
    var aliceWitnessTx = service.createFungibleWitnessTxn(
      aliceFundingSigner, aliceFundingTx, transferTx,
      alicePubKey, bobPubkeyHash,
      FungibleTokenAction.TRANSFER,
      parentTokenTxBytes: hex.decode(mintTx.serialize()),
      parentOutputCount: 5,
    );

    print('Transfer tx outputs: ${transferTx.outputs.length}');
    print('Transfer tx inputs: ${transferTx.inputs.length}');
    print('PP1_FT script length: ${transferTx.outputs[1].script.buffer.length}');

    // Step 5: Verify PP1_FT spending with trace
    var interp = Interpreter();
    var tracer = ScriptTracer(capacity: 150);
    interp.traceCallback = tracer.record;

    var verifyFlags = {VerifyFlag.SIGHASH_FORKID, VerifyFlag.LOW_S, VerifyFlag.UTXO_AFTER_GENESIS};

    try {
      interp.correctlySpends(
          aliceWitnessTx.inputs[1].script!, transferTx.outputs[1].script,
          aliceWitnessTx, 1, verifyFlags, Coin.valueOf(transferTx.outputs[1].satoshis));
      print('PP1_FT transferToken spending PASSED');
    } catch (e) {
      print('PP1_FT transferToken spending FAILED: $e');
      tracer.dump();
    }
  });
}
