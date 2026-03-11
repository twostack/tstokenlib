import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:tstokenlib/src/crypto/rabin.dart';
import 'package:collection/collection.dart';

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);

Transaction getBobFundingTx() {
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";
  return Transaction.fromHex(rawTx);
}

void main(){

  Function listEquals = ListEquality().equals;

  test("PP1Lockbuilder can parse an issuance PP1 script", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
    var fundingTx = getBobFundingTx();
    var fundingTxSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var rabinPubKeyHash = hash160(Rabin.bigIntToScriptNum(Rabin.generateKeyPair(512).n).toList());
    var issuanceTx = await service.createTokenIssuanceTxn(fundingTx, fundingTxSigner, bobPub, bobAddress, fundingTx.hash, rabinPubKeyHash);

    var issuancePP1Script = issuanceTx.outputs[1].script;
    var pp1Locker = PP1NftLockBuilder.fromScript(issuancePP1Script);

    expect(listEquals(pp1Locker.getScriptPubkey().buffer, issuancePP1Script.buffer), true);
  });
}
