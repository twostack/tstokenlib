

import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/src/builder/mod_p2pkh_builder.dart';

import 'plugpoint_spending_test.dart';

void main(){
  var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
  SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
  var bobPub = bobPrivateKey.publicKey;
  Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);

  test('dump the script', (){

    var builder = ModP2PKHLockBuilder.fromAddress(bobAddress);
    print(builder.getScriptPubkey().toString(type: 'hex'));

    var builder2 = P2PKHLockBuilder.fromAddress(bobAddress);
    print(builder2.getScriptPubkey().toString(type: 'hex'));
  });
}
