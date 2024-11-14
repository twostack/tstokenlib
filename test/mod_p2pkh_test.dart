

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

  //  <pubkey> <sig> OP_0 20 0x650c4adb156f19e36a755c820d892cda108299c4 OP_NIP OP_2 OP_PICK OP_HASH160 OP_OVER OP_EQUALVERIFY OP_OVER OP_3 OP_PICK OP_CHECKSIG OP_NIP OP_NIP OP_NIP

  // <pubkey> <sig> OP_SWAP OP_DUP OP_HASH160 20 0x650c4adb156f19e36a755c820d892cda108299c4 OP_EQUALVERIFY OP_CHECKSIG

  //<sig> <pubkey> OP_DUP OP_HASH160 20 0x650c4adb156f19e36a755c820d892cda108299c4 OP_EQUALVERIFY OP_CHECKSIG

}
