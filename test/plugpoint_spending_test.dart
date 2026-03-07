import 'dart:convert';
import 'dart:typed_data';

import 'package:buffer/buffer.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:tstokenlib/tstokenlib.dart';
import 'package:collection/collection.dart';

/**
 * NOTE: Running these tests will dump a lot of debug information to the terminal.
 *       This information is useful for sCrypt contract debugging using the classic sCrypt IDE
 */

var bobWif = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
SVPrivateKey bobPrivateKey = SVPrivateKey.fromWIF(bobWif);
var bobPub = bobPrivateKey.publicKey;
Address bobAddress = Address.fromPublicKey(bobPub, NetworkType.TEST);
var bobAddressString = "mpjFGX8CRr57qaGZKibryf1VqSwGQL5Khp";
var bobPubkeyHex = "0330aff1a7e5417393f90eb1bf221c86686e0e3ba25d2696aaa20da549b7d4b3f9";
var bobPubkeyHash = "650c4adb156f19e36a755c820d892cda108299c4";

var aliceWif = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
SVPrivateKey alicePrivateKey = SVPrivateKey.fromWIF(aliceWif);
SVPublicKey alicePubKey = alicePrivateKey.publicKey;
var aliceAddress = Address.fromPublicKey(alicePubKey, NetworkType.TEST);
var aliceAddressString = "n3vkuf1YPY3QRXx3kaLF6p8QhgWDZ2zg8F";
var alicePubkeyHex = "03afc7c94f8dd7cf7f7ab1e6b2334f26d930f27f01fad77dba260713e18a9d7f1f";

var alicePubkeyHash = "f5d33ee198ad13840ce410ba96e149e463a6c352";

var charlieWif = "cTTE1z7xTDxnpzCqC1q3fPafSQsMzgpQYT1ctb6QAj6Wrj6uYhog";
SVPrivateKey charliePrivateKey = SVPrivateKey.fromWIF(charlieWif);
SVPublicKey charliePubKey = charliePrivateKey.publicKey;
var charlieAddress = Address.fromPublicKey(charliePubKey, NetworkType.TEST);
var charliePubkeyHash = charlieAddress.pubkeyHash160;

var issuerWif = "cQt5q5kwkiuMqQfqbc315eC3rrj3aT4Qe5htpsf9hBPhCvsZeJjA";
SVPrivateKey issuerPrivateKey = SVPrivateKey.fromWIF(issuerWif);
var issuerAddress = Address.fromPublicKey(issuerPrivateKey.publicKey, NetworkType.TEST);
var issuerAddressString = "n2rR1qiq5U1ruQQrT6RMThgJr3UAkSRrT3";
var issuerPubkeyHex = "030991b2fb68f90642aa0eaab640f736ad9095872e57cf4b2c63f62253fc33b72d";
var issuerPubkeyHash = "ea08d98fe6d46d3cced28b6510d35542f21dd2ec";

Transaction getBobFundingTx() {
//rawTx hash 10 bitcoins locked to bob's address in output [1]
  var rawTx =
      "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

  return Transaction.fromHex(rawTx);
}

Transaction getAliceFundingTx() {
  //rawTx hash 10 bitcoins locked to alices's address in output [1]
  var rawTx =
      "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";

  return Transaction.fromHex(rawTx);
}

Transaction getTokenTxWithPP1andPP2(Transaction witnessFundingTx, Address ownerAddress, List<int> witnessOwnerPKH,
    List<int> witnessChangePKH, int witnessChangeAmount, TransactionSigner? tokenSigner, Transaction? prevTokenTx) {
  var fundingTx = getBobFundingTx();
  var fundingUnlocker = P2PKHUnlockBuilder(bobPrivateKey.publicKey);
  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
  var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
  var tokenTxBuilder = TransactionBuilder();

  //fund the txn
  tokenTxBuilder.spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
  tokenTxBuilder.withFeePerKb(1);

  //create PP1 Outpoint
  var pp1Locker = PP1LockBuilder(
      ownerAddress, hex.decode(witnessFundingTx.id).reversed.toList()); //tokenId is incorrect. issuance vs transfer !
  tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

  var outputWriter = ByteDataWriter();
  outputWriter.write(hex.decode(witnessFundingTx.id).reversed.toList()); //32 byte txid
  outputWriter.writeUint32(1, Endian.little);
  var fundingOutpoint = outputWriter.toBytes();
  // println("Witness Funding Outpoint : ${Hex.toHexString(fundingOutpoint)}")

  //create PP2 Outpoint
  var pp2Locker = PP2LockBuilder(fundingOutpoint, witnessChangePKH, witnessChangeAmount, hex.decode(ownerAddress.pubkeyHash160));
  tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

  //generate change address (might not be required for this testcase)
  //we are neglecting PP3 output in this testcase
  tokenTxBuilder.sendChangeToPKH(bobAddress);

  if (prevTokenTx != null && tokenSigner != null) {
    tokenTxBuilder.spendFromTxnWithSigner(
        tokenSigner, prevTokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
  }

  return tokenTxBuilder.build(false);
}

Transaction getTokenTxWithPP1andPP2andPP3(Transaction witnessFundingTx, Address ownerAddress,
    List<int> witnessChangePKH, int witnessChangeAmount, TransactionSigner? tokenSigner, Transaction? prevTokenTx) {
  var fundingTx = getBobFundingTx();
  var fundingUnlocker = P2PKHUnlockBuilder(bobPrivateKey.publicKey);
  var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
  var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
  var tokenTxBuilder = TransactionBuilder();

  //fund the txn
  tokenTxBuilder.spendFromTxnWithSigner(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
  // tokenTxBuilder.withFeePerKb(50);
  tokenTxBuilder.withFee(BigInt.from(220));

  List<int> tokenId;

  if (prevTokenTx == null) {
    tokenId = hex.decode(witnessFundingTx.id).reversed.toList();
  } else {
    tokenId = hex.decode(prevTokenTx.id).reversed.toList();
  }

  //create PP1 Outpoint
  var pp1Locker = PP1LockBuilder(ownerAddress, tokenId);
  tokenTxBuilder.spendToLockBuilder(pp1Locker, BigInt.one);

  var outputWriter = ByteDataWriter();
  outputWriter.write(hex.decode(witnessFundingTx.id).reversed.toList()); //32 byte txid in txFormat
  outputWriter.writeUint32(1, Endian.little);
  var fundingOutpoint = outputWriter.toBytes();
  print("Witness Funding Outpoint : ${hex.encode(fundingOutpoint)}");

  var pp2Locker = PP2LockBuilder(fundingOutpoint, witnessChangePKH, witnessChangeAmount, hex.decode(ownerAddress.pubkeyHash160));
  tokenTxBuilder.spendToLockBuilder(pp2Locker, BigInt.one);

  var shaLocker = PartialWitnessLockBuilder(hex.decode(ownerAddress.pubkeyHash160));
  var asmCode = shaLocker.script?.toString(type: 'asm');
//        println(Hex.toHexString(shaLocker.lockingScript.program))
  tokenTxBuilder.spendToLockBuilder(shaLocker, BigInt.one);

  tokenTxBuilder.sendChangeToPKH(bobAddress);

  if (prevTokenTx != null) {
    //FIXME: This should third spend, from output index 3 in token Txn
    tokenTxBuilder.spendFromTxnWithSigner(
        tokenSigner!, prevTokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
  }

  return tokenTxBuilder.build(false);
}

void main() {

  //this witnessHex has been pre-computed to be properly padded so that a partialSha256
  // calculation will result in the last 128 bytes starting with the last input in the Witness Txn
  test('can compute IV and remainder of preimage', () async {
    var witnessHex = "0200000003e9d435484e35b5576833c61acf056d4b610da70bc27b7fcc13a9298bcd86e555010000006a473044022018dcf6c4814d61aa5b17462ae35364fe63cf7260341a620e3ec38f49d35950f702207ea49523484c8645419ed8fd0c4eb956715ff6b945e437b6d9ca725c4a4621f541210330aff1a7e5417393f90eb1bf221c86686e0e3ba25d2696aaa20da549b7d4b3f9ffffffffc80db3d437c037a03e98e022312f2f686f314a9cbfb2012f4b31c312079e9d1901000000fdfd204d9e200200000045d87a19351a351e8a472d9dfee6cd5a1286040584d36d0635c267e21df44ac682a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8c80db3d437c037a03e98e022312f2f686f314a9cbfb2012f4b31c312079e9d1901000000fdff1f0176018801a901ac5101402097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c000014650c4adb156f19e36a755c820d892cda108299c420e9d435484e35b5576833c61acf056d4b610da70bc27b7fcc13a9298bcd86e555615179547a75537a537a537a0079537a75527a527a7575615b790087635e7961007956795679210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081058795d795d7985615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a7561695c79827700a0695e7961007901687f7501447f77517a756101207f755e795154615179517951938000795179827751947f75007f77517a75517a75517a75617e51795154615179517951938000795179827751947f75007f77517a75517a75517a75617e52795254615179517951938000795179827751947f75007f77517a75517a75517a75617e527952797e51797e0079a8a801147961007901247f75547f77517a7561007952798777777777777777777777777777777777777777777777675b795187635d79827700a0695c79827700a06901147961007956795679210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081058795d795d7985615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a756169011279a9527987695d795161545279517951937f7551797f7761007901007e81517a756151795193527a75517a0000527953a169610053799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a756868687568615153799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a756868687568615253799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a7568686875685579547951937f7554797f7761007901007e81517a756154795193557a75547a547a547a547a007954a169610051799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868680059799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615151799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685159799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615251799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685259799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615351799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685359799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a687575756851795379527a75527a75527a75527a75527a75527a75527a75615f795361545279517951937f7551797f7761007901007e81517a756151795193527a75517a0000527953a169610053799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a756868687568615153799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a756868687568615253799f635379012493547a75537a537a537a5579547951937f7554797f7761007901007e81517a7561007902fd009f630079557951935179935493567a75557a557a557a557a557a7567007902fd009c635679557953937f75557951937f7761007901007e81517a7561557953935179935493567a75557a557a557a557a557a7567007902fe009c635679557955937f75557951937f7761007901007e81517a7561557955935179935493567a75557a557a557a557a557a75675679557959937f75557951937f7761007901007e81517a7561557959935179935493567a75557a557a557a557a557a7568686875685579547951937f7554797f7761007901007e81517a756154795193557a75547a547a547a547a007954a169610051799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868680059799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615151799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685159799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615251799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685259799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a6875757568615351799f635679557958937f7555797f7761007901007e81517a756155795893567a75557a557a557a557a557a5779567951937f7556797f7701007e61007901007e81517a756100517902fd009f635179517a7557795193517993587a75577a577a577a577a577a577a577a67517902fd009c635979587953937f75587951937f7761007901007e81517a7561517a7557795393517993587a75577a577a577a577a577a577a577a67517902fe009c635979587955937f75587951937f7761007901007e81517a7561517a7557795593517993587a75577a577a577a577a577a577a577a675979587959937f75587951937f7761007901007e81517a7561517a7557795993517993587a75577a577a577a577a577a577a577a6868685359799c63597958797f7558795279947f77567a75557a557a557a557a557a5279557a75547a547a547a547a687575756851795379527a75527a75527a75527a75527a75527a75527a756101187961007901687f776100005279517f75007f77007901fd87635379537f75517f7761007901007e81517a7561537a75527a527a5379535479937f75537f77527a75517a67007901fe87635379557f75517f7761007901007e81517a7561537a75527a527a5379555479937f75557f77527a75517a67007901ff87635379597f75517f7761007901007e81517a7561537a75527a527a5379595479937f75597f77527a75517a675379517f75007f7761007901007e81517a7561537a75527a527a5379515479937f75517f77527a75517a6868685179517a75517a75517a75517a7561517a75610116796160795f797e01147e51797e60797e5e797e517a7561007901177961007958805279610079827700517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a756152795161007958805279610079827700517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a756154795161007958805279610079827700517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a7568686868007953797e517a75517a75517a75617e517a75517a7561011779546100517902fd009f63517951615179517951938000795179827751947f75007f77517a75517a75517a7561517a75675179030000019f6301fd527952615179517951938000795179827751947f75007f77517a75517a75517a75617e517a756751790500000000019f6301fe527954615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75675179090000000000000000019f6301ff527958615179517951938000795179827751947f75007f77517a75517a75517a75617e517a75686868680079517a75517a75617e53797e52797e011d797e51797e011e7961007961007982775179517954947f75517958947f77517a75517a756161007901007e81517a7561517a756154615179517951938000795179827751947f75007f77517a75517a75517a75617e0079a8a8011f7961007901687f7501447f77517a756101207f755179517987695a79007901727f755f797e51790286007f777e00795a7987695479526100545379517951937f7551797f7761007901007e81517a756151795193527a75517a007953a169610051799f630054799c63547952790124937f7552797f77537a75527a527a685179012493527a75517a5479527951937f7552797f7761007901007e81517a7561007902fd009f630079537951935179935493547a75537a537a537a7567007902fd009c635579537953937f75537951937f7761007901007e81517a7561537953935179935493547a75537a537a537a7567007902fe009c635579537955937f75537951937f7761007901007e81517a7561537955935179935493547a75537a537a537a75675579537959937f75537951937f7761007901007e81517a7561537959935179935493547a75537a537a537a756868687568615151799f635154799c63547952790124937f7552797f77537a75527a527a685179012493527a75517a5479527951937f7552797f7761007901007e81517a7561007902fd009f630079537951935179935493547a75537a537a537a7567007902fd009c635579537953937f75537951937f7761007901007e81517a7561537953935179935493547a75537a537a537a7567007902fe009c635579537955937f75537951937f7761007901007e81517a7561537955935179935493547a75537a537a537a75675579537959937f75537951937f7761007901007e81517a7561537959935179935493547a75537a537a537a756868687568615251799f635254799c63547952790124937f7552797f77537a75527a527a685179012493527a75517a5479527951937f7552797f7761007901007e81517a7561007902fd009f630079537951935179935493547a75537a537a537a7567007902fd009c635579537953937f75537951937f7761007901007e81517a7561537953935179935493547a75537a537a537a7567007902fe009c635579537955937f75537951937f7761007901007e81517a7561537955935179935493547a75537a537a537a75675579537959937f75537951937f7761007901007e81517a7561537959935179935493547a75537a537a537a7568686875685279517a75517a75517a75517a75517a7561011c79a8a8517901207f7551798777777777777777777777777777777777777777777777777777777777777777777777777777675b795287635d79a9527987695c795e79ac777777777777777777777777777767006868680100000000000000ffffffff31a04148c4e5b108c9bb92f00500bf51d091a2c5e823d595caa23155cfe916aa000000004100000020e9d435484e35b5576833c61acf056d4b610da70bc27b7fcc13a9298bcd86e5553900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffc80db3d437c037a03e98e022312f2f686f314a9cbfb2012f4b31c312079e9d19020000002120c80db3d437c037a03e98e022312f2f686f314a9cbfb2012f4b31c312079e9d19ffffffff0101000000000000001a7c76a914650c4adb156f19e36a755c820d892cda108299c488ac00000000";

    var tx = Transaction.fromHex(witnessHex);
    var witnessPreImage = hex.decode(witnessHex);

    var utils = TransactionUtils();

    var (iv, remainder) = utils.computePartialHash(witnessPreImage, 2);

    //assert that last 128 bytes actually contain the last input of witness, along with the output
    var lastBlocks = ByteDataReader();

    //lastBlocks should now contain the last Input of the Txn, and the ONE output after "remainder" is added
    //let's use the ByteDataReader() to incrementally read the Input and Output data
    lastBlocks.add(remainder);
    var txInput = TransactionInput.fromReader(lastBlocks);

    lastBlocks.readUint8(); //skip one byte for numInputs

    var txOutput = TransactionOutput.fromReader(lastBlocks);

    //assert that the last input matches
    expect(ListEquality().equals(tx.inputs[2].serialize(), txInput.serialize()), true);

    //assert that the last output matches
    assert(ListEquality().equals(tx.outputs[0].serialize(), txOutput.serialize()), true);
  });

  test("Can issue a new Token Transaction", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    var fundingTx = getBobFundingTx();
    var fundingTxSigner = TransactionSigner(sigHashAll, bobPrivateKey);

    var issuanceTxn = await service.createTokenIssuanceTxn(fundingTx, fundingTxSigner, bobPub, bobAddress, fundingTx.hash);

    //weak tests for now. stronger ones follow
    expect(issuanceTxn.outputs.length, 5);
    expect(issuanceTxn.inputs.length, 1);
  });

  test("Can create and spend the witness outputs from a newly issued Token Transaction", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    var fundingTx = getBobFundingTx();
    var fundingTxSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTxn = await service.createTokenIssuanceTxn(fundingTx, fundingTxSigner, bobPub, bobAddress, fundingTx.hash);
    //weak tests for now. stronger ones follow
    expect(issuanceTxn.outputs.length, 5);
    expect(issuanceTxn.inputs.length, 1);

    var witnessTx = service.createWitnessTxn(
      fundingTxSigner,
      fundingTx,
      issuanceTxn,
      List<int>.empty(),
      /*no issuance*/
      bobPub,
      //owner pubkey
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      TokenAction.ISSUANCE,
    );

    var interp = Interpreter();
    var verifyFlags = Set<VerifyFlag>();
    verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
    verifyFlags.add(VerifyFlag.LOW_S);
    verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

    var scriptSigPP1 = witnessTx.inputs[1].script;
    var scriptPubKeyPP1 = issuanceTxn.outputs[1].script;
    var outputSatsPP1 = issuanceTxn.outputs[1].satoshis;

    // print("Padded Witness Txn : " + witnessTx.serialize());
    print("Padded Witness TxId: ${witnessTx.id}");
    print("Witness Funding TxId: ${fundingTx.id}");
    print("Funding OutpointIndex: ${witnessTx.inputs[0].prevTxnOutputIndex}");

    //verify PP1 spending
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigPP1!, scriptPubKeyPP1, witnessTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1))
            },
        returnsNormally);

    var scriptSigPP2 = witnessTx.inputs[2].script;
    var scriptPubKeyPP2 = issuanceTxn.outputs[2].script;
    var outputSatsPP2 = issuanceTxn.outputs[2].satoshis;

    //verify PP2 spending
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigPP2!, scriptPubKeyPP2, witnessTx, 2, verifyFlags, Coin.valueOf(outputSatsPP2))
            },
        returnsNormally);

    print("Issuance Txn " + issuanceTxn.serialize());
    print("Witness Txn " + witnessTx.serialize());
  });

  /*
  First transfer spend from issuance
   */
  test("Can create a first token transfer from a newly issued Token Transaction", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    // 1. Dynamically create the issuance transaction (Bob issues token)
    var bobFundingTx = getBobFundingTx();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTx = await service.createTokenIssuanceTxn(bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);
    expect(issuanceTx.outputs.length, 5);

    // 2. Create the witness transaction for the issuance
    var witnessTx = service.createWitnessTxn(
      bobFundingSigner,
      bobFundingTx,
      issuanceTx,
      List<int>.empty(), //no parent for issuance
      bobPub,
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      TokenAction.ISSUANCE,
    );

    // 3. Extract tokenId from the issuance
    var pp1Unlocker = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
    var tokenId = pp1Unlocker.tokenId ?? [];
    print("TokenID : ${hex.encode(tokenId)}");

    // 4. Create transfer from Bob to Alice
    // Current owner (Bob) funds and signs the transfer
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx(); //Alice's witness funding tx
    var transferTx = service.createTokenTransferTxn(
      witnessTx,
      issuanceTx,
      bobPub,
      aliceAddress,
      transferFundingTx,
      bobFundingSigner,
      bobPub,
      aliceFundingTx.hash, //recipient's witness funding txid
      tokenId,
    );

    print("Transfer TokenTxn : ${transferTx.serialize()}");
    print("Alice Funding TxId: ${aliceFundingTx.id}");

    var interp = Interpreter();
    var verifyFlags = Set<VerifyFlag>();
    verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
    verifyFlags.add(VerifyFlag.LOW_S);
    verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

    //validate the spend from the Witness' output (ModP2PKH)
    var scriptSigWitness = transferTx.inputs[1].script;
    var scriptPubKeyWitness = witnessTx.outputs[0].script;
    var outputSatsWitness = witnessTx.outputs[0].satoshis;
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigWitness!, scriptPubKeyWitness, transferTx, 1, verifyFlags, Coin.valueOf(outputSatsWitness))
            },
        returnsNormally);

    //validate the spend from PartialWitness output (PP3)
    var scriptSigSha = transferTx.inputs[2].script;
    var scriptPubKeySha = issuanceTx.outputs[3].script;
    var outputSatsSha = issuanceTx.outputs[3].satoshis;
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigSha!, scriptPubKeySha, transferTx, 2, verifyFlags, Coin.valueOf(outputSatsSha))
            },
        returnsNormally);
  });

  /*
  First transfer from a regular token txn — create witness for the transferred token
   */
  test("Can create and spend the witness outputs from a Token Transaction", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    // 1. Issue token to Bob
    var bobFundingTx = getBobFundingTx();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTx = await service.createTokenIssuanceTxn(bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);

    // 2. Create witness for the issuance
    var issuanceWitnessTx = service.createWitnessTxn(
      bobFundingSigner,
      bobFundingTx,
      issuanceTx,
      List<int>.empty(),
      bobPub,
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      TokenAction.ISSUANCE,
    );

    // 3. Transfer token from Bob to Alice
    var pp1Unlocker = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
    var tokenId = pp1Unlocker.tokenId ?? [];

    // Bob funds and signs the transfer to Alice
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx(); //Alice's witness funding tx
    var recipientTokenTx = service.createTokenTransferTxn(
      issuanceWitnessTx,
      issuanceTx,
      bobPub,
      aliceAddress,
      transferFundingTx,
      bobFundingSigner,
      bobPub,
      aliceFundingTx.hash,
      tokenId,
    );

    // 4. Create witness for Alice's token (transfer witness)
    var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);
    var witnessTx = service.createWitnessTxn(
      aliceFundingSigner,
      aliceFundingTx,
      recipientTokenTx,
      hex.decode(issuanceTx.serialize()),
      alicePubKey,
      bobPubkeyHash,
      TokenAction.TRANSFER,
    );

    print("Witness inputs: ${witnessTx.inputs.length}, outputs: ${witnessTx.outputs.length}");
    print("RecipientTokenTx inputs: ${recipientTokenTx.inputs.length}, outputs: ${recipientTokenTx.outputs.length}");
    print("IssuanceTx outputs: ${issuanceTx.outputs.length}");
    print("IssuanceTx output[4] scriptHex: ${hex.encode(issuanceTx.outputs[4].script.buffer)}");
    print("RecipientTx output[4] scriptHex: ${hex.encode(recipientTokenTx.outputs[4].script.buffer)}  sats: ${recipientTokenTx.outputs[4].satoshis}");
    // Debug PP2 script structure
    var pp2Script = recipientTokenTx.outputs[2].script.buffer;
    print("PP2 script bytes [115:180]: ${hex.encode(pp2Script.sublist(115, 180))}");
    print("PP2 byte[117]=${pp2Script[117].toRadixString(16)} [153]=${pp2Script[153].toRadixString(16)} [154]=${pp2Script[154].toRadixString(16)} [174]=${pp2Script[174].toRadixString(16)} [175]=${pp2Script[175].toRadixString(16)}");
    // Same for issuance PP2 (parent)
    var parentPP2Script = issuanceTx.outputs[2].script.buffer;
    print("Parent PP2 script bytes [115:180]: ${hex.encode(parentPP2Script.sublist(115, 180))}");
    print("Parent PP2 byte[117]=${parentPP2Script[117].toRadixString(16)} [153]=${parentPP2Script[153].toRadixString(16)} [154]=${parentPP2Script[154].toRadixString(16)} [174]=${parentPP2Script[174].toRadixString(16)} [175]=${parentPP2Script[175].toRadixString(16)}");
    print("PP2 total script length: ${pp2Script.length}  Parent PP2 length: ${parentPP2Script.length}");
    // Check what's at offset 176 onwards (should be ownerPKH in new template)
    print("Parent PP2 bytes [175:200]: ${hex.encode(parentPP2Script.sublist(175, 200))}");
    print("RecipientTx change (output[0]) sats: ${recipientTokenTx.outputs[0].satoshis}");
    // Verify the token tx can be rebuilt from scriptLHS + outputs + locktime
    var tsl1 = TransactionUtils();
    var tokenTxLHS = tsl1.getTxLHS(recipientTokenTx);
    var recipientTxHex = recipientTokenTx.serialize();
    var lhsHex = hex.encode(tokenTxLHS);
    // Check that the serialized tx starts with the LHS
    print("LHS matches start of tx? ${recipientTxHex.startsWith(lhsHex)}");
    // What follows LHS should be the varint output count
    var afterLHS = recipientTxHex.substring(lhsHex.length);
    print("After LHS (first 10 hex chars): ${afterLHS.substring(0, 10)}");
    // For 5 outputs, varint should be 05
    print("Output count varint: ${afterLHS.substring(0, 2)}");

    var interp = Interpreter();
    var verifyFlags = Set<VerifyFlag>();
    verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
    verifyFlags.add(VerifyFlag.LOW_S);
    verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

    //verify PP1 spending
    var scriptSigPP1 = witnessTx.inputs[1].script;
    var scriptPubKeyPP1 = recipientTokenTx.outputs[1].script;
    var outputSatsPP1 = recipientTokenTx.outputs[1].satoshis;
    try {
      interp.correctlySpends(
          scriptSigPP1!, scriptPubKeyPP1, witnessTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1));
      print("PP1 spending: PASS");
    } catch (e, st) {
      if (e is ScriptException) {
        print("PP1 spending: FAIL - ${e.error} : ${e.cause}");
        // Print stack trace to find which line in interpreter
        print("Stack trace: ${st.toString().split('\n').take(5).join('\n')}");
      } else {
        print("PP1 spending: FAIL - $e");
      }
    }
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigPP1!, scriptPubKeyPP1, witnessTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1))
            },
        returnsNormally);

    //verify PP2 spending
    var scriptSigPP2 = witnessTx.inputs[2].script;
    var scriptPubKeyPP2 = recipientTokenTx.outputs[2].script;
    var outputSatsPP2 = recipientTokenTx.outputs[2].satoshis;
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigPP2!, scriptPubKeyPP2, witnessTx, 2, verifyFlags, Coin.valueOf(outputSatsPP2))
            },
        returnsNormally);
  });

  /*
  Token transfer chain: A→B→C
  Issue token to Bob, transfer to Alice, then transfer from Alice to Charlie
   */
  test("Can transfer token through a chain A→B→C (Bob→Alice→Charlie)", () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    // 1. Issue token to Bob
    var bobFundingTx = getBobFundingTx();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTx = await service.createTokenIssuanceTxn(bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);
    expect(issuanceTx.outputs.length, 5);

    // 2. Create witness for the issuance
    var issuanceWitnessTx = service.createWitnessTxn(
      bobFundingSigner,
      bobFundingTx,
      issuanceTx,
      List<int>.empty(),
      bobPub,
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      TokenAction.ISSUANCE,
    );

    // 3. Extract tokenId from issuance PP1
    var pp1Unlocker = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
    var tokenId = pp1Unlocker.tokenId ?? [];
    print("TokenID : ${hex.encode(tokenId)}");

    // 4. Transfer token from Bob to Alice
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx();
    var transferTxBobToAlice = service.createTokenTransferTxn(
      issuanceWitnessTx,
      issuanceTx,
      bobPub,
      aliceAddress,
      transferFundingTx,
      bobFundingSigner,
      bobPub,
      aliceFundingTx.hash,
      tokenId,
    );

    print("Transfer Bob→Alice TxId: ${transferTxBobToAlice.id}");

    // 5. Create witness for Alice's token (transfer witness)
    var aliceFundingSigner = TransactionSigner(sigHashAll, alicePrivateKey);
    var aliceWitnessTx = service.createWitnessTxn(
      aliceFundingSigner,
      aliceFundingTx,
      transferTxBobToAlice,
      hex.decode(issuanceTx.serialize()),
      alicePubKey,
      bobPubkeyHash,
      TokenAction.TRANSFER,
    );

    // 6. Transfer token from Alice to Charlie
    var aliceTransferFundingTx = getAliceFundingTx();
    var charlieFundingTx = getAliceFundingTx(); // reuse Alice funding as Charlie's witness funding source
    var transferTxAliceToCharlie = service.createTokenTransferTxn(
      aliceWitnessTx,
      transferTxBobToAlice,
      alicePubKey,
      charlieAddress,
      aliceTransferFundingTx,
      aliceFundingSigner,
      alicePubKey,
      charlieFundingTx.hash,
      tokenId,
    );

    print("Transfer Alice→Charlie TxId: ${transferTxAliceToCharlie.id}");

    var interp = Interpreter();
    var verifyFlags = Set<VerifyFlag>();
    verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
    verifyFlags.add(VerifyFlag.LOW_S);
    verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

    // Verify spending from the witness output (ModP2PKH) in Alice→Charlie transfer
    var scriptSigWitness = transferTxAliceToCharlie.inputs[1].script;
    var scriptPubKeyWitness = aliceWitnessTx.outputs[0].script;
    var outputSatsWitness = aliceWitnessTx.outputs[0].satoshis;
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigWitness!, scriptPubKeyWitness, transferTxAliceToCharlie, 1, verifyFlags, Coin.valueOf(outputSatsWitness))
            },
        returnsNormally);

    // Verify spending from PartialWitness output (PP3) of Alice's token tx
    var scriptSigPP3 = transferTxAliceToCharlie.inputs[2].script;
    var scriptPubKeyPP3 = transferTxBobToAlice.outputs[3].script;
    var outputSatsPP3 = transferTxBobToAlice.outputs[3].satoshis;
    expect(
        () => {
              interp.correctlySpends(
                  scriptSigPP3!, scriptPubKeyPP3, transferTxAliceToCharlie, 2, verifyFlags, Coin.valueOf(outputSatsPP3))
            },
        returnsNormally);

    print("Token transfer chain A→B→C completed successfully");
  });

  test("Can burn a newly issued token", timeout: Timeout(Duration(minutes: 2)), () async {
    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    // 1. Issue token to Bob
    var bobFundingTx = getBobFundingTx();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var issuanceTx = await service.createTokenIssuanceTxn(bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash);
    expect(issuanceTx.outputs.length, 5);

    // 2. Burn the token
    var burnFundingTx = getBobFundingTx();
    var burnTx = service.createBurnTokenTxn(
      issuanceTx,
      bobFundingSigner,
      bobPub,
      burnFundingTx,
      bobFundingSigner,
      bobPub,
    );

    // Burn tx should have only 1 output (change)
    expect(burnTx.outputs.length, 1);

    var interp = Interpreter();
    var verifyFlags = Set<VerifyFlag>();
    verifyFlags.add(VerifyFlag.SIGHASH_FORKID);
    verifyFlags.add(VerifyFlag.LOW_S);
    verifyFlags.add(VerifyFlag.UTXO_AFTER_GENESIS);

    // Verify PP1 burn spending (input[1])
    var scriptSigPP1 = burnTx.inputs[1].script;
    var scriptPubKeyPP1 = issuanceTx.outputs[1].script;
    var outputSatsPP1 = issuanceTx.outputs[1].satoshis;
    expect(
        () => interp.correctlySpends(
            scriptSigPP1!, scriptPubKeyPP1, burnTx, 1, verifyFlags, Coin.valueOf(outputSatsPP1)),
        returnsNormally);

    // Verify PP2 burn spending (input[2])
    var scriptSigPP2 = burnTx.inputs[2].script;
    var scriptPubKeyPP2 = issuanceTx.outputs[2].script;
    var outputSatsPP2 = issuanceTx.outputs[2].satoshis;
    expect(
        () => interp.correctlySpends(
            scriptSigPP2!, scriptPubKeyPP2, burnTx, 2, verifyFlags, Coin.valueOf(outputSatsPP2)),
        returnsNormally);

    // Verify PartialWitness burn spending (input[3])
    var scriptSigPW = burnTx.inputs[3].script;
    var scriptPubKeyPW = issuanceTx.outputs[3].script;
    var outputSatsPW = issuanceTx.outputs[3].satoshis;
    expect(
        () => interp.correctlySpends(
            scriptSigPW!, scriptPubKeyPW, burnTx, 3, verifyFlags, Coin.valueOf(outputSatsPW)),
        returnsNormally);
  });

  test("Can create an identity anchor transaction", () async {
    var algorithm = Ed25519();
    var keyPair = await algorithm.newKeyPair();
    var wand = await algorithm.newSignatureWandFromKeyPair(keyPair);

    var builder = IdentityAnchorBuilder({
      'name': 'Test Issuer',
      'org': 'Test Organization',
    });

    var fundingTx = getBobFundingTx();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
    var fundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

    var identityTx = await builder.buildTransaction(
      fundingTx, fundingSigner, bobPub, bobAddress, wand,
    );

    // Should have 3 outputs: change, MAP metadata, AIP signature
    expect(identityTx.outputs.length, 3);

    // Output[1] should be MAP OP_RETURN with identity metadata
    var mapScript = identityTx.outputs[1].script;
    expect(mapScript.buffer[0], 0x00); // OP_FALSE
    expect(mapScript.buffer[1], 0x6a); // OP_RETURN

    var metadata = IdentityAnchorBuilder.extractMetadata(identityTx);
    expect(metadata['app'], 'tsl1');
    expect(metadata['type'], 'issuer_identity');
    expect(metadata['name'], 'Test Issuer');
    expect(metadata['org'], 'Test Organization');

    // Output[2] should be AIP OP_RETURN with signature
    var aipScript = identityTx.outputs[2].script;
    expect(aipScript.buffer[0], 0x00); // OP_FALSE
    expect(aipScript.buffer[1], 0x6a); // OP_RETURN

    var pubkeyHex = IdentityAnchorBuilder.extractPublicKey(identityTx);
    expect(pubkeyHex.isNotEmpty, true);
  });

  test("Can issue a token with issuer identity and verify the link", () async {
    var algorithm = Ed25519();
    var keyPair = await algorithm.newKeyPair();
    var wand = await algorithm.newSignatureWandFromKeyPair(keyPair);

    // 1. Create the identity anchor transaction
    var identityBuilder = IdentityAnchorBuilder({
      'name': 'Token Issuer',
    });

    var bobFundingTx = getBobFundingTx();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);

    var identityTx = await identityBuilder.buildTransaction(
      bobFundingTx, bobFundingSigner, bobPub, bobAddress, wand,
    );

    // 2. Issue a token with identity link
    var service = TokenTool();
    var issuanceFundingTx = getBobFundingTx();
    var issuanceTx = await service.createTokenIssuanceTxn(
      issuanceFundingTx, bobFundingSigner, bobPub, bobAddress, issuanceFundingTx.hash,
      identityTxId: identityTx.hash,
      issuerWand: wand,
    );

    // Should still have 5 outputs
    expect(issuanceTx.outputs.length, 5);

    // 3. Verify the identity link
    var identity = IdentityVerification.extractIdentityFromMetadata(issuanceTx.outputs[4].script);
    expect(identity.identityTxId, isNotNull);
    expect(identity.identitySig, isNotNull);
    expect(identity.identityTxId, hex.encode(identityTx.hash));

    // 4. Verify signature
    var isValid = await IdentityVerification.verifyIssuanceIdentity(issuanceTx, identityTx);
    expect(isValid, true);
  });

  test("Identity metadata is preserved across token transfer", () async {
    var algorithm = Ed25519();
    var keyPair = await algorithm.newKeyPair();
    var wand = await algorithm.newSignatureWandFromKeyPair(keyPair);

    var service = TokenTool();
    var sigHashAll = SighashType.SIGHASH_FORKID.value | SighashType.SIGHASH_ALL.value;

    // 1. Create identity anchor
    var identityBuilder = IdentityAnchorBuilder({'name': 'Issuer'});
    var identityFundingTx = getBobFundingTx();
    var bobFundingSigner = TransactionSigner(sigHashAll, bobPrivateKey);
    var identityTx = await identityBuilder.buildTransaction(
      identityFundingTx, bobFundingSigner, bobPub, bobAddress, wand,
    );

    // 2. Issue token with identity
    var bobFundingTx = getBobFundingTx();
    var issuanceTx = await service.createTokenIssuanceTxn(
      bobFundingTx, bobFundingSigner, bobPub, bobAddress, bobFundingTx.hash,
      identityTxId: identityTx.hash,
      issuerWand: wand,
    );

    // 3. Create issuance witness
    var issuanceWitnessTx = service.createWitnessTxn(
      bobFundingSigner, bobFundingTx, issuanceTx,
      List<int>.empty(), bobPub,
      Address.fromPublicKey(bobPub, NetworkType.TEST).pubkeyHash160,
      TokenAction.ISSUANCE,
    );

    // 4. Transfer token from Bob to Alice
    var pp1 = PP1LockBuilder.fromScript(issuanceTx.outputs[1].script);
    var tokenId = pp1.tokenId ?? [];
    var transferFundingTx = getBobFundingTx();
    var aliceFundingTx = getAliceFundingTx();

    var transferTx = service.createTokenTransferTxn(
      issuanceWitnessTx, issuanceTx, bobPub, aliceAddress,
      transferFundingTx, bobFundingSigner, bobPub,
      aliceFundingTx.hash, tokenId,
    );

    // 5. Verify metadata is preserved in transfer
    var issuanceIdentity = IdentityVerification.extractIdentityFromMetadata(issuanceTx.outputs[4].script);
    var transferIdentity = IdentityVerification.extractIdentityFromMetadata(transferTx.outputs[4].script);
    expect(transferIdentity.identityTxId, issuanceIdentity.identityTxId);
    expect(transferIdentity.identitySig, issuanceIdentity.identitySig);

    // 6. Verify identity link still valid from transfer tx
    var isValid = await IdentityVerification.verifyIssuanceIdentity(transferTx, identityTx);
    expect(isValid, true);
  });

}
