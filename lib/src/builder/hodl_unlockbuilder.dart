

import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

/// Builds the unlocking script for spending a HODL time-locked output.
///
/// Pushes the spending signature, public key, and sighash preimage required
/// by the HODL locking script to verify ownership and enforce the time lock.
class HodlUnlockBuilder extends UnlockingScriptBuilder{

  SVSignature _spendingSig;
  SVPublicKey _pubKey;
  List<int> _txPreimage;

  /// Creates a HODL unlock builder.
  ///
  /// [_spendingSig] - The signature authorizing the spend.
  /// [_pubKey] - The public key matching the HODL lock's pubkey hash.
  /// [_txPreimage] - The sighash preimage for in-script nLockTime verification.
  HodlUnlockBuilder(this._spendingSig, this._pubKey, this._txPreimage);

  @override
  SVScript getScriptSig() {

    return ScriptBuilder()
        .addData(Uint8List.fromList(hex.decode(_spendingSig.toTxFormat())))
        .addData(Uint8List.fromList(hex.decode(_pubKey.toHex())))
        .addData(Uint8List.fromList(_txPreimage))
        .build();
  }

  @override
  void parse(SVScript script) {
    throw UnimplementedError();
  }

}