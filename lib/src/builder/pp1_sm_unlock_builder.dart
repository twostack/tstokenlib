/*
  Copyright 2024 - Stephan M. February

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

/// The type of action being performed on a state machine token.
enum StateMachineAction {
  /// Initial funnel creation.
  CREATE,
  /// Enroll a customer (INIT→ACTIVE).
  ENROLL,
  /// Confirm a milestone (ACTIVE/PROGRESSING→PROGRESSING).
  CONFIRM,
  /// Convert to settlement phase (PROGRESSING→CONVERTING).
  CONVERT,
  /// Settle with reward/payment outputs (CONVERTING→SETTLED).
  SETTLE,
  /// Timeout expiration (any→EXPIRED).
  TIMEOUT,
  /// Burn the token (terminal states only).
  BURN
}

/// Builds the unlocking script (scriptSig) for spending the PP1_SM output.
///
/// Dispatch selectors:
/// - OP_0 = create, OP_1 = enroll, OP_2 = confirm, OP_3 = convert,
///   OP_4 = settle, OP_5 = timeout, OP_6 = burn
class PP1SmUnlockBuilder extends UnlockingScriptBuilder {
  List<int>? _preImage;
  List<int>? _pp2Output;
  SVPublicKey? _merchantPubKey;
  String? _changePKH;
  BigInt? _changeAmount;
  List<int>? _tokenLHS;
  List<int>? _prevTokenTx;
  List<int>? _witnessPadding;
  StateMachineAction? action;
  List<int>? _fundingOutpoint;

  // Enroll-specific
  List<int>? _eventData;

  // Confirm/Convert-specific (dual-sig)
  SVPublicKey? _customerPubKey;
  List<int>? _customerSigBytes;

  // Settle-specific
  BigInt? _custRewardAmount;
  BigInt? _merchPayAmount;

  // Timeout-specific
  BigInt? _refundAmount;

  List<int>? _sigBytes;

  // Rabin identity fields (used for CREATE only)
  List<int>? _rabinN;
  List<int>? _rabinS;
  int? _rabinPadding;
  List<int>? _identityTxId;
  List<int>? _ed25519PubKey;

  List<int>? get preImage => _preImage;

  /// Full constructor for standard operations (enroll, confirm, convert, settle, timeout).
  PP1SmUnlockBuilder(
      this._preImage,
      this._pp2Output,
      this._merchantPubKey,
      this._changePKH,
      this._changeAmount,
      this._tokenLHS,
      this._prevTokenTx,
      this._witnessPadding,
      this.action,
      this._fundingOutpoint,
      {List<int>? eventData,
      SVPublicKey? customerPubKey,
      List<int>? customerSigBytes,
      BigInt? custRewardAmount,
      BigInt? merchPayAmount,
      BigInt? refundAmount,
      List<int>? rabinN,
      List<int>? rabinS,
      int? rabinPadding,
      List<int>? identityTxId,
      List<int>? ed25519PubKey})
      : _eventData = eventData,
        _customerPubKey = customerPubKey,
        _customerSigBytes = customerSigBytes,
        _custRewardAmount = custRewardAmount,
        _merchPayAmount = merchPayAmount,
        _refundAmount = refundAmount,
        _rabinN = rabinN,
        _rabinS = rabinS,
        _rabinPadding = rabinPadding,
        _identityTxId = identityTxId,
        _ed25519PubKey = ed25519PubKey;

  /// Creates a PP1_SM unlock builder for burning a token.
  PP1SmUnlockBuilder.forBurn(SVPublicKey ownerPubKey)
      : _merchantPubKey = ownerPubKey,
        action = StateMachineAction.BURN;

  PP1SmUnlockBuilder.fromScript(SVScript script,
      {StateMachineAction this.action = StateMachineAction.ENROLL})
      : super.fromScript(script);

  @override
  SVScript getScriptSig() {
    SVSignature? signature;
    if (signatures.isNotEmpty) {
      signature = signatures[0];
    }

    if (signature == null && action != StateMachineAction.CREATE) {
      return ScriptBuilder().build();
    }

    List<int> sigBytes = [];
    if (signature != null) {
      sigBytes = hex.decode(signatures.first.toTxFormat());
    }

    var result = ScriptBuilder();

    switch (action!) {
      case StateMachineAction.CREATE:
        // Stack: [preImage, fundingOutpoint, witnessPadding, rabinN, rabinS,
        //         rabinPadding, identityTxId, ed25519PubKey, OP_0]
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_fundingOutpoint!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        result.addData(Uint8List.fromList(_rabinN!));
        result.addData(Uint8List.fromList(_rabinS!));
        result.number(_rabinPadding!);
        result.addData(Uint8List.fromList(_identityTxId!));
        result.addData(Uint8List.fromList(_ed25519PubKey!));
        break;

      case StateMachineAction.ENROLL:
        // Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt,
        //   merchantSig, eventData, scriptLHS, parentRawTx, padding, OP_1]
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(sigBytes));
        result.addData(Uint8List.fromList(_eventData!));
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        break;

      case StateMachineAction.CONFIRM:
        // Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt,
        //   merchantSig, customerPK, customerSig, milestoneData,
        //   scriptLHS, parentRawTx, padding, OP_2]
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(sigBytes));
        result.addData(Uint8List.fromList(hex.decode(_customerPubKey!.toHex())));
        result.addData(Uint8List.fromList(_customerSigBytes!));
        result.addData(Uint8List.fromList(_eventData!));
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        break;

      case StateMachineAction.CONVERT:
        // Same layout as confirm with conversionData
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(sigBytes));
        result.addData(Uint8List.fromList(hex.decode(_customerPubKey!.toHex())));
        result.addData(Uint8List.fromList(_customerSigBytes!));
        result.addData(Uint8List.fromList(_eventData!));
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        break;

      case StateMachineAction.SETTLE:
        // Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt,
        //   merchantSig, custRewardAmt, merchPayAmt, settlementData,
        //   scriptLHS, parentRawTx, padding, OP_4]
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(sigBytes));
        result.number(_custRewardAmount!.toInt());
        result.number(_merchPayAmount!.toInt());
        result.addData(Uint8List.fromList(_eventData!));
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        break;

      case StateMachineAction.TIMEOUT:
        // Stack: [preImage, pp2Out, merchantPK, changePkh, changeAmt,
        //   merchantSig, refundAmount, scriptLHS, parentRawTx, padding, OP_5]
        result.addData(Uint8List.fromList(_preImage!));
        result.addData(Uint8List.fromList(_pp2Output!));
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(hex.decode(_changePKH!)));
        result.number(_changeAmount!.toInt());
        result.addData(Uint8List.fromList(sigBytes));
        result.number(_refundAmount!.toInt());
        result.addData(Uint8List.fromList(_tokenLHS!));
        result.addData(Uint8List.fromList(_prevTokenTx!));
        result.addData(Uint8List.fromList(_witnessPadding!));
        break;

      case StateMachineAction.BURN:
        // Stack: [ownerPubKey, ownerSig, OP_6]
        result.addData(Uint8List.fromList(hex.decode(_merchantPubKey!.toHex())));
        result.addData(Uint8List.fromList(sigBytes));
        break;
    }

    // Append dispatch selector opcode
    switch (action!) {
      case StateMachineAction.CREATE:
        result.opCode(OpCodes.OP_0);
        break;
      case StateMachineAction.ENROLL:
        result.opCode(OpCodes.OP_1);
        break;
      case StateMachineAction.CONFIRM:
        result.opCode(OpCodes.OP_2);
        break;
      case StateMachineAction.CONVERT:
        result.opCode(OpCodes.OP_3);
        break;
      case StateMachineAction.SETTLE:
        result.opCode(OpCodes.OP_4);
        break;
      case StateMachineAction.TIMEOUT:
        result.opCode(OpCodes.OP_5);
        break;
      case StateMachineAction.BURN:
        result.opCode(OpCodes.OP_6);
        break;
    }

    return result.build();
  }

  @override
  void parse(SVScript script) {
    var chunkList = script.chunks;
    _preImage = chunkList[0].buf;
    _pp2Output = chunkList[1].buf;
    _merchantPubKey = SVPublicKey.fromBuffer(chunkList[2].buf ?? []);
    _changePKH = hex.encode(chunkList[3].buf ?? [00]);
    _changeAmount = castToBigInt(chunkList[4].buf ?? [], true);
    _sigBytes = chunkList[5].buf;
    _tokenLHS = chunkList[6].buf;
    _prevTokenTx = chunkList[7].buf;
    _witnessPadding = chunkList[8].buf;
  }

  List<int>? get pp2Output => _pp2Output;
  SVPublicKey? get merchantPubKey => _merchantPubKey;
  BigInt? get changeAmount => _changeAmount;
  List<int>? get tokenLHS => _tokenLHS;
  List<int>? get prevTokenTx => _prevTokenTx;
  List<int>? get witnessPadding => _witnessPadding;
  List<int>? get fundingOutpoint => _fundingOutpoint;
  String? get changePKH => _changePKH;
  List<int>? get sigBytes => _sigBytes;
  List<int>? get eventData => _eventData;
  SVPublicKey? get customerPubKey => _customerPubKey;
  List<int>? get customerSigBytes => _customerSigBytes;
  BigInt? get custRewardAmount => _custRewardAmount;
  BigInt? get merchPayAmount => _merchPayAmount;
  BigInt? get refundAmount => _refundAmount;
}
