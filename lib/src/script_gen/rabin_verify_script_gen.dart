import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import '../crypto/rabin.dart';

/// Generates Bitcoin Scripts for Rabin signature verification.
///
/// Two modes are supported:
///
/// 1. **Pre-hashed** ([generate] / [buildScriptSig]):
///    The message hash is computed off-chain and pushed as a script number.
///
/// 2. **In-script hashing** ([generateWithBinding] / [buildBindingScriptSig]):
///    Two 32-byte data items (e.g. identityTxId and ed25519PubKey) are pushed
///    in the scriptSig. The scriptPubKey concatenates and SHA256-hashes them
///    in-script, then verifies the Rabin signature over the hash. This ensures
///    the binding cannot be faked — the verifier computes the hash itself.
class RabinVerifyScriptGen {
  /// Generate a scriptPubKey that verifies a Rabin signature against
  /// a pre-computed message hash.
  ///
  /// Stack at entry (from scriptSig): [padding, s, messageHash]
  static SVScript generate(BigInt n) {
    var b = ScriptBuilder();

    // Push Rabin public key n (sign-magnitude LE encoding)
    b.addData(Rabin.bigIntToScriptNum(n));
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Stack: [padding, s, messageHash]
    _emitRabinVerify(b);

    return b.build();
  }

  /// Generate a scriptPubKey that verifies a Rabin signature over
  /// sha256(dataA || dataB), where dataA and dataB are pushed in the scriptSig.
  ///
  /// Stack at entry (from scriptSig): [padding, s, dataA, dataB]
  ///
  /// The script concatenates dataA || dataB, SHA256-hashes the result,
  /// converts to a script number, then verifies s² mod n == hash + padding.
  static SVScript generateWithBinding(BigInt n) {
    var b = ScriptBuilder();

    // Push Rabin public key n
    b.addData(Rabin.bigIntToScriptNum(n));
    b.opCode(OpCodes.OP_TOALTSTACK);

    // Stack: [padding, s, dataA, dataB]
    // OP_CAT pops dataB (top), then dataA → result = dataA || dataB
    b.opCode(OpCodes.OP_CAT);
    // Stack: [padding, s, dataA||dataB]
    b.opCode(OpCodes.OP_SHA256);
    // Stack: [padding, s, hash(32 bytes, raw)]

    // Convert 32-byte hash to a positive script number:
    // Append 0x00 to ensure the sign bit is clear, then BIN2NUM
    // to get minimal encoding.
    b.addData(Uint8List.fromList([0x00]));
    // Stack: [padding, s, hash, 0x00]
    b.opCode(OpCodes.OP_CAT);
    // Stack: [padding, s, hash||0x00 (33 bytes)]
    b.opCode(OpCodes.OP_BIN2NUM);
    // Stack: [padding, s, hashNum]

    _emitRabinVerify(b);

    return b.build();
  }

  /// Emit the common Rabin verification logic.
  ///
  /// Expects stack: [padding, s, hashNum], altstack: [n]
  /// Leaves: [TRUE]
  static void _emitRabinVerify(ScriptBuilder b) {
    // Stack: [padding, s, hashNum]
    b.opCode(OpCodes.OP_ROT);
    // Stack: [s, hashNum, padding]
    b.opCode(OpCodes.OP_ADD);
    // Stack: [s, hashNum + padding]
    b.opCode(OpCodes.OP_SWAP);
    // Stack: [hashNum + padding, s]
    b.opCode(OpCodes.OP_DUP);
    b.opCode(OpCodes.OP_MUL);
    // Stack: [hashNum + padding, s²]
    b.opCode(OpCodes.OP_FROMALTSTACK);
    // Stack: [hashNum + padding, s², n]
    b.opCode(OpCodes.OP_MOD);
    // Stack: [hashNum + padding, s² mod n]
    b.opCode(OpCodes.OP_NUMEQUALVERIFY);
    // Stack: [] (verified)
    b.opCode(OpCodes.OP_1);
    // Stack: [TRUE]
  }

  /// Build a scriptSig for pre-hashed verification.
  ///
  /// Pushes: padding (bottom), s, messageHash (top)
  static SVScript buildScriptSig(BigInt messageHash, RabinSignature sig) {
    var b = ScriptBuilder();
    b.number(sig.padding);
    b.addData(Rabin.bigIntToScriptNum(sig.s));
    b.addData(Rabin.bigIntToScriptNum(messageHash));
    return b.build();
  }

  /// Build a scriptSig for in-script binding verification.
  ///
  /// Pushes: padding (bottom), s, dataA, dataB (top)
  ///
  /// The scriptPubKey will compute sha256(dataA || dataB) and verify
  /// the Rabin signature over the result.
  static SVScript buildBindingScriptSig(
      RabinSignature sig, List<int> dataA, List<int> dataB) {
    var b = ScriptBuilder();
    b.number(sig.padding);
    b.addData(Rabin.bigIntToScriptNum(sig.s));
    b.addData(Uint8List.fromList(dataA));
    b.addData(Uint8List.fromList(dataB));
    return b.build();
  }
}
