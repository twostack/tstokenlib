import 'dart:typed_data';

/// Signs a sighash digest and returns a DER-encoded ECDSA signature.
///
/// The sighash is the double-SHA256 hash of the transaction preimage for a
/// specific input. The returned bytes must be valid DER-encoded ECDSA
/// (without the sighash type byte — that is appended by the caller).
///
/// This is the simplest signing callback — suitable for single-key signers.
/// For multi-key HD wallets, use [SigningCallbackWithContext] instead.
typedef SigningCallback = Uint8List Function(Uint8List sighash);

/// Extended signing callback that receives the locking script of the output
/// being spent, enabling per-input key derivation.
///
/// When a transaction spends outputs locked to different keys (e.g., HD
/// multi-key wallets), the signer resolves the owner address from the
/// locking script and derives the correct signing key.
///
/// [sighash] is the double-SHA256 hash of the transaction preimage (32 bytes).
/// [inputIndex] is the transaction input index being signed.
/// [scriptPubKey] is the raw bytes of the locking script being spent.
typedef SigningCallbackWithContext = Uint8List Function(
    Uint8List sighash, int inputIndex, Uint8List scriptPubKey);
