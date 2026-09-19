# note-encryption Specification

## Purpose
How a note's contents reach its recipient: diversified addresses carrying a KEM public key, a per-note ciphertext bundle carried in the transfer's note-data output, decryptable by the recipient (incoming viewing key), the sender (outgoing viewing key) and, for gated assets, the issuer.

## Requirements

### Requirement: Addresses
A note address SHALL be a diversifier d, the diversified public key pk_d and a KEM public key derived deterministically from ivk and d, encoded with a KEM id.

#### Scenario: Address parse
- **WHEN** an encoded address is parsed
- **THEN** its KEM id determines the public key length and the address round-trips

### Requirement: Hybrid post-quantum KEM
The default KEM SHALL be X25519 combined with ML-KEM-768 (id 2), the shared secret a hash of both secrets, the ephemeral material and the recipient key, so that breaking either primitive alone does not reveal notes; X25519 alone (id 1) SHALL remain readable for compatibility.

#### Scenario: One half tampered
- **WHEN** either the X25519 or the ML-KEM half of an ephemeral is altered
- **THEN** decryption fails

### Requirement: Bundle
A bundle SHALL hold the commitment, the KEM id and ephemeral, the note ciphertext (AEAD with a key derived from the shared secret and the commitment), an outgoing copy under ovk, and optionally an issuer copy under the issuer's KEM key; a hybrid bundle is 1,827 bytes (3,027 with an issuer copy).

#### Scenario: Issuer copy
- **WHEN** a note of a gated asset is encrypted with the issuer's key
- **THEN** the issuer decrypts the plaintext and the recipient's address from its copy

### Requirement: Plaintext
The plaintext SHALL carry the value, rho, rcm, the asset id and a memo, so the recipient can reconstruct the commitment and later spend the note.

#### Scenario: Commitment check
- **WHEN** a recovered plaintext does not reproduce the bundle's commitment
- **THEN** the note is discarded
