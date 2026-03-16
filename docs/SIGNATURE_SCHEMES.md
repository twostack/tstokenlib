# Signature Schemes: Rabin vs ECDSA in Bitcoin Script

Why TSL1 uses Rabin signatures for identity anchoring and oracle attestation instead of on-chain ECDSA verification, and how this decision shapes the protocol's approach to external data access.

---

## 1. The Core Problem

TSL1 tokens need to verify that arbitrary data (identity claims, oracle attestations, state transitions) is authentically signed by a known party. Bitcoin's native `OP_CHECKSIG` only verifies signatures over the *current spending transaction* — it cannot verify a signature over an arbitrary message. Two alternative signature schemes can fill this gap: on-chain ECDSA verification and Rabin signatures.

---

## 2. On-Chain ECDSA Verification

### How It Works

sCrypt demonstrated full ECDSA signature verification implemented purely in Bitcoin Script (August 2021). The approach:

1. Parse the DER-encoded signature to extract `r` and `s` components
2. Convert from big-endian to little-endian (Script's native encoding)
3. Compute `u1 = z * s^-1 mod n` and `u2 = r * s^-1 mod n`
4. Compute the curve point `(x1, y1) = u1 * G + u2 * Q` (two scalar multiplications + one point addition)
5. Verify `r == x1 mod n`

This verifies that an arbitrary message `m` was signed by the private key corresponding to public key `Q`, without requiring `OP_CHECKSIGFROMSTACK`, `OP_CHECKDATASIG`, or any new opcodes.

### Script Size Cost

The script size is dominated by the elliptic curve arithmetic:

| Operation | Script Size | Notes |
|-----------|------------|-------|
| Modular inverse (extended Euclidean) | ~7 KB | 368 iterations max for 256-bit modulus |
| EC point addition (naive) | >1 MB | Requires modular inverse in the slope calculation |
| EC point addition (optimized) | ~400 bytes | Verify P3 = P1 + P2 instead of computing it; pass P3 and lambda in unlocking script |
| Scalar multiplication (optimized) | ~5 MB | ~256 optimized point additions chained via double-and-add, with 256 precomputed points (2P, 4P, ..., 2^255 P) passed in unlocking script |
| **Single ECDSA signature verification (optimized)** | **~10 MB** | Two scalar multiplications (u1*G + u2*Q) plus one point addition |

**Key optimization — verify, don't compute:** Instead of *computing* P3 = P1 + P2 directly (which requires modular inverse, >1 MB), pass the expected result P3 and the slope lambda in the unlocking script and only *verify* the relationship holds in the locking script. This transforms the formula to avoid division:

```
lambda * (x2 - x1) mod p == y2 - y1 mod p    (when P1 != P2)
2 * lambda * y1 mod p == 3 * x1^2 + a mod p   (when P1 == P2)
```

This reduces each point addition from >1 MB to ~400 bytes. **However, scalar multiplication chains ~256 such additions** (one per bit of a 256-bit scalar), yielding ~5 MB per multiplication. ECDSA requires two scalar multiplications, so the total is ~10 MB. This is already the optimized floor — without the verify-not-compute trick, ECDSA would be >256 MB.

The ECDSA implementation explicitly uses the optimized EC library:

```scrypt
require(EC.isMul(EC.G, u1, U1, u1Aux));   // verify U1 = u1 * G
require(EC.isMul(Q, u2, U2, u2Aux));       // verify U2 = u2 * Q
require(EC.isSum(U1, U2, lambda, P));       // verify P = U1 + U2
```

Even with all optimizations applied, a single ECDSA verification is **~10 MB of script** — impractical for tokens that need to fit within reasonable transaction sizes.

### Why TSL1 Rejected On-Chain ECDSA

At ~10 MB per signature verification, on-chain ECDSA is incompatible with TSL1's token architecture:

- PP1 locking scripts are currently 11-15 KB (hand-optimized)
- PP3 witness scripts are ~37.5 KB
- Adding a single ECDSA verification would increase script size by **~250x** over the entire current token
- Multiple verifications (e.g., dual-authority checks) would compound this

---

## 3. Rabin Signatures

### How It Works

Rabin signature is an alternative digital signature algorithm (DSA) to ECDSA. Its security depends on the fact that calculating a modular square root is as hard as integer factorisation.

**Key generation:** Choose two large primes `p` and `q`. The private key is `(p, q)`. The public key is `n = p * q`.

**Signing:** Given message `m`, find padding `U` such that `H(m || U)` is a quadratic residue modulo `n`. Compute:

```
S = [(p^(q-2) * H(m||U)^((q+1)/4) mod q) * p + (q^(p-2) * H(m||U)^((p+1)/4) mod p) * q] mod n
```

**Verification:** Check that `S^2 mod n == H(m || U) mod n`.

### The Key Asymmetry

Rabin signatures have a critical property that makes them ideal for on-chain use:

- **Signing is computationally expensive** (requires knowledge of the factorisation of `n`)
- **Verification is computationally cheap** (a single modular squaring and comparison)

Since only verification runs on-chain, this asymmetry is exactly what Bitcoin Script needs.

### Script Size Cost

The entire Rabin signature verification contract in sCrypt is approximately **10 lines of code**:

```scrypt
contract RabinSignature {
    public function verifySig(int sig, bytes msg, bytes padding, int n) {
        int h = this.fromLEUnsigned(this.hash(msg ++ padding));
        require((sig * sig) % n == h % n);
    }

    function hash(bytes x) returns (bytes) {
        bytes hx = sha256(x);
        int idx = length(hx) / 2;
        return sha256(hx[:idx]) ++ sha256(hx[idx:]);
    }

    function fromLEUnsigned(bytes b) returns (int) {
        return unpack(b ++ b"00");
    }
}
```

The verification involves only:
1. Two SHA256 hashes (to expand to 512 bits)
2. One modular squaring (`sig * sig % n`)
3. One comparison (`== h % n`)

No elliptic curve arithmetic. No iterative algorithms. Basic algebra and hashing only.

### Comparison

| Property | ECDSA (on-chain) | Rabin |
|----------|-----------------|-------|
| Verification script size | ~10 MB | ~hundreds of bytes |
| Verification operations | 2 scalar multiplications + point addition | 1 modular squaring + 2 SHA256 |
| Cost ratio | ~1,000,000x more expensive | baseline |
| Can verify arbitrary messages | Yes | Yes |
| Security basis | Elliptic curve discrete log | Integer factorisation |
| Key compatibility | Reuses Bitcoin keypairs | Separate key generation |
| Signing cost (off-chain) | Standard | Higher (but off-chain, so irrelevant) |

The sCrypt team measured ECDSA verification as being "in the order of a million-fold" more expensive than Rabin verification on-chain.

---

## 4. TSL1's Use of Rabin Signatures

### Identity Anchoring (PP1_NFT, PP1_RNFT)

TSL1 tokens embed a `rabinPubKeyHash` (20 bytes, HASH160 of the Rabin public key) as an immutable field in the PP1 header. At issuance, the issuer provides a Rabin signature over the token's identity data. The script verifies:

1. `HASH160(rabinPubKey) == rabinPubKeyHash` (identity binding)
2. `sig^2 mod n == H(tokenData || padding) mod n` (signature validity)

This anchors the token's identity to a specific Rabin key without the ~10 MB cost of ECDSA verification.

### Oracle Attestation (Future)

The [FUTURE_PRIMITIVES.md](FUTURE_PRIMITIVES.md) oracle integration design proposes using Rabin signatures for oracle attestations. An oracle signs external data (prices, weather, event outcomes) with its Rabin key. The token script verifies the attestation cheaply on-chain. This is feasible precisely because Rabin verification fits within the existing script size budget.

---

## 5. Accessing Blockchain Data Without Oracles

For data that is *already on the blockchain* (block headers, transactions), sCrypt demonstrated a technique that avoids oracles entirely (November 2021).

### Block Header Verification

A serialized Bitcoin block header is only **80 bytes** and contains six fields: version, previous block hash, Merkle root, timestamp, difficulty target (nBits), and nonce.

A smart contract can verify a block header by:
1. Hashing the 80-byte header with SHA256d
2. Checking the hash is below the difficulty target
3. Checking the difficulty target is not trivially low (preventing fake headers)

```scrypt
static function isBlockHeaderValid(BlockHeader bh, int blockchainTarget) : bool {
    int bhHash = blockHeaderHash(bh);
    int target = bits2Target(bh.bits);
    return bhHash <= target && target <= blockchainTarget;
}
```

### Transaction Inclusion Proof (SPV)

Once a block header is verified, any transaction in the block can be proven via Merkle path:

```scrypt
static function txInBlock(Sha256 txid, BlockHeader bh, MerklePath merklePath) : bool {
    return MAST.calMerkleRoot(txid, merklePath) == bh.merkleRoot;
}
```

This is the same mechanism as SPV (Simplified Payment Verification). The Merkle proof scales logarithmically — `O(log n)` hashes for `n` transactions in a block.

### Security Model

The security is economic, not absolute: producing a fake block header that meets the difficulty target requires significant hash power. The contract should set `blockchainTarget` to the current mainnet difficulty to make forgery prohibitively expensive. A contract relying on a block header should not lock more coins than it costs to produce a fake header.

### Relevance to TSL1

This technique is relevant to the [FUTURE_PRIMITIVES.md](FUTURE_PRIMITIVES.md) on-chain randomness gap (Section 2). Block header nonces can serve as a source of pseudo-randomness:

```scrypt
PubKey winner = unpack(bh.nonce) % 2 ? this.alice : this.bob;
```

However, miners can manipulate nonces (and extraNonce/timestamp) to influence outcomes at no extra cost. For fairness-critical applications, use the block *hash* instead of the nonce, as manipulating the block hash requires discarding valid blocks.

---

## 6. Three Approaches to External Data

| Approach | Trust Model | Script Cost | Data Source |
|----------|-----------|------------|-------------|
| **Rabin oracle** | Trust oracle to attest honestly | Low (~hundreds of bytes) | Any external data |
| **ECDSA oracle** | Trust oracle; reuses Bitcoin keys | Very high (~10 MB) | Any external data |
| **SPV block header** | Trustless (PoW security) | Low (~80 bytes + Merkle proof) | On-chain data only |

TSL1's current design uses Rabin for identity (implemented) and will use Rabin for oracle attestation (designed). The SPV approach applies only to accessing other on-chain data and is relevant to the future on-chain randomness primitive.

For ECDSA-based oracles, there is an alternative approach where the oracle participates as a co-signer of the transaction (using `SIGHASH_NONE | SIGHASH_ANYONECANPAY`), embedding attested data in the unlocking script. This reuses Bitcoin's native `OP_CHECKSIG` (not the ~10 MB on-chain ECDSA) but requires the oracle to actively participate in transaction construction rather than simply publishing signed data.

---

## 7. Design Decision Record

**Decision:** TSL1 uses Rabin signatures for identity anchoring and oracle attestation.

**Alternatives considered:**
1. On-chain ECDSA verification (~10 MB per verification — rejected as impractical)
2. `OP_CHECKSIGFROMSTACK` / `OP_CHECKDATASIG` (not available on BSV — rejected)
3. ECDSA co-signing oracle (viable but requires oracle to participate in tx construction — not chosen for identity anchoring; may be useful for specific oracle patterns)

**Rationale:** Rabin verification costs orders of magnitude less script space than ECDSA. The ~10 lines of Rabin verification code vs ~10 MB of ECDSA verification makes Rabin the only practical choice for tokens that must stay within reasonable script sizes. The trade-off — separate key management from Bitcoin keypairs — is acceptable because identity keys and oracle keys are typically managed separately from spending keys anyway.

**Implications for future primitives:**
- Oracle integration (FUTURE_PRIMITIVES Section 3) should use Rabin-based attestation
- N-of-M multi-sig for oracles (Section 4) benefits from Rabin's compact verification — M sequential Rabin verifications add M * ~hundreds of bytes, not M * ~10 MB
- The ECDSA co-signing pattern remains available as a complementary approach where the oracle is a transaction participant rather than a data publisher

---

## Sources

- [Efficient Elliptic Curve Arithmetic in sCrypt/Script](https://scryptplatform.medium.com/efficient-elliptic-curve-point-addition-and-multiplication-in-scrypt-script-f7e143a752e2) — sCrypt, Aug 6 2021
- [ECDSA Signature Verification in Script](https://scryptplatform.medium.com/ecdsa-signature-verification-in-script-d1e8dda5f893) — sCrypt, Aug 13 2021
- [Access External Data from Bitcoin Smart Contracts](https://medium.com/coinmonks/access-external-data-from-bitcoin-smart-contracts-2ecdc7448c43) — sCrypt / Coinmonks, Mar 28 2020
- [Access Blockchain Data from Bitcoin Smart Contracts Without Oracles](https://scryptplatform.medium.com/access-blockchain-data-from-bitcoin-smart-contracts-without-oracles-e13b9c911d32) — sCrypt, Nov 15 2021
- PDF copies of these articles are stored in `docs/` for reference
