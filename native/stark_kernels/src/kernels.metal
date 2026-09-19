// GPU kernels for the tstokenlib Circle-STARK prover, an exact port of the
// CPU kernels in lib.rs (which are themselves exact ports of the Dart code),
// so a proof built with these is byte-identical to one built without them.
//
// Every value is a canonical M31 residue in [0, p), p = 2^31 - 1. The
// reduction sequences below are transcribed term for term from `mul`, `add`
// and `sub` in lib.rs rather than rewritten, because a different but
// "equivalent" reduction that disagrees on a boundary case would silently
// change a digest.

#include <metal_stdlib>
using namespace metal;

constant uint P = 0x7fffffffu;

// a + b, both < P: the sum is < 2P, and subtracting P wraps below the sum
// exactly when the sum did not need reducing (lib.rs `v_add`).
inline uint m31_add(uint a, uint b) {
    uint s = a + b;
    return min(s, s - P);
}

inline uint m31_sub(uint a, uint b) {
    uint s = a - b;
    return min(s, s + P);
}

// a * b with no 64-bit arithmetic. With x = hi*2^32 + lo the CPU computes
// y = (x & P) + (x >> 31) then folds once more; x & P is lo & P and
// x >> 31 is (hi << 1) | (lo >> 31), and hi < 2^30 keeps y inside 32 bits.
inline uint m31_mul(uint a, uint b) {
    uint lo = a * b;
    uint hi = mulhi(a, b);
    uint y = (lo & P) + ((hi << 1) | (lo >> 31));
    uint z = (y & P) + (y >> 31);
    return min(z, z - P);
}

// 2^s * a for 1 <= s <= 30: a rotation of the 31-bit value (lib.rs `v_shl`).
inline uint m31_shl(uint a, uint s) {
    return ((a << s) & P) | (a >> (31 - s));
}

inline uint m31_pow5(uint x) {
    uint x2 = m31_mul(x, x);
    return m31_mul(m31_mul(x2, x2), x);
}

// Checks the field arithmetic against the CPU: for each i, out gets
// a+b, a-b, a*b, a^5 and 2^s*a.
kernel void m31_selftest(device const uint* a [[buffer(0)]],
                         device const uint* b [[buffer(1)]],
                         device const uint* sh [[buffer(2)]],
                         device uint* out [[buffer(3)]],
                         uint i [[thread_position_in_grid]]) {
    uint x = a[i], y = b[i];
    out[5 * i + 0] = m31_add(x, y);
    out[5 * i + 1] = m31_sub(x, y);
    out[5 * i + 2] = m31_mul(x, y);
    out[5 * i + 3] = m31_pow5(x);
    out[5 * i + 4] = m31_shl(x, sh[i]);
}

// ---------------------------------------------------------------- Poseidon2

// Width 16 over M31, the recursion flavour: 8 full rounds (4 before and 4
// after) and 14 partial ones. Ported statement by statement from `v_permute`
// and its layers in lib.rs; the round constants arrive as one buffer of
// P2_RC_LEN = 8*16 + 14 words, external rounds first.

constant uint P2_WIDTH = 16u;
constant uint P2_HALF_FULL = 4u;
constant uint P2_FULL = 8u;
constant uint P2_PARTIAL = 14u;

// The internal diagonal: -2 on lane 0, then 2^0, 2^1 .. 2^8, 2^10 .. 2^16.
constant uint P2_DIAG_SHIFTS[15] = {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 10u, 12u, 13u, 14u, 15u, 16u};

// M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]] as the Poseidon2 paper's
// add chain (t6, t5, t7, t4 are its rows).
inline void p2_m4(thread uint* x, uint b) {
    uint x0 = x[4 * b], x1 = x[4 * b + 1], x2 = x[4 * b + 2], x3 = x[4 * b + 3];
    uint t0 = m31_add(x0, x1);
    uint t1 = m31_add(x2, x3);
    uint t2 = m31_add(m31_shl(x1, 1), t1);
    uint t3 = m31_add(m31_shl(x3, 1), t0);
    uint t4 = m31_add(m31_shl(t1, 2), t3);
    uint t5 = m31_add(m31_shl(t0, 2), t2);
    x[4 * b]     = m31_add(t3, t5);
    x[4 * b + 1] = t5;
    x[4 * b + 2] = m31_add(t2, t4);
    x[4 * b + 3] = t4;
}

inline void p2_external(thread uint* s) {
    for (uint b = 0; b < 4u; ++b) p2_m4(s, b);
    for (uint r = 0; r < 4u; ++r) {
        uint sum = m31_add(m31_add(s[r], s[4 + r]), m31_add(s[8 + r], s[12 + r]));
        for (uint b = 0; b < 4u; ++b) s[4 * b + r] = m31_add(s[4 * b + r], sum);
    }
}

inline void p2_internal(thread uint* s) {
    uint sum = s[0];
    for (uint j = 1; j < P2_WIDTH; ++j) sum = m31_add(sum, s[j]);
    uint s0 = s[0];
    s[0] = m31_sub(sum, m31_shl(s0, 1));
    for (uint j = 1; j < P2_WIDTH; ++j) {
        s[j] = m31_add(sum, m31_shl(s[j], P2_DIAG_SHIFTS[j - 1]));
    }
}

inline void p2_permute(thread uint* s, device const uint* rc) {
    p2_external(s);
    for (uint r = 0; r < P2_HALF_FULL; ++r) {
        for (uint k = 0; k < P2_WIDTH; ++k) s[k] = m31_pow5(m31_add(s[k], rc[r * P2_WIDTH + k]));
        p2_external(s);
    }
    for (uint r = 0; r < P2_PARTIAL; ++r) {
        s[0] = m31_pow5(m31_add(s[0], rc[P2_FULL * P2_WIDTH + r]));
        p2_internal(s);
    }
    for (uint r = P2_HALF_FULL; r < P2_FULL; ++r) {
        for (uint k = 0; k < P2_WIDTH; ++k) s[k] = m31_pow5(m31_add(s[k], rc[r * P2_WIDTH + k]));
        p2_external(s);
    }
}

// One permutation per thread, in place over 16 lanes each.
kernel void p2_permute_test(device uint* states [[buffer(0)]],
                            device const uint* rc [[buffer(1)]],
                            uint i [[thread_position_in_grid]]) {
    uint s[16];
    for (uint k = 0; k < 16u; ++k) s[k] = states[16 * i + k];
    p2_permute(s, rc);
    for (uint k = 0; k < 16u; ++k) states[16 * i + k] = s[k];
}

// Leaf i of a column commitment: the 2k lanes ev[j][i] (j < k) then
// ev[j][M + i], hashed in chain form, h = 0^8 then h = P(h || chunk)[0..8]
// per zero-padded 8-lane chunk (lib.rs `v_leaf` with the lane function of
// `sk_commit_columns_p2`). One thread per leaf, so every write has a fixed
// address and no two threads meet.
kernel void p2_leaves_columns(device const uint* ev [[buffer(0)]],
                              device uint* out [[buffer(1)]],
                              device const uint* rc [[buffer(2)]],
                              constant uint& k [[buffer(3)]],
                              constant uint& big_m [[buffer(4)]],
                              uint i [[thread_position_in_grid]]) {
    uint n = 2u * big_m;
    uint lanes = 2u * k;
    uint chunks = (lanes + 7u) / 8u;
    uint h[8];
    for (uint t = 0; t < 8u; ++t) h[t] = 0u;
    for (uint c = 0; c < chunks; ++c) {
        uint s[16];
        for (uint t = 0; t < 8u; ++t) s[t] = h[t];
        for (uint t = 0; t < 8u; ++t) {
            uint l = c * 8u + t;
            uint v = 0u;
            if (l < lanes) v = (l < k) ? ev[l * n + i] : ev[(l - k) * n + big_m + i];
            s[8u + t] = v;
        }
        p2_permute(s, rc);
        for (uint t = 0; t < 8u; ++t) h[t] = s[t];
    }
    for (uint t = 0; t < 8u; ++t) out[8u * i + t] = h[t];
}

// One level of the tree above: node i = P(prev pair)[0..8]. Input and output
// are disjoint ranges of the same tree buffer.
kernel void p2_compress_level(device uint* tree [[buffer(0)]],
                              device const uint* rc [[buffer(1)]],
                              constant uint& in_off [[buffer(2)]],
                              constant uint& out_off [[buffer(3)]],
                              uint i [[thread_position_in_grid]]) {
    uint s[16];
    for (uint t = 0; t < 16u; ++t) s[t] = tree[in_off + 16u * i + t];
    p2_permute(s, rc);
    for (uint t = 0; t < 8u; ++t) tree[out_off + 8u * i + t] = s[t];
}

// ---------------------------------------------------------------- circle FFT

// The transforms of lib.rs `evaluate` and `interpolate`, one dispatch per
// stage over all columns at once: the grid is (butterfly, column) and column
// j occupies [j*n, (j+1)*n). Every stage has exactly M butterflies whatever
// its block size, since the blocks halve as the block count doubles, so the
// grid is the same for all of them and only the twiddle table and the stride
// change.
//
// A butterfly index b splits into the block s = (b >> log_h) << (log_h + 1)
// and the position i = b & (h - 1) inside it, which is the CPU's nested
// loop over blocks and positions flattened.

inline uint bit_reverse(uint x, uint bits) {
    return reverse_bits(x) >> (32u - bits);
}

kernel void fft_fill_zero(device uint* v [[buffer(0)]],
                          constant uint& n [[buffer(1)]],
                          uint2 g [[thread_position_in_grid]]) {
    v[g.y * n + g.x] = 0u;
}

// Coefficients into bit-reversed positions; the tail beyond `len` stays zero,
// which is the low-degree extension.
kernel void fft_scatter(device const uint* coefs [[buffer(0)]],
                        device uint* v [[buffer(1)]],
                        constant uint& len [[buffer(2)]],
                        constant uint& n [[buffer(3)]],
                        constant uint& bits [[buffer(4)]],
                        uint2 g [[thread_position_in_grid]]) {
    v[g.y * n + bit_reverse(g.x, bits)] = coefs[g.y * len + g.x];
}

kernel void fft_eval_stage(device uint* v [[buffer(0)]],
                           device const uint* tx [[buffer(1)]],
                           constant uint& log_h [[buffer(2)]],
                           constant uint& n [[buffer(3)]],
                           uint2 g [[thread_position_in_grid]]) {
    uint h = 1u << log_h;
    uint i = g.x & (h - 1u);
    uint s = (g.x >> log_h) << (log_h + 1u);
    device uint* col = v + g.y * n;
    uint a = col[s + i];
    uint t = m31_mul(tx[i], col[s + i + h]);
    col[s + i] = m31_add(a, t);
    col[s + i + h] = m31_sub(a, t);
}

kernel void fft_eval_twin(device uint* v [[buffer(0)]],
                          device const uint* ty [[buffer(1)]],
                          constant uint& big_m [[buffer(2)]],
                          constant uint& n [[buffer(3)]],
                          uint2 g [[thread_position_in_grid]]) {
    device uint* col = v + g.y * n;
    uint a = col[g.x];
    uint t = m31_mul(ty[g.x], col[big_m + g.x]);
    col[g.x] = m31_add(a, t);
    col[big_m + g.x] = m31_sub(a, t);
}

kernel void fft_interp_twin(device uint* v [[buffer(0)]],
                            device const uint* ty_inv [[buffer(1)]],
                            constant uint& big_m [[buffer(2)]],
                            constant uint& n [[buffer(3)]],
                            uint2 g [[thread_position_in_grid]]) {
    device uint* col = v + g.y * n;
    uint a = col[g.x];
    uint b = col[big_m + g.x];
    col[g.x] = m31_add(a, b);
    col[big_m + g.x] = m31_mul(m31_sub(a, b), ty_inv[g.x]);
}

kernel void fft_interp_stage(device uint* v [[buffer(0)]],
                             device const uint* tx_inv [[buffer(1)]],
                             constant uint& log_h [[buffer(2)]],
                             constant uint& n [[buffer(3)]],
                             uint2 g [[thread_position_in_grid]]) {
    uint h = 1u << log_h;
    uint i = g.x & (h - 1u);
    uint s = (g.x >> log_h) << (log_h + 1u);
    device uint* col = v + g.y * n;
    uint a = col[s + i];
    uint b = col[s + i + h];
    col[s + i] = m31_add(a, b);
    col[s + i + h] = m31_mul(m31_sub(a, b), tx_inv[i]);
}

// The n^-1 scale and the bit-reversal, into the coefficient buffer.
kernel void fft_interp_out(device const uint* v [[buffer(0)]],
                           device uint* out [[buffer(1)]],
                           constant uint& n_inv [[buffer(2)]],
                           constant uint& n [[buffer(3)]],
                           constant uint& bits [[buffer(4)]],
                           uint2 g [[thread_position_in_grid]]) {
    out[g.y * n + bit_reverse(g.x, bits)] = m31_mul(v[g.y * n + g.x], n_inv);
}
