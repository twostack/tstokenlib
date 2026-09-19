//! Native kernels for the tstokenlib Circle-STARK prover.
//!
//! Every kernel is an exact port of the Dart code in
//! `lib/src/crypto/stark_prover.dart` / `circle_fft.dart` / `m31.dart`, so a
//! proof built with these kernels is byte-identical to one built in pure
//! Dart. The Dart side (`lib/src/crypto/stark_kernels.dart`) owns the
//! transcript and the proof layout; this crate only does the arithmetic.
//!
//! Conventions (shared with the Dart side):
//! * M31 values are canonical `u32` in `[0, p)`, p = 2^31 - 1.
//! * QM31 values are 4 consecutive `u32` limbs `[c0.a, c0.b, c1.a, c1.b]`.
//! * A block of `k` columns of length `L` is one contiguous array, column `j`
//!   at `[j*L, (j+1)*L)`.
//! * A circle domain of size 2^(m+1) is stored in twin layout: position
//!   `i < M` holds the point `HalfCoset(m).at(i)`, position `M + i` its
//!   conjugate.
//! * A Merkle tree over `M` leaves is `(2M - 1) * 32` bytes: the leaf level,
//!   then each level above it, the root last.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

// ------------------------------------------------------------------ M31

const P: u32 = 0x7fff_ffff;

#[inline(always)]
fn add(a: u32, b: u32) -> u32 {
    let r = a + b;
    if r >= P {
        r - P
    } else {
        r
    }
}

#[inline(always)]
fn sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + P - b
    }
}

#[inline(always)]
fn neg(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        P - a
    }
}

#[inline(always)]
fn mul(a: u32, b: u32) -> u32 {
    let x = (a as u64) * (b as u64);
    let r = (x & P as u64) + (x >> 31);
    let r = (r & P as u64) + (r >> 31);
    let r = r as u32;
    if r >= P {
        r - P
    } else {
        r
    }
}

fn pow(mut b: u32, mut e: u64) -> u32 {
    let mut r = 1u32;
    while e > 0 {
        if e & 1 == 1 {
            r = mul(r, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    r
}

#[inline]
fn inv(a: u32) -> u32 {
    pow(a, (P - 2) as u64)
}

/// Montgomery batch inversion; zero entries are not allowed.
fn batch_inv(xs: &[u32]) -> Vec<u32> {
    let n = xs.len();
    let mut prefix = vec![0u32; n];
    let mut acc = 1u32;
    for i in 0..n {
        prefix[i] = acc;
        acc = mul(acc, xs[i]);
    }
    let mut iv = inv(acc);
    let mut out = vec![0u32; n];
    for i in (0..n).rev() {
        out[i] = mul(iv, prefix[i]);
        iv = mul(iv, xs[i]);
    }
    out
}

// ------------------------------------------------------------------ QM31

type Q = [u32; 4];

const Q_ZERO: Q = [0, 0, 0, 0];
const Q_ONE: Q = [1, 0, 0, 0];

#[inline(always)]
fn cmul(a0: u32, a1: u32, b0: u32, b1: u32) -> (u32, u32) {
    (sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0)))
}

/// (a + bi)(2 + i) = (2a - b) + (a + 2b)i
#[inline(always)]
fn cmul_2i(a: u32, b: u32) -> (u32, u32) {
    (sub(add(a, a), b), add(a, add(b, b)))
}

#[inline(always)]
fn qadd(a: &Q, b: &Q) -> Q {
    [add(a[0], b[0]), add(a[1], b[1]), add(a[2], b[2]), add(a[3], b[3])]
}

#[inline(always)]
fn qsub(a: &Q, b: &Q) -> Q {
    [sub(a[0], b[0]), sub(a[1], b[1]), sub(a[2], b[2]), sub(a[3], b[3])]
}

#[inline(always)]
fn qscale(a: &Q, m: u32) -> Q {
    [mul(a[0], m), mul(a[1], m), mul(a[2], m), mul(a[3], m)]
}

/// (c0 + c1 u)(d0 + d1 u) = (c0 d0 + c1 d1 (2+i)) + (c0 d1 + c1 d0) u
#[inline(always)]
fn qmul(a: &Q, b: &Q) -> Q {
    let (p0, p1) = cmul(a[0], a[1], b[0], b[1]);
    let (q0, q1) = cmul(a[2], a[3], b[2], b[3]);
    let (q0, q1) = cmul_2i(q0, q1);
    let (r0, r1) = cmul(a[0], a[1], b[2], b[3]);
    let (s0, s1) = cmul(a[2], a[3], b[0], b[1]);
    [add(p0, q0), add(p1, q1), add(r0, s0), add(r1, s1)]
}

fn qinv(a: &Q) -> Q {
    // n = c0^2 - c1^2 (2+i)
    let (c0a, c0b) = cmul(a[0], a[1], a[0], a[1]);
    let (c1a, c1b) = cmul(a[2], a[3], a[2], a[3]);
    let (t0, t1) = cmul_2i(c1a, c1b);
    let (n0, n1) = (sub(c0a, t0), sub(c0b, t1));
    // ni = conj(n) / |n|^2
    let nn = add(mul(n0, n0), mul(n1, n1));
    let ninv = inv(nn);
    let (ni0, ni1) = (mul(n0, ninv), mul(neg(n1), ninv));
    let (r0, r1) = cmul(a[0], a[1], ni0, ni1);
    let (s0, s1) = cmul(neg(a[2]), neg(a[3]), ni0, ni1);
    [r0, r1, s0, s1]
}

fn qbatch_inv(xs: &[Q]) -> Vec<Q> {
    let n = xs.len();
    let mut prefix = vec![Q_ONE; n];
    let mut acc = Q_ONE;
    for i in 0..n {
        prefix[i] = acc;
        acc = qmul(&acc, &xs[i]);
    }
    let mut iv = qinv(&acc);
    let mut out = vec![Q_ZERO; n];
    for i in (0..n).rev() {
        out[i] = qmul(&iv, &prefix[i]);
        iv = qmul(&iv, &xs[i]);
    }
    out
}

#[inline(always)]
fn q_at(a: &[u32], i: usize) -> Q {
    [a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3]]
}

#[inline(always)]
fn q_set(a: &mut [u32], i: usize, v: &Q) {
    a[4 * i..4 * i + 4].copy_from_slice(v);
}

/// (f0 + f1) + alpha * (f0 - f1) * twiddle_inv
#[inline(always)]
fn fold_pair(f0: &Q, f1: &Q, twiddle_inv: u32, alpha: &Q) -> Q {
    let s = qadd(f0, f1);
    let d = qscale(&qsub(f0, f1), twiddle_inv);
    qadd(&s, &qmul(alpha, &d))
}

// ------------------------------------------------------------------ circle group

#[derive(Clone, Copy)]
struct Pt {
    x: u32,
    y: u32,
}

const GENERATOR: Pt = Pt { x: 2, y: 1268011823 };
const IDENTITY: Pt = Pt { x: 1, y: 0 };

impl Pt {
    fn mul(self, o: Pt) -> Pt {
        Pt {
            x: sub(mul(self.x, o.x), mul(self.y, o.y)),
            y: add(mul(self.x, o.y), mul(o.x, self.y)),
        }
    }
    fn double(self) -> Pt {
        Pt {
            x: sub(mul(2, mul(self.x, self.x)), 1),
            y: mul(2, mul(self.x, self.y)),
        }
    }
    fn pow(self, mut e: u64) -> Pt {
        let mut r = IDENTITY;
        let mut b = self;
        while e > 0 {
            if e & 1 == 1 {
                r = r.mul(b);
            }
            b = b.double();
            e >>= 1;
        }
        r
    }
    fn subgroup_gen(log: u32) -> Pt {
        GENERATOR.pow(1u64 << (31 - log))
    }
}

/// x/y coordinates of HalfCoset(log) in natural order, with inverses.
struct Tables {
    x: Vec<u32>,
    y: Vec<u32>,
    x_inv: Vec<u32>,
    y_inv: Vec<u32>,
}

fn tables(log: u32) -> Arc<Tables> {
    static CACHE: OnceLock<Mutex<HashMap<u32, Arc<Tables>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = cache.lock().unwrap().get(&log) {
        return t.clone();
    }
    let n = 1usize << log;
    let initial = Pt::subgroup_gen(log + 2);
    let step = Pt::subgroup_gen(log);
    let mut x = vec![0u32; n];
    let mut y = vec![0u32; n];
    let mut p = initial;
    for i in 0..n {
        x[i] = p.x;
        y[i] = p.y;
        p = p.mul(step);
    }
    let x_inv = batch_inv(&x);
    let y_inv = batch_inv(&y);
    let t = Arc::new(Tables { x, y, x_inv, y_inv });
    cache.lock().unwrap().insert(log, t.clone());
    t
}

// ------------------------------------------------------------------ circle FFT

fn bitrev(x: usize, bits: u32) -> usize {
    let mut r = 0usize;
    for i in 0..bits {
        r = (r << 1) | ((x >> i) & 1);
    }
    r
}

/// Evaluations in twin layout on HalfCoset(m) (size 2^(m+1)) -> coefficients
/// in natural order.
fn interpolate(vals: &[u32], m: u32, out: &mut [u32]) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    debug_assert_eq!(vals.len(), n);
    let mut v = vals.to_vec();
    let t = tables(m);
    for i in 0..big_m {
        let (a, b) = (v[i], v[big_m + i]);
        v[i] = add(a, b);
        v[big_m + i] = mul(sub(a, b), t.y_inv[i]);
    }
    let mut l = 0u32;
    while (big_m >> l) >= 2 {
        let len = big_m >> l;
        let h = len >> 1;
        let tl = tables(m - l);
        let mut s = 0;
        while s < n {
            for i in 0..h {
                let (a, b) = (v[s + i], v[s + i + h]);
                v[s + i] = add(a, b);
                v[s + i + h] = mul(sub(a, b), tl.x_inv[i]);
            }
            s += len;
        }
        l += 1;
    }
    let n_inv = inv(n as u32);
    let bits = m + 1;
    for pos in 0..n {
        out[bitrev(pos, bits)] = mul(v[pos], n_inv);
    }
}

/// Coefficients (natural order, length a power of two <= 2^(m+1)) ->
/// evaluations in twin layout on HalfCoset(m); shorter inputs are the LDE.
fn evaluate(coefs: &[u32], m: u32, out: &mut [u32]) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let bits = m + 1;
    for x in out.iter_mut() {
        *x = 0;
    }
    for (i, c) in coefs.iter().enumerate() {
        out[bitrev(i, bits)] = *c;
    }
    let v = out;
    let mut l = m as i64 - 1;
    while l >= 0 {
        let len = big_m >> l;
        let h = len >> 1;
        let tl = tables(m - l as u32);
        let mut s = 0;
        while s < n {
            for i in 0..h {
                let a = v[s + i];
                let b = mul(tl.x[i], v[s + i + h]);
                v[s + i] = add(a, b);
                v[s + i + h] = sub(a, b);
            }
            s += len;
        }
        l -= 1;
    }
    let t = tables(m);
    for i in 0..big_m {
        let a = v[i];
        let b = mul(t.y[i], v[big_m + i]);
        v[i] = add(a, b);
        v[big_m + i] = sub(a, b);
    }
}

// ------------------------------------------------------------------ SHA256

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline(always)]
fn sha_block(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let mut i = 0;
    while i + 64 <= data.len() {
        sha_block(&mut state, &data[i..i + 64]);
        i += 64;
    }
    let rem = &data[i..];
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let total = if rem.len() + 9 <= 64 { 64 } else { 128 };
    let bits = (data.len() as u64) * 8;
    tail[total - 8..total].copy_from_slice(&bits.to_be_bytes());
    sha_block(&mut state, &tail[..64]);
    if total == 128 {
        sha_block(&mut state, &tail[64..128]);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

// ------------------------------------------------------------------ Poseidon2 over M31 (width 16)

const P2_WIDTH: usize = 16;
const P2_HALF_FULL: usize = 4;
const P2_FULL: usize = 8;
const P2_PARTIAL: usize = 14;
/// Round constants: external 8 x 16, then internal 14 (passed in from Dart,
/// which derives them; see `Poseidon2M31`).
const P2_RC_LEN: usize = P2_FULL * P2_WIDTH + P2_PARTIAL;

const M4: [[u32; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];

fn p2_internal_diag() -> [u32; 16] {
    let shifts = [0u32, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16];
    let mut d = [0u32; 16];
    d[0] = P - 2;
    for (i, s) in shifts.iter().enumerate() {
        d[i + 1] = 1u32 << s;
    }
    d
}

#[inline(always)]
fn pow5(x: u32) -> u32 {
    let x2 = mul(x, x);
    mul(mul(x2, x2), x)
}

fn p2_external_layer(s: &mut [u32; 16]) {
    let mut y = [0u32; 16];
    for b in 0..4 {
        for r in 0..4 {
            let mut acc = 0u32;
            for c in 0..4 {
                acc = add(acc, mul(s[4 * b + c], M4[r][c]));
            }
            y[4 * b + r] = acc;
        }
    }
    for r in 0..4 {
        let sum = add(add(y[r], y[4 + r]), add(y[8 + r], y[12 + r]));
        for b in 0..4 {
            y[4 * b + r] = add(y[4 * b + r], sum);
        }
    }
    *s = y;
}

fn p2_internal_layer(s: &mut [u32; 16], diag: &[u32; 16]) {
    let mut sum = 0u32;
    for v in s.iter() {
        sum = add(sum, *v);
    }
    for j in 0..16 {
        s[j] = add(sum, mul(diag[j], s[j]));
    }
}

/// The full permutation, exactly as `Poseidon2M31.permute`.
fn p2_permute(s: &mut [u32; 16], rc: &[u32], diag: &[u32; 16]) {
    p2_external_layer(s);
    for r in 0..P2_HALF_FULL {
        for k in 0..16 {
            s[k] = pow5(add(s[k], rc[r * 16 + k]));
        }
        p2_external_layer(s);
    }
    for r in 0..P2_PARTIAL {
        s[0] = pow5(add(s[0], rc[P2_FULL * 16 + r]));
        p2_internal_layer(s, diag);
    }
    for r in P2_HALF_FULL..P2_FULL {
        for k in 0..16 {
            s[k] = pow5(add(s[k], rc[r * 16 + k]));
        }
        p2_external_layer(s);
    }
}

/// P(left || right)[0..8]
#[inline]
fn p2_compress(left: &[u32], right: &[u32], rc: &[u32], diag: &[u32; 16], out: &mut [u32]) {
    let mut s = [0u32; 16];
    s[..8].copy_from_slice(left);
    s[8..].copy_from_slice(right);
    p2_permute(&mut s, rc, diag);
    out.copy_from_slice(&s[..8]);
}

/// Leaf over lanes: h = 0; h = P(h || chunk)[0..8] per zero-padded 8-lane chunk.
fn p2_leaf(lanes: &[u32], rc: &[u32], diag: &[u32; 16], out: &mut [u32]) {
    let mut h = [0u32; 8];
    let chunks = if lanes.is_empty() { 1 } else { (lanes.len() + 7) / 8 };
    for c in 0..chunks {
        let mut chunk = [0u32; 8];
        for i in 0..8 {
            let k = c * 8 + i;
            if k < lanes.len() {
                chunk[i] = lanes[k];
            }
        }
        let mut next = [0u32; 8];
        p2_compress(&h, &chunk, rc, diag, &mut next);
        h = next;
    }
    out.copy_from_slice(&h);
}

/// Build the levels above the leaves already written at `tree[..leaves*8]` (lanes).
fn merkle_above_p2(tree: &mut [u32], leaves: usize, rc: &[u32], diag: &[u32; 16]) {
    let mut offset = 0usize;
    let mut len = leaves;
    while len > 1 {
        let next = len / 2;
        let (below, above) = tree.split_at_mut(offset + len * 8);
        let prev = &below[offset..offset + len * 8];
        par_fill_u32(&mut above[..next * 8], 8, 2048, |i, node| {
            p2_compress(&prev[16 * i..16 * i + 8], &prev[16 * i + 8..16 * i + 16], rc, diag, node);
        });
        offset += len * 8;
        len = next;
    }
}

// ------------------------------------------------------------------ parallel helpers

fn threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(16)
}

/// Fill `out` (split into `chunk_len`-sized items) by calling `f(item_index, item)`
/// across threads.
fn par_fill<F>(out: &mut [u8], item_len: usize, min_items: usize, f: F)
where
    F: Fn(usize, &mut [u8]) + Sync,
{
    let n = out.len() / item_len;
    let th = threads();
    if n < min_items || th <= 1 {
        for (i, item) in out.chunks_mut(item_len).enumerate() {
            f(i, item);
        }
        return;
    }
    let per = (n + th - 1) / th;
    std::thread::scope(|s| {
        for (t, block) in out.chunks_mut(per * item_len).enumerate() {
            let f = &f;
            s.spawn(move || {
                for (j, item) in block.chunks_mut(item_len).enumerate() {
                    f(t * per + j, item);
                }
            });
        }
    });
}

fn par_fill_u32<F>(out: &mut [u32], item_len: usize, min_items: usize, f: F)
where
    F: Fn(usize, &mut [u32]) + Sync,
{
    let n = out.len() / item_len;
    let th = threads();
    if n < min_items || th <= 1 {
        for (i, item) in out.chunks_mut(item_len).enumerate() {
            f(i, item);
        }
        return;
    }
    let per = (n + th - 1) / th;
    std::thread::scope(|s| {
        for (t, block) in out.chunks_mut(per * item_len).enumerate() {
            let f = &f;
            s.spawn(move || {
                for (j, item) in block.chunks_mut(item_len).enumerate() {
                    f(t * per + j, item);
                }
            });
        }
    });
}

// ------------------------------------------------------------------ Merkle

/// Build the levels above the leaves already written at `tree[..leaves*32]`.
fn merkle_above(tree: &mut [u8], leaves: usize) {
    let mut offset = 0usize;
    let mut len = leaves;
    while len > 1 {
        let next = len / 2;
        let (below, above) = tree.split_at_mut(offset + len * 32);
        let prev = &below[offset..offset + len * 32];
        par_fill(&mut above[..next * 32], 32, 4096, |i, node| {
            node.copy_from_slice(&sha256(&prev[64 * i..64 * i + 64]));
        });
        offset += len * 32;
        len = next;
    }
}

fn tree_bytes(leaves: usize) -> usize {
    (2 * leaves - 1) * 32
}

// ------------------------------------------------------------------ exported kernels

/// ABI version; the Dart side refuses a mismatch.
#[no_mangle]
pub extern "C" fn sk_version() -> u32 {
    2
}

/// One Poseidon2 permutation of 16 lanes in place, with the round constants
/// `rc` (external 8 x 16, then internal 14).
#[no_mangle]
pub unsafe extern "C" fn sk_poseidon2_permute(state: *mut u32, rc: *const u32) {
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let s = std::slice::from_raw_parts_mut(state, 16);
    let diag = p2_internal_diag();
    let mut st = [0u32; 16];
    st.copy_from_slice(s);
    p2_permute(&mut st, rc, &diag);
    s.copy_from_slice(&st);
}

/// [sk_commit_columns] with Poseidon2: leaf i is the Poseidon2 leaf of the
/// 2k lanes `ev[j][i]`, `ev[j][M+i]`; `out_tree` holds `(2M - 1) * 8` lanes.
#[no_mangle]
pub unsafe extern "C" fn sk_commit_columns_p2(
    coefs: *const u32,
    k: usize,
    len: usize,
    m: u32,
    rc: *const u32,
    out_ev: *mut u32,
    out_tree: *mut u32,
) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let ev = std::slice::from_raw_parts_mut(out_ev, k * n);
    let tree = std::slice::from_raw_parts_mut(out_tree, (2 * big_m - 1) * 8);
    let diag = p2_internal_diag();
    par_fill_u32(ev, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
    let ev: &[u32] = ev;
    par_fill_u32(&mut tree[..big_m * 8], 8, 2048, |i, leaf| {
        let mut lanes = vec![0u32; 2 * k];
        for j in 0..k {
            lanes[j] = ev[j * n + i];
            lanes[k + j] = ev[j * n + big_m + i];
        }
        p2_leaf(&lanes, rc, &diag, leaf);
    });
    merkle_above_p2(tree, big_m, rc, &diag);
}

/// [sk_merkle_pairs] with Poseidon2; `out_tree` holds `(2h - 1) * 8` lanes.
#[no_mangle]
pub unsafe extern "C" fn sk_merkle_pairs_p2(cur: *const u32, log_len: u32, rc: *const u32, out_tree: *mut u32) {
    let len = 1usize << log_len;
    let h = len / 2;
    let cur = std::slice::from_raw_parts(cur, 4 * len);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let tree = std::slice::from_raw_parts_mut(out_tree, (2 * h - 1) * 8);
    let diag = p2_internal_diag();
    par_fill_u32(&mut tree[..h * 8], 8, 2048, |i, leaf| {
        let mut lanes = [0u32; 8];
        lanes[..4].copy_from_slice(&cur[4 * i..4 * i + 4]);
        lanes[4..].copy_from_slice(&cur[4 * (h + i)..4 * (h + i) + 4]);
        p2_leaf(&lanes, rc, &diag, leaf);
    });
    merkle_above_p2(tree, h, rc, &diag);
}

/// `k` columns of 2^(m+1) values (twin layout) -> `k` columns of coefficients.
#[no_mangle]
pub unsafe extern "C" fn sk_interpolate_columns(vals: *const u32, k: usize, m: u32, out: *mut u32) {
    let n = 1usize << (m + 1);
    let vals = std::slice::from_raw_parts(vals, k * n);
    let out = std::slice::from_raw_parts_mut(out, k * n);
    par_fill_u32(out, n, 2, |j, col| interpolate(&vals[j * n..(j + 1) * n], m, col));
}

/// `k` columns of `len` coefficients -> `k` columns of 2^(m+1) evaluations.
#[no_mangle]
pub unsafe extern "C" fn sk_evaluate_columns(coefs: *const u32, k: usize, len: usize, m: u32, out: *mut u32) {
    let n = 1usize << (m + 1);
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let out = std::slice::from_raw_parts_mut(out, k * n);
    par_fill_u32(out, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
}

/// Evaluate `k` coefficient columns on HalfCoset(m) ∪ conj and commit: leaf
/// `i` is SHA256 of the 2k little-endian words `ev[j][i]`, `ev[j][M+i]`.
/// `out_ev` holds the k columns of 2^(m+1) values, `out_tree` the
/// `(2M - 1) * 32` bytes of the tree.
#[no_mangle]
pub unsafe extern "C" fn sk_commit_columns(
    coefs: *const u32,
    k: usize,
    len: usize,
    m: u32,
    out_ev: *mut u32,
    out_tree: *mut u8,
) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let ev = std::slice::from_raw_parts_mut(out_ev, k * n);
    let tree = std::slice::from_raw_parts_mut(out_tree, tree_bytes(big_m));
    par_fill_u32(ev, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
    let ev: &[u32] = ev;
    par_fill(&mut tree[..big_m * 32], 32, 4096, |i, leaf| {
        let mut buf = vec![0u8; 8 * k];
        for j in 0..k {
            buf[4 * j..4 * j + 4].copy_from_slice(&ev[j * n + i].to_le_bytes());
            buf[4 * (k + j)..4 * (k + j) + 4].copy_from_slice(&ev[j * n + big_m + i].to_le_bytes());
        }
        leaf.copy_from_slice(&sha256(&buf));
    });
    merkle_above(tree, big_m);
}

/// DEEP quotients of `k` value columns (twin layout on HalfCoset(m)):
/// q = (c * Σ w_j col_j - A * y - B) / (dA * x + dB * y + dC) at every
/// position, P side then C side (y negated). `consts` is
/// `c, A, B, dA, dB, dC, w_0 .. w_{k-1}` as QM31 limbs. With `accumulate`
/// the quotients are added into `out` instead of replacing it.
#[no_mangle]
pub unsafe extern "C" fn sk_deep_quotients(
    consts: *const u32,
    cols: *const u32,
    k: usize,
    m: u32,
    accumulate: u32,
    out: *mut u32,
) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let consts = std::slice::from_raw_parts(consts, 24 + 4 * k);
    let cols = std::slice::from_raw_parts(cols, k * n);
    let out = std::slice::from_raw_parts_mut(out, 4 * n);
    let c = q_at(consts, 0);
    let ca = q_at(consts, 1);
    let cb = q_at(consts, 2);
    let da = q_at(consts, 3);
    let db = q_at(consts, 4);
    let dc = q_at(consts, 5);
    let w: Vec<Q> = (0..k).map(|j| q_at(consts, 6 + j)).collect();
    let t = tables(m);
    // numerators straight into out, denominators aside, then one batch inversion per chunk
    let th = threads();
    let per = ((n + th - 1) / th).max(1024);
    let cols: &[u32] = cols;
    std::thread::scope(|s| {
        for (blk, block) in out.chunks_mut(4 * per).enumerate() {
            let (c, ca, cb, da, db, dc, w, t) = (&c, &ca, &cb, &da, &db, &dc, &w, &t);
            s.spawn(move || {
                let cnt = block.len() / 4;
                let base = blk * per;
                let mut dens = vec![Q_ZERO; cnt];
                let mut nums = vec![Q_ZERO; cnt];
                for r in 0..cnt {
                    let q = base + r;
                    let i = if q < big_m { q } else { q - big_m };
                    let px = t.x[i];
                    let py = if q < big_m { t.y[i] } else { neg(t.y[i]) };
                    let mut sacc = Q_ZERO;
                    for j in 0..k {
                        sacc = qadd(&sacc, &qscale(&w[j], cols[j * n + q]));
                    }
                    nums[r] = qsub(&qsub(&qmul(c, &sacc), &qscale(ca, py)), cb);
                    dens[r] = qadd(&qadd(&qscale(da, px), &qscale(db, py)), dc);
                }
                let invs = qbatch_inv(&dens);
                for r in 0..cnt {
                    let v = qmul(&nums[r], &invs[r]);
                    if accumulate != 0 {
                        let prev = q_at(block, r);
                        q_set(block, r, &qadd(&prev, &v));
                    } else {
                        q_set(block, r, &v);
                    }
                }
            });
        }
    });
}

/// Circle fold of a twin-layout QM31 array on HalfCoset(m):
/// out[i] = (q[i] + q[M+i]) + alpha * (q[i] - q[M+i]) / y_i, added into
/// `out` when `accumulate`.
#[no_mangle]
pub unsafe extern "C" fn sk_circle_fold(q: *const u32, m: u32, alpha: *const u32, accumulate: u32, out: *mut u32) {
    let big_m = 1usize << m;
    let q = std::slice::from_raw_parts(q, 8 * big_m);
    let alpha = q_at(std::slice::from_raw_parts(alpha, 4), 0);
    let out = std::slice::from_raw_parts_mut(out, 4 * big_m);
    let t = tables(m);
    par_fill_u32(out, 4, 4096, |i, o| {
        let v = fold_pair(&q_at(q, i), &q_at(q, big_m + i), t.y_inv[i], &alpha);
        if accumulate != 0 {
            let prev = [o[0], o[1], o[2], o[3]];
            o.copy_from_slice(&qadd(&prev, &v));
        } else {
            o.copy_from_slice(&v);
        }
    });
}

/// Line fold of a QM31 layer of length 2^log_len over HalfCoset(log_len):
/// out[i] = (f[i] + f[i+h]) + alpha * (f[i] - f[i+h]) / x_i, h = len / 2.
#[no_mangle]
pub unsafe extern "C" fn sk_line_fold(cur: *const u32, log_len: u32, alpha: *const u32, out: *mut u32) {
    let len = 1usize << log_len;
    let h = len / 2;
    let cur = std::slice::from_raw_parts(cur, 4 * len);
    let alpha = q_at(std::slice::from_raw_parts(alpha, 4), 0);
    let out = std::slice::from_raw_parts_mut(out, 4 * h);
    let t = tables(log_len);
    par_fill_u32(out, 4, 4096, |i, o| {
        o.copy_from_slice(&fold_pair(&q_at(cur, i), &q_at(cur, h + i), t.x_inv[i], &alpha));
    });
}

/// Merkle tree over a QM31 layer of length 2^log_len: leaf i is SHA256 of
/// the 8 little-endian limb words of `cur[i]`, `cur[i + h]`.
#[no_mangle]
pub unsafe extern "C" fn sk_merkle_pairs(cur: *const u32, log_len: u32, out_tree: *mut u8) {
    let len = 1usize << log_len;
    let h = len / 2;
    let cur = std::slice::from_raw_parts(cur, 4 * len);
    let tree = std::slice::from_raw_parts_mut(out_tree, tree_bytes(h));
    par_fill(&mut tree[..h * 32], 32, 4096, |i, leaf| {
        let mut buf = [0u8; 32];
        for l in 0..4 {
            buf[4 * l..4 * l + 4].copy_from_slice(&cur[4 * i + l].to_le_bytes());
            buf[16 + 4 * l..16 + 4 * l + 4].copy_from_slice(&cur[4 * (h + i) + l].to_le_bytes());
        }
        leaf.copy_from_slice(&sha256(&buf));
    });
    merkle_above(tree, h);
}

/// SHA256 of `len` bytes (for tests of the hash itself).
#[no_mangle]
pub unsafe extern "C" fn sk_sha256(data: *const u8, len: usize, out: *mut u8) {
    let data = std::slice::from_raw_parts(data, len);
    let out = std::slice::from_raw_parts_mut(out, 32);
    out.copy_from_slice(&sha256(data));
}
