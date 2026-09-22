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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
pub(crate) struct Tables {
    pub(crate) x: Vec<u32>,
    pub(crate) y: Vec<u32>,
    pub(crate) x_inv: Vec<u32>,
    pub(crate) y_inv: Vec<u32>,
}

pub(crate) fn tables(log: u32) -> Arc<Tables> {
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

/// Leaves (or nodes) hashed side by side: the permutation runs on `[u32; N]`
/// per state lane in struct-of-arrays layout, so every field operation is a
/// loop of N independent lanes that the compiler vectorises.
const P2_N: usize = 16;

#[inline(always)]
fn v_add<const N: usize>(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        let s = a[i] + b[i];
        r[i] = s.min(s.wrapping_sub(P));
    }
    r
}

#[inline(always)]
fn v_sub<const N: usize>(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        let s = a[i].wrapping_sub(b[i]);
        r[i] = s.min(s.wrapping_add(P));
    }
    r
}

/// 2^s * a mod p: a rotation of the 31-bit value (a canonical, s in 1..=30).
#[inline(always)]
fn v_shl<const N: usize>(a: &[u32; N], s: u32) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        r[i] = ((a[i] << s) & P) | (a[i] >> (31 - s));
    }
    r
}

#[inline(always)]
fn v_mul<const N: usize>(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        let x = (a[i] as u64) * (b[i] as u64);
        let y = ((x & P as u64) + (x >> 31)) as u32;
        let z = (y & P) + (y >> 31);
        r[i] = z.min(z.wrapping_sub(P));
    }
    r
}

#[inline(always)]
fn v_pow5<const N: usize>(x: &[u32; N]) -> [u32; N] {
    let x2 = v_mul(x, x);
    v_mul(&v_mul(&x2, &x2), x)
}

#[inline(always)]
fn v_add_const<const N: usize>(a: &[u32; N], c: u32) -> [u32; N] {
    let mut r = [0u32; N];
    for i in 0..N {
        let s = a[i] + c;
        r[i] = s.min(s.wrapping_sub(P));
    }
    r
}

/// M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]] as the add chain of the
/// Poseidon2 paper (t6, t5, t7, t4 are its rows).
#[inline(always)]
fn v_m4<const N: usize>(x: &mut [[u32; N]; 16], b: usize) {
    let (x0, x1, x2, x3) = (x[4 * b], x[4 * b + 1], x[4 * b + 2], x[4 * b + 3]);
    let t0 = v_add(&x0, &x1);
    let t1 = v_add(&x2, &x3);
    let t2 = v_add(&v_shl(&x1, 1), &t1);
    let t3 = v_add(&v_shl(&x3, 1), &t0);
    let t4 = v_add(&v_shl(&t1, 2), &t3);
    let t5 = v_add(&v_shl(&t0, 2), &t2);
    let t6 = v_add(&t3, &t5);
    let t7 = v_add(&t2, &t4);
    x[4 * b] = t6;
    x[4 * b + 1] = t5;
    x[4 * b + 2] = t7;
    x[4 * b + 3] = t4;
}

#[inline(always)]
fn v_external_layer<const N: usize>(s: &mut [[u32; N]; 16]) {
    for b in 0..4 {
        v_m4(s, b);
    }
    for r in 0..4 {
        let sum = v_add(&v_add(&s[r], &s[4 + r]), &v_add(&s[8 + r], &s[12 + r]));
        for b in 0..4 {
            s[4 * b + r] = v_add(&s[4 * b + r], &sum);
        }
    }
}

/// Internal diagonal: -2 on lane 0, then 2^0, 2^1, .., 2^8, 2^10, .., 2^16.
const P2_DIAG_SHIFTS: [u32; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16];

#[inline(always)]
fn v_internal_layer<const N: usize>(s: &mut [[u32; N]; 16]) {
    let mut sum = s[0];
    for j in 1..16 {
        sum = v_add(&sum, &s[j]);
    }
    s[0] = v_sub(&sum, &v_shl(&s[0], 1));
    for j in 1..16 {
        let sh = P2_DIAG_SHIFTS[j - 1];
        let d = if sh == 0 { s[j] } else { v_shl(&s[j], sh) };
        s[j] = v_add(&sum, &d);
    }
}

/// The full permutation on N states at once, exactly as `Poseidon2M31.permute`.
fn v_permute<const N: usize>(s: &mut [[u32; N]; 16], rc: &[u32]) {
    v_external_layer(s);
    for r in 0..P2_HALF_FULL {
        for k in 0..16 {
            s[k] = v_pow5(&v_add_const(&s[k], rc[r * 16 + k]));
        }
        v_external_layer(s);
    }
    for r in 0..P2_PARTIAL {
        s[0] = v_pow5(&v_add_const(&s[0], rc[P2_FULL * 16 + r]));
        v_internal_layer(s);
    }
    for r in P2_HALF_FULL..P2_FULL {
        for k in 0..16 {
            s[k] = v_pow5(&v_add_const(&s[k], rc[r * 16 + k]));
        }
        v_external_layer(s);
    }
}

/// The permutation of one state in place.
fn p2_permute(s: &mut [u32; 16], rc: &[u32]) {
    let mut v = [[0u32; 1]; 16];
    for k in 0..16 {
        v[k][0] = s[k];
    }
    v_permute(&mut v, rc);
    for k in 0..16 {
        s[k] = v[k][0];
    }
}

/// N leaves at once, leaf l over the lanes `lane(l, k)`, k < n_lanes:
/// h = 0; h = P(h || chunk)[0..8] per zero-padded 8-lane chunk. Writes the
/// 8 digest lanes of leaf l at `out[8l..8l+8]`.
#[inline(always)]
fn v_leaf<const N: usize, F: Fn(usize, usize) -> u32>(n_lanes: usize, lane: F, rc: &[u32], out: &mut [u32]) {
    let chunks = if n_lanes == 0 { 1 } else { (n_lanes + 7) / 8 };
    let mut h = [[0u32; N]; 8];
    for c in 0..chunks {
        let mut s = [[0u32; N]; 16];
        s[..8].copy_from_slice(&h);
        for i in 0..8 {
            let k = c * 8 + i;
            if k < n_lanes {
                for l in 0..N {
                    s[8 + i][l] = lane(l, k);
                }
            }
        }
        v_permute(&mut s, rc);
        h.copy_from_slice(&s[..8]);
    }
    for l in 0..N {
        for k in 0..8 {
            out[8 * l + k] = h[k][l];
        }
    }
}

/// N compressions at once: node l = P(prev[16l..16l+8] || prev[16l+8..16l+16])[0..8]
/// over the 16N lanes of `prev`, written to `out[8l..8l+8]`.
#[inline(always)]
fn v_compress<const N: usize>(prev: &[u32], rc: &[u32], out: &mut [u32]) {
    let mut s = [[0u32; N]; 16];
    for l in 0..N {
        for k in 0..16 {
            s[k][l] = prev[16 * l + k];
        }
    }
    v_permute(&mut s, rc);
    for l in 0..N {
        out[8 * l..8 * l + 8].copy_from_slice(&[s[0][l], s[1][l], s[2][l], s[3][l], s[4][l], s[5][l], s[6][l], s[7][l]]);
    }
}

/// Leaf hashing of `leaves` leaves into `out` (8 lanes each), P2_N at a time.
fn p2_leaves<F: Fn(usize, usize) -> u32 + Sync>(leaves: usize, n_lanes: usize, lane: F, rc: &[u32], out: &mut [u32]) {
    let full = leaves - leaves % P2_N;
    par_fill_u32(&mut out[..full * 8], 8 * P2_N, 256, |b, block| {
        v_leaf::<P2_N, _>(n_lanes, |l, k| lane(b * P2_N + l, k), rc, block);
    });
    for i in full..leaves {
        v_leaf::<1, _>(n_lanes, |_, k| lane(i, k), rc, &mut out[8 * i..8 * i + 8]);
    }
}

/// Build the levels above the leaves already written at `tree[..leaves*8]` (lanes).
fn merkle_above_p2(tree: &mut [u32], leaves: usize, rc: &[u32]) {
    let mut offset = 0usize;
    let mut len = leaves;
    while len > 1 {
        let next = len / 2;
        let (below, above) = tree.split_at_mut(offset + len * 8);
        let prev = &below[offset..offset + len * 8];
        if next % P2_N == 0 {
            par_fill_u32(&mut above[..next * 8], 8 * P2_N, 256, |b, block| {
                v_compress::<P2_N>(&prev[16 * P2_N * b..16 * P2_N * (b + 1)], rc, block);
            });
        } else {
            for (i, node) in above[..next * 8].chunks_mut(8).enumerate() {
                v_compress::<1>(&prev[16 * i..16 * i + 16], rc, node);
            }
        }
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

// ------------------------------------------------------------------ column store

/// Committed evaluations kept on this side of the FFI boundary: `k` columns
/// of `n` words (twin layout), handed to Dart as an id. The later kernels
/// (composition, DEEP quotients, openings) read them in place, so the
/// gigabytes of a node's columns never cross into the Dart heap.
struct Stored {
    k: usize,
    n: usize,
    data: Backing,
}

/// Where a stored column set's words live. Evaluations committed on the GPU
/// stay in the shared (unified-memory) buffer they were computed in, so the
/// composition, DEEP and opening kernels read GPU output in place and a node
/// never holds two copies of its evaluations.
enum Backing {
    Heap(Vec<u32>),
    #[cfg(all(target_os = "macos", feature = "metal"))]
    Shared(gpu::SharedBuffer),
}

impl Backing {
    fn as_slice(&self) -> &[u32] {
        match self {
            Backing::Heap(v) => v,
            #[cfg(all(target_os = "macos", feature = "metal"))]
            Backing::Shared(b) => b.as_slice(),
        }
    }
}

impl Stored {
    fn column(&self, j: usize) -> &[u32] {
        &self.data.as_slice()[j * self.n..(j + 1) * self.n]
    }
}

fn store() -> &'static Mutex<HashMap<u64, Arc<Stored>>> {
    static STORE: OnceLock<Mutex<HashMap<u64, Arc<Stored>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_put(k: usize, n: usize, data: Vec<u32>) -> u64 {
    debug_assert_eq!(data.len(), k * n);
    store_backing(k, n, Backing::Heap(data))
}

fn store_backing(k: usize, n: usize, data: Backing) -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    debug_assert_eq!(data.as_slice().len(), k * n);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    store().lock().unwrap().insert(id, Arc::new(Stored { k, n, data }));
    id
}

fn store_get(id: u64) -> Arc<Stored> {
    store().lock().unwrap().get(&id).cloned().unwrap_or_else(|| panic!("column store: no columns with id {id}"))
}

/// The columns of several stored sets, in order.
fn stored_columns(sets: &[Arc<Stored>]) -> Vec<&[u32]> {
    let mut v = Vec::new();
    for s in sets {
        for j in 0..s.k {
            v.push(s.column(j));
        }
    }
    v
}

unsafe fn handles(ptr: *const u64, count: usize) -> Vec<Arc<Stored>> {
    std::slice::from_raw_parts(ptr, count).iter().map(|&h| store_get(h)).collect()
}

/// Stores `k` columns of `n` words copied from `data`; returns the id.
#[no_mangle]
pub unsafe extern "C" fn sk_store_put(data: *const u32, k: usize, n: usize) -> u64 {
    store_put(k, n, std::slice::from_raw_parts(data, k * n).to_vec())
}

/// Evaluates `k` coefficient columns of `len` words on HalfCoset(m) ∪ conj
/// and stores the values; returns the id.
#[no_mangle]
pub unsafe extern "C" fn sk_store_evaluate(coefs: *const u32, k: usize, len: usize, m: u32) -> u64 {
    let n = 1usize << (m + 1);
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_on() {
        if let Ok(g) = gpu::Gpu::get() {
            let ev = gpu::SharedBuffer::new(g, k * n);
            gpu::evaluate_columns(g, coefs, k, len, m, &ev).expect("GPU evaluation failed");
            return store_backing(k, n, Backing::Shared(ev));
        }
    }
    let mut ev = vec![0u32; k * n];
    par_fill_u32(&mut ev, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
    store_put(k, n, ev)
}

/// Frees the stored columns `id` (a no-op for an unknown id).
#[no_mangle]
pub extern "C" fn sk_store_free(id: u64) {
    store().lock().unwrap().remove(&id);
}

/// One value: column `col` at position `i` of the stored columns `id`.
#[no_mangle]
pub extern "C" fn sk_store_get(id: u64, col: usize, i: usize) -> u32 {
    store_get(id).column(col)[i]
}

/// `count` values of column `col` from position `start` into `out`.
#[no_mangle]
pub unsafe extern "C" fn sk_store_read(id: u64, col: usize, start: usize, count: usize, out: *mut u32) {
    let s = store_get(id);
    std::slice::from_raw_parts_mut(out, count).copy_from_slice(&s.column(col)[start..start + count]);
}

// ------------------------------------------------------------------ exported kernels

/// ABI version; the Dart side refuses a mismatch.
#[no_mangle]
pub extern "C" fn sk_version() -> u32 {
    7
}

// ------------------------------------------------------------------ GPU backend

#[cfg(all(target_os = "macos", feature = "metal"))]
mod gpu;

/// Whether the kernels that have a GPU path should take it. Off until
/// [sk_gpu_enable] turns it on, so a library built with the backend behaves
/// exactly as one built without it unless the caller asks.
static GPU_ON: AtomicU32 = AtomicU32::new(0);

/// Microseconds the last `sk_composition` spent extending the columns onto
/// the composition domain and running the constraint program over them. The
/// two halves scale differently and want opposite treatments, so the caller
/// can ask which one it is paying for.
static COMP_EVAL_US: AtomicU64 = AtomicU64::new(0);
static COMP_PROG_US: AtomicU64 = AtomicU64::new(0);

/// The two halves of the last composition call, in microseconds.
#[no_mangle]
pub unsafe extern "C" fn sk_composition_timing(out: *mut u64) {
    let o = std::slice::from_raw_parts_mut(out, 2);
    o[0] = COMP_EVAL_US.load(Ordering::Relaxed);
    o[1] = COMP_PROG_US.load(Ordering::Relaxed);
}

/// Whether the GPU backend can run, and if not why: 0 the library was built
/// without it (or is not on macOS), 1 available, 2 no Metal device, 3 the
/// shaders did not compile. The Dart side turns the code into a message, so
/// a refusal is never silent.
#[no_mangle]
pub extern "C" fn sk_gpu_available() -> u32 {
    #[cfg(all(target_os = "macos", feature = "metal"))]
    {
        match gpu::Gpu::get() {
            Ok(_) => 1,
            Err(gpu::GpuError::NoDevice) => 2,
            Err(_) => 3,
        }
    }
    #[cfg(not(all(target_os = "macos", feature = "metal")))]
    {
        0
    }
}

/// Turns the GPU backend on (`on` != 0) or off, and returns the state in
/// effect afterwards: asking for it on a machine that cannot run it leaves it
/// off and returns 0, which is the refusal the caller reports.
#[no_mangle]
pub extern "C" fn sk_gpu_enable(on: u32) -> u32 {
    let want = on != 0 && sk_gpu_available() == 1;
    GPU_ON.store(want as u32, Ordering::Relaxed);
    want as u32
}

/// Whether a kernel with a GPU path should take it.
#[inline]
fn gpu_on() -> bool {
    GPU_ON.load(Ordering::Relaxed) != 0
}

/// One Poseidon2 permutation of 16 lanes in place, with the round constants
/// `rc` (external 8 x 16, then internal 14).
#[no_mangle]
pub unsafe extern "C" fn sk_poseidon2_permute(state: *mut u32, rc: *const u32) {
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let s = std::slice::from_raw_parts_mut(state, 16);
    let mut st = [0u32; 16];
    st.copy_from_slice(s);
    p2_permute(&mut st, rc);
    s.copy_from_slice(&st);
}

/// [sk_commit_columns] with Poseidon2: leaf i is the Poseidon2 leaf of the
/// 2k lanes `ev[j][i]`, `ev[j][M+i]`; `out_tree` holds `(2M - 1) * 8` lanes.
/// Returns the id of the stored evaluations.
#[no_mangle]
pub unsafe extern "C" fn sk_commit_columns_p2(
    coefs: *const u32,
    k: usize,
    len: usize,
    m: u32,
    rc: *const u32,
    out_tree: *mut u32,
) -> u64 {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let tree = std::slice::from_raw_parts_mut(out_tree, (2 * big_m - 1) * 8);
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_on() {
        if let Ok(g) = gpu::Gpu::get() {
            // The evaluations are computed straight into a shared buffer, so
            // the GPU hashes them where they lie and they stay there as the
            // store's backing.
            let ev = gpu::SharedBuffer::new(g, k * n);
            gpu::evaluate_columns(g, coefs, k, len, m, &ev).expect("GPU evaluation failed");
            match gpu::commit_tree_p2(g, ev.buffer(), k, m, rc) {
                Ok(t) => {
                    tree.copy_from_slice(gpu::as_slice(&t, (2 * big_m - 1) * 8));
                    return store_backing(k, n, Backing::Shared(ev));
                }
                Err(e) => panic!("GPU commitment failed: {e}"),
            }
        }
    }
    let mut ev = vec![0u32; k * n];
    par_fill_u32(&mut ev, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
    {
        let ev: &[u32] = &ev;
        // lane j of leaf i is ev[j][i], lane k + j is ev[j][M + i]
        p2_leaves(big_m, 2 * k, |i, lane| if lane < k { ev[lane * n + i] } else { ev[(lane - k) * n + big_m + i] }, rc, &mut tree[..big_m * 8]);
    }
    merkle_above_p2(tree, big_m, rc);
    store_put(k, n, ev)
}

/// `n` two-to-one Poseidon2 compressions: pair i is the 16 lanes at
/// `pairs[16 i..16 i + 16]`, and its node, the first 8 lanes of the permuted
/// state, goes to `out[8 i..8 i + 8]`. The pool's trees hash a node this way
/// (`PoolHash.node`), so a reader rebuilding them from their leaves hands
/// each level's pairs here. It runs on the calling thread: the reader's
/// bounds are per core.
#[no_mangle]
pub unsafe extern "C" fn sk_p2_compress_pairs(pairs: *const u32, n: usize, rc: *const u32, out: *mut u32) {
    let pairs = std::slice::from_raw_parts(pairs, 16 * n);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let out = std::slice::from_raw_parts_mut(out, 8 * n);
    let full = n - n % P2_N;
    for b in 0..full / P2_N {
        v_compress::<P2_N>(&pairs[16 * P2_N * b..16 * P2_N * (b + 1)], rc, &mut out[8 * P2_N * b..8 * P2_N * (b + 1)]);
    }
    for i in full..n {
        v_compress::<1>(&pairs[16 * i..16 * i + 16], rc, &mut out[8 * i..8 * i + 8]);
    }
}

/// [sk_merkle_pairs] with Poseidon2; `out_tree` holds `(2h - 1) * 8` lanes.
#[no_mangle]
pub unsafe extern "C" fn sk_merkle_pairs_p2(cur: *const u32, log_len: u32, rc: *const u32, out_tree: *mut u32) {
    let len = 1usize << log_len;
    let h = len / 2;
    let cur = std::slice::from_raw_parts(cur, 4 * len);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let tree = std::slice::from_raw_parts_mut(out_tree, (2 * h - 1) * 8);
    // leaf i: the 4 limbs at i, then the 4 limbs at h + i
    p2_leaves(h, 8, |i, lane| if lane < 4 { cur[4 * i + lane] } else { cur[4 * (h + i) + lane - 4] }, rc, &mut tree[..h * 8]);
    merkle_above_p2(tree, h, rc);
}

/// `k` columns of 2^(m+1) values (twin layout) -> `k` columns of coefficients.
#[no_mangle]
pub unsafe extern "C" fn sk_interpolate_columns(vals: *const u32, k: usize, m: u32, out: *mut u32) {
    let n = 1usize << (m + 1);
    let vals = std::slice::from_raw_parts(vals, k * n);
    let out = std::slice::from_raw_parts_mut(out, k * n);
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_on() {
        if let Ok(g) = gpu::Gpu::get() {
            let src = gpu::SharedBuffer::from(g, vals);
            let dst = gpu::SharedBuffer::new(g, k * n);
            gpu::interpolate_columns(g, &src, k, m, &dst, inv(n as u32)).expect("GPU interpolation failed");
            out.copy_from_slice(dst.as_slice());
            return;
        }
    }
    par_fill_u32(out, n, 2, |j, col| interpolate(&vals[j * n..(j + 1) * n], m, col));
}

/// `k` columns of `len` coefficients -> `k` columns of 2^(m+1) evaluations.
#[no_mangle]
pub unsafe extern "C" fn sk_evaluate_columns(coefs: *const u32, k: usize, len: usize, m: u32, out: *mut u32) {
    let n = 1usize << (m + 1);
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let out = std::slice::from_raw_parts_mut(out, k * n);
    #[cfg(all(target_os = "macos", feature = "metal"))]
    if gpu_on() {
        if let Ok(g) = gpu::Gpu::get() {
            let dst = gpu::SharedBuffer::new(g, k * n);
            gpu::evaluate_columns(g, coefs, k, len, m, &dst).expect("GPU evaluation failed");
            out.copy_from_slice(dst.as_slice());
            return;
        }
    }
    par_fill_u32(out, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
}

/// Evaluate `k` coefficient columns on HalfCoset(m) ∪ conj and commit: leaf
/// `i` is SHA256 of the 2k little-endian words `ev[j][i]`, `ev[j][M+i]`.
/// `out_tree` holds the `(2M - 1) * 32` bytes of the tree; the k columns
/// of 2^(m+1) values are stored and their id returned.
#[no_mangle]
pub unsafe extern "C" fn sk_commit_columns(coefs: *const u32, k: usize, len: usize, m: u32, out_tree: *mut u8) -> u64 {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let tree = std::slice::from_raw_parts_mut(out_tree, tree_bytes(big_m));
    let mut ev = vec![0u32; k * n];
    par_fill_u32(&mut ev, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
    {
        let ev: &[u32] = &ev;
        par_fill(&mut tree[..big_m * 32], 32, 4096, |i, leaf| {
            let mut buf = vec![0u8; 8 * k];
            for j in 0..k {
                buf[4 * j..4 * j + 4].copy_from_slice(&ev[j * n + i].to_le_bytes());
                buf[4 * (k + j)..4 * (k + j) + 4].copy_from_slice(&ev[j * n + big_m + i].to_le_bytes());
            }
            leaf.copy_from_slice(&sha256(&buf));
        });
    }
    merkle_above(tree, big_m);
    store_put(k, n, ev)
}

/// DEEP quotients of the stored value columns `sets` (twin layout on
/// HalfCoset(m)), k columns in all:
/// q = (c * Σ w_j col_j - A * y - B) / (dA * x + dB * y + dC) at every
/// position, P side then C side (y negated). `consts` is
/// `c, A, B, dA, dB, dC, w_0 .. w_{k-1}` as QM31 limbs. With `accumulate`
/// the quotients are added into `out` instead of replacing it.
#[no_mangle]
pub unsafe extern "C" fn sk_deep_quotients(
    consts: *const u32,
    sets: *const u64,
    n_sets: usize,
    m: u32,
    accumulate: u32,
    out: *mut u32,
) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let sets = handles(sets, n_sets);
    let cols = stored_columns(&sets);
    let k = cols.len();
    for c in &cols {
        assert_eq!(c.len(), n, "stored columns are not on HalfCoset({m})");
    }
    let consts = std::slice::from_raw_parts(consts, 24 + 4 * k);
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
    std::thread::scope(|s| {
        for (blk, block) in out.chunks_mut(4 * per).enumerate() {
            let (c, ca, cb, da, db, dc, w, t, cols) = (&c, &ca, &cb, &da, &db, &dc, &w, &t, &cols);
            s.spawn(move || {
                let cnt = block.len() / 4;
                let base = blk * per;
                let mut dens = vec![Q_ZERO; cnt];
                let mut nums = vec![Q_ZERO; cnt];
                // the weighted column sum in blocks of rows, one column at a
                // time (contiguous reads), limbs kept as four lane arrays
                const DB: usize = 512;
                let mut sl = [[0u32; DB]; 4];
                let mut r0 = 0usize;
                while r0 < cnt {
                    let len = DB.min(cnt - r0);
                    for lane in 0..4 {
                        sl[lane][..len].fill(0);
                    }
                    for j in 0..k {
                        let col = &cols[j][base + r0..base + r0 + len];
                        for lane in 0..4 {
                            let wl = w[j][lane] as u64;
                            let acc = &mut sl[lane][..len];
                            for r in 0..len {
                                let x = wl * col[r] as u64;
                                let y = ((x & P as u64) + (x >> 31)) as u32;
                                let z = (y & P) + (y >> 31);
                                let m = z.min(z.wrapping_sub(P));
                                let a = acc[r] + m;
                                acc[r] = a.min(a.wrapping_sub(P));
                            }
                        }
                    }
                    for r in 0..len {
                        let q = base + r0 + r;
                        let i = if q < big_m { q } else { q - big_m };
                        let px = t.x[i];
                        let py = if q < big_m { t.y[i] } else { neg(t.y[i]) };
                        let sacc = [sl[0][r], sl[1][r], sl[2][r], sl[3][r]];
                        nums[r0 + r] = qsub(&qsub(&qmul(c, &sacc), &qscale(ca, py)), cb);
                        dens[r0 + r] = qadd(&qadd(&qscale(da, px), &qscale(db, py)), dc);
                    }
                    r0 += len;
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

/// The DEEP quotients of two groups in one pass over the shared columns.
///
/// The prover opens every column at z (group B: the trace, aux and
/// preprocessed columns followed by the composition blocks) and the trace
/// columns again at z*g (group C, which is exactly the first `k_c` columns
/// of the same list). Done as two calls that is two passes over gigabytes
/// of column data for one pass of arithmetic; here each column is read once
/// and fed to both weighted sums, and the two denominators are inverted
/// together. The result is B's quotient plus C's, which is what the caller
/// adds up anyway.
#[no_mangle]
pub unsafe extern "C" fn sk_deep_quotients2(
    consts_b: *const u32,
    consts_c: *const u32,
    sets: *const u64,
    n_sets: usize,
    k_c: usize,
    m: u32,
    out: *mut u32,
) {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let sets = handles(sets, n_sets);
    let cols = stored_columns(&sets);
    let k = cols.len();
    assert!(k_c <= k, "group C reads {k_c} of {k} columns");
    for c in &cols {
        assert_eq!(c.len(), n, "stored columns are not on HalfCoset({m})");
    }
    let cb_s = std::slice::from_raw_parts(consts_b, 24 + 4 * k);
    let cc_s = std::slice::from_raw_parts(consts_c, 24 + 4 * k_c);
    let out = std::slice::from_raw_parts_mut(out, 4 * n);
    let g = |s: &[u32]| {
        (
            q_at(s, 0),
            q_at(s, 1),
            q_at(s, 2),
            q_at(s, 3),
            q_at(s, 4),
            q_at(s, 5),
        )
    };
    let (bc, bca, bcb, bda, bdb, bdc) = g(cb_s);
    let (cc, cca, ccb, cda, cdb, cdc) = g(cc_s);
    let wb: Vec<Q> = (0..k).map(|j| q_at(cb_s, 6 + j)).collect();
    let wc: Vec<Q> = (0..k_c).map(|j| q_at(cc_s, 6 + j)).collect();
    let t = tables(m);
    let th = threads();
    let per = ((n + th - 1) / th).max(1024);
    std::thread::scope(|s| {
        for (blk, block) in out.chunks_mut(4 * per).enumerate() {
            let (bc, bca, bcb, bda, bdb, bdc) = (&bc, &bca, &bcb, &bda, &bdb, &bdc);
            let (cc, cca, ccb, cda, cdb, cdc) = (&cc, &cca, &ccb, &cda, &cdb, &cdc);
            let (wb, wc, t, cols) = (&wb, &wc, &t, &cols);
            s.spawn(move || {
                let cnt = block.len() / 4;
                let base = blk * per;
                // both denominators in one array, so one batch inversion
                // serves both groups
                let mut dens = vec![Q_ZERO; 2 * cnt];
                let mut nums = vec![Q_ZERO; 2 * cnt];
                const DB: usize = 512;
                let mut sb = [[0u32; DB]; 4];
                let mut sc = [[0u32; DB]; 4];
                let mut r0 = 0usize;
                while r0 < cnt {
                    let len = DB.min(cnt - r0);
                    for lane in 0..4 {
                        sb[lane][..len].fill(0);
                        sc[lane][..len].fill(0);
                    }
                    for j in 0..k {
                        let col = &cols[j][base + r0..base + r0 + len];
                        for lane in 0..4 {
                            let bl = wb[j][lane] as u64;
                            let acc = &mut sb[lane][..len];
                            for r in 0..len {
                                let x = bl * col[r] as u64;
                                let y = ((x & P as u64) + (x >> 31)) as u32;
                                let z = (y & P) + (y >> 31);
                                let mm = z.min(z.wrapping_sub(P));
                                let a = acc[r] + mm;
                                acc[r] = a.min(a.wrapping_sub(P));
                            }
                        }
                        if j < k_c {
                            for lane in 0..4 {
                                let cl = wc[j][lane] as u64;
                                let acc = &mut sc[lane][..len];
                                for r in 0..len {
                                    let x = cl * col[r] as u64;
                                    let y = ((x & P as u64) + (x >> 31)) as u32;
                                    let z = (y & P) + (y >> 31);
                                    let mm = z.min(z.wrapping_sub(P));
                                    let a = acc[r] + mm;
                                    acc[r] = a.min(a.wrapping_sub(P));
                                }
                            }
                        }
                    }
                    for r in 0..len {
                        let q = base + r0 + r;
                        let i = if q < big_m { q } else { q - big_m };
                        let px = t.x[i];
                        let py = if q < big_m { t.y[i] } else { neg(t.y[i]) };
                        let ab = [sb[0][r], sb[1][r], sb[2][r], sb[3][r]];
                        let ac = [sc[0][r], sc[1][r], sc[2][r], sc[3][r]];
                        nums[r0 + r] = qsub(&qsub(&qmul(bc, &ab), &qscale(bca, py)), bcb);
                        dens[r0 + r] = qadd(&qadd(&qscale(bda, px), &qscale(bdb, py)), bdc);
                        nums[cnt + r0 + r] = qsub(&qsub(&qmul(cc, &ac), &qscale(cca, py)), ccb);
                        dens[cnt + r0 + r] = qadd(&qadd(&qscale(cda, px), &qscale(cdb, py)), cdc);
                    }
                    r0 += len;
                }
                let invs = qbatch_inv(&dens);
                for r in 0..cnt {
                    let b = qmul(&nums[r], &invs[r]);
                    let c = qmul(&nums[cnt + r], &invs[cnt + r]);
                    q_set(block, r, &qadd(&b, &c));
                }
            });
        }
    });
}

/// Proof-of-work grinding: the smallest nonce whose hash of the transcript
/// state meets the target.
///
/// The verifier accepts any nonce that meets it, but the proof must be the
/// same one whoever produced it, so this cannot be a race between threads:
/// the first hit a thread happens to report is not the smallest. Threads
/// take disjoint blocks of a wave in order and the answer is the smallest
/// hit in the wave, which is the smallest overall because every nonce below
/// it was scanned in this wave or an earlier one.
fn grind_blocks<F: Fn(u64) -> bool + Sync>(hit: F) -> u64 {
    const BLOCK: u64 = 1 << 14;
    let th = threads() as u64;
    let mut wave = 0u64;
    loop {
        let found = std::sync::atomic::AtomicU64::new(u64::MAX);
        std::thread::scope(|s| {
            for b in 0..th {
                let (found, hit) = (&found, &hit);
                s.spawn(move || {
                    let start = wave + b * BLOCK;
                    for n in start..start + BLOCK {
                        if hit(n) {
                            found.fetch_min(n, Ordering::Relaxed);
                            return;
                        }
                    }
                });
            }
        });
        let f = found.load(Ordering::Relaxed);
        if f != u64::MAX {
            return f;
        }
        wave += th * BLOCK;
        if wave > u32::MAX as u64 {
            return u64::MAX;
        }
    }
}

/// SHA256 flavour: the smallest 32-bit nonce, little-endian, for which
/// SHA256(state || nonce) begins with `zero_bytes` zero bytes.
#[no_mangle]
pub unsafe extern "C" fn sk_grind_sha(state: *const u8, state_len: usize, zero_bytes: u32) -> u64 {
    let st = std::slice::from_raw_parts(state, state_len);
    let zb = zero_bytes as usize;
    grind_blocks(|n| {
        let mut buf = Vec::with_capacity(st.len() + 4);
        buf.extend_from_slice(st);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        let h = sha256(&buf);
        h[..zb].iter().all(|&b| b == 0)
    })
}

/// Poseidon2 flavour: the smallest lane nonce for which the first lane of
/// the compression of the 8-lane state with [nonce, 0..] has its low `bits`
/// bits zero.
#[no_mangle]
pub unsafe extern "C" fn sk_grind_p2(state: *const u32, rc: *const u32, bits: u32) -> u64 {
    let st = std::slice::from_raw_parts(state, 8);
    let rc = std::slice::from_raw_parts(rc, P2_RC_LEN);
    let mask = (1u32 << bits) - 1;
    grind_blocks(|n| {
        if n >= P as u64 {
            return false;
        }
        let mut s = [0u32; 16];
        s[..8].copy_from_slice(st);
        s[8] = n as u32;
        p2_permute(&mut s, rc);
        s[0] & mask == 0
    })
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

// ---------------------------------------------------------------------------
// Composition values from recorded constraint programs.
//
// A straight-line program (the AIR's constraints recorded over an
// expression ring) is run once per row of the composition domain: the main
// program over M31, the aux program over QM31 (challenges are QM31, every
// other input an embedded base value). Each output j is weighted by
// `weights[j]` (a QM31: the group's beta power times beta^k) and by the
// divisor column `div_sel[j]` at that row, and the weighted sum is the
// composition value of the row.
//
// Encodings (all u32):
//   desc: [log_c, n_cols, n_per, log_pc, n_lin, n_div,
//          main_n_inputs, main_n_ops, main_n_out, aux_n_inputs, aux_n_ops, aux_n_out, n_chal,
//          coef_len (0: cols hold values on the domain; else n_cols coefficient columns of coef_len
//          words, evaluated on the domain here so the values never cross the FFI boundary)]
//   ops:  7 words per op: kind (0 add, 1 sub, 2 mul, 3 scale, 4 constant), a, b, imm0..imm3
//   src:  2 words per input: kind (0 cur, 1 next, 2 per, 3 lin, 4 const, 5 chal), index
//   cols: with coef_len > 0, n_cols coefficient columns; else unused and the value columns
//         are the stored sets `sets` (n_sets ids, n_cols columns in all), on the domain
//         (cur at q, next at idx_next[q]); per: n_per x 2^log_pc (at idx_per[q]);
//   lin: n_lin x nC; chal: 4 words each; divs: n_div x nC; out: nC x 4 (row-major limbs).
// ---------------------------------------------------------------------------

struct Prog<'a> {
    n_inputs: usize,
    ops: &'a [u32],
    src: &'a [u32],
    outs: &'a [u32],
}

impl<'a> Prog<'a> {
    fn n_nodes(&self) -> usize {
        self.n_inputs + self.ops.len() / 7
    }
}

struct RowCtx<'a> {
    n_c: usize,
    n_pc: usize,
    cols: Vec<&'a [u32]>,
    per: &'a [u32],
    lin: &'a [u32],
    chal: &'a [u32],
    idx_next: &'a [u32],
    idx_per: &'a [u32],
}

// ---- row blocks: every op of the program runs over RB rows at once, so the
// interpreter's dispatch is paid once per RB rows and the field arithmetic
// is a loop of RB independent lanes the compiler vectorises. ----

const RB: usize = 16;
type VB = [u32; RB];
type QB = [VB; 4];
const VB_ZERO: VB = [0; RB];
const QB_ZERO: QB = [VB_ZERO; 4];

#[inline(always)]
fn vb_splat(c: u32) -> VB {
    [c; RB]
}

#[inline(always)]
fn qb_splat(q: &Q) -> QB {
    [vb_splat(q[0]), vb_splat(q[1]), vb_splat(q[2]), vb_splat(q[3])]
}

#[inline(always)]
fn qb_add(a: &QB, b: &QB) -> QB {
    [v_add(&a[0], &b[0]), v_add(&a[1], &b[1]), v_add(&a[2], &b[2]), v_add(&a[3], &b[3])]
}

#[inline(always)]
fn qb_sub(a: &QB, b: &QB) -> QB {
    [v_sub(&a[0], &b[0]), v_sub(&a[1], &b[1]), v_sub(&a[2], &b[2]), v_sub(&a[3], &b[3])]
}

/// Every limb times the per-row M31 vector `m`.
#[inline(always)]
fn qb_scale(a: &QB, m: &VB) -> QB {
    [v_mul(&a[0], m), v_mul(&a[1], m), v_mul(&a[2], m), v_mul(&a[3], m)]
}

#[inline(always)]
fn vb_cmul(a0: &VB, a1: &VB, b0: &VB, b1: &VB) -> (VB, VB) {
    (v_sub(&v_mul(a0, b0), &v_mul(a1, b1)), v_add(&v_mul(a0, b1), &v_mul(a1, b0)))
}

#[inline(always)]
fn vb_cmul_2i(a: &VB, b: &VB) -> (VB, VB) {
    (v_sub(&v_add(a, a), b), v_add(a, &v_add(b, b)))
}

/// [qmul] lane by lane.
#[inline(always)]
fn qb_mul(a: &QB, b: &QB) -> QB {
    let (p0, p1) = vb_cmul(&a[0], &a[1], &b[0], &b[1]);
    let (q0, q1) = vb_cmul(&a[2], &a[3], &b[2], &b[3]);
    let (q0, q1) = vb_cmul_2i(&q0, &q1);
    let (r0, r1) = vb_cmul(&a[0], &a[1], &b[2], &b[3]);
    let (s0, s1) = vb_cmul(&a[2], &a[3], &b[0], &b[1]);
    [v_add(&p0, &q0), v_add(&p1, &q1), v_add(&r0, &s0), v_add(&r1, &s1)]
}

impl<'a> RowCtx<'a> {
    /// The M31 lane of input (kind, idx) over rows q0 .. q0 + len (lanes
    /// past len hold the row-q0 value).
    #[inline(always)]
    fn input_block(&self, kind: u32, idx: usize, q0: usize, len: usize) -> VB {
        let mut r = VB_ZERO;
        match kind {
            0 => r[..len].copy_from_slice(&self.cols[idx][q0..q0 + len]),
            1 => {
                let col = self.cols[idx];
                for l in 0..len {
                    r[l] = col[self.idx_next[q0 + l] as usize];
                }
            }
            2 => {
                for l in 0..len {
                    r[l] = self.per[idx * self.n_pc + self.idx_per[q0 + l] as usize];
                }
            }
            3 => r[..len].copy_from_slice(&self.lin[idx * self.n_c + q0..idx * self.n_c + q0 + len]),
            4 => r = vb_splat(idx as u32),
            _ => r = vb_splat(self.chal[4 * idx]),
        }
        r
    }
}

fn run_m31_block(p: &Prog, ctx: &RowCtx, q0: usize, len: usize, vals: &mut [VB]) {
    for i in 0..p.n_inputs {
        vals[i] = ctx.input_block(p.src[2 * i], p.src[2 * i + 1] as usize, q0, len);
    }
    let mut n = p.n_inputs;
    for op in p.ops.chunks_exact(7) {
        let (a, b) = (op[1] as usize, op[2] as usize);
        vals[n] = match op[0] {
            0 => v_add(&vals[a], &vals[b]),
            1 => v_sub(&vals[a], &vals[b]),
            2 => v_mul(&vals[a], &vals[b]),
            3 => v_mul(&vals[a], &vb_splat(op[3])),
            _ => vb_splat(op[3]),
        };
        n += 1;
    }
}

fn run_q_block(p: &Prog, ctx: &RowCtx, q0: usize, len: usize, vals: &mut [QB]) {
    for i in 0..p.n_inputs {
        let (kind, idx) = (p.src[2 * i], p.src[2 * i + 1] as usize);
        vals[i] = if kind == 5 { qb_splat(&q_at(ctx.chal, idx)) } else { [ctx.input_block(kind, idx, q0, len), VB_ZERO, VB_ZERO, VB_ZERO] };
    }
    let mut n = p.n_inputs;
    for op in p.ops.chunks_exact(7) {
        let (a, b) = (op[1] as usize, op[2] as usize);
        vals[n] = match op[0] {
            0 => qb_add(&vals[a], &vals[b]),
            1 => qb_sub(&vals[a], &vals[b]),
            2 => qb_mul(&vals[a], &vals[b]),
            3 => qb_scale(&vals[a], &vb_splat(op[3])),
            _ => qb_splat(&[op[3], op[4], op[5], op[6]]),
        };
        n += 1;
    }
}

/// Run `f(range, out_slice)` over row ranges across threads; `out` holds
/// `item_len` words per row.
fn par_rows<F>(out: &mut [u32], item_len: usize, f: F)
where
    F: Fn(std::ops::Range<usize>, &mut [u32]) + Sync,
{
    let n = out.len() / item_len;
    let th = threads();
    if n < 4096 || th <= 1 {
        f(0..n, out);
        return;
    }
    let per = (n + th - 1) / th;
    std::thread::scope(|s| {
        for (t, block) in out.chunks_mut(per * item_len).enumerate() {
            let f = &f;
            s.spawn(move || {
                let start = t * per;
                f(start..start + block.len() / item_len, block);
            });
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn sk_composition(
    desc: *const u32,
    main_ops: *const u32,
    main_src: *const u32,
    main_out: *const u32,
    aux_ops: *const u32,
    aux_src: *const u32,
    aux_out: *const u32,
    chal: *const u32,
    cols: *const u32,
    sets: *const u64,
    n_sets: usize,
    per: *const u32,
    lin: *const u32,
    idx_next: *const u32,
    idx_per: *const u32,
    weights: *const u32,
    div_sel: *const u32,
    divs: *const u32,
    out: *mut u32,
) {
    let d = std::slice::from_raw_parts(desc, 14);
    let (log_c, n_cols, n_per, log_pc, n_lin, n_div) =
        (d[0], d[1] as usize, d[2] as usize, d[3], d[4] as usize, d[5] as usize);
    let n_c = 1usize << log_c;
    let n_pc = 1usize << log_pc;
    let main = Prog {
        n_inputs: d[6] as usize,
        ops: std::slice::from_raw_parts(main_ops, 7 * d[7] as usize),
        src: std::slice::from_raw_parts(main_src, 2 * d[6] as usize),
        outs: std::slice::from_raw_parts(main_out, d[8] as usize),
    };
    let aux = Prog {
        n_inputs: d[9] as usize,
        ops: std::slice::from_raw_parts(aux_ops, 7 * d[10] as usize),
        src: std::slice::from_raw_parts(aux_src, 2 * d[9] as usize),
        outs: std::slice::from_raw_parts(aux_out, d[11] as usize),
    };
    let n_out = main.outs.len() + aux.outs.len();
    let coef_len = d[13] as usize;
    let t_eval = std::time::Instant::now();
    let evaluated: Vec<u32> = if coef_len == 0 {
        Vec::new()
    } else {
        let coefs = std::slice::from_raw_parts(cols, n_cols * coef_len);
        let mut ev = vec![0u32; n_cols * n_c];
        par_fill_u32(&mut ev, n_c, 2, |j, col| evaluate(&coefs[j * coef_len..(j + 1) * coef_len], log_c - 1, col));
        ev
    };
    COMP_EVAL_US.store(t_eval.elapsed().as_micros() as u64, Ordering::Relaxed);
    let t_prog = std::time::Instant::now();
    let stored = if coef_len == 0 { handles(sets, n_sets) } else { Vec::new() };
    let value_cols: Vec<&[u32]> =
        if coef_len == 0 { stored_columns(&stored) } else { (0..n_cols).map(|j| &evaluated[j * n_c..(j + 1) * n_c]).collect() };
    assert_eq!(value_cols.len(), n_cols, "column count");
    for c in &value_cols {
        assert_eq!(c.len(), n_c, "value columns are not on the composition domain");
    }
    let ctx = RowCtx {
        n_c,
        n_pc,
        cols: value_cols,
        per: std::slice::from_raw_parts(per, n_per * n_pc),
        lin: std::slice::from_raw_parts(lin, n_lin * n_c),
        chal: std::slice::from_raw_parts(chal, 4 * d[12] as usize),
        idx_next: std::slice::from_raw_parts(idx_next, n_c),
        idx_per: std::slice::from_raw_parts(idx_per, n_c),
    };
    let weights = std::slice::from_raw_parts(weights, 4 * n_out);
    let div_sel = std::slice::from_raw_parts(div_sel, n_out);
    let divs = std::slice::from_raw_parts(divs, n_div * n_c);
    let out = std::slice::from_raw_parts_mut(out, 4 * n_c);
    let wq: Vec<QB> = (0..n_out).map(|j| qb_splat(&q_at(weights, j))).collect();
    par_rows(out, 4, |range, block| {
        let mut vm = vec![VB_ZERO; main.n_nodes()];
        let mut va = vec![QB_ZERO; aux.n_nodes()];
        let mut q0 = range.start;
        while q0 < range.end {
            let len = RB.min(range.end - q0);
            let div = |j: usize| -> VB {
                let mut d = VB_ZERO;
                let base = div_sel[j] as usize * n_c + q0;
                d[..len].copy_from_slice(&divs[base..base + len]);
                d
            };
            let mut total = QB_ZERO;
            run_m31_block(&main, &ctx, q0, len, &mut vm);
            for (j, &o) in main.outs.iter().enumerate() {
                let c = v_mul(&vm[o as usize], &div(j));
                total = qb_add(&total, &qb_scale(&wq[j], &c));
            }
            if !aux.outs.is_empty() {
                run_q_block(&aux, &ctx, q0, len, &mut va);
                let base = main.outs.len();
                for (j, &o) in aux.outs.iter().enumerate() {
                    let jj = base + j;
                    total = qb_add(&total, &qb_scale(&qb_mul(&wq[jj], &va[o as usize]), &div(jj)));
                }
            }
            let r0 = q0 - range.start;
            for l in 0..len {
                for k in 0..4 {
                    block[4 * (r0 + l) + k] = total[k][l];
                }
            }
            q0 += len;
        }
    });
    COMP_PROG_US.store(t_prog.elapsed().as_micros() as u64, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Out-of-domain evaluation: coefficient columns at a QM31 point.
// ---------------------------------------------------------------------------

/// The value at (x, y) of the coefficient vector `c` (circle basis: pairs
/// combined with y at the first level, then with x, 2x^2-1, ...).
fn eval_at(c: &[u32], x: &Q, y: &Q) -> Q {
    if c.len() == 1 {
        return [c[0], 0, 0, 0];
    }
    let mut v: Vec<Q> = (0..c.len() / 2)
        .map(|j| qadd(&[c[2 * j], 0, 0, 0], &qscale(y, c[2 * j + 1])))
        .collect();
    let mut tw = *x;
    while v.len() > 1 {
        let half = v.len() / 2;
        for j in 0..half {
            v[j] = qadd(&v[2 * j], &qmul(&tw, &v[2 * j + 1]));
        }
        v.truncate(half);
        let t2 = qmul(&tw, &tw);
        tw = qsub(&qadd(&t2, &t2), &Q_ONE);
    }
    v[0]
}

/// `out` (4k words) = each of the k coefficient columns of `len` words
/// evaluated at (x, y).
#[no_mangle]
pub unsafe extern "C" fn sk_eval_at(coefs: *const u32, k: usize, len: usize, x: *const u32, y: *const u32, out: *mut u32) {
    let coefs = std::slice::from_raw_parts(coefs, k * len);
    let x = q_at(std::slice::from_raw_parts(x, 4), 0);
    let y = q_at(std::slice::from_raw_parts(y, 4), 0);
    let out = std::slice::from_raw_parts_mut(out, 4 * k);
    par_fill_u32(out, 4, 1, |j, item| item.copy_from_slice(&eval_at(&coefs[j * len..(j + 1) * len], &x, &y)));
}

// ---------------------------------------------------------------------------
// LogUp aux columns from a recorded bus program.
//
// Per row the program (over QM31; inputs are main-row cells, preprocessed
// cells, constants and challenges) yields, per helper i, (en_i, v_i, tag_i,
// mult_i). Helper H_i = en_i / (gamma + v_i + delta tag_i), or 0 when en_i
// is 0; the accumulator column holds the prefix sums of sum_i mult_i H_i
// (ACC[0] = 0), and the total is returned for the caller's balance check.
//
//   desc: [log_n, n_main, n_pre, n_inputs, n_ops, n_helpers, n_chal, gamma_idx, delta_idx]
//   src kinds: 0 main column j of the row, 1 preprocessed column c, 4 const, 5 chal
//   rows: n x n_main row-major; pre: n_pre x n column-major
//   out: (4 n_helpers + 4) columns x n, column-major: H_0.., then ACC; total: 4 words
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sk_logup_columns(
    desc: *const u32,
    ops: *const u32,
    src: *const u32,
    outs: *const u32,
    chal: *const u32,
    rows: *const u32,
    pre: *const u32,
    out: *mut u32,
    total: *mut u32,
) {
    let d = std::slice::from_raw_parts(desc, 9);
    let n = 1usize << d[0];
    let (n_main, n_pre, n_inputs, n_ops, n_h, n_chal) =
        (d[1] as usize, d[2] as usize, d[3] as usize, d[4] as usize, d[5] as usize, d[6] as usize);
    let (gi, di) = (d[7] as usize, d[8] as usize);
    let prog = Prog {
        n_inputs,
        ops: std::slice::from_raw_parts(ops, 7 * n_ops),
        src: std::slice::from_raw_parts(src, 2 * n_inputs),
        outs: std::slice::from_raw_parts(outs, 4 * n_h),
    };
    let chal = std::slice::from_raw_parts(chal, 4 * n_chal);
    let rows = std::slice::from_raw_parts(rows, n * n_main);
    let pre = std::slice::from_raw_parts(pre, n_pre * n);
    let gamma = q_at(chal, gi);
    let delta = q_at(chal, di);
    // helpers and the row term, row-major: n x (4 n_h + 4)
    let w = 4 * n_h + 4;
    let mut tmp = vec![0u32; n * w];
    par_rows(&mut tmp, w, |range, block| {
        let mut vals = vec![Q_ZERO; prog.n_nodes()];
        let rows_in = range.len();
        let mut en = vec![Q_ZERO; rows_in * n_h];
        let mut den = vec![Q_ZERO; rows_in * n_h];
        let mut mult = vec![Q_ZERO; rows_in * n_h];
        for (r, q) in range.clone().enumerate() {
            for i in 0..n_inputs {
                let (kind, idx) = (prog.src[2 * i], prog.src[2 * i + 1] as usize);
                vals[i] = match kind {
                    0 => [rows[q * n_main + idx], 0, 0, 0],
                    1 => [pre[idx * n + q], 0, 0, 0],
                    4 => [idx as u32, 0, 0, 0],
                    _ => q_at(chal, idx),
                };
            }
            let mut m = n_inputs;
            for op in prog.ops.chunks_exact(7) {
                let (a, b) = (op[1] as usize, op[2] as usize);
                vals[m] = match op[0] {
                    0 => qadd(&vals[a], &vals[b]),
                    1 => qsub(&vals[a], &vals[b]),
                    2 => qmul(&vals[a], &vals[b]),
                    3 => qscale(&vals[a], op[3]),
                    _ => [op[3], op[4], op[5], op[6]],
                };
                m += 1;
            }
            for h in 0..n_h {
                let o = &prog.outs[4 * h..4 * h + 4];
                let e = vals[o[0] as usize];
                let v = vals[o[1] as usize];
                let tag = vals[o[2] as usize];
                en[r * n_h + h] = e;
                den[r * n_h + h] = if e == Q_ZERO { Q_ONE } else { qadd(&qadd(&gamma, &v), &qmul(&delta, &tag)) };
                mult[r * n_h + h] = vals[o[3] as usize];
            }
        }
        let inv = qbatch_inv(&den);
        for r in 0..rows_in {
            let mut term = Q_ZERO;
            for h in 0..n_h {
                let e = en[r * n_h + h];
                let hv = if e == Q_ZERO { Q_ZERO } else { qmul(&e, &inv[r * n_h + h]) };
                block[r * w + 4 * h..r * w + 4 * h + 4].copy_from_slice(&hv);
                term = qadd(&term, &qmul(&mult[r * n_h + h], &hv));
            }
            block[r * w + 4 * n_h..r * w + 4 * n_h + 4].copy_from_slice(&term);
        }
    });
    // the accumulator (prefix sums of the terms) and the transpose to columns
    let out = std::slice::from_raw_parts_mut(out, w * n);
    let mut acc = Q_ZERO;
    for q in 0..n {
        for c in 0..4 * n_h {
            out[c * n + q] = tmp[q * w + c];
        }
        for k in 0..4 {
            out[(4 * n_h + k) * n + q] = acc[k];
        }
        acc = qadd(&acc, &q_at(&tmp[q * w..q * w + w], n_h));
    }
    std::slice::from_raw_parts_mut(total, 4).copy_from_slice(&acc);
}

// ---------------------------------------------------------------------------
// ML-KEM-768 (FIPS 203) for the note-encryption KEM, via the `ml-kem` crate.
// Keys are never stored: both halves are regenerated from a 64-byte seed
// (d ‖ z) the wallet derives from its viewing key, so the Dart side only
// ever holds seeds, public keys and ciphertexts.
// ---------------------------------------------------------------------------

use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};

/// Sizes of the ML-KEM-768 encodings, in bytes.
pub const MLKEM768_PK: usize = 1184;
pub const MLKEM768_CT: usize = 1088;
pub const MLKEM768_SS: usize = 32;
pub const MLKEM768_SEED: usize = 64;

type Mlkem768Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Mlkem768Ek = <MlKem768 as KemCore>::EncapsulationKey;

fn mlkem768_from_seed(seed: &[u8]) -> (Mlkem768Dk, Mlkem768Ek) {
    let d = B32::try_from(&seed[..32]).unwrap();
    let z = B32::try_from(&seed[32..64]).unwrap();
    MlKem768::generate_deterministic(&d, &z)
}

/// The encapsulation key of the pair generated from `seed` (64 bytes: d ‖ z).
#[no_mangle]
pub unsafe extern "C" fn sk_mlkem768_public_key(seed: *const u8, pk_out: *mut u8) {
    let seed = std::slice::from_raw_parts(seed, MLKEM768_SEED);
    let out = std::slice::from_raw_parts_mut(pk_out, MLKEM768_PK);
    let (_, ek) = mlkem768_from_seed(seed);
    out.copy_from_slice(&ek.as_bytes());
}

/// Encapsulates to `pk` with the 32 random bytes `m`. Returns 0 and fills
/// `ct_out` (1088 bytes) and `ss_out` (32 bytes), or 1 when `pk` is not a
/// valid encapsulation key (FIPS 203 §7.2 modulus check: it must re-encode
/// to itself).
#[no_mangle]
pub unsafe extern "C" fn sk_mlkem768_encaps(pk: *const u8, m: *const u8, ct_out: *mut u8, ss_out: *mut u8) -> u32 {
    let pk = std::slice::from_raw_parts(pk, MLKEM768_PK);
    let m = std::slice::from_raw_parts(m, 32);
    let ct_out = std::slice::from_raw_parts_mut(ct_out, MLKEM768_CT);
    let ss_out = std::slice::from_raw_parts_mut(ss_out, MLKEM768_SS);
    let enc = ml_kem::Encoded::<Mlkem768Ek>::try_from(pk).unwrap();
    let ek = Mlkem768Ek::from_bytes(&enc);
    if ek.as_bytes().as_slice() != pk {
        return 1;
    }
    let m = B32::try_from(m).unwrap();
    let (ct, ss) = ek.encapsulate_deterministic(&m).unwrap();
    ct_out.copy_from_slice(&ct);
    ss_out.copy_from_slice(&ss);
    0
}

/// Decapsulates `ct` (1088 bytes) with the pair generated from `seed`.
/// Always fills `ss_out` (implicit rejection yields a pseudorandom secret
/// for a malformed ciphertext, as the standard prescribes).
#[no_mangle]
pub unsafe extern "C" fn sk_mlkem768_decaps(seed: *const u8, ct: *const u8, ss_out: *mut u8) {
    let seed = std::slice::from_raw_parts(seed, MLKEM768_SEED);
    let ct = std::slice::from_raw_parts(ct, MLKEM768_CT);
    let ss_out = std::slice::from_raw_parts_mut(ss_out, MLKEM768_SS);
    let (dk, _) = mlkem768_from_seed(seed);
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct).unwrap();
    let ss = dk.decapsulate(&ct).unwrap();
    ss_out.copy_from_slice(&ss);
}

#[cfg(test)]
mod p2_tests {
    use super::*;

    fn rc() -> Vec<u32> {
        (0..P2_RC_LEN as u32).map(|i| (i * 0x9e37_79b9) & P).collect()
    }

    #[test]
    fn wide_matches_scalar() {
        let rc = rc();
        let n_lanes = 45;
        let leaves = 8 * 5 + 3;
        let lane = |i: usize, k: usize| ((i * 131 + k * 7919 + 1) as u32 * 2_654_435_761u32) & P;
        let mut wide = vec![0u32; 8 * leaves];
        p2_leaves(leaves, n_lanes, lane, &rc, &mut wide);
        for i in 0..leaves {
            let mut one = [0u32; 8];
            v_leaf::<1, _>(n_lanes, |_, k| lane(i, k), &rc, &mut one);
            assert_eq!(wide[8 * i..8 * i + 8], one[..], "leaf {i}");
        }
        // the tree above 16 leaves, wide, against scalar compressions
        let mut tree = vec![0u32; (2 * 16 - 1) * 8];
        tree[..16 * 8].copy_from_slice(&wide[..16 * 8]);
        merkle_above_p2(&mut tree, 16, &rc);
        let mut node = [0u32; 8];
        v_compress::<1>(&tree[..16], &rc, &mut node);
        assert_eq!(tree[16 * 8..16 * 8 + 8], node[..]);
    }

    #[test]
    fn compress_pairs_matches_the_permutation() {
        let rc = rc();
        for n in [0usize, 1, P2_N - 1, P2_N, 3 * P2_N + 5] {
            let pairs: Vec<u32> = (0..16 * n).map(|i| ((i as u32 + 1) * 2_654_435_761u32) & P).collect();
            let mut out = vec![0u32; 8 * n];
            unsafe { sk_p2_compress_pairs(pairs.as_ptr(), n, rc.as_ptr(), out.as_mut_ptr()) };
            for i in 0..n {
                let mut st = [0u32; 16];
                st.copy_from_slice(&pairs[16 * i..16 * i + 16]);
                p2_permute(&mut st, &rc);
                assert_eq!(out[8 * i..8 * i + 8], st[..8], "n {n} pair {i}");
            }
        }
    }

    #[test]
    fn m4_matches_matrix() {
        let rc = rc();
        let _ = rc;
        let m4 = [[5u32, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
        let mut s = [[0u32; 1]; 16];
        for k in 0..16 {
            s[k][0] = (k as u32 * 0x7654_3210 + 12345) & P;
        }
        let x = s;
        v_m4(&mut s, 1);
        for r in 0..4 {
            let mut acc = 0u32;
            for c in 0..4 {
                acc = add(acc, mul(x[4 + c][0], m4[r][c]));
            }
            assert_eq!(s[4 + r][0], acc);
        }
        // the internal diagonal against the multiplications it replaces
        let mut t = x;
        v_internal_layer(&mut t);
        let mut sum = 0u32;
        for k in 0..16 {
            sum = add(sum, x[k][0]);
        }
        let mut diag = [0u32; 16];
        diag[0] = P - 2;
        for (i, sh) in P2_DIAG_SHIFTS.iter().enumerate() {
            diag[i + 1] = 1u32 << sh;
        }
        for k in 0..16 {
            assert_eq!(t[k][0], add(sum, mul(diag[k], x[k][0])), "lane {k}");
        }
    }
}

#[cfg(test)]
mod mlkem_tests {
    use super::*;

    #[test]
    fn mlkem768_round_trip() {
        let seed: Vec<u8> = (0..64u8).collect();
        let mut pk = [0u8; MLKEM768_PK];
        let mut pk2 = [0u8; MLKEM768_PK];
        unsafe {
            sk_mlkem768_public_key(seed.as_ptr(), pk.as_mut_ptr());
            sk_mlkem768_public_key(seed.as_ptr(), pk2.as_mut_ptr());
        }
        assert_eq!(pk[..], pk2[..]);
        let m = [7u8; 32];
        let mut ct = [0u8; MLKEM768_CT];
        let mut ss = [0u8; 32];
        let mut ss2 = [0u8; 32];
        unsafe {
            assert_eq!(sk_mlkem768_encaps(pk.as_ptr(), m.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr()), 0);
            sk_mlkem768_decaps(seed.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr());
        }
        assert_eq!(ss, ss2);
        // a tampered ciphertext decapsulates to something else (implicit rejection)
        ct[5] ^= 1;
        unsafe { sk_mlkem768_decaps(seed.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr()) };
        assert_ne!(ss, ss2);
        // an out-of-range key is refused
        pk[0] = 0xff;
        pk[1] = 0xff;
        unsafe { assert_eq!(sk_mlkem768_encaps(pk.as_ptr(), m.as_ptr(), ct.as_mut_ptr(), ss.as_mut_ptr()), 1) };
    }
}

// ------------------------------------------------------------------ GPU tests

/// The GPU kernels against their CPU counterparts. Every one is skipped with
/// a message when the machine has no usable device, so the suite still runs
/// on a build machine without a GPU.
#[cfg(all(test, target_os = "macos", feature = "metal"))]
mod gpu_tests {
    use super::*;

    /// A cheap deterministic stream of canonical M31 values.
    fn lcg(seed: u64, n: usize) -> Vec<u32> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ((x >> 33) as u32) % P
            })
            .collect()
    }

    fn device() -> Option<&'static gpu::Gpu> {
        match gpu::Gpu::get() {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("skipped: {e}");
                None
            }
        }
    }

    /// Round constants for the comparison. The crate takes them from the
    /// caller, so the real ones live on the Dart side; both sides of this
    /// test get the same arbitrary ones, which is what equality needs.
    fn rc() -> Vec<u32> {
        lcg(99, P2_RC_LEN)
    }

    #[test]
    fn poseidon2_permutation_matches_the_cpu() {
        let Some(g) = device() else { return };
        let n = 4096;
        let rc = rc();
        let states = lcg(7, 16 * n);
        let b = g.buffer_from(&states);
        let brc = g.buffer_from(&rc);
        g.run("p2_permute_test", n, &[&b, &brc], &[]).unwrap();
        let got = gpu::as_slice(&b, 16 * n);
        for i in 0..n {
            let mut want = [0u32; 16];
            want.copy_from_slice(&states[16 * i..16 * i + 16]);
            p2_permute(&mut want, &rc);
            assert_eq!(&got[16 * i..16 * i + 16], &want[..], "state {i}");
        }
    }

    #[test]
    fn poseidon2_commitment_matches_the_cpu() {
        let Some(g) = device() else { return };
        let rc = rc();
        for m in [10u32, 14, 16] {
            for k in [1usize, 3, 79] {
                let big_m = 1usize << m;
                let n = 2 * big_m;
                let ev = lcg(m as u64 * 100 + k as u64, k * n);
                let mut want = vec![0u32; (2 * big_m - 1) * 8];
                {
                    let ev: &[u32] = &ev;
                    p2_leaves(
                        big_m,
                        2 * k,
                        |i, lane| if lane < k { ev[lane * n + i] } else { ev[(lane - k) * n + big_m + i] },
                        &rc,
                        &mut want[..big_m * 8],
                    );
                }
                merkle_above_p2(&mut want, big_m, &rc);
                let bev = g.buffer_from(&ev);
                let tree = gpu::commit_tree_p2(g, &bev, k, m, &rc).unwrap();
                let got = gpu::as_slice(&tree, (2 * big_m - 1) * 8);
                assert_eq!(got, &want[..], "tree at m={m} k={k}");
            }
        }
    }

    /// Serialises the tests that flip the process-wide GPU switch.
    fn switch() -> &'static Mutex<()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn commit_columns_p2_gpu_matches_cpu() {
        let Some(_) = device() else { return };
        let _guard = switch().lock().unwrap_or_else(|e| e.into_inner());
        let rc = rc();
        for (m, k, len) in [(10u32, 3usize, 512usize), (13, 79, 4096)] {
            let big_m = 1usize << m;
            let n = 2 * big_m;
            let coefs = lcg(m as u64 * 31 + k as u64, k * len);
            let mut tree_cpu = vec![0u32; (2 * big_m - 1) * 8];
            let mut tree_gpu = vec![0u32; (2 * big_m - 1) * 8];
            sk_gpu_enable(0);
            let id_cpu =
                unsafe { sk_commit_columns_p2(coefs.as_ptr(), k, len, m, rc.as_ptr(), tree_cpu.as_mut_ptr()) };
            assert_eq!(sk_gpu_enable(1), 1);
            let id_gpu =
                unsafe { sk_commit_columns_p2(coefs.as_ptr(), k, len, m, rc.as_ptr(), tree_gpu.as_mut_ptr()) };
            sk_gpu_enable(0);
            assert_eq!(tree_cpu, tree_gpu, "tree at m={m} k={k}");
            let (a, b) = (store_get(id_cpu), store_get(id_gpu));
            assert_eq!(a.k, b.k);
            assert_eq!(a.n, b.n);
            assert_eq!(a.data.as_slice(), b.data.as_slice(), "stored columns at m={m} k={k}");
            assert_eq!(a.data.as_slice().len(), k * n);
            sk_store_free(id_cpu);
            sk_store_free(id_gpu);
        }
    }

    #[test]
    fn evaluate_columns_matches_the_cpu() {
        let Some(g) = device() else { return };
        for m in [8u32, 12, 16, 20] {
            let n = 1usize << (m + 1);
            for k in [1usize, 5, 79] {
                // the full width and a low-degree extension (blowup 8)
                for len in [n, n >> 3] {
                    let coefs = lcg(m as u64 * 7 + k as u64 * 3 + len as u64, k * len);
                    let mut want = vec![0u32; k * n];
                    par_fill_u32(&mut want, n, 2, |j, col| evaluate(&coefs[j * len..(j + 1) * len], m, col));
                    let out = gpu::SharedBuffer::new(g, k * n);
                    gpu::evaluate_columns(g, &coefs, k, len, m, &out).unwrap();
                    assert_eq!(out.as_slice(), &want[..], "evaluate m={m} k={k} len={len}");
                }
            }
        }
    }

    #[test]
    fn interpolate_columns_matches_the_cpu() {
        let Some(g) = device() else { return };
        for m in [8u32, 12, 16, 20] {
            let n = 1usize << (m + 1);
            let n_inv = inv(n as u32);
            for k in [1usize, 5, 79] {
                let vals = lcg(m as u64 * 11 + k as u64, k * n);
                let mut want = vec![0u32; k * n];
                par_fill_u32(&mut want, n, 2, |j, col| interpolate(&vals[j * n..(j + 1) * n], m, col));
                let src = gpu::SharedBuffer::from(g, &vals);
                let out = gpu::SharedBuffer::new(g, k * n);
                gpu::interpolate_columns(g, &src, k, m, &out, n_inv).unwrap();
                assert_eq!(out.as_slice(), &want[..], "interpolate m={m} k={k}");

                // and the round trip: coefficients back to the same values
                let back = gpu::SharedBuffer::new(g, k * n);
                gpu::evaluate_columns(g, out.as_slice(), k, n, m, &back).unwrap();
                assert_eq!(back.as_slice(), &vals[..], "round trip m={m} k={k}");
            }
        }
    }

    #[test]
    fn m31_arithmetic_matches_the_cpu() {
        let Some(g) = device() else { return };
        let n = 1 << 20;
        let a = lcg(1, n);
        let b = lcg(2, n);
        let sh: Vec<u32> = (0..n).map(|i| 1 + (i as u32 % 30)).collect();
        let (ba, bb, bs) = (g.buffer_from(&a), g.buffer_from(&b), g.buffer_from(&sh));
        let out = g.buffer(5 * n);
        g.run("m31_selftest", n, &[&ba, &bb, &bs, &out], &[]).unwrap();
        let got = gpu::as_slice(&out, 5 * n);
        for i in 0..n {
            assert_eq!(got[5 * i], add(a[i], b[i]), "add at {i}");
            assert_eq!(got[5 * i + 1], sub(a[i], b[i]), "sub at {i}");
            assert_eq!(got[5 * i + 2], mul(a[i], b[i]), "mul at {i}");
            let x2 = mul(a[i], a[i]);
            assert_eq!(got[5 * i + 3], mul(mul(x2, x2), a[i]), "pow5 at {i}");
            let v = [a[i]];
            assert_eq!(got[5 * i + 4], v_shl(&v, sh[i])[0], "shl at {i}");
        }
    }
}
