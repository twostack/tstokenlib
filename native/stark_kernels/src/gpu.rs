//! The experimental Metal backend (Apple Silicon only), behind the `metal`
//! feature. It holds one device, queue and compiled shader library for the
//! process, and a cache of pipeline states; the kernels in `lib.rs` route
//! here only while the switch set by `sk_gpu_enable` is on.
//!
//! The shaders are compiled from source at first use rather than built into
//! a `.metallib`, so the crate needs no Xcode project and the source that
//! runs is the source in the repository.

use metal::{
    Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, Library, MTLResourceOptions, MTLSize,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const SOURCE: &str = include_str!("kernels.metal");

/// Device, queue, library and pipelines. Metal's own objects are safe to use
/// from several threads (buffer and command-buffer creation are documented as
/// thread-safe); the Rust bindings do not assert that, so the promise is made
/// here. Kernels are in any case driven from the one thread that entered the
/// FFI call.
pub struct Gpu {
    device: Device,
    queue: CommandQueue,
    library: Library,
    pipelines: Mutex<HashMap<String, ComputePipelineState>>,
}

unsafe impl Send for Gpu {}
unsafe impl Sync for Gpu {}

/// Why the backend is unavailable, for the caller to report rather than
/// silently fall back.
#[derive(Debug)]
pub enum GpuError {
    NoDevice,
    Compile(String),
    MissingFunction(String),
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::NoDevice => write!(f, "no Metal device"),
            GpuError::Compile(e) => write!(f, "shader compilation failed: {e}"),
            GpuError::MissingFunction(n) => write!(f, "shader library has no function {n}"),
        }
    }
}

impl Gpu {
    fn create() -> Result<Gpu, GpuError> {
        let device = Device::system_default().ok_or(GpuError::NoDevice)?;
        let queue = device.new_command_queue();
        let opts = CompileOptions::new();
        let library = device.new_library_with_source(SOURCE, &opts).map_err(GpuError::Compile)?;
        Ok(Gpu { device, queue, library, pipelines: Mutex::new(HashMap::new()) })
    }

    /// The process's GPU, created once. `Err` is remembered too, so a machine
    /// without a device does not retry the device lookup per call.
    pub fn get() -> Result<&'static Gpu, &'static GpuError> {
        static GPU: OnceLock<Result<Gpu, GpuError>> = OnceLock::new();
        GPU.get_or_init(Gpu::create).as_ref()
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    fn pipeline(&self, name: &str) -> Result<ComputePipelineState, GpuError> {
        if let Some(p) = self.pipelines.lock().unwrap().get(name) {
            return Ok(p.clone());
        }
        let f = self.library.get_function(name, None).map_err(|_| GpuError::MissingFunction(name.to_string()))?;
        let p = self
            .device
            .new_compute_pipeline_state_with_function(&f)
            .map_err(|e| GpuError::Compile(format!("pipeline {name}: {e}")))?;
        self.pipelines.lock().unwrap().insert(name.to_string(), p.clone());
        Ok(p)
    }

    /// A shared (unified-memory) buffer of `len` words, readable by the CPU
    /// in place.
    pub fn buffer(&self, len: usize) -> Buffer {
        self.device.new_buffer((len * 4) as u64, MTLResourceOptions::StorageModeShared)
    }

    /// A shared buffer holding a copy of `data`.
    pub fn buffer_from(&self, data: &[u32]) -> Buffer {
        self.device.new_buffer_with_data(
            data.as_ptr() as *const std::ffi::c_void,
            (data.len() * 4) as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Runs `name` over `threads` threads with `buffers` bound in order and
    /// `words` as 4-byte constants bound after them, and waits for it.
    ///
    /// One dispatch per command buffer, committed and waited on: macOS kills
    /// a command buffer that runs for seconds, and every stage here is short.
    pub fn run(&self, name: &str, threads: usize, buffers: &[&Buffer], words: &[u32]) -> Result<(), GpuError> {
        if threads == 0 {
            return Ok(());
        }
        let pipeline = self.pipeline(name)?;
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(&pipeline);
        for (i, b) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(b), 0);
        }
        for (i, w) in words.iter().enumerate() {
            enc.set_bytes(
                (buffers.len() + i) as u64,
                4,
                w as *const u32 as *const std::ffi::c_void,
            );
        }
        let width = pipeline.max_total_threads_per_threadgroup().min(256) as usize;
        enc.dispatch_threads(
            MTLSize::new(threads as u64, 1, 1),
            MTLSize::new(width.min(threads) as u64, 1, 1),
        );
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        Ok(())
    }

    /// `run` over a two-dimensional grid (butterflies x columns).
    pub fn run2(&self, name: &str, x: usize, y: usize, buffers: &[&Buffer], words: &[u32]) -> Result<(), GpuError> {
        if x == 0 || y == 0 {
            return Ok(());
        }
        let pipeline = self.pipeline(name)?;
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(&pipeline);
        for (i, b) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(b), 0);
        }
        for (i, w) in words.iter().enumerate() {
            enc.set_bytes((buffers.len() + i) as u64, 4, w as *const u32 as *const std::ffi::c_void);
        }
        let width = pipeline.max_total_threads_per_threadgroup().min(256) as usize;
        enc.dispatch_threads(
            MTLSize::new(x as u64, y as u64, 1),
            MTLSize::new(width.min(x) as u64, 1, 1),
        );
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        Ok(())
    }
}

/// Contents of a shared buffer as a slice of `len` words.
pub fn as_slice(b: &Buffer, len: usize) -> &[u32] {
    unsafe { std::slice::from_raw_parts(b.contents() as *const u32, len) }
}

/// Contents of a shared buffer as a mutable slice of `len` words.
pub fn as_mut_slice(b: &Buffer, len: usize) -> &mut [u32] {
    unsafe { std::slice::from_raw_parts_mut(b.contents() as *mut u32, len) }
}

// ---------------------------------------------------------------- drivers

/// Poseidon2 leaves over `k` column pairs of the evaluations in `ev`, then
/// every level above them, into a fresh tree buffer of `(2M - 1) * 8` lanes
/// (the layout `merkle_above_p2` builds on the CPU).
pub fn commit_tree_p2(g: &Gpu, ev: &Buffer, k: usize, m: u32, rc: &[u32]) -> Result<Buffer, GpuError> {
    let big_m = 1usize << m;
    let tree = g.buffer((2 * big_m - 1) * 8);
    let brc = g.buffer_from(rc);
    g.run("p2_leaves_columns", big_m, &[ev, &tree, &brc], &[k as u32, big_m as u32])?;
    let mut offset = 0usize;
    let mut len = big_m;
    while len > 1 {
        let next = len / 2;
        g.run("p2_compress_level", next, &[&tree, &brc], &[(offset * 8) as u32, ((offset + len) * 8) as u32])?;
        offset += len;
        len = next;
    }
    Ok(tree)
}

/// A shared buffer and its length, safe to keep in the column store. The
/// buffer is only ever read as memory once the command buffer that wrote it
/// has completed, and Metal buffers may be read from any thread; the Rust
/// bindings do not assert that, so the promise is made here.
pub struct SharedBuffer {
    buffer: Buffer,
    len: usize,
}

unsafe impl Send for SharedBuffer {}
unsafe impl Sync for SharedBuffer {}

impl SharedBuffer {
    pub fn new(g: &Gpu, len: usize) -> SharedBuffer {
        SharedBuffer { buffer: g.buffer(len), len }
    }

    pub fn buffer(&self) -> &Buffer {
        &self.buffer
    }

    pub fn as_slice(&self) -> &[u32] {
        as_slice(&self.buffer, self.len)
    }

    pub fn as_mut_slice(&self) -> &mut [u32] {
        as_mut_slice(&self.buffer, self.len)
    }

    /// A shared buffer holding a copy of `data`.
    pub fn from(g: &Gpu, data: &[u32]) -> SharedBuffer {
        SharedBuffer { buffer: g.buffer_from(data), len: data.len() }
    }
}

/// Which of a domain's four tables a twiddle buffer holds.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Twiddle {
    X,
    Y,
    XInv,
    YInv,
}

/// The twiddles of HalfCoset(log) on the GPU, uploaded once per domain and
/// kept beside the CPU's own `tables` cache: a node reuses the same handful
/// of domains for every column set it commits.
fn twiddles(g: &Gpu, log: u32, which: Twiddle) -> Arc<SharedBuffer> {
    static CACHE: OnceLock<Mutex<HashMap<(u32, Twiddle), Arc<SharedBuffer>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(b) = cache.lock().unwrap().get(&(log, which)) {
        return b.clone();
    }
    let t = super::tables(log);
    let src: &[u32] = match which {
        Twiddle::X => &t.x,
        Twiddle::Y => &t.y,
        Twiddle::XInv => &t.x_inv,
        Twiddle::YInv => &t.y_inv,
    };
    let b = Arc::new(SharedBuffer::from(g, src));
    cache.lock().unwrap().insert((log, which), b.clone());
    b
}

/// Evaluates `k` coefficient columns of `len` words onto HalfCoset(m) ∪ conj
/// into `out`: the bit-reversed scatter of the zero-padded coefficients (the
/// low-degree extension), one dispatch per butterfly stage, then the twin
/// butterfly. Exactly the steps of `evaluate` in lib.rs.
pub fn evaluate_columns(g: &Gpu, coefs: &[u32], k: usize, len: usize, m: u32, out: &SharedBuffer) -> Result<(), GpuError> {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let bits = m + 1;
    let v = out.buffer();
    g.run2("fft_fill_zero", n, k, &[v], &[n as u32])?;
    let bcoefs = g.buffer_from(coefs);
    g.run2("fft_scatter", len, k, &[&bcoefs, v], &[len as u32, n as u32, bits])?;
    for l in (0..m).rev() {
        let log = m - l;
        let tx = twiddles(g, log, Twiddle::X);
        g.run2("fft_eval_stage", big_m, k, &[v, tx.buffer()], &[log - 1, n as u32])?;
    }
    let ty = twiddles(g, m, Twiddle::Y);
    g.run2("fft_eval_twin", big_m, k, &[v, ty.buffer()], &[big_m as u32, n as u32])?;
    Ok(())
}

/// Interpolates `k` value columns of 2^(m+1) words (twin layout) in `vals`
/// into coefficient columns in `out`: the twin butterfly with the y
/// inverses, one dispatch per stage with the x inverses, then the n^-1 scale
/// and bit reversal. Exactly the steps of `interpolate` in lib.rs. `vals` is
/// consumed (the transform is in place).
pub fn interpolate_columns(g: &Gpu, vals: &SharedBuffer, k: usize, m: u32, out: &SharedBuffer, n_inv: u32) -> Result<(), GpuError> {
    let big_m = 1usize << m;
    let n = 2 * big_m;
    let bits = m + 1;
    let v = vals.buffer();
    let ty = twiddles(g, m, Twiddle::YInv);
    g.run2("fft_interp_twin", big_m, k, &[v, ty.buffer()], &[big_m as u32, n as u32])?;
    let mut l = 0u32;
    while (big_m >> l) >= 2 {
        let log = m - l;
        let tx = twiddles(g, log, Twiddle::XInv);
        g.run2("fft_interp_stage", big_m, k, &[v, tx.buffer()], &[log - 1, n as u32])?;
        l += 1;
    }
    g.run2("fft_interp_out", n, k, &[v, out.buffer()], &[n_inv, n as u32, bits])?;
    Ok(())
}
