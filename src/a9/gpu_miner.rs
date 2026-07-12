//! GPU mining backend (feature `gpu_miner`, opt-in at runtime).
//!
//! Searches the 92-byte header nonce space on the GPU via a WGSL BLAKE3 kernel
//! (wgpu: Metal / Vulkan / DX12 — no system deps). Mining is NOT consensus: a
//! wrong hash here can only waste the local GPU's time, because every produced
//! block still goes through the full CPU-side validation and the network's
//! rules. Correctness is nevertheless locked by tests that compare the kernel's
//! hash byte-for-byte against the `blake3` crate.

use std::sync::atomic::{AtomicBool, Ordering};

use bytemuck::Zeroable;

const WGSL: &str = include_str!("gpu_blake3.wgsl");
const WORKGROUP: u32 = 256;
/// Sentinel zero_bits value: kernel thread 0 writes its raw hash to the result
/// buffer instead of searching (test/self-check mode).
const DEBUG_HASH_SENTINEL: u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Params {
    header: [u32; 24], // w0..w23 as 6 x vec4<u32>
    nonce_lo: u32,
    nonce_hi: u32,
    zero_bits: u32,
    threads: u32,
    iters: u32,
    // Pad the whole struct to 128 bytes: a WGSL uniform struct is 16-byte
    // aligned, so the shader-side size rounds 120 -> 128 and the binding must
    // match (wgpu rejects a 120-byte buffer as < minimum 128).
    _pad: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct ResultBuf {
    found: u32,
    nonce_lo: u32,
    nonce_hi: u32,
    _pad: u32,
    hash: [u32; 8],
}

pub struct GpuMiner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    params_buf: wgpu::Buffer,
    result_buf: wgpu::Buffer,
    readback_buf: wgpu::Buffer,
    // Buffer identities never change, so one bind group serves every dispatch
    // (rebuilding it per dispatch was pure per-dispatch churn).
    bind: wgpu::BindGroup,
    pub adapter_name: String,
}

impl GpuMiner {
    /// Initialize on the best available adapter. Errors are descriptive so the
    /// caller can fall back to CPU mining with a clear message.
    pub fn new() -> Result<Self, String> {
        pollster::block_on(Self::new_async())
    }

    async fn new_async() -> Result<Self, String> {
        // Identical to Instance::default() (all backends; Vulkan wins adapter
        // selection on NVIDIA) EXCEPT it honors WGPU_BACKEND — wgpu 22.1.0's
        // Instance::default() ignores the env var, which left no way to steer
        // a box with a broken driver stack (e.g. WGPU_BACKEND=dx12) without a
        // rebuild.
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::util::backend_bits_from_env().unwrap_or(wgpu::Backends::all()),
            ..Default::default()
        });
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or("no GPU adapter found (wgpu)")?;
        let info = adapter.get_info();
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("alphanumeric-gpu-miner"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::downlevel_defaults(),
                    memory_hints: wgpu::MemoryHints::Performance,
                },
                None,
            )
            .await
            .map_err(|e| format!("GPU device init failed: {e}"))?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("blake3-pow"),
            source: wgpu::ShaderSource::Wgsl(WGSL.into()),
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("blake3-pow"),
            layout: None,
            module: &shader,
            entry_point: "main",
            compilation_options: Default::default(),
            cache: None,
        });

        let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("params"),
            size: std::mem::size_of::<Params>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let result_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("result"),
            size: std::mem::size_of::<ResultBuf>() as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let readback_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size: std::mem::size_of::<ResultBuf>() as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind_layout = pipeline.get_bind_group_layout(0);
        let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("blake3-pow"),
            layout: &bind_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: result_buf.as_entire_binding(),
                },
            ],
        });

        Ok(Self {
            device,
            queue,
            pipeline,
            params_buf,
            result_buf,
            readback_buf,
            bind,
            adapter_name: format!("{} ({:?})", info.name, info.backend),
        })
    }

    fn header_words(header: &[u8; 92]) -> [u32; 24] {
        let mut w = [0u32; 24];
        for (i, chunk) in header.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b[..chunk.len()].copy_from_slice(chunk);
            w[i] = u32::from_le_bytes(b);
        }
        w
    }

    fn dispatch(&self, params: &Params, groups: u32) -> ResultBuf {
        self.queue
            .write_buffer(&self.params_buf, 0, bytemuck::bytes_of(params));
        self.queue.write_buffer(
            &self.result_buf,
            0,
            bytemuck::bytes_of(&ResultBuf::zeroed()),
        );
        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: None,
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind, &[]);
            pass.dispatch_workgroups(groups, 1, 1);
        }
        enc.copy_buffer_to_buffer(
            &self.result_buf,
            0,
            &self.readback_buf,
            0,
            std::mem::size_of::<ResultBuf>() as u64,
        );
        self.queue.submit([enc.finish()]);

        let slice = self.readback_buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        self.device.poll(wgpu::Maintain::Wait);
        let _ = rx.recv();
        let out: ResultBuf = *bytemuck::from_bytes(&slice.get_mapped_range());
        self.readback_buf.unmap();
        out
    }

    /// Search `threads * iters` nonces from `base_nonce` in ONE dispatch. Each
    /// thread tests `iters` consecutive nonces, so the single GPU->CPU readback is
    /// amortized across the whole batch (the ~10x throughput fix). Caller keeps
    /// `threads * iters <= 2^32` so the kernel's per-thread u32 offset is exact.
    pub fn search_batch_iters(
        &self,
        header: &[u8; 92],
        zero_bits: u32,
        base_nonce: u64,
        threads: u32,
        iters: u32,
    ) -> Option<u64> {
        debug_assert!(zero_bits != DEBUG_HASH_SENTINEL);
        let params = Params {
            header: Self::header_words(header),
            nonce_lo: base_nonce as u32,
            nonce_hi: (base_nonce >> 32) as u32,
            zero_bits,
            threads,
            iters,
            _pad: [0; 3],
        };
        let out = self.dispatch(&params, threads.div_ceil(WORKGROUP));
        if out.found != 0 {
            Some(((out.nonce_hi as u64) << 32) | out.nonce_lo as u64)
        } else {
            None
        }
    }

    /// Convenience: search `batch` nonces with one nonce per thread (used by tests).
    pub fn search_batch(
        &self,
        header: &[u8; 92],
        zero_bits: u32,
        base_nonce: u64,
        batch: u32,
    ) -> Option<u64> {
        self.search_batch_iters(header, zero_bits, base_nonce, batch, 1)
    }

    /// Search up to `max_nonces` nonces from `start_nonce` in batches, honoring
    /// `stop`. Returns the winning nonce, or None if exhausted/stopped.
    pub fn search(
        &self,
        header: &[u8; 92],
        zero_bits: u32,
        start_nonce: u64,
        max_nonces: u64,
        batch: u32,
        stop: &AtomicBool,
    ) -> Option<u64> {
        let mut done = 0u64;
        while done < max_nonces && !stop.load(Ordering::Relaxed) {
            let this = batch.min((max_nonces - done).min(u32::MAX as u64) as u32);
            if let Some(n) = self.search_batch(header, zero_bits, start_nonce.wrapping_add(done), this)
            {
                return Some(n);
            }
            done += this as u64;
        }
        None
    }

    /// Kernel self-check: BLAKE3 of the header with `nonce` computed ON THE GPU.
    /// Used by tests and the startup sanity check.
    pub fn hash_on_gpu(&self, header: &[u8; 92], nonce: u64) -> [u8; 32] {
        let params = Params {
            header: Self::header_words(header),
            nonce_lo: nonce as u32,
            nonce_hi: (nonce >> 32) as u32,
            zero_bits: DEBUG_HASH_SENTINEL,
            threads: 1,
            iters: 1,
            _pad: [0; 3],
        };
        let out = self.dispatch(&params, 1);
        let mut bytes = [0u8; 32];
        for (i, w) in out.hash.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        bytes
    }

    /// Cheap startup sanity check: one random header hashed on GPU must equal
    /// the CPU blake3 crate. Refuses to mine on a kernel that disagrees.
    pub fn self_check(&self) -> Result<(), String> {
        let mut header = [0u8; 92];
        for (i, b) in header.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let nonce: u64 = 0x0123_4567_89AB_CDEF;
        header[44..52].copy_from_slice(&nonce.to_le_bytes());
        let gpu = self.hash_on_gpu(&header, nonce);
        let cpu = blake3::hash(&header);
        if gpu != *cpu.as_bytes() {
            return Err("GPU BLAKE3 kernel disagrees with CPU (self-check failed)".into());
        }
        Ok(())
    }
}

use std::sync::atomic::AtomicU64;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::a9::blockchain::Block;

/// Process-wide cached GPU miner (init is ~100-200ms; reuse it across blocks).
/// The Err side keeps the init/self-check failure so the mine command can SHOW
/// the user why the GPU is unusable — the default log filter is Error-only, so
/// a log::warn here was invisible and `mine --gpu` on a broken adapter looked
/// like mining while doing nothing.
static GPU: OnceLock<Result<GpuMiner, String>> = OnceLock::new();

/// Converged dispatch size, carried ACROSS attempts. Attempts end on every
/// network tip change (~5s), and restarting the adaptive sizing from 4 each
/// time meant the first dispatches of EVERY attempt ran far under the wall-
/// clock target — with the rate display re-ramping alongside.
static LAST_ITERS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(4);

/// Displayed-rate EWMA (f64 bits), carried across attempts. Instantaneous
/// per-dispatch rate keeps template-rebuild gaps out of the denominator, and
/// the cross-attempt EWMA keeps the number steady through ~5s tip churn —
/// an attempt-local average sagged ~40% at every tip change and read as
/// thermal throttling on a perfectly healthy card.
static RATE_EWMA_BITS: AtomicU64 = AtomicU64::new(0);

/// Difficulty of the most recent dispatch — read by the display task.
static LAST_DIFFICULTY: AtomicU64 = AtomicU64::new(0);

fn shared_gpu_status() -> &'static Result<GpuMiner, String> {
    GPU.get_or_init(|| match GpuMiner::new() {
        Ok(m) => match m.self_check() {
            Ok(()) => Ok(m),
            Err(e) => Err(format!("self-check failed on {}: {e}", m.adapter_name)),
        },
        Err(e) => Err(e),
    })
}

/// Adapter name + backend if the GPU is usable, or the reason it is not.
/// The mine command prints this ONCE on stdout so `--gpu` is never silent
/// about which adapter it picked (or that it picked none).
pub fn gpu_status() -> Result<&'static str, String> {
    match shared_gpu_status() {
        Ok(m) => {
            // Re-verify per mine command: the OnceLock caches Ok forever, but a
            // mid-session device loss (driver reset/TDR) survives into the NEXT
            // command — without this the status line would claim a healthy GPU
            // on a dead device. One 92-byte hash (~ms); if the dead device makes
            // this panic instead of erroring, the caller's spawn_blocking
            // JoinError arm already demotes to CPU.
            m.self_check()
                .map_err(|e| format!("{} failed re-check: {e}", m.adapter_name))?;
            Ok(m.adapter_name.as_str())
        }
        Err(e) => Err(e.clone()),
    }
}

fn shared_gpu() -> Option<&'static GpuMiner> {
    shared_gpu_status().as_ref().ok()
}

/// Build the 92-byte mining header (matches the CPU miner's layout exactly).
fn build_header(
    number: u32,
    previous_hash: &[u8; 32],
    timestamp: u64,
    nonce: u64,
    difficulty: u64,
    merkle_root: &[u8; 32],
) -> [u8; 92] {
    let mut h = [0u8; 92];
    h[0..4].copy_from_slice(&number.to_le_bytes());
    h[4..36].copy_from_slice(previous_hash);
    h[36..44].copy_from_slice(&timestamp.to_le_bytes());
    h[44..52].copy_from_slice(&nonce.to_le_bytes());
    h[52..60].copy_from_slice(&difficulty.to_le_bytes());
    h[60..92].copy_from_slice(merkle_root);
    h
}

/// Expected hashes to solve one block at `difficulty` (target = MAX >> (d/16)).
fn expected_hashes(difficulty: u64) -> f64 {
    2f64.powi((difficulty / 16).min(255) as i32)
}

/// Clear the display statics at the start of a mine command so a second
/// `mine --gpu` in the same process doesn't flash the previous command's
/// GH/s and difficulty for ~1s before the first new dispatch lands.
pub fn reset_display_state() {
    RATE_EWMA_BITS.store(0, std::sync::atomic::Ordering::Relaxed);
    LAST_DIFFICULTY.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Live display readings for the mine command's bar task: (EWMA GH/s, last
/// difficulty mined against). The GPU thread only ever writes atomics — it
/// must NEVER touch the console (see gpu_mine_attempt's display note).
pub fn gpu_display_snapshot() -> (f64, u64) {
    let ghs = f64::from_bits(RATE_EWMA_BITS.load(std::sync::atomic::Ordering::Relaxed));
    let difficulty = LAST_DIFFICULTY.load(std::sync::atomic::Ordering::Relaxed);
    (if ghs.is_finite() { ghs } else { 0.0 }, difficulty)
}

/// Poisson mean seconds to one block at `difficulty` for a rate in GH/s.
pub fn expected_block_seconds(difficulty: u64, ghs: f64) -> f64 {
    expected_hashes(difficulty) / (ghs * 1e9).max(1.0)
}

/// Human "about how long" at a measured rate — the honest solo-mining ETA the
/// display owes the user (a Poisson mean, not a countdown).
pub fn format_eta(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return "…".into();
    }
    if seconds < 90.0 {
        format!("~{:.0}s", seconds)
    } else if seconds < 5400.0 {
        format!("~{:.0}m", seconds / 60.0)
    } else if seconds < 172_800.0 {
        format!("~{:.1}h", seconds / 3600.0)
    } else {
        format!("~{:.1}d", seconds / 86_400.0)
    }
}

/// GPU nonce search for one block attempt. Refreshes the timestamp/difficulty
/// per sub-batch (like the CPU miner), searching until it finds a winning nonce,
/// hits the wall-clock `budget`, or the network tip moves (tip_counter no longer
/// equals tip_version — so a block someone else mined ends this attempt in ~1
/// dispatch instead of wasting the rest of the budget on a stale template). On
/// success returns `(nonce, timestamp, difficulty, hash)` for the existing CPU
/// finalizer to build+verify — the GPU only proposes a nonce; consensus unchanged.
///
/// Display: this thread NEVER touches the console. It only writes atomics —
/// `session_progress_micro` (cumulative expected-blocks of work, micro-units)
/// plus the rate/difficulty statics — and the mine command's display task
/// paints the bar from them at its own cadence. The first version called
/// indicatif setters from this loop between dispatches; indicatif draws on the
/// CALLING thread, and Windows console writes stall for 100ms+ — the GPU sat
/// idle behind console I/O, oscillating 40-70% utilization in Task Manager on
/// a 5s-block network where every ms between dispatches is paid at the tip
/// cadence. Progress accumulates PER-DISPATCH against the difficulty that work
/// was actually done at (the Poisson intensity integral): monotonic even while
/// live difficulty flaps across a /16 band boundary, where an
/// instant-difficulty denominator would halve/double the shown percent.
#[allow(clippy::too_many_arguments)]
pub fn gpu_mine_attempt(
    number: u32,
    previous_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    previous_difficulty: u64,
    previous_block_timestamp: u64,
    budget: std::time::Duration,
    tip_counter: &std::sync::atomic::AtomicU64,
    tip_version: u64,
    session_progress_micro: &AtomicU64,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<(u64, u64, u64, [u8; 32])> {
    let gpu = shared_gpu()?;
    let deadline = Instant::now() + budget;
    // Per-dispatch batch amortizes the readback (THREADS threads each testing
    // `iters` nonces per GPU->CPU sync; THREADS*iters <= 65535*256*256 =
    // 4,294,901,760 < 2^32 keeps the kernel's per-thread u32 offset exact;
    // THREADS stays under wgpu's 65535 workgroups-per-dimension limit at
    // 65535*256 = 16.7M).
    //
    // `iters` is ADAPTIVE, targeting ~250ms of wall-clock per dispatch: the tip
    // check below only runs BETWEEN dispatches (a submitted wgpu dispatch cannot
    // be aborted), so the dispatch size IS the preemption granularity. The old
    // fixed 64 iters (~2^30 nonces) took multiple SECONDS per dispatch on slower
    // adapters — an entire block interval mining a template that was stale the
    // moment the readback returned, which read as "the GPU miner is always a few
    // blocks behind the tip". 250ms keeps any adapter within a fraction of a
    // block of the live tip while still amortizing the readback ~40x per second.
    // MAX_ITERS 256 (was 64): 64 capped a dispatch at 1.07G nonces, so any card
    // past ~4.3 GH/s ran sub-250ms dispatches and paid the readback/submit
    // overhead up to 3x more often than designed (~1-3% on a 5090-class card).
    // 65535*256*256 = 4,294,901,760 < 2^32, so the kernel's per-thread u32
    // offset stays exact; the ~250ms adaptive target still bounds preemption.
    const THREADS: u32 = 65535 * 256;
    const MAX_ITERS: u32 = 256;
    // 140ms (was 250): dispatch length trades fixed per-dispatch overhead
    // (measured ~1-2ms: fence round-trip + map + submit) against STALENESS —
    // a dispatch in flight when the tip moves is all dead work, costing D/2 on
    // average per ~5s tip change. Total waste is minimized at
    // D* = sqrt(2·T_o·T_tip) ≈ 100-160ms; 140ms cuts combined waste from
    // ~3.1% to ~2.4%. If this miner ever dominates network hashrate (rarer
    // external tip changes), larger dispatches win again — retune by the
    // formula, not by feel.
    const TARGET_DISPATCH_MS: f64 = 140.0;

    let tip_moved = || tip_counter.load(std::sync::atomic::Ordering::Acquire) != tip_version;
    // Random window base (see attempt_nonce_base): same-wallet rigs build
    // identical merkle roots within the same second, and anchored-at-0 bases
    // made them scan near-identical (timestamp, nonce) space — one rig's whole
    // hashrate wasted. Also what makes one-process-per-card multi-GPU sound.
    let mut base: u64 = crate::a9::miner::attempt_nonce_base();
    let mut iters: u32 = LAST_ITERS
        .load(std::sync::atomic::Ordering::Relaxed)
        .clamp(1, MAX_ITERS);
    // A dispatch can't be aborted once submitted, so `stop` is checked here
    // between dispatches (every ~140ms) — the finest-grained the GPU allows.
    // The caller ends the whole command on the next line when this returns.
    while Instant::now() < deadline
        && !tip_moved()
        && !stop.load(std::sync::atomic::Ordering::Relaxed)
    {
        // Clamped to the parent's timestamp (same as the CPU loop): a local
        // clock behind the parent stamps headers that fail parent-timestamp
        // validation only after the grind — every solve burned.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .max(previous_block_timestamp);
        let difficulty = Block::consensus_next_difficulty(
            previous_difficulty,
            timestamp.saturating_sub(previous_block_timestamp),
            number,
        );
        let zero_bits = (difficulty / 16) as u32;
        // Header with a placeholder nonce; the kernel substitutes each thread's.
        let header = build_header(number, previous_hash, timestamp, 0, difficulty, merkle_root);

        let per_dispatch = THREADS as u64 * iters as u64;
        let dispatch_start = Instant::now();
        if let Some(nonce) = gpu.search_batch_iters(&header, zero_bits, base, THREADS, iters) {
            // A tip that moved while this dispatch was in flight dooms the nonce
            // (the finalize guard rejects a parent mismatch anyway) — drop it here
            // and let the caller rebuild against the new tip instead of spending a
            // validate/finalize round on a dead block.
            if tip_moved() {
                return None;
            }
            let full = build_header(number, previous_hash, timestamp, nonce, difficulty, merkle_root);
            let hash = *blake3::hash(&full).as_bytes();
            return Some((nonce, timestamp, difficulty, hash));
        }
        let dispatch_ms = dispatch_start.elapsed().as_secs_f64() * 1000.0;
        base = base.wrapping_add(per_dispatch);
        iters = next_dispatch_iters(iters, dispatch_ms, TARGET_DISPATCH_MS, MAX_ITERS);
        LAST_ITERS.store(iters, std::sync::atomic::Ordering::Relaxed);

        // Telemetry only — a handful of atomic stores, nothing that can stall
        // this thread between dispatches. Rate = EWMA over per-dispatch
        // instantaneous rates; progress accumulates per_dispatch/expected AT
        // THIS DISPATCH'S DIFFICULTY in micro-expected-blocks.
        let inst_ghs = per_dispatch as f64 / (dispatch_ms.max(1.0) / 1000.0) / 1e9;
        let prev = f64::from_bits(RATE_EWMA_BITS.load(std::sync::atomic::Ordering::Relaxed));
        let ghs = if prev.is_finite() && prev > 0.0 {
            prev * 0.8 + inst_ghs * 0.2
        } else {
            inst_ghs
        };
        RATE_EWMA_BITS.store(ghs.to_bits(), std::sync::atomic::Ordering::Relaxed);
        LAST_DIFFICULTY.store(difficulty, std::sync::atomic::Ordering::Relaxed);
        let progress_inc =
            ((per_dispatch as f64 / expected_hashes(difficulty)) * 1e6).max(0.0) as u64;
        session_progress_micro.fetch_add(progress_inc, std::sync::atomic::Ordering::Relaxed);
    }
    None
}

/// Next dispatch size (iterations per thread) so one dispatch takes ~target_ms:
/// the between-dispatch tip check is the ONLY preemption point (a submitted
/// dispatch cannot be aborted), so dispatch wall-clock bounds how stale a
/// template can get. Pure so the scaling/clamping is testable. A measured time
/// of ~0 (timer glitch) leaves the size unchanged.
fn next_dispatch_iters(current: u32, measured_ms: f64, target_ms: f64, max_iters: u32) -> u32 {
    if !measured_ms.is_finite() || measured_ms < 1.0 {
        return current;
    }
    let scaled = (current as f64 * (target_ms / measured_ms)).round();
    if !scaled.is_finite() {
        return current;
    }
    (scaled as i64).clamp(1, max_iters as i64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adaptive sizing must converge toward the wall-clock target and stay
    /// inside [1, max] — dispatch size is the tip-check preemption granularity,
    /// so a slow adapter MUST shrink to ~250ms batches (the "GPU always a few
    /// blocks behind" fix) and a fast one must grow toward the readback-
    /// amortizing cap.
    #[test]
    fn dispatch_iters_adapt_toward_target() {
        // Slow adapter: 4 iters took 2s -> shrink to the floor.
        assert_eq!(next_dispatch_iters(4, 2000.0, 250.0, 64), 1);
        // Fast adapter: 4 iters in 20ms -> grow proportionally (4 * 250/20).
        assert_eq!(next_dispatch_iters(4, 20.0, 250.0, 64), 50);
        // Above the cap: clamp.
        assert_eq!(next_dispatch_iters(64, 100.0, 250.0, 64), 64);
        // The live cap (256) keeps THREADS*iters = 65535*256*256 < 2^32.
        assert!(65_535u64 * 256 * 256 < 1u64 << 32);
        assert_eq!(next_dispatch_iters(128, 50.0, 250.0, 256), 256);
        // On target: stable.
        assert_eq!(next_dispatch_iters(16, 250.0, 250.0, 64), 16);
        // Timer glitch (sub-ms measurement): unchanged.
        assert_eq!(next_dispatch_iters(8, 0.0, 250.0, 64), 8);
        assert_eq!(next_dispatch_iters(8, f64::NAN, 250.0, 64), 8);
    }

    fn miner() -> Option<GpuMiner> {
        match GpuMiner::new() {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("skipping GPU tests: {e}");
                None
            }
        }
    }

    fn header_with_nonce(seed: u8, nonce: u64) -> [u8; 92] {
        let mut h = [0u8; 92];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(seed).wrapping_add(seed);
        }
        h[44..52].copy_from_slice(&nonce.to_le_bytes());
        h
    }

    #[test]
    fn gpu_hash_matches_cpu_blake3() {
        let Some(m) = miner() else { return };
        for seed in [1u8, 7, 42, 99, 200] {
            for nonce in [0u64, 1, 0xFFFF_FFFF, 1 << 40, u64::MAX - 3] {
                let h = header_with_nonce(seed, nonce);
                let gpu = m.hash_on_gpu(&h, nonce);
                let cpu = blake3::hash(&h);
                assert_eq!(gpu, *cpu.as_bytes(), "seed={seed} nonce={nonce}");
            }
        }
    }

    #[test]
    fn gpu_search_finds_same_nonce_as_cpu_scan() {
        let Some(m) = miner() else { return };
        let zero_bits = 12u32;
        let base = 5000u64;
        let h = header_with_nonce(3, 0);
        // CPU reference scan.
        let mut expected = None;
        for n in base..base + 2_000_000 {
            let mut hh = h;
            hh[44..52].copy_from_slice(&n.to_le_bytes());
            let hash = blake3::hash(&hh);
            let lz = hash
                .as_bytes()
                .iter()
                .try_fold(0u32, |acc, &b| {
                    if b == 0 {
                        Ok(acc + 8)
                    } else {
                        Err(acc + b.leading_zeros())
                    }
                })
                .unwrap_or_else(|e| e);
            if lz >= zero_bits {
                expected = Some(n);
                break;
            }
        }
        let expected = expected.expect("reference scan found no nonce");
        let stop = AtomicBool::new(false);
        let got = m.search(&h, zero_bits, base, 2_000_000, 1 << 18, &stop);
        assert_eq!(got, Some(expected));
    }

    #[test]
    fn self_check_passes() {
        let Some(m) = miner() else { return };
        m.self_check().expect("self-check");
    }
}
