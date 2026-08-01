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
        let backends = wgpu::util::backend_bits_from_env().unwrap_or(wgpu::Backends::all());
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends,
            ..Default::default()
        });
        // Multi-GPU (one process per card): ALPHANUMERIC_GPU_INDEX=N pins THIS
        // process to the Nth enumerated adapter, so a 3-GPU rig runs three
        // processes (index 0/1/2) and each card grinds a disjoint region of the
        // nonce space — the per-attempt RANDOM nonce base (see gpu_mine_attempt)
        // makes separate processes non-overlapping with no cross-process
        // coordination. Unset = auto-select (best adapter, with fallback). When
        // an index is set the full roster is printed first so an operator can
        // map index -> card.
        let gpu_index = std::env::var("ALPHANUMERIC_GPU_INDEX")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok());

        // The ordered list of adapters to try. Each is attempted (device init +
        // BLAKE3 self-check) in turn; the FIRST that passes is used.
        let candidates: Vec<wgpu::Adapter> = if let Some(idx) = gpu_index {
            // Explicit operator pin: use ONLY the chosen adapter, never fall
            // back — a sibling process is pinned to each other card, so falling
            // back here would double up one card and leave another idle.
            let adapters = instance.enumerate_adapters(backends);
            for (i, a) in adapters.iter().enumerate() {
                let gi = a.get_info();
                // device_type (DiscreteGpu/IntegratedGpu/…) so an operator can
                // tell at a glance which index is the real card vs the iGPU on a
                // mixed-GPU laptop/rig before pinning a process to it.
                eprintln!(
                    "  GPU [{}] {} ({:?}, {:?})",
                    i, gi.name, gi.backend, gi.device_type
                );
            }
            let n = adapters.len();
            let chosen = adapters.into_iter().nth(idx).ok_or_else(|| format!(
                "ALPHANUMERIC_GPU_INDEX={idx} is out of range: {n} GPU adapter(s) found (valid indices 0..={})",
                n.saturating_sub(1)
            ))?;
            vec![chosen]
        } else {
            // Auto-select with fallback: the best (HighPerformance) adapter
            // first, then every OTHER enumerated non-software adapter. A box
            // whose preferred backend is present but BROKEN — classically a bad
            // Vulkan driver on Windows/NVIDIA, where request_adapter still hands
            // back a Vulkan adapter that then fails device-init or the self-check
            // — now falls back to DX12 instead of silently demoting to CPU (the
            // exact silent-failure this backend otherwise works hard to avoid).
            // Cpu/software adapters (llvmpipe) are skipped so we never "succeed"
            // onto a path slower than the multicore CPU miner. WGPU_BACKEND is
            // honored: `backends` is already env-filtered, so an operator who
            // pinned a backend gets only that backend's adapters here — the
            // fallback never leaves their chosen backend set.
            let mut candidates = Vec::new();
            if let Some(primary) = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                })
                .await
            {
                // Skip a software primary (llvmpipe) too: request_adapter falls
                // back to software only when NO hardware GPU exists, and the
                // multicore CPU miner beats llvmpipe — so an empty candidate
                // list here cleanly demotes to CPU rather than "GPU-mining"
                // slower than the CPU path.
                if primary.get_info().device_type != wgpu::DeviceType::Cpu {
                    candidates.push(primary);
                }
            }
            for a in instance.enumerate_adapters(backends) {
                let gi = a.get_info();
                if gi.device_type == wgpu::DeviceType::Cpu {
                    continue; // never silently mine on llvmpipe
                }
                if candidates.iter().any(|c| Self::same_adapter(&c.get_info(), &gi)) {
                    continue; // already queued (the HighPerformance pick)
                }
                candidates.push(a);
            }
            // Prefer stronger fallbacks: keep the primary (the HighPerformance
            // pick) first, then order the rest DiscreteGpu-before-IntegratedGpu
            // so a broken discrete primary falls back to the SAME card on another
            // backend (e.g. DX12) rather than to a weak iGPU that could be slower
            // than the multicore CPU miner. Stable sort keeps enumerate order
            // within a device_type; len>1 guards the [1..] slice.
            if candidates.len() > 1 {
                candidates[1..].sort_by_key(|a| match a.get_info().device_type {
                    wgpu::DeviceType::DiscreteGpu => 0u8,
                    wgpu::DeviceType::IntegratedGpu => 1,
                    wgpu::DeviceType::VirtualGpu => 2,
                    _ => 3, // Other (Cpu already filtered out above)
                });
            }
            candidates
        };

        if candidates.is_empty() {
            return Err("no GPU adapter found (wgpu)".into());
        }

        // Try each candidate in order; the first that both initializes a device
        // AND passes the BLAKE3 self-check wins. Errors are collected so a total
        // failure reports WHY each adapter was rejected, not just "no GPU".
        let mut errors: Vec<String> = Vec::new();
        for adapter in candidates {
            let gi = adapter.get_info();
            let label = format!("{} ({:?})", gi.name, gi.backend);
            match Self::try_build(&adapter).await {
                Ok(miner) => return Ok(miner),
                Err(e) => errors.push(format!("{label}: {e}")),
            }
        }
        Err(format!(
            "no usable GPU adapter (tried {}): {}",
            errors.len(),
            errors.join("; ")
        ))
    }

    /// Two adapter handles refer to the same physical device+backend. Used to
    /// avoid re-trying the HighPerformance pick when it reappears in the
    /// enumerate_adapters() fallback list (AdapterInfo isn't Eq).
    fn same_adapter(a: &wgpu::AdapterInfo, b: &wgpu::AdapterInfo) -> bool {
        a.name == b.name
            && a.backend == b.backend
            && a.device == b.device
            && a.vendor == b.vendor
    }

    /// Initialize a device + pipeline + buffers on ONE adapter and gate it on
    /// the BLAKE3 self-check. Returns Err (never mines) on any failure so
    /// new_async can try the next candidate adapter — this is what turns a
    /// broken preferred backend into a fallback instead of a CPU demotion.
    async fn try_build(adapter: &wgpu::Adapter) -> Result<Self, String> {
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
            .map_err(|e| format!("device init failed: {e}"))?;

        // build_checked (pipeline/buffers + self-check dispatch) is SYNCHRONOUS
        // and can PANIC on a broken driver — wgpu routes shader/pipeline
        // validation errors through a handler that panic!()s, and a wedged
        // device can panic in get_mapped_range during the self-check. Contain
        // that panic (the release profile is panic=unwind) so new_async falls
        // through to the NEXT candidate — e.g. DX12 when the Vulkan driver is
        // broken — instead of unwinding all the way out to a CPU demotion. This
        // is what lets the fallback cover the COMMON broken-driver case (a
        // crash), not just clean Err returns. AssertUnwindSafe is sound because a
        // caught panic discards this device/queue and the next candidate builds
        // a fresh one. (A driver that HANGS in poll(Wait) rather than panicking
        // still can't be recovered — an unavoidable limit, same as baseline.)
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            Self::build_checked(device, queue, &info)
        })) {
            Ok(res) => res,
            Err(_) => Err("driver panicked during pipeline/self-check init".into()),
        }
    }

    /// Synchronous: build the pipeline + buffers on an initialized device and
    /// gate on the BLAKE3 self-check. Split out so try_build can run it under
    /// catch_unwind. Production always goes through here (never build_unchecked
    /// directly), so no adapter mines without passing the self-check.
    fn build_checked(
        device: wgpu::Device,
        queue: wgpu::Queue,
        info: &wgpu::AdapterInfo,
    ) -> Result<Self, String> {
        let miner = Self::build_unchecked(device, queue, info);
        // Gate on BLAKE3 correctness BEFORE this adapter can ever mine: a kernel
        // that disagrees with the CPU blake3 crate rejects the adapter here and
        // the caller falls through to the next candidate.
        miner.self_check()?;
        Ok(miner)
    }

    /// Build the pipeline + buffers WITHOUT the self-check. Production always
    /// uses build_checked; only the tests construct this directly, so a broken
    /// kernel FAILS their explicit hash asserts loudly instead of the whole GPU
    /// suite silently skipping (which is what an internal self-check gate would
    /// cause via the `miner()` helper returning None).
    fn build_unchecked(device: wgpu::Device, queue: wgpu::Queue, info: &wgpu::AdapterInfo) -> Self {
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

        Self {
            device,
            queue,
            pipeline,
            params_buf,
            result_buf,
            readback_buf,
            bind,
            adapter_name: format!("{} ({:?})", info.name, info.backend),
        }
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
        // poll(Wait) below IS the synchronization: wgpu 22 guarantees every
        // map_async callback has already fired by the time Maintain::Wait
        // returns. The callback is required by the API but need do nothing — the
        // old mpsc channel + rx.recv() added a per-dispatch allocation and a
        // no-op wait whose Result was discarded anyway. A failed map still
        // surfaces as a panic in get_mapped_range, exactly as before. DO NOT
        // remove poll(Wait) — deleting it (rather than the channel) deadlocks.
        slice.map_async(wgpu::MapMode::Read, |_| {});
        self.device.poll(wgpu::Maintain::Wait);
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::a9::blockchain::Block;

/// Process-wide cached GPU miner (init is ~100-200ms; reuse it across blocks).
///
/// REBUILDABLE (was a write-once OnceLock): a mid-session device loss — Windows
/// TDR, a driver reset, an eGPU unplug — used to poison the cache permanently,
/// demoting to CPU for the rest of the PROCESS even though the GPU usually
/// recovers in ~2s. Now the cache can be rebuilt: gpu_status() detects the dead
/// device on the next command and calls rebuild_gpu(), resuming GPU mining. The
/// miner is held behind an Arc so the hot mining path clones a handle under a
/// short lock and a rebuild can swap the cached miner without disturbing an
/// in-flight attempt (which keeps its old Arc, fails once, and picks up the new
/// one next attempt). Failed keeps the reason (shown to the user — the default
/// log filter is Error-only) plus a backoff clock so a truly-dead GPU doesn't
/// thrash re-creating a device every command. Recovery is split by WHERE the
/// death is detected: an IDLE loss (device reset between commands) leaves the
/// cache Ready(dead) and gpu_status rebuilds it IMMEDIATELY on the next command
/// (likely a transient TDR, recovers in ~2s); an UNDER-LOAD loss (the mining
/// dispatch panics mid-attempt) routes through note_gpu_died() into Failed, so
/// the backoff throttles it (a card that dies under load is likely FLAPPING —
/// marginal PSU/thermal/OC — and re-initializing wgpu every block is pure waste).
enum GpuCache {
    Uninit,
    Ready(Arc<GpuMiner>),
    Failed { reason: String, since: Instant },
}

static GPU: Mutex<GpuCache> = Mutex::new(GpuCache::Uninit);

/// Min gap between rebuild attempts once the GPU is in the Failed state, so a
/// persistently-dead / flapping card retries at most ~once per this window
/// instead of re-initializing wgpu (~100-200ms) + burning a crashed attempt on
/// every mine command. Monotonic Instant (not wall-clock) so an NTP step can't
/// perturb recovery timing.
const REBUILD_BACKOFF: Duration = Duration::from_secs(30);

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

/// Observed network tip-change cadence, carried across attempts: epoch-ms of
/// the last observed tip change + an EWMA of the intervals between changes.
/// Feeds the adaptive dispatch target — the optimum dispatch length depends on
/// how often the tip actually moves (D* = sqrt(2·T_o·T_tip)), and the live
/// cadence swings between ~2s (difficulty climbing) and the 5s target
/// (equilibrium). A hardcoded target tuned to either end is mistuned at the
/// other; measuring T_tip keeps the sizing correct at both without retunes.
static LAST_TIP_CHANGE_EPOCH_MS: AtomicU64 = AtomicU64::new(0);
static TIP_INTERVAL_EWMA_MS: AtomicU64 = AtomicU64::new(0);

/// Record that a tip change was just observed by the dispatch loop. EWMA over
/// the inter-change intervals, with a sanity window so counter bursts (<200ms)
/// and idle gaps between mine commands (>60s) never poison the cadence.
fn record_tip_change_observation() {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let prev = LAST_TIP_CHANGE_EPOCH_MS.swap(now_ms, std::sync::atomic::Ordering::AcqRel);
    if prev == 0 {
        return;
    }
    let interval = now_ms.saturating_sub(prev);
    if !(200..=60_000).contains(&interval) {
        return;
    }
    let prev_ewma = TIP_INTERVAL_EWMA_MS.load(std::sync::atomic::Ordering::Acquire);
    let next = if prev_ewma == 0 {
        interval
    } else {
        (prev_ewma * 7 + interval * 3) / 10
    };
    TIP_INTERVAL_EWMA_MS.store(next, std::sync::atomic::Ordering::Release);
}

/// Difficulty of the most recent dispatch — read by the display task.
static LAST_DIFFICULTY: AtomicU64 = AtomicU64::new(0);

/// (Re)build the miner into `cache` and return a handle. GpuMiner::new() self-
/// checks each adapter inside its fallback loop, so an Ok here is a verified-
/// correct BLAKE3 kernel on a working adapter (a broken preferred backend having
/// fallen back, not demoted). Records Failed with a fresh backoff clock on error.
fn build_into(cache: &mut GpuCache) -> Result<Arc<GpuMiner>, String> {
    // catch_unwind: GpuMiner::new() -> new_async() can PANIC OUTSIDE try_build's
    // own catch_unwind — a wedged driver's wgpu error handler panics in
    // request_adapter/request_device/Instance::new, which are before the guarded
    // region. Without catching it here the panic would unwind through the held
    // Mutex guard: it would POISON the lock AND skip the `*cache = Failed` write
    // below, so the backoff would never engage and every command would re-init +
    // re-panic. Catching it records Failed (backoff engages) and lets the guard
    // drop normally (no poison). GpuMiner::new is a plain fn item, so it is
    // UnwindSafe without AssertUnwindSafe.
    let built = std::panic::catch_unwind(GpuMiner::new)
        .unwrap_or_else(|_| Err("GPU init panicked (driver crash)".to_string()));
    match built {
        Ok(m) => {
            // A rebuild may have switched adapters (fast dGPU -> slower fallback);
            // re-arm the adaptive dispatch size from the floor so the first
            // dispatch on the new adapter can't inherit the old one's converged
            // (possibly MAX) iters and run for seconds before shrinking (during
            // which the tip/stop checks can't fire). Cheap: rebuilds are rare.
            LAST_ITERS.store(4, std::sync::atomic::Ordering::Relaxed);
            let arc = Arc::new(m);
            *cache = GpuCache::Ready(Arc::clone(&arc));
            Ok(arc)
        }
        Err(e) => {
            *cache = GpuCache::Failed {
                reason: e.clone(),
                since: Instant::now(),
            };
            Err(e)
        }
    }
}

/// A live miner handle, building it on first use and rebuilding a Failed cache
/// once its backoff has elapsed. Cheap on the hot path (Arc clone under a short
/// lock). The build runs while holding the lock — this serializes concurrent
/// first-inits exactly like the old OnceLock::get_or_init, and there is no await
/// held across the std Mutex (GpuMiner::new() is synchronous).
fn shared_gpu_arc() -> Result<Arc<GpuMiner>, String> {
    let mut cache = GPU.lock().unwrap_or_else(|p| p.into_inner());
    match &*cache {
        GpuCache::Ready(m) => return Ok(Arc::clone(m)),
        GpuCache::Failed { reason, since } => {
            if since.elapsed() < REBUILD_BACKOFF {
                return Err(reason.clone()); // within backoff: don't thrash re-init
            }
            // past backoff: fall through and retry the build
        }
        GpuCache::Uninit => {} // first use: fall through and build
    }
    build_into(&mut cache)
}

/// Force a rebuild NOW, ignoring the Failed backoff — called only when a re-check
/// has just proved the cached device dead (an IDLE loss, cache still Ready), so a
/// transient TDR (recovers in ~2s) resumes GPU mining immediately instead of
/// waiting out the backoff window. (An UNDER-LOAD loss goes through
/// note_gpu_died() into Failed, so it is backoff-throttled, not rebuilt here.)
fn rebuild_gpu() -> Result<Arc<GpuMiner>, String> {
    let mut cache = GPU.lock().unwrap_or_else(|p| p.into_inner());
    build_into(&mut cache)
}

/// Record that the GPU died UNDER LOAD (mid-attempt) — called from the miner's
/// spawn_blocking JoinError arm. Poisons the cache to Failed so the NEXT command
/// backs off to CPU for REBUILD_BACKOFF instead of re-initializing wgpu + burning
/// a crashed attempt every block. A card that dies specifically under mining load
/// is likely FLAPPING (marginal PSU/thermal/OC), so throttling is right; a benign
/// transient that happened to hit under load simply waits out one backoff window
/// (still self-heals, unlike the old permanent-CPU demotion).
pub fn note_gpu_died(reason: &str) {
    let mut cache = GPU.lock().unwrap_or_else(|p| p.into_inner());
    *cache = GpuCache::Failed {
        reason: format!("GPU lost mid-session: {reason}"),
        since: Instant::now(),
    };
}

/// Adapter name + backend if the GPU is usable, or the reason it is not.
/// The mine command prints this ONCE on stdout so `--gpu` is never silent
/// about which adapter it picked (or that it picked none).
pub fn gpu_status() -> Result<String, String> {
    let miner = shared_gpu_arc()?;
    // Re-verify per mine command: a cached-Ready miner can have died since the
    // last command (driver reset/TDR) — without this the status line would claim
    // a healthy GPU on a dead device. One 92-byte hash (~ms). A dead device can
    // make the readback PANIC (get_mapped_range on a lost device) rather than
    // return Err, so catch that too and treat it as a loss.
    let alive = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| miner.self_check()))
        .unwrap_or_else(|_| Err("device panicked during re-check".into()));
    match alive {
        Ok(()) => Ok(miner.adapter_name.clone()),
        Err(_dead) => {
            // Rebuild once now (new() self-checks + falls back internally). A
            // transient TDR recovers in ~2s so GPU mining resumes this command;
            // a persistently-dead GPU caches Failed and shared_gpu_arc's backoff
            // throttles further attempts. Either way the caller's spawn_blocking
            // JoinError arm still demotes to CPU if the rebuild itself dies.
            let rebuilt = rebuild_gpu()?;
            Ok(rebuilt.adapter_name.clone())
        }
    }
}

fn shared_gpu() -> Option<Arc<GpuMiner>> {
    shared_gpu_arc().ok()
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
    // Re-arm the tip-cadence sampler (prev==0 discards the next interval):
    // this runs at the start of every mining round, so the sampler never
    // bridges a miner-idle gap — win finalize + absorption (≤20s) + jitter,
    // or a ≤60s pause between commands — into a fake "tip interval" that
    // inflates the EWMA and drags the adaptive dispatch target off cadence.
    // The interval EWMA itself is kept: genuine samples stay valid across
    // rounds; only the bridge sample is discarded.
    LAST_TIP_CHANGE_EPOCH_MS.store(0, std::sync::atomic::Ordering::Release);
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
    // ADAPTIVE dispatch target (was a fixed 140ms tuned to the 5s cadence):
    // dispatch length trades fixed per-dispatch overhead T_o (measured
    // ~1-2ms: fence round-trip + map + submit) against STALENESS — a dispatch
    // in flight when the tip moves is all dead work, costing D/2 on average
    // per tip change. Combined waste = T_o/D + D/(2·T_tip), minimized at
    // D* = sqrt(2·T_o·T_tip). T_tip is MEASURED (EWMA of observed tip-change
    // intervals, see record_tip_change_observation) because the live cadence
    // swings: ~2s while difficulty climbs → D* ≈ 77ms (waste ~4.6% → ~3.9%
    // vs the old 140), 5s at equilibrium → D* ≈ 122ms (where a fixed 77
    // would be WORSE than 140). Clamped [50, 250]ms so a cadence outlier can
    // never push preemption granularity to extremes; before the first
    // measured interval, falls back to 77ms (the deploy-time ~2s cadence).
    let target_dispatch_ms = adaptive_dispatch_target_ms(
        TIP_INTERVAL_EWMA_MS.load(std::sync::atomic::Ordering::Acquire),
    );

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
    // between dispatches (every ~target_dispatch_ms) — the finest-grained the
    // GPU allows. The caller ends the whole command when this returns.
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
                record_tip_change_observation();
                return None;
            }
            let full = build_header(number, previous_hash, timestamp, nonce, difficulty, merkle_root);
            let hash = *blake3::hash(&full).as_bytes();
            return Some((nonce, timestamp, difficulty, hash));
        }
        let dispatch_ms = dispatch_start.elapsed().as_secs_f64() * 1000.0;
        base = base.wrapping_add(per_dispatch);
        iters = next_dispatch_iters(iters, dispatch_ms, target_dispatch_ms, MAX_ITERS);
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
    // Loop exit on a moved tip is the common attempt end — feed the cadence
    // EWMA here too (deadline/stop exits record nothing: no change observed).
    if tip_moved() {
        record_tip_change_observation();
    }
    None
}

/// Optimal dispatch wall-clock target for the measured tip-change cadence:
/// D* = sqrt(2·T_o·T_tip) with T_o ≈ 1.5ms, clamped to [50, 250]ms; 77ms
/// (the ~2s-cadence optimum) until the first interval is measured. Pure so
/// the operating points are testable.
fn adaptive_dispatch_target_ms(tip_interval_ewma_ms: u64) -> f64 {
    const DISPATCH_OVERHEAD_MS: f64 = 1.5;
    const FALLBACK_TARGET_MS: f64 = 77.0;
    const MIN_TARGET_MS: f64 = 50.0;
    const MAX_TARGET_MS: f64 = 250.0;
    if tip_interval_ewma_ms == 0 {
        return FALLBACK_TARGET_MS;
    }
    (2.0 * DISPATCH_OVERHEAD_MS * tip_interval_ewma_ms as f64)
        .sqrt()
        .clamp(MIN_TARGET_MS, MAX_TARGET_MS)
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
    #[allow(clippy::assertions_on_constants)] // Named proof of the live dispatch cap invariant.
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

    /// The adaptive target must hit the documented operating points of
    /// D* = sqrt(2·T_o·T_tip) and stay inside its clamps at the extremes.
    #[test]
    fn adaptive_dispatch_target_tracks_cadence() {
        // No measurement yet: deploy-time fallback.
        assert_eq!(adaptive_dispatch_target_ms(0), 77.0);
        // ~2s cadence (difficulty climbing): ≈77ms.
        assert!((adaptive_dispatch_target_ms(2_000) - 77.46).abs() < 0.1);
        // 5s equilibrium cadence: ≈122ms.
        assert!((adaptive_dispatch_target_ms(5_000) - 122.47).abs() < 0.1);
        // Sub-second churn clamps at the floor (preemption never coarser-bounded
        // than 50ms), multi-minute cadence at the ceiling.
        assert_eq!(adaptive_dispatch_target_ms(500), 50.0);
        assert_eq!(adaptive_dispatch_target_ms(60_000), 250.0);
    }

    /// Build a miner on the best adapter WITHOUT the internal self-check, so the
    /// correctness tests below run their OWN explicit hash asserts and FAIL
    /// LOUDLY on a broken kernel. Production's GpuMiner::new() self-checks
    /// internally (the adapter-fallback gate), which would instead make this
    /// return None and SILENTLY SKIP the whole GPU suite on a broken kernel —
    /// exactly the regression a correctness test must not have. Returns None only
    /// when no GPU adapter/device exists (a legitimate skip on a headless box).
    fn miner() -> Option<GpuMiner> {
        let m = pollster::block_on(async {
            let backends = wgpu::util::backend_bits_from_env().unwrap_or(wgpu::Backends::all());
            let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
                backends,
                ..Default::default()
            });
            let adapter = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                })
                .await?;
            let info = adapter.get_info();
            let (device, queue) = adapter
                .request_device(
                    &wgpu::DeviceDescriptor {
                        label: Some("alphanumeric-gpu-miner-test"),
                        required_features: wgpu::Features::empty(),
                        required_limits: wgpu::Limits::downlevel_defaults(),
                        memory_hints: wgpu::MemoryHints::Performance,
                    },
                    None,
                )
                .await
                .ok()?;
            Some(GpuMiner::build_unchecked(device, queue, &info))
        });
        if m.is_none() {
            eprintln!("skipping GPU tests: no usable GPU adapter/device");
        }
        m
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
