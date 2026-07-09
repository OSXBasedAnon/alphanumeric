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
    batch: u32,
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
    pub adapter_name: String,
}

impl GpuMiner {
    /// Initialize on the best available adapter. Errors are descriptive so the
    /// caller can fall back to CPU mining with a clear message.
    pub fn new() -> Result<Self, String> {
        pollster::block_on(Self::new_async())
    }

    async fn new_async() -> Result<Self, String> {
        let instance = wgpu::Instance::default();
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

        Ok(Self {
            device,
            queue,
            pipeline,
            params_buf,
            result_buf,
            readback_buf,
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
        let bind_layout = self.pipeline.get_bind_group_layout(0);
        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None,
            layout: &bind_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: self.params_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: self.result_buf.as_entire_binding(),
                },
            ],
        });
        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: None,
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind, &[]);
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

    /// Search `batch` nonces starting at `base_nonce`. Returns the first winning
    /// nonce found, if any. One synchronous GPU round-trip.
    pub fn search_batch(
        &self,
        header: &[u8; 92],
        zero_bits: u32,
        base_nonce: u64,
        batch: u32,
    ) -> Option<u64> {
        debug_assert!(zero_bits != DEBUG_HASH_SENTINEL);
        let params = Params {
            header: Self::header_words(header),
            nonce_lo: base_nonce as u32,
            nonce_hi: (base_nonce >> 32) as u32,
            zero_bits,
            batch,
        };
        let out = self.dispatch(&params, batch.div_ceil(WORKGROUP));
        if out.found != 0 {
            Some(((out.nonce_hi as u64) << 32) | out.nonce_lo as u64)
        } else {
            None
        }
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
            batch: 1,
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

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::a9::blockchain::Block;

/// Process-wide cached GPU miner (init is ~100-200ms; reuse it across blocks).
/// None once init has failed, so we don't retry a broken/absent GPU every block.
static GPU: OnceLock<Option<GpuMiner>> = OnceLock::new();

fn shared_gpu() -> Option<&'static GpuMiner> {
    GPU.get_or_init(|| match GpuMiner::new() {
        Ok(m) => match m.self_check() {
            Ok(()) => {
                log::info!("GPU miner ready: {} (BLAKE3 self-check passed)", m.adapter_name);
                Some(m)
            }
            Err(e) => {
                log::warn!("GPU miner disabled: {e}");
                None
            }
        },
        Err(e) => {
            log::warn!("GPU miner unavailable ({e}); mining on CPU");
            None
        }
    })
    .as_ref()
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

/// GPU nonce search for one block attempt. Refreshes the timestamp/difficulty
/// per sub-batch (like the CPU miner), searching until it finds a winning nonce,
/// hits the wall-clock `budget`, or `stop` is set. On success returns
/// `(nonce, timestamp, difficulty, hash)` for the existing CPU finalizer to
/// build+verify — the GPU only proposes a nonce; consensus is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn gpu_mine_attempt(
    number: u32,
    previous_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    previous_difficulty: u64,
    previous_block_timestamp: u64,
    budget: std::time::Duration,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<(u64, u64, u64, [u8; 32])> {
    let gpu = shared_gpu()?;
    let deadline = Instant::now() + budget;
    const BATCH: u32 = 1 << 22; // 4M nonces / dispatch

    let mut base: u64 = 0;
    while Instant::now() < deadline && !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let difficulty = Block::consensus_next_difficulty(
            previous_difficulty,
            timestamp.saturating_sub(previous_block_timestamp),
            number,
        );
        let zero_bits = (difficulty / 16) as u32;
        // Header with a placeholder nonce; the kernel substitutes each thread's.
        let header = build_header(number, previous_hash, timestamp, 0, difficulty, merkle_root);

        if let Some(nonce) = gpu.search_batch(&header, zero_bits, base, BATCH) {
            let full = build_header(number, previous_hash, timestamp, nonce, difficulty, merkle_root);
            let hash = *blake3::hash(&full).as_bytes();
            return Some((nonce, timestamp, difficulty, hash));
        }
        base = base.wrapping_add(BATCH as u64);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
