# GPU Mining

The GPU miner is an **opt-in build** of the alphanumeric client. It hashes the
BLAKE3 proof-of-work on the GPU via [wgpu](https://wgpu.rs) — using **Vulkan,
DirectX 12, or Metal**, whichever your platform provides. There is **no CUDA and
no vendor SDK** to install.

GPU mining is a *performance* path only. Every block a GPU finds still goes
through the full CPU-side validation and the network's consensus checks before
it counts — mining is not consensus.

---

## 1. Build

The GPU miner lives behind the `gpu_miner` cargo feature (off in the stock
client). Build it with:

```sh
cargo build --release --features gpu_miner
```

`webrtc_mesh` is on by default, so the command above is a complete miner. If you
also run a bootstrap publisher, add it: `--features gpu_miner,bootstrap_publisher`.

A stock (CPU-only) build has **no** `--gpu` flag and will refuse it.

---

## 2. Run

```
mine <miner_wallet_name> [--continuous] [--gpu|--cpu]
```

- In a **GPU build, `--gpu` is the default** — `mine <wallet>` already mines on
  the GPU. `--cpu` forces CPU on a GPU build.
- `--continuous` keeps mining across blocks (paced to the network tip) instead
  of stopping after one.
- On start the miner prints the adapter and backend it selected, e.g.
  `NVIDIA GeForce RTX 4090 (Vulkan)`, or the reason it fell back to CPU.
- Before it mines, it runs a **self-check**: it hashes a known header on the GPU
  and compares to the CPU `blake3` reference. If they disagree — or GPU init
  fails — it **falls back to CPU mining so the command never silently stalls**.

Press `Enter` (or Ctrl-C) to stop.

---

## 3. Backends & troubleshooting

wgpu automatically selects the best backend for your card (Vulkan on most
NVIDIA/AMD, Metal on macOS, DirectX 12 on Windows). You normally don't touch
this. When GPU init fails, force a backend with the **`WGPU_BACKEND`** env var:

| Shell | Command (before launching the miner, in the same session) |
|---|---|
| Windows CMD | `set WGPU_BACKEND=dx12` |
| Windows PowerShell | `$env:WGPU_BACKEND="dx12"` |
| Linux / macOS | `WGPU_BACKEND=dx12 ./alphanumeric` |

Valid values: `vulkan`, `dx12`, `gl`, `metal`.

Common cases:

- **`enumerate_adaptors: initialization of an object has failed`** — the card's
  Vulkan stack is broken. Force `WGPU_BACKEND=dx12`.
- **NVIDIA CMP / mining cards** (e.g. CMP 30HX/40HX/…): their Vulkan is usually
  crippled but **DirectX 12 works** — use `WGPU_BACKEND=dx12`.
- **Remote Desktop (RDP)** hides the physical GPU, so nothing enumerates. Use a
  real monitor or a **dummy HDMI/DP plug**, or a remote tool that doesn't hijack
  the GPU (AnyDesk / Parsec), or run the miner as a service.
- **If no backend works**, the miner mines on **CPU** so you're never stuck; the
  status line will say it fell back.

---

## 4. Multi-GPU (one process per card)

Run **one miner process per GPU** and pin each process to a specific card with
**`ALPHANUMERIC_GPU_INDEX=N`** (N = the 0-based adapter index).

A 3-card rig:

```sh
# terminal / service 1
ALPHANUMERIC_GPU_INDEX=0 ./alphanumeric      # then:  mine <wallet> --gpu --continuous
# terminal / service 2
ALPHANUMERIC_GPU_INDEX=1 ./alphanumeric
# terminal / service 3
ALPHANUMERIC_GPU_INDEX=2 ./alphanumeric
```

Windows: `set ALPHANUMERIC_GPU_INDEX=1` per CMD session (or one scheduled
task / service per card).

**Mapping index → card:** when `ALPHANUMERIC_GPU_INDEX` is set, the miner prints
the full adapter roster first, so you can see which index is which card:

```
  GPU [0] NVIDIA GeForce RTX 4090 (Vulkan)
  GPU [1] NVIDIA GeForce RTX 3090 (Vulkan)
  GPU [2] NVIDIA CMP 30HX (Dx12)
```

An out-of-range index is reported (e.g. `ALPHANUMERIC_GPU_INDEX=5 is out of
range: 3 GPU adapter(s) found (valid indices 0..=2)`).

**No coordination is required or configured.** Each process seeds a **random
nonce base per attempt**, so separate processes grind disjoint regions of the
nonce space and never duplicate work — with zero cross-process communication.
Because of that:

- You can use the **same wallet on every card** (the random base de-correlates
  them), or a **different wallet per card** — both are fine.
- Adding or removing a card is just starting/stopping one more process; nothing
  else needs to change.

**Single-GPU** is the default: leave `ALPHANUMERIC_GPU_INDEX` unset and the
miner uses the single best (high-performance) adapter.

`WGPU_BACKEND` can be combined with `ALPHANUMERIC_GPU_INDEX` if a particular card
needs a specific backend (e.g. a CMP card at index 2 that needs DX12 — set both
for that process).

---

## 5. Reading the output

Each process shows a live status line with:

- **Hashrate** (GH/s) for that card,
- the **difficulty** of the block it is currently mining, and
- an **ETA** to the next block at the current rate.

Note the difficulty shown is the **next block's** target (what the miner is
working toward), which can differ slightly from the sealed-tip difficulty an
explorer shows — the miner leads the chain tip by one block's retarget.

---

## 6. Notes

- GPU mining requires the `gpu_miner` feature **at build time**; you cannot
  enable it at runtime on a stock client.
- The self-check + full block validation guarantee correctness regardless of
  backend — a GPU that computes a wrong hash is rejected and demoted to CPU, it
  never produces bad blocks.
- Mining GPU vs CPU is purely a speed choice; both submit blocks through the same
  validation and gossip path.
