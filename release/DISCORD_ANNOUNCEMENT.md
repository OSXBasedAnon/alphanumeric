**Alphanumeric v7.9.0 — witness-resolution hardening + DoS resilience**

This is a security hardening release for witness handling. No consensus rule,
wire format, or network compatibility changes.

### Key fixes
- Block witness fetches are now bounded by both wall-clock deadline and a per-block
  request budget.
- Each witness fetch uses a fixed timeout cap so slow peers cannot monopolize
  frontier verification.
- If witnesses are not available in time, blocks are deferred for later re-check
  rather than being permanently poisoned.
- Hardened on both tracks: `main` + `gpu-mining`.

### Download (macOS, Apple Silicon)
Standard: `alphanumeric-v7.9.0-macos-arm64.zip`
GPU: `alphanumeric-v7.9.0-gpu-macos-arm64.zip`

### Artifacts + checksums
- `alphanumeric-v7.9.0-macos-arm64.zip`
  - `c64dc39c6e36d52a5c99c267cec2746f68a7ed0b350d36c0e97423fa1d15d405`
- `alphanumeric-v7.9.0-gpu-macos-arm64.zip`
  - `09dcc3fa5a3a30ffae7e340458f23086745b919b8494471c33aaee53b5fd8bf2`

No known consensus impact. Source build commands:
- Standard: `git checkout main && cargo build --release`
- GPU: `git checkout gpu-mining && cargo build --release --features gpu_miner`

GitHub tag placeholder:
https://github.com/OSXBasedAnon/alphanumeric/releases/tag/v7.9.0
