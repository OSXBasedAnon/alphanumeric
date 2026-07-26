# alphanumeric v7.9.0

Security hardening release for witness resolution. No consensus-rule changes.
macOS (Apple Silicon) prebuilt below; Linux/Windows/other platforms build from
source.

## What's new
- **Bounded witness fetch during block admission**: full-witness resolution is now
  hard-bounded per block with a strict deadline and an explicit per-block request
  budget.
- **Per-fetch timeout cap in all branches**: each witness fetch is capped by a fixed
  timeout so one slow or unresponsive peer cannot stall frontier verification.
- **Defer, don’t crater**: when witness retrieval times out or exhausts budget, the
  block is deferred (`Ok(false)`) for revalidation instead of being permanently
  rejected through panic/error paths.
- **Applied to both release tracks**: this fix is present on `main` (standard build)
and `gpu-mining` (opt-in GPU build).

This hardening directly reduces peer-stall and witness-fetch resource exhaustion
risk while preserving consensus behavior and backward compatibility.

## Install / verify
- **Standard**: use `alphanumeric-v7.9.0-macos-arm64.zip`
- **GPU mining (opt-in)**: use `alphanumeric-v7.9.0-gpu-macos-arm64.zip`
- **Signature model / protocol** unchanged; no protocol migration.

## Artifacts
| file | sha256 |
|---|---|
| alphanumeric-v7.9.0-macos-arm64.zip | `c64dc39c6e36d52a5c99c267cec2746f68a7ed0b350d36c0e97423fa1d15d405` |
| alphanumeric-v7.9.0-gpu-macos-arm64.zip (opt-in GPU mining) | `09dcc3fa5a3a30ffae7e340458f23086745b919b8494471c33aaee53b5fd8bf2` |

## Notes
- Build verification source: `cargo build --release` on `main`, and
  `cargo build --release --features gpu_miner` on `gpu-mining`.
- Version in this repo is `7.9.0`; this release uses the existing macOS packaging
  layout from prior releases.
