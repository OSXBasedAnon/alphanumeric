# Decoder fuzzing

This directory is an independent `cargo-fuzz` package. It lives under `tests/` so the repository's
assurance code has one home, but it is intentionally not part of ordinary `cargo test` runs.

## Prerequisites

Install nightly Rust and `cargo-fuzz` on a supported Unix-like host:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run targets from the repository root. The explicit `--fuzz-dir` is required because this package
intentionally lives under `tests/` rather than cargo-fuzz's default top-level `fuzz/` directory:

```sh
cargo +nightly fuzz build --fuzz-dir tests/fuzz
cargo +nightly fuzz run --fuzz-dir tests/fuzz codec_decode -- -max_len=1048576
cargo +nightly fuzz run --fuzz-dir tests/fuzz transaction_decode -- -max_len=1048576
cargo +nightly fuzz run --fuzz-dir tests/fuzz block_decode -- -max_len=1048576
```

The targets exercise both raw bytes and bytes placed inside the current codec envelope. Crashing
inputs belong in `artifacts/` while being investigated. Minimized reproductions must be promoted into
bounded integration or unit tests before the defect is considered fixed.
