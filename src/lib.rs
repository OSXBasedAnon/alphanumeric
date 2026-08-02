// Production code must not panic on input it did not choose. Outside tests this crate
// contains no `panic!` at all, and the handful of remaining `unwrap`/`expect` calls are
// each infallible by construction and annotated as such. Nothing enforced that before:
// `-D warnings` only covers clippy's DEFAULT lints, and these three live in the opt-in
// `restriction` group, so one `.unwrap()` added to a decode path would have passed CI and
// handed any peer a remote process kill.
//
// `clippy::indexing_slicing` is deliberately NOT denied. It fires 124 times, almost all on
// fixed-size buffers with provably correct bounds (`header[o..o + 4].copy_from_slice(..)`);
// rewriting those to `.get()?` reads worse and blanket-allowing them would defeat the gate.
// The codec bounds-checks its own header before indexing, which is the case that mattered.
//
// Scoped to `not(test)` so test code keeps using `.unwrap()` freely. Compile-time only:
// the shipped binary is byte-identical.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod a9;
pub mod config;
