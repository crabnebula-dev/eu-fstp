//! Test-only kit for the domain invariant suites.
//!
//! The kit holds the synthetic identity vault, independent references
//! written from the spec text, generators, the scenario builder, the reduced
//! clock and the fstp-prop and fstp-mc adapters. The invariant suites live
//! in `tests/` (`docs/handoff/m2-design.md` sections 4.5 and 6).
//!
//! The kit never ships. No crate other than this one may take it, fstp-prop
//! or fstp-mc as a normal dependency, which `tools/deps-check` enforces.
//! Fixtures are synthetic numbers only, never real personal data.
//!
//! Status: the harness from step W2 is in place: `vault`, `scenario`, `clock`
//! and `harness`, owned by lane W2. The W3 to W5 lanes own their files under
//! `reference`, `gen` and `mc`, which are still empty stubs.
//!
//! # Compile-fail doctests
//!
//! Rustdoc checks the error code of a `compile_fail` doctest only on the
//! nightly channel. The pinned stable 1.97 ignores it. So each forbidden
//! construction gets a `compile_fail` doctest and a `no_run` twin that
//! differs only in the forbidden line (design section 3.5). The twins are
//! the real guard.
//!
//! The sentinel below claims E0308, a type mismatch, but fails with E0599,
//! no such method. It passes only while error codes are ignored. It guards
//! a switch of the doctest channel to nightly, not a stable version bump.
//! It fails today under nightly rustdoc, so doctests run on the pinned
//! stable toolchain only. If doctests ever move to nightly, add the error
//! codes to every `compile_fail` doctest, then give this sentinel its true
//! code.
//!
//! ```compile_fail,E0308
//! let x = 1u8;
//! x.no_such_method();
//! ```

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod activation;
pub mod clock;
pub mod harness;
pub mod mc;
pub mod publicity;
pub mod reference;
pub mod scenario;
pub mod vault;

/// Generators. `gen` is a reserved keyword in Rust 2024, so the module is
/// declared as a raw identifier and lives in `src/gen/`.
pub mod r#gen;
