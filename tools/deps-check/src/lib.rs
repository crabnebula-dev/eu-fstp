//! CI gate for the dependency policy in CLAUDE.md.
//!
//! deps-check runs four gates over the repository and fails on any error:
//!
//! 1. Dependency allowlist (TH-15, H-10). It finds every cargo project in
//!    the repository: the main workspace, the cargo-fuzz projects and any
//!    other directory with a `Cargo.lock`. For each project it runs
//!    `cargo metadata --locked` six times: for x86_64 and aarch64 Linux and
//!    for all targets, each with default features and with `--all-features`.
//!    It computes the third-party packages that cargo actually builds,
//!    honouring dependency kinds and feature activation, so an unactivated
//!    weak optional dependency does not count. Each package gets a role:
//!    `runtime`, `build` or `test` (ADR-003, R-NF-07), or `platform` when
//!    no Linux context builds it. The result must match
//!    `deps/allowlist.txt` in name, version, checksum, role ceiling and ADR
//!    tree, and each ADR must record the exact crate and version. The
//!    features enabled on each ADR root must match `deps/adr-roots.txt`.
//!    Every lockfile must match the analysed graphs exactly. Patches,
//!    source replacement, vendoring and path packages outside the
//!    repository's own crates all fail.
//! 2. No Python (CLAUDE.md). No Python files, packaging files, shebangs or
//!    interpreter invocations in scripts and workflows.
//! 3. Fuzz targets (TH-26, H-05). Every crate in `deps/fuzz-required.txt`
//!    owns a cargo-fuzz project with at least one target.
//! 4. Layering of the M2 domain crates (`docs/handoff/m2-design.md` section
//!    1). No M2 crate reaches an I/O crate, `fstp-domain` has no dependency
//!    path to `fstp-findings` or `fstp-engine` (I-10), and only
//!    `fstp-domain-testkit` takes a test-only crate as a normal dependency.
//!
//! Run it from the repository root with `cargo run -p deps-check --locked`.
//! `--print-allowlist` prints an allowlist generated from the current graph,
//! keeping existing notes, for review before it replaces the file.

mod allowlist;
mod cargo;
mod fuzz;
pub mod fuzzing;
mod graph;
mod layering;
mod lockfile;
mod metadata;
mod provenance;
mod python;
mod repo;
mod report;
mod run;

pub use run::run;
