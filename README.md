# EU FSTP platform

A multi-tenant platform for running Financial Support to Third Parties (FSTP) programmes: periodic open calls, staged evaluation, independent review, grant agreements and milestone payments. The reference process is the SuperSAFE Annexe FSTP (call HORIZON-CL4-2026-04-DATA-02). Other programmes run the same process with their own policy parameters.

CrabNebula Ltd operates the hosted service. The same codebase also builds a self-hosted single-tenant deployment.

## Status

Built milestone by milestone, as `SPEC/09-milestones.md` sets out.

| Milestone | Content | State |
| --- | --- | --- |
| M0 | Specification freeze for v1 | Done |
| M1 | Rust foundations: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Built; closes when CI passes |
| M2 | Domain core: state machine, policy engine, separation of duties, scoring | Next |

## Repository layout

| Path | Content |
| --- | --- |
| `SPEC/` | The specification. Start with `SPEC/README.md` for the reading order. |
| `docs/adr/` | Architecture decision records, including the dependency allowlists. |
| `.claude/CLAUDE.md` | Rules for the implementing agent: stack, dependency policy, git and testing rules. |
| `crates/` | Platform crates in Rust. Each parser-bearing crate has a cargo-fuzz project in `fuzz/`. |
| `tools/deps-check/` | CI gate for the dependency policy, the no-Python rule and fuzz-target presence. |
| `tools/fuzz-all.sh` | Runs every fuzz target for a fixed time. |
| `deps/` | The dependency allowlist with checksums, the ADR root crates and the list of crates that need fuzz targets. |
| `.github/workflows/ci.yml` | CI: formatting, lints, tests against PostgreSQL 16, deps-check and a fuzz smoke run. |

## Building and testing

Requirements:
- rustup. `rust-toolchain.toml` pins the stable toolchain, and rustup installs it on first use.
- PostgreSQL 16 server binaries. Tests start their own server and never touch an existing one. Point `FSTP_PG_BIN` at the binaries, for example `/usr/lib/postgresql/16/bin` on Debian and Ubuntu.
- For fuzzing: cargo-fuzz 0.13.2 and the nightly toolchain that `tools/fuzz-all.sh --print-toolchain` prints.

```sh
export FSTP_PG_BIN=/usr/lib/postgresql/16/bin
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -q -p deps-check --locked
tools/fuzz-all.sh 60
```

## Dependency policy

Code is written in-house by default. A third-party crate is used only when an ADR places it on the allowlist, and cryptography comes only from the crates in ADR-001. `tools/deps-check` enforces this in CI against every lockfile, by version, checksum and enabled features.

## Licensing

The platform is licensed under the PolyForm Noncommercial License 1.0.0, as `Cargo.toml` declares. The tenant export schema and its import and export tooling are licensed separately under EUPL-1.2 (`SPEC/schemas/README.md`). The licence texts are not yet in the repository.

External contributions are accepted with a Developer Certificate of Origin sign-off.
