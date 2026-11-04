# EU FSTP platform

A multi-tenant platform for running Financial Support to Third Parties (FSTP) programmes: periodic open calls, staged evaluation, independent review, grant agreements and milestone payments. The reference process is the SuperSAFE Annexe FSTP (call HORIZON-CL4-2026-04-DATA-02). Other programmes run the same process with their own policy parameters.

CrabNebula Ltd operates the hosted service. The same codebase also builds a self-hosted single-tenant deployment.

## Status

Status on 2026-10-31. Built milestone by milestone, as `SPEC/09-milestones.md` sets out. M4 started on 2026-10-29, before M3 closed, so that pages existed for a demo.

| Milestone | Content | State |
| --- | --- | --- |
| M0 | Specification freeze for v1 | Done |
| M1 | Rust foundations: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Done |
| M2 | Domain core: state machine, policy engine, separation of duties, scoring | Done, merged into `main` |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | In progress. Exit criteria not yet green |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server, public research tools | In progress. 9 of 24 work-plan steps done |
| M5 | Contracts, payment requests, payment adapters, MCP client integrations | Not started. Starts after M4 closes |
| M6 to M12 | Timeline and email, the LLM assessor, messaging, export and white-labelling, hardening, the pilot and calibration | Not started |

### M3: what exists and what is open

Built: the cell runtime with its routes, engine, record store and signing, and the control plane protocol and provisioning. Authentication uses passkeys and magic links, with first-admin enrolment. The identity vault, the witness and the vault run loops work. Every database connection checks the server identity (I-83), all role grants come from one plan (I-82), and a local development stack runs.

Open: the slice cycle steps of the test world, the self-hosted witness, record store gaps, key-volume custody, the control plane run loops, the vault audit chain, and ML-DSA-65 in moduletto. Production anchoring waits on the last one.

### M4: what exists and what is open

Built: tenant onboarding through to two admins, and the programme creator with drafts, validation and activation by a second admin (I-66, I-67). The Guide for Applicants parser and renderer work. Imported funding documents change a draft only through a named programme manager (I-65). The applicant, reviewer, coordinator, committee and IRC pages exist.

In progress: strict activation pairing for every programme (D2e), a home page and navigation after sign-in, the profile page, OAuth, the authorisation matrix harness, and the tenant sign-up review.

Not started: the MCP server, public pages and tools, the admin, auditor and agent pages, the switch from test fakes to the M3 runtime, the full review, and the exit run in CI.

### Branches

`main` holds all of M0 to M4 so far, and it is the only integration branch. Work runs in short-lived lane branches that merge into `main` once every gate passes. Some tests are red on purpose: each waits on a seam that a named lane closes. `ci/known-red.txt` lists each one with its seam and lane, and CI fails on any other red test (`tools/test-gate`).

### Decisions

Daniel's answers are recorded in `docs/handoff/m3-design.md` section 21.0 and `docs/handoff/m4-design.md` section 15.0, and in the ADRs in `docs/adr/`. Every reading not yet decided is marked "Interim, pending Daniel" where it is built.

## Running the demo

The demo runs one test cell with synthetic data only. Sign-in uses real passkeys through the browser's own prompt. The cell sends no email: the demo page shows every message instead.

```sh
FSTP_DEMO_PORT=8640 tools/demo/run.sh start
```

Then open the demo page at `http://127.0.0.1:8641/demo`. It lists the people of the current scene with their sign-in links, every message the cell sent, and links that switch scenes. `docs/handoff/m4-demo.md` gives the click paths and the journey results.

Known gap: after sign-in a person lands on the account page, and the app has no home page or role navigation yet. Work in progress adds both.

## Repository layout

| Path | Content |
| --- | --- |
| `SPEC/` | The specification. Start with `SPEC/README.md` for the reading order. |
| `docs/adr/` | Architecture decision records, including the dependency allowlists. |
| `.claude/CLAUDE.md` | Rules for the implementing agent: stack, dependency policy, git and testing rules. |
| `crates/` | Platform crates in Rust. Each parser-bearing crate has a cargo-fuzz project in `fuzz/`. |
| `tools/deps-check/` | CI gate for the dependency policy, the no-Python rule and fuzz-target presence. |
| `tools/fuzz-all.sh` | Runs every fuzz target for a fixed time. |
| `web/` | The pages, in TypeScript with no framework (ADR-014). |
| `e2e/` | Playwright journeys against the demo cell. |
| `tools/demo/run.sh` | Starts, seeds and stops the demo cell. |
| `docs/handoff/` | Design documents per milestone, the decisions, and the demo notes. |
| `deps/` | The dependency allowlist with checksums, the ADR root crates and the list of crates that need fuzz targets. |
| `.github/workflows/ci.yml` | CI: formatting, lints, tests against PostgreSQL 16, deps-check and a fuzz smoke run. |

## Building and testing

Requirements:
- rustup. `rust-toolchain.toml` pins the stable toolchain, and rustup installs it on first use.
- PostgreSQL 16 server binaries. Tests start their own server and never touch an existing one. Point `FSTP_PG_BIN` at the binaries, for example `/usr/lib/postgresql/16/bin` on Debian and Ubuntu.
- For the pages and the journeys: Node.js 24.11.1 with npm 11.6.2 (ADR-003). Run `npm ci --ignore-scripts` in `web/` and `e2e/`.
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

The platform is licensed under the PolyForm Noncommercial License 1.0.0, as `Cargo.toml` declares. The tenant export schema and its import and export tooling are licensed separately under EUPL-1.2 (`SPEC/schemas/README.md`). `LICENSE.md` holds the PolyForm Noncommercial License 1.0.0 text, copied unchanged from the `1.0.0` tag of the PolyForm project licence repository. The EUPL-1.2 text arrives with the export and import tooling. TODO(legal): the `Required Notice:` line that names the licensor is for Daniel to add.

External contributions are accepted with a Developer Certificate of Origin sign-off.
