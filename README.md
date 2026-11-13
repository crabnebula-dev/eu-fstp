# EU FSTP platform

A multi-tenant platform for running Financial Support to Third Parties (FSTP) programmes: periodic open calls, staged evaluation, independent review, grant agreements and milestone payments. The reference process is the SuperSAFE Annexe FSTP (call HORIZON-CL4-2026-04-DATA-02). Other programmes run the same process with their own policy parameters.

CrabNebula Ltd operates the hosted service. The same codebase also builds a self-hosted single-tenant deployment.

## Status

Status on 2026-11-13. Built milestone by milestone, as `SPEC/09-milestones.md` sets out. Several milestones were built in parallel so the whole process could be shown end to end. A milestone closes only when its exit criteria pass in CI. M0 to M2 are closed. The others below are built in part or in full, but none is closed yet.

| Milestone | Content | Built | Exit criteria |
| --- | --- | --- | --- |
| M0 | Specification freeze for v1 | Done | Closed |
| M1 | Rust foundations: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Done | Closed |
| M2 | Domain core: state machine, policy engine, separation of duties, scoring | Done | Closed at domain level |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | Built, except the cell's licence and update tasks and the self-hosted service steps | Not green. I-16 to I-19, I-78 and I-81 to I-83 are green. I-20, I-24, I-38, I-39, I-77 and I-79 each have red tests; several wait on Daniel's decisions. See `docs/handoff/m3-exit-audit.md` |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server, public research tools, and the journey UI | Built | Not green. SuperSAFE is built through the creator and the cycle reaches NEGOTIATION in the demo. I-66 and I-67 tests and the authorisation matrix are on the known-red list, and the I-84 MCP matrix run has not finished |
| M5 | Contracts and payment requests in record-only mode, grant completion, funder reports | Built | The cycle reaches PAID in the demo. The I-30 to I-33 tests exist. Not yet confirmed in CI |
| M6 | Timeline engine, dispatcher, email, and the in-app mailbox | Built | The I-25 to I-27 tests exist. The crash-injection run is not yet confirmed in CI |
| M7 | Assessor, pre-check, evaluation harness, synthetic corpus | Built | The I-10, I-11 and I-21 tests exist. No evaluation run against a live model has been reported, so the thresholds are not yet met |
| M8 | Matrix and WhatsApp | Deferred (B-03, B-05) | None while deferred |
| M9 | ML-DSA-65 and composite signatures, branding, terminology, public transparency pages, funder profiles, SBOM | Built: publicity choices, versioned funder profiles with Horizon Europe v1, the notice companion signature, admin branding and terminology screens, the SBOM | Not yet confirmed in CI. `docs/handoff/m9-exit-audit.md` maps each invariant to its tests. I-74 stays open until the Mythos confirmation |
| M10 | Hardening on a Mythos-tier model | Not started | Needs the Mythos-tier run. Design in `docs/handoff/m10-m12-design.md` |
| M11 | Pilot with SuperSAFE and a second programme | Not started | Waits on the parties' approval |
| M12 | Calibration with consented real proposals | Consent records and per-corpus metrics (`fstp-calib`) only | Needs real consented proposals |

CI on `main` passes deps-check, fmt and clippy, the web tests and the SBOM job. The known-red gate was fixed on 2026-11-13 and now judges every test part. The authorisation matrix shards, the domain testkit part and the M-ACTIVATE model check run as separate parts. The remaining red tests are listed in `ci/known-red.txt` or in the exit audits.

### M3: what is open

Built: the cell runtime with its routes, engine, record store and signing; the control plane with its run loops, operator login and cell link; `fstp-pgagent`, which applies the role plan; signup, passkeys, magic links, step-up and recovery; the login email index; the identity vault with its audit chain; the witness with a local file store for self-hosted cells; key custody through `fstp-keyd`; backups sealed with the hybrid KEM; and a test world that runs the call cycle from signup to GRANTED over HTTP. ML-DSA-65 comes from moduletto and runs in CI with its ACVP vectors.

Open: the cell's licence and update tasks and the self-hosted service steps (I-38, I-39), cell erasure, the money and ledger suites over PostgreSQL, and the decisions listed in `docs/handoff/m3-exit-audit.md` section 3.

### Demo

`tools/demo/run.sh` runs one test cell with synthetic people and scenes from programme set-up to a paid grant, the AI assessment, the fast-flow knock-out decision and the mailbox. `docs/handoff/presentation-walkthrough.md` is the click-through script.

### Branches

`main` holds all of M0 to M4 so far, and it is the only integration branch. Work runs in short-lived lane branches. Finished lanes merge in batches: CI runs the full suite against PostgreSQL 16, and the batch merges into `main` when it shows no new failure. Some tests are red on purpose: each waits on a seam that a named lane closes. `ci/known-red.txt` lists each one with its seam and lane, and CI fails on any other red test (`tools/test-gate`).

### Decisions

Daniel's answers are recorded in `docs/handoff/m3-design.md` section 21.0 and `docs/handoff/m4-design.md` section 15.0, and in the ADRs in `docs/adr/`. Every reading not yet decided is marked "Interim, pending Daniel" where it is built.

## Running the demo

The demo runs one test cell with synthetic data only. Sign-in uses real passkeys through the browser's own prompt. The cell sends no email: the demo page shows every message instead.

```sh
FSTP_DEMO_PORT=8640 tools/demo/run.sh start
```

Then open the demo page at `http://127.0.0.1:8641/demo`. It lists the people of the current scene with their sign-in links, every message the cell sent, and links that switch scenes. After sign-in each person lands on their home page, which links their work. `docs/handoff/m4-demo.md` gives the click paths and the journey results.

## Running it locally

The site runs on your machine only, on loopback, with synthetic data. It needs Node.js 24.11.1 with `npm ci` run once in `web/` and `e2e/`, and the Rust toolchain of `rust-toolchain.toml`.

1. Build and start it. The command compiles the pages with tsc, packs the assets, builds the test cell and seeds the scene "review stage1":

   ```sh
   tools/demo/run.sh
   ```

2. Open the front door at `http://127.0.0.1:8641/demo` in Chromium or Chrome. It names the scene, then lists each synthetic person with their role and one line on what they can do.
3. Choose "Sign in as" beside a person. Their home page opens at `http://a.fstp.localhost:8640/app/`, with no passkey. The top bar says "Demo sign-in". Use one browser profile per person, such as a new incognito window each.
4. Switch scenes from the front door, or from a terminal:

   ```sh
   tools/demo/run.sh seed review ranked
   tools/demo/run.sh seed applicant STAGE2
   tools/demo/run.sh reset
   tools/demo/run.sh advance 60
   ```

5. Stop it:

   ```sh
   tools/demo/run.sh stop
   ```

`FSTP_DEMO_PORT=<n>` moves the four listeners: the cell on `<n>`, the front door on `<n + 1>`. `FSTP_DEMO_SIGNIN=off` starts the cell as the e2e suite runs it, with passkeys only. Then the name link of each person enrols a passkey, and the person signs in with it. A name under `.localhost` is a secure context in Chromium, so passkeys work over plain HTTP.

The front door also links the public pages under `/p`, which work with scripts turned off. `docs/handoff/m4-demo.md` gives the click paths of each role.

The Playwright specs run against two stacks. `tools/demo/run.sh e2e` runs every spec of project `demo` against the running demo cell. `tools/devstack/run.sh e2e` starts the real M3 cells of `fstp-devstack e2e`, runs the six root M3 specs of project `devstack` against them, and stops the stack.

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
