# EU FSTP platform

A multi-tenant platform for running Financial Support to Third Parties (FSTP) programmes: periodic open calls, staged evaluation, independent review, grant agreements and milestone payments. The reference process is the SuperSAFE Annexe FSTP (call HORIZON-CL4-2026-04-DATA-02). Other programmes run the same process with their own policy parameters.

CrabNebula Ltd operates the hosted service. The same codebase also builds a self-hosted single-tenant deployment.

## Status

Status on 2026-11-16, from CI run 43853477946 on 9acb87d1 while its workspace part still runs. Built milestone by milestone, as `SPEC/09-milestones.md` sets out. Several milestones were built in parallel so the whole process could be shown end to end. A milestone closes only when its exit criteria pass in CI. M0 to M2 are closed. M3 to M6 and M9 are built, and every part of CI that decides them has passed except the workspace part and the MCP matrix. Both are described below.

| Milestone | Content | Built | Exit criteria |
| --- | --- | --- | --- |
| M0 | Specification freeze for v1 | Done | Closed |
| M1 | Rust foundations: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Done | Closed |
| M2 | Domain core: state machine, policy engine, separation of duties, scoring | Done | Closed at domain level |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | Built, including backups, recovery with the I-79 evidence record, break-glass, and cell erasure for production: witness revocation, one batch approval per operator, sign keys in `fstp-keyd`, and route tables that remote edges poll. All 22 devstack browser specs pass | Not closed yet. The isolation part passed on 9acb87d1, including `t_iso_i20` and the I-80 memory scans. The workspace part decides the rest. See `docs/handoff/m3-exit-audit.md` |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server, public research tools, and the journey UI | Built. Since 2026-11-13, also built: the setup gate (ADR-021), "Create a programme" (the wizard) and the Programme editor, the I-67 override (ADR-022), the coordinator unmask (ADR-023), the audit log, the page gate (SA-09), team and member pages with display names (SA-11), set-up by tenant admins (SA-12) and field help (SA-13) | Not closed yet. On 9acb87d1: I-66 and I-67 with the M-ACTIVATE checks, the api-testkit part, all 479 demo browser specs and all 4 HTTP matrix shards passed. The direct matrix shards still run. The 8 MCP shards failed on one case: with P-75 off, MCP refuses `review.read_content` and the web reads, as change D6 decides. The parity rule now admits exactly that case (a4d85be2). It needs one manual matrix run to confirm |
| M5 | Contracts and payment requests in record-only mode, grant completion, funder reports | Built, plus the P-41 retention reminder and the erasures page | The cycle reaches PAID in the demo. The I-30 to I-33 tests run in the workspace part, which decides the milestone |
| M6 | Timeline engine, dispatcher, email, and the in-app mailbox | Built | The I-25 to I-27 tests, including the crash-injection tests, run in the workspace part, which decides the milestone |
| M7 | Assessor, pre-check, evaluation harness, synthetic corpus | Built | The I-10, I-11 and I-21 tests exist. No evaluation run against a live model has been reported, so the thresholds are not yet met |
| M8 | Matrix and WhatsApp | Deferred (B-03, B-05) | None while deferred |
| M9 | ML-DSA-65 and composite signatures, branding, terminology, public transparency pages, funder profiles, SBOM | Built, plus P-57 reporting periods, the P-79 milestone opt-in, tenant copies of funder profiles, the programme footer in `/app/`, operator rotation of the notice key, and funder profile reads for all programme staff | The workspace part decides the milestone. `docs/handoff/m9-exit-audit.md` maps each invariant to its tests. I-74 stays open until the Mythos confirmation |
| M10 | Hardening on a Mythos-tier model | Not started | Daniel decided on 2026-11-15 to run it on Claude Mythos 5.2 once phase 1 development is done. Design in `docs/handoff/m10-m12-design.md` |
| M11 | Pilot with SuperSAFE and a second programme | Not started | Waits on the parties' approval |
| M12 | Calibration with consented real proposals | Consent records and per-corpus metrics (`fstp-calib`) only | Needs real consented proposals |

CI run 43853477946 on 9acb87d1 (2026-11-16) has passed these parts so far: deps-check, fmt and clippy, fuzz smoke, the web tests, the SBOM job, the demo browser suite (479 specs), and the api-testkit, domain-testkit, devstack, isolation and M-ACTIVATE parts. All 4 HTTP matrix shards passed, and 5 of the 12 direct matrix shards have passed so far. The MCP matrix failed only on the D6 case in the M4 row. The workspace part was still running when this was written.

The previous run (a0e126cc) also failed two workspace tests and one browser spec. All three were races in the tests, not product faults, and are fixed on `main` (04bd3264, 7f152b69, 9acb87d1).

`ci/known-red.txt` is empty. It listed 16 tests on the morning of 2026-11-15, and 79 on 2026-11-13.

CI runs the tests in two tiers (Daniel, 2026-11-16). The light tier runs on every push and pull request. It skips the direct, HTTP and MCP authorisation matrices and the teeth tests (tests named `*_teeth_*`, each of which plants a known bug and proves a check catches it). It also caps every property test at 32 cases. A test whose case count is part of a stated claim keeps its minimum, such as the 1000 inputs of the I-90 claim run. The per-operation agreement tests of the api-testkit part still run. The full tier runs everything at full size: the matrices, every teeth test and every property at its own case count, in about three hours. A milestone closes, and a release ships, only on a green full run. To start one, open Actions, choose the workflow "ci", click "Run workflow", tick `full` and run it on the branch.

### M3: what is open

Built: the cell runtime with its routes, engine, record store and signing; the control plane with its run loops, operator login and cell link; `fstp-pgagent`, which applies the role plan; signup, passkeys, magic links, step-up and recovery; the login email index; the identity vault with its audit chain; the witness with a local file store for self-hosted cells; key custody through `fstp-keyd`; backups sealed with the hybrid KEM; cell erasure; and a test world that runs the call cycle from signup to GRANTED over HTTP. ML-DSA-65 comes from moduletto and runs in CI with its ACVP vectors.

Open:

- The workspace part of the current CI run.
- Production gaps recorded in `docs/handoff/m3-exit-audit.md` section 8. The production `fstp-cell` does not yet serve `/app/` or host the API core. The cell does not yet send `NegotiationOpened` to its vault. `Workspaces` has no PostgreSQL port yet.

### Demo

`tools/demo/run.sh` runs one test cell with synthetic people and scenes from programme set-up to a paid grant, the AI assessment, the fast-flow knock-out decision and the mailbox. `docs/handoff/presentation-walkthrough.md` is the click-through script. A page the signed-in person may not open, or one that does not exist, sends the browser home (SA-09).

### Branches

`main` holds all work so far, and it is the only integration branch. Work runs in short-lived lane branches, each merged after its own checks pass, then confirmed by the full CI run. Some tests are red on purpose. `ci/known-red.txt` lists each one with its reason, and CI fails on any other red test (`tools/test-gate`).

### Decisions

Daniel's answers are recorded in these places:
- `docs/handoff/m3-design.md` section 21.0 and `docs/handoff/m4-design.md` section 15.0, plus the decision tables at the end of `m4-design.md`;
- the ADRs in `docs/adr/`;
- the spec amendments SA-01 to SA-13 in `docs/design/spec-amendments.md`;
- `docs/handoff/session-handoff-2026-11-15.md`.

Every reading not yet decided is marked "Interim, pending Daniel" where it is built. Legal text is never written in: each place that needs it carries `TODO(legal)`.

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
