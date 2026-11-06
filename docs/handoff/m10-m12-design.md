# M10 to M12 design: hardening, pilot and calibration

Milestones M10, M11 and M12 in `SPEC/09-milestones.md`:

- M10: hardening on a Mythos-tier model. Exit criteria in `SPEC/08-hardening/hardening-plan.md`.
- M11: pilot with SuperSAFE as first tenant and a second programme to validate configurability. Exit: first live call completed with no invariant violations.
- M12: calibration with consented real proposals. Exit: metrics reported per corpus, I-37 green.

Status: draft for Daniel's review, written 2026-11-06 for the weekend build before Brussels. Labels such as `L10-SBOM` or `Q1` exist only in this document. Every `I-`, `R-`, `H-`, `TH-`, `P-` and `ADR-` identifier is quoted from the repository. Crate, file and command names are design proposals.

Sources read: `SPEC/09-milestones.md`, `08-hardening/hardening-plan.md`, `05-compliance/{cra,ai-act,gdpr}.md`, `06-threat-model/threat-model.md`, `02-domain/invariants.md` (I-37, I-74, I-75, I-90), `03-architecture/{overview,self-hosted-services}.md`, `07-test-plan/{test-plan,llm-evaluation}.md`, `04-llm-assessment/assessment.md`, `01-requirements/functional.md` (R-LA-09 to R-LA-11), ADR-001 (A5), ADR-003, ADR-005, ADR-011, `tools/fuzz-all.sh`, `tools/demo/run.sh`, `tools/devstack/run.sh`, `.github/workflows/ci.yml` and `README.md` status.

---

## 0. The honest summary

All three milestones end in something that code cannot produce on its own:

- M10 ends with a Mythos-tier model run over a finished system, and with recorded Tier B confirmations (I-74).
- M11 ends with a real call run to completion with real applicants. A call spans weeks of submission, evaluation and contracting.
- M12 ends with metrics over real proposals whose applicants consented after their outcome notice. None exist until M11 produces them.

So this weekend builds the tooling, the gates and the synthetic rehearsals for each milestone. No milestone exit can be claimed this weekend. The exit report should say exactly that.

Two dependencies sit further upstream:

- M10 entry needs M1 to M6 closed. M3 and M4 are open, M5 is in build, and M6 and M7 are not started (`README.md`).
- Production writes are refused until moduletto has ML-DSA-65 (M3 NOTE 2). No real call can run in production before that pull request lands and its pin gets an I-74 confirmation.

---

## 1. M10: hardening

### 1.1 What exists

- `tools/fuzz-all.sh` runs every cargo-fuzz target. CI runs each for 60 seconds (`fuzz smoke`). There are about 150 targets.
- `deps-check` enforces the allowlist, the no-Python rule, fuzz targets per parser and layering. `deps-check --release` already fails on an unconfirmed Tier B version (ADR-001 A5, tests `i74_*`).
- `deps/tier-b-confirmations.txt` exists, with its parser fuzzed (`tier_b_confirmations_decode`). It holds no confirmation.
- `tools/deps-check/src/report.rs` renders a machine-readable report "for the release SBOM". No SBOM file is produced yet.
- No CI job runs on a release tag.

### 1.2 Code and CI this weekend

| Item | What gets built | Plan row |
| --- | --- | --- |
| Long fuzz campaigns | A scheduled workflow running `fuzz-all.sh` for 600 s per target, plain git checkout, no third-party actions, as in `ci.yml`. A triage script turns a crash artefact into a committed seed and a named regression test | H-05, TH-26 |
| SBOM | An in-house emitter in `deps-check` that writes the resolved tree of each shipped binary. Runtime and build-time components are separated, and Node.js and npm are listed as build-time (ADR-003) | R-NF-07, TH-15, H-10 |
| Release checks | A tag-triggered workflow: `deps-check --release`, SBOM, full test run, fuzz smoke, and the hardening evidence bundle. It fails today on moduletto, which is correct | I-74, H-10, H-18 |
| Threat traceability | A tool that reads the TH tables and the H activity table, then scans tests for `TH-`, `T-` and the mitigating `I-` IDs. It reports each threat with no test. Development builds report; `--release` fails | Test plan principle, TH-01 to TH-68 |
| Missing threat tests | Tests for built surfaces with no traced test. A first scan found no test names citing T-BREAKGLASS, T-MC-* or T-AU-*. Some may exist under `I-` names; the tool settles that | TH-18, TH-55 to TH-57, TH-60 to TH-66 |
| Findings register | A typed file of findings with severity, state, H row and regression test name. A check fails if a closed finding names a test that does not exist | Rules section of the plan |
| I-74 record helper | A `deps-check tier-b-template` command. It prints crate, exact version and source hash for each Tier B package in the release tree, with the date and findings reference left blank | I-74, H-18 |
| Evidence bundle | One directory per release: SBOM, fuzz stats, traceability report, findings register, `deps-check --release` output | CRA technical documentation (`cra.md`) |

Rules kept:

- The release workflow is never made to pass by editing `deps/tier-b-confirmations.txt`. Only a real Mythos-tier review fills a row.
- Each new parser (findings register, threat tables) gets a fuzz target in its first commit.
- The CRA vulnerability disclosure policy text is not written here. TODO(legal): Daniel to supply the published vulnerability handling and reporting text that `cra.md` requires from the first release.

### 1.3 What needs the Mythos-tier run

These are the plan's activities themselves. Code can prepare entry points, but it cannot perform them:

- H-01 to H-10, H-13 to H-16, H-18, H-19 and H-21 to H-23: adversarial review of the built system.
- H-03 and H-04 need the M7 assessor and pre-check, which do not exist yet.
- H-18 is the I-74 confirmation. It waits for the final moduletto pin, which moves again when the ML-DSA-65 pull request merges (ADR-001).
- Out of scope while deferred: H-11 (B-06), H-12 (B-05, B-03), H-20 (B-04), most of H-17 (B-07 to B-09) and the bank execution part of H-14 (B-11).

The plan asks to record the model tier before scoping. That is Q1.

### 1.4 Exit criteria status after the weekend

| Exit criterion | After the weekend |
| --- | --- |
| No open critical or high findings | Not claimable. No Mythos-tier run has happened |
| Every Tier B version has a recorded confirmation (I-74) | Not claimable. The gate exists and fails correctly |
| All regression tests merged and green | The register check exists. The register is empty |
| Hardening report available | The evidence bundle exists. The report needs the run's findings |

---

## 2. M11: pilot

### 2.1 Pilot-readiness code this weekend

| Item | What gets built |
| --- | --- |
| Tenant provisioning runbook as scripts | `tools/pilot/provision-tenant.sh` drives `fstp-control` provisioning: cell databases, role plan, `pg_hba`, grants and first-admin enrolment (ADR-011). It runs end to end against the devstack only. Each step prints what it did and is idempotent |
| Deployment scripts | Host bootstrap and service units for the ADR-005 topology: `application`, `vault` and `witness` clusters self-operated, `control` managed. Input is an inventory file. Tested against local hosts only |
| Second synthetic programme | A fictional programme fixture, `harbour.programme.json`, built through the creator. It differs from SuperSAFE on as many policy parameters as the creator allows: stage count, scoring scale, thresholds, SoD settings, P-42 and the vocabulary pack. A test lists each difference and shows both compile and run |
| Invariant checker | `fstp-invcheck` reads a cell's record store and audit chain after a run. It replays them and checks every invariant that can be checked post hoc, extending the M2 replay verifier. Its output is the evidence for "no invariant violations" |
| Live-call dry run on the demo cell | `tools/pilot/dry-run.sh` seeds two cells, one per programme, and drives a full call with Playwright and `run.sh advance`. It then runs `fstp-invcheck` on both. It stops at PAID once M5 merges, else at NEGOTIATION |

The dry run is a rehearsal on a test cell with synthetic data (layering rule A9). It is not the pilot and does not count toward the M11 exit.

### 2.2 What the real pilot needs, and why not this weekend

- **Hosting.** OVHcloud is named, but verify items V1 to V11 are open, and L-15 is open. R-HS-01 is not claimed. TODO(legal): L-15, contracting entity and sub-processor terms.
- **Production writes.** Refused until moduletto ML-DSA-65 lands (M3 NOTE 2), then gated by I-74 at release.
- **Release-window interim.** Under ADR-008's interim, no production proposal passes IRC_REVIEW to NEGOTIATION.
- **Notices.** Email dispatch is M6, not started. Applicants need their outcome notices.
- **Assessor.** If SuperSAFE uses findings, M7 must exist first.
- **Calendar.** A live call needs a published call, real applicants and real evaluation time. A weekend cannot compress that.
- **Legal.** Tenant DPA, applicant information and AI disclosure text (R-LA-08). TODO(legal) for each.

---

## 3. M12: calibration

### 3.1 What runs on synthetic data now

| Item | What gets built |
| --- | --- |
| I-37 property tests first | Generated sequences of outcome notices, consent requests, consents, revocations and calibration runs. Two properties: every set member had unrevoked consent when the set was built; no consent request precedes the proposal's outcome notice. Written before the code |
| Consent domain | Commands to request, give and revoke calibration consent (R-LA-09, R-LA-10). A request is refused unless P-42 is on and the proposal's outcome notice record is already committed. The request must carry a strictly later sequence than that record |
| Consent page | The applicant sees the request on their outcome page only, and can revoke later. The consent wording is a placeholder. TODO(legal): consent text and the legal basis for pseudonymised use |
| Calibration set builder | Selects proposals with unrevoked consent at build time, pseudonymises them as for reviewer views, and writes a manifest naming each consent record. A later revocation excludes the proposal from every later run (R-LA-10) |
| Per-corpus metrics | In-house Krippendorff's alpha and the T-LLM-* measures, each labelled with its corpus (`synthetic` or `consented`). Reports refuse to mix corpora in one figure (`llm-evaluation.md`). Inputs are findings plus human marks, so it runs on fixtures without the assessor |

Scope kept: use within the tenant only. Use beyond the tenant needs tenant agreement and a separate consent (R-LA-11), which is not built.

Reading on "outcome notice": the stricter reading is used. The committed notice record in the cell counts, not an earlier state change. Once M6 dispatches email, the request also waits for the notice's dispatch record.

### 3.2 What needs the real consented corpus

- Real proposals exist only after the M11 pilot reaches outcome notices.
- Consent cannot be requested earlier, by I-37 itself.
- Meaningful assessor metrics need the M7 assessor and its evaluation harness.
- So "metrics reported per corpus" can be shown this weekend for the synthetic corpus only. I-37 can be green at domain and pipeline level on synthetic data. The milestone exit needs both on the consented corpus.

---

## 4. Lanes

At most three lanes run at once (medium mode), and the M5 lanes already hold slots. Each lane owns its files and starts when its dependencies have merged into `main`. Priority 1 lanes give Brussels something visible.

| Lane | Builds | Owns | Needs | Priority |
| --- | --- | --- | --- | --- |
| L10-SBOM | SBOM emitter, format recorded in ADR-003 (Q2) | `tools/deps-check/src/sbom.rs`, its tests | none | 1 |
| L10-REL | Release workflow and evidence bundle | `.github/workflows/release.yml`, `tools/release/` | L10-SBOM, L10-TRACE, L10-FIND | 2 |
| L10-FUZZ | Scheduled long fuzz campaign and crash triage | `.github/workflows/fuzz-campaign.yml`, `tools/fuzz-triage.sh` | none | 2 |
| L10-TRACE | Threat traceability tool with fuzz target | `tools/threat-trace/` (new crate and fuzz project) | none | 1 |
| L10-THTEST | Missing threat tests for built surfaces | New test files only, named per TH and I ID | L10-TRACE | 3 |
| L10-FIND | Findings register, its check and fuzz target, `tier-b-template` | `tools/deps-check/src/findings.rs`, `tools/deps-check/src/tier_b_template.rs`, `docs/hardening/findings.tsv` | none | 2 |
| L11-PROV | Provisioning and deployment scripts, devstack-tested | `tools/pilot/provision-tenant.sh`, `tools/deploy/` | none | 2 |
| L11-PROG2 | Second synthetic programme and its tests | `crates/fstp-programme/fixtures/harbour.programme.json`, `crates/fstp-programme/tests/m11_second_programme.rs`, `e2e/tests/m11-second-programme.spec.ts` | none (creator on `main`) | 1 |
| L11-INVCHECK | Post-hoc invariant checker | `crates/fstp-invcheck/` (new) | none | 1 |
| L11-DRYRUN | Live-call dry run on the demo cell, two programmes | `tools/pilot/dry-run.sh`, `e2e/tests/m11-dry-run.spec.ts` | L11-PROG2, L11-INVCHECK; M5 lanes for PAID | 1 |
| L12-I37 | I-37 property tests, then the consent domain | `crates/fstp-domain/src/calibration.rs`, `crates/fstp-domain/tests/i37_*.rs`, the new command variants | the M5 domain lane (`m5dom`) merged, since both touch `command.rs` | 1 |
| L12-UI | Consent ops and applicant page, TODO(legal) text | consent ops in `fstp-access` registry, `web/src/applicant/consent.ts` | L12-I37 | 2 |
| L12-SET | Calibration set builder and manifest | `crates/fstp-calib/src/set.rs` (new crate) | L12-I37 | 2 |
| L12-METRICS | Per-corpus metrics and in-house alpha | `crates/fstp-calib/src/metrics.rs`, synthetic fixtures | none | 3 |

L12-SET and L12-METRICS share the new crate. L12-METRICS creates it, or the two run in sequence.

Suggested first wave of three: L11-PROG2, L11-INVCHECK, L10-TRACE. Then L11-DRYRUN, L12-I37 (once `m5dom` merges) and L10-SBOM.

---

## 5. Open questions that block

**Q1. Which Mythos-tier model runs M10, and when?** The plan requires recording it before scoping. Claude Fable 5.1 carries safeguards that may limit offensive testing; Claude Mythos 5.1 does not. Blocks the M10 exit, not the lanes.
Recommendation: Claude Mythos 5.1. Schedule the run once M6 closes and the moduletto ML-DSA-65 pin is final, so H-18 confirms the version that ships.

**Q2. Which SBOM format?** R-NF-07 asks for a machine-readable SBOM without naming one. The format becomes a public commitment per release. Blocks the L10-SBOM merge, not its start.
Recommendation: CycloneDX JSON, written in-house, recorded as a short ADR-003 amendment.

**Q3. Does a synthetic second programme satisfy "a second programme to validate configurability"?** M11 could mean a second real tenant. Blocks the M11 exit claim only.
Recommendation: the synthetic programme proves configurability now. A second real programme joins the pilot when one is available, and the exit report names which was used.
