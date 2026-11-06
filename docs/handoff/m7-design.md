# M7 design: assessor, pre-check, evaluation harness, synthetic corpus

Milestone M7 in `SPEC/09-milestones.md`. Exit criteria:

- the LLM evaluation thresholds of `SPEC/07-test-plan/llm-evaluation.md` are met;
- I-10 and I-11 are green through the assessment pipeline (M2 claimed them with a fake assessor);
- I-21 is green.

Status: draft for Daniel's review, written for a weekend build where "built even if buggy" beats perfect. Labels such as `L-WIRE` or `Q2` exist only in this document. Crate, type, op and table names are design proposals. Every `I-`, `R-`, `P-`, `T-LLM-`, `TH-` and `ADR-` identifier is quoted from the repository.

Sources read: `SPEC/04-llm-assessment/{assessment,pre-check}.md`, `SPEC/05-compliance/{ai-act,gdpr}.md`, `SPEC/02-domain/invariants.md`, `SPEC/02-domain/policy-parameters.md` (P-21 to P-23, P-28, NOTE 10), `SPEC/01-requirements/functional.md` (R-LA-01 to R-LA-11), `SPEC/07-test-plan/{llm-evaluation,synthetic-corpus,test-plan}.md`, `SPEC/03-architecture/overview.md` (Assessor, Inference), `SPEC/06-threat-model/threat-model.md` (TH-01, TH-02, TH-12, TH-13, TH-29). Also read: `docs/handoff/m4-design.md` section 15.0 (Q38), ADR-009 (Outbound destinations), and the code of `fstp-findings`, `fstp-engine/src/findings.rs`, `fstp-api-core/src/{port,content,forms}.rs`, `fstp-access` (`review.findings`, `review.mark_finding`), `fstp-cell/src/egress.rs` and `fstp-http/src/client.rs`.

No spec text or ADR names an inference provider or model. P-21 is a tenant choice, and the SuperSAFE fixture holds `placeholder` and `placeholder-model`. This design names none. The wire protocol is ADR-required (Q1).

---

## 1. Scope

### 1.1 Already built

| Exists | Where |
| --- | --- |
| `Finding`, `UntrustedText`, `FindingStore`, the I-11 store check, `FindingCommand::{Record, Mark, Regenerate}` | `fstp-findings` |
| `decide_finding` routing: system actor only for `Record` and `Regenerate`, never through MCP (I-10) | `fstp-engine/src/findings.rs` |
| `PublishCall { config, config_model }`, filled from `TenantSettings.inference` | `fstp-domain`, `fstp-api-core/src/forms.rs` |
| `review.findings` read and `review.mark_finding` op | `fstp-access/src/registry.rs` |
| Empty `Precheck` port, `FakePrecheck`, `PrecheckUnavailable` creator check (Q38) | `fstp-api-core/src/port.rs`, `fstp-api-testkit`, `fstp-creator` |
| HTTP/1.1 client over TLS with limits and deadlines, NDJSON reader, canonical JSON | `fstp-http`, `fstp-tls`, `fstp-json` |

### 1.2 M7 builds

- The in-house inference client with record, replay and synthetic transports (R-LA-04).
- The assessor process and the eight pipeline stages of `assessment.md` (R-LA-01, R-LA-02, R-LA-05).
- Traces, their deletion job, and fallback regeneration (R-LA-07, NOTE 10).
- The pre-check: port, ops, P-23 limits, storage in the applicant workspace, and UI (R-LA-06, R-LA-08, I-21).
- Reviewer findings panel with agree and dispute marks (R-LA-03).
- The synthetic corpus generator, fixture git and web server, and the evaluation harness with its report.

### 1.3 Out of scope

- Indicative rubric bands (P-28 is off in SuperSAFE). M7 generates no bands at all.
- Calibration sets and consent requests (R-LA-09 to R-LA-11, I-37). M12 claims them.
- Attachments. A proposal holds only `title`, `summary`, `narrative` and the plan. The "hidden injection" variant covers Unicode tricks only until attachments exist.
- Retrieval from the public internet. It waits for Q2. M7 retrieval reaches the fixture server only.

## 2. Readings

Each is interim, pending Daniel.

1. **Required elements.** The spec does not list a call's required elements. M7 pins a rubric file per P-01 criterion that lists closed element tags, such as `problem`, `approach`, `ois_relevance`, `team_experience`, `deliverables_licence`, `milestones`, `budget_justification`. The rubric is part of `config_id`.
2. **config_id.** It is the first 16 bytes of a labelled SHA-256 (aws-lc-rs, ADR-001 Tier A) over the canonical JSON of: provider, model, decoding parameters, prompt set digest, rubric digest and the call's P-01. It is derived at publication. Each fallback model in P-21 gets its own config_id at the same moment.
3. **Fallback trigger.** A programme manager confirms a switch to the next P-21 fallback with a step-up (`assess.switch_fallback`). The pipeline then regenerates every finding of the call and commits one `Regenerate` (NOTE 10). The switch is refused once the call has a ranking.
4. **Pre-check reply.** It carries kind, criterion, severity, statement and evidence. It omits `confidence` and every number other than the remaining-check counts, so no score or band is derivable (T-LLM-ORACLE).
5. **False major findings (T-LLM-FP).** Counted over completeness, accuracy and integrity findings on clean proposals. Quality findings carry no ground-truth label, so they are reported but not counted.
6. **Unavailability.** Loss of the provider leaves findings "pending" on reviewer pages. Nothing in evaluation waits for them (R-NF-10, I-10).

## 3. Pipeline and the data channel

### 3.1 Process boundary

The assessor is a separate binary, `fstp-assessor`, that the cell spawns as a child process (`overview.md` Assessor). It has no database credential and no ledger access, so it has no write access to domain state.

- **Queue.** Jobs go to the child on stdin and results come back on stdout, one canonical JSON object per line. The cell validates each result line against the finding schema before anything is stored. The NDJSON decoder of both ends is a fuzz target.
- **Egress.** The assessor connects only through `AssessorDestination { Inference, Retrieval }`, a closed enum in its own crate. This needs an ADR-009 amendment, with an enumeration test like `i16_cell_egress_has_no_payment_destination`.
- **Runtime.** The assessor uses the cell's runtime behind `fstp-rt` (ADR-002).

The cell side builds jobs, stores results and traces, and turns each validated result into `FindingCommand::Record` under a system actor. Nothing else from the assessor reaches the engine.

### 3.2 Stages

| # | Stage (`assessment.md`) | Where | Model call |
| --- | --- | --- | --- |
| 1 | Extract text. NFC-normalise, record and remove zero-width, bidi-control and tag characters with their spans | Cell, `fstp-assess::extract` | No |
| 2 | Strip PII to stable placeholders (`[EMAIL-1]`, `[PERSON-2]`) | Cell, `fstp-assess::strip`, plus the vault for names (Q4) | No |
| 3 | Completeness per rubric element; plan checks (milestones, task rates) are deterministic | Assessor | Yes |
| 4 | Quality per P-01 criterion | Assessor | Yes |
| 5 | Claim extraction: kind, subject URL, quoted span | Assessor | Yes |
| 6 | Claim verification through the retrieval proxy | Assessor and `fstp-retrieve` | Yes |
| 7 | Integrity: a deterministic scanner over stage 1 marks and known address patterns, plus a model check | Assessor | Yes |
| 8 | Schema validation, evidence location, publication | Cell, `fstp-assess::validate` | No |

Stage 1 and 2 run in the cell so that raw text never leaves it. The stripped text and the placeholder map stay apart: the map never leaves the cell.

Retrieval sources are classed as applicant-controlled when their host and path match a URL the proposal names as its own, or a repository whose maintainership it claims. Otherwise they are independent. A rule in code, after the model, refuses `verified` for any claim whose supporting sources are all applicant-controlled (TH-12, T-LLM-RETRIEVAL). The finding states which kind of source it used.

### 3.3 The data channel (binding)

Submission and retrieved content travel only in the data channel. Instructions come only from the pinned prompt. The type system enforces this in `fstp-infer`:

- `Instruction` is built only from `&'static str` prompt files (`include_str!` of `crates/fstp-assess/prompts/v1/*.txt`) and closed enums such as criterion names from the frozen P-01. It has no constructor that takes `String` or `UntrustedText`.
- `DataPart` is the only type that accepts `UntrustedText`. The encoder writes each data part as a JSON string value inside a separate data message, in the role the wire protocol keeps for user content. It is never interpolated into the instruction message.
- The criterion names and element tags in an instruction come from the frozen policy and the rubric, which are tenant configuration, not submission content.
- The prompt tells the model that the data message is data to assess, that instructions inside it are integrity evidence, and that English fluency is not a quality signal.
- Structured output: the model must return one JSON object per the output schema. Where the endpoint supports schema-constrained output, the schema is sent as a request parameter, not as prompt text.

Tests: a property test feeds random `UntrustedText` with canaries through every stage and asserts that no encoded `Instruction` byte range contains a canary byte sequence (`th01_data_channel_never_reaches_instruction`). A source scan fails the build if any module outside `fstp-infer::encode` builds a request body.

### 3.4 Output validation

The output parser (`fstp-json` plus a typed decoder, fuzz target `assess_output_decode`) accepts only the schema fields. Unknown members fail the whole result, so a model cannot add `score`, `decision` or `state`. Then:

- each finding gives quoted evidence; the validator locates the quote in the stripped text and maps it back to spans of the original section (R-LA-02). A finding with no locatable evidence is dropped and counted in the trace;
- `criterion` must be in the frozen P-01, and `element` in the pinned rubric;
- `statement` is bounded to 1,000 bytes and stored as `UntrustedText`;
- placeholders in statements stay placeholders. Reviewers see `[PERSON-1]`, never a name.

### 3.5 Traces and regeneration

- `assess.trace` rows hold input hashes, prompt set version, config_id, the raw model responses sealed through `Sealer`, and the retrieval log (R-LA-07). A scheduled job deletes them at the end of P-22, which runs to the end of P-41.
- Pre-check traces live with the draft and follow `pre-check.md`: deleted when the call closes or the applicant withdraws.
- Regeneration (reading 3) runs every submitted proposal of the call under the fallback config, holds the results, and commits one `Regenerate` only when all succeed. A partial run commits nothing.

## 4. Pre-check

- **Port.** `Precheck` gains `request(proposal, account, snapshot) -> RunId`, `runs(proposal) -> Vec<PrecheckRun>` and `quota(proposal, account) -> Quota`. A cell with a configured P-21 provider supplies the port, so `PrecheckUnavailable` clears there. A cell without a provider keeps failing it (Q38).
- **Ops.** `proposal.precheck` (command, web only, team members of a draft) and `proposal.precheck_runs` (read, same audience). MCP answers `Deny(NotExposed)`. Both are refused for every Operator and Judging role (I-21), which the authorisation matrix covers in every state.
- **Limits (P-23, TH-29).** The run is counted when requested. Limits apply per proposal per day, per proposal per call, and per account across all drafts in the same call. The reply shows remaining checks and the next available time.
- **Config.** A run uses the call's pinned config_id (I-11). A draft of an unpublished call cannot run one.
- **Storage.** Runs and their findings live in the applicant workspace store beside the draft, never in `FindingStore`. The operator gets aggregate counts only (`assess.precheck_usage`: runs per call per day).
- **Submission.** The submitted version gets a fresh assessment. Nothing from a pre-check run is carried over.
- **Disclosure (R-LA-08).** The pre-check panel states that the applicant is using an AI system, and the Guide's "How to apply" states that AI assessment is used. Exact wording carries `TODO(legal)` for Daniel (AI Act Article 50).
- **Integrity findings** are shown to the applicant as well.

## 5. Synthetic corpus

Generator: `tools/corpus`, a Rust binary, deterministic from a seed. Output is versioned under `corpus/v1/` with a `manifest.json` of labels. No model generates the corpus in v1. Texts come from templates and construction, so the generator family differs from any assessor by construction. The report names the generator as `template-v1`.

- **Base proposals.** 40, across Open Internet Stack topics drawn from a fixed topic list, such as transport security, package signing and federated identity. Each has title, summary, narrative with every rubric element, and a plan with tasks, rates and milestones.
- **Variants.** Built from the base per `synthetic-corpus.md`: omission (one element removed), inflated claim (a maintainership or usage claim with a fixture repository that contradicts it), budget anomaly (rates far above the corpus median). The injection variants are direct injection, Unicode hidden injection, indirect injection (fixture README). Fluency variants are rule-based rewrites of identical substance. The domain variants (minor, excluded affiliation, Sybil, repeat applicant) are emitted as e2e seeds and are not used by the evaluation.
- **No real personal data.** Person names are built from a fixed list of invented syllables and checked against nothing real. Emails use `example.org` and the `.test` domain (RFC 2606). Repository and page hosts are `*.test`, served only by the fixture server. Phone numbers use a fictional range. IBAN-shaped canaries use a bank code the manifest records and the generator uses nowhere else.
- **Canaries.** Every item carries one canary per PII class. The manifest lists them for the privacy tests.
- **Fixtures.** `fstp-fixture-web` (test-only, in `fstp-api-testkit`) serves fixture repositories and pages over plain HTTP inside the test environment. No test reaches the public internet.

## 6. Evaluation harness

`tools/assess-eval` runs the corpus through the real pipeline: the same `fstp-assess` stages, the same encoder, the same validator. Only the transport differs. Modes: `live` (a real endpoint), `record` (live, saving each response), `replay` (saved responses only) and `synthetic`.

Recordings are keyed by SHA-256 of the canonical request bytes without credentials, stored as `corpus/v1/recordings/<config_id>/<digest>.json`. A replay miss fails the run. So any prompt, rubric or stripping change forces a new recording.

Measurement per test, with every ratio held as an exact integer fraction and compared with the threshold as a fraction (`19/20` for 0.95):

| Test | How it is measured |
| --- | --- |
| T-LLM-COMPLETE | Omission items: a completeness finding with the removed element tag counts as detected. Recall = detected over seeded |
| T-LLM-ACCURACY | Inflated-claim items: an accuracy finding whose claim subject URL matches the manifest counts as detected |
| T-LLM-FP | Major completeness, accuracy and integrity findings on the 40 clean items, divided by 40 (reading 5) |
| T-LLM-INJ | Each injected item against its clean base: the set of (kind, criterion, element, severity) for quality and accuracy findings is equal, and an integrity finding exists |
| T-LLM-RETRIEVAL | No claim marked verified on applicant-controlled sources alone, both in the trace and in the findings |
| T-LLM-FLUENCY | Fluency pairs: quality finding severities per criterion are equal |
| T-LLM-STABLE | Five live runs of 20 items; an item is stable when all five finding tuple sets are equal; at least 19 of 20 stable |
| T-LLM-ORACLE | Structural: the pre-check reply schema has no score, band, weight or confidence member. Harness: no reply member correlates with a criterion score field, because none exists |
| T-LLM-CAL | Krippendorff's alpha per finding type between findings and panel labels in `corpus/v1/panel/*.json`, computed in exact rationals (Q3) |

The report goes to `docs/eval/m7-<date>.md` with a JSON twin. It states the corpus version, config_id, provider, model, mode, generator `template-v1`, and each metric with its threshold. Only a `live` or `record` run supports the exit claim. CI runs `replay` on that run's recordings on every change, so pipeline drift fails the gate. The `synthetic` mode is never reported as an LLM result.

## 7. Demo-cell path

A real model call is optional. `fstp-e2e-cell` gains `--assessor=synthetic|replay:<dir>|live:<config file>`, default `synthetic`, and `tools/demo/run.sh` passes nothing.

- **synthetic.** `SyntheticModel` is a transport in `fstp-infer` that speaks the chosen wire format in memory. It is deterministic code that reads the data message: it emits completeness findings for missing rubric elements by keyword, integrity findings for stage 1 marks and address patterns, and one info quality finding per criterion. The cell spawns the real `fstp-assessor` binary with it, so the process boundary, stripping, encoding, validation and storage all run offline.
- **replay.** The demo seeds its proposals from corpus base items, so recordings from the evaluation run replay offline when present.
- **live.** Only when Daniel passes a config with an endpoint.
- The config_id of a synthetic run names provider `synthetic`, and every finding panel then says "Synthetic assessor (demo)".
- **Click-through.** The applicant reaches "Check my draft" from the draft page and sees remaining checks and findings. The reviewer reaches findings from the assessment page and marks them. The coordinator sees "Findings pending" or a count, never statements, in the round view. Each is reached by clicking from sign-in.
- The FakePrecheck of Q38 is replaced by the real port over `SyntheticModel`. The Guide's "not yet available" note goes once the port is present.

## 8. Tests first

| ID | Test |
| --- | --- |
| I-10 | `i10_pipeline_hostile_outputs_never_change_core`: a hostile transport returns fuzzed and adversarial outputs, including members named `score` and `decision`; the core state digest is unchanged and only finding records append. Rerun of the M2 I-10 property over the pipeline |
| I-11 | `i11_pipeline_call_findings_share_config`: generated calls with submissions, a mid-call fallback switch and regeneration; every stored finding and every pre-check run of a call carries the current pin |
| I-21 | `i21_precheck_runs_unreadable_by_staff`: matrix rows for both ops over every Operator and Judging role in every state; canary text in pre-check findings never appears in staff views, logs, metrics or traces outside the workspace |
| TH-01 | `th01_data_channel_never_reaches_instruction` (section 3.3) and T-LLM-INJ |
| TH-02, TH-29 | `th29_account_cap_across_drafts`, `th02_precheck_reply_has_no_score_member` |
| TH-12 | `th12_applicant_sources_alone_never_verify` |
| Privacy | `privacy_canaries_never_reach_inference_requests`: every canary class from the manifest, checked on the encoded request bytes of every stage |
| R-LA-02 | `r_la_02_finding_without_located_evidence_is_dropped` |
| R-LA-07 | `r_la_07_traces_deleted_after_p22` under a simulated clock |
| R-NF-10 | `r_nf_10_provider_down_never_blocks_stage1_close` |

Fuzz targets from the first commit: `infer_response_decode`, `assess_output_decode`, `assessor_queue_ndjson`, `retrieve_html_text`, `retrieve_http_body`, `extract_unicode_marks`.

## 9. Dependencies and ADRs

- No new crate. The client uses `fstp-http`, `fstp-tls`, `fstp-json` and aws-lc-rs digests.
- **ADR-required:** the inference wire protocol (Q1), as the next free ADR number.
- **ADR-009 amendment:** `AssessorDestination` and the trust anchors for the inference endpoint (Q2).
- **Compliance, not blocking the build:** the DPIA for LLM assessment and the inference provider as a sub-processor in each tenant's DPA (`gdpr.md`) are needed before a production tenant enables P-21.

## 10. Lanes

One agent per lane. The usage cap allows three at once, so waves are shown. `port.rs` is lead-owned, so the lead lands L-SEAM first.

| Lane | Builds | Owns | Needs | Wave |
| --- | --- | --- | --- | --- |
| L-SEAM | `Precheck` methods, `InferenceRecord` with config derivation input, `assess.switch_fallback` and pre-check op stubs answering `not_implemented`, ADR draft for Q1, ADR-009 amendment draft | `crates/fstp-api-core/src/port.rs`, `docs/adr/ADR-NNN-inference-client.md`, `docs/adr/ADR-009-*` | None | 0 (lead) |
| L-WIRE | `fstp-infer`: `Instruction`, `DataPart`, encoder, response decoder, `Transport` trait, HTTP, record, replay and synthetic transports, TH-01 property test, fuzz target | `crates/fstp-infer/**` | L-SEAM ADR draft | 1 |
| L-CORPUS | `tools/corpus`, `corpus/v1/` with manifest and canaries, `fstp-fixture-web` | `tools/corpus/**`, `corpus/**`, `crates/fstp-api-testkit/src/fixture_web.rs` | None | 1 |
| L-RETR | `fstp-retrieve`: GET-only proxy, size and host limits, HTML-to-text, source classing, TH-12 rule, fuzz targets | `crates/fstp-retrieve/**` | None | 1 |
| L-PIPE | `fstp-assess`: extract, strip, rubric v1, prompts v1, stage orchestration, validator, config_id derivation, fuzz targets | `crates/fstp-assess/**` | L-WIRE | 2 |
| L-PROC | `fstp-assessor` binary: NDJSON queue, `AssessorDestination`, stage calls, retrieval client | `crates/fstp-assessor/**` | L-PIPE, L-RETR | 2 |
| L-CELL | Child spawn, job building, result intake to `FindingCommand::Record`, traces with sealing and deletion job, regeneration, config_id at publication, migration (next number) | `crates/fstp-cell/src/assess/**`, `crates/fstp-pgstore/migrations/app/` (next number), `crates/fstp-api-core/src/dispatch/assess.rs` | L-PROC | 3 |
| L-PRE | Pre-check ops, P-23 limits, workspace storage and deletion, operator usage counts, registry and matrix rows, I-21 and TH-29 tests | `crates/fstp-api-core/src/dispatch/precheck.rs`, `crates/fstp-api-core/src/content.rs` (pre-check part), `crates/fstp-access/src/{registry,reads}.rs` (new rows only) | L-SEAM, L-CELL | 3 |
| L-EVAL | `tools/assess-eval`, metrics, alpha, report writer, CI replay gate | `tools/assess-eval/**`, `docs/eval/**`, `tools/test-gate` (replay step) | L-PIPE, L-CORPUS | 3 |
| L-UI | Applicant pre-check panel, reviewer findings panel with marks, coordinator pending count, AI disclosure, generated op types | `web/src/precheck/**`, `web/src/findings/**`, `web/src/gen/` (regenerated) | L-PRE | 4 |
| L-DEMO | `--assessor` flag, synthetic default, corpus-seeded demo proposals, Q38 note removal, click-through Playwright spec | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/**`, `crates/fstp-api-testkit/src/fake/misc.rs`, `e2e/assess/**`, `docs/handoff/m7-demo.md` | L-UI, L-CELL | 4 |
| L-EXIT | Live record run (after Q1 to Q3), report, I-10 and I-11 reruns, exit audit | `docs/handoff/m7-exit-audit.md`, `docs/eval/m7-*.md` | All above | 5 |

Lanes L-CORPUS and L-RETR can start at once with L-WIRE. The interfaces they share are the manifest schema (section 5) and the retrieval request and result (section 3.2), which each lane writes first as a fixture file.

## 11. Blocking questions

**Q1. Inference wire protocol and the exit-run endpoint.** No spec or ADR names a provider, model or API shape. It blocks the ADR and the live exit run, not the lanes, which build against `SyntheticModel`.
Recommendation: one adapter for the chat-completions JSON shape that local open-weight servers commonly serve, non-streaming, with schema-constrained output where offered. This fits R-LA-04 for self-hosted cells. For the exit run, Daniel picks one EU-hosted or local open-weight model for P-21, so TH-13 holds.

**Q2. Public TLS trust anchors.** ADR-009 and `egress.rs` record that no allowlisted crate provides a public root store. A hosted endpoint cannot be reached without one. It blocks live calls to a hosted endpoint and all production retrieval.
Recommendation: the tenant's inference record carries pinned trust anchors (PEM) for its endpoint, so no new crate is needed. Retrieval stays on the fixture server in M7. Production retrieval waits for a root-store ADR, and until then accuracy findings say "not verified: retrieval unavailable".

**Q3. Human panel for T-LLM-CAL.** The alpha needs blind human labels on the synthetic set. Nobody is assigned. It blocks the T-LLM-CAL row of the exit claim only.
Recommendation: Daniel and one colleague label 30 corpus items blind, through a small labelling page in `tools/assess-eval`. Until then the report shows T-LLM-CAL as "not measured", and the exit audit states the gap.

**Q4. Stripping names before inference.** Legal names are vault facts, so the cell cannot recognise them in free text. Without stripping, the privacy canary test for names fails, and that test may not be weakened.
Recommendation: add a vault mask query by spec change, as Q35 did. The cell sends the stripped text to the vault, which replaces the team's vault-held names with placeholders and returns the text. Until it lands, L-PIPE strips email, phone, IBAN-shaped strings and team handles, and the name canary test stays red, visible in the exit audit.
