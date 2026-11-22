# ADR-035: Injection scan, neutralised view and integrity hold

Status: Proposed. Drafted 2026-11-22 by lane L30 (`prod/injection-scan`, from `prod/mcp-assessment`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one. ADR-032 is lane L25's, ADR-033 lane L28's and ADR-034 lane L29's, each on its own branch.

## Context

Daniel, 2026-11-22, verbatim: "We must also make sure that there is no prompt injection in the submission, so that is an essential additional safeguard both for the human operator and additional systems."

He decided the reaction on the same day: "Flag, neutralise, hold AI". A detection records an integrity finding that reviewers see and that the applicant sees at pre-check. Hidden characters are stripped and flagged passages are marked in everything agents receive. AI assessment of the proposal waits until the coordinator has looked at the flag and released it. A heuristic never rejects a submission.

Sources read for this record: `SPEC/06-threat-model/threat-model.md` (TH-01, TH-02, TH-47, TH-60), `SPEC/04-llm-assessment/assessment.md` (step 7 and the integrity findings), `SPEC/04-llm-assessment/pre-check.md`, `SPEC/07-test-plan/llm-evaluation.md` (T-LLM-INJ), `SPEC/03-architecture/mcp-server.md` (Untrusted content), `SPEC/03-architecture/authentication.md` (high-risk actions), I-03, I-10, I-11, I-21, I-85, R-LA-01 to R-LA-08, R-NF-02, ADR-013 ("Results"), ADR-029 and ADR-033.

## Spec check

No invariant or SPEC rule forbids the design below. The rules that bear on it:

| Rule | How it is met |
| --- | --- |
| I-10: findings never cause a state transition, score or decision | The scan never refuses a submission and never changes its state. The hold gates only the AI assessment, which is advisory anyway. The release is a finding record, never a core record |
| TH-01: data channel separation, integrity findings, no assessor write access | The scanner is deterministic code in the cell. It runs before any model or agent sees the text. Its findings are platform text. The neutralised text still travels only in data fields |
| TH-02: the pre-check is an oracle | The applicant sees the scan's integrity findings only through the pre-check, which P-23 rate-limits. The finding names the kind and the place, never the rule that matched |
| TH-60: delimited data fields, content classification | Flagged spans are reported as offsets and closed reason codes in a member beside the text, inside the read model. No marker is ever written into the text, so content cannot forge one |
| I-11: one pinned configuration per call | The scan findings are recorded under the call's pinned configuration, as the deterministic stage 7 findings of the pipeline already are |
| I-85: high-risk actions never complete through MCP | The release has no MCP tool at all. An agent that reads the flagged text can never release its own hold |
| R-NF-02: no proposal content in logs | The scanner returns reason codes and offsets only. Its `Debug` output holds no text |
| `pre-check.md`: integrity findings are shown to the applicant | The pipeline's stage 7 scan is the same scanner, so every pre-check run carries them |

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Where it lives | A new pure crate, `fstp-injscan`: no I/O, no clock, memory linear in the text it scans, no third-party crate. It depends on `fstp-unorm` only, for the compatibility caseless key of ADR-029 | CLAUDE.md dependency policy |
| When it runs | At submission, on the title, summary and narrative that the submission freezes. At every read that hands proposal text to a model or an agent: the ADR-033 input, `review.read_content` through MCP, and stage 7 of the pipeline (pre-check and the cell assessor) | Daniel, 2026-11-22; TH-01; TH-60 |
| What it returns | A list of detections. Each has a closed reason, a start and an end in bytes of the scanned text. At most `MAX_DETECTIONS` (64) per text, with a count of the ones left out | Bounded output |
| Bounds | Linear passes over at most `MAX_SCAN_BYTES` (1 MiB) per text. The submission limits are smaller, so every submitted text is scanned whole. A longer text yields the reason `truncated` for the rest | Bounded time and memory |
| Neutralised view | `neutralise` removes every character of the hidden classes below. The original text is stored as submitted; the neutralised view is derived on each read. Neutralising twice equals neutralising once, and the result is always a subsequence of the input. Property tests prove both | Daniel, 2026-11-22 |
| Who gets the neutralised view | Every model and every agent: the pipeline (stage 1 already removed the zero-width, bidi and tag classes; it now removes every hidden class), the ADR-033 input, and every content read through MCP. A person in the web sees the text as submitted, with the flagged spans listed beside it, so the scan never alters what a human reads. Interim, pending Daniel | Daniel, 2026-11-22; usability rule |
| Marks | Each read model that carries proposal text carries its flags beside it: `title_flags` and `text_flags` in `review.read_content` and `irc.case`, and `flags` in each part of `assess.client_input`. One entry per detection, with the reason code and the start and end in Unicode scalar values of the text served. Scalar offsets count characters, as most agents and the web do. The marks are platform data inside the data structure, never inside the text | TH-60; ADR-013 "Results" |
| Integrity finding | A submission with at least one detection records, in the same ledger entry as its `Submit`, one integrity finding per part and reason class. Its statement is fixed platform text that names the kind and the part in plain words, such as "The narrative holds hidden characters (zero-width). They were removed before any AI system read it." It never quotes the detected text. Its evidence points at the spans. It carries the call's pin (I-11) and a drawn trace reference | Daniel, 2026-11-22; `assessment.md` integrity findings |
| Hold record | The same entry holds `IntegrityHeld`: the call, the proposal and the reason codes. The proposal is held until a release | Daniel, 2026-11-22 |
| Why the entry of `Submit` | One API call makes one audit entry (design section 3.7 step 9). The engine's composed command `ScannedSubmit` decides the core `Submit` and adds the finding records, as `Stage2Revision` composes its two core commands. A clean submission stays a plain core `Submit`, so nothing changes for it | M2 design section 3.7; `compose.rs` |
| What is held | Every AI assessment of the proposal: the engine refuses `ReadAssessmentInput`, `RecordClientAssessment` and the assessor's `Record` while it is held. The ADR-033 queue shows the proposal as `held`, and `fstp_assessment_get_input` refuses it with rule I-10 | Daniel, 2026-11-22 |
| Not held | Human review. Reviewers read the proposal and its integrity findings as before. The submission itself is never refused, delayed or changed in state by a detection | Daniel, 2026-11-22: "the submission itself is never rejected by a heuristic"; I-10 |
| Release | `assess.release_integrity` (`POST /proposals/{proposal}/integrity-release`), by the FSTP coordinator of the call, web only. The engine records `IntegrityReleased` with the coordinator's account, in the ledger and in the audit entry | Daniel, 2026-11-22 |
| Step-up for the release | None. The release is not in the high-risk table of `authentication.md`, and it binds nothing: the findings it lets through stay advisory (I-10). It has no MCP tool, so no agent can complete it, which is stronger than a prepared action. A step-up would add ceremony that no invariant asks for. Interim, pending Daniel | I-78; I-85; usability rule, 2026-11-21 |
| Who may release | The rule of `assess.rerun`: an active FSTP coordinator binding in the call's programme, on a submitted proposal of the call. A conflict declaration is not required, since the release reads no content. Interim, pending Daniel | Issue 6 M3; I-03 |
| After a release | The ADR-033 queue shows the proposal as `awaiting` again, and the coordinator's agent assesses it. In a cell with an assessor, the coordinator starts the run with "Re-run assessment". The scan's findings stay | ADR-033 |
| Pre-check | Stage 7 of the pipeline now uses the scanner, so every pre-check run shows the integrity findings with the same plain words. A cell without a pre-check port (the production cell of today) shows none. Interim, pending Daniel: whether such a cell should offer a scan-only pre-check, counted under P-23 | `pre-check.md`; TH-02 |
| Imports | Not changed by this lane. `fstp-import` keeps its tested rule that format controls stay in the stored text (TH-16), and no proposer that calls a model exists yet. When one is built, it receives the neutralised view and the import pages list the flags. The person who resolves each value confirms it (I-65). Interim, pending Daniel | TH-47; TH-16 |
| False positives | A detection never refuses anything, so a false positive costs one look by the coordinator. The detectors still aim low: each rule names its benign controls in the corpus, and the tests require none of them to be flagged | Daniel, 2026-11-22 |

## Detectors, interim readings, pending Daniel

| Reason code | What it finds | Benign controls that must not match |
| --- | --- | --- |
| `zero_width` | U+200B, U+2060 to U+2064, U+FEFF after the first character, U+180E, U+034F, the Hangul fillers. U+200C and U+200D unless both neighbours are letters of a joining script or pictographs | Persian and Indic text with ZWNJ and ZWJ, emoji sequences, a leading byte order mark |
| `bidi` | U+202A to U+202E and U+2066 to U+2069 always. U+200E, U+200F and U+061C only in a text with no right-to-left letter | Hebrew and Arabic text with direction marks |
| `tag` | U+E0000 to U+E007F, except a flag sequence after U+1F3F4 | Subdivision flags |
| `variation_run` | Two or more variation selectors in a row, or a supplementary selector after a character that is no ideograph | One selector after an emoji or an ideograph |
| `format` | Other invisible format characters: U+FFF9 to U+FFFB, U+1D173 to U+1D17A. The soft hyphen is removed but never flagged | Soft hyphens from copied text |
| `hidden_markup` | Markup that hides text: HTML comments, `display:none`, `visibility:hidden`, `opacity:0`, `font-size` of 0 to 2 units, white or near-white text colour, negative or off-page positions | Code that mentions CSS in prose without hiding anything, such as "we set a dark colour scheme" |
| `role_marker` | Chat roles and template tokens: `<\|im_start\|>`, `<\|system\|>`, `[INST]`, `<<SYS>>`, `</s>`, a line that starts with `system:`, `assistant:` or `### System`, a `<system>` tag | Prose about "the system" or "an operating system" |
| `override` | "Ignore", "disregard" or "forget" with "previous", "prior" or "above" instructions, and "new instructions", "you are now", "from now on you", in English, German, French, Spanish, Italian, Dutch, Portuguese and Polish | "Instructions for installation", "previous work" |
| `addressed` | Text addressed to an AI reader: "note to the AI", "dear assessor", "AI reviewer", "language model", "as an AI", "assessment system", in the same languages | "Our AI model detects anomalies", "large language models in research" as subject matter |
| `score_request` | Requests to set a score, a band or a finding: "give this proposal the highest score", "rate it 10/10", "mark as excellent", "no findings", "rank this first" | "Scoring is done by the committee" |
| `tool_call` | Requests to call tools and tool-call payloads: "call the tool", "use the function", `fstp_` tool names, `<tool_call>`, `<function_calls>`, `"tool_use"`, `"function_call"`, a JSON object with `name` and `arguments` | Code snippets in technical proposals without those members |
| `schema_payload` | JSON-schema-like or finding-shaped payloads: `"$schema"`, `"findings":` arrays, `"severity":` with `"statement":` | A JSON config example with other members |
| `exfil_link` | Links that could carry data out: a Markdown image whose URL has a query, a URL whose query is 48 bytes or longer, a URL with a template placeholder such as `{{` or `%7B%7B` | Plain links to project pages and repositories |
| `encoded_blob` | Base64 runs of 120 characters or more with both cases and digits, and hex runs of 128 digits or more | SHA-256 digests (64 hex digits), commit hashes |
| `confusable` | A word that mixes Latin letters with Cyrillic or Greek letters, or uses full-width Latin letters | Words written wholly in Cyrillic or Greek |
| `truncated` | The text was longer than `MAX_SCAN_BYTES`, and the rest was not scanned | None |

Every phrase detector runs on a folded view: hidden characters removed, `fold_nfkc` of ADR-029 per character, and Cyrillic and Greek look-alike letters mapped to their Latin twins. So "іgnоre" in Cyrillic letters matches "ignore". Each detection maps back to the span of the original text.

The languages are the official languages whose speakers this lane could cover with care. P-25 sets the programme language. Interim, pending Daniel: which further languages the pilot needs.

## Operations

| Operation | Route | Tool | Roles | Channel |
| --- | --- | --- | --- | --- |
| `assess.release_integrity` | `POST /proposals/{proposal}/integrity-release` | None | FSTP coordinator | Web only |

`assess.findings_status` (web) gains the member `integrity`: `clear`, `held` or `released`, and the reason codes. The ADR-033 queue gains the status `held`. `assess.client_input` and `review.read_content` gain `flags`.

## Tests

| ID | Test | Where |
| --- | --- | --- |
| TH-01, T-LLM-INJ | `th01_every_injection_sample_is_flagged_with_its_reasons` (every reason covered) | `crates/fstp-injscan/tests/corpus.rs` |
| TH-01 | `th01_benign_controls_are_not_flagged` | same |
| TH-01, T-LLM-INJ | `th01_v1_corpus_flags_exactly_the_injected_proposals`: every direct and hidden injection of corpus v1 is flagged, and none of the other 180 or so items | same |
| TH-01 | `th01_neutralise_is_idempotent`, `th01_neutralise_never_adds_content`, `th01_neutralised_text_has_no_hidden_class`, `adr035_scan_is_bounded_and_spans_are_char_boundaries`, `adr035_detections_are_capped_and_counted`, `adr035_long_text_is_truncated_and_flagged` | `crates/fstp-injscan/tests/props.rs` |
| R-NF-02 | `r_nf_02_detections_debug_holds_no_text` | same |
| TH-01, TH-26 | fuzz target `scan_text` | `crates/fstp-injscan/fuzz` |
| TH-02, R-LA-06, T-LLM-INJ | `adr035_th02_precheck_shows_the_scan_findings` | `crates/fstp-assess/tests/adr035_precheck.rs` |
| R-NF-02, I-10 | `adr035_statement_is_platform_text` (no statement reads as a score) | `crates/fstp-assess/src/integrity.rs` |
| TH-01, I-10 | `adr035_th01_held_proposal_takes_no_ai_assessment_until_released` | `crates/fstp-findings/tests/adr035_integrity_hold.rs` |
| TH-26 | `adr035_integrity_records_round_trip_and_refuse_other_spellings`, the record generator and two fuzz seeds of `finding_decode` | same, and `crates/fstp-findings` |
| TH-60 | `adr035_th60_flags_and_agent_view`, `adr035_reply_shapes_name_every_reason_code` | `crates/fstp-api-core/src/dispatch/integrity.rs` |
| TH-01, I-10, I-11, I-85, R-LA-01, R-LA-02, T-LLM-INJ | `adr035_flagged_submission_is_held_marked_and_assessed_after_release` | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/assess_client_tests.rs` |
| TH-60, P-75 | `adr035_th60_mcp_content_is_neutralised_and_marked` | same |
| TH-01, I-10 | the cell assessor tests of `assess.rs` release the seeded injection first | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/assess.rs` |
| TH-01, TH-60 | `adr035_th01_coordinator_sees_the_hold_and_releases_it`, `adr035_released_row_and_closed_reasons`, `adr035_th60_content_view_carries_closed_flags`, `adr035_th60_flagged_passages_render_as_text`, `adr035_no_flags_no_section` | `web/test` |
| I-84 | `i84_reference_and_registry_name_the_same_operations`, with `assess.release_integrity` in `reference::authz` as `R::Coordinator`, binding | `crates/fstp-api-testkit/src/matrix.rs` |

The new operation is a candidate of the PostgreSQL authorisation sample like every other operation, with an empty body. A narrow local run (`FSTP_PG_MATRIX_OPS` with the new and the changed operations) passed.

## Record of lane L30 (2026-11-22)

| Topic | Reading | Basis |
| --- | --- | --- |
| Where the hold is enforced | In the engine: `ReadAssessmentInput`, `RecordClientAssessment` and the assessor's `Record` are refused with rule I-10 while the proposal is held, after the actor checks, so the authorisation classes do not change. The e2e cell's assessor skips a held proposal; after the release, "Re-run assessment" runs it | I-10; T-AUTHZ-MATRIX classes |
| Rule of the refusal | I-10, a guard. The input tool answers `{"code":"refused","rule":"I-10"}`, and the skill explains it | `fstp-domain` has no rule for a threat |
| Release rule | As `assess.rerun`: an active FSTP coordinator binding of the programme and a submitted proposal of the call. The engine refuses a release of a proposal that is not held (I-10). Interim, pending Daniel: a coordinator with a conflict fact on the proposal may release it, since the release reads no content | Issue 6 M3 |
| Deterministic findings | The scan's findings carry the call's pin, a drawn trace and confidence 1000 permille. A later `Regenerate` replaces every finding of the call, so a regeneration must carry them again. No regeneration runs in production today | I-11; P-21 NOTE 10 |
| Client path duplicates | `assess.client_submit` adds the cell's own scan only for a proposal that no scan at submission flagged, so the same finding is never recorded twice | ADR-033 "Stages" |
| Agent view | Through MCP, `review.read_content` and `irc.case` serve the neutralised view; the web serves the text as submitted. Both carry the flags of the text they serve. The ADR-033 input is stripped by stage 1, which now removes every hidden class | ADR-035 "Who gets the neutralised view" |
| Scan failures | A draft that cannot be read at submission, or a call with no pin, leaves the `Submit` unscanned. The scan then runs again on every served input and content read, and marks what it finds, but no hold is recorded | Daniel, 2026-11-22: the submission is never rejected by a heuristic |
| Statements | Fixed platform text per part and reason. None reads as a score (stage 8's check), so the assessor's intake accepts them | I-10 |

## Known gaps, each interim, pending Daniel

- The production cell has no pre-check port, so the applicant sees the scan's findings only where a pre-check runs. Should such a cell offer a scan-only pre-check, counted under P-23?
- Imported documents keep their stored text (TH-16). The neutralised view and the flags for a proposer wait until a proposer that calls a model exists.
- The flags of the ADR-033 input are computed on the stripped text. Hidden characters removed by stage 1 are named by the scan's findings, not by a mark at their place.
- No PDF or rich-format extraction exists in the platform. Hidden markup is detected in the submitted text itself.
- Should the release need a step-up after all? This lane reads no invariant that asks for one.
- Which further languages the override and address detectors need for the pilot.

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-11-22 |
| Synthetic corpus | `corpus/injection-v1/samples.json`, hand-written, every sample marked synthetic | 2026-11-22 |
| Dependency tree | `fstp-injscan` depends on `fstp-unorm` only. `fstp-findings`, `fstp-assess`, `fstp-api-core` and `fstp-api-testkit` now depend on `fstp-injscan`, so `fstp-unorm` joins their trees and the lockfiles of fifteen fuzz projects. No third-party crate enters the workspace, and deps-check passes | 2026-11-22 |
| New operation | `assess.release_integrity`, web only, binding, no step-up | 2026-11-22 |
| New records | `FindingRecord::IntegrityHeld` and `FindingRecord::IntegrityReleased`; command `FindingCommand::ReleaseIntegrityHold`; engine command `ScannedSubmit` | 2026-11-22 |
