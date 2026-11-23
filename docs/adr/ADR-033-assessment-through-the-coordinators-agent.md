# ADR-033: Assessment through the FSTP coordinator's connected agent

Status: Proposed. Drafted 2026-11-22 by lane L28 (`prod/mcp-assessment`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one. ADR-032 is lane L25's (`prod/anonymous-drafts`, not merged yet).

## Context

A production cell has no assessor. No worker is connected, and no system task issues `FindingCommand::Record`. Reviewers therefore see no AI findings (R-LA-01).

Daniel decided on 2026-11-22, verbatim: "I would like the pilot to also be run over the connected administrator's / coordinator's local Claude Code instance. This could be arranged via MCP, for example."

Sources read for this record: `SPEC/04-llm-assessment/assessment.md` and `pre-check.md`, every invariant of `SPEC/02-domain/invariants.md` on findings, identity, separation of duties and MCP (I-03, I-10, I-11, I-12, I-17, I-21, I-84, I-85, I-86), `SPEC/02-domain/roles-and-sod.md`, `SPEC/02-domain/policy-parameters.md` (P-10, P-21, P-75, P-77, NOTE 10), `SPEC/03-architecture/mcp-server.md`, `SPEC/03-architecture/authentication.md` (high-risk actions), ADR-013, ADR-019, `docs/handoff/m7-design.md`, and the code of `fstp-assess`, `fstp-assessor`, `fstp-findings`, `fstp-infer`, `fstp-engine/src/findings.rs`, `fstp-access` and `fstp-api-core`.

## Spec check

No invariant or SPEC rule forbids the approach below. Three rules bear on it, and the design meets each:

| Rule | How it is met |
| --- | --- |
| `assessment.md`: "Submission and retrieved content travel only in the data channel. Instructions come only from the pinned prompt." | The submission reaches the client only inside `structuredContent.data` of a tool result, where every string is listed under `untrusted` (ADR-013 "Results"). The assessment instructions are the pinned prompt set v1 of `fstp-infer`, shipped verbatim in the plugin's assessor agent. A test compares them byte for byte, and the cell refuses a submission whose prompt set digest differs. See "Residual: the client harness" for the one point Daniel should confirm |
| I-11, R-LA-05: one pinned model, prompt and rubric per call | The client path is a P-21 provider value, frozen per call at publication. A call is assessed either by a cell assessor or by the coordinator's agent, never both. Each submission names the model the client reports, which must equal the frozen P-21 model, and the prompt set digest, which must equal the cell's. Findings carry the call's pinned `config_id` |
| I-17, I-86 | The client receives the submitted title, summary and narrative after stages 1 and 2 of the pipeline, never an identity attribute. No tool of this ADR reads the vault |

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Who runs it | The FSTP coordinator of the call's programme, with an active binding. The proposal must be one the coordinator may read in the web: SUBMITTED, or STAGE1 and STAGE2 under P-10 "operator staff only". The coordinator must have declared on the proposal with no conflict, and the cell asks the vault again on every read (I-03) | Roles table: the coordinator runs the knock-out read; `fstp-access` content rule; R-AC-01 |
| Not the administrator | A tenant admin has no proposal content access (roles table) and no conflict declaration, so I-03 could not hold. An admin who should run it holds an FSTP coordinator binding in the programme | Roles table; I-03 |
| Reviewer independence | A coordinator who holds a reviewer or IRC assignment on the proposal, in any status, is refused. The findings anchor the scores of the assigned reviewers, so none of them produces the findings of a proposal they score. The reverse is refused too: an account that recorded the AI assessment of a proposal is never assigned to review it (decided by Daniel on 2026-11-22, record of lane L31) | SoD-01 allows a coordinator to be a committee member (SoD-02 bars IRC only); P-28 NOTE 3 |
| The switch | Per programme, off by default. The programme's P-21 provider is the reserved token `coordinator_agent`. P-21 is frozen at publication (I-12), so the choice holds for the whole call and is fixed before applicants submit. Every other provider value leaves the client path closed | P-21; I-11; I-12 |
| Why not a new parameter | A new frozen parameter would be a key of `FrozenValues::opaque`. `fstp_domain::policy::validate` refuses a version without every frozen key (I-12), so every stored policy version and every pilot programme would fail. P-21 already names the provider and is frozen | `policy::validate` |
| Agents never set the switch | Through MCP, a creator save or clear that names P-21 is prepared, like P-75 and P-77. The person confirms it in the platform | ADR-013 "P-75 and P-77 through MCP" (Daniel, 2026-11-20), applied to P-21 |
| Data channel | Tool results only. The input tool returns the parts `title`, `summary` and `narrative` as JSON strings after extraction and PII stripping, under closed labels, with the tasks of the call as closed values: the stage names, the P-01 criterion ids as `c-<32 hex>`, and the rubric element tags. No submission text is ever placed in a tool name, description, schema, the skill or the agent | ADR-013 "Results", TH-60, TH-63 |
| The pinned prompt | `fstp_infer::Prompt::text` of each stage and the v1 output schema, copied verbatim into the plugin's assessor agent, with the prompt set version `v1` and the hex of `fstp_infer::prompt_set_digest`. A test reads the agent file and checks every prompt text, the schema and the digest. A cell refuses a submission whose digest differs, and the input tool returns the digest it expects, so an old plugin stops before it runs | `assessment.md`; ADR-019 "Consequences" |
| Why no MCP prompt | `fstp-mcp` marks every string of a result as untrusted (ADR-013 "Results"), so a prompt served by a tool would arrive labelled as data. An MCP `prompts` method would be new protocol surface. The plugin file is fixed text, versioned with the platform and checked by test | ADR-013 Methods row |
| Stages | Completeness, quality per P-01 criterion, claims and integrity. Verification is not run: the client has no retrieval proxy, and the assessor agent has no web tool. Claims stay "info" accuracy findings that judge no truth, as the claims prompt says. The cell adds its own deterministic integrity scan (stage 7) to every submission, whatever the client sends | `assessment.md` steps 6 and 7; TH-12 |
| Submission | One call per proposal: the input digest, the prompt set digest, the model the client reports, and one reply object per task. Each reply goes through `fstp_assess::decode_output` for its stage (closed schema, no score-like statement, criterion in P-01, element in the rubric, bounds) and through `Prepared::locate` for evidence (R-LA-02). A refused reply drops whole and is listed by stage and code as `RefusalsRecorded`. Nothing of it is stored | M7 design section 3.4; I-10 |
| Containment | The submission tool records only finding records. It cannot name another operation, and the engine returns finding records only (I-10). A reply that asks for a score, a decision or a tool call fails the closed schema or the score-like check, or becomes a bounded statement. The assessment tools need their own scope, `assess:run`, and the plugin connects a second server entry that asks for that scope alone. The plugin's assessor agent may use only that server's tools | TH-01; ADR-013 "Scopes" |
| One run per proposal | A proposal takes one client assessment. A further one is accepted only while a coordinator's re-run (`assess.rerun`, web only, at most three) is in flight. So an injected instruction cannot keep adding findings | Issue 6 M3 re-run bounds |
| Input binding | The input read appends a ledger record with the input digest. A submission must name the digest of the latest input read of the same account on that proposal, and the cell recomputes the digest from the submitted content | R-AU-01; provenance |
| Record or prepare | Recorded directly. Recording findings is no high-risk action (authentication.md table), so I-85 does not apply. Findings are advisory and never binding (I-10), so P-77 does not apply either. A confirmation per proposal would add a step no invariant asks for (usability rule, 2026-11-21) | I-78; I-85; I-10 |
| Identity of the assessor | The findings are recorded by the coordinator's account through MCP, with the client in the audit entry, never as the system. `Actor` keeps no assessor variant. The provenance record names who ran it. The system path (`FindingCommand::Record`) stays for a cell assessor | I-10; I-84; ADR-013 audit row |
| Provenance | `ClientAssessed`: call, proposal, the coordinator's account, the model as the client reported it, the prompt set digest, the input digest and the trace reference. The ledger entry holds the time, and the audit entry holds the agent client. Every finding of the run carries that trace reference and the call's `config_id` | `assessment.md` schema outline, `config_id` and `trace_id`; R-LA-07 |
| Classification | Input results are `confidential` | `mcp-server.md` Untrusted content |
| Data transfer | Sending submission content to the coordinator's AI client is a transfer to that client's provider. Decided by Daniel on 2026-11-22: the transfer of proposal text to Anthropic for assessment is agreed by the parties; the information is not used for training. The switch stays per call through P-21: a programme admin chooses the provider `coordinator_agent`. The Guide's disclosure text is legal wording and is not written here (`TODO(legal)`, drafts in `legal/`) | ADR-019; R-LA-08 |

## Operations

| Operation | Route | Tool | Roles | Scope | Channel |
| --- | --- | --- | --- | --- | --- |
| `assess.client_queue` | `GET /calls/{call}/client-assessment` | `fstp_assessment_list_proposals` | FSTP coordinator | `assess:run` | Allow |
| `assess.client_input` | `GET /proposals/{proposal}/client-assessment/input` | `fstp_assessment_get_input` | FSTP coordinator | `assess:run` | Allow |
| `assess.client_submit` | `POST /proposals/{proposal}/client-assessment` | `fstp_assessment_submit` | FSTP coordinator | `assess:run` | Allow |

Each has a web route under the same role (I-84). The queue lists ids and states only, never a title. Consent text of `assess:run`, interim, pending Daniel: "Run the AI assessment of proposals you may read: read their text with personal data replaced, and record advisory findings. Nothing else."

## Residual: the client harness

Claude Code wraps the assessor agent in its own system text, and the version of that text follows the client's updates. The pinned prompt is the only assessment instruction, but it is not the only text the model sees. The run records the model the client reports. The agent client's registered name is in the audit entry. Decided by Daniel on 2026-11-22: no instruction ever comes from submission or tenant text, and Claude Code's own system prompt is acceptable.

## Known gaps, each interim, pending Daniel

- Closed by lane L31: the vault name mask and the sealed raw traces (record of lane L31 below).
- No fallback switch for a client-run call. `Regenerate` stays a system command, and the client cannot regenerate a whole call in one step (P-21 NOTE 10).
- The model id is the client's own report. The cell cannot verify it.

## Tests

| ID | Test | Where |
| --- | --- | --- |
| ADR-033, I-11 | `adr033_i11_only_the_reserved_provider_names_the_client_path` | `crates/fstp-findings/tests/adr033_client_runs.rs` |
| ADR-033, R-AU-01 | `adr033_client_run_binds_the_runners_latest_input_read` | same |
| ADR-033, I-10 | `adr033_i10_one_client_run_per_proposal_unless_a_rerun_is_in_flight` | same |
| TH-26 | the record generator and the fuzz seeds of `finding_decode` cover the two new records | `crates/fstp-findings` |
| ADR-033, TH-01, I-84, I-85 | `adr033_th01_assessment_tools_need_their_own_scope_and_nothing_more` | `crates/fstp-access/src/tests.rs` |
| ADR-033, I-85 | `p75_p77_sets_agent_policy_by_the_decoded_command` (P-21 clear prepares) | same |
| ADR-033 | `adr033_input_digest_binds_tasks_and_parts`, `adr033_th01_submission_body_is_closed` | `crates/fstp-api-core/src/dispatch/assess.rs` |
| ADR-033, I-11 | `adr033_i11_a_client_path_call_has_no_cell_assessment` | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/assess_client_tests.rs` |
| ADR-033, R-LA-01, R-LA-02, I-10, I-11, I-84, I-85, R-AU-01 | `adr033_coordinator_agent_assesses_a_proposal_end_to_end` | same |
| ADR-033, TH-01, I-10, T-LLM-INJ | `adr033_th01_injected_replies_yield_only_findings_or_refusals` | same |
| ADR-033, I-11, R-AU-01 | `adr033_i11_model_prompt_set_and_input_must_match` | same |
| ADR-033, I-84, SoD | `adr033_i84_only_the_coordinator_with_assess_run` | same |
| ADR-033, I-17, I-86 | `adr033_i17_i86_the_input_holds_no_identity_attribute` | same |
| ADR-033, I-11, R-LA-05 | `adr033_i11_agent_ships_the_pinned_prompt_set` | `crates/fstp-infer/tests/adr033_plugin_prompt.rs` |
| ADR-033, TH-01 | `adr033_th01_agent_reaches_only_the_assessment_server`, `adr033_th01_skill_treats_submissions_as_data` | same |
| I-84 | `i84_reference_and_registry_name_the_same_operations`, with the three operations in `reference::authz` | `crates/fstp-api-testkit/src/matrix.rs` |

The PostgreSQL authorisation sample (`t_authz_matrix_pg_sample`) now builds its world with P-21 on the client path, and the coordinator records a real finding on X through `assess.client_submit`. `review.findings` and `review.mark_finding` cells meet that finding. The three new operations are candidates of the sample like every other operation.

## Record of lane L28 (2026-11-22)

| Topic | Reading | Basis |
| --- | --- | --- |
| Order of the engine checks | The coordinator binding first, then the P-21 path, then the state and P-10, the conflict facts, the declaration and the assignments, then the vault. A caller who is no coordinator learns nothing of the path. In a call off the path every coordinator gets the `P-21` guard | Interim, pending Daniel; T-AUTHZ-MATRIX classes |
| Input read rule | `assess.client_input` admits the coordinator of the programme in every state at the access layer. The engine's `ReadAssessmentInput` then refuses every state but SUBMITTED, and STAGE1 and STAGE2 under P-10 "operator staff only", before any content is opened | R-AC-01; I-21 |
| Evidence references | Each section's text reference is derived from the proposal, the section and the section's digest. No reviewer page shows spans today | Interim, pending Daniel |
| Confidence | The v1 output schema carries no confidence, so each finding records 0 permille, as the test cell's intake does | Interim, pending Daniel |
| Test cell | `fstp-e2e-cell --assessor client` (or `client:<model>`) seeds the programme with P-21 `coordinator_agent` and no assessor in the cell, for a local trial with Claude Code | ADR-013 record of lane mcp-demo |
| Creator label | The P-21 field names the token `coordinator_agent`, so the person setting up the programme finds it on the page | Usability rule, 2026-11-21 |

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-11-22 |
| Reserved P-21 provider | `coordinator_agent` | 2026-11-22 |
| New scope | `assess:run` | 2026-11-22 |
| Dependency tree | `fstp-api-core` depends on `fstp-assess` and `fstp-infer` without the `http` feature, so it reaches no TLS crate (record of lane L31) | 2026-11-22 |

## Record of lane L31 (2026-11-22)

Daniel decided six points on 2026-11-22. This record states each decision and how the lane builds it, before the code.

| Topic | Decision or reading | Basis |
| --- | --- | --- |
| Who runs it | The FSTP coordinator only. The row "Who runs it" above stands, and the tenant admin stays excluded | Decided by Daniel on 2026-11-22 |
| The client harness | No instruction ever comes from submission or tenant text. Claude Code's own system prompt is acceptable | Decided by Daniel on 2026-11-22 |
| The runner is never a reviewer | `Assign`, alone or in a `review.assign_batch`, is refused under I-03 when the assignee recorded a client assessment of that proposal. The runner's act makes the conflict, never a finding's content, so I-10 holds. The engine checks it beside the core, since the core never reads the finding store. The reference model states the rule. No matrix world holds such an assignee, so the matrices meet it only through its own tests | Decided by Daniel on 2026-11-22; I-03 |
| Vault name mask | Built before the pilot runs assessment (M7 Q4). The cell sends the vault the proposal team's account ids, taken from its own bindings as for `HasConflict`, and the texts it is about to hand to an agent or a model. The vault resolves each account's verified identity, opens its sealed tuple inside the vault, and matches the family and given names and the date of birth. Names match word by word through `fstp_unorm::name_key`, words of two letters or more. Dates match in the ISO spelling and in day, month, year order with `.`, `/` or `-`. The vault answers spans only: byte offsets into the text sent, a person index in account order, and a class, name or date of birth | Decided by Daniel on 2026-11-22; I-17; ADR-029 |
| Why spans | The cell holds the text already, so a span tells it only which part of its own text names a team member. It never receives a name or a date the text does not hold. Keyed digests of every name would let the cell test candidate names offline, so the vault sends none. Masked text would tell the cell the same as spans, at more bytes | I-17; I-86 |
| R-NF-08 | The vault keeps nothing of the texts. The tuples stay sealed at rest under the vault's own keys, and are opened in the vault process only | R-NF-08 |
| Bounds of the mask | At most 16 accounts, 3 texts and 192 KiB of text per request, and at most 120 mask requests per minute per vault. A compromised cell could still probe the mask with texts of its choosing within those bounds. Interim, pending Daniel | TH-01; residual |
| Where the mask applies | Every text that leaves the cell for an agent or a model: the ADR-033 input and the agent view of the content tools (`review.read_content` and `irc.case` through MCP, ADR-035). The vault mask runs after the cell's own pattern stripping. Persons become `[PERSON-n]`, dates of birth `[BIRTHDATE-n]`. The web shows the text as submitted. A vault that cannot mask fails closed: no text leaves the cell | Decided by Daniel on 2026-11-22; TH-60; NOTE 2 of `overview.md` |
| Spec | `03-architecture/overview.md` "Operations other than queries" gains a fifth kind, masks, with this decision | Decided by Daniel on 2026-11-22 |
| Sealed raw traces | Each submission's raw replies, as the client sent them, with the prompt set digest, the input digest and the model, are stored as one confidential text of the proposal in the cell's text store, sealed at rest (R-NF-08). The `ClientAssessed` record names it. The proposal's texts are erased with the proposal's retention, which runs to the end of P-41, so P-22 holds. No read operation serves it. It is reached only through the audit path: the audit entries name its reference, and the appeal and calibration reads of `assessment.md` Traces are not built. Interim, pending Daniel: the trace read for appeals | Decided by Daniel on 2026-11-22; R-LA-07; P-22; ADR-007 |
| Dependency tree | `fstp-infer` puts its HTTP transport behind the feature `http`. `fstp-assessor` and the test kit enable it. `fstp-api-core` does not, so its tree and the fuzz lockfiles return to the reviewed ones | Decided by Daniel on 2026-11-22; CLAUDE.md dependency policy |

### Built by lane L31

| ID | Test | Where |
| --- | --- | --- |
| M7 Q4, I-17, ADR-029 | `m7_q4_names_match_by_name_key_and_join`, `m7_q4_person_index_and_dates`, `r_nf_02_mask_person_debug_names_nothing` | `crates/fstp-unorm/src/mask.rs` |
| M7 Q4, I-17 | `m7_q4_i17_spans_are_sound_and_mask_every_name_word` (property), fuzz target `mask_spans` | `crates/fstp-unorm` |
| M7 Q4, TH-26 | `m7_q4_mask_request_and_answer_round_trip`, `m7_q4_mask_request_bounds`, `m7_q4_mask_answer_bounds` | `crates/fstp-vault-proto/tests/m7_q4_mask_codec.rs` |
| M7 Q4, I-17, R-NF-08 | `m7_q4_i17_vault_masks_names_from_the_sealed_tuple`, on PostgreSQL with the real keystore; fuzz target `identity_tuple_decode` | `crates/fstp-vault` |
| M7 Q4, I-17, TH-60 | `m7_q4_i17_vault_masks_team_names_before_text_leaves_for_an_agent`, `m7_q4_a_vault_that_cannot_mask_lets_no_text_leave` | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/assess_client_tests.rs` |
| I-03 | `adr033_l31_store_names_the_runners_of_a_proposal`, `adr033_l31_i03_the_runner_is_never_assigned_to_review_it` | `crates/fstp-findings/tests/adr033_client_runs.rs`, the test cell |
| R-LA-07, P-22 | the sealed trace in `adr033_coordinator_agent_assesses_a_proposal_end_to_end`; the `raw` member in the codecs, generator and fuzz seed `record_client_assessed_raw` | the test cell, `crates/fstp-findings` |

Readings of lane L31, each interim, pending Daniel:

- The mask lives in `fstp-unorm`, beside `name_key`, and `fstp-vault-core` re-exports it. The M3 layering rule keeps the test kit away from `fstp-vault-core`, and the synthetic vault must mask as the vault does.
- A production tuple that is not one of `TUPLE_LABEL` refuses the mask as unavailable, so assessment of that team fails closed. The seeded vault of `fstp-celltest` reads such a tuple as holding no name.
- The agent's content view records the content read before the vault masks it. A vault that cannot mask then refuses the call, with no text and no second audit entry.
- A text over 64 KiB after the cell's pattern stripping cannot be sent to the vault, so its input fails closed. Superseded by the record of lane L40: such a text is masked in pieces.
- `fstp-infer`'s `http` feature is on by default for the crate itself, and the workspace dependency turns default features off. `fstp-assessor` and the test kit ask for it.

## Record of lane L40 (2026-11-23): long texts

Daniel decided on 2026-11-23 that a text over the vault's cap is masked in pieces. Before, a proposal text over 64 KiB after the cell's pattern stripping could not go to the vault, so its assessment input failed closed. This record states the decision and how the lane builds it, before the code.

| Topic | Decision or reading | Basis |
| --- | --- | --- |
| Pieces | The cell splits a text into pieces of at most 64 KiB. Each cut falls at the last paragraph break in reach, else the last line break, else the last white space, else after the last character that belongs to no word and no date run. No cut splits a UTF-8 sequence | Decided by Daniel on 2026-11-23 |
| The vault cap | Unchanged: at most 16 accounts, 3 texts and 64 KiB per text in one request, 120 requests per minute. The cell sends the pieces of all texts of one call in order, three per request | Decided by Daniel on 2026-11-23 |
| Whole words | The mask reads a word as a maximal run of letters, digits and combining marks, and a date as a run of digits and `.`, `/` or `-`. A cut follows white space or a character outside both, so every word and every date run lies whole in one piece, and each word passes through `name_key` whole | I-17; ADR-029 |
| A name across a cut | The spans of each piece move by the piece's start. A name span of one person whose gap to the next name span of the same person holds only joiners and crosses a cut becomes one span, as the mask of the whole text joins them. So "Maradine" before a cut and "Velinorra" after it are one `[PERSON-n]` | I-17 |
| Proof | The property test shows that the joined spans of the pieces equal the spans of the whole text, for generated texts, names and piece sizes. The mask is therefore as strong as one request over the whole text | I-17 |
| Fail closed | A window with no cut, a text of more than 64 pieces (4 MiB), any failed request, an answer of the wrong length, and any span outside its piece fail every text of the call closed. No text leaves the cell | TH-60; NOTE 2 of `overview.md` |
| Order and content | The pieces cover the text in order. The masked text is built from the joined spans over the original text, so it differs from the text only where a mask stands | Decided by Daniel on 2026-11-23 |
| Data channel | Submission text stays untrusted data. The pieces go to the vault only, and the masked text reaches the agent through the assessor's data channel as before. No instruction is built from it | TH-60; CLAUDE.md |
| Never part of a mask | The vault answered at most 4096 spans per text and cut longer answers short, which would leave names unmasked. It now refuses such a text as unavailable, so the cell fails closed | I-17 |
| Where | `fstp_unorm::mask::{mask_pieces, join_piece_spans}` beside the mask, re-exported by `fstp-vault-core`. `crate::masking::mask_in_pieces` in `fstp-api-core` drives the requests for both the assessment input and the agent's content view. The test kit's synthetic vault keeps the vault's request cap, so the tests see the pieces | ADR-033 record of lane L31 |

Interim, pending Daniel:

- The limit of 64 pieces per text (4 MiB). It keeps one text from spending the vault's mask rate. Today's texts are at most a little over 64 KiB, so this limit is not reached.
- A text with more than 4096 masked spans in one piece fails closed. A real proposal is not expected to name a team member that often.
- A cut uses white space before a character that no word or date holds. A text of more than 64 KiB with neither, such as one long run of letters, fails closed.

### Built by lane L40

| ID | Test | Where |
| --- | --- | --- |
| M7 Q4, I-17 | `m7_q4_i17_pieces_mask_exactly_as_the_whole_text` (property), `m7_q4_i17_a_span_outside_its_piece_fails_the_join` (property), `m7_q4_i17_a_name_across_a_cut_is_masked_as_one`, `m7_q4_cuts_prefer_paragraph_then_line_then_space`, `m7_q4_i17_a_window_without_a_cut_fails_closed`, `m7_q4_piece_bounds_keep_the_vault_cap`; fuzz target `mask_pieces` | `crates/fstp-unorm/tests/m7_q4_mask_pieces.rs`, `crates/fstp-unorm/fuzz` |
| M7 Q4, I-17, TH-60 | `m7_q4_i17_a_long_text_is_masked_in_pieces_within_the_vault_cap`, `m7_q4_i17_any_failed_piece_fails_the_whole_text_closed`, `m7_q4_short_texts_go_in_one_request`, `m7_q4_i17_an_uncuttable_or_too_long_text_fails_closed` | `crates/fstp-api-core/src/masking.rs` |
| M7 Q4, I-17 | `m7_q4_pieces_keep_the_vault_request_cap`, `m7_q4_i17_vault_never_answers_part_of_a_mask` | `crates/fstp-vault-core/tests/m7_q4_mask_wire.rs` |
