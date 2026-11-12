# M7 demo: the AI assessment in the e2e cell

Written in lane `m7/ui` (M7 lanes L-UI and L-DEMO) on 2026-11-12. It records how to run the AI assessment against `fstp-e2e-cell`, the click path of each person, what this lane built of lanes L-CELL and L-PRE, and the decisions and open questions for Daniel. Read it with `docs/handoff/m7-design.md` sections 3, 4, 7 and 8, and `docs/handoff/m4-demo.md`.

Every person, proposal and text in the demo is synthetic. The demo proposals come from `corpus/v1` (generator `template-v1`). No model API is called: the cell runs the synthetic assessor in the real `fstp-assessor` child process.

## Run it

```sh
tools/demo/run.sh                          # builds the pages, fstp-e2e-cell and fstp-assessor; seeds "review stage1"
tools/demo/run.sh seed applicant DRAFT     # the open call with proposal z drafted from the corpus
tools/demo/run.sh seed review stage1       # five corpus proposals, assessed at submission
tools/demo/run.sh e2e assess/              # the M7 click-through spec against the running cell
tools/demo/run.sh stop
```

Lane runs used `FSTP_DEMO_PORT=8670` and `FSTP_DEMO_STATE=<worktree>/target/demo`.

- `run.sh` now builds `fstp-assessor` beside `fstp-e2e-cell`. The cell finds it next to its own executable.
- `fstp-e2e-cell --assessor synthetic` is the default. `--assessor replay:<dir>` passes `--inference replay:<dir>` to the child. `--assessor live:<file>` is refused, so the demo never calls a model.
- Without the `fstp-assessor` binary, every assessment stays pending. The coordinator then sees "Findings pending", and nothing is recorded (R-NF-10).

## Click paths

Each person starts on the front door `/demo` and clicks "Sign in as".

### Applicant: the pre-check (R-LA-06, R-LA-08, TH-02, TH-29)

1. Choose the scene **DRAFT** under "Applicant". It seeds the open call and the draft of proposal z, whose text is the corpus item `b02-omission`: the team section is missing.
2. "Sign in as" the lead of z. The home page lists the proposal.
3. Proposal z, then the step "Proposal text". The draft page shows a "Check my draft" link with one line on what it does.
4. "Check my draft" opens `/app/proposals/1002/precheck`. The page says that an AI system reads the draft and that the assessor is "Synthetic assessor (demo)". It shows the remaining checks: 1 today, 5 in this call, 5 across the person's drafts.
5. "Check my draft now" runs the check. The run lists a major completeness finding with "Rubric element: Team and experience", and one info quality finding per P-01 criterion. No score, band or confidence appears.
6. The button is then disabled, and the page says when the next check is available (P-23 is one check a day per proposal in SuperSAFE).

A second check needs a rolling day of cell clock. `/demo/advance` moves the clock, but the DRAFT call closes 30 minutes after the seed (as `OPEN_CALL` does), so reseed the scene instead.

### Reviewer: findings with marks (R-LA-03, I-10)

1. Choose the scene **stage1** under "Review". Each of the five proposals was assessed at submission through the child.
2. "Sign in as Committee member R1", then the assignment of proposal 1001.
3. Declare "No, I have no conflict of interest" (R-CF-02). The content shows, then the **Assessor findings** panel, then the score sheet.
4. The panel states that the findings come from an AI system and never decide, and names the synthetic assessor. Each finding shows its kind, severity and statement, with "Agree" and "Dispute". A mark is recorded through `review.mark_finding` and the panel shows it. No confidence is shown.
5. Proposal w (`b01-direct`) and v (`b02-hidden`) carry integrity findings for the injected text and the hidden characters. The injected text is treated as data and never as an instruction (TH-01).

### Coordinator: the pending count (I-10)

1. Same scene, "Sign in as Coordinator C1", then the call board from the home page.
2. Below the board, **AI assessment** lists each submitted proposal with "N findings" or "Findings pending". It shows no statement, kind or severity.

## What this lane built

### L-UI (web)

- `web/src/precheck/page.ts`: the pre-check page and the "Check my draft" link of the draft page.
- `web/src/findings/panel.ts`: the reviewer's findings panel and the coordinator's assessment status.
- `web/src/findings/model.ts`: closed decoders. A reply with a `score`, `band`, `weight` or `confidence` member is refused, not shown.
- `web/src/findings/messages.en.ts`: every string, with `TODO(legal)` on the AI disclosure wording.
- `web/src/gen/api.ts`: regenerated with `gen-ts`.
- Small mount edits in `web/src/applicant/{app,client,workspace}.ts`, `web/src/reviewer/pages.ts` and `web/src/coordinator/pages.ts`.

### L-DEMO (e2e cell)

- `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/assess.rs`: the `--assessor` flag, the child link, the corpus narratives and the assessment at submission.
- `scenario.rs`: the narratives of the five review proposals come from the corpus (contact block left out). `submit` is split into `draft` and `submit_one`, and each submission is assessed at once. The new applicant scene `DRAFT`.
- `demo.rs`: the `DRAFT` scene link. `main.rs`: the flag and the link, a few lines.
- `tools/demo/run.sh`: builds `fstp-assessor` too (one line).
- `e2e/assess/assess_click_through.spec.ts`, and the `DRAFT` scene in `e2e/navigation/click_through.spec.ts`.

### Slice of L-CELL (taken by this lane)

- `crates/fstp-assessor/src/intake.rs`: the cell side of the queue. `CellJob::prepare` runs stages 1 and 2 in the cell and writes the job with stripped bodies only. `decode_result` accepts only the closed result shape against its job. `CellJob::intake` maps spans back to the original text. `Link` runs the child over a Unix socket as its stdin, or the synthetic model in process for tests.
- Fuzz target `assessor_result_decode` with seeds.
- The e2e cell records each validated finding through `FindingCommand::Record` under a system actor and the call's pin. Nothing else from the assessor reaches the engine.

It sits in `fstp-assessor`, not in `crates/fstp-cell/src/assess/`, because `fstp-api-testkit` cannot depend on `fstp-cell`. The real cell can call the same module. Not built: traces with sealing and their deletion job, regeneration, `config_id` derivation at publication, the migration.

### Slice of L-PRE (taken by this lane)

- `proposal.precheck` (POST `/proposals/{proposal}/precheck`) and `proposal.precheck_runs` (GET, same path): web only, no MCP tool, the drafting team only (lead, team member, guardian) and only on a draft. Registry, read rule, reply shapes, reference authz rows (`R::DraftingTeam`).
- `assess.findings_status` (GET `/calls/{call}/findings-status`) for the coordinator.
- `crates/fstp-api-core/src/dispatch/precheck.rs`: P-23 limits read from the frozen P-23 value, counted when requested, per rolling day and per call per proposal, and per account across drafts in the call (TH-29).
- `crates/fstp-api-core/src/content.rs`: the request log beside the workspace.
- `crates/fstp-api-testkit/src/fake/precheck.rs`: the `Precheck` port over the assessor. Runs stay beside the draft, never in the `FindingStore` (I-21).
- `port.rs` (lead-owned, additive only): `PrecheckSnapshot.pin` (`PrecheckPin`: call, config, model, P-01 criteria, endpoint), and `PrecheckFinding.element`. The port cannot read the engine state, so dispatch passes the pin.
- `review.findings` rows gained `assessor` (`synthetic` or `model`), so the panel can name a demo run.

Not built: operator usage counts (`assess.precheck_usage`), deletion of runs when the call closes, sealing of the workspace store.

## Tests (each names its ID)

| ID | Test |
| --- | --- |
| I-10 | `i10_result_with_score_member_is_refused`, `i10_score_like_statement_is_refused`, `i10_criterion_and_element_outside_the_pin_are_refused`, `i10_result_of_another_job_is_refused`, `i10_garbage_lines_are_refused` (`fstp-assessor/tests/intake.rs`); `i10_findings_status_shows_counts_only` (`fstp-access`); `i10_findings_status_refuses_a_statement` (web); `i10_coordinator_sees_counts_only` (Playwright) |
| I-11 | `i11_demo_findings_enter_through_record_under_the_pin` (e2e cell) |
| I-21 | `i21_precheck_ops_are_not_exposed_through_mcp`, `i21_precheck_runs_read_is_the_drafting_team_only` (`fstp-access`); the direct authz matrix over `proposal.precheck`, `proposal.precheck_runs`, `assess.findings_status` and `review.findings` |
| TH-02 | `th02_precheck_reply_has_no_score_member` (`fstp-access`), `th02_precheck_reply_with_a_score_member_is_refused` (web) |
| TH-29 | `th29_account_cap_across_drafts` (`fstp-api-core`), `th29_no_check_left_offers_none` (web) |
| P-23 | `p23_daily_limit_and_next_instant`, `p23_call_limit_is_final`, `p23_limits_read_from_the_frozen_value` |
| R-LA-01 | `r_la_01_child_link_runs_the_binary` |
| R-LA-02 | `r_la_02_intake_maps_evidence_to_the_original_text`, `r_la_02_evidence_outside_the_job_is_refused` |
| R-LA-03 | `r_la_03_review_findings_decode_and_drop_confidence` (web), `r_la_03_reviewer_marks_findings` (Playwright) |
| R-LA-06, R-LA-08 | `r_la_06_precheck_view_decodes`, `r_la_08_disclosure_labels_exist` (web), `r_la_06_applicant_checks_the_draft` (Playwright) |
| R-NF-10 | `r_nf_10_pending_and_missing_binary_make_no_finding`, `r_nf_10_unreachable_assessor_records_nothing` |
| Privacy | `privacy_canaries_never_reach_the_job_line` |

## Decisions and open questions for Daniel

Decisions made tonight, each the strict and quick option:

1. **Queue transport.** Open question (socket versus stdout) not settled. The code does what `fstp-assessor` already does: one Unix socket pair passed as the child's stdin, result lines back on the same socket, stdout unused.
2. **Trust anchors.** Open question (ADR-009 versus ADR-019) not settled. Nothing here reaches a network endpoint. `--assessor live:` is refused in the demo cell.
3. **System cause.** Findings are recorded under `Actor::System(SystemCause::Timeline)`, as the M2 harness does. The domain has no assessor cause. An `Assessor` cause would make the audit trail clearer; it needs a domain change.
4. **Where the cell side lives.** In `fstp-assessor` (`intake.rs`), next to the queue decoder it answers, so the real cell and the test cell share one validator.
5. **P-23 counting.** The API core counts requests when they are made, in the content store beside the workspace. "Per day" is a rolling 24 hours. With `account_cap_across_drafts_in_call`, both limits also apply per account across the call's drafts. `Precheck::quota` of the port is not used.
6. **Guardian.** The guardian is on the team for the pre-check, as the registry's TEAM and the reference model say. The workspace save excludes the guardian; the two differ. Please confirm.
7. **Refusal of an outsider.** Outside the drafting team, `proposal.precheck` refuses as the wrong actor, which the authz matrix expects. Over the limit it answers `rate_limited` with rule P-23.
8. **Pending.** A proposal with no recorded finding reads "Findings pending". A trace record from L-CELL will tell "assessed, none found" apart.
9. **Confidence.** The synthetic model reports none, so its findings carry confidence 0. The reviewer panel never shows confidence.
10. **Narratives.** The five review proposals keep their titles and summaries; their narratives are corpus items without the contact block: x `b01`, z `b02-omission`, w `b01-direct`, v `b02-hidden`, u `b01-inflated`.
11. **Element on pre-check findings.** `PrecheckFinding.element` names the rubric tag, so the page can say which element is missing. The stored `Finding` has no element, so the reviewer panel does not show one.

Open questions:

- **Q38 Guide note.** Done per cell by lane m7/guide-note; see "Q38 Guide note: decisions" below.
- **AI disclosure wording.** `TODO(legal)` in `web/src/findings/messages.en.ts` (AI Act Article 50).
- **Name stripping (Q4).** The demo uses an empty name mask; the corpus contact block is left out of the narratives instead.
- **Run deletion.** Pre-check runs are not deleted when the call closes or the applicant withdraws yet.

## Q38 Guide note: decisions

Lane m7/guide-note, 2026-11-12. Interim, pending Daniel.

1. **Per cell, not per milestone.** The note goes where the cell has a pre-check provider. `GuideFacts`, `GuideSource` and `GuideInputs` carry `precheck_available`. `bind` copies it into the bound `Template`, and the renderer reads it there. The e2e and demo cells set it from `PortPresence::precheck`, which is true by default. A cell without a provider keeps the Q38 C note.
2. **What the Guide says with the port.** The template step stays byte for byte. After it come two fixed paragraphs of class `guide-note`: `PRECHECK_AVAILABLE` and `PRECHECK_LEGAL`. The first says the check is available and where to find it. It says the applicant is interacting with an AI system, not a person. It says the check gives findings, never a score, a band or a decision. It says each run counts towards the limits above, that only the team sees results, and that the submission is assessed afresh.
3. **The P-23 limit is not restated.** The template step just before shows `{{P-23.per_day}}` and `{{P-23.per_call}}` as locked values bound from the call. The paragraph points to "the limits above" and holds no number. So no parameter-bound text stands outside the bindings, and `bound()` stays one entry per placeholder (I-51).
4. **Legal wording.** `PRECHECK_LEGAL` is a visible `TODO(legal)` line asking for approval of the AI interaction disclosure (R-LA-08, `ai-act.md`). It follows the template's own visible markers in sections 10 and 11. No article is cited. The profile's `legal_wording_pending` reads only the template, so this renderer line does not make `LegalWordingPending` fail. Open question below.
5. **I-51, I-52, I-53.** The canonical document holds the paragraph as `["note", ...]` lines, so the digest covers it and the two flag values never share a digest. A published Guide is stored in its entry and never bound again (I-53). So Guides already published keep the note and their digest. Only Guides published after this change carry the paragraph. No snapshot or digest test was weakened. The tests that build inputs by hand pass `false` and keep their old expectations.
6. **Previews.** The creator's Guide scan and the public text preview pass `false`. Neither shows the note: the scan reads sections and bindings, and `preview_text` shows template blocks only.
7. **Tests.** `fstp-guide` `r_ga_01_precheck_note.rs`: both flag values, the order after the step, the canonical document, the digest input differing, and no paragraph without the step. `fstp-api-testkit` `i51_published_guide_snapshot.rs`: I-51 bytes unchanged under a live P-05 edit with the port, and the published page following the flag. `r_ga_01_fake_cell_stores_the_guide.rs`: the fake cell stores the paragraph with its digest over the canonical document, and a cell without the port keeps the note. Playwright `applicant/find_and_draft.spec.ts` `r_la_08_...`: the applicant's Guide shows the paragraph and not the note.

Open questions:

- Should the renderer's `TODO(legal)` line count towards `legal_wording_pending`, so an approved profile still waits for the disclosure wording?
- Should the paragraph restate the per-day number itself? That needs a second bound occurrence of `{{P-23.per_day}}` outside the template.
