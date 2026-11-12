# Fast flow: the knock-out criteria and the early decision

Written in lane `m4/fast-flow` on 2026-11-12. It records what the lane built for the demo, how to run it, the decisions taken alone while Daniel was away, and what is still open. Read it with `docs/handoff/presentation-walkthrough.md`, section "Fast flow: criteria and the early decision (4 minutes)".

Every person, proposal and text in the demo is synthetic.

## The request and the decision

Daniel asked for "a fast-flow early decision that includes criteria that the coordinator can set up".

In the spec the early decision is the knock-out check: `SPEC/02-domain/state-machine.md` rows SUBMITTED to INELIGIBLE and SUBMITTED to STAGE1, R-EV-01, and P-09 in `SPEC/02-domain/policy-parameters.md`. The roles table of `SPEC/02-domain/roles-and-sod.md` gives the writing of the criteria to the call drafter (Drafting) and the check to the FSTP coordinator (Judging). SoD-01 forbids one person to hold Drafting and Judging roles in one programme.

**Decided by Daniel on 2026-11-12:** the call drafter writes the knock-out criteria, as the spec says, and nothing in the spec changes. The FSTP coordinator applies them. The demo exercises the writing of the criteria by the call drafter, and the criteria the drafter writes are the ones the coordinator checks.

## What the lane built

### The live chain

1. **Scene `fast_flow`** (`/demo/fast`): the SuperSAFE programme, active, with call 1 "SuperSAFE open call 2026" in DRAFT, drafted by "Call drafter D1". No proposal exists yet. Seeded in its own module, `crates/fstp-api-testkit/src/bin/fstp-e2e-cell/scenario/fastflow.rs`.
2. **The criteria.** D1 signs in and clicks "Knock-out criteria of programme 1" on Home. The new page `/app/programmes/1/studio/knock-outs` (`web/src/studio/knockouts.ts`) shows the current P-09 criteria by their text, one text box each, with "Add an item to Knock-out criteria (P-09)" and a remove button per item. "Save the knock-out criteria" sends `creator.save_fields` with this one field.
3. **Approval and publication.** Programme manager M1 clicks "Programme set-up of programme 1", then "Open approval and publication". The page now lists call 1 as DRAFT and fills in its number. M1 presses "Approve the publication of this call", then "Publish this call" and confirms the step-up. The call freezes the criteria D1 wrote (I-12).
4. **Submissions.** On `/demo`, "Submit the synthetic proposals to call 1" drafts and submits proposals 1001, 1002 and 1003 to call 1, each as its lead, through the production commands the review seeds use. It refuses before call 1 is published, and a second press changes nothing. Each lead then gets a "Sign in as" link.
5. **The early decision.** Coordinator C1 opens the mailbox line on Home, then "Check the knock-out criteria of new proposals in call 1", which opens the intake queue. For each proposal C1 declares no conflict (R-CF-02), then opens "Go to the knock-out check of proposal …". The criteria show by their text, in P-09 order. A failed criterion needs a reason (R-EV-01). A failure makes the proposal INELIGIBLE. A pass records the check, and the proposal waits in SUBMITTED for its reviewers.
6. **The applicant.** The lead of the failed proposal sees "Not eligible" and "Reason recorded by the FSTP coordinator: …" on the proposal page (O-54). The mail on `/demo` names the proposal, its state and a link, never the reason or the criteria (I-27).

### Changes outside the demo

| Where | Change | Why |
| --- | --- | --- |
| `fstp-domain` `policy::check_edit`, `rules.rs` | An `EditPolicy` whose only change is P-09 admits a call drafter as well as a programme manager. Any other change still needs a programme manager. | Roles table: the call drafter writes the knock-out criteria. Before this, only a programme manager could. |
| `fstp-domain-testkit` `reference/policy.rs` | The policy reference reads the same rule. | The reference follows the roles table. |
| `fstp-creator` `decide.rs` | A `SaveFields` of P-09 alone admits a call drafter. It is also the one save an active programme takes: it composes the core `EditPolicy` and records no creator record, since the draft is sealed at activation. | The criteria are written after activation, while a call is in DRAFT. |
| `fstp-creator` `draft.rs` | `draft_view` of an active programme reads every policy field from the head policy. `manual_wording` names typed P-09 texts. | The page shows the criteria in force. Typed texts are stored like template texts. |
| `fstp-api-core` `creator_ops.rs` | Typed P-09 texts in `creator.save_fields` are stored as public texts first, then named by reference (ADR-007). | Before this, a typed P-09 text was refused as inline wording. |
| `fstp-access` `reads.rs`, `registry.rs`; `fstp-api-testkit` `reference/authz.rs`, `matrix.rs` | `creator.get_draft` also admits a call drafter of the programme. The report and the other draft reads do not. | The drafter reads the criteria before writing them. |
| `fstp-domain` `decision.rs`; `reference/lifecycle.rs` | A failed knock-out enqueues `OutboxEvent::ProposalOutcome` with state INELIGIBLE, before the transition. | The lead gets the outcome mail, ids and a link only (I-27). Nothing emitted this event before. |
| `fstp-api-core` `dispatch.rs`, `model.rs`; `fstp-access` `replies.rs`; `web/src/gen/api.ts` | `proposal.view` and `proposal.list_own` carry `knock_out_reason` for an INELIGIBLE proposal, read through the web. | O-54: an INELIGIBLE proposal shows the recorded knock-out reason. |
| `web/src/home/model.ts` | Home links "Knock-out criteria of programme N" for a call drafter. | Click path from sign-in. |
| `web/src/studio/pages.ts`, `model.ts` | "Approval and publication" lists the calls in DRAFT or APPROVED from `call.list` and fills in the first call number. | M1 reached a DRAFT call only by typing its number. |
| `web/src/applicant/proposal.ts`, `wire.ts` | The outcome panel shows the recorded reason. | O-54. |

### Tests

- `crates/fstp-domain-testkit/tests/r_pc_03_call_drafter_writes_the_knock_out_criteria.rs`: the drafter writes P-09, the call freezes it, the drafter changes no other parameter, and a P-09 change after an approval needs a new approval.
- `scenario/fastflow.rs` test `r_ev_01_r_pc_03_fast_flow_chain_checks_the_criteria_the_drafter_wrote`: the whole chain through the API core on one cell state.
- `matrix.rs` `r_pg_01_draft_reads_open_to_managers_and_admins`: the drafter reads the draft and not the report.
- `e2e/fastflow/r_ev_01_r_pc_03_r_nf_03_fast_flow.spec.ts`: the whole flow, clicked from `/demo`.

## Run it

```sh
tools/demo/run.sh                     # then choose "fast_flow" under "Scenes" on /demo
tools/demo/run.sh e2e fastflow/       # the click-through spec
tools/demo/run.sh stop
```

## Decisions taken in the lane

1. **The page.** The criteria get their own page, "Knock-out criteria", rather than the generic evaluation step of the creator. The step page also holds P-01, P-02 and other parameters that the drafter may not change, and it reads the validation report, which the drafter may not read.
2. **Active programme.** The creator stops at activation. The lane opened one path after activation: a save of P-09 alone. It records the new policy version through the core and no creator record. P-01 stays closed after activation. Daniel may want the same path for P-01 and the call text.
3. **Who may save P-09.** A programme manager or a call drafter of the programme. The domain checks it again: a drafter's version must differ from the head in P-09 only.
4. **Approval after the change.** The domain already returns an approved call to DRAFT when P-09 changes (R-PC-03 NOTE), and the drafter becomes the last author of P-09. The scene starts with call 1 in DRAFT, so the demo shows one approval.
5. **The pass.** A passed check leaves the proposal in SUBMITTED. Admission to STAGE1 also needs P-03 reviewers declared without conflict (R-EV-02), which section 3 of the walkthrough shows. The fast flow stops at the passed check.
6. **The outcome mail.** The lane made a failed knock-out enqueue the existing `ProposalOutcome` event. Its mail template already existed and names the proposal, the state and a link. The calibration lane counts this event as the outcome notice (I-37), so a lead of an INELIGIBLE proposal may now be asked for calibration consent.
7. **The reason on the applicant page.** The reason is a confidential text of the proposal. The API core shows it only from the text it remembered when it stored it, and only to web callers. A restarted cell shows "Not eligible" without the reason until a durable read exists.

## Open points for Daniel

- Whether P-01 and the call text should take the same path after activation as P-09 (decision 2).
- Whether an INELIGIBLE proposal's outcome notice should open calibration consent (decision 6). If not, the calibration lane needs a state filter.
- The reason read needs a durable source in a production cell, such as a read of the `KnockOutRecorded` text through the text store with a clearance (decision 7).
- TODO(legal): any wording that should accompany a not-eligible notice to an applicant, such as the right to complain.

## Decided by Daniel on 2026-11-13

- P-01 and the call text do not take the P-09 path. After activation only the knock-out criteria change through a call drafter's save.
- An INELIGIBLE proposal's outcome notice does not open calibration consent. The calibration side needs a state filter that leaves INELIGIBLE proposals out (I-37).
- The reason read gets a durable source: the `KnockOutRecorded` text, read through the text store with a clearance.
- Wording beside a not-eligible notice, such as the right to complain: on hold. The `TODO(legal)` stays.
