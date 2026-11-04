# 05. Programme staff and programme set-up

Status: draft, updated with Daniel's decisions of 2026-11-01. Prototypes: `coordinator-conflict.html`, `coordinator-conflicts-list.html`, `stage1-close.html`, `planning-studio.html` ("Programme set-up"), `seal-ceremony.html` ("Approval and publication"), plus `home-coordinator.html`.

## Purpose and audience

FSTP coordinators, programme managers, call drafters and tenant admins. The UI enforces the order the rules require, so staff cannot skip a step by accident.

## Coordinator: conflict, then read, then record

Page title "Eligibility check (knock-out) for SSF-2024-OC2". An ordered stepper with three steps.

1. **Declare conflicts.** One row per SUBMITTED proposal with the title and the neutral summary (`m4-design.md` §2.2 J5, Q9). Buttons "No conflict" and "Declare conflict". A declared conflict shows "Conflict declared: reassigning (SoD enforced)" with no identity.
2. **Read applications.** Locked until every row is answered. The control has `aria-disabled="true"`, no href, a dashed border, a lock glyph on the step and a reason line.
3. **Record knock-out result.** Appears only after read access. Radios: "All criteria passed. Admit to Stage 1 evaluation (STAGE1)." or "A criterion failed. Mark as Not eligible (INELIGIBLE)." A reason is required for a failure.

The server enforces the same order. The UI only mirrors it (I-92).

## Notifiable conflicts list

Prototype: `coordinator-conflicts-list.html` (`m4-demo.md` J5 step 6, `spec-questions.md` item 19). It lists the conflict drafts that reviewers declared in the current call. Columns: Proposal id (pseudonymous), Declared by, Declaration date, Status (Draft or Submitted). "Declared by" always reads "Reviewer". A callout explains R-CF-04: the coordinator sees the draft only, with no identity detail.

## Stage 1 close

- Shows the computed outcome: "Proposals selected for Stage 2: 4. Proposals not selected: 3." with a breakdown table and plain stage badges.
- Threshold P-02 is stated, "strictly above 75.00%". A proposal at exactly 75.00% goes to NOT_SELECTED (I-08).
- "This outcome is computed from reviewer scores. You cannot change it. (R-LA-03)"
- One action: "Confirm this outcome". No alternative is offered (R-JV-10, NOTE 3).
- Warning: "Confirming will send non-selection notices to 3 applicants." Notices go within P-08.

## Queue health

Per-state counts and pseudonymous ids before conflict declaration. No titles and no applicant data (O-57; `12-journey-ui.md` §8.3). An overdue callout names the longest wait: "1 proposal in SUBMITTED for 12 days". Scope (Q6, Daniel's decision, 2026-11-01): counts cover only programmes where the person holds the coordinator role, grouped per programme and call.

## Programme set-up

The spec name is Planning Studio (`12-journey-ui.md` §8.2). The page title is "Programme set-up" with "Spec name: Planning Studio" as a secondary line (`spec-questions.md` item 12).

Set-up is per programme, not per call. It holds the 11 creator steps in the order of `m4-design.md` §3.1 and `12-journey-ui.md` §8.2. The design groups them under five plain headings. Each heading carries the spec studio name as a `.voyage-label` line.

| Plain group heading | Studio name (secondary) | Steps |
| --- | --- | --- |
| Funder and identity | Surveying the territory | 1 Funder and instrument, 2 Programme identity |
| Eligibility and scope | Border rules | 3 Eligibility, 4 What we fund |
| Evaluation, money and contract | Instruments | 5 Evaluation, 6 Money, 7 Contract |
| Support, people and communications | Support and crew | 8 Support and complaints, 9 People (live SoD checks), 10 Communications |
| Review and approval | Charter seal | 11 Review |

The prototype shows step 6 Money as the current step.

- The sidebar is a `<nav aria-label="Set-up steps">` with check, dot and open circle glyphs plus hidden status words. The current step has `aria-current="step"`.
- Validation refuses a save that breaks an invariant. Example: a cap per recipient (P-05) of 400 000.00 EUR above the funder ceiling (P-58) of 300 000.00 EUR is refused under I-50 (`m4-design.md` §3.2, CapAboveCeiling). The error summary has `role="alert"` and links to the field.
- Provenance hint under an imported value: source document, page and the person who confirmed it (I-65).
- A programme with validation failures cannot be activated. Warnings need an acknowledgement (I-66).
- Previews: progress map preview (R-JV-08), Guide for Applicants preview (R-GA-01) and public page preview.
- Amount inputs take decimal strings with `inputmode="decimal"`.

## Approval and publication

The spec name is the seal ceremony. The page title is "Approval and publication". Activation comes before publication.

### Step 1: activate the programme

The builder submits the programme with a clean validation report (I-66). A tenant admin outside the builder set approves with a passkey confirmation (`m4-design.md` §2.2 J1, I-67). The builder cannot choose the approver, so the page has no approver select. The prototype shows "Activated", approved by `admin-0f5c`.

### Step 2: approve and publish the call

1. The drafter (`drafter-d1e8`) requests approval. Status: "Awaiting approval from a non-drafter (R-PC-03)."
2. A different person (`pm-m2c7`) approves. The page shows the approver handle and time. Call state becomes APPROVED.
3. "Publish call" becomes available. Publishing recomputes the validation report, which must be clean, and generates the Guide for Applicants (I-52). It freezes the policy version (I-12) and needs a passkey confirmation (`m4-design.md` §2.2 J3).

### Change after approval

An edit to the call text, P-01 or P-09 after approval returns the call to DRAFT. Approval must then be requested again. The page says so before the save.

## Copy keys

`staff.eligibility.title`, `staff.eligibility.order_note`, `staff.eligibility.step.conflict`, `staff.eligibility.step.read`, `staff.eligibility.step.record`, `staff.eligibility.conflict_declared`, `staff.eligibility.locked_reason`, `staff.eligibility.ko.pass`, `staff.eligibility.ko.fail`, `staff.eligibility.ko.reason`, `staff.stage1.title`, `staff.stage1.computed`, `staff.stage1.cannot_change`, `staff.stage1.confirm`, `staff.stage1.notice_warning`, `staff.queue.title`, `staff.queue.overdue`, `setup.title`, `setup.spec_name`, `setup.group.*`, `setup.step.*`, `setup.error_summary`, `setup.provenance`, `setup.previews`, `setup.next`, `approval.title`, `approval.activation.title`, `approval.activation.approved_by`, `approval.call.request`, `approval.call.awaiting`, `approval.call.approved_by`, `approval.call.publish`, `approval.after_approval_note`.

## Accessibility notes

- Locked steps are not focusable and carry a reason. A disabled control without a reason is not allowed.
- Steppers are ordered lists, so the step number is announced.
- The error summary receives focus on load after a failed save.

## Spec IDs

R-CF-02, R-CF-04, R-LA-03, R-PC-03, R-JV-08, R-JV-10, R-GA-01, I-07, I-08, I-12, I-50, I-52, I-65, I-66, I-67, P-02, P-05, P-08, P-10, P-58, SoD-07, O-57.

## Open points

- Resolved on 2026-11-01: "Programme set-up" for Planning Studio and "Approval and publication" for the seal ceremony (item 12), and the queue count scope (item 6).
