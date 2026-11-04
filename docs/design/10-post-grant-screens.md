# 10. Post-grant, complaints, transparency, reporting, support and onboarding screens

Status: draft, 2026-11-01. Sources: `payment-requests.md`, `contracts.md`, `complaints.md`, `public-transparency.md`, `funder-reporting.md`, `support-programme.md` and `programme-creator.md` (onboarding steps). The spec wins over this document.

## Shared shell and language

- All 21 screens use the shared prototype shell: skip link, header navigation with a role chip, one `main` landmark, footer and `../tokens.css`.
- Brand: Horizon Bridges. Programme: SuperSAFE. Call: SuperSAFE Call 1.
- Plain grant language only. These screens carry no Voyage labels, not even as a secondary line.
- Status badges show the plain label with the formal state beside it (I-96).
- Every disabled button has a `TODO(js)` comment and an `aria-describedby` reason. Legal wording sits in `TODO(legal)` comments.
- Amounts use the server-formatted style of the other prototypes, for example "48 500.00 EUR" (ADR-006).

New navigation roles in the generator:

| Role | Role chip | Navigation |
| --- | --- | --- |
| Grantee | Signed in as Grantee | Home, Payments, Agreement, Complaints, Visibility, Support |
| Contract signatory | Signed in as Contract signatory | Home (`home-signatory.html`), Awaiting countersignature |
| Consortium expert (mentor) | Signed in as Consortium expert (mentor) | Home, Mentoring |
| Operations approver | Signed in as Operations approver | Home, Funder reports, Report approvals |
| Public visitor (data) | none | Open calls, Funded projects, Open data, Sign in |

Existing roles gained links:
- Finance: Payment approvals and Payment releases.
- Auditor: Audit trail goes to `audit-log.html`, plus Funder reports.
- Coordinator and IRC: Complaints.
- Programme manager: Contracts and Funder reports.
- Tenant admin: Set-up.
- Applicant: Support goes to `grantee-support.html`.

## Payment requests

Screens: `payment-request-form.html`, `payment-request-review.html`, `payment-release.html`, `payment-status.html`, `payment-checks-failed.html`.

States: DRAFT, SUBMITTED, CHECKS_FAILED, UNDER_REVIEW, CHANGES_REQUESTED, ACCEPTED, PAYMENT_APPROVED, RELEASED, PAID, plus REJECTED, WITHDRAWN and CLOSED.

- **Form.** Tasks appear in plan order with available and total amounts.
  - Each milestone row shows due date, total, available and any pending amount.
  - Each row also has a requested amount, a "Fill available" control, an evidence URL, an SPDX licence and progress notes.
  - A milestone paid in full stays visible with its input disabled and a "Paid in full" badge.
  - A running total sits before Submit.
- **Automated checks** run before human review: public reachability, licence in P-26, line within available (I-58) and evidence rules (P-34).
- **Line review.** The finance approver approves in full, approves a lower amount with a reason, or rejects with a reason. The prototype shows one line in each state.
- **Release.** The payment releaser releases approved requests. Payment mode is record-only in the demo.
- **Prerequisite (Q25).** Org roles must be assigned before subgranting can begin. The tenant admin assigns Finance approver and Payment releaser during onboarding or in `admin-members.html`. The review and release screens carry a callout that links there.
- **Two approval steps (Q25).** ACCEPTED closes the finance approver's line review. PAYMENT_APPROVED is a separate step where the finance approver confirms the request total. Only then can the releaser act.
- **CHECKS_FAILED (Q25).** The request returns to the grantee to correct and resubmit. `payment-status.html` shows a "Checks failed" row with that callout.
- **SoD-04.** Approver and releaser are different people for any single payment. The release queue shows a row the signed-in person approved, with Release blocked and the reason given.
- **Status list.** Five requests in UNDER_REVIEW, CHANGES_REQUESTED, ACCEPTED, PAID and WITHDRAWN. A callout asks the grantee to resubmit the CHANGES_REQUESTED request.

## Contracts after negotiation

Screens: `contract-view.html`, `contract-signatory.html`, `contract-amendment.html`, `home-signatory.html`, `contract-drafted.html`, `contract-advanced-approval.html`, `contract-terminal.html`. `negotiation.html` links to `contract-view.html` and `contract-drafted.html`.

States: DRAFTED, SENT, SIGNED_BY_GRANTEE, EFFECTIVE, AMENDMENT_PENDING, SUPERSEDED, plus TERMINATED.

- **Signature cascade (P-30).** First the EUDI Wallet qualified signature, then a remote qualified signature with the tenant's QTSP, then an advanced signature.
  - The advanced signature needs programme manager approval and a recorded reason.
  - The signature is created in the wallet or with the QTSP, never by the platform.
- **Decline.** The grantee can decline before signature (R-NG-04).
- **Countersignature.** The Contract signatory is an Operations role. SoD-03 keeps it apart from Receiving roles.
- **Immutability.** A signed version never changes. Its hash is in the audit log (I-30).
- **Amendment.** An amendment is a new version, and all parties sign again.
  - Each clause change is shown as a diff with the proposer's role label and date.
  - The proposal state does not change while the amendment is pending.
  - IRC review follows P-14.

## Complaints

Screens: `complaint-file.html`, `complaint-coordinator-review.html`, `complaint-irc-escalation.html`, `complaint-status.html`.

States: FILED, OUT_OF_SCOPE, COORDINATOR_REVIEW, RESOLVED, ESCALATED, UPHELD, DISMISSED.

- **Scope.** Complaints cover procedure:
  - knock-out decisions and conflict handling;
  - missed deadlines or notices and deviation from the Guide;
  - payment rejections, bank-detail holds and hardship refusals.

  They do not cover scores or expert judgement.
- **Windows.** Filing within P-61, coordinator review within P-62, escalation within P-63 and IRC review within P-64. The exact window labels stay `TODO(legal)`.
- **SoD-13.** Nobody who took part in the contested decision reviews the complaint at either level.
- **I-56.** Every complaint gets a reasoned, recorded response within its deadline. Each deadline is a timeline event.
- **I-57.** Filing never changes evaluation, scores or payment status, except through a recorded remedy.
- **IRC level.** At least two IRC members review, and the decision is final. The remedies are re-evaluation by different reviewers, re-entry into the next call, and correction of a payment decision. A remedy never reduces another grantee's award.
- **Visibility.** Records are visible to the complainant, the complaint reviewers and auditors only.
- **Scope decision (Q27).** The coordinator review shows a scope decision above the response. A second static section, "Out of scope view", shows the reasoned response and "Record as out of scope". SoD-13 applies. The complainant can escalate within P-63.
- **Terms and conditions (Q27).** The complaint procedure must be referenced in the participation T&Cs and the application submission T&Cs. TODO(legal): confirm wording. `complaint-file.html`, `complaint-coordinator-review.html` and `complaint-irc-escalation.html` carry the TODO(legal) comment.

## Public transparency

Screens: `public-grants.html`, `grantee-visibility.html`, `public-calls-feed.html`.

- **Opt-in model.** Open calls are always public. Funded and finished subgrants are opt-in.
- **Levels.**
  - Hidden is the default.
  - Project shows the title, public summary, call and status.
  - Project and grantee adds the grantee name.
  - Full adds the granted amount and milestone status.
- **Limits.** The programme sets the maximum level for funded (P-50) and finished (P-51) projects. The grantee chooses up to that limit for each phase. Options above the limit are disabled with "Above programme limit".
- **I-41.** No public page shows anything about a proposal that never reached GRANTED.
- **I-42.** No public page names a minor. `public-grants.html` records this as an HTML comment.
- **Minor on the team (Q26).** `grantee-visibility.html` shows a team with a minor. "Project and grantee" and "Full" are disabled in both phases with "Not available: a team member is a minor (I-42)." Hidden and Project stay selectable.
- **I-43.** Each project is published at the lower of the programme limit and the grantee's current choice. Narrowing or withdrawing applies at once.
- **Aggregates.** Aggregate figures appear only when they cover at least P-54 grants.
- **Public summary.** Written or approved by the grantee, never the proposal text.
- **No tracking.** Public pages carry no tracking scripts and set no cookies. The footer says so.
- **Feed.** The machine-readable feed exists when P-52 is on and applies the same filter.

## Funder reporting and audit

Screens: `audit-log.html`, `funder-report.html`, `report-approval.html`, `report-generation-failure.html`. `home-auditor.html` links to both the audit log and funder reports.

- **I-44.** Every figure reconciles with recorded contracts, payments and payment requests at the snapshot. Generation fails on a mismatch.
- **Report types.** Call publication record, open call package, periodic reporting data, and the audit file per call.
- **Audit file contents.** Knock-out decisions, scores, stage 2 records, ranking, cut-off rationale, IRC validations, conflict declarations, contracts, notices and payment evidence, all with hashes.
- **Approval.** Documents are drafts until a named Operations role approves them. The approver must not be the generator.
- **Record.** Every document records its snapshot hash and template version.
- **No portal submission.** Humans upload approved documents to the funder portal. The platform submits nothing.
- **Audit log.** Events show role labels, object references and truncated hashes. They show no proposal content and no identity attributes. Full export needs step-up authentication. Positive identity matches are visible only to the Auditor role (R-CF-03).

## Support programme

Screens: `grantee-support.html`, `mentor-assignment.html`, `home-mentor.html`.

- **Elements.** Mentoring, presenting results, promotion and visibility, and CRA compliance guidance.
- **Mentoring.** The grantee can end mentoring at any time. Session notes are optional and private to the mentor and the grantee.
- **Presentation slots.** Planned through the timeline engine.
- **SoD-12.** A mentor is never an assigned reviewer for later proposals from the same grantee team. A mentor never accepts payment requests for a mentored grant.
- **I-54.** Every mentoring assignment is recorded in the vault and used in conflict detection in all later calls.
- **I-55.** No commercial offers reach grantees through the platform. Grantee contact data is never used commercially.

## Tenant onboarding wizard

Screen: `onboarding.html`. `home-admin.html` links to it.

- **Steps.** Nine steps in order: Organisation, Agreements, Branding, Domains and email, Identity, Inference, Payments, Channels, Administrators.
- **Gating.** Each step validates before the next opens. The admin can save and return.
- **Prototype state.** Step 1 (Organisation) is current, with synthetic values. Steps 2 to 9 show a "Locked" badge in the step bar.
- **Panels.** All nine steps appear on one page, separated by a divider and a "Step N of 9" label. Each step has a disabled "Save and continue" button. Steps 2 to 9 have a back link to the previous step and the note "This step opens after the previous step is completed and validated."
- **Step 2, Agreements.** SaaS terms and data processing agreement, each signed 2026-10-15 with Download and a disabled Re-sign. Sub-processor list link and change notice. Descriptions are TODO(legal).
- **Step 3, Branding.** Read-only organisation name and light and dark logo slots. Full settings link to `admin-branding.html`.
- **Step 4, Domains and email.** Primary domain and sending address. Detailed settings link to `admin-domains.html`.
- **Step 5, Identity.** EUDI Wallet relying party switch shown on (P-45). Verification methods (P-18): EUDI Wallet and remote qualified. Advanced signature is not listed. A note says it is a P-30 signing route configured in the contract signing flow (Q30).
- **Step 6, Inference.** Hosted endpoint provider and model `fstp-default-v2` (P-21). PII is stripped before inference. The assessor has no write access to domain state.
- **Step 7, Payments.** Record-only selected, Execution available (P-20). The bank interface is disabled outside Execution mode. The platform never holds funds (I-16).
- **Step 8, Channels.** Matrix homeserver shown as reachable. WhatsApp Business must be tenant-owned (O-21). Email stays the durable record for contractual notices.
- **Step 9, Administrators.** Two confirmed admins, a disabled invite and a disabled "Activate organisation". An activation approval panel shows the admin who completed setup and the second admin awaiting approval, with a disabled "Approve activation". Activation needs a second tenant admin who did not complete the setup (Q29).
- **SoD-07.** At least two tenant admins must exist before activation. Self-grants need a second admin.
- **Later changes.** After onboarding, the five admin screens of doc 09 handle changes.

**Q24 resolved.** The onboarding wizard is built as `onboarding.html`, a 9-step wizard (Daniel's decision, 2026-11-01).

## Payment request checks failed

Screen: `payment-checks-failed.html`. The CHECKS_FAILED row in `payment-status.html` links to it with "View details".

- **Content.** Reference PR-2026-0014, submitted date and total. A "Failed checks" table with Check, Result and Detail.
- **Checks.** Deliverable reachable fails (404). Licence detected fails (no SPDX identifier). Amount within available passes.
- **Next step.** The grantee corrects the issues and resubmits. Resubmitting creates a new request reference. "Edit and resubmit" is disabled with a TODO(js) comment.

## Contract draft and advanced signature approval

Screens: `contract-drafted.html` (grantee), `contract-advanced-approval.html` (programme manager).

- **DRAFTED.** The negotiation table lists clause changes with clause, summary, proposer role, date and status. One grantee change is pending programme manager review. One programme manager change is accepted.
- **Diff.** Changes are recorded as a diff against the template. Each names the proposer's role only.
- **Decline.** The grantee can decline before signing (R-NG-04).
- **Advanced signature.** The programme manager sees the contract, grantee, signer and the signer's reason. Approval needs a recorded reason (P-30 step 3) and is logged with account and timestamp. `contract-view.html` links here with "Request advanced signature approval".

## Contract history and terminal states

Screen: `contract-terminal.html`. `contract-view.html` links to it.

- **SUPERSEDED.** Version 1 is replaced by amendment version 2, which is EFFECTIVE.
- **TERMINATED.** A separate panel shows a terminated contract with date and reason. No party signed it, so the draft PDF is sealed and stored at termination. The link reads "Download sealed draft" (Q28).
- **I-30.** Signed versions are immutable. Each content hash is in the audit log.

## Mentor and operations homes

Screens: `home-mentor.html`, `home-operations.html`.

- **Mentor.** Two cards: My assignments (2 active, links to `mentor-assignment.html`) and Upcoming sessions (1 scheduled). SoD-12 note.
- **Operations.** Four queue cards: payment requests to approve, payments to release, contracts to countersign and reports to approve. A person sees a queue for each role held.
- **Separation.** SoD-04: approver and releaser differ for any payment. SoD-03: the contract signatory holds no Receiving role in the same programme.
- **Navigation.** The Operations nav links to all four queues. The Mentor and Operations approver Home links point to the new homes.

## Report generation failure

Screen: `report-generation-failure.html`. The Generate reason on `funder-report.html` names it.

- **Content.** Report name, generation time, snapshot hash and a "Mismatches found" table with Figure, Recorded value, Report value and Source.
- **I-44.** Generation fails when a figure cannot be reconciled with recorded contracts, payments and payment requests at the snapshot. The user corrects the records and regenerates.
- **Support.** A "Contact support" link. The support channel description is TODO(legal).

## Spec IDs

SoD-03, SoD-04, SoD-07, SoD-12, SoD-13, I-16, I-30, I-41, I-42, I-43, I-44, I-54, I-55, I-56, I-57, I-58, I-96, P-14, P-18, P-20, P-21, P-26, P-30, P-34, P-45, P-50, P-51, P-52, P-54, P-61, P-62, P-63, P-64, R-NG-04, R-CF-03, O-21, O-32, ADR-006.
