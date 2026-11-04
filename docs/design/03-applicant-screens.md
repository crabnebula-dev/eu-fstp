# 03. Applicant surfaces

Status: draft, updated with Daniel's decisions of 2026-11-01. Prototypes: `calls-public.html`, `call-detail-public.html`, `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html`, `auth-signin.html`, `plan-editor.html` ("Your proposal"), `packing-check.html` ("Pre-submission check"), `submission-receipt.html`, `stage2-questions.html`, `negotiation.html`, `end-states.html` ("Final outcomes").

## Purpose and audience

Applicants, team members and grantees, often small organisations applying once. Every screen names the current stage with its plain label and formal state, and offers one primary action. The Voyage pack label, where shown, is a secondary line.

## Screens

### Open calls list (public)

- Works with scripts off (R-PB-04). Keyword search is a GET form.
- Card per call: programme, call title, call id, status badge (Open, Closes soon), grant range as decimal strings, deadline with zone.
- States: results, no results ("No open calls match {q}"), no open calls at all ("There are no open calls right now. Calls open {cadence}.").

### Call detail (public)

Prototype: `call-detail-public.html` (`m4-demo.md` J4 step 4, `spec-questions.md` item 18). Works with scripts off.

- Header with a minimal navigation: "Back to calls", "Call details" (current page) and "Sign in".
- Call title, call id and status badge.
- Open and close dates in two zones: the call's own zone and UTC. A public visitor has no profile zone, so UTC is the second zone.
- Total call budget and grant range as server text decimal strings.
- Eligibility summary: the three P-09 rules in plain words.
- AI disclosure block, "Use of AI tools" (R-LA-08). The wording is a placeholder with a TODO(legal) comment.
- "Sign in to apply" and "Create an account".

Not yet in the prototype: the static progress map with no script (R-JV-06) and the Guide link. The map on a public page uses the same renderer with no current position.

### Sign-up, check email, passkey enrolment and sign-in (public)

Prototypes: `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html`, `auth-signin.html` (`m4-demo.md` J0 and J4 steps 2 and 3, `spec-questions.md` item 16).

- Sign-up: one email field, "Send confirmation link", and a link to sign in. Terms and privacy wording is a TODO(legal) comment.
- Check your email: a static confirmation naming the synthetic address. No resend control, because resending needs script. The email body is a TODO(legal) comment.
- Create a passkey: a device name field, a disabled "Create passkey" button with a reason, and a table with one enrolled device. The button needs WebAuthn script, marked TODO(js). Consent text is TODO(legal).
- Sign in: a disabled "Sign in with a passkey" button with a reason (TODO(js)), a "Use a different device" link and an access terms TODO(legal) comment.
- The public navigation marks "Sign in" as the current page on all four.

### Proposal editor (DRAFT)

- Page title "Your proposal (DRAFT)", with a static "Last saved 14:32" line under it. The product autosaves the title, the neutral summary and the narrative (I-21, `m4-demo.md` J4 step 5).
- A "Proposal steps" navigation: 1. Plan, 2. Eligibility, 3. Submit. The current step carries `aria-current="step"`. Each panel has a top divider and a step badge (Current step, Next step).
- Plan: Project title (required), "Neutral summary, visible to reviewers before conflict declaration" (500 character limit, count "482 / 500 characters"), Narrative (required), Objectives (required), a milestones table and an amounts table.
- Milestones: a two-row example with name, start, due and amount. "Add milestone" and "Remove milestone {n}" are submit buttons, so no script is needed. Amounts use two decimals; 1500.5 is refused.
- Amounts requested: cost categories and a server-computed total that matches the milestones.
- Eligibility: three yes or no questions. The answers go to the vault only (R-NG-01). A No that may exclude the proposal shows the callout "This answer may make your proposal ineligible."
- Submit: ticks for "I confirm the information above is accurate" and "No ethics issue", then Submit. The confirmation wording is a TODO(legal) comment. `m4-demo.md` J4 step 8 also names the data protection notice tick, which stays in that comment.
- Late submission refused: a "Submission closed" banner, the past deadline in two zones (§7.4), and "The deadline for this call has passed." in place of the button.
- Team members are managed on the Team page.
- Error pattern: `aria-invalid="true"`, a thicker border and an "Error:" prefixed message linked by `aria-describedby`.
- Submit is disabled until every required field is complete. A visible line explains why.
- Pre-submission check panel beside the form: findings with Info, Warning and Error badges. "Findings only, not scores (R-LA-06)." The spec name for this check is the packing check (`spec-questions.md` item 12).
- Deadline clock: "Call closes in 14 days", in the deadline's own zone and the viewer's zone (`12-journey-ui.md` §7.4).

### Team page

Not prototyped. List of team members by handle and role in the team. Invite by email. Removing a member asks for confirmation. Personal details stay in the vault.

### Submission review and receipt

- Review: a read-only summary of the proposal with "Submit" and the pre-submission check result.
- Receipt: proposal id, call, submitted time in UTC, ledger sequence, audit anchor (R-JV-04, O-56).
- The receipt also records the data protection notice version shown and acknowledged (R-NG-06) and the ethics self-declaration (R-SB-05). Notice text is TODO(legal).
- Until the anchor is witnessed: "Anchor pending (ADR-015 O-56)" info badge, no anchor value, and "Reload this page later to see it." (§7.4.)
- "Email a copy" form. The email holds ids and times only, never proposal text (I-27, R-SB-04).
- Next steps: "What happens next: your application is now with the FSTP coordinator for an eligibility check."

### Stage 2 questions (STAGE2)

- Window clock as a prominent card: "8 days 4 hours". `role="timer"` with `aria-live="off"` so it does not interrupt.
- States the consequence: if the window (P-07) ends without answers, the proposal moves to Deferred to the next call (DEFERRED). This follows the STAGE2 to DEFERRED row (state machine NOTE 4).
- One fieldset per question, legend "Question 1 from reviewer-7f3a". Reviewer handles only (P-11).
- Save answers (draft) and Submit answers.
- "Your answers are seen by the assigned reviewers and the FSTP coordinator."

### Negotiation (NEGOTIATION)

Read-only in M4 (`m4-design.md` §2.2 J4). Ordered steps: identity check (vault outcome only, R-CF-03), guardian consent, data protection notice (version acknowledged, R-NG-06), grant amount with milestones, grant agreement. Guardian consent does not apply to adults. For minors the applicant sees "Waiting for your guardian" and the guardian sees the consent step (O-60).

- The agreement summary sits in `<details>`. The diff between versions uses `<ins>` and `<del>` with the words "Added:" and "Removed:".
- Agreement text is TODO(legal).
- "Accept and sign" stays disabled. The reason line says signing arrives after M4. When built, signing needs a passkey confirmation (ADR-014 step-up).

### Final outcomes

Headings use the plain label. The Voyage pack label is a secondary line (`12-journey-ui.md` §5.2).

| State | Heading | Voyage line | Shows | Never shows |
| --- | --- | --- | --- | --- |
| INELIGIBLE | Not eligible | Route closed at the border | Knock-out criterion and recorded reason, complaint link with window | Scores (none exist, O-54) |
| NOT_SELECTED | Not selected | Route ended | Reason, scores and comments with anonymous handles (O-54), complaint window | Reviewer identities |
| DECLINED | Declined | Route ended | Recorded reason, scores and comments (O-54), complaint link | Reviewer identities |
| WITHDRAWN | Withdrawn | Route ended | Date withdrawn, "Start a new proposal" | Scores and comments (O-54) |
| COMPLETED | Completed | Safe harbour | Proposal history PDF download (O-59), public visibility choice | Nothing withheld beyond normal rules |
| TERMINATED | Grant terminated | Route ended | Recorded reason, proposal history PDF, complaint path TODO(legal) | Internal deliberation |
| DEFERRED after an IRC concern | Your proposal has been deferred | Wintering for the next voyage | Why it was deferred, "Rules of {original call}, version {n}" with a "View frozen rules" link, the reconsideration note | The concern author |
| IRC_REVIEW held for guardian consent (I-18) | Your proposal is on hold | Independent watch | What is missing and where to look | Anything about the guardian (O-60) |

The prototype shows Not eligible, Not selected, Completed, the deferred panel and the on-hold panel (`spec-questions.md` item 23). The other three follow the same pattern. The on-hold notification wording is a TODO(legal) comment.

### Frozen rules of a deferred proposal (Q5)

Daniel's decision, 2026-11-01. A published call's frozen policy version stays readable while any proposal depends on it, even after the call is archived. The overlay shows "Rules of {original call}, version {n}" and links to the frozen version (NOTE 8, R-JV-07).

### Proposal history PDF step-up (Q7)

Daniel's decision, 2026-11-01. The grantee confirms with a passkey before the proposal history PDF downloads. The auditor follows the existing export policy. See `06-profile-page.md`.

### Content rules for negative outcomes

- Lead with what happened in one sentence. Then the reason. Then what the person can do.
- Thank the applicant on NOT_SELECTED and DECLINED. Do not apologise for the rules.
- Never use words like "failed", "rejected" or "unsuccessful" in headings. Use the plain label.
- Always link to the complaint path and to other open calls.

## Copy keys

`applicant.calls.title`, `applicant.calls.search`, `applicant.calls.count`, `applicant.calls.none`, `applicant.calls.no_match`, `applicant.proposal.title_label`, `applicant.proposal.abstract_label`, `applicant.proposal.abstract_hint`, `applicant.proposal.char_count`, `applicant.proposal.objectives_label`, `applicant.proposal.team_label`, `applicant.proposal.team_hint`, `applicant.proposal.save_draft`, `applicant.proposal.submit`, `applicant.proposal.submit_why`, `applicant.precheck.title`, `applicant.precheck.not_scores`, `applicant.precheck.level.*`, `applicant.receipt.*`, `applicant.receipt.anchor_pending`, `applicant.receipt.notice_version`, `applicant.receipt.ethics`, `applicant.receipt.email_copy`, `applicant.receipt.next_steps`, `applicant.stage2.window`, `applicant.stage2.deferred_warning`, `applicant.stage2.audience`, `applicant.stage2.question_legend`, `applicant.stage2.save`, `applicant.stage2.submit`, `applicant.negotiation.*`, `applicant.negotiation.stepup`, `applicant.end.<state>.title`, `applicant.end.<state>.body`, `applicant.end.complaint`, `applicant.end.history_pdf`.

## Accessibility notes

- Disabled submit buttons carry `aria-describedby` to the reason text.
- Character counts sit under the field and are linked with `aria-describedby`. A live update, when built, uses `aria-live="polite"` and announces only at 90 and 100 percent.
- Errors appear in a summary at the top with links to fields, and next to each field.
- Amounts are server-formatted decimal strings, never computed in the browser (ADR-006, R-JV-12).

## Spec IDs

R-LA-08 (AI disclosure on the call page), R-NG-01 (eligibility answers to the vault), I-18, I-21, R-SB-03 (withdraw until signature), R-SB-04, R-SB-05 (submission, receipt and ethics declaration), R-NG-06 (notice version), R-EV-05 (stage 2 questions), R-PB-04 (public pages without script).

R-JV-04, R-JV-06, R-LA-06 (findings not scores), R-LA-03, R-CF-03, O-54, O-56, O-59, O-60, I-27, I-96, ADR-006.

## Open points

- TODO(legal): agreement summary, notice text and complaint window wording.
- TODO(js): passkey create and get steps on the enrolment and sign-in pages.
