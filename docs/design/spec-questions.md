# Spec questions

Status: draft. Points where the spec is unclear or seems wrong, found during design. Each has a recommendation. The spec wins until Daniel decides. On 2026-11-01 Daniel decided every open item, so all 23 are now Resolved. Item 24, about tenant onboarding, was opened later on 2026-11-01 and is now Resolved. Items 25 to 27 came from the post-grant build. Daniel decided them on 2026-11-01, so they are now Resolved. Items 28 to 30 came from the build of the remaining screens. Item 31 came from Daniel's signatory roles decision. Daniel decided items 28 to 31 on 2026-11-01, so all 31 items are now Resolved. Items needing spec or backend changes are tracked in `spec-amendments.md`.

Reconciled on 2026-11-01 against `SPEC/12-journey-ui.md` (repository version) and `docs/handoff/m4-design.md`. Reconciled again on 2026-11-01 against `docs/handoff/m4-demo.md`. Items those documents settle are marked **Resolved** with a citation. The others stay **Open**.

## 1. Zone display for deadlines

**Status.** Resolved by `SPEC/12-journey-ui.md` §7.4.

**Question.** Should the UI show a deadline in the viewer's zone and the deadline's own zone, or only the deadline's zone?

**Resolution.** §7.4 shows the next deadline "in the recipient's zone and the deadline's own zone". The design now always shows both, leading with the deadline's own zone. The earlier idea of hiding the second zone when they match is dropped.

## 2. INELIGIBLE and scores

**Status.** Resolved by `SPEC/12-journey-ui.md` §15, O-54.

**Resolution.** O-54 says an INELIGIBLE proposal has no scores and shows the recorded knock-out reason. `end-states.html` already does this.

## 3. WITHDRAWN from DRAFT

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Question.** A proposal withdrawn in DRAFT has no submitted content and no reviewers. Should its activity log entry differ from one withdrawn in STAGE2?

**Reference.** State machine NOTE 10; `SPEC/12-journey-ui.md` §15 O-54 (WITHDRAWN shows no scores or comments).

**Recommendation.** One entry kind with a stage-aware sentence. From DRAFT: "You withdrew this draft before submitting it." After submission: "You withdrew this proposal at {plain stage label} ({STATE}). Reviewers were told it is no longer under review." Neither shows scores.

**Resolution.** Recommendation accepted: one entry kind with a stage-aware sentence. The rule is in `02-voyager-route-diary.md`. No prototype change.

## 4. When "anchor pending" ends

**Status.** Resolved by `SPEC/12-journey-ui.md` §7.4 and R-JV-04.

**Resolution.** The receipt says "anchor pending", shows no anchor value, and gains the anchor when it is witnessed. Showing it on the next page load is a design choice that needs no script. The "Receipt anchored" activity log entry stays as a design proposal.

## 5. DEFERRED overlay when the original call is archived

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Question.** A deferred proposal keeps its original call's frozen policy. If that call is archived, what does the programme overlay show?

**Reference.** State machine NOTE 8; I-12; `SPEC/12-journey-ui.md` §5.5 and R-JV-07 (the overlay uses the original policy). Neither says what happens when the call is archived.

**Recommendation.** A published call's frozen policy version must stay readable while any proposal depends on it. The overlay shows "Rules of {original call}, version {n}" and links to the frozen version.

**Resolution.** Recommendation accepted. The rule is in `03-applicant-screens.md`, and `end-states.html` shows "Rules of SuperSAFE Call 1, version 2" with a link.

## 6. Scope of queue counts before conflict

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `SPEC/12-journey-ui.md` §15 O-57 and §8.3; roles are bound per programme (`roles-and-sod.md`).

**Recommendation.** Only programmes where the person holds the coordinator role, grouped per programme and call.

**Resolution.** Recommendation accepted. The rule is in `05-programme-staff-studio.md`, Queue health.

## 7. Step-up for the chronicle PDF

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `SPEC/12-journey-ui.md` §15 O-59 and §10; ADR-014 step-up seam.

**Recommendation.** Step-up for the grantee, because the PDF collects a whole proposal history in one portable file. The auditor follows their existing export policy.

**Resolution.** Recommendation accepted. The rule is in `06-profile-page.md` and `03-applicant-screens.md`.

## 8. Language of the public progress graphic

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** R-NF-04; R-JV-06 (public pages show static SVG with no script).

**Recommendation.** Render in the visitor's chosen locale, falling back to the tenant default. Formal state names stay untranslated beside the labels (I-96).

**Resolution.** Recommendation accepted. The rule is in `02-voyager-route-diary.md`.

## 9. IRC outcomes versus the state machine

**Status.** Resolved by state machine NOTE 7 and NOTE 13, `SPEC/12-journey-ui.md` §8.3 (R-IR-03, O-58), and `m4-design.md` §2.2 J8 and Q16.

**Resolution.** IRC members choose one of two options: validate, or raise a concern. They see the nominated proposal and outcome only, with no scores, ballots or rationale. A concern leads to DEFERRED when a future call exists, otherwise to DECLINED, recorded by the programme manager. `irc-view.html` now offers exactly these two radios and explains the consequence in a callout.

## 10. Source documents missing from the first pass

**Status.** Resolved. `SPEC/12-journey-ui.md` and `docs/handoff/m4-design.md` were reconciled on 2026-11-01. `docs/handoff/m4-demo.md` was supplied and reconciled the same day.

**Resolution.** `demo-walkthrough.md` now follows the `m4-demo.md` click paths J0 and J4 to J8 in order. Screens in the demo that had no prototype were items 16 to 23. Each now has one.

## Questions added during reconciliation

### 11. Default vocabulary pack

**Status.** Resolved. Daniel's decision, 2026-11-01. O-55 is amended in `SPEC/12-journey-ui.md`, `SPEC/10-open-questions.md` and ADR-015.

**Reference.** `SPEC/12-journey-ui.md` §15 O-55 and §17.2: Voyage is the platform default pack, and tenants can switch to a plain pack.

**Design position.** Daniel asked for plain grant language as the default because "this is STILL a grant process". The prototypes show plain labels as primary and the Voyage label as a secondary line.

**Recommendation.** Amend O-55 so the plain pack is the platform default and Voyage is opt-in per tenant.

**Resolution.** Plain grant language is the platform default and Voyage is opt-in per tenant. O-55 was amended to match on 2026-11-01. See `07-vocabulary-pack.md`.

### 12. Spec metaphor names paired with plain labels

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `SPEC/12-journey-ui.md` §4, §5.2, §7 and §8; `07-vocabulary-pack.md` Catalogue 3.

**Design position.** Where the spec names a surface with a metaphor, the design keeps the name as a secondary line and leads with a plain label. Examples: "Activity log" (spec name: Passage Diary), "Progress map" (Voyager route), "Programme set-up" (Planning Studio), "Approval and publication" (seal), "Pre-submission check" (packing check).

**Recommendation.** Confirm the plain primary labels, or name the ones that must keep the spec term as primary.

**Resolution.** All five pairings are confirmed: "Activity log" (Passage Diary), "Progress map" (Voyager route), "Programme set-up" (Planning Studio), "Approval and publication" (seal ceremony), "Pre-submission check" (packing check).

### 13. Citation for the account-page landing

**Status.** Resolved by `m4-demo.md` "Click paths", J0 steps 2 and 3.

**Question.** Earlier drafts cited "m4-design 15.0 (2026-10-31)" for sign-in landing on the account page. The 15.0 table in `m4-design.md` has a profile page row (`/app/me`) but no row for the sign-in landing.

**Resolution.** The demo script records the current behaviour: after "Create a passkey", the account page lists the session and the device, and sign-out happens there. The landing is current behaviour, not a decision, so no 15.0 row is needed. The design cites `m4-demo.md` J0 and `design-brief.md`.

### 14. Titles before conflict declaration

**Status.** Resolved by `m4-demo.md` "Click paths", J4 step 5, J5 steps 2 and 3, and J6 steps 2 and 4.

**Reference.** `m4-design.md` §2.2 J5 and Q9 (R-CF-02); `SPEC/12-journey-ui.md` §8.3.

**Resolution.** The applicant writes the neutral summary in the workspace, beside the title and the narrative (J4 step 5). Declaration views for the coordinator and the reviewer show only the title and that summary, and the content route refuses until the declaration (J5 step 3, J6 step 2). The coordinator's intake list shows "Proposal" and an id only (J5 step 2). The separate ranking summary, with its own title, neutral summary and rationale, is written by the reviewer (J6 step 4). The two rules apply to different surfaces, as the design assumed.

### 15. Recused rows in the committee ranking

**Status.** Resolved by `m4-demo.md` "Click paths", J7 step 3.

**Resolution.** For a conflicted member, the row shows "recused" only, without title, summary or scores. `committee-ranking.html` matches. The demo does not say whether the row keeps its position number. The design keeps it.

## Questions added after `m4-demo.md`

Each item names a screen or state the demo script reaches that the first 27 prototypes did not cover, or covered differently. All are now prototyped.

### 16. Sign-up, enrolment and passkey sign-in pages

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` "Run it" and J0, J4 steps 2 and 3: `/auth/signup`, the mailed proof link, the enrolment link with "Create a passkey", and `/auth/login`.

**Gap.** No prototype covers these pages. `profile.html` covers only the account page after sign-in.

**Recommendation.** Add prototypes for sign-up, the "check your email" state, enrolment and passkey sign-in, all script-free where the auth flow allows. Terms and consent wording stays TODO(legal).

**Resolution.** Added `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html` and `auth-signin.html`. Passkey actions are disabled with TODO(js). Legal wording is TODO(legal).

### 17. Proposal workspace sections and late submission

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J4 steps 5 to 9. The workspace autosaves the title, neutral summary and narrative (I-21). It has a "Plan" section with milestones and amounts, an "Eligibility" section feeding the vault (R-NG-01), a "Submit" section with the notice tick and "No ethics issue", and refusal after the deadline.

**Gap.** `plan-editor.html` shows title, abstract, objectives and team with a "Save as draft" button. It has no neutral summary field, no autosave state, no Plan, Eligibility or Submit sections, and no late-submission refusal.

**Recommendation.** Rework the proposal editor into the four demo sections, with an autosave status line and a refusal state on Submit after the deadline.

**Resolution.** `plan-editor.html` now shows Plan, Eligibility, Submit and the late-submission refused state, each with a divider and a step indicator, plus "Last saved 14:32".

### 18. Public call detail with AI disclosure

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J4 step 4: the call page shows amounts as server text, the deadline with its zone and the AI disclosure.

**Gap.** Call detail is specified in `03-applicant-screens.md` but has no prototype. The AI disclosure is not in the design.

**Recommendation.** Add a call detail prototype with the AI disclosure block. Disclosure wording is TODO(legal).

**Resolution.** Added `call-detail-public.html` with dates in two zones, amounts as server text, an eligibility summary and the AI disclosure block (TODO(legal)).

### 19. Notifiable conflicts list

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J5 step 6: `/app/calls/1/notifiable-conflicts` lists the draft of a notifiable conflict declared by a reviewer (R-CF-04).

**Gap.** No prototype covers this coordinator list. `coordinator-conflict.html` covers the coordinator's own declarations only.

**Recommendation.** Add a coordinator list of notifiable conflict drafts with pseudonymous ids and no identity details.

**Resolution.** Added `coordinator-conflicts-list.html`. Declared by shows "Reviewer" only, and one row is Submitted (R-CF-04).

### 20. Reviewer correction reason, ranking summary and stage 2 page

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J6 steps 4 and 5: "Correct the score" needs a reason (I-23); the ranking summary needs a title, a neutral summary and a rationale; the reviewer stage 2 page offers a question or "no questions".

**Gap.** `reviewer-scoring.html` has one combined "Ranking summary and overall comment" field and a correction note with no reason field. The reviewer stage 2 page has no prototype.

**Recommendation.** Split the ranking summary into its three fields, add a required reason to the correction state, and add a reviewer stage 2 prototype.

**Resolution.** `reviewer-scoring.html` splits the ranking summary into Title, Neutral summary and Rationale, and adds a "Correct score" panel with a required reason. Added `reviewer-stage2.html`.

### 21. Ranking table columns and unserved round controls

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J7 steps 2 and 3, and the note under J7: a weighted score per P-01 criterion, the requested amount and the remaining budget, no findings column. Cut-off rounds and ballots are not served in M4.

**Gap.** `committee-ranking.html` shows one weighted score column and no requested amount. It shows round and ballot controls that the demo does not serve.

**Recommendation.** Add per-criterion score columns and a requested amount column. Keep the round and ballot controls, which follow `m4-design.md` J7, but label them as not served in the M4 demo.

**Resolution.** `committee-ranking.html` adds per-criterion columns, "Requested (€)" and a remaining budget row. Round and ballot controls are labelled "Not served in M4 demo". `m4-design.md` gives the P-01 weights only, so the criterion names stay Excellence, Impact and Implementation.

### 22. IRC case list, declaration and second validation

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` J8 steps 1 to 5: `/app/me/irc-cases`, a declaration before the case read, two validations (`i1` and `i2`) before NEGOTIATION, a minor-flagged proposal held in IRC_REVIEW without a consent record (I-18), and a concern that needs its text.

**Gap.** `irc-view.html` shows one case after declaration. It has no case list, no IRC declaration step, no "1 of 2 validations" state and no minor hold.

**Recommendation.** Add the case list and declaration step, show the validation count, and add a held state that names I-18 without identity details.

**Resolution.** Added `irc-cases.html`. `irc-view.html` shows "1 of 2 validations complete" and a proposal held for guardian consent (I-18) with no action.

### 23. Applicant views of a deferred proposal and of the minor hold

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `m4-demo.md` "The seeds": `seed applicant` with DEFERRED_AFTER_CONCERN and IRC_REVIEW_MINOR.

**Gap.** `end-states.html` covers Not eligible, Not selected and Completed. `route-map.html` has a DEFERRED help panel. No applicant page shows a proposal deferred after an IRC concern, or one held in IRC_REVIEW for a missing guardian consent.

**Recommendation.** Add both applicant states. The deferred view states the original call's policy (NOTE 8). The minor hold says what is missing, and the guardian steps stay visible to the guardian only (O-60).

**Resolution.** `end-states.html` adds the deferred panel with the frozen rules link and the on-hold panel, which says nothing about the guardian (O-60).

### 24. Tenant onboarding: separate wizard or folded into the admin screens

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `programme-creator.md` onboarding steps: Organisation, Agreements, Branding, Domains and email, Identity (P-45, P-18), Inference (P-21), Payments (P-20), Channels and Administrators (SoD-07).

**Question.** Are the onboarding steps (Organisation through Channels) a separate onboarding wizard prototype, or are they folded into `admin-org.html` and `admin-branding.html`?

**Gap.** The admin screens cover Organisation, Agreements, Branding, Domains and email, and Administrators. Identity, Inference, Payments and Channels have no screen.

**Recommendation.** A separate step-based wizard for first-time onboarding, reusing the step pattern of `planning-studio.html`. The five admin screens then handle later changes. See `09-tenant-admin.md`.

**Resolution.** Built as `onboarding.html`, 9-step wizard, Daniel's decision 2026-11-01. See `10-post-grant-screens.md`.

### 25. Who moves a payment request from ACCEPTED to PAYMENT_APPROVED

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `payment-requests.md` states: DRAFT, SUBMITTED, CHECKS_FAILED, UNDER_REVIEW, CHANGES_REQUESTED, ACCEPTED, PAYMENT_APPROVED, RELEASED, PAID. Line review is by the finance approver. Release is by the payment releaser (SoD-04).

**Question.** The list has two approval-like states, ACCEPTED and PAYMENT_APPROVED. The extracted rules do not say which role or event moves a request from one to the other. CHECKS_FAILED also reads as a branch, not a step between SUBMITTED and UNDER_REVIEW.

**Recommendation.** ACCEPTED closes the line review. PAYMENT_APPROVED is a separate finance approval of the request total, held by the finance approver. CHECKS_FAILED returns the request to the grantee. `payment-request-review.html` and `payment-release.html` assume this.

**Resolution.** Daniel's decision, 2026-11-01. Recommendation accepted. ACCEPTED closes the line review. The finance approver then confirms the request total (PAYMENT_APPROVED) before the payment releaser can act. CHECKS_FAILED returns the request to the grantee to correct and resubmit.

Design note: onboarding and role assignment are prerequisites. Callouts added to payment-request-review.html and payment-release.html.

Changed: `payment-request-review.html`, `payment-release.html` and `payment-status.html` (new CHECKS_FAILED row).

### 26. Visibility levels for a grantee who is a minor

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `public-transparency.md` I-42 (no public page names a minor) and the grantee choice of level up to P-50 and P-51.

**Question.** Should the levels "Project and grantee" and "Full" be unavailable when the grantee or a team member is a minor? Or does the platform publish the project but suppress only the name?

**Recommendation.** Cap the choice at "Project" for any grant with a minor on the team, and show the reason beside the disabled options. `grantee-visibility.html` shows an adult grantee today.

**Resolution.** Daniel's decision, 2026-11-01. Recommendation accepted. Hidden and Project stay selectable when a team member is a minor (I-42).

Design note: 'Project and grantee' and 'Full' are disabled with reason when a minor is on the team.

Changed: `grantee-visibility.html` now shows a team with a minor.

### 27. Who decides OUT_OF_SCOPE for a complaint, and can it be escalated

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `complaints.md` states FILED, OUT_OF_SCOPE, COORDINATOR_REVIEW. SoD-13 and I-56 apply to every complaint.

**Question.** The rules do not name the role that marks a complaint OUT_OF_SCOPE. They also do not say whether that decision can itself be escalated to the IRC.

**Recommendation.** A coordinator who took no part in the contested decision decides scope, with a reasoned response (I-56). The complainant can escalate within P-63. `complaint-coordinator-review.html` does not show the scope decision yet.

**Resolution.** Daniel's decision, 2026-11-01. Recommendation accepted. A coordinator who took no part in the contested decision decides scope (SoD-13), with a reasoned response. The complainant can escalate within P-63.

Design note: complaint procedure must appear in participation T&Cs and application submission T&Cs. TODO(legal) markers added.

Changed: `complaint-coordinator-review.html` (scope decision panel and out of scope view), `complaint-file.html` and `complaint-irc-escalation.html`.

### 28. What document a contract terminated before signature keeps

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** I-30 (signed versions are immutable, hashes in the audit log). `contract-terminal.html` shows CTR-2026-0039, TERMINATED with the reason "Project abandoned before signature."

**Question.** A contract terminated before signature has no signed version. Which PDF is kept and called immutable: the last unsigned draft, or a termination record only?

**Recommendation.** Keep the last sent draft as an immutable PDF, labelled unsigned, and record its hash with the termination reason. `contract-terminal.html` shows a "Download PDF" link on this assumption.

**Resolution.** Daniel's decision, 2026-11-01. See docs/design/spec-amendments.md SA-03.

Decision: the generated draft PDF is sealed with the tenant's electronic seal and stored at termination, with the termination reason recorded. Changed: `contract-terminal.html` now shows the sealed draft note and a "Download sealed draft" link.

### 29. Which rule governs the second-admin approval at onboarding activation

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** SoD-07 (at least two tenant admins). The brief for `onboarding.html` step 9 cites "I-67 equivalent for onboarding".

**Question.** I-67 covers programme publication. No extracted rule names the two-person check for organisation activation. Is it SoD-07 alone, or a new invariant?

**Recommendation.** Treat activation as a two-person action under SoD-07: the approver must not be the admin who built the setup. Add an explicit invariant to the spec. The step 9 note keeps the brief's wording until then.

**Resolution.** Daniel's decision, 2026-11-01. See docs/design/spec-amendments.md SA-02.

Decision: activation needs approval by a second tenant admin who did not complete the setup, by analogy with I-67. Changed: `onboarding.html` step 9 now has an activation approval panel and the explicit note.

### 30. Advanced signature listed as a verification method

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** P-18 (verification methods) and P-30 (signature cascade). `onboarding.html` step 5 lists "Advanced signature" under Verification methods (P-18).

**Question.** P-18 covers identity verification. Advanced signature is a signing method under P-30. Should the onboarding step list signing methods separately from verification methods?

**Recommendation.** Split step 5 into "Identity verification (P-18)" and "Signature methods (P-30)". `onboarding.html` follows the brief for now.

**Resolution.** Daniel's decision, 2026-11-01. See docs/design/spec-amendments.md SA-04.

Decision: advanced signature is removed from step 5. It is a signing route under P-30, not a verification method under P-18. Changed: `onboarding.html` step 5 lists two methods and explains where advanced signature is configured.

### 31. Financial signatory and Legal signatory roles are not in the spec

**Status.** Resolved (Daniel's decision, 2026-11-01).

**Reference.** `roles-and-sod.md`. Daniel's decision, 2026-11-01: two tenant-wide roles, Financial signatory and Legal signatory. Each needs at least one named holder before activation. One person may hold both.

**Question.** The Financial signatory and Legal signatory roles are not in roles-and-sod.md. They were introduced by Daniel's decision on 2026-11-01. Should they be added to the spec as tenant-wide Operations roles? What authority do they have (signing, approving, countersigning)?

**Recommendation.** Add to roles-and-sod.md as tenant-wide Operations roles. Financial signatory: approves payment instructions and financial commitments at the organisation level. Legal signatory: approves contracts, terms and legal commitments at the organisation level. Separate from the programme-bound Contract signatory. Spec amendment pending.

**Design note.** Shown in `admin-members.html` (Tenant-wide roles column), `admin-org.html` (Signatories section) and `onboarding.html` step 9 (activation conditions). Tenant admins can add, change or remove these roles later in `admin-members.html` (Daniel, 2026-11-01). Removing the last holder of either role is blocked.

**Resolution.** Daniel's decision, 2026-11-01. See docs/design/spec-amendments.md SA-01.

Decision: recommendation accepted. The spec needs an amendment and the backend needs work. Both are listed in SA-01.
