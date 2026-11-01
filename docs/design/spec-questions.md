# Spec questions

Status: draft. Points where the spec is unclear or seems wrong, found during design. Each has a recommendation. The spec wins until Daniel decides. On 2026-11-01 Daniel decided every open item, so all 23 are now Resolved. Item 24, about tenant onboarding, was opened later on 2026-11-01 and is Open.

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

**Status.** Resolved (design decision, spec amendment pending). Daniel's decision, 2026-11-01.

**Reference.** `SPEC/12-journey-ui.md` §15 O-55 and §17.2: Voyage is the platform default pack, and tenants can switch to a plain pack.

**Design position.** Daniel asked for plain grant language as the default because "this is STILL a grant process". The prototypes show plain labels as primary and the Voyage label as a secondary line.

**Recommendation.** Amend O-55 so the plain pack is the platform default and Voyage is opt-in per tenant.

**Resolution.** Plain grant language is the platform default and Voyage is opt-in per tenant. Until O-55 is formally amended, the build treats this as a design decision pending a spec update. See `07-vocabulary-pack.md`.

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

**Status.** Open.

**Reference.** `programme-creator.md` onboarding steps: Organisation, Agreements, Branding, Domains and email, Identity (P-45, P-18), Inference (P-21), Payments (P-20), Channels and Administrators (SoD-07).

**Question.** Are the onboarding steps (Organisation through Channels) a separate onboarding wizard prototype, or are they folded into `admin-org.html` and `admin-branding.html`?

**Gap.** The admin screens cover Organisation, Agreements, Branding, Domains and email, and Administrators. Identity, Inference, Payments and Channels have no screen.

**Recommendation.** A separate step-based wizard for first-time onboarding, reusing the step pattern of `planning-studio.html`. The five admin screens then handle later changes. See `09-tenant-admin.md`.
