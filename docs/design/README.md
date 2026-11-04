# Grant process UI design deliverables

Design work for the FSTP platform proposal and grant UI, started 2026-11-01. Everything here is a design artefact. The build never reads these files and nothing here ships.

Inputs: `design-brief.md`, ADR-014, ADR-015, `SPEC/12-journey-ui.md` (repository version), `docs/handoff/m4-design.md`, `SPEC/02-domain/state-machine.md`, `SPEC/02-domain/roles-and-sod.md`, `programme-creator.md`, `white-labelling.md`, `payment-requests.md`, `contracts.md`, `complaints.md`, `public-transparency.md`, `funder-reporting.md`, `support-programme.md`, `SPEC/01-requirements/non-functional.md` and `docs/handoff/m4-demo.md`.

## Index

| Item | File(s) | Status |
| --- | --- | --- |
| 1. Information architecture, navigation and home pages | `01-navigation-home.md`; `design/prototypes/nav-pattern.html`, `home-voyager.html`, `home-coordinator.html`, `home-reviewer.html`, `home-committee.html`, `home-irc.html`, `home-finance.html`, `home-auditor.html`, `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html`, `auth-signin.html` | draft; built in `web/` by lane m4/site (2026-11-04), without home-finance and home-auditor |
| 2. Progress map and activity log | `02-voyager-route-diary.md`; `design/prototypes/route-map.html`, `diary.html` | draft |
| 3. Applicant surfaces | `03-applicant-screens.md`; `design/prototypes/calls-public.html`, `call-detail-public.html`, `plan-editor.html`, `packing-check.html`, `submission-receipt.html`, `stage2-questions.html`, `negotiation.html`, `end-states.html` | draft; built in `web/` by lane m4/site (2026-11-04), without the public call pages and the pre-submission check |
| 4. Reviewer, committee and IRC surfaces | `04-reviewer-committee-irc.md`; `design/prototypes/reviewer-assignments.html`, `reviewer-scoring.html`, `reviewer-stage2.html`, `committee-ranking.html`, `irc-cases.html`, `irc-view.html` | draft; built in `web/` by lane m4/site (2026-11-04) |
| 5. Programme staff and programme set-up | `05-programme-staff-studio.md`; `design/prototypes/coordinator-conflict.html`, `coordinator-conflicts-list.html`, `stage1-close.html`, `planning-studio.html`, `seal-ceremony.html` | draft; built in `web/` by lane m4/site (2026-11-04) |
| 6. Profile page (`/app/me`) | `06-profile-page.md`; `design/prototypes/profile.html` | draft; built in `web/` by lane m4/site (2026-11-04), without the preferences |
| 7. Vocabulary packs (plain platform default, Voyage opt-in per tenant) | `07-vocabulary-pack.md` | draft |
| 8. Design tokens | `08-design-tokens.md`; `design/tokens.css`, `design/prototypes/tokens-showcase.html` | draft; copied into `web/src/site/tokens.css` and `web/src/auth/tokens.css` by lane m4/site (2026-11-04) |
| 9. Tenant admin screens (new) | `09-tenant-admin.md`; `design/prototypes/home-admin.html`, `admin-org.html`, `admin-members.html`, `admin-branding.html`, `admin-domains.html`, `admin-masquerade.html` | draft |
| Sidebar layout, layout and routing contract, masquerade mode (new) | `01-navigation-home.md`; `08-design-tokens.md` Layout tokens; `design/tokens.css` section 5b; `design/prototypes/nav-pattern.html`, `admin-masquerade.html` | draft |
| 10. Post-grant, complaints, transparency, reporting, support and onboarding (new) | `10-post-grant-screens.md`; `design/prototypes/payment-request-form.html`, `payment-request-review.html`, `payment-release.html`, `payment-status.html`, `contract-view.html`, `contract-signatory.html`, `contract-amendment.html`, `home-signatory.html`, `complaint-file.html`, `complaint-coordinator-review.html`, `complaint-irc-escalation.html`, `complaint-status.html`, `public-grants.html`, `grantee-visibility.html`, `public-calls-feed.html`, `audit-log.html`, `funder-report.html`, `report-approval.html`, `grantee-support.html`, `mentor-assignment.html`, `onboarding.html`, `payment-checks-failed.html`, `contract-drafted.html`, `contract-advanced-approval.html`, `contract-terminal.html`, `home-mentor.html`, `home-operations.html`, `report-generation-failure.html` | draft |
| Demo walkthrough | `demo-walkthrough.md` | draft |
| Spec questions | `spec-questions.md` | draft |
| Spec amendments and backend notes (new, not normative) | `spec-amendments.md` | draft |
| Prototype tests (Playwright) | `design/tests/prototypes.spec.ts`, `design/tests/playwright.config.ts`, `design/tests/README.md` | draft |

File names keep their first-pass names (for example `home-voyager.html` and `02-voyager-route-diary.md`) so existing links still work. The page copy inside them uses plain grant language.

## How to view the prototypes

Open any file in `design/prototypes/` directly in a browser. They use no script and no network. Each page links only to `../tokens.css`. Each page shows a "Prototype state" label naming the screen state it demonstrates.

## Rules every file follows

- Synthetic data only: Nova Research Foundation, SuperSAFE, Meridian Social Lab, CSW-2024-0042, `demo@e2e.invalid`. The admin screens use Horizon Bridges, OpenTech Fund and `horizon-bridges.example` accounts.
- Admin and post-grant screens carry no Voyage labels, not even as a secondary line.
- Plain grant language leads in headings, buttons, status labels, nav items, empty states, errors and notifications.
- The Voyage pack label appears only as a secondary line (`.voyage-label`) and in the progress map subtitle.
- Every displayed label sits beside its formal state name (I-96).
- State is never shown by colour alone. Each state carries a glyph and a word.
- No em dashes. Sentences under 40 words. Legal text is marked TODO(legal). In the 34 prototypes added on 2026-11-01, TODO(legal) and TODO(js) are HTML comments beside a neutral visible placeholder.

## Reconciliation log

Changes made on 2026-11-01 after `SPEC/12-journey-ui.md` and `m4-design.md` were supplied. The spec wins over any earlier design idea.

| Change | Why | Citation |
| --- | --- | --- |
| Voyage labels for all 16 states now match the node table. Invented labels such as "Route declined", "Voyage ended", "Charter ended", "Closed at the border" and the short "Wintering" are gone | The spec defines the default labels | `12-journey-ui.md` §5.2 |
| Pack keys use `journey.node.<state>` | The journey definition file names nodes this way | `12-journey-ui.md` §5.3, §4 |
| Withdraw bracket on the progress map covers every state before GRANTED, including DEFERRED | Withdrawal is allowed from DEFERRED | state machine NOTE 10; `12-journey-ui.md` §5.1 |
| Programme set-up is per programme, with the 11 creator steps in spec order. Money is step 6 | The earlier design had the studio per call and a different order | `12-journey-ui.md` §8.2; `m4-design.md` §3.1 |
| A cap per recipient above the funder ceiling is refused at save (I-50). Imported values show provenance (I-65). Validation failures block activation (I-66). Previews include the progress map | Spec checks and preview rules | `m4-design.md` §3.2 (CapAboveCeiling), 15.0; `12-journey-ui.md` §8.2, R-JV-08 |
| Approval order: policy activation by a tenant admin outside the builder set, then call drafting, approval by a non-drafter and publication | The builder cannot choose their approver | `m4-design.md` §2.2 J1 and J3; R-PC-03; I-52, I-66, I-67 |
| IRC view offers two options, validate or raise a concern, and states the DEFERRED or DECLINED consequence. No scores, ballots or rationale | The earlier three radios did not match the state machine | `m4-design.md` §2.2 J8, Q16; R-IR-03; O-58; state machine NOTE 7, NOTE 13 |
| Committee ranking has per-member ballots with delegation and a "Recused" row label | Ballots are cast by each member | `m4-design.md` §2.2 J7, Q4, Q16; D5 |
| Reviewer scoring uses 0 to 5 with criterion weights 30, 40 and 30 | Matches the M4 demo policy | `m4-design.md` §2.1 |
| Declaration view shows the title and a neutral summary. Queue health keeps ids only | Two rules for two surfaces | `m4-design.md` §2.2 J5, Q9; `12-journey-ui.md` §8.3, O-57 |
| Receipt shows the data protection notice version and the ethics declaration. Negotiation is read-only in M4 | Spec fields and M4 scope | `m4-design.md` §2.2 J4; R-NG-06; R-SB-05 |
| Footer carries platform attribution and funder visibility as TODO(legal) | Spec footer rule | `m4-design.md` §3.9; P-68 |
| Stage 2 window explains that DEFERRED follows if P-07 elapses with no answers and no "no questions" record | State machine rule | state machine NOTE 4 |
| Deadlines always show both zones | Spec display rule | `12-journey-ui.md` §7.4 |
| Account-page landing now cites `design-brief.md` | `m4-design.md` 15.0 has no such row | `spec-questions.md` item 13 |
| Plain grant language is the default in all 27 prototypes. Spec metaphor names stay as secondary lines | Daniel: "this is STILL a grant process" | `spec-questions.md` items 11 and 12; `07-vocabulary-pack.md` |
| `demo-walkthrough.md` rewritten to follow the demo click paths J0 and J4 to J8 in order | The earlier file was written without the demo script | `m4-demo.md` "Click paths" |
| Spec questions 10, 13, 14 and 15 resolved | The demo script records the behaviour | `m4-demo.md` J0, J4 to J7; `spec-questions.md` |
| Demo screens with no prototype, or a different one, logged as questions 16 to 23. They cover auth pages, workspace sections, call detail with AI disclosure, notifiable conflicts, reviewer correction and stage 2, ranking columns, IRC case flow, applicant deferred and minor-hold views | Gaps between the demo and the 27 prototypes. No prototype was changed in this pass | `m4-demo.md` J0, J4 to J8, "The seeds"; `spec-questions.md` items 16 to 23 |
| Playwright suite grew from 222 to 250 tests, including a check that primary chrome uses plain language | Guards the copy and the reconciled flows | `design/tests/README.md` |
| Q11 decided: plain grant language is the platform default, Voyage is opt-in per tenant. Recorded as a design decision pending a spec amendment of O-55 | Daniel's decision, 2026-11-01 | `spec-questions.md` item 11; `07-vocabulary-pack.md`; `12-journey-ui.md` §15 O-55 |
| Q12 decided: "Activity log", "Progress map", "Programme set-up", "Approval and publication" and "Pre-submission check" confirmed as plain primary labels | Daniel's decision, 2026-11-01 | `spec-questions.md` item 12; `07-vocabulary-pack.md` Catalogue 3 |
| Q3, Q5, Q6, Q7 and Q8 recommendations accepted and recorded in docs 02, 03, 05 and 06 | Daniel's decision, 2026-11-01 | `spec-questions.md` items 3, 5 to 8 |
| 8 new prototypes: `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html`, `auth-signin.html`, `call-detail-public.html`, `coordinator-conflicts-list.html`, `reviewer-stage2.html`, `irc-cases.html`. The package now has 35 | Closes gaps 16, 18, 19, 20 and 22 | `m4-demo.md` J0, J4 to J8; `spec-questions.md` items 16 to 22 |
| Updated prototypes: `plan-editor.html` (Plan, Eligibility, Submit and late refusal panels), `reviewer-scoring.html` (three summary fields, correction panel), `committee-ranking.html` (criterion columns, requested amount, remaining budget row, "Not served in M4 demo" labels). Also `irc-view.html` (validation count, I-18 hold), `end-states.html` (deferred and on-hold panels). `calls-public.html` now links to the call page | Closes gaps 17, 20, 21, 22 and 23 | `m4-demo.md` J4 to J8, "The seeds"; `spec-questions.md` items 17, 20 to 23 |
| All 23 spec questions are now Resolved | Daniel's decisions of 2026-11-01 close the remaining items | `spec-questions.md` |
| Playwright suite grew from 250 to 366 tests. The 250 earlier tests are unchanged, except the file count, which moved from 27 to 35 | Guards the new and updated prototypes | `design/tests/README.md` |
| New doc `09-tenant-admin.md`: tenant admin role, the five admin screens, key rules and open question Q24 | Tenant admin had no screens | `roles-and-sod.md`, `programme-creator.md`, `white-labelling.md` |
| 5 new admin prototypes: `home-admin.html`, `admin-org.html`, `admin-members.html`, `admin-branding.html`, `admin-domains.html`. The package now has 40 | Covers O-47, SoD-07, SoD-09 and I-68 to I-72 | `09-tenant-admin.md` |
| Admin navigation and brand: Home, Organisation, Members and roles, Branding, Domains and email, under the Horizon Bridges brand. `tokens-showcase.html` picks up the new admin navigation | The old admin items linked nowhere | `09-tenant-admin.md` Shell |
| Mandatory elements checklist shows five items, adding the accessibility statement to the four in the screen brief | I-69 lists five elements | `white-labelling.md` I-69 |
| Q24 opened: separate onboarding wizard, or onboarding folded into the admin screens | Identity, Inference, Payments and Channels steps have no screen | `spec-questions.md` item 24 |
| Playwright suite grew from 366 to 431 tests. The earlier tests are unchanged, except the file count, which moved from 35 to 40 | Guards the admin screens | `design/tests/README.md` |
| New doc `10-post-grant-screens.md`: payment requests, contracts, complaints, public transparency, funder reporting and audit, support programme and the onboarding wizard | These areas had no screens | the six post-grant spec files and `programme-creator.md` |
| 4 payment screens: `payment-request-form.html`, `payment-request-review.html`, `payment-release.html`, `payment-status.html` | Covers lines, automated checks, line review and SoD-04 | `payment-requests.md` |
| 4 contract screens: `contract-view.html`, `contract-signatory.html`, `contract-amendment.html`, `home-signatory.html` (new role home) | Covers the P-30 cascade, R-NG-04, SoD-03, I-30 and amendments | `contracts.md` |
| 4 complaint screens: `complaint-file.html`, `complaint-coordinator-review.html`, `complaint-irc-escalation.html`, `complaint-status.html` | Covers scope, SoD-13, I-56 and I-57 | `complaints.md` |
| 3 transparency screens: `public-grants.html`, `grantee-visibility.html`, `public-calls-feed.html` | Covers the opt-in levels, P-50 to P-54 and I-41 to I-43 | `public-transparency.md` |
| 3 reporting screens: `audit-log.html`, `funder-report.html`, `report-approval.html` | Covers I-44, the report types and separate approval | `funder-reporting.md` |
| 2 support screens: `grantee-support.html`, `mentor-assignment.html` | Covers SoD-12, I-54 and I-55 | `support-programme.md` |
| `onboarding.html`: 9-step wizard, step 1 current, steps 2 to 9 locked. The package now has 61 prototypes | Resolves Q24 | `spec-questions.md` item 24 |
| Navigation: new Grantee, Contract signatory, Mentor, Operations approver and public data roles. Links added from `home-finance.html`, `home-auditor.html`, `negotiation.html`, `end-states.html` (new Granted panel), `home-voyager.html` and `home-admin.html` | Every new screen is reachable | `10-post-grant-screens.md` |
| Q25 to Q27 opened: ACCEPTED versus PAYMENT_APPROVED, visibility for minors, OUT_OF_SCOPE decision | Gaps found during the build | `spec-questions.md` items 25 to 27 |
| Playwright suite grew from 431 to 670 tests. The earlier tests are unchanged, except the file count, which moved from 40 to 61 | Guards the new screens and links | `design/tests/README.md` |
| Q25 resolved. Role prerequisite callouts on payment review and release, a two-step approval note and a CHECKS_FAILED row in payment status | Daniel's decision, 2026-11-01. Org roles must be set before subgranting begins | `spec-questions.md` Q25, `10-post-grant-screens.md` |
| Q26 resolved. Visibility page shows a team with a minor, with "Project and grantee" and "Full" disabled in both phases | Daniel's decision, 2026-11-01. I-42 | `spec-questions.md` Q26, `10-post-grant-screens.md` |
| Q27 resolved. Scope decision panel and out of scope view on coordinator review. TODO(legal) T&C markers on three complaint screens | Daniel's decision, 2026-11-01. SoD-13 and P-63 | `spec-questions.md` Q27, `10-post-grant-screens.md` |
| Playwright suite grew from 670 to 673 tests. Two payment and visibility tests were updated for the new states | Guards the Q25 to Q27 changes | `design/tests/README.md` |
| `onboarding.html` completed: all 9 steps shown as panels with "Step N of 9", a back link, a locked note and a disabled Save and continue | Completes the wizard from Q24 | `10-post-grant-screens.md` |
| New `payment-checks-failed.html`: two failed checks, one pass, resubmit note. `payment-status.html` links to it from the CHECKS_FAILED row | Grantee detail view for CHECKS_FAILED (Q25) | `10-post-grant-screens.md` |
| New `contract-drafted.html` (DRAFTED, clause changes, R-NG-04) and `contract-advanced-approval.html` (P-30 step 3) | Covers the negotiation draft and the advanced signature approval | `10-post-grant-screens.md` |
| New `contract-terminal.html`: SUPERSEDED, EFFECTIVE and TERMINATED versions with I-30 | Covers the contract terminal states | `10-post-grant-screens.md` |
| New role homes `home-mentor.html` (SoD-12) and `home-operations.html` (four queues, SoD-03, SoD-04). New Operations nav role. Mentor and Operations approver Home links now point to them | Every role has a home | `10-post-grant-screens.md` |
| New `report-generation-failure.html`: mismatches table and I-44 note | Shows where generation failures appear | `10-post-grant-screens.md` |
| Links added from `home-admin.html` (First-time setup card), `negotiation.html`, `contract-view.html`, `funder-report.html` and `payment-status.html`. The package now has 68 prototypes | Every new screen is reachable | `10-post-grant-screens.md` |
| Q28 to Q30 opened: document kept after termination before signature, rule for onboarding activation, advanced signature listed under P-18 | Gaps found during the build | `spec-questions.md` items 28 to 30 |
| Playwright suite grew from 673 to 754 tests. The file count moved from 61 to 68. The payment status link count was updated | Guards the new screens and links | `design/tests/README.md` |
| Financial signatory and Legal signatory roles added to admin-members.html, admin-org.html and onboarding.html. Daniel's decision, 2026-11-01. Q31 added | Both are tenant-wide and required before activation. One person may hold both | `spec-questions.md` item 31 |
| Roles can be changed after onboarding. `admin-members.html` has a disabled Change roles button per row and a callout. `admin-org.html` and `onboarding.html` step 9 point to Members and roles | Daniel, 2026-11-01: the administrator must be able to change or add roles later | `spec-questions.md` item 31 |
| Q28 resolved. `contract-terminal.html` shows the sealed draft note and "Download sealed draft" | Daniel's decision, 2026-11-01. The draft PDF is sealed and stored at termination | `spec-questions.md` item 28; `spec-amendments.md` SA-03 |
| Q29 resolved. `onboarding.html` step 9 has an activation approval panel and the explicit second-admin note | Daniel's decision, 2026-11-01. By analogy with I-67 | `spec-questions.md` item 29; `spec-amendments.md` SA-02 |
| Q30 resolved. Advanced signature removed from `onboarding.html` step 5, with a note on where it is configured | Daniel's decision, 2026-11-01. P-30 signing route, not P-18 verification | `spec-questions.md` item 30; `spec-amendments.md` SA-04 |
| Q31 resolved. Financial signatory and Legal signatory need a spec amendment and backend work | Daniel's decision, 2026-11-01. Recommendation accepted | `spec-questions.md` item 31; `spec-amendments.md` SA-01 |
| New doc `spec-amendments.md`: SA-01 to SA-04, with the spec text to add and the backend work for each. All 31 spec questions are now Resolved | Input for Daniel's engineering work. Not normative | `spec-questions.md` items 28 to 31 |
| Playwright suite grew from 758 to 761 tests. Two tests updated: step 5 now has two verification checkboxes, and the contract history has two "Download PDF" links plus one "Download sealed draft" | Guards the Q28 to Q30 changes | `design/tests/README.md` |
| Playwright suite grew from 754 to 758 tests. Admin organisation and members tests updated for 4 lists, 4 accounts and the Tenant-wide roles column | Guards the signatory roles and later role changes | `design/tests/README.md` |
| Sidebar layout for all 61 signed-in prototypes. Top bar keeps brand and tools. Navigation, role chip, Account and Sign out move to a 220px left sidebar from 900px up. Below 900px the links stack under the top bar | Daniel's request, 2026-11-01. Layout CSS lives only in `tokens.css` section 5b | `01-navigation-home.md` Sidebar layout; `08-design-tokens.md` Layout tokens |
| Two layouts, `AppLayout` and `PublicLayout`, with fixed sidebar slots and a layout and routing contract. The 8 public pages keep their links in the top bar and have no sidebar | Daniel, 2026-11-01: the layout must map cleanly to routing in the real build. No framework is chosen here | `01-navigation-home.md` Layout and routing contract |
| Masquerade mode. New `admin-masquerade.html`, a Support tools section on `home-admin.html` and a Support tools item in the admin sidebar. The banner is in every signed-in page, hidden except on `home-voyager.html` and `reviewer-scoring.html`. The package now has 69 prototypes | Tenant admin support tool. Read-only. TODO(js): real masquerade needs a session flag | `01-navigation-home.md` Masquerade mode |
| Contrast check for the new pairs. The warning border failed 3:1 as a banner edge. Fixed with a 4px left bar in the warning text colour | WCAG 2.2 AA, 1.4.11 | `08-design-tokens.md` Layout tokens |
| Playwright suite grew from 761 to 847 tests. Avatar test now uses the sidebar Account link. The current page check looks in the top bar or the sidebar | Guards the sidebar, public layout and masquerade changes | `design/tests/README.md` |
