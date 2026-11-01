# Grant process UI design deliverables

Design work for the FSTP platform proposal and grant UI, started 2026-11-01. Everything here is a design artefact. The build never reads these files and nothing here ships.

Inputs: `design-brief.md`, ADR-014, ADR-015, `SPEC/12-journey-ui.md` (repository version), `docs/handoff/m4-design.md`, `SPEC/02-domain/state-machine.md`, `SPEC/02-domain/roles-and-sod.md`, `SPEC/01-requirements/non-functional.md` and `docs/handoff/m4-demo.md`.

## Index

| Item | File(s) | Status |
| --- | --- | --- |
| 1. Information architecture, navigation and home pages | `01-navigation-home.md`; `design/prototypes/nav-pattern.html`, `home-voyager.html`, `home-coordinator.html`, `home-reviewer.html`, `home-committee.html`, `home-irc.html`, `home-finance.html`, `home-auditor.html`, `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html`, `auth-signin.html` | draft |
| 2. Progress map and activity log | `02-voyager-route-diary.md`; `design/prototypes/route-map.html`, `diary.html` | draft |
| 3. Applicant surfaces | `03-applicant-screens.md`; `design/prototypes/calls-public.html`, `call-detail-public.html`, `plan-editor.html`, `packing-check.html`, `submission-receipt.html`, `stage2-questions.html`, `negotiation.html`, `end-states.html` | draft |
| 4. Reviewer, committee and IRC surfaces | `04-reviewer-committee-irc.md`; `design/prototypes/reviewer-assignments.html`, `reviewer-scoring.html`, `reviewer-stage2.html`, `committee-ranking.html`, `irc-cases.html`, `irc-view.html` | draft |
| 5. Programme staff and programme set-up | `05-programme-staff-studio.md`; `design/prototypes/coordinator-conflict.html`, `coordinator-conflicts-list.html`, `stage1-close.html`, `planning-studio.html`, `seal-ceremony.html` | draft |
| 6. Profile page (`/app/me`) | `06-profile-page.md`; `design/prototypes/profile.html` | draft |
| 7. Vocabulary packs (plain platform default, Voyage opt-in per tenant) | `07-vocabulary-pack.md` | draft |
| 8. Design tokens | `08-design-tokens.md`; `design/tokens.css`, `design/prototypes/tokens-showcase.html` | draft |
| Demo walkthrough | `demo-walkthrough.md` | draft |
| Spec questions | `spec-questions.md` | draft |
| Prototype tests (Playwright) | `design/tests/prototypes.spec.ts`, `design/tests/playwright.config.ts`, `design/tests/README.md` | draft |

File names keep their first-pass names (for example `home-voyager.html` and `02-voyager-route-diary.md`) so existing links still work. The page copy inside them uses plain grant language.

## How to view the prototypes

Open any file in `design/prototypes/` directly in a browser. They use no script and no network. Each page links only to `../tokens.css`. Each page shows a "Prototype state" label naming the screen state it demonstrates.

## Rules every file follows

- Synthetic data only: Nova Research Foundation, SuperSAFE, Meridian Social Lab, CSW-2024-0042, `demo@e2e.invalid`.
- Plain grant language leads in headings, buttons, status labels, nav items, empty states, errors and notifications.
- The Voyage pack label appears only as a secondary line (`.voyage-label`) and in the progress map subtitle.
- Every displayed label sits beside its formal state name (I-96).
- State is never shown by colour alone. Each state carries a glyph and a word.
- No em dashes. Sentences under 40 words. Legal text is marked TODO(legal). In the 8 prototypes added on 2026-11-01, TODO(legal) and TODO(js) are HTML comments beside a neutral visible placeholder.

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
