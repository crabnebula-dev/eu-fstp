# Demo walkthrough

Status: draft. Date: 2026-11-01. Source: `docs/handoff/m4-demo.md` (lane m4int-b, written 2026-10-30), read with `m4-design.md` sections 2, 3.7, 3.9 and 8.7.

This file retells the M4 demo script in the order `m4-demo.md` gives it. It was not run from this design environment, so no live screen was seen. Every person, proposal and text below is synthetic, as in the source. The demo script uses plain grant terms throughout. It has no Voyage or nautical terms to translate. Where its wording differs from the prototypes, the prototype page is named in brackets.

## Setting up

The demo runs the M4 pages in Chromium against the test-only cell `fstp-e2e-cell` at `http://a.fstp.localhost:8640` (`m4-demo.md` "Run it"). `tools/demo/run.sh` builds and starts the cell. Each `seed` command replaces the whole cell state and prints one-time enrolment links. A person opens their link, chooses "Create a passkey" and is signed in. Each persona uses its own browser profile. The seeds place programme 1 (SuperSAFE) and call 1 in a given stage, with proposals x, z, w, v and u. They also create the personas `c1` (coordinator), `r1` to `r4` (reviewers), `i1` and `i2` (IRC members) and `lead` (applicant) (`m4-demo.md` "The seeds").

## Scene 1: tenant admin sign-in (J0, first step)

After `run.sh reset`, the tenant admin opens the printed enrolment link and creates a passkey. Sign-in lands on the account page, which lists the session and the device. The admin signs out there, opens `/auth/login` and signs in again with the passkey. The identity page and the onboarding steps load, but their operations are not served yet (`m4-demo.md` "Click paths", J0). [Account page: `profile.html`. Enrolment: `auth-enrol.html`. Sign-in: `auth-signin.html`.]

## Scene 2: an applicant drafts and submits a proposal (J4)

With call 1 open and its deadline 30 minutes away, a new applicant signs up at `/auth/signup` with `demo@e2e.invalid`, opens the mailed proof link and creates a passkey. At `/app/calls` they open the call, which shows the amounts as server text, the deadline with its zone and the AI disclosure. "Start a proposal" opens a workspace that autosaves the title, the neutral summary and the narrative (I-21). Under "Plan" (the proposal's work plan) they add one milestone of 1500.50 with start and due days. The cell shows the total and the page refuses a non-canonical amount such as 1500.5. Under "Eligibility" they state a country, which goes to the vault only (R-NG-01). Under "Submit" they tick the data protection notice, choose "No ethics issue" and submit, and the proposal reads SUBMITTED. Moving the clock 60 minutes passes the deadline, and the submit page then refuses a late submission (`m4-demo.md` J4). [Sign-up: `auth-signup.html` and `auth-check-email.html`. Passkey: `auth-enrol.html`. Call list: `calls-public.html`. Call page: `call-detail-public.html`. Workspace with Plan, Eligibility, Submit and the late refusal: `plan-editor.html`. The prototype's Submit ticks follow Daniel's wording, and the notice tick stays a TODO(legal) comment.]

## Scene 3: the FSTP coordinator runs the eligibility check and the stage 1 close (J5)

The coordinator `c1` opens `/app/calls/1/intake`, which lists the submitted proposals as "Proposal" and an id. A declaration view shows only the title and the neutral summary, and the content route refuses until the coordinator declares (R-CF-02). After "no conflict", the knock-out page shows the content and the three SuperSAFE P-09 criteria. Failing a criterion without a reason prompts for one, and with a reason the proposal becomes INELIGIBLE. With every stage 1 score in, `c1` opens `/app/calls/1/board` and records the stage 1 close. Proposal x, scored 100.00, moves to STAGE2. Proposal w, scored 60.00 against the P-02 threshold of 75.00, moves to NOT_SELECTED. No control states an outcome (I-07, I-08). When reviewer R1 declares a notifiable conflict on w, `/app/calls/1/notifiable-conflicts` lists its draft (R-CF-04) (`m4-demo.md` J5). [`coordinator-conflict.html`, `stage1-close.html`, `coordinator-conflicts-list.html`.]

## Scene 4: assigned reviewers score and ask stage 2 questions (J6)

Reviewer `r1` opens `/app/me/assignments` and the assignment of x. Before the declaration only the title and summary show. After "no conflict" the content and the score sheet appear. The reviewer enters whole numbers on the 0 to 5 scale of P-01. The page refuses 3.5 or 6, and a saved score survives a reload. Once all scores are in, "Correct the score" needs a reason (I-23), and the ranking summary needs a title, a neutral summary and a rationale. In stage 2, `r1` asks a question or records "no questions". When R1 and R2 both record "no questions", the window closes and x is RANKED (`m4-demo.md` J6). [`reviewer-assignments.html`, `reviewer-scoring.html` (three summary fields and the correction panel), `reviewer-stage2.html`.]

## Scene 5: the committee reads the ranking (J7)

At `/app/calls/1/ranking` the committee member sees x, v and w in order. Each row has a weighted score per P-01 criterion, the requested amount and the remaining budget, with no findings column. Signed in as `r4`, who is conflicted on w, the row of w shows "recused" only, without title, summary or scores (Q16). Opening a cut-off round and casting or delegating ballots are not served in the demo. The `irc_review` seed records a round through the engine instead (`m4-demo.md` J7). [`committee-ranking.html`, with criterion columns, the requested amount and the remaining budget row. Its round and ballot controls carry "Not served in M4 demo".]

## Scene 6: independent review up to negotiation (J8)

IRC member `i1` opens `/app/me/irc-cases` and the case of x. The case read refuses until `i1` declares. After "no conflict" the case shows the proposal and "nominated", with no score, ballot or rationale (R-IR-03). `i1` validates, then `i2` declares and validates, and x enters NEGOTIATION. Coordinator `c1` sees x as NEGOTIATION on the board. Proposal v is flagged as involving a minor with no consent record, so two validations leave it in IRC_REVIEW (I-18). A concern on u needs its text and defers u, because call 2 is published (NOTE 7). Finally the applicant `lead` opens `/app/proposals/1001/negotiation`, reads the data protection notice and acknowledges it (R-NG-06) (`m4-demo.md` J8). [`irc-cases.html`, `irc-view.html` (validation count and the I-18 hold), `negotiation.html`. Applicant views of the deferred proposal and the minor hold: `end-states.html`.]

## What the demo does not run

`m4-demo.md` "What does not run, and why" lists the gaps. Creator and onboarding (J0 after sign-in, J1, J2) answer `not_implemented`. Declared affiliations, guardian consent, the copy request, the stage 2 revision and the Guide are not served. Confidential texts, drafts and R-NG-06 acknowledgements live in the API core's memory, so a restarted cell loses them. The design prototypes for programme set-up (`planning-studio.html`) and approval and publication (`seal-ceremony.html`) therefore have no demo scene.

## Results recorded in the source

The Playwright journeys ran on 2026-10-30 at `m4/int-b 33d6a30` with `retries: 0`. All review specs passed (irc 5 of 5, reviewer 7 of 7, coordinator 5 of 5, committee 4 of 4, judging pages 4 of 4, unit 36 of 36). Applicant journeys passed 23 of 28, and creator and onboarding specs 31 of 54 (`m4-demo.md` "Results of the Playwright journeys").

## Design fixes that still apply

1. Sign-in lands on a "Your work" home, not the account page (`01-navigation-home.md`, `home-*.html`). Scene 1 shows the current landing on the account page.
2. Each role reaches its primary task in at most three clicks. The demo routes, such as `/app/me/assignments` and `/app/me/irc-cases`, become top-row items ("My assignments", "My cases").
3. The account page stays at `/app/me`, reached from the avatar.
4. Navigation, headings and buttons use plain grant language.
