# M4 demo: the pages against fstp-e2e-cell

Written in lane m4int-b on 2026-10-30 for the demo that afternoon. It records how to run the M4 pages in Chromium against `fstp-e2e-cell`, the click path of each journey, and what does not run yet with its reason. Read it with `docs/handoff/m4-design.md` sections 2, 3.7, 3.9 and 8.7.

Every person, proposal and text in the demo is synthetic. The cell is test only (layering rule A9). Its control routes exist on a loopback control base and never on a cell origin.

## Run it

```sh
tools/demo/run.sh            # build the pages and the cell, start it, seed "review stage1"
tools/demo/run.sh seed review irc_review
tools/demo/run.sh seed applicant OPEN_CALL
tools/demo/run.sh mail <email>      # the links the cell mailed, such as a sign-up proof
tools/demo/run.sh advance 60        # move the cell clock 60 minutes forward
tools/demo/run.sh reset             # an empty cell and its first tenant admin link
tools/demo/run.sh e2e review/       # the Playwright journeys against the running cell
tools/demo/run.sh stop
```

- The cell origin is `http://a.fstp.localhost:8640`. Chromium and Chrome resolve every name under `localhost` to loopback and treat it as a secure context, so passkeys work over plain HTTP.
- `FSTP_DEMO_PORT` moves the four listeners. `FSTP_DEMO_STATE` moves the pid, the log and the stack manifest (default `target/demo`).
- The build needs `web/node_modules` (ADR-003) and the cargo cache. Set `CARGO_NET_OFFLINE=true` on a machine without network.
- Each seed replaces the whole cell state and prints one-time enrolment links. Open a link, choose "Create a passkey", and the person is signed in. A second sign-in uses the passkey on `/auth/login`.
- Use one browser profile per person, such as a new incognito window each. A persona's link works once.

## The seeds

| Command | What the cell holds |
| --- | --- |
| `seed review submitted` | Programme 1 (SuperSAFE, compiled from the `fstp-programme` fixture), call 1 published and past its deadline, proposals x, z, w and v SUBMITTED |
| `seed review stage1` | x and w in STAGE1 with R1 to R4 assigned. R3 and R4 declared at admission (R-EV-02 needs P-03 declared reviewers), R1 and R2 have to declare |
| `seed review stage1_scored` | As stage1, every assignee scored: x at 100.00, w at 60.00 against P-02 75.00 |
| `seed review stage2` | x in STAGE2 with R1 and R2 declared |
| `seed review ranked` | x, v and w RANKED with ranking summaries, R4 conflicted on w |
| `seed review ranked_tie` | x and w RANKED with equal effective scores |
| `seed review irc_review` | x, v and u in IRC_REVIEW after a recorded cut-off round, I1 and I2 assigned, call 2 published |
| `seed applicant OPEN_CALL` | Call 1 open, its deadline 30 minutes after the cell clock |
| `seed applicant <state>` | One proposal of the lead in STAGE2, NEGOTIATION, NOT_SELECTED, DEFERRED_AFTER_CONCERN, INELIGIBLE or IRC_REVIEW_MINOR |

Every seed runs from genesis through production commands. Operations that a page route reaches go through `ApiCore::dispatch` with the actor's session: the workspace, the submission, scores, ranking summaries, stage 2 questions, "no questions" and IRC verdicts. The rest goes through the engine port, because no M4 route reaches it: the programme and its activation, grants, calls, drafts, plans, assignments, declarations, the knock-out, admission, the stage 1 close and the cut-off rounds of change D5.

## Click paths

### Tenant admin passkey sign-in (J0, first step)

1. `tools/demo/run.sh reset`, then open the printed enrolment link.
2. Choose "Create a passkey". The account page lists the session and the device.
3. Sign out on the account page, open `/auth/login` and choose the passkey sign-in.

The identity page and the onboarding steps load, but their operations are not served yet (see "What does not run").

### An applicant drafts and submits (J4)

1. `tools/demo/run.sh seed applicant OPEN_CALL`.
2. Open `/auth/signup`, enter a synthetic address such as `demo@e2e.invalid` and send it.
3. `tools/demo/run.sh mail demo@e2e.invalid` prints the proof link. Open it and create a passkey.
4. Open `/app/calls`, then the call. The page shows the amounts as server text, the deadline with its zone and the AI disclosure.
5. Choose "Start a proposal". The workspace autosaves the title, the neutral summary and the narrative as you type (I-21).
6. Open "Plan", enter one milestone of 1500.50 with a start and a due day, and save. The cell shows the total. A non-canonical amount such as 1500.5 is refused in the page.
7. Open "Eligibility" and state a country. It goes to the vault route only (R-NG-01).
8. Open "Submit", tick the data protection notice, choose "No ethics issue" and submit. The proposal page reads SUBMITTED.
9. `tools/demo/run.sh advance 60` passes the deadline. A draft submitted after it is refused, and the submit page says so.

### The FSTP coordinator (J5)

1. `seed review submitted`, then open the `c1` link.
2. `/app/calls/1/intake` lists the submitted proposals as "Proposal" and an id.
3. Open a declaration. Only the title and the neutral summary show, and the content route refuses (R-CF-02). Declare no conflict.
4. The knock-out page shows the content and the three SuperSAFE P-09 criteria. Fail one without a reason: the page asks for one. With a reason, the proposal becomes INELIGIBLE.
5. `seed review stage1_scored`, sign in as `c1` again, and open `/app/calls/1/board`. Record the stage 1 close of x and of w. x moves to STAGE2 and w to NOT_SELECTED. No control states an outcome (I-07, I-08).
6. `seed review stage1`: when R1 declares a notifiable conflict on w, `/app/calls/1/notifiable-conflicts` lists its draft (R-CF-04).

### Assigned reviewers (J6)

1. `seed review stage1`, then open the `r1` link and `/app/me/assignments`.
2. Open the assignment of x. Before the declaration only the title and summary show. Declare no conflict, and the content and the score sheet appear.
3. Enter integers on the 0 to 5 scale of P-01. 3.5 or 6 is refused in the page. Save, reload, and the score is kept.
4. `seed review stage1_scored`: "Correct the score" needs a reason (I-23). The ranking summary needs a title, a neutral summary and a rationale.
5. `seed review stage2`, sign in as `r1`, and open the stage 2 page. Ask a question, or record "no questions". Once R1 and R2 record "no questions", the window closes and x is RANKED.

### The committee (J7)

1. `seed review ranked`, then open the `r1` link and `/app/calls/1/ranking`.
2. The table lists x, v and w in order, with a weighted score per P-01 criterion, the requested amount and the remaining budget. It has no findings column.
3. Sign in as `r4`: the row of w shows "recused" only, without title, summary or scores (Q16).

Opening a cut-off round, casting and delegating ballots are not served yet (see below). The irc_review seed records a round through the engine instead.

### The IRC up to NEGOTIATION (J8)

1. `seed review irc_review`, then open the `i1` link and `/app/me/irc-cases`.
2. Open the case of x. Before the declaration the case read refuses. Declare no conflict, and the case shows the proposal and "nominated", with no score, ballot or rationale (R-IR-03).
3. Validate. Then sign in as `i2`, declare and validate x. x enters NEGOTIATION.
4. Sign in as `c1` and open `/app/calls/1/board`: x reads NEGOTIATION.
5. v is minor-flagged without a consent record. Two validations leave it in IRC_REVIEW (I-18). A concern on u needs its text and defers u, since call 2 is published (NOTE 7).
6. `seed applicant NEGOTIATION`, open the `lead` link and `/app/proposals/1001/negotiation`: the lead reads the data protection notice and acknowledges it (R-NG-06).

## Results of the Playwright journeys

Run against the cell on 2026-10-30 with Chromium 1248 and the virtual authenticator, `retries: 0`.

| Specs | Passed | Not passing, and why |
| --- | --- | --- |
| `e2e/review/irc.spec.ts` | 5 of 5 | |
| `e2e/review/reviewer.spec.ts` | 7 of 7 | |
| `e2e/review/coordinator.spec.ts` | 3 of 5 | Both need the assignment view `review.assignments`, which the registry lacks |
| `e2e/review/committee.spec.ts` | 1 of 4 | `committee.open_round`, `committee.cast` and `committee.delegate` are not in the registry |
| `e2e/review/i17_judging_pages.spec.ts` | 4 of 4 | |
| `e2e/review/unit/*` | 36 of 36 | |
| `e2e/applicant/*` journeys | 17 of 28 | The Guide, affiliations, the copy request, the stage 2 revision, guardian consent, and the five withdrawal and one NOT_SELECTED specs that read the proposal after it left the review (see below) |
| `e2e/creator/*`, `e2e/onboarding*.spec.ts` | 31 of 54 (the page-logic and wire specs) | The 23 journeys stop at the identity page, which reads `me.get_verification` first (see below) |
| `e2e/applicant/review_w4b_pages.spec.ts` fuzz check | 0 of 1 | It needs the review decoders' fuzz target (lane W1c) |

## What does not run, and why

Each item needs a file outside this lane's scope, so it is a request to the lead.

- **Creator and onboarding (J0 after sign-in, J1, J2).** `fstp-engine` has no `Creator`, `Import` or `Tenant` envelope and no creator part of `EngineState` (design section 4.2, lane W2e). So `fstp-api-core` cannot dispatch any `creator.*`, `import.*` or `tenant.*` operation, and answers `not_implemented`. The registry also lacks `me.get_verification`, which the identity page reads first. The activation composition of `fstp-engine::compose` refuses every programme for the same reason.
- **Committee rounds (J7).** `fstp-access::OPS` routes no `committee.open_round`, `committee.cast` or `committee.delegate` (the W3a gap that `t_authz_matrix_direct` names).
- **Coordinator assignment (J5).** The page reads `review.assignments`, which `OPS` lacks.
- **Applicant reads after the review (J4).** The `Team` read rule admits active Receiving bindings only, and the domain ends them when a proposal is WITHDRAWN or NOT_SELECTED. The withdrawal itself is accepted, but the proposal page cannot read the new state afterwards.
- **Declared affiliations.** `port::Affiliations` is a W0 placeholder with private fields, so no request can build it.
- **Guardian consent.** `port::VerificationPurpose` has no guardian consent purpose, and the vault origin is not served.
- **Copy request.** The outbox port has no write method (R-SB-04 is recorded in M6).
- **Stage 2 revision.** `stage2.revise` needs `RecordPlanVersion` and `SubmitRevision` in one entry. Dispatch executes one command per call.
- **The Guide.** `calls.guide` needs the creator artefacts, which are not in the engine state.
- **Confidential texts through the ports.** `port::ReadClearance` is a W0 placeholder that only `port.rs` can build, so `TextStore::get` and `Sealer::open` cannot be called. The API core keeps the texts it stored, and the content frozen at submission, in process memory instead (`content.rs`).
- **Plans and content across a restart.** The domain exposes no public read of a proposal's plans, scores or stage 2 thread (lane W1b). The API core folds them from the commands it executed (`journal.rs`). Its workspace and frozen content live in its memory (`content.rs`). A proposal whose creation or submission this core did not fold is unknown to it. Every read and every derived plan member of an unknown proposal fails closed with `not_implemented`. It never answers with an empty draft, a wrong plan or a wrong refusal. One cell process therefore runs one API core per ledger, and a restarted cell loses the drafts. The fix needs a domain read accessor (W1b) and a workspace port with a read clearance in `port.rs` (the lead, W6).
- **The negotiation notice acknowledgement.** R-NG-06 acknowledgements are kept in the API core's memory only, with no ledger or outbox record and no audit entry of their own. They need a write port (W6).

## Security notes for the demo

- **Passkeys.** The cell stores the attested COSE public key at registration. Every login and step-up assertion is verified over the authenticator data and the SHA-256 of the client data, through `fstp-crypto` (aws-lc-rs). A forged or foreign signature is refused. The cell does not call `fstp_webauthn::verify_assertion`, which needs an `https` origin without a port.
- **The control base.** `http://127.0.0.1:<port + 1>` refuses any request with an `Origin` header, a `Sec-Fetch-Site` other than `none`, or a `Host` other than `127.0.0.1` with the control port. So a web page open in the demo browser cannot reset the cell or mark an identity verified. `tools/demo/run.sh` and the Playwright request fixture send none of these headers.
- **Submissions name their plan.** Dispatch names the latest plan in a submission before the action digest is made. An agent's prepared submission, its pending view and the user's confirmation therefore carry the same plan (I-85). A plan the agent records after the preparation is never the one confirmed.
