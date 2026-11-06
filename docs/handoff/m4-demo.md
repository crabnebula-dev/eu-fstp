# M4 demo: the pages against fstp-e2e-cell

Written in lane m4int-b on 2026-10-30 for the demo that afternoon. It records how to run the M4 pages in Chromium against `fstp-e2e-cell`, the click path of each journey, and what does not run yet with its reason. Read it with `docs/handoff/m4-design.md` sections 2, 3.7, 3.9 and 8.7.

Every person, proposal and text in the demo is synthetic. The cell is test only (layering rule A9). Its control routes exist on a loopback control base and never on a cell origin.

## Run it

```sh
tools/demo/run.sh            # build the pages and the cell, start it with --demo-signin, seed "review stage1"
FSTP_DEMO_SIGNIN=off tools/demo/run.sh   # the same, with passkeys only, as the e2e suite runs the cell
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
- Each seed replaces the whole cell state and prints one-time enrolment links. The demo page lists the same links. Open a link, choose "Create a passkey", and the person is signed in and lands on the home page `/app/`. A second sign-in uses the passkey on `/auth/login`.
- Use one browser profile per person, such as a new incognito window each. A persona's link works once.

## The site and the demo sign-in (2026-11-04, lane m4/site)

Daniel asked for the pages to become a proper website to share, built with the TypeScript of `web/`, and ruled out a framework or bundler. He also said: "for the demo it makes NO SENSE to have to use and generate passkeys."

- **One document.** Every `/app/` page renders in one document (`web/src/core/router.ts`). A link or a form that leads to another `/app/` page changes the URL with the History API, with no reload. Back, Forward, a reload and a pasted deep link show the same page. Focus moves to the page's `h1`, and a polite live region speaks its title.
- **Reactive pages.** After an action, the page shows the outcome in place, from the reply or a re-read: the stage 1 close on the call board, the declaration and the score sheet of an assignment, the plan total.
- **Tokens and layout.** `web/src/site/tokens.css` and `web/src/auth/tokens.css` are copies of `design/tokens.css`. Every page sits on them in light and dark, with the top bar, the sidebar and the footer of `nav-pattern.html`. A proposal state shows as a chip with its text.
- **The front door.** `/demo` names the scene in `#demo-scene`, then each person with their role and one line on what they can do.
- **Demo sign-in.** `tools/demo/run.sh` starts the cell with `--demo-signin` (`FSTP_DEMO_SIGNIN=off` turns it off). The front door then gives each person a "Sign in as <name>" link. One click opens a session on the cell origin and lands on `/app/`, with no passkey. The link carries a single-use token of at most five minutes of cell clock, which the control base issues and `/auth/demo-signin` redeems once. A reused, expired or forged token is refused with an alert and sets no cookie. The session is a passkey session in the fake port, so every guard holds. Its step-up dialog shows a plain "Confirm" button, and the command still records a step-up. Every `/app/` page of such a session, and the M3 page `/auth/account`, says "Demo sign-in" in the top bar. Both pages name the session's method as a passkey, since the fake port records it so. On `/auth/account`, removing a passkey or ending a session still asks for a passkey, which a demo account does not have, so that page is not part of the demo. The demo modules are served only with the flag. The route, the flag and the bypass live in `fstp-e2e-cell` only (rule A9). Without the flag the route answers 404, which `e2e/site/demo.spec.ts` and `crates/fstp-web/tests/demo_signin_absent.rs` check.
- **Public pages.** In a scene with a published call, the front door's top bar links "Public open calls" (`a[data-demo-link="public-calls"]`), the page `/p/1/` on the cell origin. The programme page lists the open calls. Each call page shows the dates with their zone, the budget and the P-04 range as server text, the P-09 rules and the AI disclosure. The pages hold no script and set no cookie, so they work with scripts off. No Guide link and no grant shows yet: the Guide needs the data protection texts, which no port supplies, and the grantee choice records come with M9. `/p/1/funded` and `/p/1/finished` say that nothing is public yet.
- **Account.** The sidebar's Account opens the profile page `/app/me`, with the verification status, the roles held and the sessions. The top bar's "Passkeys and sessions" opens the M3 page `/auth/account`, which adds and removes passkeys.

Screens not built, each because its operation is missing:

- `home-operations`: no seeded persona and no queue read.
- `packing-check`: no pre-submission check operation.
- The "on hold" panel of `end-states`: `proposal.view` carries no I-18 hold member.
- `admin-members` and `admin-org`: no read of the tenant's members with their roles, or of the organisation record.

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

Interim, pending Daniel (design section 15.0, row of 2026-10-31). Every path starts on the demo page of the control base, `http://127.0.0.1:<port + 1>/demo`. Choose a scene there. Then open the person's link under "People of this scene" in its own incognito window and choose "Create a passkey". The line under each person says what they can do in that scene.

After the passkey, the person lands on the home page `/app/`, "Your work". It lists one link per piece of work for each role the person holds. Every step below starts there and follows links only. Each page header links to Home, the person's role pages, the applicant pages and Account, and the account page links back to Home.

A person whose link is used signs in again with the passkey: choose the cell link at the top of the demo page, which opens `/auth/login`. A deep `/app/` page opened without a session goes to the login page and returns to that page after sign-in.

### Tenant admin (J0, first step)

1. Choose "Reset", then open the link of the first tenant admin (`synthetic-a1-...`).
2. The home page lists "Onboarding of your organisation", "Open a new programme draft" and "Approvals waiting for a tenant admin". Choose the onboarding link to see the steps and their status.
3. Choose "Account" in the header. The account page lists the session and the device. Sign out there, sign in again with the passkey, and the home page shows again.

The identity page and the onboarding steps load, but their operations are not served yet (see "What does not run").

### An applicant drafts and submits (J4)

1. Choose the applicant scene `OPEN_CALL`.
2. The demo page names the sign-up address. Open `/auth/signup`, enter a synthetic address such as `demo@e2e.invalid` and send it.
3. The demo page never reloads by itself, so focus stays where it is. Choose "Refresh this page", then, under "Messages the cell sent", open the sign-up link and create a passkey.
4. The home page says that the person holds no role yet and offers "Open calls". Choose it, then the call. The page shows the amounts as server text, the deadline with its zone and the AI disclosure. The public pages show the same call with no sign-in: choose "Public open calls" on the demo page.
5. Choose "Start a proposal". The workspace autosaves the title, the neutral summary and the narrative as you type (I-21).
6. Open "Plan", enter one milestone of 1500.50 with a start and a due day, and save. The cell shows the total. A non-canonical amount such as 1500.5 is refused in the page.
7. Open "Eligibility" and state a country. It goes to the vault route only (R-NG-01).
8. Open "Submit", tick the data protection notice, choose "No ethics issue" and submit. The proposal page reads SUBMITTED.
9. Choose "+60 minutes" on the demo page to pass the deadline. A draft submitted after it is refused, and the submit page says so.

### The programme manager (J1, J3)

1. Choose any review or applicant scene, then open the `Programme manager M1` link.
2. The home page lists "Programme creator of programme 1", "People and invitations of programme 1" and the call board of each published call. Choose the creator link to open the creator review of programme 1, or the people link to invite.

### The FSTP coordinator (J5)

1. Choose `review submitted`, then open the `c1` link.
2. The home page lists "Intake queue of SuperSAFE open call 2026". Choose it. The intake lists the submitted proposals as "Proposal" and an id.
3. Open a declaration. Only the title and the neutral summary show, and the content route refuses (R-CF-02). Declare no conflict.
4. The knock-out page shows the content and the three SuperSAFE P-09 criteria. Fail one without a reason: the page asks for one. With a reason, the proposal becomes INELIGIBLE.
5. Choose `review stage1_scored`, open the new `c1` link, and choose "Call board of SuperSAFE open call 2026" on the home page. Record the stage 1 close of x and of w. x moves to STAGE2 and w to NOT_SELECTED. No control states an outcome (I-07, I-08).
6. Choose `review stage1`. When R1 declares a notifiable conflict on w, the coordinator's home page link "Notifiable conflicts of SuperSAFE open call 2026" lists its draft (R-CF-04).

### Assigned reviewers (J6)

1. Choose `review stage1`, then open the `r1` link.
2. The home page lists "Your review assignments". Choose it, then the assignment of x. Before the declaration only the title and summary show. Declare no conflict, and the content and the score sheet appear.
3. Enter integers on the 0 to 5 scale of P-01. 3.5 or 6 is refused in the page. Save, reload, and the score is kept.
4. Choose `review stage1_scored` and open the new `r1` link. From "Your review assignments", "Correct the score" needs a reason (I-23). The ranking summary needs a title, a neutral summary and a rationale.
5. Choose `review stage2`, open the new `r1` link, choose "Your review assignments" and then the stage 2 page of x. Ask a question, or record "no questions". Once R1 and R2 record "no questions", the window closes and x is RANKED.

### The committee (J7)

1. Choose `review ranked`, then open the `r1` link.
2. The home page lists "Ranking of SuperSAFE open call 2026". Choose it. The table lists x, v and w in order, with a weighted score per P-01 criterion, the requested amount and the remaining budget. It has no findings column.
3. Open the `r4` link: the row of w shows "recused" only, without title, summary or scores (Q16).
4. A round opened from the ranking page shows on the home page of each committee member as "Open cut-off round of SuperSAFE open call 2026".

### The IRC up to NEGOTIATION (J8)

1. Choose `review irc_review`, then open the `i1` link.
2. The home page lists "Your IRC cases". Choose it, then the case of x. Before the declaration the case read refuses. Declare no conflict, and the case shows the proposal and "nominated", with no score, ballot or rationale (R-IR-03).
3. Validate. Then open the `i2` link, declare and validate x. x enters NEGOTIATION.
4. Open the `c1` link and choose "Call board of SuperSAFE open call 2026": x reads NEGOTIATION.
5. v is minor-flagged without a consent record. Two validations leave it in IRC_REVIEW (I-18). A concern on u needs its text and defers u, since call 2 is published (NOTE 7).
6. Choose the applicant scene `NEGOTIATION` and open the lead's link. The home page lists "Your proposal: Synthetic open sensor kit". Choose it, then the negotiation link: the lead reads the data protection notice and acknowledges it (R-NG-06).
7. In the applicant scene `IRC_REVIEW_MINOR`, the guardian's home page lists "Guardian consent for Synthetic school data vault", which opens the guardian page.

## Progress map and activity log (2026-11-05, lane j3)

- **Applicant.** On the front door, choose the scene `/demo/applicant?at=STAGE2` and "Sign in as" the lead of x. On the home page, the card of "Synthetic open sensor kit" now holds "Progress" and "Activity". The proposal page holds the same two links.
- **Progress** (`/app/proposals/1001/progress`, "Application progress"). The map draws sixteen nodes, each a link named by its plain label, its formal state and its status. DRAFT, SUBMITTED and STAGE1 show as completed and STAGE2 as current, with a ring that stops under reduced motion. "Progress as a list" holds the same nodes in the same order. A node or list link opens that stage's help panel in place. With no link chosen, the STAGE2 panel shows its 14-day window from the overlay.
- **Activity** (`/app/proposals/1001/activity`, "Activity log"). Newest first: the two reviewer questions, the move into STAGE2, the move into STAGE1, then the submission receipt with "Anchor pending". A filter narrows the log by kind.
- **Reviewer.** In `/demo/review?stage=stage2`, R1's assignment page shows the "Proposal status" strip with STAGE2 current. An IRC member's pages show no strip (O-58). Whether a reviewer who has not declared yet sees the strip is the read's decision alone. Opened by URL, the progress page shows a reviewer the strip and a refusal, with no map and no withdrawal.
- **Guardian.** In `/demo/applicant?at=IRC_REVIEW_MINOR`, the guardian's home card and the guardian page hold "Activity". The log shows their guardian step (O-60).
- No new seed: every scene runs from genesis through production commands, so the ledger already holds each route.
- `e2e/journey/voyager.spec.ts` runs with `tools/demo/run.sh e2e journey/`. Four of its five tests pass. The applicant test expects the move into STAGE2 as the newest entry, but the STAGE2 scene records two reviewer questions after that move, so "Question received" is newest.

## The MCP server (2026-11-06, lane W3c)

The cell serves `/mcp` and `/mcp/public` at the ADR-013 floor revision, 2025-06-18. One command opens a public session and prints its `Mcp-Session-Id`:

```sh
curl -si http://a.fstp.localhost:8640/mcp/public -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
```

- Send that id back as `Mcp-Session-Id`, with `MCP-Protocol-Version: 2025-06-18`, then `notifications/initialized`, `tools/list` and `tools/call`. `/mcp/public` lists the eight public tools only.
- `/mcp` without a token gets 401 with a Bearer challenge naming `/.well-known/oauth-protected-resource`. The demo cell is a test cell, so its two metadata documents name its `http` origin as the issuer. No route issues a token yet.

## Results of the Playwright journeys

Run against the cell on 2026-10-30 at m4/int-b 33d6a30 (after lanes m4eng and m4disp) with Chromium 1248 and the virtual authenticator, `retries: 0`.

| Specs | Passed | Not passing, and why |
| --- | --- | --- |
| `e2e/review/irc.spec.ts` | 5 of 5 | |
| `e2e/review/reviewer.spec.ts` | 7 of 7 | |
| `e2e/review/coordinator.spec.ts` | 5 of 5 | |
| `e2e/review/committee.spec.ts` | 4 of 4 | |
| `e2e/review/i17_judging_pages.spec.ts` | 4 of 4 | |
| `e2e/review/unit/*` | 36 of 36 | |
| `e2e/applicant/*` journeys | 23 of 28 | The Guide, affiliations, the copy request, the stage 2 revision and guardian consent (see below) |
| `e2e/creator/*`, `e2e/onboarding*.spec.ts` | 31 of 54 (the page-logic and wire specs), counted before m4disp | The journeys need the tenant and creator dispatch (see below) |
| `e2e/i17-vault-origin-release.spec.ts` | 0 of 4 | It targets the M3 devstack control routes (`/test/scenario/negotiation`), which the e2e cell does not serve |
| `e2e/applicant/review_w4b_pages.spec.ts` fuzz check | 0 of 1 | It needs the review decoders' fuzz target (lane W1c) |

### Run of 2026-10-31: the home page and the click-through journeys

Run against the cell on 2026-10-31 at m4/int-b 9c32f1a plus lane m4/home (the home page, `me.roles` and the site navigation), with the same browser and `retries: 0`. The new spec `e2e/navigation/click_through.spec.ts` signs each person in from the demo page and reaches their work by clicking only.

| Specs | Passed | Not passing, and why |
| --- | --- | --- |
| `e2e/navigation/click_through.spec.ts` | 152 of 153 | `nav_committee_member_r4_review_ranked_reaches_assignment_and_ranking`: the spec expects R4 to hold an assignment in `review ranked`. R4 declared a conflict on w, which released that assignment, so R4 has none to open |
| `e2e/review/*` and `e2e/review/unit/*` | 63 of 63 | |
| `e2e/applicant/*` | 48 of 54 | The six known failures: the Guide, affiliations, the stage 2 revision, guardian consent, the copy request and the review decoders' fuzz check |
| `e2e/onboarding.spec.ts`, `e2e/onboarding_logic.spec.ts` | 17 of 17 | |
| `e2e/creator/*` | 23 of 37 | The import, second-person and SuperSAFE journeys (14) wait for the programme invitation mail: the e2e cell sends admin invitations only |

## What does not run, and why

Each item needs a file outside this lane's scope, so it is a request to the lead.

- **Creator and onboarding (J0 after sign-in, J1, J2).** Lane m4eng gave `fstp-engine` the `Creator`, `Import` and `Bridge` envelopes. `fstp-api-core` still answers `not_implemented` for `creator.*`, `import.*` and `tenant.*`. Lanes m4wire and m4tenant wire them, and lanes m4creator and m4guide close the `fstp-creator` and `fstp-guide` seams the journeys reach.
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
