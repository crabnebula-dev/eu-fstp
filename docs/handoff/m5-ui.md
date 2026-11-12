# M5 UI handoff (lanes L-UI1 and L-UI2)

Branch `m5/ui`. Scope: `web/src/grant/**`, `web/src/contract/**`, `web/src/payments/**`, `web/src/operations/**`, plus the navigation and home edits listed below. Source: `docs/handoff/m5-design.md` sections 1.2, 3, 5 and 6, and `docs/design/10-post-grant-screens.md`.

## Screens and how each role reaches them

All pages mount from `web/src/grant/routes.ts`, which `web/src/shell/main.ts` joins before the Judging pages.

| Path | Page | Who sees actions |
| --- | --- | --- |
| `/app/grants` | Grants: own, on the caller's calls (`call.board`), reviewed (`me.assignments`), open by number | everyone signed in |
| `/app/grants/{p}` | Grant overview: state, determination, amount, paid. Determine amount (R-NG-03), accept, approve (NOTE 9), close milestone (I-64), terminate, vault buttons for bank details, dispute, verify, hardship (I-33, R-PR-04) | reviewer, lead, programme manager, finance approver |
| `/app/grants/{p}/contract` | Contract: versions, parties with signature badge beside the formal state (I-96), hash (I-30), draft, clause changes and decisions (R-CT-04), send, sign with the three P-30 routes, advanced approval, decline (R-NG-04) | programme manager, lead, signatory |
| `/app/grants/{p}/payments` | Payment requests with status badges, checks, the checks-failed and changes-requested callouts | grant parties |
| `/app/grants/{p}/payments/new` | Payment form: lines with milestone, amount, evidence URL, release, SPDX licence, notes (I-58, P-34) | lead |
| `/app/grants/{p}/payments/{r}` | Request: lines, checks, line review and changes (I-32, SoD-12), withdraw, approve (HR), release (HR, I-05, I-31, I-33, SoD-04), payee details through the vault (reading 6), confirm paid, close | lead, reviewer, finance approver, releaser, programme manager |
| `/app/grants/{p}/payments/{r}/resubmit` | Resubmit form (a new reference) | lead |
| `/app/operations` | Queues from `payment.queue` (review, approve, release, confirm), contracts to countersign, report links, SoD note | operations roles |
| `/app/programmes/{pr}/reports` | Funder reports: list, generate (R-RP-04), approve (R-RP-03, I-44), draft and approved badges | programme manager, financial signatory, auditor read |

Click paths from sign-in:

- Lead: Home, card "Your applications", "Your grant" link, then the grant page and its links. The negotiation page also links to the grant and contract pages.
- Assigned reviewer: Home, card "Your review assignments", "Grants you review", then the grant page (determination) and Operations (line review).
- Programme manager, finance approver, payment releaser, contract signatory, auditor: Home card "Operations" and the sidebar "Operations" link, then the queues, the grant list and the reports. The sidebar shows "Grants" to everyone.
- Financial signatory (tenant-wide): the sidebar "Operations" link, then reports by programme number.

Edits outside my four folders, needed for reachability: `web/src/home/{model,page,messages.en}.ts`, `web/src/auth/{sitenav,messages.en}.ts` (the account page mirrors the sidebar), `web/src/shell/main.ts`, `web/src/applicant/{negotiation,messages.en}.ts`, and the tests `home.test.ts` and `fuzz_targets.test.ts`. I updated three expectations in `home.test.ts` because the navigation now holds "Grants" and "Operations" and the auditor has a page. No invariant test was weakened.

## Tests

- `web/test/m5ui_models.test.ts`: decoders and bodies (R-NG-03, R-CT-04, I-30, I-32, I-58, I-86, R-RP-03).
- `web/test/m5ui_routes.test.ts`: routes and role reachability (R-NF-03).
- `web/test/m5ui_pages.test.ts`: page smoke tests over the fake DOM (R-NG-03, R-CT-04, I-30, I-32, I-58, R-RP-03, R-NF-03).
- Fuzz target `web/fuzz/postgrant_wire.fuzz.ts` with corpus `web/fuzz/seeds/postgrant_wire/expect.tsv`, registered in `targets.ts` and checked by `fuzz_targets.test.ts`.

## Decisions and open questions for Daniel

1. **No LibPDF Worker on the signing page.** The M5 API route `contract.sign` takes a route only (`wallet_qes`, `qtsp_remote_qes`, `advanced`) and signs on the cell through the signature port. There are no `prepare_signature` or `complete_signature` ops in the registry, so the browser has nothing to sign. The page asks the cell to sign. The vendored LibPDF stays unused by these screens until those ops exist. Strict choice: no signing logic in the browser.
2. **No running total in the payment form.** ADR-006 keeps money arithmetic on the cell. The design asks for a running total before Submit. The page says the platform computes the total and shows it on the request. A cell read for it would let the form show it.
3. **Milestone and plan numbers.** `grant.overview` names neither the agreed plan nor the milestones, and `payment.form` (design section 5) is not in the registry. The determination form asks for the plan number. The payment form asks for a milestone number per line. `decodeOverview` reads optional `plan` and `milestones` (`milestone`, `amount`, `paid`, `due`) when the cell sends them, and then the form shows a milestone list and "Fill available" for unpaid milestones. See the request below.
4. **Hardship request.** It goes through the vault ticket button (`vault.hardship.submit`). The payment form submits milestone claims only. The domain's hardship kind needs evidence from the vault, which the page never holds (I-86).
5. **Request and signatory lists.** No read lists contracts to countersign or grants for the operations roles. The Operations page reads `call.board` for the caller's calls (works for programme staff) and offers open by number otherwise. A signatory or finance approver may have to type a proposal number.
6. **Checks detail.** `payment.status` gives two booleans per request, not which check failed. The checks-failed page lists the four checks in words and says the cell does not name the failed one. Design file `payment-checks-failed.html` shows a table with detail.
7. **Report download.** No op serves the report bytes or the sealed draft. The pages show hashes and state only. `vault.report.download` is not in the registry.
8. **Approver of reports.** The registry names the Financial signatory, while design 10 says an Operations role approves (Q3). The page follows the registry.
9. **Advanced signature request.** `contract.request_advanced` is not in the registry. The signer picks the advanced route, the cell refuses until the programme manager approves with a reason, and the page shows that refusal.
10. **Step-up.** HR ops go through `withStepUp` and the creator step-up dialog. Vault ticket ops that are high risk (`vault.bank.set`, `vault.bank.view_for_release`) use the same path.
11. **Text wording.** All legal-looking text carries a `TODO(legal)` in the label files or comments. No legal citation is written.

## Requests

For the demo lane (`m5/demo`):

- Seed ids are not shown by the cell. Until `grant.overview` carries `plan` and `milestones`, the click-through needs the plan number (agreed plan) and the milestone number printed in the demo script, for the determination form and the payment form.
- The demo accounts need `me.roles` bindings with calls: programme manager on the call (so the grant list shows the proposal), reviewer with an assignment, finance approver, releaser and signatory with programme bindings.
- The cell must serve `/app/grants...`, `/app/operations`, `/app/programmes/{p}/reports` as shell pages (the shell serves every `/app/` path today).
- The vault redirect check requires the vault at `id.<cell host>` on the page's scheme and port, path `/w` or `/r`.

For L-API or the lead:

- Add `plan` (agreed plan id) and `milestones` to `grant.overview`: `[{milestone, amount, paid, due}]`. The UI already reads them.
- Add a read of grants for the caller (all roles), and a "contracts awaiting me" read for the signatory.
- Add `payment.form` as in design section 5 (available per milestone), or let `grant.overview.milestones` carry `available`.

## Known gaps

- Not run in a browser or Playwright: I added no `e2e/m5ui` spec because the cell was not built in this lane. The web tests cover the pages over the fake DOM only.
- No amendment screens (`contract-amendment.html`), mentor or public pages. They are not in L-UI1 or L-UI2 rows.
- No download of the sealed draft, reports or the Guide PDF link on the call page.

## M5 reads follow-up: decisions and open questions for Daniel

Branch `m5/reads`. It answers the three requests above and the lead's reviewer gap of 2026-11-12.

### Reads added

| Op | Route | Rule (d11) | Who gets rows |
| --- | --- | --- | --- |
| `grant.overview` (extended) | `GET /grants/{proposal}` | unchanged: `GRANT_READER` in `GRANT_STATES` | as before. New members `plan` and `milestones` (`milestone`, `amount`, `due`, `paid`, `pending`, `available`, `closed`) |
| `grant.list_mine` | `GET /me/grants` | `Own`, all 16 states | each grant `grant.overview` serves the caller, with `via`: the rule that admitted the caller |
| `contract.awaiting_me` | `GET /me/contracts-awaiting-signature` | `Own`, all 16 states | each latest, live version that waits on the caller's own signature now, where `contract.view` serves the caller |
| `grant.determination_view` | `GET /grants/{proposal}/determination` | `ProposalReviewer`, NEGOTIATION only | the declared, conflict-free assigned reviewer of the proposal |

### Decisions

1. **Lists judge each row again.** Both lists are the caller's own reads. The dispatch then runs `authorize_read` for `grant.overview` or `contract.view` on every candidate proposal. A list therefore never widens those reads: same rule, states, programme scope and SoD. The grant list test checks this both ways for the whole cast in four states.
2. **Candidate proposals come from the roster.** Every proposal holds its lead's Receiving binding from its draft on. Ended bindings count too, so COMPLETED and TERMINATED grants stay listed for their former team and staff.
3. **The signing list follows P-30.** A grantee party waits once the version is sent. The signatory waits only once the grantee side signed. A signed party, a terminated contract and an older version wait on nobody.
4. **`available` on the milestones, not `payment.form`.** It is smaller and fits the overview the form already reads. The domain computes it (`fstp_domain::payment::grant_milestones`) the way the I-58 check folds paid plus pending. It is zero on a closed milestone and outside IN_EXECUTION. A property test checks it against the payment reference, and an example test checks that one cent above it is refused.
5. **The browser computes no money.** "Fill available" copies the cell's `available` string. A closed milestone offers no fill.
6. **No MCP tool for the new reads.** `grant.overview` and `grant.determine_amount` have none, so the lists and the determination view are web only (I-85).
7. **Reviewer gap (lead, 2026-11-12, R-NG-03).** `GRANT_READER` stays unchanged. A narrow read, `grant.determination_view`, gives the assigned reviewer the proposal state, the plan the determination starts from (the current agreed plan, else the effective plan), its total, the current determination and its amount. It names no paid sum, contract, request or account. A new `ReadRule::ProposalReviewer` judges the caller's own reviewer assignment of the target proposal. A conflict refuses with I-03 first, an undeclared assignee with R-CF-02, anyone else with R-AC-01. Every state other than NEGOTIATION is a judged refusal (D11). The grant page falls back to this view when the overview is refused, so Home, "Grants you review", grant, determination works by clicking.
8. **Labels.** "Grants on your calls" became "Grants in your programmes", since the list now holds finance, release, signatory and auditor rows. "Contracts to countersign" became "Contracts awaiting your signature".

### Open questions for Daniel

- Should the assigned reviewer also read the overview after NEGOTIATION, for the line review of payment requests (SoD-12)? Today the reviewer reaches line review from Operations only.
- Should `contract.awaiting_me` get a read-only MCP tool, as `contract.view` has? It has none for now.
- `via` names one admitting rule per grant. A person with two roles on a grant sees the first match only.

### Tests

- `crates/fstp-domain-testkit/tests/i58_r_pr_07_milestone_funds_view.rs` (I-58, R-PR-07): property machine and edge cases.
- `crates/fstp-access/tests/m5reads_d11_list_reads.rs` (D11, I-85, I-86, R-PR-07, R-NG-03).
- `crates/fstp-api-testkit/src/harness_m5_reads.rs` (R-AC-01, D11, R-CT-01, P-30, R-PR-07, I-58, R-NG-03, I-03, R-CF-02, I-86).
- The narrowed direct and HTTP authorisation matrices agree with the reference for all four reads (`FSTP_MATRIX_OPS`).
- `web/test/m5reads.test.ts` (R-AC-01, R-NF-03, R-PR-07, R-NG-03).
- `e2e/speedrun/speedrun.ui.spec.ts`: the reviewer step now clicks to the determination form. Not run in this lane.

## Polish: labels, decisions

Lane `m5/polish-text`. Display text and chips only; no data flow or access logic changed.

1. **State chip.** `badge()` in `web/src/grant/kit.ts` now shows one translated label. The formal code stays as visually hidden text (`state-name fstp-visually-hidden`, read as "(CODE)") and as `data-state` on the chip, so I-96 still holds for assistive technology and tests. Operations contract rows use the new `contractStateBadge`; Operations grant rows map proposal states through `kit.state.*`.
2. **Payment request labels.** The 64-bit reference is no longer a label. Lists and the request page read "Payment request N for milestone M", where N is the position among the grant's requests ordered by reference. The Operations queue has no list, so it reads "Payment request for milestone M of proposal P". The request page shows a muted "Reference {id}" line. Line review fields read "Line N (milestone M)".
3. **Determination.** The grant and reviewer pages read "Recorded" with a muted "Reference {id}".
4. **Open by number.** The grant hub and Operations forms sit in a `details` disclosure. An empty submit moves focus to the field and shows no banner. A non-digit entry still shows the error.
5. **Contract link.** "Contract of proposal {id}" on the grant page. Operations shows the same label with a state chip.
6. **Pre-check.** The newest run is under "Latest check" (`#precheck-latest`); the rest are under "Earlier checks".
7. **Reports.** Programmes now come from every role binding, since each binding names its programme. With exactly one, the link reads "Open the funder reports of your programme (programme N)". The number form moved into a disclosure. A tenant-wide Financial signatory with no binding at all still needs the number: no read lists programmes for them. Open question for Daniel.
8. No test expectation was weakened. Two tests were added in `web/test/m5ui_pages.test.ts`.

## Polish: line review access, decisions

Lane `m5/polish-access`. A browser click-through of `UNDER_REVIEW` found that nobody could do the line review by clicking, that R1's Home gave no way to it, and that a release needed six vault steps first.

### Who can do what now

| Person | What they reach by clicking |
| --- | --- |
| Committee member R1 (assigned reviewer) | Home card "1 payment request to review", or the sidebar Operations link. Operations, "To review", the request page with each line's evidence and the decision forms |
| R2, R3, R4, H1, I1 and other roles without the right | The request page still answers R-AC-01. Only the declared, conflict-free assigned reviewer reads the line review view |
| Finance approver F1 | Operations, "To approve", approve |
| Payment releaser P1 | Operations, "To release", release. Refused with I-33 until the P-36 hold ends |

### Decisions

1. **A narrow read, not a wider `GRANT_READERS`.** `payment.line_review_view` (`GET /grants/{proposal}/payment-requests/{request}/line-review`, `ReadKind::GetLineReview`) uses the existing `ReadRule::ProposalReviewer`: the caller's own reviewer assignment of the grant, declared, conflict first (I-03, R-CF-02). It is web only, as `payment.review_line` is (I-85).
2. **D11 rows.** The read is open only while the grant is IN_EXECUTION. Every other proposal state is a judged refusal. The dispatch then serves only a request of that grant in UNDER_REVIEW. Any other request, existing or not, is refused as R-AC-01, so the view reveals no other request.
3. **What it holds.** The request row as `payment.status` shows it (status, kind, both checks, lines with requested and approved amounts), and per line the evidence the lead gave: location, release, licence and report. No bank detail, account, payee or paid sum (I-86). The reference matrix has a `LineReview` rule, and the narrowed direct and HTTP matrices agree.
4. **Evidence source.** The domain projection keeps no line evidence, so the API core journal now keeps the evidence of each `RequestPayment` it recorded, bounded. A text the core did not store shows as "-", never a guess.
5. **The page.** When `payment.status` is refused to a committee member, the request page reads the line review view and shows it with the same request label, reference line, state chip and line labels as the full page. The back link goes to Operations, since the reviewer reads no payment list. After the last line is decided the view closes, and the page says "The line review of this request is complete".
6. **Home and sidebar.** A committee member whose `payment.queue` holds a review gets the card "Payment requests to review" first on Home, linking to Operations. The shell adds the sidebar Operations link for such a person only. The mailbox's `payment.review` message links to Operations, which now leads to a working page.
7. **SoD unchanged.** The reviewer is offered no approve or release button. The test checks that the reviewer's approval is refused (SoD-04, I-05).
8. **Bank details in the seeds.** From `IN_EXECUTION` on, every grant scene runs the lead's `vault.bank.set` and finance's `vault.bank.verify`, each followed by the vault page's own action (`grantdemo::act_on_ticket`, shared with `/r/act`). The entry happens at the seed's instant, so the P-36 hold still runs. The first release press is refused with I-33.
9. **The hold, shown.** The seed reply has a `bank` member. `run.sh` prints when the details were entered, that they are verified, and when the hold ends. `/demo` shows `#demo-bank` with the same facts. The programme's live P-36 is 7 days.
10. **The hold link.** "Advance past the P-36 bank hold" now moves the clock one minute past the end of the hold of the latest entry, read from the programme's live P-36. Without bank details it keeps the old 30 days. This closes open question 2 of `m5-demo.md`.
11. **PAID and ALL_CLOSED.** These scenes now wait for the hold before the release, instead of writing bank details at setup time.
12. **Step-up in the click-through.** Approve and release open the step-up dialog in the demo. The spec confirms it with the dialog's demo button, as a presenter would.

### Requirements and invariants covered

R-PR-08, R-PR-01, R-PR-05, R-AC-01, R-CF-02, R-NF-03. I-03, I-05, I-32, I-33, I-60, I-85, I-86, SoD-04, D11.

### Tests

- `crates/fstp-access/tests/m5reads_d11_list_reads.rs`: `r_pr_08_d11_line_review_view_is_the_assigned_reviewers_in_execution`.
- `crates/fstp-api-testkit/src/harness_m5_reads.rs`: `r_pr_08_assigned_reviewer_reads_and_decides_the_line_review`, `r_pr_08_d11_line_review_view_is_closed_outside_execution`.
- `scenario/postgrant.rs`: `m5_demo_grant_scenes_reach_their_states` now checks the verified bank details and the running hold.
- `web/test/m5reads.test.ts` and `web/test/home.test.ts`: three `r_pr_08_*` tests.
- `e2e/speedrun/speedrun.ui.spec.ts`: `ui_payment_under_review_to_released_by_clicking`, clicking only.

### Open questions for Daniel

1. The line review view is closed once the request leaves UNDER_REVIEW, so the reviewer cannot look back at a decided request. Should the reviewer keep a read-only view of requests they decided?
2. The Operations page offers R1 a funder reports link per programme, which R1 cannot open. It was left as is to keep this lane's web edits small.
3. `review_home/review_usability_programme_manager_pages_load.spec.ts` fails twice in this run, on `/programmes/1/draft/previews/contract` (501) and `/calls/1/findings-status` (403). Neither read is touched by this lane.
