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
