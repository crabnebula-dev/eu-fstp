# M5 demo: the post-grant lifecycle in fstp-e2e-cell

Lane L-DEMO, branch `m5/demo`, written 2026-11-12. Read it with `docs/handoff/m4-demo.md`, `docs/handoff/m5-design.md` sections 1.2 and 7, and `docs/handoff/m5-ui.md`. Every person and text is synthetic. The cell is test only (layering rule A9).

## Run it

```sh
export FSTP_DEMO_PORT=8660 FSTP_DEMO_STATE=$PWD/target/demo   # a port of your own
FSTP_DEMO_SEED="grant NEGOTIATION_READY" tools/demo/run.sh    # build, start, seed
tools/demo/run.sh seed grant SENT                              # any scene below
tools/demo/run.sh clock milestone_start                        # grant clock links
tools/demo/run.sh forge-fail                                   # the fake forge answers 404 once
tools/demo/run.sh e2e speedrun/                                # the Playwright speedrun
tools/demo/run.sh e2e mail/                                    # the mail specs
tools/demo/run.sh stop
```

## The scenes

Each scene replaces the cell state. Each starts from the `NEGOTIATION` applicant seed and runs the real operations through the API core, as the person of the design would. No seed writes a ledger row by hand. The seed prints the agreed plan number (6001) and the milestone number (7001) for the determination and payment forms.

| Scene | What the cell holds |
| --- | --- |
| `NEGOTIATION_READY` | x in NEGOTIATION, nothing determined. Every post-grant person enrolled |
| `SENT` | amount determined, accepted, approved. Contract drafted, one clause change agreed, sent |
| `EFFECTIVE` | the lead and the signatory signed. x is GRANTED |
| `IN_EXECUTION` | the clock passed the first milestone start. x is IN_EXECUTION |
| `UNDER_REVIEW` | the lead requested payment of milestone 1 with deliverable evidence. The checks passed |
| `PAID` | line accepted, approved, released after the bank hold, confirmed paid |
| `ALL_CLOSED` | milestone closed, x COMPLETED, five funder outputs generated and approved |
| `HARDSHIP` | x IN_EXECUTION. The lead asked for the hardship ticket and filed a hardship request. Finance verifies the evidence on the vault page |

The demo page lists the scenes under "Grant (post-grant lifecycle)". Its clock links are "first milestone start", "P-36 bank hold", "due minus 14 days", "due" and "due plus 7 days". "Make the next checks fail" arms the fake forge's 404.

## The people and their click paths

Open `<control base>/demo`, choose a scene, then "Sign in as" the person. Each person follows links from the home page `/app/`.

| Person | Click path |
| --- | --- |
| Lead applicant X | Home, "Your grant" link, grant page, then Contract and Payment requests links. Bank details on the grant page open the vault page |
| Committee member R1 (reviewer) | Home, "Grants you review". The grant page answers R-AC-01 for a reviewer (see gaps) |
| Programme manager M1 | Home, "Operations", then the grants list and the grant page. Reports at `/app/programmes/1/reports` |
| Contract signatory S1 | Home, "Operations", the grant, the contract, countersign |
| Finance approver F1 | Home, "Operations", the approval queue. Bank verification on the grant page |
| Payment releaser P1 | Home, "Operations", the release queue |
| Auditor A1 | Home, "Operations", read only |
| Report approver (Financial signatory) F2 | Sidebar "Operations", then reports by programme number 1 |

## Fakes, and where they live

- **Wallet and QTSP.** `fstp_contract::fake::FakeTrustServices` signs through `api_core_with_signing` in `Inner::new`. A production core builds none.
- **Vault read page.** The fake vault answers a bank ticket with `<vault origin>/r#synthetic-ticket-n`. The cell serves `/r` on `id.<cell host>` (`grantdemo::vault_read`). The page shows the action of the latest ticket: the lead enters synthetic bank details, finance verifies, the releaser views the payee. It writes facts into the synthetic vault. No bank value exists anywhere (I-86, I-33).
- **Pump.** `pump.rs` runs the sweep (`StartExecution`, `Complete`) and the checks runner for each waiting payment request, every half second, through the real commands. The forge 404 arms one failing run of the submission checks.
- **Fake forge.** `/demo/forge/synthetic-sensor-kit` on the control base, with a licence file.

## The Playwright speedrun

- `e2e/speedrun/speedrun.api.spec.ts` runs rows 5 to 14 of M5 design section 1.2 at the wire, with each person signed in by the demo link: determination, contract with a clause change, both signatures, clock to the milestone start, bank details and verification on the vault page, a payment request whose checks fail once and resubmit, line review, approval, a release refused by I-33 and then made after the hold, paid, milestone closure, COMPLETED, report generation and approval of all five outputs. It checks the refusals that matter: the lead cannot determine or review its own line (SoD-12), the proposing side cannot decide its own clause change (R-CT-04), the generator cannot approve its report (R-RP-03).
- `e2e/speedrun/speedrun.hardship.spec.ts` follows the `HARDSHIP` scene by clicking: the lead from the grant to the payments list (kind hardship) and the hardship evidence vault page, finance from Operations to the grant and the verification vault page.
- `e2e/speedrun/speedrun.ui.spec.ts` follows links only through the `m5/ui` screens: lead to grant, contract and payments, operations roles to Operations, the reviewer to the grants list, the Financial signatory to the reports.
- Both pass on this branch: 5 of 5 (run against a cell built from this branch merged with `main` at `c886689c`).

Rows 1 to 4 (build, publish, submit, review, IRC) run in the M4 specs. The speedrun starts at `NEGOTIATION_READY`.

## Requirements and invariants covered

R-NG-03, R-CT-01, R-CT-04, R-PR-01 to R-PR-05, R-RP-03, R-RP-04, R-NF-03. I-05, I-30, I-31, I-32, I-33, I-44, I-64, I-86, I-96. The Rust test `m5_demo_grant_scenes_reach_their_states` (in `scenario/postgrant.rs`) builds every scene and checks the state of x, the paid status, the five reports and the hardship request (R-PR-04).

## Decisions and open questions for Daniel

1. **Speedrun starts at the negotiation.** Rows 1 to 4 already have M4 specs and seeds, and a 40-hour deadline favours a short run. Decision: `NEGOTIATION_READY` is the start. The full-call video would chain the M4 scenes by hand.
2. **P-36 hold in the demo.** The clock link advances 30 days, and the speedrun passes with it. I did not read the programme's P-36 value. Open: read P-36 from the programme and advance exactly that.
3. **Fake forge is not behind the checks runner.** `fstp-checks` needs resolved evidence texts and an egress client. The pump passes the checks and fails them once on request. The location text is `http://a.fstp.localhost/demo/forge/...`, which no code fetches. Open: wire `fstp_checks::runner::run` to the forge when the evidence reads exist.
4. **Open call package not generated.** Closed by the gaps lane, see below.
5. **Hardship request is not seeded.** Closed by the gaps lane, see below.
6. **Reviewer cannot read the grant.** `GRANT_READERS` in the registry lists no reviewer, so the grant page, where `m5/ui` puts the amount determination, answers R-AC-01 for R1. The speedrun determines the amount at the wire. Needs a decision by the lead: add the reviewer to `grant.overview` in NEGOTIATION, or give the determination its own read.
7. **Tenant provisioning for post-grant scenes.** The review world has no tenant record, so the Financial signatory cannot be granted there. The post-grant seeds start the ledger with the provisioning record (`fresh_review_with(info, true)`). Other seeds are unchanged.
8. **Step-up in seeds.** The seeder plays a person's step-up confirmation in a fresh session when a high-risk operation asks (`Seeder::api`). One small edit to `scenario.rs`.
9. **Vault origin page uses a script file.** `/r.js` is a few lines of plain JavaScript served by the test cell only. It is not part of `web/` and never ships.

## Gaps lane: decisions

Lane `m5/gaps`, 2026-11-12. Covers R-RP-04, I-48, I-53, R-PR-04, I-86, I-27. Every person and text is synthetic.

1. **Why the open call package answered 501.** `report.generate` in `fstp-api-core` returned `NotImplemented` for it because the core was thought not to hold the stored Guide. It does: `StoredGuide::canonical()` is in the ledger state (R-GA-01, I-53). Decision: the core builds the package like the other four outputs. The Guide bytes are the stored canonical document. The data protection notice and the privacy statement address are the values the Guide stored at publication (`gdpr.notice_summary`, `funder.privacy_statement_url`), so the I-48 check on the notice keeps its meaning.
2. **Package parts that do not exist yet.** The proposal form and the contract template are one-line skeletons, the same placeholder the contract draft uses. They carry `TODO(legal)`. Open: real proposal form and contract template texts, from legal review (I-49).
3. **ALL_CLOSED holds five outputs.** The seed generates and the Financial signatory approves all five. The Rust scene test checks five. The wire speedrun generates and approves the package too.
4. **Hardship scene `HARDSHIP`.** Starts at IN_EXECUTION. The lead calls `vault.hardship.submit` and files a payment request of kind Hardship, both through the real operations as the lead. No ledger row is written. The evidence reference is fixed by the seed (`hardship_evidence`, proposal id plus 8000), because the synthetic vault has to agree with the request. Open: a production vault draws it.
5. **Vault page for hardship.** The cell's `/r` page now also serves the hardship tickets. The lead sees "Submit synthetic hardship evidence", which changes nothing. Finance sees "Verify the hardship evidence", which writes the one verified-evidence fact into the synthetic vault. The request is not approved by the seed: finance approves it after the line review. Open: the lead payment form has no hardship option on screen, so a lead cannot file a new hardship request by clicking.
6. **The mail spec flake.** `i27_irc_concern_mail_holds_ids_and_a_link_only` failed with "the concern mail is sent" in full runs. Cause, found with a stack sample of a hung cell: the demo page handler locked the mail mirror on a runtime worker thread, while the mail tick held the same lock across the SMTP exchange and waited for the I/O driver. The driver is turned by the workers, and the cell has two, so a blocked worker stalled the exchange for good (up to the RFC 5321 client timeouts of minutes). The page also hung, which made later specs time out on `page.goto`. Fix: handlers read a snapshot (`View`) that the tick publishes after each step. Its lock is never held across I/O. Nothing the test asserts was loosened.
7. **Mirror identity.** The mirror compared cell states by pointer address as an integer, so an address the allocator reused could pass a new scene for the old one. It now holds the `Arc` and compares with `Arc::ptr_eq`. A unit test pins it. Not seen as a failure, a cheap hazard removed.
8. **Regression spec.** `e2e/mail/mail_in_flight.spec.ts` reads the demo page from eight readers at once while the concern mail is sent.
