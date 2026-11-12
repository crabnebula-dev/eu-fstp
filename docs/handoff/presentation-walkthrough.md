# Presentation walkthrough: one grant from call to payment

A script for showing the platform live, in about 30 minutes. It follows one synthetic proposal ("Synthetic open sensor kit", proposal 1001) through the whole cycle. Every person reaches their work by clicking from sign-in. All data is synthetic.

Each step names the scene to seed, the person to sign in as, the clicks, and what to point out. Link texts are quoted as they appear on screen. The detail behind each step is in `m4-demo.md`, `m5-demo.md`, `m6-demo.md`, `m7-demo.md` and `mailbox-design.md`.

## Before you start

```sh
tools/demo/run.sh            # builds the pages, the cell and the assessor; seeds "review stage1"
```

- Open the front door `http://127.0.0.1:8641/demo` in Chrome or Chromium. Everything starts there.
- The scenes are links under "Scenes". Choosing one replaces the whole cell state in under a second. Any step can be repeated by choosing its scene again.
- People are listed under "People of this scene". "Sign in as" is one click with no passkey, and it opens a new tab. The top bar then says "Demo sign-in". Step-up shows a plain "Confirm" button.
- The cell's date is in late October 2026, so the public call reads as already closed.
- Run `tools/demo/run.sh stop` at the end.

## 1. The public call (1 minute)

1. On `/demo`, choose the applicant scene **OPEN_CALL**.
2. Choose "Public open calls" in the top bar, then "SuperSAFE open call 2026".
3. Point out: the call page shows the dates with their time zone, the total budget, "Who can apply" and "Use of AI tools". The page has no script and sets no cookie.

## 2. The applicant drafts and checks with AI (4 minutes)

1. Choose the applicant scene **DRAFT**. "Sign in as" the lead, listed by the address `synthetic-lead-z…@e2e.invalid`.
2. Home, "Your proposal: Synthetic closed protocol bridge", then "Write the proposal". Type a word: "All changes are saved." appears.
3. Choose "Check my draft", then "Check my draft now".
4. Point out:
   - The page names "Synthetic assessor (demo)" and says no language model ran.
   - The findings include a major completeness finding, "Rubric element: Team and experience". No score, band or decision is shown.
   - The check is limited to one a day. The button disables and shows when the next check is available.
   - The submission text reaches the assessor only as data, never as instructions.
5. Optional: open "Guide" from the proposal. The Guide now explains the pre-check and the AI disclosure.

## 3. Review with conflict checks and AI findings (4 minutes)

1. Choose the review scene **stage1**, then "Sign in as Committee member R1".
2. Home, "Your review assignments", then "Open the assignment for proposal 1001".
3. Before declaring, only the title and the neutral summary show. Choose "No, I have no conflict of interest", then "Record my declaration". The proposal, "Assessor findings" and the score sheet appear.
4. Press "Agree" or "Dispute" on a finding.
5. Enter whole numbers from 0 to 5 in "Criterion 1" to "Criterion 3", then "Record my scores". 3.5 or 6 is refused with a clear message.
6. Optional: proposal 1003 carries "Integrity, Major: The text addresses an assessor or a model. It is treated as data." It shows a prompt injection caught and treated as data.
7. Sign in as "Coordinator C1", then Home, "Call board of SuperSAFE open call 2026". The "AI assessment" section shows counts only, never the statements.

## 4. Ranking and the committee (2 minutes)

1. Choose the review scene **ranked**, then sign in as R1.
2. Home, "Ranking of SuperSAFE open call 2026". The table ranks 1001, 1004 and 1003 with weighted scores and the remaining budget.
3. Sign in as R4: row 2 shows "Recused", because R4 declared a conflict on it.

## 5. The independent review committee (2 minutes)

1. Choose the review scene **irc_review**, then sign in as IRC member I1.
2. Home, "Your IRC cases", "Open the IRC case of proposal 1001". Declare "No, I have no conflict of interest" and "Record my declaration".
3. Choose "Validate the nomination", then "Record my verdict".
4. Sign in as I2 and do the same. Proposal 1001 enters NEGOTIATION, as the coordinator's call board shows.
5. Optional: the applicant scene **IRC_REVIEW_MINOR** shows a minor's proposal held until a guardian consents. The guardian's Home links to the consent page.

## 6. Negotiation and the contract (5 minutes)

1. Choose the grant scene **NEGOTIATION_READY**.
2. Sign in as R1. Home, "Grants you review", then the link "Proposal 1001". Assigned reviewers set the amount (R-NG-03). Enter the agreed plan number shown on the page and "Record the determination".
3. Choose the grant scene **SENT**. Sign in as "Lead applicant X". Home, "Your grant", "Contract and signatures". The page shows the version, the parties and the content hash. Press "Sign".
4. Sign in as the contract signatory S1. Home, the operations queues link (or "Operations" in the sidebar), "Contracts awaiting your signature", the contract of proposal 1001, "Sign". The contract becomes effective.
5. Choose **EFFECTIVE** to show the signed contract and the grant as GRANTED.

## 7. Payment with evidence, review, approval and release (5 minutes)

1. Choose the grant scene **UNDER_REVIEW**. Sign in as "Lead applicant X". Home, "Your grant", "Payment requests". The request for milestone 1 passed its automatic checks.
2. Sign in as R1. Home, the payment requests to review, then the request. Accept the line. The reviewer sees only what the line review needs.
3. Sign in as finance approver F1. Operations, "To approve", the request, "Approve the payment", "Confirm".
4. Sign in as payment releaser P1. Operations, the request, "Release the payment". It is refused with I-33: the bank hold is still running. This is a talking point.
5. On `/demo`, choose "Advance the P-36 bank hold". As P1, reload and release again, then "Confirm". The status reads RELEASED.
6. Choose **PAID** to show "Paid so far" and the paid request.
7. Point out: the reviewer, the approver and the releaser are three different people (separation of duties). Amounts are computed on the server only. Bank details live in a separate vault on another origin.
8. Optional: the grant scene **HARDSHIP** shows a hardship request with its evidence in the vault, which finance verifies.

## 8. Closure and the funder reports (2 minutes)

1. Choose the grant scene **ALL_CLOSED**. The lead's Home shows "Completed".
2. Sign in as the report approver F2 (Financial signatory). Open "Operations", then the reports of programme 1.
3. Point out: five funder outputs, each approved, with its SHA-256 and template version. "Humans upload approved documents to the funder portal. The platform submits nothing."

## 9. Mail that never carries content (2 minutes)

1. Choose the applicant scene **DEFERRED_AFTER_CONCERN**. Wait about 5 seconds, then choose "Refresh this page" on `/demo`.
2. Under "Mail through the dispatcher", open "raw message". The mail names proposal 1001 and links to `/app/notices`. The concern text itself stays on the platform, and the mail says the platform never asks for bank details by email.
3. Sign in as "Lead applicant X" and open the notices to read the concern on the platform.
4. Optional fault demo: choose the scene again and click "Refuse the next message (451)" straight away, before the mail is sent. Then "+60 minutes": the mail is retried and sent once. "Accept, then lose the reply" ends IN_DOUBT and is never sent twice.

## 10. The platform mailbox (3 minutes)

1. Choose the review scene **stage1** and sign in as R1. The top bar shows "Mailbox (n)", and Home says how many items wait.
2. Open the mailbox. Each item names the work and links to the page where it happens, such as the declaration or the score sheet.
3. Do the work, for example "Record my declaration". Back in the mailbox, the item is gone. Items close themselves when the work is done.
4. Repeat with other people: Coordinator C1 in **submitted** (the intake check), IRC member I1 in **irc_review**, the lead in the applicant scenes **STAGE2** and **NEGOTIATION**, finance and the releaser in **UNDER_REVIEW**.
5. Point out:
   - The mailbox is computed from the work each person may see, so it shows nothing a person could not open.
   - Emails carry only ids, a time and one link, and point back into the platform.
   - Sign-in and invitation mails stay out of the mailbox, because they carry a one-time capability.

## Avoid during the talk

- `/auth/account`: removing a passkey asks for a passkey, which a demo account does not have.
- A second pre-check in the DRAFT scene: choose DRAFT again instead.
- A reviewer opening the grant page after negotiation is refused with R-AC-01. Go through the review links instead.
- Visible "TODO(legal)" lines and "the approved wording is pending" footers are placeholders for legal wording. Say so if asked.
- The synthetic proposal texts contain test markers such as "SYNTHETIC-CONTENT-CANARY". They check that no content leaks.

## If something goes wrong

- Choose the scene again on `/demo`. It rebuilds the state from scratch.
- If a page does not load, run `tools/demo/run.sh stop` and then `tools/demo/run.sh` again.
