# Presentation walkthrough: one grant from call to payment

A script for showing the platform live, in about 36 minutes with every section, or about 30 without the programme set-up and the fast flow. It follows one synthetic proposal ("Synthetic open sensor kit", proposal 1001) through the whole cycle. Every person reaches their work by clicking from sign-in. All data is synthetic.

Each step names the scene to seed, the person to sign in as, the clicks, and what to point out. Link texts are quoted as they appear on screen. The detail behind each step is in `m4-demo.md`, `m5-demo.md`, `m6-demo.md`, `m7-demo.md` and `mailbox-design.md`.

## Before you start

```sh
tools/demo/run.sh            # builds the pages, the cell and the assessor; seeds "review stage1"
```

- Open the front door `http://127.0.0.1:8641/demo` in Chrome or Chromium. Everything starts there.
- The scenes are links under "Scenes". Choosing one replaces the whole cell state in under a second. Any step can be repeated by choosing its scene again.
- People are listed under "People of this scene". "Sign in as" is one click with no passkey, and it opens a new tab. The top bar then says "Demo sign-in". Step-up shows a plain "Confirm" button.
- The cell's clock is fixed. It reads 30 October 2026 in the early scenes and December 2026 in the grant scenes.
- Most links on `/demo` open a new tab. "Sign in as" and "raw message" do. The scene links and the clock links stay on `/demo`.
- Run `tools/demo/run.sh stop` at the end.

## Optional: Programme set-up (2 minutes)

Before the call exists, a programme manager builds the programme in a guided creator. This scene shows a fully built SuperSAFE draft.

1. On `/demo`, under "Scenes", choose "programme_setup" on the line "Programme set-up". Then "Sign in as Programme manager M1".
2. Home, "Programme set-up of programme 5563071439709405193". The cell draws this long number when the draft opens, and it is the same in every run. The overview groups the 11 steps under five headings, and each step reads "validated".
3. In the step list choose "11. Review: validated". The page shows the final validation report, then the previews "Guide for Applicants", "Public programme page" and "Contract".
4. Point out:
   - Every step is checked as it is saved, and a step opens only when the steps before it validate (R-PG-01).
   - The previews are built from the draft values. The contract preview marks each value only a grant sets, such as "[granted amount: set for each grant]".
   - "Request activation" is enabled because the report is clean. Activation then needs a second tenant admin who did not build the programme (I-66, I-67). This scene lists no such admin, so end on the review page without pressing it.

## 1. The public call (1 minute)

1. On `/demo`, choose the applicant scene **OPEN_CALL**.
2. Choose "Public open calls" in the top bar (a new tab opens), then "SuperSAFE open call 2026".
3. Point out: the call page shows the dates with their time zone, the total budget, "Who can apply" and "Use of AI tools". The page has no script and sets no cookie. "Sign in to apply" and "Create an account" are the only actions.

## 2. The applicant drafts and checks with AI (4 minutes)

1. Choose the applicant scene **DRAFT**. "Sign in as" the lead, listed by the address `synthetic-lead-z…@e2e.invalid`.
2. Home, "Your proposal: Synthetic closed protocol bridge", then "Write the proposal". Type a word in the title or narrative: "All changes are saved." appears.
3. Choose "Check my draft", then "Check my draft now". The page shows "Checks left: 1 today on this proposal" before the check.
4. Point out:
   - The page names "Synthetic assessor (demo)" and says no language model ran.
   - The findings include a major completeness finding, "Rubric element: Team and experience". No score, band or decision is shown.
   - The check is limited to one a day. The button disables and the page says when the next check is available.
   - The submission text reaches the assessor only as data, never as instructions.
5. Optional: from the proposal choose "Read the call", then "Read the Guide for Applicants". Section 5, "How to apply", explains the pre-submission check, and section 6 explains how reviewers use AI.

## Fast flow: criteria and the early decision (4 minutes)

One live chain: the criteria the call drafter writes are the ones the coordinator applies. Details are in `fast-flow.md`.

1. On `/demo`, under "Scenes", choose **fast_flow** on the line "Fast flow (criteria and the early decision)". The programme is active, and call 1 is in DRAFT. No proposal exists yet.
2. "Sign in as Call drafter D1". On Home choose "Knock-out criteria of programme 1". Edit the criteria in the text boxes, or choose "Add an item to Knock-out criteria (P-09)" for a new one. Then choose "Save the knock-out criteria". The page reads "The knock-out criteria are saved. The next call a programme manager publishes freezes them (I-12)."
3. "Sign in as Programme manager M1". Home, "Programme set-up of programme 1", then "Open approval and publication". Call 1 is listed as DRAFT, and its number is filled in. Choose "Approve the publication of this call", then "Publish this call" and "Confirm". The page reads "Published. The call is PUBLISHED."
4. Back on `/demo`, choose "Submit the synthetic proposals to call 1". Proposals 1001, 1002 and 1003 are submitted by their leads, who now appear under "People of this scene".
5. "Sign in as Coordinator C1". Choose the line "Your mailbox: … waiting for you" on Home, or "Mailbox" in the top bar. Then choose "Check the knock-out criteria of new proposals in call 1". In the intake queue choose "Declare for proposal 1002", then "No, I have no conflict of interest" and "Record my declaration". Choose "Go to the knock-out check of proposal 1002".
6. The criteria D1 wrote appear by their text, in order. Mark the first "Fails" and the others "Passes". "Record the knock-out check" without a reason is refused: "Enter the reason the proposal fails." Type a reason in "Reason for a failed criterion" and record again. The state becomes INELIGIBLE.
7. Optional: do the same for proposal 1001 with every criterion "Passes". It stays SUBMITTED until its reviewers are assigned and declared, as in section 3.
8. On `/demo`, "Sign in as" the lead listed by the address `synthetic-lead-z…@e2e.invalid`. Home, "Your proposal: Synthetic closed protocol bridge". The page shows "Not eligible" and "Reason recorded by the FSTP coordinator:" with the reason C1 typed.
9. On `/demo`, wait about 5 seconds and choose "Refresh this page". Under "Mail through the dispatcher", open the "raw message" of the template `proposal-outcome`. It names proposal 1002 and links to `/app/proposals/1002`.
10. Point out:
    - Separation of duties: D1 writes the criteria, and C1 applies them. No person may hold both roles in one programme (SoD-01). D1 cannot approve the call, and M1 approves it (R-PC-03).
    - The criteria are frozen when the call is published, so the check uses exactly the published criteria (I-12).
    - The reason is recorded with the decision, and the applicant reads it on the platform (R-EV-01).
    - The mail carries ids, a time and a link only, never the reason or the criteria (I-27).

## 3. Review with conflict checks and AI findings (4 minutes)

1. Choose the review scene **stage1**, then "Sign in as Committee member R1".
2. Home, "Your review assignments", then "Open the assignment for proposal 1001".
3. Before declaring, only the title and the neutral summary show. Choose "No, I have no conflict of interest", then "Record my declaration". The proposal, "Assessor findings" and the score sheet appear.
4. Press "Agree" or "Dispute" on a finding. The finding then reads "You agreed."
5. Enter whole numbers from 0 to 5 in "Criterion 1" to "Criterion 3", then "Record my scores". 3.5 is refused with "Enter a whole number from 0 to 5 for Criterion 1, with no spaces, signs or decimals." 6 is refused with "The score for Criterion 1 must be at most 5."
6. Optional: back in "My assignments", open the assignment for proposal 1003 and declare no conflict. Finding 4 reads "Integrity, Major: The text addresses an assessor or a model. It is treated as data." It shows a prompt injection caught and treated as data.
7. Sign in as "Coordinator C1", then Home, "Call board of SuperSAFE open call 2026". The "AI assessment" section shows counts per proposal only, never the statements.

## 4. Ranking and the committee (2 minutes)

1. Choose the review scene **ranked**, then sign in as R1.
2. Home, "Ranking of SuperSAFE open call 2026". The table ranks proposals 1001, 1004 and 1003 with weighted scores, the requested amounts and the remaining call budget.
3. Sign in as R4 and open the same ranking: row 2 shows "Recused", because R4 declared a conflict on it.

## 5. The independent review committee (2 minutes)

1. Choose the review scene **irc_review**, then sign in as IRC member I1.
2. Home, "Your IRC cases", "Open the IRC case of proposal 1001". Declare "No, I have no conflict of interest" and "Record my declaration".
3. Choose "Validate the nomination", then "Record my verdict".
4. Sign in as I2 and do the same. Proposal 1001 enters NEGOTIATION. Sign in as Coordinator C1, then Home, "Call board of SuperSAFE open call 2026": the row of proposal 1001 reads "Negotiation".
5. Optional: the applicant scene **IRC_REVIEW_MINOR** shows a minor's proposal held until a guardian consents. Sign in as the guardian, listed by the address `synthetic-guardian…@e2e.invalid`. Home, "Guardian consent for Synthetic school data vault", then "Continue to the identity vault".

## 6. Negotiation and the contract (5 minutes)

1. Choose the grant scene **NEGOTIATION_READY**.
2. Sign in as R1. Home, "Grants you review: amount determination and payment requests", then the link "Proposal 1001". Assigned reviewers set the amount (R-NG-03). Enter the plan number shown under "Plan the amount starts from" (6001) in "Agreed plan number" and press "Record the determination". The page reads "The determination is recorded." and 60000.00.
3. Choose the grant scene **SENT**. Sign in as "Lead applicant X". Home, "Your grant: Synthetic open sensor kit", "Contract of proposal 1001". The page shows the version, the parties and the content hash. Press "Sign". The page reads "Your signature is applied."
4. Sign in as the contract signatory S1. Home, "Your operations queues: payments, contracts and funder reports" (or "Operations" in the sidebar), then under "Contracts awaiting your signature" the link "Contract of proposal 1001", then "Sign". The contract status becomes "Effective".
5. Choose **EFFECTIVE** to show the signed contract and the grant as "Granted".

## 7. Payment with evidence, review, approval and release (5 minutes)

1. Choose the grant scene **UNDER_REVIEW**. On `/demo`, point out the bank line: the details were verified by finance, and the P-36 hold of 7 days is still running (I-33). Sign in as "Lead applicant X". Home, "Your grant: Synthetic open sensor kit", "Payment requests". "Payment request 1 for milestone 7001" is "Under review" and both automatic checks read "Passed".
2. Sign in as R1. Home, "Payment requests to review" (the card says "1 payment request to review"). Under "To review", open "Payment request for milestone 7001". The reviewer sees the evidence of the line only. The amount is already filled in at 60000.00. Press "Record the decision for line 1 (milestone 7001)". The page says the review is complete and waits for the finance approver.
3. Sign in as finance approver F1. Home, "Operations". Under "To approve", open "Payment request for milestone 7001", then "Approve the payment" and "Confirm". The status reads "Payment approved".
4. Sign in as payment releaser P1. Home, "Operations". Under "To release", open the request, then "Release the payment". It is refused: "The platform refused this under rule I-33." The bank hold is still running. This is a talking point.
5. On `/demo`, choose "Advance past the P-36 bank hold". The bank line now says the hold ended. As P1, reload the request page, press "Release the payment" again, then "Confirm". The page reads "The payment is released." and the status "Released".
6. Choose **PAID** and sign in as the lead. The grant page shows "Paid so far" 60000.00, and the payment request is "Paid".
7. Point out: the reviewer, the approver and the releaser are three different people (separation of duties). Amounts are computed on the server only. Bank details live in a separate vault on another origin.
8. Optional: the grant scene **HARDSHIP**. The lead opens "Payment requests": the request is of kind "Hardship contribution". Sign in as F1, Home, "Operations", then under "Grants you work on" the link "Proposal 1001", then "Verify hardship evidence". The vault page opens on its own origin. Press "Verify the hardship evidence": "Done. The vault recorded the fact. No bank value leaves the vault."

## 8. Closure and the funder reports (2 minutes)

1. Choose the grant scene **ALL_CLOSED**. The lead's Home shows "Completed".
2. Sign in as the report approver "Report approver (Financial signatory) F2", Home, "Operations", then "Open the funder reports of programme 1". The auditor A1 gets the same page through "Open the funder reports of your programme (programme 1)".
3. Point out: five funder outputs (call publication record, periodic reporting data, audit file, deliverable draft, open call package), each "Approved", with its SHA-256 and template version. "Humans upload approved documents to the funder portal. The platform submits nothing."

## 9. Mail that never carries content (2 minutes)

1. Choose the applicant scene **DEFERRED_AFTER_CONCERN**. Wait about 5 seconds, then choose "Refresh this page" on `/demo`.
2. Under "Mail through the dispatcher", open "raw message" (a new tab). The mail names proposal 1001 and links to `/app/notices`. The concern text itself stays on the platform, and the mail says the platform never asks for bank details by email.
3. Sign in as "Lead applicant X" and choose "Notifications" in the top bar. The notice reads "The independent review committee raised a concern about your proposal."
4. Optional fault demo: choose the scene again and click "Refuse the next message (451)" straight away, before the mail is sent. Wait 5 seconds and refresh: the delivery reads TRANSIENT. Then "+60 minutes" and refresh: the mail is sent once. For "Accept, then lose the reply", the delivery reads COMMITTING, then after "+60 minutes" it ends IN_DOUBT and is never sent twice.

## 10. The platform mailbox (3 minutes)

1. Choose the review scene **stage1** and sign in as R1. The top bar shows "Mailbox (2)", and Home says "Your mailbox: 2 waiting for you".
2. Choose "Mailbox". Each item names the work and links to the page where it happens: "Declare any conflict on proposal 1001". Each item names a proposal or call number, never an internal id.
3. Open the first item and do the work: "No, I have no conflict of interest", then "Record my declaration". Back in the mailbox, the declaration item is gone and "Score proposal 1001" has taken its place. Items close themselves when the work is done.
4. Repeat with other people:
   - Coordinator C1 in **submitted**: "Check the knock-out criteria of new proposals in call 1".
   - IRC member I1 in **irc_review**: three items "Declare any conflict on IRC case of proposal …".
   - The lead ("Lead applicant X") in **STAGE2**: "Answer the stage 2 questions on proposal 1001". In **NEGOTIATION**: "Read and acknowledge the negotiation notice of proposal 1001".
   - In **UNDER_REVIEW**: R1 has "Review the lines of the payment request of proposal 1001". The mailboxes of F1 and P1 are empty at first. F1 gets "Approve the payment request of proposal 1001" once R1 has reviewed. P1 gets "Release the payment request of proposal 1001" once F1 has approved.
5. Point out:
   - The mailbox is computed from the work each person may see, so it shows nothing a person could not open.
   - Emails carry only ids, a time and one link, and point back into the platform.
   - Sign-in and invitation mails stay out of the mailbox, because they carry a one-time capability.

## Avoid during the talk

- `/auth/account`: removing a passkey asks for a passkey, which a demo account does not have.
- A second pre-check in the DRAFT scene: choose DRAFT again instead.
- A reviewer opening the grant page (`/app/grants/1001`) after negotiation is refused with R-AC-01. Go through "Payment requests to review" and Operations instead.
- In the SENT scene the grant page no longer offers "Accept the amount", because the contract exists. Go to "Contract of proposal 1001".
- The first release in step 7.4 shows no "Confirm" dialog, because the hold refuses it first. Only the second release asks for "Confirm".
- On the Operations page, leave "Open the reports of another programme by its number" closed. Both F2 and A1 reach the reports through their link, so nobody types a programme number.
- Visible "TODO(legal)" lines and "the approved wording is pending" footers are placeholders for legal wording. Say so if asked.
- The synthetic proposal texts contain test markers such as "SYNTHETIC-CONTENT-CANARY". They check that no content leaks.
- In the review, applicant and grant scenes M1's own set-up of programme 1 is an empty draft, and its steps stay locked. Show the creator only in the "programme_setup" scene.

## If something goes wrong

- Choose the scene again on `/demo`. It rebuilds the state from scratch.
- If a page does not load, run `tools/demo/run.sh stop` and then `tools/demo/run.sh` again.
