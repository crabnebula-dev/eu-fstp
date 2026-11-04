# 04. Reviewer, committee and IRC surfaces

Status: draft, updated with Daniel's decisions of 2026-11-01. Prototypes: `reviewer-assignments.html`, `reviewer-scoring.html`, `reviewer-stage2.html`, `committee-ranking.html`, `irc-cases.html`, `irc-view.html`.

## Purpose and audience

Assigned reviewers, committee members and IRC members. They judge, so the screens must never leak identities and must record every decision under a named person (R-LA-03). The spec calls these Judging roles (`12-journey-ui.md` §8.3). The UI uses the role names.

## Reviewer

### Assignment list

Page title "My assignments". Table per call: proposal id, the reviewer's status badge (Assigned, Scored, Released), stage with plain label and formal state, window badge, one action. A callout says: "Declare before you read. Before declaring you see the title and a neutral summary only."

### Conflict declaration

The declaration view shows the proposal title and an applicant-written, length-limited neutral summary (`m4-design.md` §2.2 J5, Q9, R-CF-02). A yes or no radio pair follows. No free text. The answer is never shown with an identity to anyone else. "Yes" releases the reviewer and the scores of conflicted reviewers never count (NOTE 3). The applicant writes the summary in the workspace (`spec-questions.md` item 14, resolved).

### Scoring form

- Shown only after the conflict answer is "no". Read access follows P-10.
- Three criteria, each a fieldset with a 0 to 5 whole-number input and a rationale textarea. Weights: Excellence 30%, Impact 40%, Implementation 30% (`m4-design.md` §2.1).
- Ranking summary in three required fields: Title, Neutral summary and Rationale (`m4-demo.md` J6 step 4). The hint says "The applicant sees this after a final decision, without your name (O-54)."
- Anonymity note: "Your score is anonymous under P-11 until the programme manager lifts anonymity."
- A note explains how to correct a recorded score.
- "Correct score" panel, shown after submission: the original score, the corrected score, a required "Reason for correction" (I-23) and a disabled "Save correction" button. The passkey step needs script, marked TODO(js).
- Submit needs a passkey confirmation.

### Stage 2 question view

Prototype: `reviewer-stage2.html`, page title "Stage 2 evaluation" (`m4-demo.md` J6 step 5). It shows the reviewer's stage 1 scores read-only, a radio pair ("Yes, I have a question" or "No questions") and a "Your question for the applicant" field. Submit is disabled with a reason, marked TODO(js). When every assigned reviewer records "No questions", the window closes and the proposal becomes RANKED. If P-07 elapses with no answers and no "no questions" record, the proposal moves to DEFERRED (NOTE 4).

## Committee

### Ranking view

- Page title "Ranking for SuperSAFE Open Call 2".
- Budget card: remaining and total budget as decimal strings (R-EV-08).
- Table: Position, Proposal (pseudonymous id), one column per P-01 criterion, Weighted score, Requested (€), Status, Action (`m4-demo.md` J7 step 2). No findings column.
- Each criterion column holds the weighted score for that criterion: the weight times the mean reviewer score (D9). The three add up to the weighted score. `m4-design.md` gives the P-01 weights only (30, 40, 30). The criterion names Excellence, Impact and Implementation are design placeholders.
- A footer row "Remaining budget (€) after the cut-off" closes the table.
- Cut-off line after position 3: a full-width row with a 3px dashed rule. Status badges say "Above cut-off" with an up triangle or "Below cut-off" with a down triangle.
- Recusal: the row shows "Recused" with an R glyph, and every score and amount cell says "Hidden" (`m4-design.md` Q16, `spec-questions.md` item 15).
- Tie-break: a warning callout says two proposals share a weighted score at position 3. The round records the P-17 tie-break and its rationale (NOTE 6).
- "Open the cut-off round" form, then "Your ballot". Each carries a visible "Not served in M4 demo" badge (`m4-demo.md` J7 note). In "Your ballot" there are two radios, "Approve the cut-off" or "Reject the cut-off", and a delegate select. "Cast ballot" records it. Each member casts or delegates their own ballot (`m4-design.md` §2.2 J7, Q4, D5). Voting follows P-16 (R-EV-09).
- When the round closes, proposals above the cut-off move to IRC_REVIEW and the rest to NOT_SELECTED.

## IRC

### Case list

Prototype: `irc-cases.html` at `/app/me/irc-cases` (`m4-demo.md` J8 step 1). Table: Proposal id, Call, Assigned date, Status, Action. Statuses: Pending declaration, In review, Validated, Concern raised. The pending row has a disabled "Declare and open" button (TODO(js)). A callout says the declaration comes before reading the case.

### Case view

- "1 of 2 validations complete." sits at the top. Two IRC members must validate before NEGOTIATION (J8 step 3).
- Nominated proposal view: id, title, content and the outcome so far. No scores, ballots or rationale (R-IR-03, `m4-design.md` Q16).
- No proposal status strip anywhere on any IRC page (O-58).
- Two radios, following the state machine and `m4-design.md` §2.2 J8:
  1. "Validate. The proposal moves to Negotiation (NEGOTIATION)."
  2. "Raise a concern."
- A callout states what a concern leads to. When a later call is published, the proposal is Deferred to the next call (DEFERRED) under the original call's policy (NOTE 7, NOTE 8). Without one, it is Declined (DECLINED), recorded by the programme manager (NOTE 13).
- The concern reaches the applicant per R-IR-02.
- A second panel shows a proposal held in IRC_REVIEW because a minor has no guardian consent record (I-18). It shows the pseudonymous id, the badge "On hold: guardian consent required" and "The applicant has been notified. No identity detail is shown here." The IRC member has no action on it.

## "Proposal status" strip

For reviewers and committee members only (`12-journey-ui.md` §8.3). Heading "Proposal status". An ordered list of the main line with plain labels and formal states. Done stages carry a check, the current stage a filled dot, a thicker border and `aria-current="step"`. It omits end states the viewer cannot act on. IRC never sees it (O-58).

## Copy keys

`judging.assignments.title`, `judging.assignments.conflict_banner`, `judging.assignments.status.*`, `judging.conflict.question`, `judging.conflict.summary`, `judging.conflict.no`, `judging.conflict.yes`, `judging.score.title`, `judging.score.criterion_legend`, `judging.score.score_label`, `judging.score.rationale_label`, `judging.score.overall_label`, `judging.score.overall_hint`, `judging.score.anonymity`, `judging.score.correction`, `judging.score.submit`, `judging.score.stepup`, `committee.ranking.budget`, `committee.ranking.cutoff`, `committee.ranking.above`, `committee.ranking.below`, `committee.ranking.recused`, `committee.ranking.tie_notice`, `committee.round.open`, `committee.ballot.legend`, `committee.ballot.approve`, `committee.ballot.reject`, `committee.ballot.delegate`, `committee.ballot.cast`, `irc.review.title`, `irc.review.outcome.validate`, `irc.review.outcome.concern`, `irc.review.concern_effect`, `journey.strip.title`.

## Accessibility notes

- The cut-off row is a `<th scope="row">` spanning all columns, so screen readers announce it in table order.
- Number inputs have labels naming the criterion and the scale, for example "Score for Impact, 0 to 5".
- Recused rows say "Hidden" in text, not an empty cell.
- Radio groups sit in a `<fieldset>` with a `<legend>`.
- Step-up notices sit next to the action they guard.

## Spec IDs

R-CF-02 (conflict declaration yes or no only, with title and neutral summary), I-18, I-23, D9, D10, R-CF-03, R-EV-08, R-EV-09, R-IR-02, R-IR-03, R-LA-03, P-10, P-11, P-16, P-17, D5, SoD-02, SoD-10, SoD-11, O-54, O-58, Q4, Q9, Q16.

## Open points

- Whether the strip notes a past deferral when a proposal re-entered from DEFERRED. Recommendation: a "Deferred once" note beside the current stage.
- TODO(js): passkey steps for the correction, the stage 2 submission and the IRC declaration.
