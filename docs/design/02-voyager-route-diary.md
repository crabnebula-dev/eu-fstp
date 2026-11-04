# 02. Progress map and activity log

Status: draft. Prototypes: `route-map.html` (page title "Application progress"), `diary.html` (page title "Activity log").

The spec names these surfaces the Voyager route and the Passage Diary (`12-journey-ui.md` §5.1 and §7). The design leads with plain labels and keeps the spec names as secondary lines. Daniel confirmed "Progress map" for Voyager route and "Activity log" for Passage Diary on 2026-11-01 (`spec-questions.md` item 12).

## Purpose and audience

The progress map shows an applicant where their proposal is, where it has been, and where it may go next. The activity log records each step in plain words. Both are projections of the ledger with no authority of their own (I-92). A next action is a suggestion, and the command endpoint re-checks every guard.

Audience: applicants, team members and grantees. Guardians see their own consent steps only (O-60).

## The progress map

Server-rendered SVG from the journey definition and the programme overlay (`12-journey-ui.md` §5.5, §6), made by the `fstp-html` renderer (ADR-015). Deterministic for identical inputs. No client diagram library.

The page heading is "Application progress". The only metaphor on the page is the subtitle "Your route through the call" (`.voyage-label`) and a "Voyage pack label:" line in each help panel.

### Layout

Four rows on a 1110 by 430 viewBox. The map scrolls sideways inside its frame on narrow screens. The text list below never scrolls.

| Row | Nodes |
| --- | --- |
| Withdraw row | WITHDRAWN, one node, joined by a dashed bracket spanning DRAFT to NEGOTIATION |
| Main line | DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED, IRC_REVIEW, NEGOTIATION, GRANTED, IN_EXECUTION, COMPLETED |
| Pause row | DEFERRED, between STAGE2 and IRC_REVIEW |
| Final outcome row | INELIGIBLE, NOT_SELECTED, DECLINED, TERMINATED |

### Node labels

Each node shows the plain label and the formal state in monospace (I-96). The Voyage label for each state follows `12-journey-ui.md` §5.2 and appears in the help panel, not on the node.

| State | Plain label | Voyage pack label (§5.2) |
| --- | --- | --- |
| DRAFT | Draft | At the departure hall |
| SUBMITTED | Submitted | Departed, awaiting border check |
| STAGE1 | Stage 1 evaluation | Crossing |
| STAGE2 | Stage 2 questions | Ascent: questions from the scouts |
| RANKED | Ranked, awaiting committee decision | Awaiting the council |
| IRC_REVIEW | Independent review | Independent watch |
| NEGOTIATION | Negotiation | Treaty |
| GRANTED | Granted | Charter in force |
| IN_EXECUTION | Project in progress | On the road |
| COMPLETED | Completed | Safe harbour |
| DEFERRED | Deferred to the next call | Wintering for the next voyage |
| INELIGIBLE | Not eligible | Route closed at the border |
| NOT_SELECTED | Not selected | Route ended |
| DECLINED | Declined | Route ended |
| WITHDRAWN | Withdrawn | Route ended |
| TERMINATED | Grant terminated | Route ended |

### Edges

Every edge maps one to one to a row of the transition table (I-95). Main line edges join neighbours. Negative edges: SUBMITTED to INELIGIBLE, STAGE1 and RANKED to NOT_SELECTED, IRC_REVIEW and NEGOTIATION to DECLINED, GRANTED and IN_EXECUTION to TERMINATED. Deferral edges: STAGE2 and IRC_REVIEW to DEFERRED.

### WITHDRAWN

The state machine has one rule: any non-terminal state before GRANTED may move to WITHDRAWN, including DEFERRED (NOTE 10; `12-journey-ui.md` §5.1). The map draws it as one bracket and one node, not nine arrows. The bracket text reads "Withdraw: possible in any state before GRANTED, including DEFERRED". On the page, one "Withdraw this proposal" control sits below the help panels.

### DEFERRED re-entry

Two dashed loop edges run from DEFERRED back to STAGE2 and IRC_REVIEW. The label "re-enters at the stage it left" sits under the node (NOTE 8). The loop is styled with a long dash and an arrow, so it is distinct without colour. A deferred proposal keeps its original call's policy in the overlay (R-JV-07).

STAGE2 moves to DEFERRED if P-07 elapses with no answers and no "no questions" record (NOTE 4). The STAGE2 help panel says so.

### Node styling (never colour alone)

| Status | Glyph | Stroke | Words in accessible name |
| --- | --- | --- | --- |
| Completed | check mark | solid | "completed" |
| Current | filled dot, plus a ring | thick solid, ring | "current stage" |
| Upcoming | open circle | dashed | "upcoming" |
| Pause (DEFERRED) | loop arrow | dashed | "possible pause, returns at the stage it left" |
| Positive end (COMPLETED) | star | thick solid | "upcoming, final outcome" |
| Negative end | filled square, square corners | dotted | "possible final outcome" |

Each node is `<a href="#node-STATE">` with `aria-label="Stage 2 questions (STAGE2), current stage"` and a `<title>`, so it is keyboard reachable.

### Reduced motion

The current ring pulses with a CSS animation. Under `prefers-reduced-motion: reduce` it stops and turns into a static dashed ring. Nothing else moves.

### Text alternative

"Progress as a list" gives every node in the order main line, pause, then final outcomes, with status words: "Completed", "Current stage", "Upcoming", "Possible final outcome". The current item has `aria-current="step"`. Each item links to the same help panel as its node (R-JV-05).

### Help panel per node

Selecting a node or list item targets `#node-STATE`. The panel uses `:target`, so it works with no script. With no target, the current node's panel shows. Each panel has four headings:

1. What is happening now
2. Who acts
3. Deadline (for STAGE2: "Your window closes in 8 days", in the deadline's own zone and the viewer's zone, §7.4)
4. What you can do, with at most one primary action

## Activity log

Newest first. Twenty entries per page with server pagination. A GET filter form narrows by kind. Every sentence is built at read time from a catalogue key and the source record (I-97). No clear text is stored in the journey schema. Entries follow the kinds and visibility in `12-journey-ui.md` §7.1 and §7.2.

### Entry anatomy

Icon circle with a glyph (hidden from screen readers), a badge with the kind in words, a `<time>` element, then the body. Optional link and a muted footnote.

### Layout per entry kind

| Kind | Glyph | Badge | Body | Extra |
| --- | --- | --- | --- | --- |
| State change | arrow | info "State change" | "Moved from {plain label} ({STATE}) to {plain label} ({STATE})." | Who recorded it, by role |
| Deadline reminder | stopwatch | warning "Deadline reminder" | Deadline in the deadline zone and the viewer's zone | Link to the action |
| Question received | ? | neutral "Question received" | Reviewer handle only (P-11) and topic | Link "Read and answer" |
| Answer sent | A | neutral "Answer sent" | "You answered {n} questions." | None |
| Vault verification | check or cross | success or error | Outcome only. Details stay in the vault. | None |
| Receipt | R | info "Receipt" | Ledger sequence | "Anchor pending" badge until witnessed (O-56, R-JV-04), link to receipt |
| Scores published | star | info "Scores published" | Only after NOT_SELECTED, DECLINED or GRANTED (O-54) | Link to scores |
| Milestone accepted | star | success | Milestone name and amount as a decimal string (R-JV-12) | None |
| Payment released | coin glyph | success | Request id and amount | None |
| Contractual notice | envelope | neutral | Notice title from the notice template, never a pack label (I-94, R-JV-09) | PDF link with size |
| Withdrawn | arrow | neutral "Withdrawn" | Stage-aware sentence, see "Withdrawal entries" below | No scores (O-54) |
| Text erased | empty set | neutral "Text erased" | "Entry text erased on {date}, reason: {reason}." Italic. | "The entry stays so the order of events is kept." |
| Guardian step | shield | neutral | "Your consent for applicant handle {handle} was recorded." | Guardian's log only (O-60) |

### Erased-text placeholder

Erasure destroys the data key of the text (ADR-004, I-81, §7.3, R-JV-11). The entry keeps its time and kind so the order of events stays readable. The body says when and why. It never says what was erased.

### Withdrawal entries (Q3)

Daniel's decision, 2026-11-01. Withdrawal is one entry kind with a stage-aware sentence (NOTE 10, O-54).

- From DRAFT: "You withdrew this draft before submitting it."
- After submission: "You withdrew this proposal at {plain stage label} ({STATE}). Reviewers were told it is no longer under review."
- Neither sentence shows scores or comments.

### Guardian steps

Visible only to the guardian (O-60). The applicant, staff and auditors see no guardian entry. The visibility function enforces this per request (R-JV-03).

### "Anchor pending" receipts

A receipt entry carries the ledger sequence and time. Until the audit-log anchor is witnessed, a warning badge with an ellipsis glyph reads "Anchor pending" (O-56, §7.4). It never shows a placeholder value. The anchor appears on the next page load after it is witnessed.

## Copy keys

`journey.route.title`, `journey.route.subtitle`, `journey.route.legend.*`, `journey.route.leave_label`, `journey.route.reenter_label`, `journey.route.list_title`, `journey.route.status.complete`, `journey.route.status.current`, `journey.route.status.upcoming`, `journey.route.status.end`, `journey.node.<state>` (pack labels, §5.3), `journey.help.what`, `journey.help.who`, `journey.help.deadline`, `journey.help.can`, `journey.help.<state>.*`, `journey.withdraw.title`, `journey.withdraw.body`, `journey.withdraw.action`, `journey.diary.title`, `journey.diary.filter`, `journey.diary.kind.*`, `journey.diary.erased`, `journey.diary.erased_note`, `journey.diary.anchor_pending`, `journey.diary.guardian_consent`, `journey.diary.empty`, `journey.diary.pagination`.

## Accessibility notes

- The SVG has `role="group"`, a `<title>` "Progress map for CSW-2024-0042" and a `<desc>` naming the current stage.
- Focus on an SVG node thickens its stroke in the focus colour. It is not only a colour change.
- The text list carries the same content as the map, so a screen reader user never needs the SVG.
- The activity log is an `<ol>`, so position is announced. Pagination is a `<nav>` with `aria-current="page"`.
- The help panel receives focus on target because it has `tabindex="-1"`.

## Spec IDs and R-JV mapping

| ID | Where it shows in this design |
| --- | --- |
| R-JV-01 | Plain label plus formal name on all 16 nodes and list items |
| R-JV-02 | Drift test between journey file and transition table. A build test, not a screen element |
| R-JV-03 | Activity log filtered per viewer |
| R-JV-04 | "Anchor pending" on the receipt and its log entry |
| R-JV-05 | "Progress as a list", keyboard reachable nodes, light and dark tokens |
| R-JV-06 | Public pages use the same SVG with no script. It renders in the visitor's chosen locale with a fallback to the tenant default. Formal state names stay untranslated beside the labels (I-96, Q8) |
| R-JV-07 | DEFERRED overlay uses the original call's policy |
| R-JV-08 | Programme set-up links to a progress map preview |
| R-JV-09 | No pack labels in contracts, notices, the Guide or emails |
| R-JV-10 | Stage 1 close shows the computed outcome only, with no alternative (`stage1-close.html`) |
| R-JV-11 | Log entries hold only `TextRef` values. Erased text yields the placeholder |
| R-JV-12 | Amounts shown as canonical ADR-006 decimal strings |

Also: I-92 to I-97, O-54, O-56, O-60, R-SB-03 (withdrawal until signature), R-NF-03.

## Open points

- Resolved on 2026-11-01: withdrawal sentences (item 3), public graphic language (item 8) and plain primary labels (item 12).

## Public progress graphic language (Q8)

Daniel's decision, 2026-11-01. The public SVG renders in the visitor's chosen locale and falls back to the tenant default. Formal state names stay untranslated beside the labels (I-96, R-NF-04).
