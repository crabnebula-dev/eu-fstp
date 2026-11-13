# Platform mailbox: design and first cut

Lane `m6/mailbox`, written 2026-11-11 for the overnight build. Daniel's brief of 2026-11-07: a platform-based mailbox that calls each person to the place where their attention, decision or signature is needed.

Status: draft for Daniel's review. Every decision below is interim until he confirms it. Labels such as `MB-Q1` exist only in this document. Every `I-`, `R-`, `P-`, `SoD-` and `ADR-` identifier is quoted from the repository.

Sources read: `SPEC/02-domain/invariants.md` (I-03, I-05, I-21, I-25 to I-27, I-67, I-84 to I-86), `SPEC/01-requirements/functional.md` (R-NT-01 to R-NT-05, R-EV-04, R-IR-02, R-AC-01), `SPEC/02-domain/roles-and-sod.md` (SoD-04, SoD-07, SoD-18), `SPEC/03-architecture/notifications.md`, `docs/handoff/m6-design.md`, `docs/handoff/m5-design.md` section 6, `docs/design/10-post-grant-screens.md`, and on `main`: `fstp-access` (`reads.rs`, `registry.rs`, `replies.rs`), `fstp-api-core` (`dispatch.rs`, `pending.rs`, `dispatch/grant.rs`, `dispatch/me_roles.rs`, `dispatch/creator_ops.rs`, `journal.rs`), `fstp-mail` (`placeholder.rs`, `template.rs`), `web/src/home`, `web/src/applicant/lists.ts`, `web/src/journey` and the e2e cell.

---

## 1. What a message is

A message is one piece of work, or one notice, that the platform holds for the signed-in person. It names:

| Member | Meaning |
| --- | --- |
| `id` | A stable key built from the kind and the target ids, such as `contract.sign:41:2:lead`. The same work gives the same id on every read |
| `kind` | One of a closed list (section 2) |
| `action` | `true` when the person must act, `false` for a notice to read |
| `href` | The platform page where the person acts, always a path under `/app/` |
| ids | Only the ids the target needs: `proposal`, `call`, `assignment`, `round`, `contract`, `request`, `pending`, `programme` |
| `since`, `due` | Optional instants, as decimal microseconds, when the source holds them |

A message holds no title, no proposal text, no score, no name and no email. The page it links to shows what the person may read there, through that page's own read. So the mailbox is a channel in the sense of I-27 and holds what an email may hold: ids, times and a link.

The reply is `{"open": n, "messages": [...]}`. `open` counts the messages with `action: true`. The shell shows it beside the Mailbox entry.

## 2. Where messages come from

The mailbox is a read model derived from state that already exists. It adds no store, no record, no op family and no table. It is one read, `me.mailbox`, with the rule `Own` (`ReadKind::GetMyMailbox`). So no ADR is needed (ADR-020 stays free).

| Kind | Source | Who | Closes when | Page |
| --- | --- | --- | --- | --- |
| `pending.confirm` | Open, unexpired pending action (I-85, `pending.rs`) | The account whose agent prepared it | Confirmed, discarded or expired | `/app/pending/{pending}` |
| `proposal.submit` | Own draft in an open call | The lead | Submitted, or the call closes | `/app/proposals/{proposal}/submit` |
| `stage2.respond` | Proposal in STAGE2 | The lead | The proposal leaves STAGE2 | `/app/proposals/{proposal}/stage2` |
| `negotiation.acknowledge` | Proposal in NEGOTIATION, notice not acknowledged (R-NG-06) | Each team member | Acknowledged, or the state moves on | `/app/proposals/{proposal}/negotiation` |
| `review.declare` | Reviewer assignment awaiting declaration (R-CF-02) | The assignee | Declared | `/app/assignments/{assignment}` |
| `review.score` | Active reviewer assignment, proposal in STAGE1 or STAGE2, no score for the current stage and plan | The assignee | Scored, or the stage ends | `/app/assignments/{assignment}` |
| `irc.declare` | IRC assignment awaiting declaration | The IRC assignee | Declared | `/app/irc-assignments/{assignment}` |
| `irc.review` | Active IRC assignment, proposal in IRC_REVIEW, no review recorded for it | The IRC assignee | Review recorded, or the state moves on | `/app/irc-assignments/{assignment}` |
| `intake.knock_out` | A published call of the caller's programme with a SUBMITTED proposal (R-EV-01) | The FSTP coordinator | No SUBMITTED proposal is left | `/app/calls/{call}/intake` |
| `round.vote` | An open cut-off round of a call where the caller sits on the committee | Committee members and the chair | Cast, delegated, or the round closes | `/app/cut-off-rounds/{round}` |
| `admin.approve_activation` | A programme draft with a live activation request | A tenant admin who built nothing in it (I-67) | Approved, or the request ends | `/app/admin/approvals` |
| `contract.sign` | Latest contract version SENT or SIGNED_BY_GRANTEE, caller is an unsigned party, the signatory only once the grantee side signed | That party | Signed, or the version moves on | `/app/grants/{proposal}/contract` |
| `payment.review` | Payment request UNDER_REVIEW on a grant where the caller holds an active reviewer assignment | The assigned reviewer | The request leaves UNDER_REVIEW | `/app/operations` |
| `payment.approve` | Request ACCEPTED, caller is finance approver of the programme | The finance approver | Approved | `/app/operations` |
| `payment.release` | Request PAYMENT_APPROVED, caller is payment releaser, and caller neither accepted a line nor approved it (SoD-04, I-05) | The payment releaser | Released | `/app/operations` |
| `payment.confirm` | Request RELEASED, caller is finance approver | The finance approver | Confirmed paid | `/app/operations` |
| `notice.outcome` | `me.notices` ProposalOutcome (R-EV-04) | The team | Never: a notice to read | `/app/notices` |
| `notice.irc_concern` | `me.notices` IrcConcern (R-IR-02) | The team | Never: a notice to read | `/app/notices` |

Each work message is computed again on every read from the state the same read sees. When the action is done, the state changes and the message is gone. Nothing is written to close it.

## 3. Visibility (roles and separation of duties)

Three rules, each tested:

1. **Own only.** The read is `ReadRule::Own`. It derives messages for the caller's account and nothing else (I-86). It never names another account.
2. **The target read decides.** Before a message is kept, the mailbox asks `fstp_access::authorize_read` for the read behind its page (D11), with the caller's own principal, state and clock. A message whose page the caller could not read is dropped. So the mailbox never shows more than the read rules show, in any of the 16 proposal states. Examples: the caller's own assignment list for `review.declare` and `irc.declare` (R-CF-02 forbids a content read before the declaration), the score sheet for `review.score` (I-03), the IRC case for `irc.review`, the intake queue for `intake.knock_out`, the round through its call for `round.vote`, the contract read for `contract.sign` (I-21 keeps drafts to the team).
3. **Act only where the domain lets you.** Work messages follow the domain's own guards: SoD-04 and I-05 for release, I-67 for activation approval, the signing order of `contracts.md` for the signatory, and an active binding at the read instant for every role.

The page itself still runs its own read and command checks. The mailbox only decides what to point at.

## 4. Links

Every `href` is built in one table on the server (`fstp-api-core/src/mailbox.rs`, `href_of`), from the kind and ids. A test checks each href against the route list `MAILBOX_ROUTES`. A web test checks that each route of that list is mounted by the `/app/` shell, except the M5 pages listed in section 9, which lane `m5/ui` builds.

The pending action page `/app/pending/{id}` had no page on `main` (`pending.rs` already names it in each MCP answer). This lane adds it in `web/src/mailbox`: it shows the operation name, the canonical request as untrusted text (TW-9), the expiry, and Confirm (with step-up) and Discard buttons.

## 5. The email relation

- Emails stay as M6 built them: ids, states, times and one link into the authenticated platform, plus the bank-details sentence (I-27, `notifications.md` content rules). No change to `fstp-mail` or `fstp-timeline` in this lane, so no pinned template version moves (I-25).
- An email's link goes straight to the page of its event. The mailbox lists the same work with the same target, so a person reaches it either way.
- The mailbox reply passes the same content test as an email: only ids, kinds, instants, booleans and paths (test T4 below).

## 6. MCP exposure

`me.mailbox` is web only in this cut, like `me.roles`. No MCP tool is registered. Reason: a message can point at review, payment or committee work, and the MCP scopes are per area (`proposals:read`, `review:read`, and others). One tool would need a filter per message by the scope of its target read. That filter is cheap later, but it needs its own test against I-84. See MB-Q4.

## 7. Tests (written before the code)

| ID | Where | What |
| --- | --- | --- |
| T1 | `fstp-api-testkit/src/harness/mailbox_tests.rs` | I-86, R-AC-01: on matrix worlds in the states where work exists, for every principal of the cast, each message's target read is admitted for that principal through `ApiCore::dispatch`. The mailbox of each principal names only work its own bindings give |
| T2 | same | Closing: a contract signature, a payment approval and release, a ballot and a declaration each remove their message on the next read, and nothing else changes |
| T3 | same | SoD-04, I-05: a releaser who approved the request, or accepted a line of it, gets no `payment.release` message |
| T4 | same, and `fstp-api-core` unit tests | I-27, I-86: every reply holds only the members of section 1, ids are decimal, `href` matches `MAILBOX_ROUTES`, no `@`, and no title or text of the world appears |
| T5 | `fstp-api-core/src/mailbox.rs` unit tests | Each kind maps to one route and one target read, and `open` equals the number of action messages |
| T6 | `fstp-api-testkit/src/harness/mailbox_tests.rs` | I-85: a prepared action appears as `pending.confirm` for its own account only, and disappears once confirmed or discarded |
| T7 | `web/test/mailbox.test.ts` | The decoder refuses any member outside the shape; every `MAILBOX_ROUTES` pattern is mounted by the shell or listed as an M5 page; the nav shows the open count |
| T9 | `e2e/mailbox/mailbox.spec.ts` | I-27, I-86, R-NF-03: on a demo cell, the coordinator, a reviewer, an IRC member and the lead in stage 2 and in negotiation each click from "Sign in as" to the home page, to the mailbox, to their first work page. The top bar count equals the page count |
| T8 | registry, authz reference, `REPLIES` fit | The read is in the registry, the reference matrix (`R::AnyAccount`, no tool) and the reply shapes, as for every read |

## 8. Build

- `fstp-access`: `ReadKind::GetMyMailbox`, its `Own` rule, the registry row `me.mailbox` at `GET /me/mailbox`, class Personal, no tool, and its reply shape.
- `fstp-domain`: two read accessors with no new state: `PaymentState::approver` and `decision::irc_review_recorded`.
- `fstp-api-core`: `mailbox.rs` with the kinds, `href_of` and the view; `dispatch/mailbox.rs` with the derivation.
- `tools/gen-ts`: regenerate `web/src/gen/api.ts`.
- Web: `web/src/mailbox/**` with the mailbox page `/app/mailbox` and the pending action page, a Mailbox entry with its open count in the shell navigation, and a "Waiting for you" link on the home page.
- Demo: each person's card on `/demo` links to the cell's `/app/mailbox`, and the page says that every email points into the platform. The demo sign-in still lands on the home page, which links to the mailbox.

## 9. Decisions and open questions for Daniel

**MB-D1. Derived, not stored.** The mailbox is a pure read over the engine state, the API core's journal and content projections, and the pending store. Why: the brief prefers it, it adds no record to keep in step, and a message cannot outlive its work. Cost: no "read" or "dismissed" flag per notice. That would need a per-account store and an ADR (MB-Q1).

**MB-D2. Each work message closes itself when the action is done.** It is recomputed on every read, so a signature, a vote, a declaration or a payment step removes it at once. Notices (`notice.outcome`, `notice.irc_concern`) never close. They are records of an event, so they show as "to read" and do not count in `open`.

**MB-D3. Who sees what.** Own messages only, kept only when the read behind the page admits the caller (section 3), and only where the domain lets the caller act (SoD-04, I-05, I-67, the contract signing order). Tenant admins see only tenant work. A role with no page in this release gets no message.

**MB-D4. Sign-in and invitation mails do not go through the mailbox.** They carry a one-time capability in the link fragment for a person who may have no session yet. Showing them in a signed-in mailbox would be circular, and would put a capability where any open tab can read it. They stay on the M6 dispatcher path (M6 reading 2). An invitation for an account that already exists could become a message later (MB-Q3).

**MB-D5. Web only, no MCP tool yet** (section 6).

**MB-D6. Email links go straight to the page of the event,** and the mailbox lists the same target (section 5). Why: one click to act, and no change to the pinned templates (I-25) or the sealed message codec this week.

**MB-D7. M5 routes.** The contract message links to `/app/grants/{proposal}/contract`, the page lane `m5/ui` built. The four payment messages link to `/app/operations`, which lists the caller's payment queue from the same `payment.queue` read the mailbox checks against. The request page itself uses a grant read that an assigned reviewer does not hold, so Operations is the one page every payment role can open (lead, 2026-11-12, at the merge).

**MB-D8. Stage 2 is one message per proposal.** `stage2.respond` stays while the proposal is in STAGE2, since the lead may answer questions or revise the plan until the window closes (P-07). A finer "unanswered question" message needs the thread projection to mark answers per question (MB-Q2).

**MB-D9. Guardian consent is left out.** The domain cannot know whether the vault holds the consent, so a consent message could not close itself. The guardian keeps the home card and the guardian page.

Open questions:

- **MB-Q1.** Should notices carry a per-account "read" mark? It needs a small store and an ADR. Recommendation: not before the pilot.
- **MB-Q2.** Should `stage2.respond` split into one message per unanswered question? It needs the journal to fold answers per question.
- **MB-Q3.** Should an invitation or role grant to an existing account show as a message? Recommendation: yes, once the people pages show pending invitations for the invitee.
- **MB-Q4.** MCP: add `fstp_list_mailbox`, filtering each message by the scope of its target read? Recommendation: yes, after T1 runs over the MCP channel.
- **MB-Q5.** Should emails link to `/app/mailbox#<id>` instead of the page? Recommendation: no, keep one click to the work.
- **MB-Q6.** Programme managers have no work message in this cut. Candidates: an advanced signature route to approve (P-30 step 3), contract changes proposed by the grantee, and milestones to close. Each needs a request state the domain does not expose yet.

## 10. First cut: status and known gaps

- Built: sections 2 to 8, except the MCP tool (MB-D5). The read is `GET /api/v1/me/mailbox`, the pages are `/app/mailbox` and `/app/pending/{id}`, and the top bar shows "Mailbox (n)".
- **Gap G1, recusal.** A committee member recused from a round (R-CF-02 NOTE) still sees `round.vote` until the round closes. The recusal is a vault question that the round page asks, and the mailbox asks no vault question. The round page then says the member is recused.
- **Gap G2, the target gate has no failing case in the worlds.** Every message the sources derive is already readable, so test T1 passes with or without the `authorize_read` gate. The gate stays as a second line, and T1 proves the sources alone never point at a closed page.
- **Gap G3, M5 pages.** `/app/grants/{proposal}/contract` and `/app/operations` show the not-found page on this branch until lane `m5/ui` merges. The web test lists them as M5 pages and fails if a mailbox route is neither mounted nor listed.
- **Gap G4, scoring history.** When the journal no longer holds a proposal's history, `review.score` stays listed and its page says why it cannot load.

### Decided by Daniel on 2026-11-13

- MB-Q1: yes. Notices carry a per-account "read" mark. It needs a small store, so an ADR comes first.
- MB-Q2: yes. `stage2.respond` splits into one message per unanswered question, once the journal folds answers per question.
- MB-Q3: yes. An invitation or role grant to an existing account shows as a message.
- MB-Q4: yes, later. `fstp_list_mailbox` waits until the mailbox runs over the MCP channel.
- MB-Q5: no. Emails keep linking straight to the page of the work.

## Decisions of 2026-11-13: build notes

Lane `product/decisions-1113` builds the eight decisions of 2026-11-13 recorded in this file, in `fast-flow.md` and in `m5-ui.md`. Each reading below is interim, pending Daniel.

1. **Calibration consent leaves INELIGIBLE proposals out (I-37).** Interim, pending Daniel: the filter sits in the domain's calibration lane, the one place consent is requested. An outcome notice with state INELIGIBLE is not noted as the outcome notice. A request on an INELIGIBLE proposal is refused under I-37. A consent on an INELIGIBLE proposal never admits it to a calibration set. No API op requests consent yet (M12), so no web or MCP surface changed. Tests: `crates/fstp-domain-testkit/tests/i37_ineligible_outcome_opens_no_consent.rs`.
2. **The knock-out reason has a durable source (O-54, R-EV-01).** Interim, pending Daniel: the placeholder `ReadClearance` of `fstp-api-core/src/port.rs` is now `fstp_access::ReadClearance`, which only `authorize_read` builds. `proposal.view` passes its own clearance to `TextStore::get` for the newest `KnockOutRecorded` reason, and checks the text against the record's digest. `proposal.list_own` asks one `proposal.view` clearance per INELIGIBLE row, so the list opens no text the one read would not. The in-memory text is no longer consulted. The fake text store now releases a proposal's text only to a clearance on that proposal. The production cell wires no `TextStore` port into the API core yet, so the restart is proven on the test cell: a fresh API core over the same ledger and text store still shows the reason. Agents still get no reason.
3. **The assigned reviewer reads the grant overview after NEGOTIATION (R-PR-08, SoD-12).** Interim, pending Daniel: a new read rule `GrantReviewer` admits the declared, conflict-free assigned reviewer in GRANTED, IN_EXECUTION, COMPLETED and TERMINATED. WITHDRAWN and DECLINED end the negotiation without a grant, so they stay closed. In NEGOTIATION the reviewer keeps the determination view only. `contract.view` and `payment.status` do not gain the rule. `grant.list_mine` names the reviewer's grant with `via: "assigned_reviewer"`, and the grants hub shows it under "Grants you review". The reference has the rule `GrantOverview`. The grant page shows such a reviewer a link to Operations instead of the contract and payments links. The line review page links "Grant overview of proposal N". Web only, as before (I-85).
5. **Operations offers no funder reports link to a person whose `report.list` refuses them (R-RP-03, R-AC-01).** Interim, pending Daniel: a judged refusal of `report.programmes` now means no programme, so the binding programmes no longer stand in. Only a failed read lets the programme manager and auditor bindings stand in. The reports section, with its number form, shows only when a programme is listed or the caller holds a programme manager, auditor or Financial signatory role. Reviewer R1 sees no reports section. The click-through is `e2e/decisions/r_pr_08_sod_12_reviewer_reads_the_overview.spec.ts`.
4. **`contract.awaiting_me` has a read-only MCP tool (I-84 to I-87).** Interim, pending Daniel: the tool is `fstp_list_contracts_to_sign`, with no input and the `proposals:read` scope of `fstp_get_contract_status`. It is a read, not prepare-only, and signing stays web only (I-85). Its reply is the web reply: contract, version, field, role, state and digest, with no account, email or bank value (I-86). The capability row map places it in the Grantee row, beside the contract status tool. The narrowed direct, HTTP and MCP matrices agree with the reference, and the I-86 canary crawl covers it.
6. **MB-Q1: notices carry a per-account read mark.** `docs/adr/ADR-020-mailbox-read-marks.md` comes first, status Proposed, pending Daniel's acceptance. Interim, pending Daniel: the new operation `me.mailbox.mark_read` (`POST /me/mailbox/read`, body `{"message": "<id>"}`) is web only, class Personal, rule any account. It accepts only a notice of the caller's own mailbox at that instant. Any other id gets `not_found` with rule `Input`. The marks live in memory in the API core, bounded at 4096 per account and 1 000 000 in all, as the negotiation acknowledgement does, until lane W6 gives them a table. Each notice in `me.mailbox` carries `read`, and work messages carry none. The mailbox page shows "Unread" or "Read" beside each notice, an unread count, and a "Mark as read" button. Tests: `adr020_*` in `fstp-api-core/src/mailbox.rs`, `harness/mailbox_tests.rs` and `web/test/mailbox.test.ts`.
7. **MB-Q2: one `stage2.respond` message per unanswered question (R-EV-05).** Interim, pending Daniel: the domain's `AnswerQuestions` carries one text and names no question, so the journal folds an answer as answering every question asked before it (`Journal::unanswered`). Each unanswered question gives one message, with the member `question` (its ordinal in the thread, from 1) and `since` (when it was asked). The id gains the ordinal, so each question has its own message and its own id. A proposal in STAGE2 with no unanswered question now has no message, which replaces MB-D8. A thread the journal does not hold keeps one message for the proposal, as gap G4 does for scores. The label reads "Answer question N on proposal P". Per-question answers in the domain would need a command change; Daniel decides whether that is wanted.
