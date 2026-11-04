# 07. Vocabulary packs: plain (platform default) and Voyage (opt-in per tenant)

Status: draft, revised 2026-11-01 against `SPEC/12-journey-ui.md` (repository version) and `docs/handoff/m4-design.md`, then updated with Daniel's decisions of 2026-11-01 (Q11, Q12).

## Purpose and audience

This is still a grant process. The **plain grant vocabulary is the platform default pack**. The **Voyage pack is opt-in per tenant**, never the default. Where the prototypes show it, it appears as a small secondary line with the class `voyage-label`.

Both packs are terminology override sets (`white-labelling.md`, I-72). Tenants can edit labels or choose a pack (12-journey-ui §4, §5.4, R-WL-05). The formal state name stays visible beside every label in both packs (I-96, R-JV-01).

**Decision on O-55: design decision, spec amendment pending.** 12-journey-ui §15 O-55 still says "Voyage is the platform default vocabulary pack." Daniel decided on 2026-11-01 that plain grant language is the platform default and Voyage is opt-in per tenant. Until the spec is formally amended, the build must treat this as a design decision pending a spec update. See `spec-questions.md` item 11.

## Where pack labels may appear (I-94, R-JV-09)

Pack labels are interface labels only. A template scan enforces this (R-JV-09). No Voyage label may appear in:

- contracts and grant agreements,
- contractual notices,
- the Guide for Applicants,
- funder documents and reports,
- emails and other channel messages.

Public pages may show Voyage labels in headings through the pack, never in funder-required or legal text (12-journey-ui §8.5). Those documents use the formal state name or plain legal wording, marked TODO(legal) until Daniel supplies it.

## Catalogue 1: proposal states (node labels)

Key format follows 12-journey-ui §5.3: `journey.node.<state>` for the label and `journey.help.<state>` for the help text, in lowercase. Voyage labels are the §5.2 defaults, unchanged.

| Key | Formal state | Plain label (platform default) | Voyage label (§5.2) | Notes |
| --- | --- | --- | --- | --- |
| `journey.node.draft` | DRAFT | Draft | At the departure hall | |
| `journey.node.submitted` | SUBMITTED | Submitted | Departed, awaiting border check | |
| `journey.node.ineligible` | INELIGIBLE | Not eligible | Route closed at the border | Lead with the knock-out reason. No scores (O-54). |
| `journey.node.stage1` | STAGE1 | Stage 1 evaluation | Crossing | |
| `journey.node.stage2` | STAGE2 | Stage 2 questions | Ascent: questions from the scouts | |
| `journey.node.ranked` | RANKED | Ranked, awaiting committee decision | Awaiting the council | |
| `journey.node.irc_review` | IRC_REVIEW | Independent review | Independent watch | |
| `journey.node.deferred` | DEFERRED | Deferred to the next call | Wintering for the next voyage | Say which stage it re-enters at (§5.2). |
| `journey.node.negotiation` | NEGOTIATION | Negotiation | Treaty | |
| `journey.node.granted` | GRANTED | Granted | Charter in force | Not terminal (O-54). |
| `journey.node.in_execution` | IN_EXECUTION | Project in progress | On the road | |
| `journey.node.completed` | COMPLETED | Completed | Safe harbour | |
| `journey.node.not_selected` | NOT_SELECTED | Not selected | Route ended | Thank the applicant. Scores shown (O-54). |
| `journey.node.declined` | DECLINED | Declined | Route ended | Recorded reason first. |
| `journey.node.withdrawn` | WITHDRAWN | Withdrawn | Route ended | Neutral tone. No scores (O-54). |
| `journey.node.terminated` | TERMINATED | Grant terminated | Route ended | Recorded reason. Legal wording TODO(legal). |

Edge labels use `journey.edge.<from>_<to>`, for example `journey.edge.stage2_ranked` and `journey.edge.stage2_deferred` (§5.3). Edge ids map one to one to rows of the state machine transition table.

## Catalogue 2: domain concepts (12-journey-ui §4)

The spec fixes the Voyage labels. It does not name keys for these concepts. The `vocab.*` keys below are a design proposal.

| Proposed key | Concept | Plain label (platform default) | Voyage label (§4) | Spec note |
| --- | --- | --- | --- | --- |
| `vocab.call` | Call | Call | Voyage / Open passage | Public name stays the programme's own |
| `vocab.guide` | Guide for Applicants | Guide for Applicants | Chart room | Link only. Guide text untouched |
| `vocab.proposal_draft` | Proposal draft | Your proposal | Expedition plan | DRAFT |
| `vocab.team` | Team | Team | Crew | Roles stay formal in settings |
| `vocab.pre_check` | Pre-check | Pre-submission check | Packing check | Findings only, never scores (R-LA-06) |
| `vocab.submission` | Submission | Submission | Departure | SUBMITTED |
| `vocab.knock_out` | Knock-out check | Eligibility check (knock-out) | Border check | |
| `vocab.review_stages` | Review stages | Stage 1 evaluation, Stage 2 questions | Crossing, Ascent | STAGE1, STAGE2 |
| `vocab.committee` | Committee / IRC | Committee / Independent Review Committee | Council / Independent watch | |
| `vocab.negotiation` | Negotiation | Negotiation | Treaty | NEGOTIATION |
| `vocab.contract` | Contract | Grant agreement | Charter | The document keeps contract wording |
| `vocab.milestone` | Milestone | Milestone | Waypoint | |
| `vocab.payment_request` | Payment request | Payment request | Resupply request | Lines per milestone (R-PR-06) |
| `vocab.hardship` | Hardship contribution | Hardship contribution | Hardship relief | |
| `vocab.timeline` | Timeline | Deadlines | Weather and deadlines | |
| `vocab.audit_trail` | Audit trail | Audit trail | Logbook | Auditor view |

## Catalogue 3: surface names the spec gives as metaphors

12-journey-ui and ADR-015 name some surfaces with metaphor names. The design keeps each spec name in documentation and pairs it with a plain primary label in the UI. Daniel confirmed all five pairings on 2026-11-01 (`spec-questions.md` item 12): Activity log (Passage Diary), Progress map (Voyager route), Programme set-up (Planning Studio), Approval and publication (seal ceremony), Pre-submission check (packing check).

| Proposed key | Spec name | Plain primary label | Source |
| --- | --- | --- | --- |
| `place.diary` | Passage Diary | Activity log | 12-journey-ui §7, ADR-015 |
| `place.route_map` | route map | Application progress (progress map) | 12-journey-ui §1, §8.1 |
| `place.strip` | "where is this proposal" strip | Proposal status | 12-journey-ui §8.3 |
| `place.studio` | Planning Studio | Programme set-up | 12-journey-ui §8.2 |
| `place.studio.group1` | Surveying the territory | Funder and identity | §8.2 |
| `place.studio.group2` | Border rules | Eligibility and scope | §8.2 |
| `place.studio.group3` | Instruments | Evaluation, money and contract | §8.2 |
| `place.studio.group4` | Support and crew | Support, people and communications | §8.2 |
| `place.studio.group5` | Charter seal | Review and approval | §8.2 |
| `place.seal` | Seal ceremony | Approval and publication | §8.2 |
| `place.onboarding` | Founding the harbour | Tenant onboarding | §8.2 |
| `place.chronicle` | Chronicle | Proposal history (PDF) | §7.4, O-59 |
| `role.applicant` | voyager | Applicant | §1 |
| `role.planner` | trip planner | Programme manager | §1 |
| `role.reviewer` | scouts | Reviewer | §1, §8.3 |
| `role.committee` | council | Committee | §1, §8.3 |
| `role.irc` | watch | IRC | §1, §8.3 |

The 11 creator step names (`programme-creator.md`, m4-design §3.1) are already plain and are used unchanged.

## Catalogue 4: progress map and activity log

| Key | Plain label (platform default) | Voyage label | Notes |
| --- | --- | --- | --- |
| `journey.map.title` | Application progress | Your route | Subtitle "Your route through the call" is the light motif |
| `journey.map.status.complete` | Completed | Completed | |
| `journey.map.status.current` | Current stage | You are here | |
| `journey.map.status.upcoming` | Upcoming | Upcoming | |
| `journey.map.status.end` | Possible final outcome | Possible end of route | |
| `journey.map.withdraw_bracket` | Withdraw: possible in any state before GRANTED, including DEFERRED | Leave the route | One control, not 8 arrows (§5.1, NOTE 10) |
| `journey.map.reenter` | re-enters at the stage it left | re-enters at the stage it left | NOTE 8 |
| `journey.withdraw.action` | Withdraw this proposal | Withdraw this proposal | Same in both packs. The action has legal effect. |
| `journey.diary.erased` | Entry text erased on {date}, reason: {cause}. | Same | §7.3, I-97 |
| `journey.diary.anchor_pending` | Anchor pending | Anchor pending | §7.4, R-JV-04. Never a placeholder value |
| `journey.diary.guardian_consent` | Your consent for applicant handle {handle} was recorded. | Same | Guardian only (O-60) |
| `journey.strip.title` | Proposal status | Where is this proposal | Reviewers and committee only. Never IRC (O-58) |

## Catalogue 5: navigation and home

| Key | Plain label (platform default) | Voyage label | Notes |
| --- | --- | --- | --- |
| `nav.my_applications` | My applications | My voyages | |
| `nav.programme_setup` | Programme set-up | Planning Studio | |
| `nav.audit_trail` | Audit trail | Logbook | |
| `nav.history_export` | History export | Chronicle | |
| `nav.tenant_settings` | Tenant settings | Tenant settings | |
| `home.primary.kicker.applicant` | Your next step | Next step on your voyage | |
| `home.recent_activity` | Recent activity | Recent diary entries | |
| `home.activity.open_full` | Open the full activity log | Open the full Passage Diary | |
| `home.applicant.empty.title` | You have no applications yet | You have not started a voyage yet | |
| `home.applicant.empty.body` | Pick an open call and start a proposal. You can save it as a draft and come back later. | Pick an open call and start an expedition plan. You can save it as a draft and come back later. | |
| `home.applicant.answer_questions` | Answer reviewer questions | Answer the scouts' questions | |

Keys whose text is the same in both packs (Home, Open calls, Proposals, Calls, People, Notifications, Help, Account, Skip to main content, and the staff home headings) are not repeated here.

## Content rules for negative outcomes

1. Lead with what happened in one plain sentence.
2. Give the recorded reason next. Never hide it behind a link.
3. Say what the person can do: complain, read scores where allowed, find other calls.
4. Thank the applicant for NOT_SELECTED and DECLINED.
5. Avoid "failed", "rejected" and "unsuccessful" in headings.
6. No jokes or metaphor on INELIGIBLE, NOT_SELECTED, DECLINED or TERMINATED (12-journey-ui §4). In the Voyage pack the label is the only metaphor, and it never replaces the reason.
7. Sentences under 40 words. No em dashes.
8. Plural forms and number formats come from the locale, never string concatenation.

## Spec IDs

O-55, I-72, I-94, I-96, R-JV-01, R-JV-09, R-WL-05, R-NF-04, O-54, O-56, O-58, O-59, O-60, R-LA-06, I-97.
