# 01. Information architecture, navigation and "Your work" home

Status: draft, updated with Daniel's decisions of 2026-11-01. Prototypes: `nav-pattern.html` and the seven `home-*.html` files. The sign-in path before a home is in `auth-signup.html`, `auth-check-email.html`, `auth-enrol.html` and `auth-signin.html` (see `03-applicant-screens.md`).

## Purpose and audience

Every signed-in person lands on a home page that shows their own work. Today the demo lands every sign-in on the account page with no way into the app (`design-brief.md`; `m4-demo.md` J0; `spec-questions.md` item 13). This item fixes that.

Audience: all nine role groups. The first screen says what to do next in plain grant-process words.

## Top row

Order, left to right: tenant mark | role links | spacer | role chip | Notifications | Help | Account avatar.

| Element | Behaviour | Key |
| --- | --- | --- |
| Tenant mark and name | Link to Home. Logo and name are tenant tokens, self-hosted. | `nav.brand` |
| Role links | Every page the person may open without an id. Current page has `aria-current="page"`, bold weight and a 3px bar. | `nav.*` |
| Role chip | "Signed in as Applicant". Text only, so people with several roles know which view is active. | `nav.role_chip` |
| Notifications | Link with a number badge and hidden text "unread". The number is the cue, colour is extra. | `nav.notifications`, `nav.unread` |
| Help | Help for the current page. | `nav.help` |
| Account | Avatar with initials, or a person glyph when no initials exist. Link to `/app/me`. Accessible name "Account: {handle}". | `nav.account` |

The row wraps on narrow screens. It needs no menu button and no script. Every link keeps a 44 by 44 pixel target (WCAG 2.5.8).

The footer carries platform attribution (P-68) and funder visibility text, both marked TODO(legal) (`m4-design.md` §3.9).

## Navigation per role group

A person with roles in several groups sees the union of items, de-duplicated, with the role chip naming the active programme role. SoD-01 keeps most people inside one group per programme.

| Role group | Items after Home |
| --- | --- |
| Applicant (applicant, team member, grantee) | My applications, Open calls, Support |
| Programme manager and call drafter | Programmes, Calls, Programme set-up |
| FSTP coordinator | Proposals, Calls, Programmes, People |
| Assigned reviewer | My assignments, Conflicts |
| Committee member | Rankings, My assignments |
| IRC member | Reviews |
| Finance and operations (finance approver, payment releaser, contract signatory) | Payments, Contracts |
| Auditor | Audit trail, History export |
| Tenant admin | People, Programmes, Tenant settings |

Public visitors see Open calls, How it works and Sign in. Public pages work with scripts off (R-PB-04).

The spec groups these roles as Receiving, Drafting, Judging and Operations (`12-journey-ui.md` §8). The UI shows role names, not group names.

## "Your work" home per role

Every home has the same three parts: one primary card, count summaries, and recent activity filtered by the visibility function (I-93).

| Role | Primary card | Counts | Recent activity |
| --- | --- | --- | --- |
| Applicant | The proposal with the nearest deadline. Plain stage label, formal state, id, deadline in both zones, one primary action. The Voyage label is a secondary line. | Open calls badge, Support card with mentor state | State changes, reminders, questions received on own proposals |
| Programme manager | The programme set-up draft with the next open step, or a pending approval request | Calls by call state (DRAFT, APPROVED, PUBLISHED) | Approvals given and requested, call edits that returned a call to DRAFT |
| Coordinator | "N proposals need a knock-out decision" | Queue health: per-state counts with pseudonymous ids only (O-57, §8.3). Overdue clock callout. | State changes the coordinator recorded, overdue clocks |
| Reviewer | "N proposals need your score" | Assigned, questions open, scored | Answers received, scores recorded |
| Committee | Ranking round with proposal count and budget remaining (R-EV-08) | Proposals RANKED, recusals, ballots cast | State changes into RANKED, recusals |
| IRC | "N nominated proposals for independent review" | Nominations | Nominations only. No proposal status strip anywhere (O-58). |
| Finance | Approver: requests awaiting approval. Releaser: approved requests awaiting release, as a separate section (SoD-04, I-05). | Contracts awaiting signature, payments released | Payment request state changes |
| Auditor | Proposal history with export (O-59) | Audit trail count, erasure log count | None. The auditor views logs, not a personal activity list. |
| Tenant admin | Pending role grants needing a second admin (SoD-07), and policies awaiting activation | People, programmes | Role grants and revocations |

### Empty states

- Applicant with no proposals: "You have no applications yet" with "See open calls" (`home.applicant.empty.*`).
- Reviewer with no assignments: "No proposals are assigned to you right now. We will notify you when one is."
- Any list with no entries: "No activity yet."

## The 3-click rule

Each role reaches its primary task in at most three clicks from sign-in. Sign-in always lands on Home, never on the account page.

| Role | Path | Clicks |
| --- | --- | --- |
| Applicant in STAGE2 | Sign in, Home, "Answer reviewer questions" | 1 |
| Applicant starting | Home, "See open calls", call card "Read the call", "Start a proposal" | 3 |
| Programme manager | Home, "Programme set-up", step | 2 |
| Coordinator | Home, "Start conflict check" | 1 |
| Reviewer | Home, "Score this proposal" | 1 |
| Committee | Home, "Review rankings" | 1 |
| IRC | Home, "Review nomination" | 1 |
| Finance approver | Home, "Review approvals", request | 2 |
| Payment releaser | Home, "Review releases", request | 2 |
| Auditor | Home, "Open proposal history", proposal | 2 |
| Tenant admin | Home, "People", person | 2 |

## Copy keys

`nav.brand`, `nav.home`, `nav.my_applications`, `nav.open_calls`, `nav.support`, `nav.proposals`, `nav.calls`, `nav.programmes`, `nav.people`, `nav.programme_setup`, `nav.my_assignments`, `nav.conflicts`, `nav.rankings`, `nav.reviews`, `nav.payments`, `nav.contracts`, `nav.audit_trail`, `nav.history_export`, `nav.tenant_settings`, `nav.notifications`, `nav.unread`, `nav.help`, `nav.account`, `nav.role_chip`, `nav.skip_to_main`, `home.title`, `home.welcome`, `home.primary.kicker`, `home.recent_activity`, `home.activity.open_full`, `home.applicant.empty.title`, `home.applicant.empty.body`, `home.coordinator.queue_health`, `home.coordinator.overdue`, `home.finance.sod_note`, `home.auditor.read_only`, `footer.attribution`, `footer.funder`.

## Accessibility notes

- One `<nav aria-label="Main navigation">` per page. The prototype `nav-pattern.html` has three, labelled "(example a)" to "(example c)" for review only.
- `aria-current="page"` marks the active item. It is also shown by weight and an underline bar, never colour alone.
- The skip link is the first focusable element and moves focus to `<main id="main-content">`.
- No keyboard trap. There are no menus that capture focus. Tab order follows reading order.
- The notification count has hidden text "unread" so screen readers announce "2 unread".
- Mobile: the row wraps to two lines. Primary action buttons span the card width below 52rem. Touch targets are at least 44px.
- Headings: one `h1` "Your work", then `h2` per card.

## Spec IDs

R-NF-03 (WCAG 2.2 AA), R-NF-04 (every string is a catalogue key), I-96 (displayed label beside the formal state on the primary card), I-93 (activity filtered per viewer), O-57, O-58, O-59, SoD-04, SoD-07, I-05, R-EV-08, R-PB-04, P-68.

## Open points

- The programme manager and tenant admin homes are specified here but have no prototype yet.
- Whether a person with roles in two groups sees one merged home or a role switcher. Recommendation: one merged home with a section per role.
- Default vocabulary pack: resolved. Plain grant language is the platform default and Voyage is opt-in per tenant (Daniel's decision, 2026-11-01). Until O-55 is amended, this is a design decision pending a spec update (`spec-questions.md` item 11).
- Public navigation: "Sign in" now links to `auth-signin.html`. The public call page uses a minimal navigation with "Back to calls" and "Sign in". The IRC navigation gains "My cases" (`irc-cases.html`).
