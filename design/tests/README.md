# Prototype tests (Playwright)

Playwright tests for the static prototypes in `../prototypes`. Playwright is allowlisted as a test tool (ADR-003). It never ships, and this folder adds no package to the product.

Written to the patterns in the Playwright guide "Writing tests" (https://playwright.dev/docs/writing-tests): `test` and `test.describe`, role and label locators, and web-first `expect` assertions.

## What the tests cover

Shared rules, run on all 69 prototypes:

- `lang="en"`, a title ending in " - FSTP", header, main and footer landmarks, and the prototype state label.
- No `<script>`, no inline event handlers, no banned DOM calls, no em dashes, and only `../tokens.css` as a stylesheet.
- No request leaves `file://`, so no external fonts, scripts or images load.
- The skip link is the first tab stop, becomes visible and moves to `#main-content`.
- The current page carries `aria-current="page"` in the top row or the sidebar.
- Every form control has an accessible name.
- Badges, primary and danger buttons, paragraphs and table cells meet 4.5:1 contrast in light and dark themes (I-70).
- Primary chrome uses plain grant language. Headings, buttons, nav items, badges, labels and legends contain no journey metaphor words. Text inside `.voyage-label` is excluded, because it is the secondary Voyage layer.

Screen rules:

- Progress map: heading "Application progress", 16 keyboard-reachable SVG nodes naming the formal state, a 16-item text alternative and `:target` help panels with no script. Also one WITHDRAWN node with a bracket that includes DEFERRED, a labelled DEFERRED re-entry, and no animation under reduced motion.
- Activity log: 8 entry kinds, the erased-text placeholder, "Anchor pending" and pagination.
- Public calls with JavaScript disabled, including the GET search form (R-PB-04).
- Applicant screens: plain headings, disabled submit and sign buttons, exact amounts, the receipt anchor, notice version and ethics declaration, the stage 2 clock and `reviewer-` handles, no scores on INELIGIBLE, and anonymous scores on NOT_SELECTED (O-54).
- Judging: no status strip for IRC (O-58), a strip for reviewers and committee, and the title and neutral summary before the yes or no conflict answer. Also the 0 to 5 scale, the cut-off row, "Recused", per-member ballots with delegation, and exactly two IRC options with the DEFERRED or DECLINED consequence.
- Staff: the conflict, read and knock-out order, and "Confirm this outcome" as the only Stage 1 action. Also 5 groups with the 11 creator steps in spec order, step 6 Money current, the I-50 refusal, I-65 and I-66 notes, activation before publication, and the finance SoD split.
- Navigation: the primary task is one click from each home, with plain button names, and the avatar leads to `/app/me`.
- Tokens: dark theme by system preference, the `data-theme` override and a 3px focus outline.

Checks for the 8 new and 5 updated prototypes of 2026-11-01 (Daniel's decisions, spec-questions items 16 to 23):

- Each file loads with HTTP status 200 through a local route and has one main landmark.
- No metaphor word appears in headings or button labels.
- TODO markers sit in HTML comments. No "TODO" text renders inside `main`. The footer TODO(legal) line is outside `main` and unchanged.
- Auth flow: the email field, no resend control, disabled passkey buttons with a reason, one enrolled device, and the TODO(legal) and TODO(js) comments.
- Public call page with JavaScript disabled: two zones, amounts, the AI disclosure and the minimal navigation.
- Conflicts list: "Reviewer" only, one Submitted row and the R-CF-04 callout.
- Reviewer stage 2 and scoring: read-only stage 1 scores, the "No questions" radio, the three summary fields and the required correction reason.
- Committee ranking: criterion columns, "Requested (€)", the remaining budget row and two "Not served in M4 demo" labels.
- IRC: four case statuses, the disabled declare button, "1 of 2 validations complete." and a held proposal with no controls.
- Proposal editor: four panels, the current step, the eligibility warning, the two ticks and the late refusal with no button.
- Final outcomes: the frozen rules link and an on-hold panel with no links or controls.

Checks for the 5 tenant admin prototypes (`09-tenant-admin.md`):

- Each file loads with HTTP status 200 through a local route and has one main landmark.
- No metaphor word in headings or buttons, no `.voyage-label` and no Voyage pack label anywhere on the page.
- The shell shows "Signed in as Tenant admin", the Horizon Bridges brand and links to all five admin screens.
- TODO markers sit in HTML comments. Every disabled button has a TODO(js) comment and an `aria-describedby` reason.
- Home: the two cards, the members and domains links, two programmes linking to Programme set-up, and the attribution note in the footer.
- Organisation: four definition lists, three disabled Edit buttons, two signed agreements, the sub-processor link, three TODO(legal) comments and the SoD-07 note.
- Members: four accounts, two admins, the Tenant-wide roles column, the highlighted self row with SoD-07, the pending Call drafter invitation and the SoD-09 note.
- Branding: three upload slots, one "Fails WCAG 2.2 AA" pair, five mandatory elements present, and Save disabled with its reason. Also the I-68, I-70 and I-72 notes.
- Domains: two verified domains, the pending domain linking to its DNS instructions, three passing email checks, disabled Add domain and Re-check, and the ACME note.

Checks for the 28 post-grant prototypes (`10-post-grant-screens.md`):

- Each file loads with HTTP status 200 through a local route and has one main landmark.
- No metaphor word in headings, buttons, table headers, labels or legends. No `.voyage-label` and no Voyage pack label. The Horizon Bridges brand is shown.
- TODO markers sit in HTML comments. Every disabled button has a TODO(js) comment and an `aria-describedby` reason.
- Payments: plan order, the disabled paid-in-full row, the pending amount, the running total, three passing checks, the full, partial and reject lines, and the SoD-04 release block. Also the six request states, including CHECKS_FAILED.
- Contracts: SENT, the three-step cascade, Decline, three Countersign buttons, the EFFECTIVE row and the amendment diff.
- Complaints: three decision options, I-57, SoD-13, three remedies and five complaint states.
- Transparency: three cards at three levels, the no-tracking footer, the I-42 comment, two default Hidden choices, four options disabled for a minor on the team and the JSON example.
- Reporting, support and onboarding: six audit events, four report rows, the separate approver note, four support cards, three private session-notes links and nine wizard steps with eight locked.
- Decisions Q25 to Q27: role prerequisite callouts on review and release, the scope decision and out of scope view, and the TODO(legal) T&C comments on three complaint screens.
- Remaining screens: nine onboarding panels with "Step N of 9", back links, locked notes and step content. The checks failed detail, the contract draft, advanced approval and history, the mentor and operations homes and the report failure view.
- Signatory roles: Tenant-wide roles badges for 4 accounts, K. Wu holding both signatory roles, the two signatory subsections on Organisation and the step 9 activation conditions. Four disabled Change roles buttons and the notes that roles can be changed later.
- Decisions Q28 to Q30: the sealed draft note and link on contract history, the step 9 activation approval panel and note, and step 5 with two verification methods.
- Navigation: the updated home, negotiation, contract, funder report, payment status and final outcome pages link to the new screens.

Layout shell and masquerade rules:
- The 61 signed-in prototypes have one `aside.sidebar` labelled "Main navigation" in the app layout. It holds the nav, a role chip, Account and Sign out. The top bar has no nav.
- On those pages the masquerade banner is the first element in the page body. It is hidden on every page except `home-voyager.html` and `reviewer-scoring.html`, where it is visible above the nav and Exit masquerade goes to Administration.
- The 8 public prototypes use the public layout, with the nav in the top bar and no sidebar or banner.
- Desktop at 1280px: the sidebar is 220px, sticky and left of main, main is at most 960px and the avatar is hidden. Mobile at 375px with scripts off: the nav stacks under the top bar and the avatar leads to the profile page.
- Sidebar links, role chip, label and the visible banner meet 4.5:1 in light and dark themes.
- `admin-masquerade.html`: heading, explanation, ten "View as" links, the read-only note and the TODO(js) comment. `home-admin.html` links to it under Support tools.

Last run on 2026-11-01: 847 passed, 0 failed.

## Running

From any folder that has `@playwright/test` installed:

```sh
npx playwright install chromium
PW_OUTPUT_DIR=/tmp/pw-results npx playwright test -c design/tests/playwright.config.ts
```

`PW_OUTPUT_DIR` keeps run artefacts out of the design tree. When `@playwright/test` is installed in a folder outside the repository, run from that folder and set `NODE_PATH` to its `node_modules`, so the config can resolve the package.
