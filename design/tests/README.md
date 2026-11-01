# Prototype tests (Playwright)

Playwright tests for the static prototypes in `../prototypes`. Playwright is allowlisted as a test tool (ADR-003). It never ships, and this folder adds no package to the product.

Written to the patterns in the Playwright guide "Writing tests" (https://playwright.dev/docs/writing-tests): `test` and `test.describe`, role and label locators, and web-first `expect` assertions.

## What the tests cover

Shared rules, run on all 40 prototypes:

- `lang="en"`, a title ending in " - FSTP", header, main and footer landmarks, and the prototype state label.
- No `<script>`, no inline event handlers, no banned DOM calls, no em dashes, and only `../tokens.css` as a stylesheet.
- No request leaves `file://`, so no external fonts, scripts or images load.
- The skip link is the first tab stop, becomes visible and moves to `#main-content`.
- The current page carries `aria-current="page"` in the top row.
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
- Organisation: three definition lists, three disabled Edit buttons, two signed agreements, the sub-processor link, three TODO(legal) comments and the SoD-07 note.
- Members: three accounts, two admins, the highlighted self row with SoD-07, the pending Call drafter invitation and the SoD-09 note.
- Branding: three upload slots, one "Fails WCAG 2.2 AA" pair, five mandatory elements present, and Save disabled with its reason. Also the I-68, I-70 and I-72 notes.
- Domains: two verified domains, the pending domain linking to its DNS instructions, three passing email checks, disabled Add domain and Re-check, and the ACME note.

Last run on 2026-11-01: 431 passed, 0 failed.

## Running

From any folder that has `@playwright/test` installed:

```sh
npx playwright install chromium
PW_OUTPUT_DIR=/tmp/pw-results npx playwright test -c design/tests/playwright.config.ts
```

`PW_OUTPUT_DIR` keeps run artefacts out of the design tree. When `@playwright/test` is installed in a folder outside the repository, run from that folder and set `NODE_PATH` to its `node_modules`, so the config can resolve the package.
