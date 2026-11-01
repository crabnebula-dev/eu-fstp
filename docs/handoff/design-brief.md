# Design brief: the journey UI and the experience of every role

For the design agent working alongside the implementing agent, from 2026-11-01. The implementing agent is paused until Wednesday 4 November; the design work below needs no code changes and can run now.

## The product in one paragraph

The FSTP platform runs EU cascade-funding programmes: a funder opens calls, small organisations and individuals apply, expert reviewers and a committee judge them, an independent review committee checks the result, and grantees sign a contract and claim payments per milestone. The reference programme is SuperSAFE. The platform is security-first and multi-tenant, and many users are non-native English speakers who use it rarely. Daniel's concern: the system must be friendly and intuitive for every role, not only correct.

## Read first, in this order

1. `.claude/CLAUDE.md`: the repository rules. They bind design work too.
2. `SPEC/12-journey-ui.md`: the journey UI layer. **This is how the UI and UX are built.** It is the main input to your work.
3. `SPEC/02-domain/state-machine.md` and `SPEC/02-domain/roles-and-sod.md`: the states and roles your designs must show truthfully.
4. `docs/handoff/m4-design.md` sections 2.2 (journeys J0 to J8) and 3.9 (frontend), and the rows of section 15.0 dated 2026-10-31 and 2026-11-01 (home page, profile page, top-row links).
5. `docs/adr/ADR-014-frontend-architecture.md` (the frontend rules) and `docs/adr/ADR-015-journey-ui-projection.md` (the journey layer, a draft for Daniel).
6. `SPEC/01-requirements/non-functional.md`: R-NF-03 accessibility and R-NF-04 localisation.
7. `docs/handoff/m4-demo.md`: how the demo works and what it shows today.

## Hard constraints

- **The spec wins.** Where a design idea conflicts with `SPEC/`, the spec wins. `SPEC/12-journey-ui.md` section 2 lists ideas that were already rejected; do not reintroduce them.
- **Truthful states.** Every metaphor label sits next to the formal state name (I-96). Never invent a state, a transition or a step the state machine lacks (I-95). Separation of duties is real: acceptance and payment release are different people (I-05), activation needs a second approver (I-67), publication needs a non-drafter.
- **No leaks.** Judging roles see conflict answers as yes or no only, never an identity. Before access, staff see counts and pseudonymous ids, not titles. Applicants see scores and comments only after a final decision (O-54). Messages never carry scores or content (I-27).
- **Frontend rules (ADR-014).** No framework, no third-party fonts, scripts or icon sets, no inline script, CSP with Trusted Types. Fonts are self-hosted tenant tokens. Diagrams are server-rendered SVG, never a client library. Public pages work with scripts off.
- **Accessibility.** WCAG 2.2 AA in light and dark themes (I-70): contrast, keyboard paths, visible focus, labels, headings, reduced motion. State is never shown by colour alone.
- **Copy.** Plain language, localisable (every string is a catalogue key), respectful on negative outcomes. No em dashes, sentences under 40 words. Never write legal text; mark it `TODO(legal)`. Amounts are exact decimal strings such as `1234.50`.
- **Data.** Synthetic data only in mockups and examples. No Python anywhere. No new npm package or crate.

## What to design

Work in this order. Each item names the spec sections that govern it.

1. **Information architecture and navigation.** The top row (Home, Account, and every page the person may use without an id), the "Your work" home page per role, and how each role reaches its work in at most three clicks from sign-in. Daniel found the demo unusable because every sign-in landed on the account page with no way into the app (`m4-design.md` 15.0, 2026-10-31).
2. **The voyager route map and Passage Diary** (`12-journey-ui.md` sections 5 to 7): the route visual for all 16 states, the current position, completed and upcoming legs, WITHDRAWN as one "leave the route" control, DEFERRED re-entry, the help panel per node, the text alternative, and the diary entry layouts per kind, including the erased-text placeholder.
3. **Applicant surfaces** (section 8.1): open calls, the plan editor with the packing check, the crew, submission and its receipt (including "anchor pending"), stage 2 questions with the window clock, negotiation, and the end states.
4. **Reviewer, committee and IRC surfaces** (section 8.3): assignments and declarations, scoring, the ranking with cut-off and recusal, the "where is this proposal" strip, and IRC without a strip (O-58).
5. **Programme staff** (sections 8.2 and 8.3): the coordinator's conflict, read and knock-out order; Stage 1 close as "confirm outcome"; the Planning Studio over the 11 creator steps; and the two-person seal ceremony.
6. **The profile page** (`m4-design.md` 15.0, 2026-10-31): one page at `/app/me` with a Profile part (display handle, preferences, verification status, roles held, and a link to the vault origin for name, organisation and affiliations) and a Security part (passkeys, sessions, sign-out, recovery).
7. **The Voyage vocabulary pack** (section 4): the full English catalogue, with a plain pack beside it, and the content rules for negative outcomes.
8. **Design tokens**: colour, type scale, spacing and focus for light and dark themes, each colour pair checked against WCAG 2.2 AA (I-70), as tenant-overridable tokens.

Also walk the running demo as each role, by clicking only, and record what confuses or blocks a first-time user. It runs at `http://127.0.0.1:8981/demo` (people and sign-in links) and `http://a.fstp.localhost:8980` (the cell). A sign-in needs a passkey; a browser with a platform authenticator works. Do not stop or restart that demo.

## Deliverables

- `docs/design/` holds one Markdown spec per item above: purpose, the people it serves, the screens with every state (empty, loading, error, success, read-only), the copy with catalogue keys, the accessibility notes, and the spec IDs it satisfies.
- `design/prototypes/` holds static HTML and CSS mockups, one file per screen, with synthetic data, no script and self-hosted assets only. They never ship and the build never reads them.
- `docs/design/demo-walkthrough.md` records the demo walk: per role, what was tried, what happened, and a fix.
- `docs/design/spec-questions.md` lists every point where the spec is unclear or seems wrong, with a recommendation. Do not change `SPEC/`, `docs/adr/` or code yourself; Daniel decides spec changes.

## Boundaries and git

- Do not edit `crates/`, `web/`, `e2e/`, `tools/`, `SPEC/` or `docs/adr/`. The implementing agent turns approved designs into code, tests first.
- Work on the branch `design/journey-ui` from `main`. Commit with the repository's configured git identity. Never set Claude as author or committer, and add no Co-authored-by or Signed-off-by line. Push the branch; do not push to `main`. Daniel reviews, and the implementing agent merges approved work.
- Keep commits small and named by item, for example "Design the voyager route map (12-journey-ui 5 to 6)".

## Handoff

When an item is ready, add a line to `docs/design/README.md`: the item, its status (draft, ready for Daniel, approved), and its files. The implementing agent starts from items marked approved.
