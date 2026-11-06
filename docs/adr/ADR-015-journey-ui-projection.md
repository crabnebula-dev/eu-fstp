# ADR-015: Journey UI projection

Status: Accepted 2026-11-01 (Daniel Thompson-Yvetot).

`SPEC/12-journey-ui.md` proposed this ADR as ADR-008. ADR-008 to ADR-014 were already used, so it is ADR-015.

## Context

- `SPEC/12-journey-ui.md` gives every actor one way to see where they are in the process: a voyage, with a route map and a Passage Diary kept along the way. Daniel accepted its direction on 2026-11-01 and decided O-54 to O-60.
- The proposal state machine is fixed, model-checked and frozen per call (I-12). The journey layer must not become a second source of truth.
- The application is in-house TypeScript with no framework (ADR-014). Public pages work without scripts (R-PB-04). No third-party dependency is added (ADR-001, ADR-003).
- Free text stays out of ledger bodies behind a `TextRef`, and erasure destroys its key (ADR-007, I-81). Amounts are canonical decimal strings (ADR-006).

## Decision

### Read model only (I-92)

- The journey layer is a projection of the cell's one ledger, its audit log, timeline events and policy versions. It holds no authority and writes no ledger entry.
- Deleting every journey table and replaying the ledger rebuilds byte-identical rows. A projection checkpoint must equal a full replay.
- Next actions it shows are suggestions. Executing one calls the existing command endpoint, which re-checks every guard.
- It adds no cryptography and no key handling. A diary text is erased only by destroying its data key (ADR-004).

### Storage and roles

- Journey tables sit in the cell's application database, in a `journey` schema, never in the vault database (I-83).
- Ids are 16 random bytes and times are microseconds since the epoch, as in every other cell table. Every column carries a class from the closed list of `docs/handoff/m3-design.md` section 4.5.
- No clear content is stored. A diary sentence is built at read time from a catalogue key and the source record, and text references are ids with salted digests (I-97, R-NF-08).
- No new database role. The projector runs under the existing `app` role. `cell_role_plan` grants it SELECT on the ledger and INSERT and SELECT on the journey tables through `apply_grant`, and the I-82 tests cover the new rows.

### Visibility (I-93)

- Each diary entry is filtered per request by one visibility function over the viewer's role, programme and P-10. Nothing is stored once and filtered in the browser.
- The matrix of `SPEC/12-journey-ui.md` section 7.2 is the specification. A property test checks every role and entry kind against it.
- Messages on channels never carry scores (I-27). In the diary, scores and reviewer comments reach the applicant only after a final decision, NOT_SELECTED, DECLINED or GRANTED, under P-11 anonymity (O-54).

### Journey definition and drift test (I-95)

- One JSON definition per profile, versioned and checksummed like migrations, parsed by the in-house JSON codec. Edge ids map one to one to rows of the domain core's transition table.
- The transition table and state enum are exported from the domain core as a reusable crate. The drift test, in Rust, fails the build when a node or edge differs on either side, including the "any non-terminal state before GRANTED to WITHDRAWN" rule.
- The definition parser and the vocabulary pack parser each get a fuzz target in their first commit.

### Vocabulary pack (I-94, I-96, O-55)

- Plain grant language is the platform default vocabulary pack. Voyage is an optional pack a tenant switches on, shown as a secondary line beside the plain label. Both are terminology override sets (`white-labelling.md`, I-72), and tenants can edit labels in either. Amended by Daniel on 2026-11-01 (O-55).
- Pack labels appear in interface labels only, never in contracts, notices, the Guide, funder documents or emails. A template scan enforces this (R-JV-09).
- Every metaphor label is shown with the formal state name beside it in text.

### Rendering

- The route map is server-rendered SVG from the definition and the programme overlay, deterministic for identical inputs, through an in-house renderer that escapes every text. No client diagram library.
- Every node is keyboard operable and names the formal state. A text-only ordered list of the route is always available as the accessible alternative (R-JV-05).
- Public call pages show the route as static SVG with no script (R-JV-06).

#### Amendment (Daniel, 2026-11-06)

- `fstp-html` lays out and renders the map on the server. No client layout code.
- `/p` serves the map as static SVG markup, with no script and no viewer position, under the `/p` CSP.
- `/p` links no stylesheet, so the public map paints itself inside the closed subset. Shapes and edges stroke in `currentColor` with no fill, and texts fill in `currentColor` at a whole `font-size`. A linked token sheet still overrides this paint (review J4-REV-1, I-70).
- In `/app/` the read returns the renderer's checked element tree as data. The server renders the tree through the escaping writer and the well-formedness checker accepts it before it is sent.
- The browser builds that tree with `createElementNS` against the same closed SVG subset, because the `/app/` CSP admits no markup strings. It refuses the whole tree when any part leaves the subset, and then draws nothing.
- The browser's tree reader is an in-house parser of wire data, so it has a fuzz target.

### Rendering home and zones (decided 2026-11-01)

- The route SVG renderer is a module of `fstp-html`, which already holds the escaping writer and the well-formedness checker. Its fuzz targets cover the renderer.
- The deadline zone table ships the IANA zones of every EU and EEA country plus UTC. A new zone is added by a forward-only migration that only appends, so a stored index never changes meaning.

### Decisions recorded (2026-11-01)

| ID | Decision |
| --- | --- |
| O-54 | Applicants see scores and reviewer comments only after a final decision (NOT_SELECTED, DECLINED or GRANTED), anonymous under P-11. INELIGIBLE shows the knock-out reason. WITHDRAWN shows no scores or comments |
| O-55 | Plain grant language is the platform default pack; Voyage is optional per tenant (amended 2026-11-01) |
| O-56 | Submission receipts carry the audit-log anchor beside the ledger sequence and time. Until the anchor is witnessed, the receipt says "anchor pending" |
| O-57 | Coordinators may see aggregate per-state counts before conflict declaration, with no titles or applicant data |
| O-58 | IRC members get no route strip |
| O-59 | Chronicle PDFs are a self-service export by the grantee or auditor, not a funder report |
| O-60 | Guardian consent steps appear only to the guardian |

## Consequences

- M4 starts the journey work with the transition-table crate and the drift test, then the projector and visibility function with property tests, then the renderer, the voyager surface and the Planning Studio (`SPEC/12-journey-ui.md` sections 14 and 16).
- The execution-phase view, payment-request track and chronicle PDF follow in M5, the deadlines bar in M6.
- Production receipts cannot show an anchor until ML-DSA-65 lands in moduletto (ADR-010).

## Open points

- TODO(legal): whether the pseudonymous skeleton after P-41 counts as anonymised data (`SPEC/12-journey-ui.md` section 7.3).
