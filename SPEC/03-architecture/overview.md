# Architecture overview

## Cells

Each tenant runs in an isolated cell. A cell contains:

- application services in Rust,
- a PostgreSQL database and an object store,
- an append-only domain ledger in that database (ADR-007),
- an identity vault as a separate service with separate keys,
- an assessor worker for LLM findings,
- a timeline engine and notification dispatcher (`notifications.md`),
- messaging channel adapters (`messaging.md`),
- an append-only, hash-chained audit log.

The SaaS is many cells behind a shared control plane. A self-hosted install is one cell with no control plane dependency.

NOTE 1: This gives tenant isolation, export as a complete cell dump, and a direct switching path to self-hosting.

NOTE 2: Whether SaaS cells share a PostgreSQL cluster with one database each, or run a cluster each, is ADR-required. The vault uses its own database in both cases.

## Control plane

The control plane provisions cells, routes requests, hosts the template library and handles billing. It holds no tenant content and no identity attributes, apart from templates tenants chose to publish (I-73). Platform operator staff have no content access (SoD-08).

NOTE: Self-hosted cells call two CrabNebula-hosted services, described in `self-hosted-services.md`.

## Identity vault

The vault holds verified identity attributes, verification records, guardian consent, declared affiliations, bank details, messaging handles and hardship evidence. It answers the application only through the queries below. Every answer is one bit, except the change query.

| Query | Serves |
| --- | --- |
| Is this account verified? | SoD-09, I-06 |
| Does this account share a verified identity with any account in a given set? | SoD-09, I-06, I-15 |
| Does this reviewer have a conflict with this proposal's applicant team? | I-03, I-54 |
| Is this account in an excluded affiliation class of this programme? | I-04 |
| Would this amount keep the recipient within the cap? | I-14 |
| Do all recipients of the programme stay within the cap? | I-14, on P-05 edits |
| Does this proposal have a verified guardian consent record? | I-18 |
| Does any team member declare an affiliation on this proximity list? | I-35 |
| Does this applicant meet the P-17 country condition of this programme? | R-EV-08, P-17 |
| Which accounts have vault facts that changed since a given vault epoch? | Reaction to vault changes |

The change query returns account identifiers and no attributes. The query set was decided on 2026-10-25.

NOTE 1: The application builds each candidate set from its own bindings: active bindings, and bindings inside a cooling-off bar (`02-domain/roles-and-sod.md` Cooling-off). For the cap queries it sends per-account totals of granted and reserved amounts, and the vault groups them by verified identity.

NOTE 2: Fail closed (decided 2026-10-25). When the vault cannot answer, the application refuses the command that needed the answer and records nothing.

NOTE 3: Every answer carries a vault epoch. The application accepts answers only at the epoch it has processed. When the vault reports a newer epoch, the application processes the change first and asks again.

NOTE 4: Verification commit protocol (decided 2026-10-25). The vault marks a new verification or affiliation as provisional. The application reacts in one step and records the reaction with that epoch. The vault then makes the fact effective. Queries count only effective facts, so I-04 and I-06 hold at every instant. The exception is the reaction itself: its queries see the provisional fact it reacts to. Until the fact is effective, the vault refuses every other query about the accounts it affects, so the application fails closed and refuses those commands. Once the reaction is recorded, the application acknowledges it, and the vault makes the fact effective (decided 2026-10-25).

NOTE 5: What the platform learns (decided 2026-10-25). A positive answer over a one-member set tells the platform that two accounts share a verified identity. The repeat-grant check (I-15) and the SoD-09 check at negotiation can both use one-member sets. The link is evident anyway, because the platform must void or refuse in response.

- Refusals name only the rule, never an account.
- Each vault answer is recorded as a query digest and the answer bit, with no identity attributes.
- Only the Auditor role can see recorded positive matches. Judging roles never see them (R-CF-03).
- Such links are between accounts of one tenant. I-20 concerns accounts in different tenants and is unaffected.

NOTE 6: The P-17 query answers one bit and releases no country to Judging roles (decided 2026-10-25). How the vault holds the country before NEGOTIATION, given R-NG-01 and I-17, is open (O-48). TODO(Daniel): decide the source and confirm that the derived bit is consistent with I-17.

Identity attributes are released to Operations roles only in NEGOTIATION and later. Phone numbers and messaging handles are released only to the channel adapters.

## Assessor

The assessor runs as a separate process with these constraints:

- no write access to domain state,
- network egress only to the configured inference endpoint and a retrieval proxy,
- output through a schema-validated queue,
- PII stripped from input before inference.

Retrieved content is untrusted, like submission content.

## Contracts and payment requests

See `02-domain/contracts.md` and `02-domain/payment-requests.md`. Contract PDFs are rendered in-house from templates and agreed plan versions.

## Payments

A payment adapter interface has two implementations:

- Record-only: exports approved payments for the tenant's finance system.
- Execution: generates SEPA payment instructions against the tenant's own bank account, as a file or through the tenant's bank API credentials.

The platform never holds or controls funds (I-16).

## Profile bundle

The user exports selected profile fields as an integrity-protected bundle and imports it elsewhere. The receiving tenant treats fields as self-declared (R-PS-03). No server-side record links the two accounts (I-20).

## Inference

The tenant configures an inference endpoint. Self-hosted cells can point at a local endpoint serving open-weight models. The inference client is written in-house against the endpoint's HTTP API.

## Build approach

Components are written in-house per the dependency policy in `../.claude/CLAUDE.md`. In-house components with significant scope:

| Component | Notes |
| --- | --- |
| HTTP server and client | Fuzzed request parsing |
| JSON and NDJSON | Shared by API, export and adapters |
| PostgreSQL wire protocol client | Extended query protocol only; no string-built SQL |
| Migration runner | Forward-only, checksummed |
| Scheduler and outbox worker | See `notifications.md` |
| SMTP submission client with DKIM signing | Signing through ADR-001 crates |
| PDF writer for contracts | Deterministic output for hashing |
| PDF and document text extraction | Sandboxed, fuzzed |
| Property-testing harness | Shrinking required for useful failures |
| State machine model checker | Bounded exhaustive exploration |
| Frontend in TypeScript | No framework; component model, routing and state written in-house |
| Export and import executable | Separate program under EUPL-1.2, invoked by the cell (`schemas/README.md`) |
| Qualified signature validation | In-house procedure on allowlisted parsers (ADR-001) |
| Matrix client-server adapter | E2EE through ADR-001 crates |
| WhatsApp Business Platform adapter | Subject to O-21 |

NOTE: In-house code reduces supply chain exposure and increases the attack surface you own. Hardening activity H-05 covers every in-house parser.

## Related decisions

- Authentication: `authentication.md`.
- Key hierarchy and custody: ADR-004.
- Hosting provider and database layout: ADR-005.
- Money representation: ADR-006.
- Domain ledger and record storage: ADR-007.
