# Architecture overview

## Cells

Each tenant runs in an isolated cell. A cell contains:

- application services in Rust,
- a PostgreSQL database and an object store,
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

The vault holds verified identity attributes, verification records, guardian consent, declared affiliations, bank details, messaging handles and hardship evidence. It exposes only boolean queries to the application:

- Does this applicant's verified identity match any Drafting or Judging binding in this programme? (SoD-09)
- Does this reviewer have a conflict with this proposal's applicant team? (I-03)
- Would this amount exceed the recipient cap? (I-14)
- Is this applicant in an excluded affiliation class? (I-04)

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

Components are written in-house per the dependency policy in `CLAUDE.md`. In-house components with significant scope:

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
