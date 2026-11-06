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

The vault holds verified identity attributes, verification records, over-18 attestations, guardian consent, declared affiliations, bank details, messaging handles and hardship evidence. It answers the application only through the queries below. Every answer is one bit, except the change query. Its other operations are listed under Operations other than queries.

| Query | Serves |
| --- | --- |
| Is this account verified? | SoD-09, I-06 |
| Does this account share a verified identity with any account in a given set? | SoD-09, I-06, I-15 |
| Does this reviewer have a conflict with this proposal's applicant team? | I-03, I-54 |
| Is this account in an excluded affiliation class of this programme? | I-04 |
| Would this amount keep the recipient within the cap? | I-14 |
| Do all recipients of the programme stay within the cap? | I-14, on P-05 edits |
| Does this proposal have a verified guardian consent record? | I-18 |
| Does this proposal's lead have an effective verified over-18 attestation at the call deadline? | I-18, R-ID-04 |
| Does any team member declare an affiliation on this proximity list? | I-35 |
| Does this applicant meet the P-17 country condition of this programme? | R-EV-08, P-17 |
| Which accounts have vault facts that changed since a given vault epoch? | Reaction to vault changes |

The change query returns account identifiers and no attributes. After a provisional verification, it also lists every other account that the facts revealed by that verification touch (confirmed 2026-10-25). The query set was decided on 2026-10-25. The over-18 attestation query was added to it (decided 2026-10-28, NOTE 7).

NOTE 1: The application builds each candidate set from its own bindings: active bindings, and bindings inside a cooling-off bar (`02-domain/roles-and-sod.md` Cooling-off). For the cap queries it sends per-account totals of granted and reserved amounts, and the vault groups them by verified identity.

NOTE 2: Fail closed (decided 2026-10-25). When the vault cannot answer, the application refuses the command that needed the answer and records nothing.

NOTE 3: Every answer carries a vault epoch. The application accepts answers only at the epoch it has processed. When the vault reports a newer epoch, the application processes the change first and asks again.

NOTE 4: Verification commit protocol (decided 2026-10-25). The vault marks a new verification or affiliation as provisional. The application reacts in one step and records the reaction with that epoch. The vault then makes the fact effective. Queries count only effective facts, so I-04 and I-06 hold at every instant. The exception is the reaction itself: its queries see the provisional fact it reacts to. Until the fact is effective, the vault refuses every other query about the accounts it affects, so the application fails closed and refuses those commands. Once the reaction is recorded, the application acknowledges it, and the vault makes the fact effective (decided 2026-10-25).

NOTE 5: What the platform learns (decided 2026-10-25). A positive answer over a one-member set tells the platform that two accounts share a verified identity. The repeat-grant check (I-15) and the SoD-09 check at negotiation can both use one-member sets. The link is evident anyway, because the platform must void or refuse in response.

- Refusals name only the rule, never an account.
- Each vault answer is recorded as a query digest and the answer bit, with no identity attributes.
- Only the Auditor role can see recorded positive matches. Judging roles never see them (R-CF-03).
- Such links are between accounts of one tenant. I-20 concerns accounts in different tenants and is unaffected.

NOTE 6: The P-17 query answers one bit and releases no country to Judging roles (decided 2026-10-25). The applicant states the country at submission, and only the vault receives it. It is verified in NEGOTIATION, and a false statement is grounds to decline (decided 2026-10-25, O-48). TODO(legal): confirm the early collection under GDPR.

NOTE 7: The over-18 attestation query (decided 2026-10-28), named `IsVerifiedAdultAtDeadline` in code. It answers yes only for an effective verified attestation that shows the lead was 18 or older at the call deadline (`01-requirements/functional.md` R-ID-04). It answers no in every other case. It releases no age and no date of birth. The guard into NEGOTIATION asks it (`02-domain/state-machine.md` NOTE 14), and Judging roles never see its answer. Interim, pending Daniel: whether the guard into GRANTED asks it too, and how a later verification showing the lead under 18 affects the answer, are not decided (ADR-008, Minor flag details). The attestation becomes effective under the commit protocol of NOTE 4. TODO(legal): L-02, the legal basis for the attestation before NEGOTIATION, and whether Article 8 GDPR applies to it.

NOTE 8: Two creator queries join the query set (decided 2026-11-06, M4 Q35 A), named `classes_defined` and `proximity_lists_declared` in code. "Does the vault define every P-13 exclusion class of this programme?" serves I-04: on a no, the creator's `ExclusionClassUnknown` check fails. "Has every partner organisation in P-38 of this programme declared its proximity list?" serves I-35: on a no, the `ProximityListMissing` warning stands until acknowledged. Each answers one bit and names no account. The creator asks both for a validation report and again at the activation approval. A vault that cannot answer leaves both rows standing as not checked (NOTE 2). Each answer is recorded as NOTE 5 says. The table above lists the queries of the domain core. Adding these two rows waits for the query enum of the domain core and the vault protocol, which the table test reads.

Identity attributes are released to Operations roles only in NEGOTIATION and later. Phone numbers and messaging handles are released only to the channel adapters.

### Operations other than queries

The queries are the vault's only answers to the application (decided 2026-10-28). The vault also takes four kinds of operation, and none of them returns an identity attribute to the application:

- **Writes** add a fact of a kind the vault holds. A person writes attributes, the P-17 country, affiliations, attestations, guardian consents and identity documents on the vault origin. The application writes only facts that carry no identity attributes, such as an I-54 relationship between two account ids.
- **Releases** show identity attributes on the vault origin to an Operations role holder, only for a proposal in NEGOTIATION or later. Handles go only to the channel adapters.
- **Acknowledgements** report that the application has recorded its reaction to a provisional fact. The vault then makes the fact effective (NOTE 4).
- **Negotiation facts** tell the vault that a proposal has entered NEGOTIATION. The vault refuses a release for a subject that no negotiation fact lists.

From writes, the application learns only the resulting epoch change, through the change query.

The vault origin is a web origin of the vault, separate from the application's origin and inside the cell (decided 2026-10-28, ADR-009). The browser sends attributes, the P-17 country and identity documents to it directly, and released attributes are shown there. So the application never receives them (I-17, NOTE 6). Each write or release by a person needs a signed, single-use ticket that the application issues. Issuing a ticket is recorded, so every read of identity attributes is logged (R-AU-01). The vault origin keeps no sessions.

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
| WhatsApp Business Platform adapter | Deferred by Daniel on 2026-11-04 (B-03) |

NOTE: In-house code reduces supply chain exposure and increases the attack surface you own. Hardening activity H-05 covers every in-house parser.

## Related decisions

- Authentication: `authentication.md`.
- Key hierarchy and custody: ADR-004.
- Hosting provider and database layout: ADR-005.
- Money representation: ADR-006.
- Domain ledger and record storage: ADR-007.
