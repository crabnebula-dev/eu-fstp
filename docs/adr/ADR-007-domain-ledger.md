# ADR-007: Domain ledger

Status: Accepted by Daniel on 2026-10-25. How P-41 retention and I-81 crypto-shredding coexist with I-23 stays open (O-45).

## Context

Role bindings, conflict declarations, policy versions, scores and decisions are append-only, and corrections are new records (I-23). Every state transition, role binding, policy change and read of proposal content or identity attributes is logged (R-AU-01). The audit log is tamper-evident (I-24).

- The M2 domain core is a pure fold over records. M3 persists those records in the cell's application database (ADR-005).
- Amounts in hashed and signed records are canonical decimal strings, and PostgreSQL stores amounts as `numeric` (ADR-006).
- Reasons, rationale, concerns and plan text are free text. Erasure works by key destruction (R-KY-02, I-81), and retention follows P-41.
- A repeat-grant check spans every programme of the tenant (I-15), so a check can read records of several programmes.

Options considered:

| Option | Description | Outcome |
| --- | --- | --- |
| A | One append-only domain ledger per cell | Chosen |
| B | One ledger per programme | Rejected. Checks across programmes would read several sequences with no common order |

## Decision

Each cell has one append-only domain ledger. Every programme of the tenant writes to it.

- An entry holds a sequence number, a time, a command identifier, a schema version and a record.
- An append is an atomic batch. It succeeds only if the ledger head is still the one the writer expected. A repeated command identifier is refused.
- No operation updates or deletes an entry. The database role that writes the ledger holds INSERT and SELECT only.
- A correction is a new record that names the record it supersedes. Ending a binding is a new record. A policy change is a new policy version.
- Record bodies are stored as canonical text under RFC 8785, not as `jsonb`. The stored bytes are the bytes that are hashed.
- Amounts in canonical record text are ADR-006 strings, for example `"1234.50"`.
- Queryable projections are folds of the ledger. They store amounts in `numeric` columns at the currency's scale, through fstp-pgwire's `Numeric` type. Daniel decided on 2026-10-25 that this split meets ADR-006.
- Free text is kept out of ledger bodies. A body holds a `TextRef`, which is an identifier and a digest of the text. The text itself is stored outside the ledger.
- The ledger holds no identity attributes. A vault answer is recorded as a query digest and the answer bit (`SPEC/03-architecture/overview.md`).
- The ledger sits in the application database, never in the identity vault database (I-83).

## Replay and schema versions

- Replay checks structure only. A correction must target an existing record of the same kind. The fold never re-runs guards on load.
- Each decision records the version of the rules that produced it. A later rule change applies going forward, and old decisions stay valid under their recorded version.
- Every entry carries its schema version. Decoders accept every published version and upcast in memory. Stored bytes are never rewritten.
- Projection checkpoints may speed up startup. Tests compare each checkpoint with a full replay.

## Consequences

- One sequence per cell gives a total order across programmes. Tenant-wide checks such as I-15 read one ordered history.
- The canonical bytes of each entry can feed the I-24 hash chain in M3 directly, with hashes from ADR-001 crates.
- Because free text sits behind `TextRef`, erasure never needs to rewrite a ledger body.
- The tenant export reads ledger records through the file interface in `SPEC/schemas/README.md`. No EUPL-1.2 code is linked into the platform.
- Open: how P-41 retention and I-81 crypto-shredding of referenced text coexist with I-23 (O-45). This includes what a `TextRef` resolves to after its text is erased.
