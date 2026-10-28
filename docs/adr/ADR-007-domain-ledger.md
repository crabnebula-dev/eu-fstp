# ADR-007: Domain ledger

Status: Accepted by Daniel on 2026-10-25. Retention and erasure were decided on 2026-10-25 (section "Retention and erasure", O-45). Two legal checks are pending.

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
- An append is an atomic batch. It succeeds only if the ledger head is still the one the writer expected. A repeated command identifier is refused. A store checks the command identifier before the head, so a retry after a lost acknowledgement is reported as a duplicate (confirmed 2026-10-25).
- No operation updates or deletes an entry. The database role that writes the ledger holds INSERT and SELECT only.
- A correction is a new record that names the record it supersedes. Ending a binding is a new record. A policy change is a new policy version.
- Record bodies are stored as canonical text under RFC 8785, not as `jsonb`. The stored bytes are the bytes that are hashed.
- Amounts in canonical record text are ADR-006 strings, for example `"1234.50"`.
- Queryable projections are folds of the ledger. They store amounts in `numeric` columns at the currency's scale, through fstp-pgwire's `Numeric` type. Daniel decided on 2026-10-25 that this split meets ADR-006.
- Free text is kept out of ledger bodies. A body holds a `TextRef`, which is an identifier and a digest of the text. The digest is keyed with a random salt stored with the text and destroyed with it, so after erasure the digest cannot confirm a guessed text (decided 2026-10-25). The text itself is stored outside the ledger.
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
- Retention and erasure follow the section below.

## Retention and erasure

Decided by Daniel on 2026-10-25 (O-45).

- Each text has its own data key, so one text can be erased alone (ADR-004 level 3). Erasure destroys that key (R-KY-02, I-81).
- After erasure, a `TextRef` resolves to the text's entry in the erasure log, never to the text. The ledger entry that holds the reference is unchanged (I-23).
- An erasure-log entry holds the text id, the time of erasure, the cause (retention expiry, an erasure request or cell erasure) and the person who authorised it. It is linked into the tamper-evident audit chain (I-24), so an auditor can show that the erasure happened.
- The Auditor role and tenant admins read the erasure log. The person concerned receives a confirmation.
- An erasure request is honoured at once for everything outside the funder retention obligation (P-41). The rest is erased automatically when P-41 ends. TODO(legal): confirm which records the retention obligation covers and that deferring erasure for them is lawful.
- When P-41 ends, the ledger stays as a pseudonymous skeleton: ids, amounts, scores and decisions, with no text and no identity vault data. I-23 and I-24 stay verifiable, and account ids cannot be linked to people once the vault and text keys are destroyed. TODO(legal): confirm whether that skeleton counts as anonymised data.

## Amendment of 2026-10-28: storage at rest in M3

Status of this section: Proposed (drafted 2026-10-28), awaiting Daniel's acceptance. The sections above keep their accepted status.

### Context

- R-NF-08 asks for all data at rest in a cell to be encrypted with cell-specific keys. In shared mode many cells sit on one cluster (ADR-005), so disk encryption is not cell-specific.
- The decision above stores ledger bodies as plaintext canonical text, and projections as `numeric` columns. On a shared cluster, a database superuser, a WAL archive and a cluster backup would then read content in clear (design gap G2).
- The source-of-truth order in `.claude/CLAUDE.md` ranks `SPEC/01-requirements/` above this ADR, so R-NF-08 governs.
- Daniel answered Q5 with option A on 2026-10-28, and accepted the listed clear column classes. The design source is `docs/handoff/m3-design.md`, sections 3.2, 4.2, 4.5, 5.1, 5.3, 5.5, 5.6 and 7.

| Option (Q5) | Description | Outcome |
| --- | --- | --- |
| A | Seal bodies, checkpoints and audit events under cell keys. The chain hashes stored ciphertext. Projections in memory with sealed checkpoints | Chosen by Daniel on 2026-10-28 |
| B | As A, but keep `numeric` projection tables for amounts | Rejected. Amounts would sit in clear on shared clusters |
| C | Keep plaintext bodies and restate R-NF-08 for shared mode | Rejected. It weakens a requirement to fit an ADR |

### Decision

**Sealed bodies.**

- Each entry's canonical RFC 8785 text is sealed with AES-256-GCM under the cell's current ledger data key before it is stored. The `body` column holds the nonce, the ciphertext and the tag.
- The AAD is `"fstp-ledger-v1" || cell || seq || at || command || schema`. A body moved to another cell, sequence number, time, command or schema version fails to open.
- The clear columns `seq`, `at`, `command`, `schema` and `key_ix` stay in clear for indexing. `key_ix` names the ledger key generation.
- The ledger key belongs to the App chain, purpose `Ledger` (ADR-004). ADR-004 part 1 (Seal-count limit) is the single statement of its replacement rule. In short: it is replaced after 2^20 seals, counting bodies, chain event bodies and checkpoints together, and every process start draws a new key generation (`key_ix`).
- The canonical text inside the seal is unchanged. Content hashes that records carry, such as the SoD-07 `grant_digest`, stay hashes over canonical plaintext.

**Random nonces.**

- Every AES-256-GCM seal goes through `fstp_crypto::aead::seal`, which wraps `aws_lc_rs::aead::RandomizedNonceKey`. It draws a fresh 96-bit nonce from the system generator and stores it in the sealed bytes.
- No function in the workspace takes a nonce from its caller. None derives a nonce from a sequence number, row id or counter.
- This covers ledger bodies, chain event bodies, checkpoints, outbox rows, texts, keystore secrets and backup chunks.
- Reason: an append that aborts after sealing leaves its ciphertext in the WAL and in archived WAL. A counter nonce such as `seq` would then be reused by the retry under the same key, which breaks AES-GCM.
- `fstp-keys` counts seals per key and refuses at 2^24. ADR-004 part 1 records the nonce rule and this limit.

**The chain hashes stored bytes.**

- The decision above says "the stored bytes are the bytes that are hashed". That still holds. The stored bytes are now the sealed row, so the audit chain hashes ciphertext.
- The witness and an auditor verify the chain without any content key.
- The consequence above that "the canonical bytes of each entry can feed the I-24 hash chain" is replaced by this rule. ADR-010 fixes the link function and the row byte layout.

**Database link trigger.**

- An insert trigger on `audit.chain` recomputes each link with PostgreSQL's `sha256()` and refuses a mismatch. It is a second, independent implementation of the link function in `fstp-audit`.
- A differential test compares both implementations byte for byte. ADR-010 holds the details.
- Triggers on `ledger.entry`, `audit.chain` and both `auth_log` tables refuse UPDATE, DELETE and TRUNCATE for every role, the table owner included, with SQLSTATE 42501.
- A cluster superuser can still bypass triggers. Such an edit is not prevented, but the chain verifier and the witness detect it (ADR-010).

**Insert-only side effects.**

- The writer role `c_<cell>_writer` keeps INSERT and SELECT only, as decided above. It holds no UPDATE or DELETE right on any table.
- Side effects of an append are inserted in the same transaction as the entries:
  - one `auth_log.stepup_consumed` row per consumed step-up, keyed by the challenge id;
  - one `auth_log.session_end` row per ended session;
  - sealed `ops.outbox` rows for later dispatch.
- A session or a step-up challenge ends only by such an insert. A second consumption of a step-up violates the primary key, and the whole append aborts. The database then refuses a replay even if the fold were wrong (I-78).
- Sessions, challenges, sign counts and tokens are operational rows in the `auth` schema, written by `c_<cell>_app`. They are not ledger records.

**Projections in memory with sealed checkpoints.**

- No plaintext projection table exists. The engine folds the ledger into memory at start.
- Every 10 000 entries the engine writes a sealed checkpoint to `ops.checkpoint`. It uses a random nonce and the ledger key, like `ledger.entry`.
- A test compares every checkpoint with a full replay, as the "Replay and schema versions" section already requires.
- The decision above that projections store amounts in `numeric` columns is withdrawn for M3. Amounts now appear only inside sealed bodies, as ADR-006 strings.
- ADR-006's rule for `numeric` columns stays in force for any amount column a later ADR adds. None exists in M3.

**Cell envelope members.**

- The stored JSON form of a record is an object with exactly one member, as in M2.
- The members `core` and `finding` decode through `fstp_engine::Record` unchanged, so every M2 record keeps its exact bytes.
- The cell adds six members: `auth`, `tenant`, `text`, `key`, `release` and `ops`. Their records are defined in `fstp-cell-core`.
- Accounts, credential public keys, tenant admin grants, login policy, recovery approvals, break-glass approvals and ticket issuance are ledger records, so they are append-only (I-23).
- Decoders accept every published schema version of every member, as decided above.

**Erasure-log entries.**

- The erasure log is the set of `TextErasureRequested` and `TextErased` ledger records. `DocumentErased` and `KeyEpochDestroyed` are ledger records too. Each sits in the audit chain by construction (I-24).
- Each entry holds the text id, the request time, `completed_at`, the cause and the authoriser.
- Causes: retention expiry (P-41), an erasure request, cell erasure, and a completed verification for identity documents (R-ID-03).
- The authoriser is the requesting account for an erasure request, and the tenant admin or the operator ticket for a cell erasure. For a retention expiry it is the system, with a reference to the P-41 rule.
- `completed_at` comes from the `TextErased` or `DocumentErased` record. That record is appended only after the custody backend has returned its destroy receipt for the old root epoch (ADR-004 part 2). Until then the entry shows the request time only.
- A `TextRef` under destruction resolves to its erasure-log entry from the moment the request is recorded, never to the text.
- Interim, pending Daniel (Q42): an Auditor reads only entries for texts of the programme its binding names. Entries for tenant-wide texts, such as login emails, and for cell erasure are for tenant admins only. Tenant admins read every entry.

**Clear column classes.** A column may stay in clear only if it belongs to one of these classes:

| Class | Meaning | Basis |
| --- | --- | --- |
| `RandomId` | A random identifier, such as a `CellId`, record id or session id | Accepted by Daniel on 2026-10-28 (Q5: ids) |
| `Sequence` | A sequence or generation number | Interim, pending Daniel. Q5 listed no sequence class; design section 4.5 adds it |
| `Time` | A timestamp | Accepted by Daniel on 2026-10-28 (Q5: times) |
| `Enum` | A fixed-width closed enumeration | Accepted by Daniel on 2026-10-28 (Q5: enums) |
| `SecretDigest` | A hash of a random secret, such as a session token | Accepted by Daniel on 2026-10-28 (Q5: digests of random tokens) |
| `KeyedDigest` | An HMAC under a cell key that erasure rotates (ADR-004 part 2) | Accepted by Daniel on 2026-10-28 (Q5: keyed lookup digests) |
| `Count` | A count | Interim, pending Daniel. Q5 listed no count class; design section 4.5 adds it |

- Every other column is `Sealed`.
- If Daniel refuses `Sequence` or `Count`, columns of that class are sealed or become keyed digests, and this table is amended first.
- Sealed where no index needs them: the `ops.licence_state` token, the `vault.document` object reference and the `vault.negotiation` accounts.
- Credential ids are stored as keyed digests under the `CredLookup` key.
- The login email is a `TextRef` with a keyed lookup under the `Lookup` key. Interim, pending Daniel (Q22): the address is sealed in the cell and treated as identity-revealing for I-17 canaries.
- Free-text salts sit inside the sealed text, never in a clear column.

**The schema catalogue is the enforced list.**

- `fstp_migrate::catalogue` declares every table with a closed `TableClass` and every column with one of the classes above or `Sealed`.
- `TableClass` is `LedgerRecord`, `AuditEvent`, `SealedContent`, `KeyMaterial`, `Operational`, `Migration` or `Placement`. It has no class for a balance or a held amount (I-16).
- Each migration set exports its own list. A test takes their union and fails on any table or column missing from it, and on any clear column outside the classes above.
- This table of classes is the decision. The catalogue is where it is enforced. Adding a class needs an amendment of this ADR.

### Tests

- `adr007_pg_store_matches_mem_store`: same inputs, same results, same refusal order.
- `adr007_erased_textref_resolves_to_its_log_entry`, `adr007_erasure_log_visible_to_auditor_and_tenant_admin_only`.
- `r_nf_08_catalogue_has_no_clear_content_column`, `r_nf_08_aborted_append_never_reuses_a_nonce`, `r_nf_08_no_api_takes_a_caller_nonce`, `r_nf_08_seal_count_limit_refuses_at_two_to_the_24`, and the teeth test `r_nf_08_teeth_counter_nonce_is_caught`.
- `i78_writer_role_holds_insert_and_select_only`, `i78_database_refuses_a_second_step_up_consumption`.
- `i24_database_refuses_bad_link_and_mutation`, `i24_erasure_entries_are_chained`.
- `i81_completion_recorded_only_after_destroy_receipt`, `i81_text_salt_never_stored_in_clear`.

### Consequences

- A database superuser, the WAL archive and cluster backups see only ciphertext for content (R-NF-08, R-CR-01, TH-58). Random ids, sequence numbers, times, enums and digests stay readable.
- Ad hoc SQL can no longer read content. Operators use typed metrics and the audit view (design risk R15).
- Startup cost grows with the ledger, bounded by the latest checkpoint. The latency budget is measured in W2. Record at first use: the measured replay time from a checkpoint.
- If a later milestone needs a queryable projection table, its columns must fit the classes above or be sealed. A plaintext amount column would need a new amendment.
- The tenant export decrypts bodies inside the cell before it writes the export file (`SPEC/schemas/README.md`).
