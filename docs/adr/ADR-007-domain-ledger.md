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

Status of this section: Accepted 2026-10-28 (Daniel Thompson-Yvetot). The sections above keep their accepted status.

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
- Decided (Daniel, 2026-11-15: "Tenant admin for all"). A tenant admin requests an erasure of every cause: retention expiry (P-41), an erasure request, cell erasure and a completed verification. The requesting tenant admin is the authoriser the entry names. No system or vault path records an erasure.
- When a retention period (P-41) expires, the system only reminds the tenant admins. It erases nothing by itself. Decided by Daniel on 2026-11-15 (late) and built by lane m5/retention: retention starts at the confirmation of the grant's last payment request, the timeline event `RETENTION_END` falls due P-41 years later, and every tenant admin gets the mailbox notice `admin.retention_ended`. It links to `/app/admin/erasures`, where a tenant admin requests the erasure of the grant's texts with its cause, with a step-up (`docs/handoff/m3-exit-audit.md` section 9).
- The operator ticket path for a cell erasure is unchanged.
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

## Built by lane L33 `prod/erasure-log`, 2026-11-22: the erasure log of the production cell

Daniel decided on 2026-11-22: build the production erasure log now, with a row for each display name a person replaces or clears. Written before the code. Every other row is interim, pending Daniel, unless it says otherwise.

Until this lane the production cell served no erasure log. `CellTexts::erasures` and the route backend's `erasures` answered `Unavailable`, so `admin.erasures` and `GET /api/v1/erasures` failed closed, and the System page named no cell erasure.

| Topic | Reading |
| --- | --- |
| Home | The ledger, as section "Erasure-log entries" says: the log is the set of its erasure records, each in the audit chain (I-24). So the log survives a restart, and a restore of the ledger restores it. No new table |
| Ledger texts | Unchanged: `EraseTexts` by a tenant admin appends `ErasureRequested` and `TextsErased`, so a request names its cause and authoriser |
| Keystore texts | A text the keystore keeps that no ledger record names, today a replaced or cleared display name (ADR-004 section "Written by lane L26"), gets its request entry from the new key record `KeystoreErasureRequested { ids, cause, by, kind }`. The erasure runner appends it as the system task `ErasureRunner`, before it requests the erasure in its chain state. It names the text id, the cause 2 (an erasure request), the account that replaced or cleared the name as the authoriser, and the kind 2 (a display name). It holds no name. The fold refuses an id that the ledger names as a text, or that has an entry already |
| Authoriser | The section above says that no system path records an erasure, since a tenant admin requests every cause. A display name change is the person's own act, so the entry names the person, and the runner only writes it for them. Interim, pending Daniel |
| Completion | Step 7 of a batch appends `KeyEpochDestroyed`, then the new key record `ErasuresCompleted { epoch, ids }` for every text whose key the batch destroyed and that has an entry. The fold records the destroyed epoch and the instant on each entry. Both commands have a fixed id per epoch, so a step repeated after a crash appends nothing twice. A batch of more than `MAX_TEXT_IDS` texts appends several records |
| `completed_at` | The section above says that `completed_at` follows the destroy receipt. A display name entry takes it from `ErasuresCompleted`. A ledger text entry keeps the `TextsErased` instant that M3 records in the request's batch, and the log shows the destruction instant once `ErasuresCompleted` names it. The move of `TextsErased` itself after the destruction stays with lane W2c |
| What the log serves | One row per entry: the text id, the kind, the cause, the authoriser, the request instant, the completion instant, and the destroyed root epoch once known. No content, no name and no address |
| `admin.erasures` | `CellTexts::erasures` reads the entries from the engine's state, oldest request first. So `admin.erasures`, the work plan read (`plan_text`) and the System page's key copy check (`last_cell_erasure`) read the log. The no-log fallback of `plan_text` stays for a store that keeps none |
| `GET /api/v1/erasures` | The route backend reads the same entries. A text's programme is not recorded, so each entry is tenant-wide: a tenant admin reads it, and an Auditor does not, as section "Erasure-log entries" reads Q42 for tenant-wide texts |
| Documents | A document's data key has no text id, so a document erasure gets no entry here. `DocumentErased` stays with its own lane |

Tests, written before the code: `r_ky_02_i81_keystore_erasure_is_logged_then_completed_by_its_epoch`, `adr007_ledger_text_gains_its_destroyed_epoch`, `adr007_keystore_erasure_refusals`, `i81_completion_needs_a_destroyed_epoch_and_an_open_entry` and `i24_erasure_log_records_round_trip` (`crates/fstp-cell-core/tests/adr007_erasure_log.rs`); `r_ky_02_i81_erasure_log_names_requests_and_destroyed_epochs` (`crates/fstp-cell/tests/keystore_tables.rs`); `r_ky_02_i81_production_cell_keeps_an_erasure_log` (the production cell over PostgreSQL, `crates/fstp-celltest/tests/adr007_erasure_log_pg.rs`); `adr007_p41_erasures_reply_decodes_strictly` and `adr007_l33_erasure_kinds_have_labels` (`web/test/admin_erasures.test.ts`). The `admin.erasures` reply gains `kind` (`text` or `display_name`) and `destroyed_epoch`.

## Built by lane L37 `prod/erasure-docs-demo-link`, 2026-11-22: document erasures in the erasure log

Daniel approved on 2026-11-22: a document erasure gets its own entry in the erasure log, with its own kind, so `admin.erasures` lists it. Written before the code. Every row is interim, pending Daniel, unless it says otherwise.

Before this lane no production path erased a document. `doc.blob` is append-only, `BlobStore` has no erase call, and the erasure runner only requested texts and display names. The document erasure that ADR-004 part 2 and design section 3.6 describe (`DocumentErasureRequested`, `DocumentErased`) existed in the test world's Vault chain only (R-ID-03, `fstp-celltest`). So this lane builds the erasure itself in the runner, and logs it.

| Topic | Reading |
| --- | --- |
| Entry id | A document's data key id. The blob store draws it at random when it seals the document (ADR-026 record of lane L5), and a text's data key id is its text id, so one 16-byte id space names both. The row above that said a document's key has no text id is replaced by this one |
| Request | The new runner call `erase_document(id, cause, by)` appends `KeystoreErasureRequested { ids: [id], cause, by, kind: 3 }` as the system task `ErasureRunner`, under a fixed command id per document. Kind 3 is a document. It holds no content, no owner and no digest. The fold refuses an id that the ledger names as a text, or that has an entry already, as for a display name |
| Trigger | The ledger record is the durable trigger, as `TextErasureRequested` is for a ledger text. On its next step the runner joins every document entry whose key it holds to the chain state. A crash between the record and the join loses nothing |
| Open | A document opens no more from the moment its request is in the ledger, before the planner runs (I-81, design section 3.4) |
| Completion | Step 7 names the document in `ErasuresCompleted` with the destroyed epoch, as for a text. `completed_at` is that instant |
| Authoriser and cause | The caller names both. The closed list of causes is unchanged |
| Caller | Interim, pending Daniel: no operation calls `erase_document` yet. The runner call and the log are the seam. Which operation should erase a document (an import removal, the end of a retention period, an identity document at verification on the App chain) is an open question. An import is stored after a fresh salt (`salted.rs`), so the same document can be uploaded again after its erasure, as a new blob under a new key. A brand asset is stored without a salt, so after its erasure the same logo cannot be stored again, since one digest holds one row (ADR-026 record of lane L5) |
| Blob row | The sealed `doc.blob` row stays, since the table is append-only. Its key is destroyed with the root epoch, so the row is unrecoverable (I-81). Deleting the row is unchanged: the `keys` role's DELETE grant on erased blob rows stays unused |
| `admin.erasures` | The reply's `kind` gains `document`. `CellTexts::erasures` maps each kind code it knows and fails the read closed on any other |

Tests, written before the code: `r_ky_02_i81_document_erasure_is_logged_then_completed_by_its_epoch`, `adr007_document_erasure_refusals` and `i24_document_erasure_round_trips` (`crates/fstp-cell-core/tests/adr007_document_erasure.rs`); `r_ky_02_i81_production_cell_logs_a_document_erasure` (the production cell over PostgreSQL, `crates/fstp-celltest/tests/adr007_document_erasure_pg.rs`); `adr007_l37_document_kind_has_a_label` (`web/test/admin_erasures.test.ts`).

## Decided by Daniel on 2026-11-23, built by lane L39 `prod/erasure-triggers`: what erases a document, and the sealed row

Daniel answered the open questions 1 to 3 of section "Built by lane L37" on 2026-11-23. Written before the code. His decisions are in the first table. The second table holds the lane's readings, each interim, pending Daniel, unless it says otherwise.

| Decision (Daniel, 2026-11-23) | Text |
| --- | --- |
| 1a. Identity documents | An identity document is erased once identity verification is complete, when the result is recorded |
| 1b. Retention | The runner erases a document automatically when its retention period ends. The periods are the ones the SPEC defines. Where a period is missing, it is recorded as `TODO(legal)` and nothing of that class is erased |
| 1c. Manual | A tenant admin erases a chosen document from a web page, with a stated reason. The operation joins the access registry and the authorisation reference. A plain button and a reason field, with no ceremony that no invariant requires |
| 2. The sealed row | Once the key is destroyed, the encrypted `doc.blob` row is deleted through the `keys` role's DELETE grant. The table stays append-only for every other role. The deletion is safe after a crash: idempotent, and ordered after the key destruction |
| 3. Authoriser | Each trigger records its cause and its authoriser in the erasure log. A system cause names the system. A manual erasure names the tenant admin |
| Brand assets | A logo is stored without a salt, so an erased logo could not be stored again (section "Built by lane L37"). No trigger erases a brand asset |

These decisions replace, for documents only, two rows of section "Erasure-log entries": "No system or vault path records an erasure" and "When a retention period (P-41) expires, the system only reminds the tenant admins". The reminder and the tenant admin's request for a grant's texts are unchanged. They also replace the rows "Caller" and "Blob row" of section "Built by lane L37".

| Topic | Reading |
| --- | --- |
| 1a. What the code holds | No production path stores an identity document. ADR-008 "Manual identity checks" records `VerificationRecorded { account, method, document_type, checks, at, verifier }` and states that no document number or image is stored (R-ID-02). The recorder sees the document outside the platform ("Request, staff record it", ADR-026 record of lane L24). The vault origin serves no `DocumentUpload` write (`web/src/vault/write.ts`: "no fact body exists for it yet"), and no code writes `vault.document`. The legal draft `legal/13-retention-and-erasure.md` says the same: "document upload is not served yet" |
| 1a. What this lane builds | Nothing to erase, so no trigger code. An identity document belongs to the Vault chain (ADR-004, purpose `Document`; ADR-009 "Vault documents"), never to `doc.blob` of the application database (I-83). When a lane builds the vault document upload, the trigger belongs in the vault's `Runner::record_verification`, which runs when staff record the result. That lane erases the account's documents there with the cause `verification_completed` (P-19, R-ID-03). Open question for Daniel |
| 1b. Document classes | A `doc.blob` row names its class by `kind` (migration `0005_doc.sql`, `crates/fstp-cell/src/api/content.rs`). Kinds 1 to 4 are contract documents (`fstp_contract::BlobKind`), kind 5 an import document (R-PG-02), kind 6 a brand asset (ADR-030) |
| 1b. Contract documents, kinds 1 to 4 | The SPEC keeps them for the funder retention period (P-41, `SPEC/02-domain/contracts.md`, `SPEC/05-compliance/horizon-europe-mga.md`), counted per grant from its last confirmed payment (`fstp_domain::retention`). A `doc.blob` row names no grant, and the production cell stores no contract document yet (`SystemTask::ContractPort` is interim). So the sweep erases none. A lane that stores them gives the sweep their grant first |
| 1b. Import documents, kind 5 | The SPEC sets no period for an uploaded funding document. `TODO(legal)`: the retention period of import documents. Until then the sweep erases none |
| 1b. Brand assets, kind 6 | Never erased by a trigger (Daniel, 2026-11-23) |
| 1b. Any other kind | Never erased: the rule table fails closed |
| 1b. The sweep | `fstp_cell::tasks::retention` runs once an hour. It reads `kind`, `dek` and `stored_at` of each `doc.blob` row as the `app` role, asks the closed rule table of each kind, and asks the erasure runner to erase each due document. It names the cause `retention_expiry` and the system authoriser. With today's table it erases nothing. Adding a period is a change of the table alone |
| 1c. The operation | `admin.erase_document`, `POST /admin/documents/{document}/erasure` with the body `{reason}`. `document` is an import document id. The tenant admin acts, as for `admin.request_erasure`. It erases the import document's blob only: a brand asset is refused, and a contract document is no import document |
| 1c. Ceremony | Not high-risk. `SPEC/03-architecture/authentication.md` lists no erasure among the high-risk actions, so I-78 asks no step-up. The usability rule then asks for none. It has no MCP tool, so it is web only. `admin.request_erasure` stays high-risk, as Daniel decided on 2026-11-15 |
| 1c. Reason | Plain text of 1 to 500 characters after trimming, required. The API core stores it as a confidential text of the tenant in the text store, under a key of its own (ADR-007, so it is erasable). The erasure record names its text id. `admin.erasures` resolves it for a tenant admin at read time (I-97). Its length is interim |
| 1c. The page | `/app/admin/erasures` gains a section "Documents". Each import document shows its id, its programme and its media type, with a reason field and an "Erase" button. An erased document shows that it is erased |
| 2. Database rule | Migration `0014_doc_blob_erasure.sql` replaces the UPDATE OR DELETE trigger of `doc.blob`. UPDATE and TRUNCATE stay refused for every role. A DELETE passes only for the cell's own `keys` role (`current_database() || '_keys'`), and only once no `keystore.data_key` row holds the row's data key. Every other role, the owner included, is refused with SQLSTATE 42501 |
| 2. Grant | The role plan (`fstp_control::pg`) gives the `keys` role SELECT and DELETE on `doc.blob`, as on `blob.text`. The `app` role keeps INSERT and SELECT |
| 2. Order and crash safety | The erasure runner deletes the row in the keystore batch written after step 7, once `ErasuresCompleted` names the document with its destroyed epoch. Its data key row left at step 4. A start deletes the row of every completed document entry again, so a crash between the record and the batch loses nothing. A DELETE of a missing row deletes nothing, so a repeat is a no-op |
| 2. What stays | The erasure-log entry stays: it is the ledger's (I-23, I-24). A backup taken before the deletion still holds the sealed row under a destroyed key, so it does not open (I-81) |
| 3. System authoriser | `fstp_cell_core::ERASURE_SYSTEM`, the account id whose bytes are `fstp:st:erasure` and a zero byte. It lies in the system task namespace `SYSTEM_PREFIX`, so no account command uses it. The decider refuses a keystore erasure named by the system unless its cause is `retention_expiry` or `verification_completed` and it carries no reason |
| 3. On the page | Each `admin.erasures` row gains `authoriser`: `system` or `account`. The page never names the account (R-CF-03) |

Tests, written before the code:

- `adr007_l39_system_authoriser_names_only_system_causes`, `adr007_l39_prop_keystore_erasure_authoriser_rule` and `i24_l39_reason_round_trips_and_the_old_form_decodes` (`crates/fstp-cell-core/tests/adr007_erasure_triggers.rs`).
- `adr007_l39_prop_retention_rules_erase_no_brand_and_no_undefined_class` and `adr007_l39_sweep_plans_only_due_rows` (`crates/fstp-cell/tests/adr007_retention_sweep.rs`).
- `i81_l39_blob_row_deleted_after_completion_and_again_at_start` (`crates/fstp-cell/tests/keystore_tables.rs`).
- `i81_l39_doc_blob_delete_only_by_keys_after_key_row_gone` and `i81_l39_keystore_batch_deletes_blob_rows_idempotently` (`crates/fstp-pgstore/tests/adr007_doc_blob_delete.rs`).
- `adr007_l39_admin_erases_an_import_document_with_a_reason` and `adr007_l39_retention_sweep_erases_no_import_document` (the production cell over PostgreSQL, `crates/fstp-celltest/tests/adr007_erasure_triggers_pg.rs`). The L37 test `r_ky_02_i81_production_cell_logs_a_document_erasure` now expects the erased row gone.
- `adr007_l39_documents_and_authoriser_decode` (`web/test/admin_erasures.test.ts`).

Open questions for Daniel, each recorded above as interim:

1. Identity documents: no production path stores one, so 1a erases nothing today. Should the vault document upload be built, with its erasure at `record_verification`?
2. `TODO(legal)`: the retention period of an import document (kind 5).
3. The reason limit of 500 characters, and whether the page should name which tenant admin erased a document.
