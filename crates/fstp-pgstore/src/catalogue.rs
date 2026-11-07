//! The tables of the application database `c_<cell>` (design sections
//! 4.2 and 4.5, ADR-007 "Clear column classes", R-NF-08, I-16), next to
//! the migrations in `migrations/app/`.
//!
//! Every table of the migrated database is listed with every column in
//! declaration order: the design tables, `fstp_meta.placement` and the
//! migration ledger `fstp_migrate.schema_migrations`.
//!
//! Every column carries a class. Daniel's Q-A answer of 2026-11-07
//! (m4-design section 15.0) settles the columns ADR-007 left open:
//!
//! - chain links, stored-row hashes, `auth.challenge.action_digest`, the
//!   digest `ops.delivery.event`, and the migration ledger's `checksum`
//!   are `PublicDigest`;
//! - `ops.delivery.body_digest` is an HMAC-SHA256 under a cell key, so it
//!   is a `KeyedDigest` (Daniel, 2026-11-07, section 15.0);
//! - both `receipt` columns are `Signature`, and
//!   `keystore.group_key.public_key` is `PublicKeyMaterial`;
//! - `keystore.root.handle` and `ops.outbox.idem` are `OpaqueReference`.
//!
//! Migrations 7 and 8 add the length checks of those classes.
//!
//! Readings, interim, pending Daniel: `schema` is an `Enum` (a published
//! schema version), `key_ix` and `generation` are `Sequence` (a
//! generation number), and the migration ledger's `name` is an `Enum` (a
//! name from the binary's own migration list).

use fstp_migrate::catalogue::ColumnClass::{
    Count, Enum, KeyedDigest, OpaqueReference, PublicDigest, PublicKeyMaterial, RandomId, Sealed,
    SecretDigest, Sequence, Signature, Time,
};
use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

const fn col(name: &'static str, class: ColumnClass) -> ColumnSpec {
    ColumnSpec {
        name,
        class: Some(class),
    }
}

const fn table(
    schema: &'static str,
    name: &'static str,
    class: TableClass,
    columns: &'static [ColumnSpec],
) -> TableSpec {
    TableSpec {
        schema,
        name,
        class,
        columns,
    }
}

/// The tables of the application database (`c_<cell>`).
pub const CATALOGUE: &[TableSpec] = &[
    table(
        "fstp_meta",
        "placement",
        TableClass::Placement,
        &[
            col("cell_id", RandomId),
            col("cluster_id", RandomId),
            col("kind", Enum),
        ],
    ),
    table(
        "fstp_migrate",
        "schema_migrations",
        TableClass::Migration,
        &[
            col("version", Sequence),
            col("name", Enum),
            col("checksum", PublicDigest),
            col("applied_at", Time),
            col("statement_count", Count),
        ],
    ),
    // `ledger.command` holds command envelopes, not submission text, so
    // it is operational (Daniel, 2026-11-07, m4-design section 15.0).
    table(
        "ledger",
        "command",
        TableClass::Operational,
        &[
            col("command", RandomId),
            col("first_seq", Sequence),
            col("last_seq", Sequence),
            col("at", Time),
        ],
    ),
    table(
        "ledger",
        "entry",
        TableClass::LedgerRecord,
        &[
            col("seq", Sequence),
            col("at", Time),
            col("command", RandomId),
            col("schema", Enum),
            col("key_ix", Sequence),
            col("body", Sealed),
        ],
    ),
    table(
        "audit",
        "chain",
        TableClass::AuditEvent,
        &[
            col("n", Sequence),
            col("at", Time),
            col("kind", Enum),
            col("ledger_seq", Sequence),
            col("stored_hash", PublicDigest),
            col("body", Sealed),
            col("link", PublicDigest),
        ],
    ),
    table(
        "audit",
        "anchor",
        TableClass::AuditEvent,
        &[
            col("n", Sequence),
            col("link", PublicDigest),
            col("at", Time),
            col("signature", Signature),
            col("witness_seq", Sequence),
            col("receipt", Signature),
        ],
    ),
    table(
        "blob",
        "text",
        TableClass::SealedContent,
        &[
            col("id", RandomId),
            col("dek", RandomId),
            col("envelope", Sealed),
        ],
    ),
    table(
        "keystore",
        "root",
        TableClass::KeyMaterial,
        &[
            col("chain", Enum),
            col("epoch", Sequence),
            col("backend", Enum),
            col("handle", OpaqueReference),
            col("wrapped_seal_key", Sealed),
            col("state", Enum),
            col("created_at", Time),
            col("destroyed_at", Time),
            col("receipt", Signature),
        ],
    ),
    table(
        "keystore",
        "group_key",
        TableClass::KeyMaterial,
        &[
            col("chain", Enum),
            col("purpose", Enum),
            col("group_id", RandomId),
            col("generation", Sequence),
            col("public_key", PublicKeyMaterial),
            col("sealed_secret", Sealed),
            col("epoch", Sequence),
            col("state", Enum),
        ],
    ),
    table(
        "keystore",
        "data_key",
        TableClass::KeyMaterial,
        &[
            col("id", RandomId),
            col("group_id", RandomId),
            col("generation", Sequence),
            col("sealed", Sealed),
            col("state", Enum),
        ],
    ),
    table(
        "keystore",
        "erasure_intent",
        TableClass::KeyMaterial,
        &[
            col("id", RandomId),
            col("chain", Enum),
            col("plan", Sealed),
            col("phase", Enum),
        ],
    ),
    table(
        "auth",
        "session",
        TableClass::Operational,
        &[
            col("token_hash", SecretDigest),
            col("session_id", RandomId),
            col("account_id", RandomId),
            col("method", Enum),
            col("created_at", Time),
            col("last_seen_at", Time),
            col("idle_expiry", Time),
            col("absolute_expiry", Time),
        ],
    ),
    table(
        "auth",
        "challenge",
        TableClass::Operational,
        &[
            col("id", RandomId),
            col("session_id", RandomId),
            col("purpose", Enum),
            col("action_digest", PublicDigest),
            col("challenge", RandomId),
            col("issued_at", Time),
        ],
    ),
    table(
        "auth",
        "sign_count",
        TableClass::Operational,
        &[
            col("credential_key", KeyedDigest),
            col("sign_count", Count),
            col("last_used_at", Time),
        ],
    ),
    table(
        "auth",
        "token",
        TableClass::Operational,
        &[
            col("token_hash", SecretDigest),
            col("kind", Enum),
            col("account_id", RandomId),
            col("expires_at", Time),
            col("consumed_at", Time),
        ],
    ),
    table(
        "auth_log",
        "stepup_consumed",
        TableClass::Operational,
        &[col("challenge_id", RandomId), col("ledger_seq", Sequence)],
    ),
    table(
        "auth_log",
        "session_end",
        TableClass::Operational,
        &[
            col("session_id", RandomId),
            col("at", Time),
            col("cause", Enum),
            col("ledger_seq", Sequence),
        ],
    ),
    table(
        "ops",
        "outbox",
        TableClass::Operational,
        &[
            col("id", RandomId),
            col("kind", Enum),
            col("idem", OpaqueReference),
            col("dek", RandomId),
            col("body", Sealed),
            col("created_at", Time),
        ],
    ),
    table(
        "ops",
        "checkpoint",
        TableClass::Operational,
        &[
            col("seq", Sequence),
            col("key_ix", Sequence),
            col("body", Sealed),
        ],
    ),
    table(
        "ops",
        "licence_state",
        TableClass::Operational,
        &[
            col("id", Enum),
            col("sealed_token", Sealed),
            col("last_refresh_ok", Time),
            col("last_refresh_attempt", Time),
        ],
    ),
    // ADR-015, `SPEC/12-journey-ui.md` section 11: the journey read model.
    // Every column is an id, a code, a sequence number, a count, a time or
    // a salted digest, so no table holds clear content (I-97).
    table(
        "journey",
        "entry",
        TableClass::Operational,
        &[
            col("entry_id", RandomId),
            col("source_seq", Sequence),
            col("subject_kind", Enum),
            col("subject_id", RandomId),
            col("kind", Enum),
            col("occurred_at", Time),
            col("deadline_zone", Enum),
            col("scope_mask", Enum),
            col("summary_key", Enum),
            col("supersedes", RandomId),
        ],
    ),
    table(
        "journey",
        "entry_text",
        TableClass::Operational,
        &[
            col("entry_id", RandomId),
            col("ord", Count),
            col("text_id", RandomId),
            col("digest", KeyedDigest),
        ],
    ),
    table(
        "journey",
        "projection_cursor",
        TableClass::Operational,
        &[col("projector", Enum), col("last_ledger_seq", Sequence)],
    ),
    table(
        "journey",
        "leg",
        TableClass::Operational,
        &[
            col("proposal_id", RandomId),
            col("ord", Count),
            col("from_state", Enum),
            col("to_state", Enum),
            col("at", Time),
            col("source_seq", Sequence),
        ],
    ),
    table(
        "journey",
        "route_start",
        TableClass::Operational,
        &[
            col("proposal_id", RandomId),
            col("call_id", RandomId),
            col("at", Time),
            col("source_seq", Sequence),
        ],
    ),
    table(
        "journey",
        "assignment",
        TableClass::Operational,
        &[
            col("assignment_id", RandomId),
            col("proposal_id", RandomId),
            col("source_seq", Sequence),
        ],
    ),
    // M5 design section 4.3, I-30: write-once documents, sealed content
    // keyed by the public SHA-256 the ledger records.
    table(
        "doc",
        "blob",
        TableClass::SealedContent,
        &[
            col("digest", PublicDigest),
            col("kind", Enum),
            col("dek", RandomId),
            col("envelope", Sealed),
            col("stored_at", Time),
        ],
    ),
    // M6 design section 3.2: the delivery log of the dispatcher. `event`
    // is a SHA-256 digest over public inputs, so it takes the digest class
    // (Q-A). `body_digest` is an HMAC-SHA256 of the rendered body under a
    // cell key (Daniel, 2026-11-07, m4-design section 15.0).
    table(
        "ops",
        "delivery",
        TableClass::Operational,
        &[
            col("outbox_id", RandomId),
            col("attempt", Count),
            col("phase", Enum),
            col("at", Time),
            col("worker", RandomId),
            col("lease_until", Time),
            col("event", PublicDigest),
            col("template_version", Enum),
            col("body_digest", KeyedDigest),
            col("reply_code", Enum),
        ],
    ),
];
