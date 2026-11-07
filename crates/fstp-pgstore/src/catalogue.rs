//! The tables of the application database `c_<cell>` (design sections
//! 4.2 and 4.5, ADR-007 "Clear column classes", R-NF-08, I-16), next to
//! the migrations in `migrations/app/`.
//!
//! Every table of the migrated database is listed with every column in
//! declaration order: the design tables, `fstp_meta.placement` and the
//! migration ledger `fstp_migrate.schema_migrations`.
//!
//! A column whose class ADR-007 does not settle carries `None`, as lanes
//! W0 and W2d did. Each is reported to Daniel:
//!
//! - chain links and stored-row hashes in `audit.chain`, anchor receipts,
//!   and the keystore's custody handles, destroy receipts and public
//!   keys;
//! - `auth.challenge.action_digest`, a SHA-256 over a command, which is
//!   neither a digest of a random secret nor keyed;
//! - `ops.outbox.idem`, now SHA-256 over the event, the recipient and the
//!   channel (M6 design section 3.1), and the digests `ops.delivery.event`
//!   and `ops.delivery.body_digest`;
//! - the migration ledger's `name` and `checksum`, which describe the
//!   binary's own migrations.
//!
//! The `audit.anchor` link is a `PublicDigest` and its signature a
//! `Signature`, the classes Daniel added to design section 4.5 on
//! 2026-10-30 for the witness columns of the same kind. The receipt
//! column holds a whole encoded receipt, fields and signature together,
//! so no single class covers it.
//!
//! Readings, interim, pending Daniel: `schema` is an `Enum` (a published
//! schema version), and `key_ix` and `generation` are `Sequence` (a
//! generation number).

use fstp_migrate::catalogue::ColumnClass::{
    Count, Enum, KeyedDigest, PublicDigest, RandomId, Sealed, SecretDigest, Sequence, Signature,
    Time,
};
use fstp_migrate::catalogue::{ColumnClass, ColumnSpec, TableClass, TableSpec};

const fn col(name: &'static str, class: ColumnClass) -> ColumnSpec {
    ColumnSpec {
        name,
        class: Some(class),
    }
}

const fn open(name: &'static str) -> ColumnSpec {
    ColumnSpec { name, class: None }
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
            open("name"),
            open("checksum"),
            col("applied_at", Time),
            col("statement_count", Count),
        ],
    ),
    table(
        "ledger",
        "command",
        TableClass::LedgerRecord,
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
            open("stored_hash"),
            col("body", Sealed),
            open("link"),
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
            open("receipt"),
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
            open("handle"),
            col("wrapped_seal_key", Sealed),
            col("state", Enum),
            col("created_at", Time),
            col("destroyed_at", Time),
            open("receipt"),
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
            open("public_key"),
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
            open("action_digest"),
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
            open("idem"),
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
    // and `body_digest` are SHA-256 digests over public inputs and over a
    // rendered body. Neither is keyed nor a digest of a random secret, so
    // their class is left open for Daniel, as `ops.outbox.idem` is.
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
            open("event"),
            col("template_version", Enum),
            open("body_digest"),
            col("reply_code", Enum),
        ],
    ),
];
