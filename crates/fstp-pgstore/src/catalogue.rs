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
            // Lane L3, migration `0011_keystore.sql`: the receipt digest.
            col("receipt_digest", PublicDigest),
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
    // Lane L1 (ADR-026): the pending actions of the API core and their
    // confirmations (I-85), and the sealed workspaces (I-21). `op_kind`
    // and `status` are names from closed lists, `key_ix` a generation.
    table(
        "api",
        "pending_actions",
        TableClass::SealedContent,
        &[
            col("id", RandomId),
            col("account", RandomId),
            col("client_id", RandomId),
            col("op_kind", Enum),
            col("key_ix", Sequence),
            col("request", Sealed),
            col("digest", PublicDigest),
            col("created_at", Time),
            col("expires_at", Time),
            col("status", Enum),
            col("closed_at", Time),
        ],
    ),
    table(
        "api",
        "pending_confirmed",
        TableClass::Operational,
        &[col("id", RandomId), col("ledger_seq", Sequence)],
    ),
    table(
        "workspace",
        "drafts",
        TableClass::SealedContent,
        &[
            col("proposal", RandomId),
            col("slot", Enum),
            col("revision", Count),
            // F-017 (migration 15): sealed under the proposal's own
            // workspace key, so no ledger key generation names the row.
            col("sealed", Sealed),
            col("updated_at", Time),
        ],
    ),
    // Lane L25 (ADR-032): the anonymous drafts. The token is a 256-bit
    // random secret, so its hash is a `SecretDigest`.
    table(
        "workspace",
        "anonymous_drafts",
        TableClass::SealedContent,
        &[
            col("token_hash", SecretDigest),
            col("call", RandomId),
            col("key_ix", Sequence),
            col("sealed", Sealed),
            col("started_at", Time),
            col("updated_at", Time),
            col("expires_at", Time),
        ],
    ),
    // Lane L2 (ADR-013 amendment of 2026-11-20): the durable records of
    // the OAuth 2.1 authorisation server. Interim readings, pending
    // Daniel: `metadata_ref` names a sealed text, so it is a `RandomId`
    // like the other text ids; `scopes` is a set of a closed enum and
    // `revoked` a closed flag, so both are `Enum`; `account` is the raw
    // account id, a `RandomId`. Both hash columns are SHA-256 digests of
    // 256-bit random tokens (`SecretDigest`, ADR-013 "Token storage").
    table(
        "mcp",
        "client",
        TableClass::Operational,
        &[
            col("number", Sequence),
            col("client_id", RandomId),
            col("metadata_ref", RandomId),
            col("registered_at", Time),
        ],
    ),
    table(
        "mcp",
        "family",
        TableClass::Operational,
        &[
            col("id", Sequence),
            col("client", Sequence),
            col("account", RandomId),
            col("scopes", Enum),
            col("started_at", Time),
            col("ends_at", Time),
            col("current_hash", SecretDigest),
            col("refreshes", Count),
            col("revoked", Enum),
            col("method", Enum),
            col("version", Sequence),
        ],
    ),
    table(
        "mcp",
        "refresh",
        TableClass::Operational,
        &[col("hash", SecretDigest), col("family", Sequence)],
    ),
    // Lane L3 (ADR-004, decided by Daniel on 2026-11-20), migration
    // `0011_keystore.sql`: the keystore of the App chain in its tables.
    // The chain state, the signer secrets and the texts are sealed. The
    // login digests are HMACs under the `Lookup` key, which erasure
    // replaces (decision 27).
    table(
        "keystore",
        "chain",
        TableClass::KeyMaterial,
        &[
            col("chain", Enum),
            col("epoch", Sequence),
            col("state", Sealed),
            col("lookup_group", RandomId),
            col("login_group", RandomId),
            col("startup_unwrap", RandomId),
        ],
    ),
    table(
        "keystore",
        "text",
        TableClass::SealedContent,
        &[
            col("id", RandomId),
            col("dek", RandomId),
            col("generation", Sequence),
            col("envelope", Sealed),
        ],
    ),
    table(
        "keystore",
        "signer",
        TableClass::KeyMaterial,
        &[
            col("purpose", Enum),
            col("generation", Sequence),
            col("public_key", PublicKeyMaterial),
            col("created_at", Time),
            col("epoch", Sequence),
            col("sealed_secret", Sealed),
        ],
    ),
    table(
        "keystore",
        "login_digest",
        TableClass::KeyMaterial,
        &[col("digest", KeyedDigest), col("account", RandomId)],
    ),
    table(
        "keystore",
        "login_text",
        TableClass::KeyMaterial,
        &[col("account", RandomId), col("text_id", RandomId)],
    ),
    table(
        "keystore",
        "erasure_request",
        TableClass::KeyMaterial,
        &[col("text_id", RandomId)],
    ),
    // Lane L26 (SA-11 amendment, ADR-004), migration
    // `0012_display_name.sql`: the display name index. The name is a
    // sealed text of `keystore.text`. The fingerprint is an HMAC under a
    // key derived from `Lookup`, which erasure replaces.
    table(
        "keystore",
        "display_name",
        TableClass::KeyMaterial,
        &[
            col("account", RandomId),
            col("text_id", RandomId),
            col("fingerprint", KeyedDigest),
        ],
    ),
];

#[cfg(test)]
mod api_tests {
    use super::*;

    fn class(schema: &str, name: &str, column: &str) -> Option<ColumnClass> {
        CATALOGUE
            .iter()
            .find(|t| t.schema == schema && t.name == name)
            .and_then(|t| t.columns.iter().find(|c| c.name == column))
            .and_then(|c| c.class)
    }

    /// R-NF-08, I-21, I-85, ADR-026: every column of the `api` and
    /// `workspace` tables carries a class. The request a pending action
    /// replays and every workspace value are sealed. No other column of
    /// these tables is sealed or holds content: ids, times, enums,
    /// generations and one public digest only.
    #[test]
    fn r_nf_08_api_and_workspace_columns_are_classed() {
        let tables: Vec<&TableSpec> = CATALOGUE
            .iter()
            .filter(|t| matches!(t.schema, "api" | "workspace"))
            .collect();
        let names: Vec<(&str, &str)> = tables.iter().map(|t| (t.schema, t.name)).collect();
        assert_eq!(
            names,
            vec![
                ("api", "pending_actions"),
                ("api", "pending_confirmed"),
                ("workspace", "drafts"),
                ("workspace", "anonymous_drafts"),
            ]
        );
        for t in &tables {
            for c in t.columns {
                assert!(
                    c.class.is_some(),
                    "R-NF-08: {}.{}.{}",
                    t.schema,
                    t.name,
                    c.name
                );
            }
        }
        assert_eq!(class("api", "pending_actions", "request"), Some(Sealed));
        assert_eq!(class("workspace", "drafts", "sealed"), Some(Sealed));
        let sealed: Vec<String> = tables
            .iter()
            .flat_map(|t| {
                t.columns
                    .iter()
                    .filter(|c| c.class == Some(Sealed))
                    .map(move |c| format!("{}.{}", t.name, c.name))
            })
            .collect();
        assert_eq!(
            sealed,
            vec![
                "pending_actions.request",
                "drafts.sealed",
                "anonymous_drafts.sealed"
            ]
        );
        // ADR-032: the token of a resume link rests as its hash only.
        assert_eq!(
            class("workspace", "anonymous_drafts", "token_hash"),
            Some(SecretDigest)
        );
        assert_eq!(
            class("api", "pending_actions", "digest"),
            Some(PublicDigest)
        );
        for (t, c) in [
            ("pending_actions", "id"),
            ("pending_actions", "account"),
            ("pending_actions", "client_id"),
            ("pending_confirmed", "id"),
        ] {
            assert_eq!(class("api", t, c), Some(RandomId), "{t}.{c}");
        }
    }
}

#[cfg(test)]
mod mcp_tests {
    use super::*;

    /// R-NF-08, TH-61, lane L2: every column of the `mcp` schema has a
    /// class, none holds content in clear, and each token column is a
    /// digest of a random secret. The tables are operational, since they
    /// hold no tenant content: client text lives in a sealed text.
    #[test]
    fn r_nf_08_mcp_columns_are_classed() {
        let mcp: Vec<&TableSpec> = CATALOGUE.iter().filter(|t| t.schema == "mcp").collect();
        let names: Vec<&str> = mcp.iter().map(|t| t.name).collect();
        assert_eq!(names, ["client", "family", "refresh"]);
        for t in &mcp {
            assert_eq!(t.class, TableClass::Operational, "mcp.{}", t.name);
            for c in t.columns {
                let class = c
                    .class
                    .unwrap_or_else(|| panic!("R-NF-08: mcp.{}.{} unclassed", t.name, c.name));
                assert!(
                    !matches!(class, ColumnClass::Infrastructure | ColumnClass::Sealed),
                    "mcp.{}.{} holds content",
                    t.name,
                    c.name
                );
            }
        }
        let class = |table: &str, column: &str| {
            mcp.iter()
                .find(|t| t.name == table)
                .and_then(|t| t.columns.iter().find(|c| c.name == column))
                .and_then(|c| c.class)
        };
        assert_eq!(class("family", "current_hash"), Some(SecretDigest));
        assert_eq!(class("refresh", "hash"), Some(SecretDigest));
        assert_eq!(class("client", "client_id"), Some(RandomId));
        assert_eq!(class("client", "metadata_ref"), Some(RandomId));
        assert_eq!(class("family", "account"), Some(RandomId));
    }

    /// R-NF-08, lane L2: the catalogue lists the columns of
    /// `0010_mcp.sql` in declaration order. The database comparison of
    /// `tests/schema.rs` checks the same on a migrated cluster.
    #[test]
    fn r_nf_08_mcp_catalogue_follows_the_migration() {
        let sql = include_str!("../migrations/app/0010_mcp.sql");
        for t in CATALOGUE.iter().filter(|t| t.schema == "mcp") {
            let head = format!("CREATE TABLE mcp.{} (", t.name);
            let body = sql
                .split_once(head.as_str())
                .and_then(|(_, rest)| rest.split_once("\n);"))
                .map(|(b, _)| b)
                .unwrap_or_else(|| panic!("no table mcp.{}", t.name));
            let declared: Vec<&str> = body
                .lines()
                .filter_map(|l| l.split_whitespace().next())
                .filter(|w| *w != "CHECK")
                .collect();
            let listed: Vec<&str> = t.columns.iter().map(|c| c.name).collect();
            assert_eq!(declared, listed, "mcp.{}", t.name);
        }
    }
}
