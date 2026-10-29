//! The tables of the vault database `v_<cell>` (design sections 4.3 and
//! 4.5, R-NF-08), next to the vault migrations in `migrations/vault/`.
//!
//! The `vault` schema holds the eight tables of design section 4.3 with
//! exactly its columns, plus `vault.p17_condition`, which section 4.3 does
//! not have yet (reported to Daniel). `vault_audit` holds the vault's own chain and
//! anchors (I-24), and `keystore` the vault chain's keys, with the shapes
//! of section 4.2.
//!
//! Readings, reported to Daniel:
//!
//! - A column whose class section 4.5 has not settled carries `None`, as
//!   lane W0 did for `witness.anchor`: chain links, stored-row digests,
//!   signatures, receipts, custody handles and public keys.
//! - `vault_audit.chain` has no ledger, so its `epoch` column takes the
//!   place of `ledger_seq` in `audit.chain`: a kind 1 row records a vault
//!   epoch, a kind 2 row an event such as a ticket use.

use fstp_migrate::catalogue::ColumnClass::{Enum, KeyedDigest, RandomId, Sealed, Sequence, Time};
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

/// The tables of the vault database (`v_<cell>`).
pub const CATALOGUE: &[TableSpec] = &[
    TableSpec {
        schema: "vault",
        name: "epoch",
        class: TableClass::Operational,
        columns: &[
            col("epoch", Sequence),
            col("state", Enum),
            col("created_at", Time),
            col("affected", Sealed),
            col("ack_seq", Sequence),
            open("ack_link"),
            col("acked_at", Time),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "fact",
        class: TableClass::SealedContent,
        columns: &[
            col("fact_id", RandomId),
            col("epoch", Sequence),
            col("kind", Enum),
            col("subject", RandomId),
            col("dek", RandomId),
            col("body", Sealed),
            col("ended_epoch", Sequence),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "identity",
        class: TableClass::Operational,
        columns: &[col("identity_id", RandomId), col("match_key", KeyedDigest)],
    },
    TableSpec {
        schema: "vault",
        name: "account",
        class: TableClass::Operational,
        columns: &[
            col("account_id", RandomId),
            col("identity_id", RandomId),
            col("verified_epoch", Sequence),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "document",
        class: TableClass::SealedContent,
        columns: &[
            col("doc_id", RandomId),
            col("account_id", RandomId),
            col("dek", RandomId),
            col("sealed_object_ref", Sealed),
            col("uploaded_at", Time),
            col("erased_epoch", Sequence),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "negotiation",
        class: TableClass::Operational,
        columns: &[
            col("proposal_id", RandomId),
            col("sealed_accounts", Sealed),
            col("opened_seq", Sequence),
            col("closed_seq", Sequence),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "ticket_used",
        class: TableClass::Operational,
        columns: &[col("ticket_id", RandomId), col("used_at", Time)],
    },
    TableSpec {
        schema: "vault",
        name: "query_log",
        class: TableClass::Operational,
        columns: &[
            col("n", Sequence),
            col("at", Time),
            col("query_digest", KeyedDigest),
            col("holds", Enum),
            col("epoch", Sequence),
        ],
    },
    TableSpec {
        schema: "vault",
        name: "p17_condition",
        class: TableClass::Operational,
        columns: &[col("programme_id", RandomId), col("countries", Enum)],
    },
    TableSpec {
        schema: "vault_audit",
        name: "chain",
        class: TableClass::AuditEvent,
        columns: &[
            col("n", Sequence),
            col("at", Time),
            col("kind", Enum),
            col("epoch", Sequence),
            open("stored_hash"),
            col("body", Sealed),
            open("link"),
        ],
    },
    TableSpec {
        schema: "vault_audit",
        name: "anchor",
        class: TableClass::AuditEvent,
        columns: &[
            col("n", Sequence),
            open("link"),
            col("at", Time),
            open("signature"),
            col("witness_seq", Sequence),
            open("receipt"),
        ],
    },
    TableSpec {
        schema: "keystore",
        name: "root",
        class: TableClass::KeyMaterial,
        columns: &[
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
    },
    TableSpec {
        schema: "keystore",
        name: "group_key",
        class: TableClass::KeyMaterial,
        columns: &[
            col("chain", Enum),
            col("purpose", Enum),
            col("group_id", RandomId),
            col("generation", Sequence),
            open("public_key"),
            col("sealed_secret", Sealed),
            col("epoch", Sequence),
            col("state", Enum),
        ],
    },
    TableSpec {
        schema: "keystore",
        name: "data_key",
        class: TableClass::KeyMaterial,
        columns: &[
            col("id", RandomId),
            col("group_id", RandomId),
            col("generation", Sequence),
            col("sealed", Sealed),
            col("state", Enum),
        ],
    },
    TableSpec {
        schema: "keystore",
        name: "erasure_intent",
        class: TableClass::KeyMaterial,
        columns: &[
            col("id", RandomId),
            col("chain", Enum),
            col("plan", Sealed),
            col("phase", Enum),
        ],
    },
];
