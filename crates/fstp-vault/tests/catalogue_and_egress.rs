//! The vault database catalogue (design sections 4.3 and 4.5, R-NF-08)
//! and the vault's closed egress (B4a, ADR-009 "Outbound destinations").
//!
//! `fstp_vault::CATALOGUE` lists the tables of `v_<cell>` next to the
//! vault migrations. The `vault` schema has the eight tables of design
//! section 4.3 with exactly its columns, plus `vault_audit.chain` and
//! `vault_audit.anchor`. The column classes and the keystore tables
//! follow section 4.5 and lane W2e's union test in `fstp-celltest`.
//!
//! Gap (lane report): `egress::connect` takes only a `VaultDestination`,
//! so the ADR-009 test
//! `b4a_vault_connector_refuses_every_address_outside_vault_destination`
//! has no address to refuse yet. The structural test below stands for it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_migrate::catalogue::TableSpec;
use fstp_vault::{CATALOGUE, VaultDestination};

/// The `vault` tables of design section 4.3 and their columns, in
/// declaration order.
const VAULT_TABLES: [(&str, &[&str]); 8] = [
    (
        "epoch",
        &[
            "epoch",
            "state",
            "created_at",
            "affected",
            "ack_seq",
            "ack_link",
            "acked_at",
        ],
    ),
    (
        "fact",
        &[
            "fact_id",
            "epoch",
            "kind",
            "subject",
            "dek",
            "body",
            "ended_epoch",
        ],
    ),
    ("identity", &["identity_id", "match_key"]),
    ("account", &["account_id", "identity_id", "verified_epoch"]),
    (
        "document",
        &[
            "doc_id",
            "account_id",
            "dek",
            "sealed_object_ref",
            "uploaded_at",
            "erased_epoch",
        ],
    ),
    (
        "negotiation",
        &["proposal_id", "sealed_accounts", "opened_seq", "closed_seq"],
    ),
    ("ticket_used", &["ticket_id", "used_at"]),
    ("query_log", &["n", "at", "query_digest", "holds", "epoch"]),
];

fn find(schema: &str, name: &str) -> Option<&'static TableSpec> {
    CATALOGUE
        .iter()
        .find(|t| t.schema == schema && t.name == name)
}

/// R-NF-08, design section 4.3: the catalogue lists every `vault` table
/// with exactly the designed columns.
#[test]
fn r_nf_08_vault_catalogue_lists_the_section_4_3_tables() {
    for (name, columns) in VAULT_TABLES {
        let t = find("vault", name).unwrap_or_else(|| panic!("vault.{name} is not catalogued"));
        let got: Vec<&str> = t.columns.iter().map(|c| c.name).collect();
        assert_eq!(got, columns.to_vec(), "vault.{name}");
    }
}

/// I-24, design section 4.3: the vault keeps its own chain and anchors,
/// in `vault_audit`.
#[test]
fn i24_vault_catalogue_lists_its_own_chain_tables() {
    for name in ["chain", "anchor"] {
        assert!(
            find("vault_audit", name).is_some(),
            "vault_audit.{name} is not catalogued"
        );
    }
}

/// R-NF-08: every catalogued table is listed once, and no vault
/// table is in a schema the application database owns.
#[test]
fn r_nf_08_vault_catalogue_names_each_table_once() {
    assert!(!CATALOGUE.is_empty(), "the catalogue is empty");
    for (i, t) in CATALOGUE.iter().enumerate() {
        assert!(
            [
                "vault",
                "vault_audit",
                "keystore",
                "fstp_migrate",
                "fstp_meta"
            ]
            .contains(&t.schema),
            "{}.{} is outside the vault schemas",
            t.schema,
            t.name
        );
        assert!(
            CATALOGUE[..i]
                .iter()
                .all(|u| (u.schema, u.name) != (t.schema, t.name)),
            "{}.{} is listed twice",
            t.schema,
            t.name
        );
    }
}

/// B4a, ADR-009 "Outbound destinations": the vault reaches its database,
/// its custody entry, the witness and, once Daniel accepts it, its
/// keystore snapshot prefix. The enum is closed. A new member breaks this
/// match and needs an amendment of ADR-009.
#[test]
fn b4a_vault_destination_is_closed() {
    let all = [
        VaultDestination::VaultDatabase,
        VaultDestination::Custody,
        VaultDestination::Witness,
        VaultDestination::KeystoreSnapshots,
    ];
    for d in all {
        match d {
            VaultDestination::VaultDatabase
            | VaultDestination::Custody
            | VaultDestination::Witness
            | VaultDestination::KeystoreSnapshots => {}
        }
    }
}

/// B4a, ADR-009 "Keystore snapshots": no connector builds the
/// `KeystoreSnapshots` member before Daniel accepts it.
#[test]
fn b4a_keystore_snapshot_destination_is_not_built() {
    assert!(fstp_vault::egress::connect(&VaultDestination::KeystoreSnapshots).is_err());
}
