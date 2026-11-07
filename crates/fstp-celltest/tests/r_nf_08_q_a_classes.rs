//! R-NF-08, I-19, design section 4.5: the column classes of Daniel's Q-A
//! answer (docs/handoff/m4-design.md section 15.0, 2026-11-07).
//!
//! Keys, hashes and receipts take the public key material, public digest
//! and signature classes. `endpoint` and `host` take the ADR-009
//! `Infrastructure` class. `org_ref`, `key_ref`, `case_ref`,
//! `keystore.root.handle` and `ops.outbox.idem` take the closed
//! `OpaqueReference` class.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::place_model::db;
use fstp_celltest::world::ClusterHandle;
use fstp_migrate::catalogue::{ColumnClass, TableSpec};

use ColumnClass::{Infrastructure, OpaqueReference, PublicDigest, PublicKeyMaterial, Signature};

fn class_of(cat: &[TableSpec], schema: &str, table: &str, column: &str) -> Option<ColumnClass> {
    cat.iter()
        .find(|t| t.schema == schema && t.name == table)
        .and_then(|t| t.columns.iter().find(|c| c.name == column))
        .and_then(|c| c.class)
}

/// R-NF-08, Q-A: each column Daniel named carries the class he gave it,
/// in every catalogue that lists it.
#[test]
fn r_nf_08_q_a_columns_take_daniels_classes() {
    let app = fstp_pgstore::CATALOGUE;
    let vault = fstp_vault::CATALOGUE;
    let cp = fstp_control::CATALOGUE;
    let pins: [(&[TableSpec], &str, &str, &str, ColumnClass); 27] = [
        (cp, "cp", "cluster", "server_spki", PublicKeyMaterial),
        (cp, "cp", "staff_credential", "cose_key", PublicKeyMaterial),
        (
            app,
            "keystore",
            "group_key",
            "public_key",
            PublicKeyMaterial,
        ),
        (
            vault,
            "keystore",
            "group_key",
            "public_key",
            PublicKeyMaterial,
        ),
        (app, "audit", "chain", "stored_hash", PublicDigest),
        (app, "audit", "chain", "link", PublicDigest),
        (vault, "vault_audit", "chain", "stored_hash", PublicDigest),
        (vault, "vault_audit", "chain", "link", PublicDigest),
        (vault, "vault", "epoch", "ack_link", PublicDigest),
        (app, "auth", "challenge", "action_digest", PublicDigest),
        (app, "ops", "delivery", "event", PublicDigest),
        (app, "ops", "delivery", "body_digest", PublicDigest),
        (app, "audit", "anchor", "receipt", Signature),
        (app, "keystore", "root", "receipt", Signature),
        (vault, "vault_audit", "anchor", "receipt", Signature),
        (vault, "keystore", "root", "receipt", Signature),
        (cp, "cp", "cluster", "endpoint", Infrastructure),
        (cp, "cp", "route", "host", Infrastructure),
        (cp, "cp", "cell", "org_ref", OpaqueReference),
        (cp, "cp", "custody_entry", "key_ref", OpaqueReference),
        (cp, "cp", "operator_ticket", "case_ref", OpaqueReference),
        (app, "keystore", "root", "handle", OpaqueReference),
        (vault, "keystore", "root", "handle", OpaqueReference),
        (app, "ops", "outbox", "idem", OpaqueReference),
        (
            app,
            "fstp_migrate",
            "schema_migrations",
            "checksum",
            PublicDigest,
        ),
        (
            vault,
            "fstp_migrate",
            "schema_migrations",
            "checksum",
            PublicDigest,
        ),
        (app, "doc", "blob", "digest", PublicDigest),
    ];
    let mut wrong = Vec::new();
    for (cat, s, t, c, want) in pins {
        let got = class_of(cat, s, t, c);
        if got != Some(want) {
            wrong.push(format!("{s}.{t}.{c}: {got:?}, Q-A gives {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// R-NF-08, I-19, Q-A: each `OpaqueReference` column is a `bytea` with a
/// length CHECK, and each `Infrastructure` column is a `text` with a
/// grammar CHECK, in the database its migration set creates. A column of
/// either class without a check holds anything, content included.
#[test]
fn r_nf_08_opaque_reference_and_infrastructure_columns_are_checked() {
    let mut missing = Vec::new();
    for s in db::migration_sets() {
        let cols: Vec<(&str, &str, &str, ColumnClass)> = s
            .catalogue
            .iter()
            .flat_map(|t| {
                t.columns.iter().filter_map(move |c| match c.class {
                    Some(k @ (OpaqueReference | Infrastructure)) => {
                        Some((t.schema, t.name, c.name, k))
                    }
                    _ => None,
                })
            })
            .collect();
        if cols.is_empty() {
            continue;
        }
        let cluster = ClusterHandle::start(s.kind).unwrap();
        let name = db::migrated(cluster.server(), &s).unwrap();
        let checks = cluster
            .server()
            .psql(
                &name,
                "SELECT n.nspname || '.' || c.relname || '|' || pg_get_constraintdef(k.oid) \
                 FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
                 JOIN pg_namespace n ON n.oid = c.relnamespace WHERE k.contype = 'c'",
            )
            .unwrap();
        let types = cluster
            .server()
            .psql(
                &name,
                "SELECT table_schema || '.' || table_name || '.' || column_name || '|' || data_type \
                 FROM information_schema.columns",
            )
            .unwrap();
        for (schema, table, col, class) in cols {
            let (ty, needle) = match class {
                OpaqueReference => ("bytea", format!("octet_length({col})")),
                _ => ("text", format!("({col} ~ ")),
            };
            let typed = types
                .lines()
                .any(|l| l == format!("{schema}.{table}.{col}|{ty}"));
            let checked = checks
                .lines()
                .any(|l| l.starts_with(&format!("{schema}.{table}|")) && l.contains(&needle));
            if !typed || !checked {
                missing.push(format!(
                    "{}: {schema}.{table}.{col} ({ty}: {typed}, CHECK: {checked})",
                    s.set
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}

/// R-NF-08 teeth: a catalogue with an opaque reference given another
/// class is caught by the pin test's lookup.
#[test]
fn r_nf_08_teeth_misclassed_opaque_reference_is_caught() {
    use fstp_migrate::catalogue::{ColumnSpec, TableClass};
    const BAD: &[TableSpec] = &[TableSpec {
        schema: "cp",
        name: "cell",
        class: TableClass::Placement,
        columns: &[ColumnSpec {
            name: "org_ref",
            class: Some(ColumnClass::Enum),
        }],
    }];
    assert_ne!(
        class_of(BAD, "cp", "cell", "org_ref"),
        Some(OpaqueReference)
    );
}
