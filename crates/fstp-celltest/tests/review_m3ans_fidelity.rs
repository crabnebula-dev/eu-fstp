//! Review of lane m3ans, invariant fidelity (R-NF-08, I-19, design
//! section 4.5 as Daniel amended it on 2026-10-30, section 21.0).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::mc::place_model::db;
use fstp_celltest::world::ClusterHandle;
use fstp_migrate::catalogue::ColumnClass;

/// R-NF-08, design section 4.5: each column of the three public classes
/// (`PublicDigest`, `Signature`, `PublicKeyMaterial`) is a `bytea` that
/// the database checks by length, exact or bounded. A public class whose
/// column takes any number of bytes holds anything, content included.
#[test]
fn review_public_class_columns_are_checked_by_type_and_length() {
    let mut missing = Vec::new();
    for s in db::migration_sets() {
        let public: Vec<(&str, &str, &str)> = s
            .catalogue
            .iter()
            .flat_map(|t| {
                t.columns
                    .iter()
                    .filter(|c| {
                        matches!(
                            c.class,
                            Some(
                                ColumnClass::PublicDigest
                                    | ColumnClass::Signature
                                    | ColumnClass::PublicKeyMaterial
                            )
                        )
                    })
                    .map(move |c| (t.schema, t.name, c.name))
            })
            .collect();
        if public.is_empty() {
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
        for (schema, table, col) in public {
            let typed = types
                .lines()
                .any(|l| l == format!("{schema}.{table}.{col}|bytea"));
            let bounded = checks.lines().any(|l| {
                l.starts_with(&format!("{schema}.{table}|"))
                    && l.contains(&format!("octet_length({col})"))
            });
            if !typed || !bounded {
                missing.push(format!(
                    "{}: {schema}.{table}.{col} (bytea: {typed}, length CHECK: {bounded})",
                    s.set
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}
