//! I-83, I-97, R-NF-08, ADR-015 "Storage and roles", M3 design sections
//! 4.5 and 4.6, `SPEC/12-journey-ui.md` section 11: the journey schema.
//!
//! The journey tables sit in the cell's application database, in a
//! `journey` schema, created by a forward-only migration after the
//! existing ones. They never sit in the vault database. Every column
//! carries a class from the closed list of design section 4.5, as the
//! section 11 sketch assigns it, and no column is sealed content or free
//! text.
//!
//! Lane j2 test author. Red until the implementer adds the journey
//! migration and its catalogue rows. The vault and forward-only tests
//! are green and guard that the new migration changes nothing else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use fstp_migrate::catalogue::{ColumnClass, TableSpec};
use fstp_pgstore::{CATALOGUE, MIGRATIONS};

/// The columns and classes of the section 11 sketch, in declaration
/// order, by table.
fn section_11() -> BTreeMap<&'static str, Vec<(&'static str, ColumnClass)>> {
    use ColumnClass::{Count, Enum, KeyedDigest, RandomId, Sequence, Time};
    BTreeMap::from([
        (
            "entry",
            vec![
                ("entry_id", RandomId),
                ("source_seq", Sequence),
                ("subject_kind", Enum),
                ("subject_id", RandomId),
                ("kind", Enum),
                ("occurred_at", Time),
                ("deadline_zone", Enum),
                ("scope_mask", Enum),
                ("summary_key", Enum),
                ("supersedes", RandomId),
            ],
        ),
        (
            "entry_text",
            vec![
                ("entry_id", RandomId),
                ("ord", Count),
                ("text_id", RandomId),
                ("digest", KeyedDigest),
            ],
        ),
        (
            "projection_cursor",
            vec![("projector", Enum), ("last_ledger_seq", Sequence)],
        ),
    ])
}

fn journey_specs() -> Vec<&'static TableSpec> {
    CATALOGUE.iter().filter(|t| t.schema == "journey").collect()
}

/// I-83, R-NF-08, section 11: the application catalogue lists the three
/// tables of the sketch, each with its columns in order and the class the
/// sketch gives them.
#[test]
fn i83_app_catalogue_lists_the_section_11_journey_tables() {
    let specs: BTreeMap<&str, &TableSpec> =
        journey_specs().into_iter().map(|t| (t.name, t)).collect();
    for (table, want) in section_11() {
        let spec = specs
            .get(table)
            .unwrap_or_else(|| panic!("ADR-015: CATALOGUE lacks journey.{table}"));
        let got: Vec<(&str, Option<ColumnClass>)> =
            spec.columns.iter().map(|c| (c.name, c.class)).collect();
        let want: Vec<(&str, Option<ColumnClass>)> =
            want.into_iter().map(|(n, c)| (n, Some(c))).collect();
        assert_eq!(got, want, "R-NF-08: columns of journey.{table}");
    }
}

/// I-97, R-NF-08, ADR-015: every column of every journey table carries a
/// class, and none is sealed content or key material. No clear content is
/// stored in the journey schema.
#[test]
fn i97_journey_columns_hold_no_content() {
    let specs = journey_specs();
    assert!(!specs.is_empty(), "ADR-015: no journey table is catalogued");
    for t in specs {
        for c in t.columns {
            match c.class {
                Some(
                    ColumnClass::RandomId
                    | ColumnClass::Sequence
                    | ColumnClass::Time
                    | ColumnClass::Enum
                    | ColumnClass::Count
                    | ColumnClass::KeyedDigest,
                ) => {}
                other => panic!("I-97: journey.{}.{} has class {other:?}", t.name, c.name),
            }
        }
    }
}

/// I-83, ADR-015, design section 4.6: a migration after the existing
/// three creates the `journey` schema in the application database.
#[test]
fn i83_a_later_app_migration_creates_the_journey_schema() {
    let creating: Vec<(u32, &str)> = MIGRATIONS
        .iter()
        .filter(|m| m.sql.to_ascii_lowercase().contains("create schema journey"))
        .map(|m| (m.version, m.name))
        .collect();
    assert_eq!(
        creating.len(),
        1,
        "ADR-015: one app migration creates the journey schema: {creating:?}"
    );
    assert!(
        creating.iter().all(|(v, _)| *v > 3),
        "design section 4.6: the journey schema comes after the existing migrations: {creating:?}"
    );
    assert!(fstp_migrate::MigrationSet::new(MIGRATIONS).is_ok());
}

/// Design section 4.6: migrations are forward-only. The three that exist
/// before the journey schema keep their versions, names and SHA-256.
#[test]
fn i83_existing_app_migrations_are_unchanged() {
    let pinned = [
        (
            1u32,
            "meta",
            "9f756d92803331134285cac2409741d89ffceb50eebb691f73283519898f0532",
        ),
        (
            2,
            "apply_grant",
            "30ff777e6346b25590b4f21da5a3fceb602bcbb7c78aecd1bb169318818375e0",
        ),
        (
            3,
            "app",
            "af505b2e4d141ef50c2e8d64ffafea53d0324c45bf17c9059fa9721867d78f76",
        ),
    ];
    for (version, name, sha) in pinned {
        let m = MIGRATIONS
            .iter()
            .find(|m| m.version == version)
            .unwrap_or_else(|| panic!("migration {version} is gone"));
        assert_eq!(m.name, name, "migration {version}");
        let got: String = fstp_crypto::sha256(m.sql.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, sha, "design section 4.6: migration {version} changed");
    }
}

/// I-83, ADR-015: no vault migration names the journey schema, so no
/// journey table can sit in a vault database.
#[test]
fn i83_vault_migrations_never_name_the_journey_schema() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fstp-vault/migrations/vault");
    let mut read = 0usize;
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.expect("a directory entry").path();
        if p.extension().is_some_and(|x| x == "sql") {
            let text = std::fs::read_to_string(&p).expect("a migration reads");
            assert!(
                !text.to_ascii_lowercase().contains("journey"),
                "I-83: {} names the journey schema",
                p.display()
            );
            read = read.saturating_add(1);
        }
    }
    assert!(
        read >= 3,
        "the vault migrations were not found in {}",
        dir.display()
    );
}
