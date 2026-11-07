//! The application database `c_<cell>` after its migrations and grants
//! (M3 design sections 4.1, 4.2, 4.5, 4.6 and 7.1, ADR-007, ADR-010,
//! R-NF-08, I-16, I-24, I-77, I-78, I-82, I-83).
//!
//! Each PostgreSQL test provisions its own cell database on the named
//! server `app`: five login roles, the migrations applied by the
//! migrator, and every reference grant through `fstp_meta.apply_grant`.
//!
//! Each database check is a predicate over a provisioned database. The
//! production tests run it over `fstp_pgstore::MIGRATIONS`. The harness
//! self-test runs every predicate over the reference schema of
//! `tests/reference/app.sql`, and each teeth test seeds one flaw into that
//! schema and expects its predicate to fail.
//!
//! The W2e test author wrote these tests before the production code. The
//! production tests are red until `fstp_pgstore` exports its migrations
//! and catalogue (`common::MIGRATIONS_SEAM`). The self-test and the teeth
//! are green.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::reference::{self, APP_TABLES, APPEND_ONLY};
use common::{
    CellDb, Gap, REFERENCE_APP, bytea, column_grants, columns, fresh16, insert_chain_sql,
    insert_entries_sql, must, schema_grants, table_grants, uuid_text,
};
use fstp_audit::chain::{
    ChainId, ChainRow, Link, RowKind, StoredEntry, genesis, link_of, stored_hash,
};
use fstp_migrate::catalogue::{ColumnClass, TableClass, TableSpec};
use fstp_pgstore::CATALOGUE;
use fstp_prop::{Config, Gen, prop_assert, prop_assert_eq};

/// A predicate over a provisioned database: `Err` names each breach.
type Predicate = fn(&CellDb) -> Result<(), String>;

/// Runs `p` over a database of the production migrations.
fn on_production(p: Predicate) {
    let db = must(CellDb::provision());
    if let Err(e) = p(&db) {
        panic!("{e}");
    }
}

// ---------------------------------------------------------------------------
// The catalogue (design section 4.5, R-NF-08).

fn spec(schema: &str, name: &str) -> Option<&'static TableSpec> {
    CATALOGUE
        .iter()
        .find(|t| t.schema == schema && t.name == name)
}

fn class_of(schema: &str, name: &str, column: &str) -> Result<Option<ColumnClass>, String> {
    let t = spec(schema, name).ok_or(format!(
        "fstp_pgstore::CATALOGUE lists no {schema}.{name} (lane W2e)"
    ))?;
    let c = t
        .columns
        .iter()
        .find(|c| c.name == column)
        .ok_or(format!("{schema}.{name} lists no column {column}"))?;
    Ok(c.class)
}

/// The tables and column names of `catalogue`.
fn listed(catalogue: &[TableSpec]) -> BTreeMap<(String, String), Vec<String>> {
    catalogue
        .iter()
        .map(|t| {
            (
                (t.schema.to_owned(), t.name.to_owned()),
                t.columns.iter().map(|c| c.name.to_owned()).collect(),
            )
        })
        .collect()
}

/// The R-NF-08 comparison: `catalogue` lists each table of `db` once,
/// with every column in declaration order, and nothing else.
fn catalogue_matches(db: &CellDb, catalogue: &[TableSpec]) -> Result<(), String> {
    let have: BTreeMap<(String, String), Vec<String>> = columns(db)
        .into_iter()
        .map(|(k, cols)| (k, cols.into_iter().map(|(n, _)| n).collect()))
        .collect();
    let want = listed(catalogue);
    if want.len() != catalogue.len() {
        return Err("R-NF-08: a table is listed twice".to_owned());
    }
    if want != have {
        let missing: Vec<_> = have
            .iter()
            .filter(|(k, v)| want.get(*k) != Some(*v))
            .collect();
        let extra: Vec<_> = want
            .iter()
            .filter(|(k, v)| have.get(*k) != Some(*v))
            .collect();
        return Err(format!(
            "R-NF-08: catalogue and database differ. In the database only or different: {missing:?}. In the catalogue only or different: {extra:?}"
        ));
    }
    Ok(())
}

/// R-NF-08, design section 4.5: `fstp_pgstore::CATALOGUE` lists every
/// table of the migrated application database, the migration ledger and
/// `fstp_meta.placement` included, with every column in declaration
/// order, and nothing else.
#[test]
fn r_nf_08_app_catalogue_lists_every_table_and_column_in_order() {
    on_production(|db| catalogue_matches(db, CATALOGUE));
}

/// R-NF-08, ADR-007 "Clear column classes": every catalogued column of
/// the application database carries a class. A column the design has not
/// classed (`None`) fails until Daniel decides its class.
#[test]
fn r_nf_08_app_catalogue_classes_every_column() {
    assert!(
        !CATALOGUE.is_empty(),
        "fstp_pgstore::CATALOGUE lists no table yet (lane W2e)"
    );
    let unclassed: Vec<String> = CATALOGUE
        .iter()
        .flat_map(|t| {
            t.columns
                .iter()
                .filter(|c| c.class.is_none())
                .map(move |c| format!("{}.{}.{}", t.schema, t.name, c.name))
        })
        .collect();
    assert!(
        unclassed.is_empty(),
        "R-NF-08: unclassed columns {unclassed:?}"
    );
}

/// R-NF-08, ADR-007, design section 4.2: every column that holds content,
/// a wrapped key or a plan is `Sealed`.
#[test]
fn r_nf_08_app_content_columns_are_sealed() {
    let sealed = [
        ("ledger", "entry", "body"),
        ("audit", "chain", "body"),
        ("blob", "text", "envelope"),
        ("keystore", "root", "wrapped_seal_key"),
        ("keystore", "group_key", "sealed_secret"),
        ("keystore", "data_key", "sealed"),
        ("keystore", "erasure_intent", "plan"),
        ("ops", "outbox", "body"),
        ("ops", "checkpoint", "body"),
        ("ops", "licence_state", "sealed_token"),
    ];
    for (s, t, c) in sealed {
        assert_eq!(
            class_of(s, t, c).unwrap_or_else(|e| panic!("{e}")),
            Some(ColumnClass::Sealed),
            "R-NF-08: {s}.{t}.{c}"
        );
    }
}

/// R-NF-08, design section 4.2 and Q5: session and token hashes are
/// digests of random secrets, and credential lookups are keyed digests.
#[test]
fn r_nf_08_app_lookup_columns_are_digests() {
    let pins = [
        ("auth", "session", "token_hash", ColumnClass::SecretDigest),
        ("auth", "token", "token_hash", ColumnClass::SecretDigest),
        (
            "auth",
            "sign_count",
            "credential_key",
            ColumnClass::KeyedDigest,
        ),
    ];
    for (s, t, c, want) in pins {
        assert_eq!(
            class_of(s, t, c).unwrap_or_else(|e| panic!("{e}")),
            Some(want),
            "R-NF-08: {s}.{t}.{c}"
        );
    }
}

/// R-NF-08, I-16, design section 4.5: the table classes of the
/// application database, where the design fixes them.
#[test]
fn r_nf_08_app_table_classes_follow_the_design() {
    let pins = [
        // Daniel, 2026-11-07, m4-design section 15.0: command envelopes,
        // not submission text.
        ("ledger", "command", TableClass::Operational),
        ("ledger", "entry", TableClass::LedgerRecord),
        ("audit", "chain", TableClass::AuditEvent),
        ("audit", "anchor", TableClass::AuditEvent),
        ("blob", "text", TableClass::SealedContent),
        ("keystore", "root", TableClass::KeyMaterial),
        ("keystore", "group_key", TableClass::KeyMaterial),
        ("keystore", "data_key", TableClass::KeyMaterial),
        ("auth", "session", TableClass::Operational),
        ("fstp_meta", "placement", TableClass::Placement),
        ("fstp_migrate", "schema_migrations", TableClass::Migration),
    ];
    for (s, t, want) in pins {
        let got = spec(s, t).map(|t| t.class);
        assert_eq!(got, Some(want), "design section 4.5: {s}.{t} (lane W2e)");
    }
}

/// R-NF-08 teeth: a catalogue that omits one column of the reference
/// schema fails the comparison.
#[test]
fn r_nf_08_teeth_catalogue_missing_a_column_is_caught() {
    use fstp_migrate::catalogue::ColumnSpec;
    let db = CellDb::provision_with(REFERENCE_APP);
    let mut tables: Vec<TableSpec> = Vec::new();
    for ((s, t), cols) in columns(&db) {
        let cols: Vec<ColumnSpec> = cols
            .into_iter()
            .map(|(name, _)| ColumnSpec {
                name: Box::leak(name.into_boxed_str()),
                class: Some(ColumnClass::Sealed),
            })
            .collect();
        tables.push(TableSpec {
            schema: Box::leak(s.into_boxed_str()),
            name: Box::leak(t.into_boxed_str()),
            class: TableClass::Operational,
            columns: Box::leak(cols.into_boxed_slice()),
        });
    }
    assert_eq!(
        catalogue_matches(&db, &tables),
        Ok(()),
        "the full reference catalogue"
    );
    let i = tables
        .iter()
        .position(|t| t.schema == "auth" && t.name == "session")
        .unwrap();
    let mut cut = tables[i].columns.to_vec();
    cut.pop();
    tables[i].columns = Box::leak(cut.into_boxed_slice());
    assert!(
        catalogue_matches(&db, &tables).is_err(),
        "R-NF-08: a missing column passed"
    );
}

// ---------------------------------------------------------------------------
// Column types (I-16).

/// No column has an amount type.
fn no_amount_column(db: &CellDb) -> Result<(), String> {
    let amounts: Vec<String> = columns(db)
        .into_iter()
        .flat_map(|((s, t), cols)| {
            cols.into_iter()
                .filter(|(_, ty)| {
                    ty.starts_with("numeric")
                        || ty == "money"
                        || ty == "real"
                        || ty == "double precision"
                })
                .map(move |(c, ty)| format!("{s}.{t}.{c} {ty}"))
        })
        .collect();
    if amounts.is_empty() {
        Ok(())
    } else {
        Err(format!("I-16: amount columns {amounts:?}"))
    }
}

/// I-16, design section 14.4: no column of the migrated application
/// database has an amount type. Amounts appear only inside sealed bodies
/// (ADR-007 amendment, "Projections in memory").
#[test]
fn i16_app_schema_has_no_amount_column() {
    on_production(no_amount_column);
}

// ---------------------------------------------------------------------------
// Append-only tables (ADR-007 "Database link trigger", I-24).

/// One committed row in each append-only table, written as the writer.
/// It writes only into an empty ledger, so predicates can share a
/// database.
fn seed_rows(db: &CellDb) -> Result<(), String> {
    if db.count("SELECT count(*) FROM ledger.entry;") > 0 {
        return Ok(());
    }
    let cell = db.cell_id();
    let command = fresh16();
    let entry = StoredEntry {
        seq: 1,
        at: 1_000,
        command,
        schema: 1,
        key_ix: 0,
        body: vec![0xA5; 40],
    };
    let mut sql = insert_entries_sql(&command, 1_000, std::slice::from_ref(&entry));
    let kind = RowKind::Ledger { seq: 1 };
    let sh = stored_hash(1_000, &kind, Some(&entry)).map_err(|e| e.to_string())?;
    let link = link_of(&genesis(cell, ChainId::App), cell, ChainId::App, 1, &sh);
    sql.push_str(&insert_chain_sql(
        &ChainRow {
            n: 1,
            at: 1_000,
            kind,
            stored_hash: sh,
        },
        &link,
    ));
    sql.push_str(&format!(
        "INSERT INTO auth_log.stepup_consumed (challenge_id, ledger_seq) VALUES ('{}', 1);\n",
        uuid_text(&fresh16())
    ));
    sql.push_str(&format!(
        "INSERT INTO auth_log.session_end (session_id, at, cause, ledger_seq) VALUES ('{}', 1000, 1, 1);\n",
        uuid_text(&fresh16())
    ));
    db.psql_as("writer", &sql)
        .map(|_| ())
        .map_err(|e| format!("the writer's seed rows: {e:?}"))
}

/// A column of each writer table, for an UPDATE that changes nothing.
fn key_column(table: &str) -> &'static str {
    match table {
        "ledger.entry" => "seq",
        "ledger.command" => "command",
        "audit.chain" | "audit.anchor" => "n",
        "auth_log.stepup_consumed" => "challenge_id",
        "auth_log.session_end" => "session_id",
        "ops.outbox" => "id",
        _ => "",
    }
}

/// UPDATE, DELETE and TRUNCATE of each append-only table fail with 42501
/// for the owner and the superuser, and no row changes.
fn append_only_refuses_owner_and_superuser(db: &CellDb) -> Result<(), String> {
    seed_rows(db)?;
    let before = db.row_counts();
    let mut wrong = Vec::new();
    for table in APPEND_ONLY {
        let col = key_column(table);
        for stmt in [
            format!("UPDATE {table} SET {col} = {col};"),
            format!("DELETE FROM {table};"),
            format!("TRUNCATE {table} CASCADE;"),
        ] {
            let owner = db.state_as("migrator", &stmt);
            if owner.as_deref() != Some("42501") {
                wrong.push(format!("owner: {stmt} gave {owner:?}"));
            }
            let su = db.psql(&stmt).err().map(|e| e.state.unwrap_or(e.text));
            if su.as_deref() != Some("42501") {
                wrong.push(format!("superuser: {stmt} gave {su:?}"));
            }
        }
    }
    if db.row_counts() != before {
        wrong.push("a protected row changed".to_owned());
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-24: {wrong:#?}"))
    }
}

/// I-24, ADR-007: the triggers on `ledger.entry`, `audit.chain` and both
/// `auth_log` tables refuse UPDATE, DELETE and TRUNCATE with SQLSTATE
/// 42501 for the table owner and for the superuser too. No row changes.
#[test]
fn i24_append_only_tables_refuse_mutation_for_owner_and_superuser() {
    on_production(append_only_refuses_owner_and_superuser);
}

/// UPDATE, DELETE and TRUNCATE of each writer table fail with 42501 for
/// the writer, and no row changes.
fn writer_cannot_mutate(db: &CellDb) -> Result<(), String> {
    seed_rows(db)?;
    let before = db.row_counts();
    let mut wrong = Vec::new();
    for (suffix, object, _) in reference::plan() {
        if suffix != "writer" {
            continue;
        }
        let col = key_column(object);
        for stmt in [
            format!("UPDATE {object} SET {col} = {col};"),
            format!("DELETE FROM {object};"),
            format!("TRUNCATE {object};"),
        ] {
            let got = db.state_as("writer", &stmt);
            if got.as_deref() != Some("42501") {
                wrong.push(format!("{stmt} gave {got:?}"));
            }
        }
    }
    if db.row_counts() != before {
        wrong.push("a writer row changed".to_owned());
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-24: {wrong:#?}"))
    }
}

/// I-24, I-78, ADR-007 "holds INSERT and SELECT only": the writer gets
/// SQLSTATE 42501 for UPDATE, DELETE and TRUNCATE on every table it
/// writes.
#[test]
fn i24_writer_cannot_update_delete_or_truncate() {
    on_production(writer_cannot_mutate);
}

/// The writer holds exactly SELECT and INSERT on the tables of design
/// section 4.1.
fn writer_holds_insert_and_select_only(db: &CellDb) -> Result<(), String> {
    let writer = db.role("writer");
    let have: BTreeSet<(String, String)> = table_grants(db)
        .into_iter()
        .filter(|(r, _, _)| *r == writer)
        .map(|(_, o, p)| (o, p))
        .collect();
    let want: BTreeSet<(String, String)> = [
        "ledger.command",
        "ledger.entry",
        "audit.chain",
        "audit.anchor",
        "auth_log.stepup_consumed",
        "auth_log.session_end",
        "ops.outbox",
    ]
    .into_iter()
    .flat_map(|o| ["SELECT", "INSERT"].map(|p| (o.to_owned(), p.to_owned())))
    .collect();
    if have == want {
        Ok(())
    } else {
        Err(format!(
            "I-78: the writer holds {have:?}, the plan gives {want:?}"
        ))
    }
}

/// I-78, ADR-007: the ledger-writing role holds INSERT and SELECT only,
/// on exactly the tables design section 4.1 names.
#[test]
fn i78_writer_role_holds_insert_and_select_only_on_its_tables() {
    on_production(writer_holds_insert_and_select_only);
}

/// A second row with the same key fails with 23505.
fn second_row_refused(db: &CellDb, insert: &str, what: &str) -> Result<(), String> {
    seed_rows(db)?;
    if let Some(s) = db.state_as("writer", insert) {
        return Err(format!("{what}: the first row failed with {s}"));
    }
    match db.state_as("writer", insert) {
        Some(s) if s == "23505" => Ok(()),
        other => Err(format!("{what}: the second row gave {other:?}, not 23505")),
    }
}

fn stepup_replay_refused(db: &CellDb) -> Result<(), String> {
    let challenge = uuid_text(&fresh16());
    second_row_refused(
        db,
        &format!(
            "INSERT INTO auth_log.stepup_consumed (challenge_id, ledger_seq) VALUES ('{challenge}', 1);"
        ),
        "I-78",
    )
}

fn session_end_replay_refused(db: &CellDb) -> Result<(), String> {
    let session = uuid_text(&fresh16());
    second_row_refused(
        db,
        &format!(
            "INSERT INTO auth_log.session_end (session_id, at, cause, ledger_seq) VALUES ('{session}', 5, 1, 1);"
        ),
        "I-77",
    )
}

/// I-78, design section 4.2: a second consumption of one step-up
/// challenge violates the primary key of `auth_log.stepup_consumed`
/// (SQLSTATE 23505), so the database refuses a replay.
#[test]
fn i78_stepup_consumed_refuses_a_second_row_for_one_challenge() {
    on_production(stepup_replay_refused);
}

/// I-77, design section 4.2: a session ends by one row in
/// `auth_log.session_end`. A second row for the same session violates the
/// primary key (SQLSTATE 23505).
#[test]
fn i77_session_end_refuses_a_second_row_for_one_session() {
    on_production(session_end_replay_refused);
}

// ---------------------------------------------------------------------------
// The link trigger (design section 7.1, ADR-010 "Database link trigger").

/// How the last row of a link-trigger case is spoiled.
#[derive(Clone, Copy, Debug)]
enum Spoil {
    /// One bit of the link column flipped.
    LinkBit,
    /// One bit of the stored hash flipped, the link consistent with it.
    StoredHashBit,
    /// The row number skips one, the link consistent with it.
    Gap,
    /// The link computed with another cell's id.
    OtherCell,
    /// The link computed for the Vault chain.
    OtherChain,
    /// A kind 1 row whose stored hash covers another body than the
    /// stored entry's, the link consistent with it.
    OtherBody,
}

const SPOILS: [Spoil; 6] = [
    Spoil::LinkBit,
    Spoil::StoredHashBit,
    Spoil::Gap,
    Spoil::OtherCell,
    Spoil::OtherChain,
    Spoil::OtherBody,
];

/// The row and link of `spoil` applied to `good` after `prev`.
fn spoiled(
    spoil: Spoil,
    good: &ChainRow,
    entry: Option<&StoredEntry>,
    prev: &Link,
    cell: fstp_audit::CellId,
) -> Result<(ChainRow, Link), String> {
    let mut row = good.clone();
    let consistent = |r: &ChainRow| link_of(prev, cell, ChainId::App, r.n, &r.stored_hash);
    Ok(match spoil {
        Spoil::LinkBit => {
            let mut l = consistent(&row);
            l.0[7] ^= 0x10;
            (row, l)
        }
        Spoil::StoredHashBit => {
            row.stored_hash[3] ^= 0x01;
            let l = consistent(&row);
            (row, l)
        }
        Spoil::Gap => {
            row.n += 1;
            let l = consistent(&row);
            (row, l)
        }
        Spoil::OtherCell => {
            let other = fstp_audit::CellId(fresh16());
            let from = if row.n == 1 {
                genesis(other, ChainId::App)
            } else {
                *prev
            };
            let l = link_of(&from, other, ChainId::App, row.n, &row.stored_hash);
            (row, l)
        }
        Spoil::OtherChain => {
            let l = link_of(prev, cell, ChainId::Vault, row.n, &row.stored_hash);
            (row, l)
        }
        Spoil::OtherBody => {
            let mut e = entry.cloned().ok_or("OtherBody needs a kind 1 row")?;
            e.body[0] ^= 0xFF;
            row.stored_hash =
                stored_hash(row.at, &row.kind, Some(&e)).map_err(|e| e.to_string())?;
            let l = consistent(&row);
            (row, l)
        }
    })
}

/// The link-trigger property over databases from `provision`, each
/// changed by `flaw` (superuser SQL) when given, with spoils drawn from
/// `spoils`: the trigger accepts each `fstp-audit` row of both kinds and
/// refuses the spoiled last row, then accepts the correct one.
fn link_trigger_property(
    name: &str,
    provision: fn() -> Result<CellDb, Gap>,
    flaw: Option<&'static str>,
    spoils: &'static [Spoil],
) -> fstp_prop::Outcome {
    fstp_prop::run(name, Config::default().with_cases(6), move |g: &mut Gen| {
        let db = provision()?;
        if let Some(sql) = flaw {
            db.psql(sql).map_err(|e| format!("the flaw: {e:?}"))?;
        }
        let cell = db.cell_id();
        let mut prev = genesis(cell, ChainId::App);
        let mut seq = 0u64;
        let rows = g.u64_in(1..=5);
        let spoil = *g.pick(spoils);
        g.note("spoil", &spoil);
        for n in 1..=rows {
            let last = n == rows;
            let at = g.i64_in(-5..=5_000_000);
            let ledger = g.bool() || (last && matches!(spoil, Spoil::OtherBody));
            let (kind, entry) = if ledger {
                seq += 1;
                let command = fresh16();
                let e = StoredEntry {
                    seq,
                    at,
                    command,
                    schema: g.u16_in(1..=3),
                    key_ix: g.u32_in(0..=2),
                    body: g.bytes(28..=60),
                };
                db.psql_as(
                    "writer",
                    &insert_entries_sql(&command, at, std::slice::from_ref(&e)),
                )
                .map_err(|e| format!("ledger rows: {e:?}"))?;
                (RowKind::Ledger { seq }, Some(e))
            } else {
                (
                    RowKind::Event {
                        body: g.bytes(1..=40),
                    },
                    None,
                )
            };
            let sh = stored_hash(at, &kind, entry.as_ref()).map_err(|e| e.to_string())?;
            let good = ChainRow {
                n,
                at,
                kind,
                stored_hash: sh,
            };
            let good_link = link_of(&prev, cell, ChainId::App, n, &sh);
            if last {
                let (bad, bad_link) = spoiled(spoil, &good, entry.as_ref(), &prev, cell)?;
                let refused = db
                    .psql_as("writer", &insert_chain_sql(&bad, &bad_link))
                    .is_err();
                prop_assert!(
                    refused,
                    "I-24: the trigger accepted a {spoil:?} row at n {n}"
                );
            }
            let ok = db.psql_as("writer", &insert_chain_sql(&good, &good_link));
            prop_assert!(
                ok.is_ok(),
                "I-24: the trigger refused the fstp-audit row {n}: {ok:?}"
            );
            prev = good_link;
        }
        prop_assert_eq!(
            db.count("SELECT count(*) FROM audit.chain;"),
            rows,
            "the committed rows"
        );
        Ok(())
    })
}

fn reference_db() -> Result<CellDb, Gap> {
    Ok(CellDb::provision_with(REFERENCE_APP))
}

/// I-24, design section 7.1, ADR-010: the `audit.check_link` insert
/// trigger accepts each row whose stored hash and link are the
/// `fstp-audit` values, for both row kinds, and refuses a row with any
/// one spoiled field. After the refusal the correct row is accepted.
#[test]
fn i24_check_link_trigger_accepts_exactly_the_fstp_audit_link() {
    let outcome = link_trigger_property(
        "i24_check_link_trigger_accepts_exactly_the_fstp_audit_link",
        CellDb::provision,
        None,
        &SPOILS,
    );
    if let Some(f) = outcome.failure() {
        panic!("{}", f.report());
    }
}

/// Harness self-test: the link-trigger property holds over the reference
/// trigger, so its predicate accepts a design-faithful trigger.
#[test]
fn harness_reference_trigger_meets_the_link_property() {
    let outcome = link_trigger_property(
        "harness_reference_trigger_meets_the_link_property",
        reference_db,
        None,
        &SPOILS,
    );
    if let Some(f) = outcome.failure() {
        panic!("{}", f.report());
    }
}

/// The reference trigger without its stored-hash check: the link is
/// recomputed from the row's own stored hash column.
const TRIGGER_WITHOUT_STORED_HASH: &str = "CREATE OR REPLACE FUNCTION audit.check_link() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  cell bytea := decode(substr(current_database(), 3), 'hex');
  prev bytea;
BEGIN
  IF NEW.n = 1 THEN
    prev := sha256(convert_to('fstp-audit-genesis-v1', 'UTF8') || cell || '\\x01'::bytea);
  ELSE
    SELECT link INTO prev FROM audit.chain WHERE n = NEW.n - 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'chain gap'; END IF;
  END IF;
  IF sha256(convert_to('fstp-audit-v1', 'UTF8') || cell || '\\x01'::bytea || int8send(NEW.n) || prev || NEW.stored_hash) <> NEW.link THEN
    RAISE EXCEPTION 'link mismatch';
  END IF;
  RETURN NEW;
END $$;";

/// I-24 teeth: a trigger that recomputes the link but trusts the stored
/// hash column fails the link-trigger property.
#[test]
fn i24_teeth_trigger_trusting_the_stored_hash_is_caught() {
    const SPOILS_OF_HASH: [Spoil; 2] = [Spoil::StoredHashBit, Spoil::OtherBody];
    let outcome = link_trigger_property(
        "i24_teeth_trigger_trusting_the_stored_hash_is_caught",
        reference_db,
        Some(TRIGGER_WITHOUT_STORED_HASH),
        &SPOILS_OF_HASH,
    );
    let failure = outcome.failure().map(|f| f.message.clone());
    assert!(
        failure.as_deref().is_some_and(|m| m.contains("I-24")),
        "I-24 teeth: the flawed trigger passed: {failure:?}"
    );
}

// ---------------------------------------------------------------------------
// Grants (design section 4.1, I-82).

/// Each role holds exactly its plan on the design tables. Outside them
/// only SELECT on `fstp_meta.placement` may be granted. PUBLIC holds no
/// table privilege and no column grant exists.
fn exact_plan(db: &CellDb) -> Result<(), String> {
    let grants = table_grants(db);
    let want: BTreeSet<(String, String, String)> = reference::plan()
        .into_iter()
        .flat_map(|(suffix, object, privs)| {
            let role = db.role(suffix);
            privs
                .iter()
                .map(move |p| (role.clone(), object.to_owned(), (*p).to_owned()))
        })
        .collect();
    let in_app: BTreeSet<(String, String, String)> = grants
        .iter()
        .filter(|(_, o, _)| APP_TABLES.contains(&o.as_str()))
        .cloned()
        .collect();
    let mut wrong = Vec::new();
    for g in in_app.difference(&want) {
        wrong.push(format!("granted beyond the plan: {g:?}"));
    }
    for g in want.difference(&in_app) {
        wrong.push(format!("missing from the grants: {g:?}"));
    }
    for g in &grants {
        let outside = !APP_TABLES.contains(&g.1.as_str())
            && !(g.1 == "fstp_meta.placement" && g.2 == "SELECT");
        if outside || g.0 == "PUBLIC" {
            wrong.push(format!("outside the plan: {g:?}"));
        }
    }
    for g in column_grants(db) {
        wrong.push(format!("column grant: {g:?}"));
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-82: {wrong:#?}"))
    }
}

/// I-82, design section 4.1: after the migrations and the reference
/// grants, each role holds exactly its plan on the tables of design
/// section 4.2. Outside them no role but the owner holds any privilege,
/// except SELECT on `fstp_meta.placement` (a trigger may read it). No
/// grant goes to PUBLIC, and no column grant exists.
#[test]
fn i82_every_app_role_holds_exactly_its_plan() {
    on_production(exact_plan);
}

/// USAGE on a schema exactly where a table privilege is held, CREATE for
/// no one but the owner, nothing for PUBLIC.
fn usage_only_where_tables(db: &CellDb) -> Result<(), String> {
    let want: BTreeSet<(String, String, String)> = table_grants(db)
        .iter()
        .map(|(r, o, _)| {
            (
                r.clone(),
                reference::schema_of(o).to_owned(),
                "USAGE".to_owned(),
            )
        })
        .collect();
    let have = schema_grants(db);
    if have == want {
        Ok(())
    } else {
        Err(format!(
            "I-82: schema privileges {have:?}, the table grants imply {want:?}"
        ))
    }
}

/// I-82: a role holds USAGE on a schema exactly when it holds a table
/// privilege in it, CREATE on none, and PUBLIC holds nothing on the
/// schemas the migrations made.
#[test]
fn i82_cell_roles_hold_usage_only_where_they_hold_a_table() {
    on_production(usage_only_where_tables);
}

/// No cell role but the migrator can grant through `apply_grant`.
fn roles_cannot_call_apply_grant(db: &CellDb) -> Result<(), String> {
    let before = table_grants(db);
    let mut wrong = Vec::new();
    for suffix in ["writer", "app", "keys", "auditor"] {
        // A table the role holds no privilege on, so a GRANT by it fails
        // even if it could reach the function.
        let object = if suffix == "keys" {
            "ledger.entry"
        } else {
            "keystore.root"
        };
        let call = format!(
            "SELECT pg_catalog.set_config('fstp.cell', '{}', false);\n\
             SELECT fstp_meta.apply_grant('SELECT, INSERT, UPDATE, DELETE', '{object}', '{suffix}');",
            db.hex
        );
        let got = db.state_as(suffix, &call);
        if got.as_deref() != Some("42501") {
            wrong.push(format!("apply_grant as {suffix} gave {got:?}"));
        }
    }
    if table_grants(db) != before {
        wrong.push("a grant changed".to_owned());
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-82: {wrong:#?}"))
    }
}

/// I-82, design section 4.1: no cell role other than the migrator can
/// change a grant through `fstp_meta.apply_grant`. Each call fails with
/// SQLSTATE 42501 and the grants stay as they were.
#[test]
fn i82_cell_roles_cannot_call_apply_grant() {
    on_production(roles_cannot_call_apply_grant);
}

fn no_extension(db: &CellDb) -> Result<(), String> {
    let ext = db
        .psql("SELECT string_agg(extname, ',' ORDER BY extname) FROM pg_catalog.pg_extension;")
        .map_err(|e| format!("{e:?}"))?;
    if ext == "plpgsql" {
        Ok(())
    } else {
        Err(format!("I-82: extensions {ext}"))
    }
}

/// I-82, design section 4.1: the migrations install no extension, so
/// `dblink` and `postgres_fdw` are absent.
#[test]
fn i82_app_migrations_install_no_extension() {
    on_production(no_extension);
}

fn no_security_definer(db: &CellDb) -> Result<(), String> {
    let n = db.count(
        "SELECT count(*) FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema');",
    );
    if n == 0 {
        Ok(())
    } else {
        Err(format!(
            "design section 4.6: {n} SECURITY DEFINER functions"
        ))
    }
}

/// I-82, design section 4.6: trigger and grant functions run with the
/// caller's rights. No function the migrations made is SECURITY DEFINER.
#[test]
fn i82_app_functions_are_not_security_definer() {
    on_production(no_security_definer);
}

fn placement_application_only(db: &CellDb) -> Result<(), String> {
    let cell = bytea(&db.cell);
    let cluster = bytea(&fresh16());
    let cases = [
        (format!("({cell}, {cluster}, 2)"), "vault kind"),
        (format!("({cell}, {cluster}, 3)"), "unknown kind"),
        (
            format!("({}, {cluster}, 1)", bytea(&[1; 15])),
            "short cell id",
        ),
        (
            format!("({cell}, {}, 1)", bytea(&[2; 17])),
            "long cluster id",
        ),
    ];
    let mut wrong = Vec::new();
    for (values, what) in cases {
        let got = db
            .psql(&format!(
                "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES {values};"
            ))
            .err()
            .and_then(|e| e.state);
        if got.as_deref() != Some("23514") {
            wrong.push(format!("{what} gave {got:?}"));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-83: {wrong:?}"))
    }
}

/// I-83, design section 4.1: the placement row of an application database
/// takes kind 1 only, and both ids are 16 bytes (SQLSTATE 23514).
#[test]
fn i83_app_placement_accepts_only_the_application_kind() {
    on_production(placement_application_only);
}

/// I-82, design section 4.1: the application set defines
/// `fstp_meta.apply_grant` from the one shared text in `fstp-migrate`.
/// Exactly one migration holds that text, byte for byte.
#[test]
fn i82_app_migrations_embed_the_shared_apply_grant_text() {
    let shared = must(common::apply_grant_sql());
    let set = must(common::app_migrations());
    let found = set.iter().filter(|m| m.sql.contains(shared)).count();
    assert_eq!(
        found, 1,
        "design section 4.1: migrations holding APPLY_GRANT_SQL"
    );
}

// ---------------------------------------------------------------------------
// Harness self-test and teeth over the reference schema.

/// Every database predicate of this file, by name.
const PREDICATES: [(&str, Predicate); 11] = [
    ("no_amount_column", no_amount_column),
    (
        "append_only_refuses_owner_and_superuser",
        append_only_refuses_owner_and_superuser,
    ),
    ("writer_cannot_mutate", writer_cannot_mutate),
    (
        "writer_holds_insert_and_select_only",
        writer_holds_insert_and_select_only,
    ),
    ("stepup_replay_refused", stepup_replay_refused),
    ("session_end_replay_refused", session_end_replay_refused),
    ("exact_plan", exact_plan),
    ("usage_only_where_tables", usage_only_where_tables),
    (
        "roles_cannot_call_apply_grant",
        roles_cannot_call_apply_grant,
    ),
    ("no_extension", no_extension),
    ("no_security_definer", no_security_definer),
];

/// Harness self-test: every database predicate holds over the reference
/// schema, so no predicate refuses a design-faithful database. The
/// placement predicate runs last, since it leaves no row but writes.
#[test]
fn harness_reference_schema_meets_every_schema_predicate() {
    let db = CellDb::provision_with(REFERENCE_APP);
    let mut failed = Vec::new();
    for (name, p) in PREDICATES {
        if let Err(e) = p(&db) {
            failed.push(format!("{name}: {e}"));
        }
    }
    if let Err(e) = placement_application_only(&db) {
        failed.push(format!("placement_application_only: {e}"));
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// Runs `p` over the reference schema changed by the superuser SQL
/// `flaw`, and expects `p` to fail.
fn expect_caught(p: Predicate, flaw: &str, id: &str) {
    let db = CellDb::provision_with(REFERENCE_APP);
    db.psql(flaw)
        .unwrap_or_else(|e| panic!("the flaw did not apply: {e:?}"));
    let got = p(&db);
    assert!(
        got.as_ref().is_err_and(|e| e.contains(id)),
        "{id} teeth: the flaw `{flaw}` passed: {got:?}"
    );
}

/// I-82 teeth: a seeded UPDATE grant to the writer is caught by the plan
/// check.
#[test]
fn i82_teeth_seeded_update_grant_is_caught() {
    let db = CellDb::provision_with(REFERENCE_APP);
    let flaw = format!("GRANT UPDATE ON ledger.entry TO {};", db.role("writer"));
    db.psql(&flaw).unwrap();
    assert!(
        exact_plan(&db).is_err_and(|e| e.contains("I-82")),
        "I-82 teeth"
    );
}

/// I-82 teeth: a seeded PUBLIC grant is caught by the plan check.
#[test]
fn i82_teeth_seeded_public_grant_is_caught() {
    expect_caught(exact_plan, "GRANT SELECT ON blob.text TO PUBLIC;", "I-82");
}

/// I-82 teeth: a seeded CREATE on a schema is caught by the schema check.
#[test]
fn i82_teeth_seeded_schema_create_is_caught() {
    let db = CellDb::provision_with(REFERENCE_APP);
    db.psql(&format!(
        "GRANT CREATE ON SCHEMA ledger TO {};",
        db.role("app")
    ))
    .unwrap();
    assert!(
        usage_only_where_tables(&db).is_err_and(|e| e.contains("I-82")),
        "I-82 teeth"
    );
}

/// I-82 teeth: a seeded SECURITY DEFINER function is caught.
#[test]
fn i82_teeth_security_definer_function_is_caught() {
    expect_caught(
        no_security_definer,
        "CREATE FUNCTION ledger.escalate() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';",
        "design section 4.6",
    );
}

/// I-24 teeth: a dropped mutation trigger is caught by the append-only
/// check.
#[test]
fn i24_teeth_dropped_mutation_trigger_is_caught() {
    expect_caught(
        append_only_refuses_owner_and_superuser,
        "DROP TRIGGER session_end_no_update ON auth_log.session_end;",
        "I-24",
    );
}

/// I-78 teeth: a dropped primary key of `auth_log.stepup_consumed` is
/// caught by the replay check.
#[test]
fn i78_teeth_stepup_without_primary_key_is_caught() {
    expect_caught(
        stepup_replay_refused,
        "ALTER TABLE auth_log.stepup_consumed DROP CONSTRAINT stepup_consumed_pkey;",
        "I-78",
    );
}

/// I-83 teeth: a placement table without its kind check is caught.
#[test]
fn i83_teeth_placement_without_kind_check_is_caught() {
    expect_caught(
        placement_application_only,
        "ALTER TABLE fstp_meta.placement DROP CONSTRAINT placement_kind_check;",
        "I-83",
    );
}

/// I-82 teeth: a writer that reaches `fstp_meta` and holds a grant option
/// on `keystore.root` can widen its own rights through `apply_grant`. The
/// caller check catches it.
#[test]
fn i82_teeth_role_with_a_grant_option_is_caught() {
    let db = CellDb::provision_with(REFERENCE_APP);
    let writer = db.role("writer");
    db.psql(&format!(
        "GRANT USAGE ON SCHEMA fstp_meta, keystore TO {writer};\n\
         GRANT SELECT, INSERT, UPDATE, DELETE ON keystore.root TO {writer} WITH GRANT OPTION;"
    ))
    .unwrap();
    assert!(
        roles_cannot_call_apply_grant(&db).is_err_and(|e| e.contains("I-82")),
        "I-82 teeth"
    );
}
