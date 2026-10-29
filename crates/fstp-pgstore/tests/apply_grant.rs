//! The schema catalogue types and the shared `fstp_meta.apply_grant` text
//! of `fstp_migrate::catalogue` (M3 design sections 4.1 and 4.5, ADR-007,
//! ADR-011, I-16, I-82, R-NF-08).
//!
//! `fstp_migrate::catalogue::APPLY_GRANT_SQL` is the one text that every
//! cell migration set uses to define `fstp_meta.apply_grant`, and
//! `APPLY_GRANT_REVOKE_SQL` follows it. The tests read the first through
//! [`apply_grant_sql`]. The PostgreSQL tests define the function from that
//! text in a database `c_<cell>` on the application cluster and call it
//! as `fstp-pgagent` does.
//!
//! The tests live in `fstp-pgstore`, which owns the first migration set
//! that embeds the text. They tie the role grammar to
//! `fstp_cp_proto::ROLE_SUFFIX_GRAMMAR`, so they need `fstp-cp-proto` as a
//! dev-dependency, and `fstp-migrate` stays as M1 left its manifest.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use fstp_migrate::catalogue::{ColumnClass, TableClass};
use fstp_migrate::{Migration, MigrationSet, SplitLimits, split_statements};
use fstp_prop::{Config, Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// The seam.

/// `fstp_migrate::catalogue::APPLY_GRANT_SQL`. Lane W2e replaced the
/// refusal with the constant.
fn apply_grant_sql() -> Result<&'static str, String> {
    Ok(fstp_migrate::catalogue::APPLY_GRANT_SQL)
}

fn shared() -> &'static str {
    apply_grant_sql().unwrap_or_else(|e| panic!("{e}"))
}

// ---------------------------------------------------------------------------
// The text (design section 4.1).

/// I-82, design section 4.1: the role check of `apply_grant` is the
/// suffix grammar of `fstp_cp_proto::ROLE_SUFFIX_GRAMMAR`, verbatim, so
/// the grant function and `RoleName` accept the same roles.
#[test]
fn i82_apply_grant_sql_holds_the_cp_proto_role_grammar() {
    holds_role_grammar(shared());
}

fn holds_role_grammar(sql: &str) {
    let quoted = format!("'{}'", fstp_cp_proto::ROLE_SUFFIX_GRAMMAR);
    assert!(
        sql.contains(&quoted),
        "I-82: APPLY_GRANT_SQL lacks {quoted}"
    );
}

/// I-82, design section 4.1: `apply_grant` checks the cell id, the
/// privileges and the object against the closed grammars of the design,
/// verbatim, and reads the cell from the `fstp.cell` setting.
#[test]
fn i82_apply_grant_sql_holds_the_design_grammars() {
    holds_design_grammars(shared());
}

fn holds_design_grammars(sql: &str) {
    for part in [
        "current_setting('fstp.cell')",
        "'^[0-9a-f]{32}$'",
        "'^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$'",
        "'^[a-z_]{1,30}\\.[a-z_]{1,30}$'",
    ] {
        assert!(sql.contains(part), "I-82: APPLY_GRANT_SQL lacks {part}");
    }
}

/// I-82, ADR-011, design section 4.6: every dynamic statement of
/// `apply_grant` is built by `format` with `%I` for identifiers, and the
/// function is not SECURITY DEFINER.
#[test]
fn i82_apply_grant_sql_quotes_identifiers_and_runs_as_its_caller() {
    quotes_and_runs_as_caller(shared());
}

fn quotes_and_runs_as_caller(sql: &str) {
    let upper = sql.to_ascii_uppercase();
    assert!(
        !upper.contains("SECURITY DEFINER"),
        "design section 4.6: SECURITY DEFINER"
    );
    let executes: Vec<usize> = upper.match_indices("EXECUTE").map(|(i, _)| i).collect();
    assert!(!executes.is_empty(), "APPLY_GRANT_SQL runs no statement");
    for i in executes {
        let after = upper[i + "EXECUTE".len()..].trim_start();
        assert!(
            after.starts_with("FORMAT("),
            "I-82: an EXECUTE not built by format: {}",
            &sql[i..sql.len().min(i + 60)]
        );
    }
    assert!(sql.contains("%I"), "I-82: no identifier is quoted with %I");
    assert!(
        !upper.contains("QUOTE_LITERAL") && !upper.contains("QUOTE_IDENT"),
        "I-82: identifiers quoted outside format"
    );
}

/// Design section 4.1: the shared text is one statement that a migration
/// set accepts, so each set can define the function from it.
#[test]
fn i82_apply_grant_sql_is_one_valid_migration_statement() {
    one_valid_statement(shared());
}

fn one_valid_statement(sql: &'static str) {
    let stmts = split_statements(sql, &SplitLimits::default()).unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "design section 4.1: statements in APPLY_GRANT_SQL"
    );
    let list = [
        Migration::new(1, "meta", "CREATE SCHEMA fstp_meta;"),
        Migration::new(2, "apply_grant", sql),
    ];
    assert!(
        MigrationSet::new(&list).is_ok(),
        "a migration set refuses it"
    );
}

// ---------------------------------------------------------------------------
// The function over PostgreSQL.

/// The grammars of `apply_grant`, written in Rust from design section 4.1.
mod grammar {
    const PRIVS: [&str; 4] = ["SELECT", "INSERT", "UPDATE", "DELETE"];

    pub(super) fn cell(s: &str) -> bool {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    pub(super) fn privs(s: &str) -> bool {
        !s.is_empty() && s.split(", ").all(|p| PRIVS.contains(&p))
    }

    fn ident(s: &str) -> bool {
        (1..=30).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    }

    pub(super) fn object(s: &str) -> bool {
        s.split_once('.').is_some_and(|(a, b)| ident(a) && ident(b))
    }

    pub(super) fn suffix(s: &str) -> bool {
        ["migrator", "writer", "app", "keys", "auditor", "vault"].contains(&s)
    }
}

/// The suffixes of the grammar.
const SUFFIXES: [&str; 6] = ["migrator", "writer", "app", "keys", "auditor", "vault"];

/// The tables the PostgreSQL tests grant on.
const TABLES: [&str; 4] = ["ledger.entry", "keystore.root", "vault.fact", "ops.outbox"];

/// A database `c_<cell>` with the six roles of the cell, the four tables,
/// and `fstp_meta.apply_grant` defined from the shared text. Dropped with
/// its roles.
struct GrantDb {
    hex: String,
    dbname: String,
}

impl GrantDb {
    fn new(apply_grant: &str) -> GrantDb {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = format!(
            "{}-{n}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        );
        let hex: String = fstp_crypto::sha256(seed.as_bytes())[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dbname = format!("c_{hex}");
        let server = common::app_server();
        let mut roles = String::new();
        for s in SUFFIXES {
            roles.push_str(&format!("CREATE ROLE c_{hex}_{s} NOLOGIN;\n"));
        }
        server
            .psql("postgres", &format!("{roles}CREATE DATABASE {dbname};"))
            .unwrap_or_else(|e| panic!("{e}"));
        let db = GrantDb { hex, dbname };
        let mut setup = String::from("CREATE SCHEMA fstp_meta;\n");
        for t in TABLES {
            let (s, _) = t.split_once('.').unwrap();
            setup.push_str(&format!(
                "CREATE SCHEMA IF NOT EXISTS {s};\nCREATE TABLE {t} (x int);\n"
            ));
        }
        db.psql(&setup).unwrap_or_else(|e| panic!("{e}"));
        db.psql(apply_grant)
            .unwrap_or_else(|e| panic!("the apply_grant text: {e}"));
        db
    }

    /// Runs `sql` as the superuser, with verbose errors.
    fn psql(&self, sql: &str) -> Result<String, String> {
        common::app_server()
            .psql(&self.dbname, &format!("\\set VERBOSITY verbose\n{sql}"))
            .map_err(|e| e.to_string())
    }

    /// Calls `apply_grant(privs, object, suffix)` with `fstp.cell` set to
    /// `cell`, as `fstp-pgagent` does.
    fn apply(&self, cell: &str, privs: &str, object: &str, suffix: &str) -> Result<String, String> {
        let q = |s: &str| s.replace('\'', "''");
        self.psql(&format!(
            "SELECT pg_catalog.set_config('fstp.cell', '{}', false);\n\
             SELECT fstp_meta.apply_grant('{}', '{}', '{}');",
            q(cell),
            q(privs),
            q(object),
            q(suffix)
        ))
    }

    /// Every table privilege held by a role other than the owner.
    fn grants(&self) -> BTreeSet<(String, String, String)> {
        let out = self
            .psql(
                "SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '.' || c.relname \
                 || '|' || a.privilege_type \
                 FROM pg_catalog.pg_class c \
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                 CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a \
                 LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee \
                 WHERE a.grantee <> c.relowner AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
                 ORDER BY 1;",
            )
            .unwrap_or_else(|e| panic!("{e}"));
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let f: Vec<&str> = l.splitn(3, '|').collect();
                (f[0].to_owned(), f[1].to_owned(), f[2].to_owned())
            })
            .collect()
    }
}

impl Drop for GrantDb {
    fn drop(&mut self) {
        let mut sql = format!("DROP DATABASE IF EXISTS {} WITH (FORCE);\n", self.dbname);
        for s in SUFFIXES {
            sql.push_str(&format!("DROP ROLE IF EXISTS c_{}_{s};\n", self.hex));
        }
        let _ = common::app_server().psql("postgres", &sql);
    }
}

/// A non-empty list of distinct privileges in random order.
fn privs(g: &mut Gen) -> Vec<&'static str> {
    let mut all = vec!["SELECT", "INSERT", "UPDATE", "DELETE"];
    g.shuffle(&mut all);
    let n = g.usize_in(1..=4);
    all.truncate(n);
    all
}

/// I-82, design section 4.1: a call inside the grammar grants exactly the
/// named privileges on the named table to `c_<cell>_<suffix>`, the role of
/// this database's cell, and changes no other grant.
#[test]
fn i82_apply_grant_grants_exactly_what_it_names() {
    grants_exactly(shared(), "i82_apply_grant_grants_exactly_what_it_names");
}

/// The property of [`i82_apply_grant_grants_exactly_what_it_names`] over
/// the function text `sql`.
fn grants_exactly(sql: &str, name: &str) {
    let db = GrantDb::new(sql);
    fstp_prop::check_with(name, Config::default().with_cases(24), |g: &mut Gen| {
        let object = *g.pick(&TABLES);
        let suffix = *g.pick(&SUFFIXES);
        let p = privs(g);
        let before = db.grants();
        db.apply(&db.hex, &p.join(", "), object, suffix)
            .map_err(|e| format!("I-82: a call inside the grammar failed: {e}"))?;
        let role = format!("c_{}_{suffix}", db.hex);
        let mut want = before.clone();
        for x in &p {
            want.insert((role.clone(), object.to_owned(), (*x).to_owned()));
        }
        prop_assert_eq!(
            db.grants(),
            want,
            "I-82: apply_grant({p:?}, {object}, {suffix})"
        );
        Ok(())
    });
}

/// Arguments outside the grammar, with injection attempts.
const BAD_PRIVS: [&str; 9] = [
    "",
    "ALL",
    "TRUNCATE",
    "SELECT, TRUNCATE",
    "SELECT,INSERT",
    "select",
    "SELECT ON ledger.entry TO PUBLIC; --",
    "SELECT, ",
    " SELECT",
];
const BAD_OBJECTS: [&str; 11] = [
    "ledger.entry.x",
    "ops.outbox.",
    "keystore.root.z",
    "",
    "ledger",
    "Ledger.entry",
    "ledger.entry1",
    "\"ledger\".entry",
    "ledger.entry; DROP TABLE ledger.entry",
    "abcdefghijklmnopqrstuvwxyzabcde.entry",
    "pg_catalog.pg_authid ",
];
const BAD_SUFFIXES: [&str; 7] = [
    "",
    "Writer",
    "writer ",
    "writer; --",
    "superuser",
    "writer_app",
    "postgres",
];
const BAD_CELLS: [&str; 6] = [
    "",
    "0123456789abcdef0123456789abcde",
    "0123456789abcdef0123456789abcdef0",
    "0123456789ABCDEF0123456789ABCDEF",
    "0123456789abcdef0123456789abcdeg",
    "x'; DROP DATABASE postgres; --",
];

/// A random printable string without backslashes, quotes or newlines.
fn junk(g: &mut Gen) -> String {
    let n = g.usize_in(0..=34);
    (0..n)
        .map(|_| {
            let c = char::from(g.u8_in(0x20..=0x7E));
            if c == '\\' || c == '\'' { '_' } else { c }
        })
        .collect()
}

/// I-82, design section 4.1: a call with any one argument outside its
/// grammar, an injection attempt or a random string, fails and changes no
/// grant. The cell id, the privileges, the object and the role suffix
/// are each checked.
#[test]
fn i82_apply_grant_refuses_every_argument_outside_its_grammar() {
    refuses_outside(
        shared(),
        "i82_apply_grant_refuses_every_argument_outside_its_grammar",
    );
}

/// The property of [`i82_apply_grant_refuses_every_argument_outside_its_grammar`]
/// over the function text `sql`.
fn refuses_outside(sql: &str, name: &str) {
    let db = GrantDb::new(sql);
    fstp_prop::check_with(name, Config::default().with_cases(48), |g: &mut Gen| {
        let mut cell = db.hex.clone();
        let mut p = privs(g).join(", ");
        let mut object = (*g.pick(&TABLES)).to_owned();
        let mut suffix = (*g.pick(&SUFFIXES)).to_owned();
        let random = g.bool();
        match g.u8_in(0..=3) {
            0 => {
                cell = if random {
                    junk(g)
                } else {
                    (*g.pick(&BAD_CELLS)).to_owned()
                }
            }
            1 => {
                p = if random {
                    junk(g)
                } else {
                    (*g.pick(&BAD_PRIVS)).to_owned()
                }
            }
            2 => {
                object = if random {
                    junk(g)
                } else {
                    (*g.pick(&BAD_OBJECTS)).to_owned()
                }
            }
            _ => {
                suffix = if random {
                    junk(g)
                } else {
                    (*g.pick(&BAD_SUFFIXES)).to_owned()
                }
            }
        }
        let inside = grammar::cell(&cell)
            && grammar::privs(&p)
            && grammar::object(&object)
            && grammar::suffix(&suffix);
        g.assume(!inside);
        let before = db.grants();
        let got = db.apply(&cell, &p, &object, &suffix);
        prop_assert!(
            got.is_err(),
            "I-82: apply_grant({p:?}, {object:?}, {suffix:?}) with cell {cell:?} succeeded"
        );
        prop_assert_eq!(db.grants(), before, "I-82: a refused call changed a grant");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The closed classes (design section 4.5).

/// I-16, design section 4.5: `TableClass` is closed and has no class for
/// a balance or a held amount. The match is exhaustive, so a new variant
/// fails to compile here until this list is reviewed.
#[test]
fn i16_table_class_has_no_fund_class() {
    let all = [
        TableClass::LedgerRecord,
        TableClass::AuditEvent,
        TableClass::SealedContent,
        TableClass::KeyMaterial,
        TableClass::Operational,
        TableClass::Migration,
        TableClass::Placement,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|c| match c {
            TableClass::LedgerRecord => "ledger record",
            TableClass::AuditEvent => "audit event",
            TableClass::SealedContent => "sealed content",
            TableClass::KeyMaterial => "key material",
            TableClass::Operational => "operational",
            TableClass::Migration => "migration",
            TableClass::Placement => "placement",
        })
        .collect();
    assert_eq!(names.len(), 7, "I-16: the table classes");
}

/// R-NF-08, ADR-007 "Clear column classes": the column classes are
/// `Sealed` and the seven clear classes of ADR-007, no more. Adding one
/// needs an ADR-007 amendment, and this exhaustive match fails to compile
/// until it is reviewed.
#[test]
fn r_nf_08_column_classes_are_the_adr007_set() {
    let all = [
        ColumnClass::Sealed,
        ColumnClass::RandomId,
        ColumnClass::Sequence,
        ColumnClass::Time,
        ColumnClass::Enum,
        ColumnClass::SecretDigest,
        ColumnClass::KeyedDigest,
        ColumnClass::Count,
    ];
    let clear = all
        .iter()
        .filter(|c| match c {
            ColumnClass::Sealed => false,
            ColumnClass::RandomId
            | ColumnClass::Sequence
            | ColumnClass::Time
            | ColumnClass::Enum
            | ColumnClass::SecretDigest
            | ColumnClass::KeyedDigest
            | ColumnClass::Count => true,
        })
        .count();
    assert_eq!(clear, 7, "R-NF-08: the clear classes of ADR-007");
}

/// Harness self-test: the Rust grammars accept the design examples and
/// refuse every listed bad argument.
#[test]
fn harness_grammar_matches_the_design_examples() {
    assert!(grammar::cell("0123456789abcdef0123456789abcdef"));
    assert!(grammar::privs("SELECT, INSERT, UPDATE, DELETE"));
    assert!(grammar::object("auth_log.stepup_consumed"));
    assert!(SUFFIXES.iter().all(|s| grammar::suffix(s)));
    assert!(BAD_CELLS.iter().all(|s| !grammar::cell(s)));
    assert!(BAD_PRIVS.iter().all(|s| !grammar::privs(s)));
    assert!(BAD_OBJECTS.iter().all(|s| !grammar::object(s)));
    assert!(BAD_SUFFIXES.iter().all(|s| !grammar::suffix(s)));
}

/// The function of design section 4.1, verbatim. The harness self-tests
/// run both properties over it, so neither refuses the designed function.
const DESIGN_APPLY_GRANT: &str = r"CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cell text := current_setting('fstp.cell');
BEGIN
  IF cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, split_part(object, '.', 1), split_part(object, '.', 2),
                 left(current_database(), 1) || '_' || cell || '_' || suffix);
END $$;";

/// Harness self-test: the designed function grants exactly what it names.
#[test]
fn harness_design_apply_grant_grants_exactly_what_it_names() {
    grants_exactly(
        DESIGN_APPLY_GRANT,
        "harness_design_apply_grant_grants_exactly_what_it_names",
    );
}

/// Harness self-test: the designed function refuses every argument
/// outside its grammar.
#[test]
fn harness_design_apply_grant_refuses_outside_its_grammar() {
    refuses_outside(
        DESIGN_APPLY_GRANT,
        "harness_design_apply_grant_refuses_outside_its_grammar",
    );
}

/// The designed function with its object check removed.
const APPLY_GRANT_WITHOUT_OBJECT_CHECK: &str = r"CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cell text := current_setting('fstp.cell');
BEGIN
  IF cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, split_part(object, '.', 1), split_part(object, '.', 2),
                 left(current_database(), 1) || '_' || cell || '_' || suffix);
END $$;";

/// I-82 teeth: a function whose object check is gone grants on
/// `ledger.entry.x` as on `ledger.entry`. The sweep of listed bad
/// arguments catches it.
#[test]
fn i82_teeth_apply_grant_without_object_check_is_caught() {
    let got = sweep(APPLY_GRANT_WITHOUT_OBJECT_CHECK);
    assert!(
        got.as_ref().is_err_and(|e| e.contains("I-82")),
        "I-82 teeth: the flawed function passed: {got:?}"
    );
}

/// Calls the function `sql` once with each listed bad argument, the other
/// three valid, and checks that each call fails and changes no grant.
fn sweep(sql: &str) -> Result<(), String> {
    let db = GrantDb::new(sql);
    let mut calls: Vec<(String, String, String, String)> = Vec::new();
    let ok = (
        db.hex.clone(),
        "SELECT, INSERT".to_owned(),
        "ledger.entry".to_owned(),
        "writer".to_owned(),
    );
    for c in BAD_CELLS {
        calls.push((c.to_owned(), ok.1.clone(), ok.2.clone(), ok.3.clone()));
    }
    for p in BAD_PRIVS {
        calls.push((ok.0.clone(), p.to_owned(), ok.2.clone(), ok.3.clone()));
    }
    for o in BAD_OBJECTS {
        calls.push((ok.0.clone(), ok.1.clone(), o.to_owned(), ok.3.clone()));
    }
    for s in BAD_SUFFIXES {
        calls.push((ok.0.clone(), ok.1.clone(), ok.2.clone(), s.to_owned()));
    }
    let mut wrong = Vec::new();
    for (cell, p, object, suffix) in calls {
        let before = db.grants();
        if db.apply(&cell, &p, &object, &suffix).is_ok() {
            wrong.push(format!(
                "apply_grant({p:?}, {object:?}, {suffix:?}) with cell {cell:?} succeeded"
            ));
        }
        if db.grants() != before {
            wrong.push(format!(
                "apply_grant({p:?}, {object:?}, {suffix:?}) changed a grant"
            ));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("I-82: {wrong:#?}"))
    }
}

/// I-82, design section 4.1: each listed injection attempt and bad
/// argument, one at a time, fails and changes no grant.
#[test]
fn i82_apply_grant_refuses_each_listed_bad_argument() {
    if let Err(e) = sweep(shared()) {
        panic!("{e}");
    }
}

/// Harness self-test: the designed function passes the sweep.
#[test]
fn harness_design_apply_grant_passes_the_sweep() {
    assert_eq!(sweep(DESIGN_APPLY_GRANT), Ok(()));
}

/// Harness self-test: the designed function text meets every text check.
#[test]
fn harness_design_apply_grant_meets_the_text_checks() {
    holds_role_grammar(DESIGN_APPLY_GRANT);
    holds_design_grammars(DESIGN_APPLY_GRANT);
    quotes_and_runs_as_caller(DESIGN_APPLY_GRANT);
    one_valid_statement(DESIGN_APPLY_GRANT);
}

// ---------------------------------------------------------------------------
// The shared revoke (design section 4.1).

/// I-82, design section 4.1: the shared revoke text is one statement, and
/// run right after the function text it leaves PUBLIC no EXECUTE on
/// `fstp_meta.apply_grant`. A role of the cell then cannot call it.
#[test]
fn i82_shared_revoke_leaves_public_no_execute_on_apply_grant() {
    let revoke = fstp_migrate::catalogue::APPLY_GRANT_REVOKE_SQL;
    let stmts = split_statements(revoke, &SplitLimits::default()).unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "design section 4.1: statements in the revoke"
    );
    let db = GrantDb::new(&format!("{}\n{revoke}", shared()));
    let public = db
        .psql(
            "SELECT count(*) FROM pg_catalog.pg_proc p \
             CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl, \
             pg_catalog.acldefault('f', p.proowner))) a \
             WHERE p.proname = 'apply_grant' AND a.grantee = 0;",
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(public, "0", "I-82: PUBLIC holds EXECUTE on apply_grant");
    let call = db.psql(&format!(
        "GRANT USAGE ON SCHEMA fstp_meta TO c_{}_writer;\nSET ROLE c_{}_writer;\n\
         SELECT pg_catalog.set_config('fstp.cell', '{}', false);\n\
         SELECT fstp_meta.apply_grant('SELECT', 'ledger.entry', 'writer');",
        db.hex, db.hex, db.hex
    ));
    assert!(
        call.as_ref().is_err_and(|e| e.contains("42501")),
        "I-82: a cell role called apply_grant: {call:?}"
    );
}
