//! Review reproducers for lane W1f, fix round 1 (adversarial pass).
//!
//! Each test fails against the current lane tests and passes once the
//! defect it names is fixed. The tests run on real PostgreSQL clusters of
//! their own. Where the defect sits in a private helper of another test
//! binary, the test also reads that test's source.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::place_model::cell_hex;
use fstp_celltest::mc::place_model::db::{self, Credential};
use fstp_celltest::world::{ClusterHandle, ClusterKind};
use fstp_control::isolation_audit::{PrivilegeEdge, PrivilegeGraph};

fn tests_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn source(file: &str) -> String {
    std::fs::read_to_string(tests_dir().join(file)).unwrap()
}

fn random_hex() -> String {
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    cell_hex(fstp_cp_proto::CellId(raw))
}

fn ca_pem(c: &ClusterHandle) -> Vec<u8> {
    c.server().cluster_ca().unwrap().cert_pem().to_vec()
}

/// A synthetic cell `hex` on `c`, as the harness lays one out: its app
/// role with a `pg_hba` line, and its database with CONNECT for that role
/// only. Returns the role's credential and the database name.
fn synthetic_cell(c: &ClusterHandle, hex: &str) -> (Credential, String) {
    let role = format!("c_{hex}_app");
    let l = c.server().create_login_role(&role).unwrap();
    let dbn = format!("c_{hex}");
    c.server().create_database_for(&dbn, &[&role]).unwrap();
    (
        Credential {
            role: l.role,
            password: l.password,
            cert_pem: l.cert_pem,
            key_pem: l.key_pem,
        },
        dbn,
    )
}

/// The string literals of `text`, unescaped, with `\` line continuations
/// joined as Rust joins them.
fn string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut s = String::new();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('\n') => {
                        while chars.peek().is_some_and(|c| c.is_whitespace()) {
                            chars.next();
                        }
                    }
                    Some('n') => s.push('\n'),
                    Some(other) => s.push(other),
                    None => {}
                },
                other => s.push(other),
            }
        }
        out.push(s);
    }
    out
}

/// The `(path, sql)` pairs of `ESCAPES` in `t_db_iso_i82.rs`.
fn escapes() -> Vec<(String, String)> {
    let src = source("t_db_iso_i82.rs");
    let start = src.find("const ESCAPES").unwrap();
    let end = start + src[start..].find("];").unwrap();
    let lits = string_literals(&src[start..end]);
    assert_eq!(lits.len() % 2, 0, "{lits:?}");
    lits.chunks(2)
        .map(|p| (p[0].clone(), p[1].clone()))
        .collect()
}

/// The ESCAPES probes of the T-DB-ISO sweep that report a path for `cred`
/// in `dbn`.
fn opened_probes(c: &ClusterHandle, cred: &Credential, dbn: &str) -> Vec<String> {
    let ca = ca_pem(c);
    escapes()
        .iter()
        .filter_map(
            |(path, sql)| match db::run_as(c.server(), &ca, cred, true, dbn, sql) {
                Ok(out) if !out.is_empty() => Some(path.clone()),
                _ => None,
            },
        )
        .collect()
}

/// The privilege graph of the reference edges of `c`'s catalogue rows.
fn reference_graph(c: &ClusterHandle) -> PrivilegeGraph {
    let rows = db::catalogue_rows(c.server()).unwrap();
    PrivilegeGraph {
        edges: db::reference_edges(&rows)
            .into_iter()
            .map(|(from, to)| PrivilegeEdge {
                from,
                to,
                via: "reference".to_owned(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// I-82: SET ROLE into a superuser role.

/// I-82, design section 4.1: "No cell role is SUPERUSER". A cell role that
/// is a member of a NOLOGIN SUPERUSER role can `SET ROLE` to it and then
/// read any file of the cluster, every other cell's relation files
/// included. `attribute_breaches` in `i82_role_plan.rs` checks attributes
/// on the role itself and memberships of the eight predefined roles only.
/// `db::cross_cell_paths` treats only those predefined roles as reaching
/// every database. The T-DB-ISO probes all run as the role itself. So no
/// I-82 check of the lane reports this path.
#[test]
fn review_i82_set_role_to_a_superuser_role_is_reported() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_review_setrole").unwrap();
    let (cred, dbn) = synthetic_cell(&c, &random_hex());
    let _other = synthetic_cell(&c, &random_hex());
    c.server()
        .psql(
            "postgres",
            &format!(
                "CREATE ROLE w1f_review_su SUPERUSER NOLOGIN;\n\
                 GRANT w1f_review_su TO {};",
                cred.role
            ),
        )
        .unwrap();
    // The hole is real: the cell role becomes a superuser and reads a
    // server file.
    db::run_as(
        c.server(),
        &ca_pem(&c),
        &cred,
        true,
        &dbn,
        "SET ROLE w1f_review_su; SELECT length(pg_read_file('postgresql.conf'))",
    )
    .unwrap_or_else(|e| panic!("precondition: SET ROLE to the superuser role failed: {e}"));
    let paths: Vec<String> = db::cross_cell_paths(&reference_graph(&c))
        .into_iter()
        .filter(|p| p.starts_with(&cred.role))
        .collect();
    let opened = opened_probes(&c, &cred, &dbn);
    assert!(
        !paths.is_empty() || !opened.is_empty(),
        "{} can SET ROLE to a SUPERUSER role, but neither db::cross_cell_paths nor any \
         ESCAPES probe of t_db_iso_i82.rs reports it",
        cred.role
    );
}

// ---------------------------------------------------------------------------
// I-82, G14: cross-database statistics views.

/// I-82, G14, design section 4.1: `pg_stat_database`, `pg_stat_activity`
/// and similar cross-database views are revoked from PUBLIC on every
/// cluster, "tested as part of I-82". A cell role that reads every
/// database's row of `pg_stat_database` passes every ESCAPES probe, and no
/// I-82 test of the lane names the view.
#[test]
fn review_i82_g14_cross_database_stat_views_are_checked() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_review_stats").unwrap();
    let (cred, dbn) = synthetic_cell(&c, &random_hex());
    let (_, other) = synthetic_cell(&c, &random_hex());
    // The hole is real: the role sees the other cell's database activity.
    let seen = db::run_as(
        c.server(),
        &ca_pem(&c),
        &cred,
        true,
        &dbn,
        &format!("SELECT count(*) FROM pg_stat_database WHERE datname = '{other}'"),
    )
    .unwrap_or_else(|e| panic!("precondition: pg_stat_database is not readable: {e}"));
    assert_eq!(
        seen, "1",
        "precondition: the other cell's row is not visible"
    );
    let opened = opened_probes(&c, &cred, &dbn);
    let named = [
        "t_db_iso_i82.rs",
        "i82_role_plan.rs",
        "t_iso_i19.rs",
        "i19_boundary.rs",
    ]
    .iter()
    .any(|f| source(f).contains("pg_stat_database"));
    assert!(
        !opened.is_empty() || named,
        "{} reads pg_stat_database rows of other cells' databases, but no ESCAPES probe \
         reports it and no I-82 test checks the G14 revocation",
        cred.role
    );
}

// ---------------------------------------------------------------------------
// R-NF-05: a fixed install credential that is not on the list.

/// The text of `fn name` in `src`, from its opening brace to its closing
/// brace. Braces inside string literals are skipped.
fn fn_body(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let bytes = src.as_bytes();
    let open = start + src[start..].find('{').unwrap();
    let (mut depth, mut i, mut in_str) = (0i32, open, false);
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return src[open..=i].to_owned();
            }
        }
        i += 1;
    }
    panic!("unbalanced fn {name}")
}

/// R-NF-05, design section 9.5:
/// `r_nf_05_self_hosted_install_has_no_default_credentials` "checks that
/// every credential is generated at install and that no file holds a
/// fixed value". The lane's test tries six listed passwords and the role
/// name on the cell roles only. An install that ships one fixed password
/// not on that list, the same in every install, passes it. The test runs
/// one install and reads no install file, so it can tell neither.
#[test]
fn review_r_nf_05_self_hosted_test_detects_a_fixed_install_credential() {
    let src = source("r_nf_m3.rs");
    let start = src.find("const DEFAULTS").unwrap();
    let end = start + src[start..].find("];").unwrap();
    let listed = string_literals(&src[start..end]);
    assert!(listed.len() >= 2, "cannot read DEFAULTS: {listed:?}");
    let fixed = "fstp-selfhosted-install-2026";
    assert!(!listed.iter().any(|p| p == fixed), "{listed:?}");
    // Two installs that ship the same fixed password both log in with it.
    for name in ["w1f_review_install_a", "w1f_review_install_b"] {
        let c = ClusterHandle::start_named(ClusterKind::Application, name).unwrap();
        let (cred, dbn) = synthetic_cell(&c, &random_hex());
        c.server()
            .psql(
                "postgres",
                &format!("ALTER ROLE {} PASSWORD '{fixed}'", cred.role),
            )
            .unwrap();
        let shipped = Credential {
            password: fixed.to_owned(),
            ..cred
        };
        db::run_as(c.server(), &ca_pem(&c), &shipped, true, &dbn, "SELECT 1")
            .unwrap_or_else(|e| panic!("precondition: the fixed password does not log in: {e}"));
    }
    let body = fn_body(
        &src,
        "r_nf_05_self_hosted_install_has_no_default_credentials",
    );
    let helper = fn_body(&src, "default_credentials");
    let two_installs = body.matches("world(").count() >= 2;
    let reads_files = [&body, &helper]
        .iter()
        .any(|t| t.contains("read_dir") || t.contains("stores()") || t.contains("scan"));
    assert!(
        two_installs || reads_files,
        "r_nf_05_self_hosted_install_has_no_default_credentials runs one install, reads no \
         install file and tries only {listed:?}, so a fixed shipped password {fixed:?} passes"
    );
}
