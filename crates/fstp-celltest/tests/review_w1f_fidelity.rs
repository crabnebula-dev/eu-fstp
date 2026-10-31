//! Review reproducers for lane W1f (reference fidelity).
//!
//! Each test fails against the current tests or reference, and passes once
//! the defect it names is fixed. Two tests run on real PostgreSQL clusters
//! of their own. The others read the lane's test sources, because the
//! defect sits in a private helper of another test binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::place_model::db::{self, Credential};
use fstp_celltest::mc::place_model::{app_grants, cell_hex};
use fstp_celltest::world::{ClusterHandle, ClusterKind};
use fstp_control::pg::Privilege;
use fstp_cp_proto::RoleName;

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

fn login(c: &ClusterHandle, role: &str) -> Credential {
    let l = c.server().create_login_role(role).unwrap();
    Credential {
        role: l.role,
        password: l.password,
        cert_pem: l.cert_pem,
        key_pem: l.key_pem,
    }
}

fn ca_pem(c: &ClusterHandle) -> Vec<u8> {
    c.server().cluster_ca().unwrap().cert_pem().to_vec()
}

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

/// I-82, ADR-011 "The cell role plan", design sections 4.1 and 14.4:
/// "`CREATE EXTENSION` is refused for every cell role". The T-DB-ISO sweep
/// probes only `dblink` and `postgres_fdw`. Both are untrusted, so a
/// non-superuser is always refused them, and the probe cannot fail. The
/// migrator needs CREATE on its database to run `CREATE SCHEMA`, and with
/// it a trusted extension such as `pgcrypto` installs. The sweep's probes
/// must report that open path.
#[test]
fn review_i82_sweep_probes_a_trusted_extension() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_review_ext").unwrap();
    let hex = random_hex();
    let role = format!("c_{hex}_migrator");
    let dbn = format!("c_{hex}");
    let cred = login(&c, &role);
    c.server().create_database_for(&dbn, &[&role]).unwrap();
    c.server()
        .psql(
            "postgres",
            &format!("GRANT CREATE ON DATABASE {dbn} TO {role}"),
        )
        .unwrap();
    let ca = ca_pem(&c);
    // The hole is real: the role installs a trusted extension.
    db::run_as(
        c.server(),
        &ca,
        &cred,
        true,
        &dbn,
        "CREATE EXTENSION pgcrypto; DROP EXTENSION pgcrypto; SELECT 'opened'",
    )
    .unwrap_or_else(|e| panic!("precondition: the role could not install pgcrypto: {e}"));
    let probes = escapes();
    assert!(probes.len() >= 7, "{probes:?}");
    let opened: Vec<String> = probes
        .iter()
        .filter_map(
            |(path, sql)| match db::run_as(c.server(), &ca, &cred, true, &dbn, sql) {
                Ok(out) if !out.is_empty() => Some(path.clone()),
                _ => None,
            },
        )
        .collect();
    assert!(
        !opened.is_empty(),
        "{role} can run CREATE EXTENSION on a trusted extension, and no ESCAPES probe \
         of t_db_iso_i82.rs reports it"
    );
}

/// I-82, I-81, design section 4.1: the `keys` role deletes the `blob` rows
/// of completed erasures. PostgreSQL needs SELECT on the columns a DELETE
/// reads in its WHERE clause. The reference plan gives `keys` DELETE alone
/// on `blob.text`, and `i82_role_plan_matches_design_section_4_1` pins it
/// exactly. Under it the role cannot delete one erased row by id.
#[test]
fn review_i82_keys_role_can_delete_an_erased_blob_row() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_review_keys").unwrap();
    let hex = random_hex();
    let role = format!("c_{hex}_keys");
    let dbn = format!("c_{hex}");
    let cred = login(&c, &role);
    c.server().create_database_for(&dbn, &[&role]).unwrap();
    c.server()
        .psql(
            &dbn,
            &format!(
                "CREATE SCHEMA blob; \
                 CREATE TABLE blob.text (id uuid PRIMARY KEY, dek uuid NOT NULL UNIQUE, \
                 envelope bytea NOT NULL); \
                 INSERT INTO blob.text VALUES ('00000000-0000-4000-8000-000000000001', \
                 '00000000-0000-4000-8000-000000000002', '\\x00'); \
                 GRANT USAGE ON SCHEMA blob TO {role};"
            ),
        )
        .unwrap();
    let grants: Vec<Vec<Privilege>> = app_grants()
        .into_iter()
        .filter(|(r, o, _)| *r == RoleName::Keys && *o == "blob.text")
        .map(|(_, _, p)| p)
        .collect();
    assert_eq!(grants.len(), 1, "{grants:?}");
    let privs: Vec<&str> = grants[0]
        .iter()
        .map(|p| match p {
            Privilege::Select => "SELECT",
            Privilege::Insert => "INSERT",
            Privilege::Update => "UPDATE",
            Privilege::Delete => "DELETE",
        })
        .collect();
    c.server()
        .psql(
            &dbn,
            &format!("GRANT {} ON blob.text TO {role}", privs.join(", ")),
        )
        .unwrap();
    let got = db::run_as(
        c.server(),
        &ca_pem(&c),
        &cred,
        true,
        &dbn,
        "DELETE FROM blob.text WHERE id = '00000000-0000-4000-8000-000000000001'; \
         SELECT 'deleted'",
    );
    assert_eq!(
        got.as_deref(),
        Ok("deleted"),
        "the reference grants {privs:?} on blob.text to keys"
    );
}

/// I-19, design section 14.4: a canary of one cell found only in another
/// cell's database is a crossing. `crossings` in `t_iso_i19.rs` learns a
/// cell's database from that cell's own canary hits. Stored data is sealed
/// (B3), so the only clear hit is the leak itself, and the rule records
/// the foreign database as the canary's home with no breach. Its database
/// arm must compare the hit against the canary cell's own database.
#[test]
fn review_i19_crossing_rule_checks_the_canary_cell_owns_the_database() {
    let body = fn_body(&source("t_iso_i19.rs"), "crossings");
    let arm_start = body.find("StoreOwner::Database(").unwrap();
    let arm = &body[arm_start..];
    let arm = &arm[..arm.find("\n        }").unwrap_or(arm.len())];
    assert!(
        arm.contains("!=") || arm.contains("=="),
        "the database arm of crossings never compares the database with the canary's \
         own cell, so a lone leak into another cell's database passes:\n{arm}"
    );
}

/// I-20, design section 14.4: `shared_identifiers` runs "over every store
/// reachable from either cell and from shared infrastructure".
/// `t_iso_i20_no_shared_identifier_across_tenants` compares the two cells'
/// database stores only, so a link held by the control plane, the witness,
/// a shared cluster file or an egress capture is never compared.
#[test]
fn review_i20_t_iso_compares_shared_infrastructure_stores() {
    let src = source("t_iso_i20.rs");
    assert!(
        src.contains("outside_stores") || src.contains(".egress()"),
        "t_iso_i20.rs builds its dumps from stores_by_cell alone"
    );
}

/// SoD-07, R14 (the ledger is time-monotone), design section 5.1:
/// `sod_07_self_grant_matches_the_reference_rule` runs approvals in
/// generation order with random times. A correct cell refuses an approval
/// stamped before the last entry (`ClockBackwards`), yet the reference
/// still counts it. Approvals at T0+500 (another digest) and T0+400 (the
/// grant's digest), with the grant at T0+600, make the reference admit
/// what a correct cell refuses. The approvals must run in time order.
#[test]
fn review_sod_07_property_runs_approvals_in_time_order() {
    let body = fn_body(
        &source("sod_07_self_grant.rs"),
        "sod_07_self_grant_matches_the_reference_rule",
    );
    let lp = body.find("for a in &approvals").unwrap();
    assert!(
        body[..lp].contains("sort"),
        "the approvals are executed unsorted, and the reference counts every one"
    );
}

/// Whether the body of a test can return without a panic: it asserts
/// something, and its last top-level statement is no `panic!`.
fn can_pass(body: &str) -> Result<(), String> {
    if !body.contains("assert") {
        return Err("it asserts nothing; every path panics".to_owned());
    }
    let inner = body
        .trim_end()
        .trim_end_matches('}')
        .trim_end()
        .trim_end_matches(';')
        .trim_end();
    if let Some(i) = inner.rfind("panic!(") {
        let before = &inner[..i];
        let depth = before.matches('{').count() as i64 - before.matches('}').count() as i64;
        let after = &inner[i..];
        if depth <= 1 && after.trim_end().ends_with(')') && !after.contains(';') {
            return Err("its last statement is an unconditional panic!".to_owned());
        }
    }
    Ok(())
}

fn check_can_pass(file: &str, name: &str) {
    let body = fn_body(&source(file), name);
    if let Err(why) = can_pass(&body) {
        panic!("{file}::{name} can never pass, so no production lane can turn it green: {why}");
    }
}

/// SoD-08, design sections 8.6 and 14.5 (T-BREAKGLASS): the required test
/// ends in an unconditional `panic!`, so lane W2c cannot turn it green.
#[test]
fn review_sod_08_break_glass_test_can_pass() {
    check_can_pass(
        "sod_08_break_glass.rs",
        "sod_08_break_glass_needs_tenant_approval_and_logs_every_read",
    );
}

/// I-83, design section 9.2: every arm of the vault start-check test
/// panics, so lane W2d cannot turn it green.
#[test]
fn review_i83_vault_start_check_test_can_pass() {
    check_can_pass(
        "i83_placement.rs",
        "i83_vault_refuses_an_application_cluster",
    );
}

/// I-83, design section 9.2: every arm of the cell start-check test
/// panics, so lane W3a cannot turn it green.
#[test]
fn review_i83_cell_start_check_test_can_pass() {
    check_can_pass("i83_placement.rs", "i83_cell_refuses_a_vault_cluster");
}

/// R-NF-09, design section 14.5: the handshake test ends in an
/// unconditional `panic!`, so it never checks a client certificate.
#[test]
fn review_r_nf_09_mutual_authentication_test_can_pass() {
    check_can_pass(
        "r_nf_m3.rs",
        "r_nf_09_every_internal_link_is_mutually_authenticated",
    );
}
