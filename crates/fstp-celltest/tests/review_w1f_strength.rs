//! Review reproducers for lane W1f (I-19, I-20, I-82, I-83, R-NF-08,
//! SoD-07): test strength.
//!
//! Each defect lives in a lane W1f test file, whose helpers are private.
//! So each reproducer shows the defect on real components, such as a named
//! cluster, the scanner or the W1b reference. It also reads the affected
//! test's source, and it passes once that test no longer has the defect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::canary::generate_set;
use fstp_celltest::mc::place_model::{cell_hex, db};
use fstp_celltest::reference::auth::{self as r, RefAdmin, RefRoster, RefSelfGrantApproval};
use fstp_celltest::scan::{Needle, StoreSet, scan, scan_bytes};
use fstp_celltest::world::{ClusterHandle, ClusterKind, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN, ADMIN_2, T0};

/// The source of the test file `file` of this crate.
fn test_source(file: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The text of the top-level function `name` of `file`, from its `fn` to
/// its closing brace at column zero.
fn fn_body(file: &str, name: &str) -> String {
    let src = test_source(file);
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("{file} has no fn {name}"));
    let rest = &src[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
    rest[..end].to_owned()
}

fn random_hex() -> String {
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    cell_hex(fstp_cp_proto::CellId(raw))
}

/// A synthetic cell on a named application cluster of its own: its app
/// role, with a `pg_hba` line, and its database. Returns the role's
/// credential, the database name and the cluster.
fn synthetic_cell(cluster: &str) -> (db::Credential, String, ClusterHandle) {
    let c = ClusterHandle::start_named(ClusterKind::Application, cluster).unwrap();
    let hex = random_hex();
    let role = format!("c_{hex}_app");
    let login = c.server().create_login_role(&role).unwrap();
    let dbname = format!("c_{hex}");
    c.server().create_database_for(&dbname, &[&role]).unwrap();
    let cred = db::Credential {
        role: login.role,
        password: login.password,
        cert_pem: login.cert_pem,
        key_pem: login.key_pem,
    };
    (cred, dbname, c)
}

// ---------------------------------------------------------------------------
// I-82: the role attribute check exempts every role of a single-host world.

/// I-82, design section 4.1: `i82_no_remote_role_has_createrole_or_createdb`
/// checks role attributes only for roles with a non-loopback `pg_hba` line.
/// Every `fstp-pgtest` line is `127.0.0.1/32`, so a cell role with CREATEDB
/// and CREATEROLE is never checked. Design section 4.1 forbids those
/// attributes for every cell role, whatever its address.
#[test]
fn review_i82_remote_role_filter_skips_every_cell_role() {
    let (cred, _dbname, c) = synthetic_cell("review_w1f_remote");
    c.server()
        .psql(
            "postgres",
            &format!("ALTER ROLE {} CREATEDB CREATEROLE", cred.role),
        )
        .unwrap();
    // The selection of the I-82 test, applied to this cluster.
    let remote: BTreeSet<String> = db::hba_rows(c.server())
        .unwrap()
        .into_iter()
        .filter(|h| h.rule.method != "reject")
        .filter(|h| {
            !(h.rule.address == "127.0.0.1"
                && (h.netmask.is_empty() || h.netmask == "255.255.255.255"))
        })
        .map(|h| h.rule.user)
        .collect();
    let skipped = !remote.contains(&cred.role);
    let body = fn_body(
        "i82_role_plan.rs",
        "i82_no_remote_role_has_createrole_or_createdb",
    );
    let filters_loopback = body.contains("!is_loopback(h)");
    assert!(
        !(skipped && filters_loopback),
        "{} has CREATEDB and CREATEROLE, but its only pg_hba line is loopback, so \
         i82_no_remote_role_has_createrole_or_createdb never checks it (remote set {remote:?})",
        cred.role
    );
}

// ---------------------------------------------------------------------------
// I-82: the COPY FROM probe of the T-DB-ISO sweep cannot run.

/// The SQL of the escape probe labelled `label` in `t_db_iso_i82.rs`.
fn escape_probe(label: &str) -> String {
    let src = test_source("t_db_iso_i82.rs");
    let at = src
        .find(&format!("\"{label}\","))
        .unwrap_or_else(|| panic!("t_db_iso_i82.rs has no escape probe {label:?}"));
    let rest = &src[at + label.len() + 3..];
    let open = rest.find('"').unwrap();
    let rest = &rest[open + 1..];
    let close = rest.find('"').unwrap();
    rest[..close].to_owned()
}

/// I-82, T-DB-ISO: the sweep's "COPY FROM a server file" probe starts with
/// `CREATE TEMP TABLE`. Every cell database revokes TEMPORARY from PUBLIC,
/// so the probe fails before its COPY runs. A cell role that is a member
/// of `pg_read_server_files` therefore passes the sweep.
#[test]
fn review_i82_copy_probe_cannot_run_without_temporary() {
    let (cred, dbname, c) = synthetic_cell("review_w1f_copy");
    c.server()
        .psql(
            "postgres",
            &format!("GRANT pg_read_server_files TO {}", cred.role),
        )
        .unwrap();
    let probe = escape_probe("COPY FROM a server file");
    let ca = c.server().cluster_ca().unwrap().cert_pem().to_vec();
    let got = db::run_as(c.server(), &ca, &cred, true, &dbname, &probe);
    assert!(
        got.as_ref().is_ok_and(|out| !out.is_empty()),
        "{} is a member of pg_read_server_files, yet the sweep's COPY FROM probe \
         reports the path shut: {got:?}",
        cred.role
    );
}

// ---------------------------------------------------------------------------
// I-20: the account id needles miss the UUID text form.

/// I-20, B6: `i20_control_plane_and_witness_hold_no_account_id` looks for
/// each account id as 16 raw bytes and as 32 hex digits. The scanner
/// derives hex, base64 and UTF-16LE forms from them, but not the
/// 8-4-4-4-12 text form in which a `uuid` value is usually written. A
/// control-plane capture that carries an account id in that form is
/// missed.
#[test]
fn review_i20_account_id_needles_miss_the_uuid_text_form() {
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let text = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    // The needles the I-20 test builds for one account id.
    let needles = [
        Needle {
            label: "account 0 raw".to_owned(),
            bytes: raw.to_vec(),
        },
        Needle {
            label: "account 0 hex".to_owned(),
            bytes: hex.clone().into_bytes(),
        },
    ];
    let mut stores = StoreSet::default();
    stores.push(
        "egress/cell-0/control-plane/1/out",
        format!("{{\"kind\":\"heartbeat\",\"case\":\"{text}\"}}").into_bytes(),
    );
    let missed = scan_bytes(&stores, &needles).unwrap().is_clean();
    let body = fn_body(
        "i20_tenants.rs",
        "i20_control_plane_and_witness_hold_no_account_id",
    );
    let has_text_form = body.contains("}-{") || body.contains("'-'") || body.contains("\"-\"");
    assert!(
        !(missed && !has_text_form),
        "the account id {text} in a control-plane capture is not found by the needles \
         of i20_control_plane_and_witness_hold_no_account_id"
    );
}

// ---------------------------------------------------------------------------
// SoD-07: approvals in random time order.

/// SoD-07, Q40: `sod_07_self_grant_matches_the_reference_rule` runs the
/// generated approvals in generation order, with random times. The ledger
/// is time-monotone (design section 2.2), so a correct cell refuses an
/// approval stamped before the previous one. The test still hands that
/// approval to the reference. Here admin2 approves another digest at 9
/// minutes, then the grant's own digest at 6 minutes, and the grant runs
/// at 10 minutes. The reference admits the grant, while a time-monotone
/// cell holds no approval of its digest and refuses it.
#[test]
fn review_sod_07_reference_counts_an_approval_the_ledger_refuses() {
    let roster = RefRoster {
        bindings: Vec::new(),
        admins: vec![
            RefAdmin {
                account: ADMIN,
                end: None,
            },
            RefAdmin {
                account: ADMIN_2,
                end: None,
            },
        ],
    };
    let (own, other) = ([0x11; 32], [0x22; 32]);
    let at = |min: i64| Timestamp::from_micros(T0.micros() + min * r::MINUTE_US);
    let approval = |d: [u8; 32], t: Timestamp| RefSelfGrantApproval {
        approver: ADMIN_2,
        grant_digest: d,
        stepup_at: t,
        used: false,
    };
    let generated = vec![approval(other, at(9)), approval(own, at(6))];
    let now = at(10);
    // What a time-monotone ledger records: each approval no earlier than
    // the last recorded one.
    let mut recorded: Vec<RefSelfGrantApproval> = Vec::new();
    for a in &generated {
        if recorded
            .last()
            .is_none_or(|l| a.stepup_at.micros() >= l.stepup_at.micros())
        {
            recorded.push(*a);
        }
    }
    let admit = |aps: &[RefSelfGrantApproval]| {
        r::admit_self_grant(&roster, ADMIN, ADMIN, own, aps, now, r::P71_DEFAULT_US).is_ok()
    };
    let (test_want, cell_answer) = (admit(&generated), admit(&recorded));
    let body = fn_body(
        "sod_07_self_grant.rs",
        "sod_07_self_grant_matches_the_reference_rule",
    );
    let orders_times = body.contains("sort");
    assert!(
        test_want == cell_answer || orders_times,
        "the test expects the grant admitted ({test_want}), but a time-monotone cell \
         records only {} of {} approvals and refuses it ({cell_answer})",
        recorded.len(),
        generated.len()
    );
}

// ---------------------------------------------------------------------------
// I-83: the start check tests call the service loops.

/// I-83, design section 9.2: `i83_vault_refuses_an_application_cluster` and
/// `i83_cell_refuses_a_vault_cluster` call `fstp_vault::run()` and
/// `fstp_cell::run()`, which run their service until shutdown, and panic in
/// every match arm. Once lanes W2d and W3a land, each call either blocks
/// the test or returns into a panic, so neither test can pass, and
/// neither ever checks the start rule.
#[test]
fn review_i83_start_check_tests_call_the_service_loop() {
    let mut found = Vec::new();
    for (name, call) in [
        (
            "i83_vault_refuses_an_application_cluster",
            "fstp_vault::run()",
        ),
        ("i83_cell_refuses_a_vault_cluster", "fstp_cell::run()"),
    ] {
        let body = fn_body("i83_placement.rs", name);
        let arms = body.matches("=> panic!(").count();
        if body.contains(call) {
            found.push(format!(
                "{name} calls {call}, with {arms} arms that all panic"
            ));
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

// ---------------------------------------------------------------------------
// R-NF-08: committed rows hide a nonce reused after an abort.

/// R-NF-08, design section 14.5: `r_nf_08_aborted_append_never_reuses_a_nonce`
/// reads only committed `ledger.entry` and `ops.checkpoint` rows. A seal
/// whose append aborts leaves no row, so a retry that reuses its nonce
/// leaves one row per nonce and the test passes. Its gap note says so, but
/// unlike `r_nf_09_every_internal_link_is_mutually_authenticated` it then
/// goes green on the committed rows alone.
#[test]
fn review_r_nf_08_committed_rows_hide_a_nonce_reused_after_an_abort() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "review_w1f_nonce").unwrap();
    let s = c.server();
    let name = db::fresh_database(s, "review_w1f_nonce").unwrap();
    let nonce = "0102030405060708090a0b0c";
    s.psql(
        &name,
        &format!(
            "CREATE TABLE seal (key_ix integer NOT NULL, body bytea NOT NULL);\n\
             BEGIN; INSERT INTO seal VALUES (1, '\\x{nonce}aa'); ROLLBACK;\n\
             INSERT INTO seal VALUES (1, '\\x{nonce}bb');"
        ),
    )
    .unwrap();
    // The query of the R-NF-08 test.
    let rows = s
        .psql(
            &name,
            "SELECT key_ix::text || '|' || encode(substr(body, 1, 12), 'hex') FROM seal",
        )
        .unwrap();
    let seen = rows.lines().filter(|l| l.ends_with(nonce)).count();
    let body = fn_body("r_nf_m3.rs", "r_nf_08_aborted_append_never_reuses_a_nonce");
    // Fixed when the test reads every seal, or stays red at a top-level
    // `panic!` until it can, as the R-NF-09 handshake test does.
    let committed_only = body.contains("encode(substr(body, 1, 12), 'hex') FROM {table}")
        && !body.contains("\n    panic!(");
    assert!(
        !(seen < 2 && committed_only),
        "two seals used nonce {nonce} under key 1, one in an aborted append, but the \
         committed rows show it {seen} time(s), so the R-NF-08 test passes"
    );
}

// ---------------------------------------------------------------------------
// I-19: the T-ISO sweep has no positive control.

/// I-19, T-ISO: the `t_iso_i19_*` sweep reports a crossing only for a hit,
/// and never asserts that any canary reached its own cell. A world where
/// the cycle drops every `<kind>:<text>` step, or seals every value, has no
/// hit and passes. Here a world with no cell gives a clean scan for the
/// canaries of three cells, which the sweep reads as no crossing.
#[test]
fn review_t_iso_i19_sweep_has_no_positive_control() {
    let w = World::start(WorldSpec {
        cells: 0,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap();
    let mut all = Vec::new();
    for i in 0..3 {
        all.extend(generate_set(i).unwrap());
    }
    let report = scan(&w.stores().unwrap(), &all).unwrap();
    let body = fn_body("t_iso_i19.rs", "sweep");
    let has_control = body.contains("vacuous") || body.contains("never reached");
    assert!(
        !(report.hits.is_empty() && !has_control),
        "no canary of any cell is in any store, and the t_iso_i19 sweep reports no \
         crossing for that world"
    );
}
