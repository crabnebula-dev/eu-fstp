//! Self-tests for the M3 additions to the PostgreSQL test harness (M3
//! design sections 1.3, 2.2 and 4.1, lane W1a): several named servers per
//! test binary, each with its own cluster CA, any role name, client
//! certificates minted at runtime and per-database `pg_hba` lines.
//!
//! The logins here run a psql that each test configures itself, so the
//! harness's own `psql` helper is not the oracle. Written test first: the
//! named-server API refuses until lane W1a lands it, and minted
//! certificates also need `fstp-pki` (lane W1i) and the `fstp-crypto`
//! signing module (lane W1h).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use fstp_pgtest::{PgServer, RoleLogin};

/// The OU every named server of this binary carries, unless a test names
/// another.
const OU: &str = "application";

/// A private directory for one psql run. libpq refuses a key that others
/// can read, and `HOME` must hold no default certificate.
fn private_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "fstp-pgtest-named-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

fn write_private(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(data).unwrap();
    path
}

/// Runs `SELECT current_user` in `dbname` with a psql this test configures:
/// TLS verify-full against `root_ca_pem`, the given role and password, and
/// the given client certificate, if any. Returns psql's output or its
/// standard error.
fn login(
    server: &PgServer,
    root_ca_pem: &[u8],
    user: &str,
    password: &str,
    cert: Option<(&[u8], &[u8])>,
    dbname: &str,
) -> Result<String, String> {
    let home = private_dir("home");
    let root = write_private(&home, "root.pem", root_ca_pem);
    let mut cmd = Command::new(server.bindir().join("psql"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", &home)
        .env("PGPASSWORD", password)
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", &root)
        .env("PGCONNECT_TIMEOUT", "10")
        .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
        .args([
            "-h",
            server.host(),
            "-p",
            &server.port().to_string(),
            "-U",
            user,
        ])
        .args(["-d", dbname, "-c", "SELECT current_user"])
        .stdin(Stdio::null());
    if let Some((chain, key)) = cert {
        cmd.env("PGSSLCERT", write_private(&home, "client.pem", chain))
            .env("PGSSLKEY", write_private(&home, "client-key.pem", key));
    }
    let out = cmd.output().unwrap();
    std::fs::remove_dir_all(&home).unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The CA certificate of a named server.
fn ca_pem(server: &PgServer) -> Vec<u8> {
    server
        .cluster_ca()
        .expect("a named server has its own cluster CA")
        .cert_pem()
        .to_vec()
}

/// Logs `who` in to `dbname` with its own password and certificate.
fn login_as(server: &PgServer, who: &RoleLogin, dbname: &str) -> Result<String, String> {
    login(
        server,
        &ca_pem(server),
        &who.role,
        &who.password,
        Some((&who.cert_pem, &who.key_pem)),
        dbname,
    )
}

/// The contents of the file a server setting names, read by the superuser
/// through `SHOW`. The file is the one the server actually uses.
fn setting_file(server: &PgServer, setting: &str) -> Vec<u8> {
    let path = server.psql("postgres", &format!("SHOW {setting}")).unwrap();
    std::fs::read(path).unwrap()
}

/// Design section 2.2: each call with the same name returns the same
/// server.
#[test]
fn pgtest_shared_named_returns_one_server_per_name() {
    let a = PgServer::shared_named("alpha", OU).unwrap();
    let again = PgServer::shared_named("alpha", OU).unwrap();
    assert!(std::ptr::eq(a, again));
}

/// Design section 2.2: two names give two servers, apart from the default
/// shared server.
#[test]
fn pgtest_shared_named_servers_are_distinct() {
    let a = PgServer::shared_named("alpha", OU).unwrap();
    let b = PgServer::shared_named("beta", OU).unwrap();
    let default = PgServer::shared().unwrap();
    let ports = [a.port(), b.port(), default.port()];
    assert!(
        ports[0] != ports[1] && ports[0] != ports[2] && ports[1] != ports[2],
        "{ports:?}"
    );
    assert_ne!(a.dir(), b.dir());
    assert_ne!(a.dir(), default.dir());
}

/// Design section 1.3: a name keeps the OU it started with, so a test
/// cannot get a server whose certificate names another cluster kind.
#[test]
fn pgtest_shared_named_refuses_another_ou_for_a_started_name() {
    PgServer::shared_named("gamma", OU).unwrap();
    assert!(PgServer::shared_named("gamma", "vault").is_err());
}

/// B1, design section 1.3: each named server has its own cluster CA, and
/// that CA is the only one its `ssl_ca_file` holds.
#[test]
fn b1_named_servers_each_trust_only_their_own_cluster_ca() {
    let a = PgServer::shared_named("alpha", OU).unwrap();
    let b = PgServer::shared_named("beta", OU).unwrap();
    let (ca_a, ca_b) = (ca_pem(a), ca_pem(b));
    assert_ne!(ca_a, ca_b);
    assert_eq!(setting_file(a, "ssl_ca_file"), ca_a);
    assert_eq!(setting_file(b, "ssl_ca_file"), ca_b);
}

/// R-NF-09, D2: the superuser of a named server logs in through the
/// cluster CA, so the harness can set the server up.
#[test]
fn r_nf_09_d2_named_superuser_logs_in_through_its_cluster_ca() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    assert_eq!(server.psql("postgres", "SELECT 1").unwrap(), "1");
}

/// Design section 2.2: any role name in the harness grammar is accepted,
/// including the cell role names of design section 4.1 and a 63-byte
/// name.
#[test]
fn pgtest_any_role_name_in_the_grammar_is_accepted() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    let long = format!("r{}", "x".repeat(62));
    for role in [
        "c_0123456789abcdef0123456789abcdef_writer",
        "v_0123456789abcdef0123456789abcdef_vault",
        "witness_service",
        "_underscore_first",
        long.as_str(),
    ] {
        let minted = server.create_login_role(role).unwrap();
        assert_eq!(minted.role, role);
    }
}

/// Design section 2.2: a role name outside the grammar never reaches SQL
/// or `pg_hba.conf`. A valid name is accepted first, so a server that
/// refuses everything fails this test.
#[test]
fn pgtest_role_names_outside_the_grammar_are_refused() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    server.create_login_role("grammar_control").unwrap();
    let too_long = "a".repeat(64);
    for role in [
        "",
        "Upper",
        "1digit_first",
        "a\"b",
        "a'b",
        "a b",
        "a;b",
        "a-b",
        "a\nb",
        too_long.as_str(),
    ] {
        assert!(
            server.create_login_role(role).is_err(),
            "role name {role:?} was accepted"
        );
    }
}

/// R-NF-09, D2, design section 1.3: a client certificate minted at runtime
/// for a role logs that role in to its own database.
#[test]
fn r_nf_09_d2_minted_role_certificate_logs_in() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    let who = server.create_login_role("minted_ok").unwrap();
    server
        .create_database_for("minted_ok_db", &["minted_ok"])
        .unwrap();
    assert_eq!(login_as(server, &who, "minted_ok_db").unwrap(), "minted_ok");
}

/// R-NF-09, D2: a minted certificate whose CN names another role of the
/// same cluster is refused, even with the right password.
#[test]
fn r_nf_09_d2_minted_certificate_for_another_role_is_refused() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    let a = server.create_login_role("cn_a").unwrap();
    let b = server.create_login_role("cn_b").unwrap();
    server
        .create_database_for("cn_db", &["cn_a", "cn_b"])
        .unwrap();
    // Control: each role's own certificate logs it in.
    assert_eq!(login_as(server, &a, "cn_db").unwrap(), "cn_a");
    let err = login(
        server,
        &ca_pem(server),
        &a.role,
        &a.password,
        Some((&b.cert_pem, &b.key_pem)),
        "cn_db",
    )
    .unwrap_err();
    assert!(
        err.contains("FATAL:  password authentication failed for user \"cn_a\""),
        "{err}"
    );
    let log = std::fs::read_to_string(server.dir().join("server.log")).unwrap();
    assert!(
        log.contains(
            "certificate validation (clientcert=verify-full) failed for user \"cn_a\": CN mismatch"
        ),
        "{log}"
    );
}

/// B1, R-NF-09, D2: a certificate for the right role name, signed by
/// another cluster's CA, is refused. The TLS handshake fails before
/// authentication.
#[test]
fn b1_certificate_from_another_cluster_ca_is_refused() {
    let a = PgServer::shared_named("alpha", OU).unwrap();
    let b = PgServer::shared_named("beta", OU).unwrap();
    let who = a.create_login_role("foreign_ca").unwrap();
    a.create_database_for("foreign_ca_db", &["foreign_ca"])
        .unwrap();
    // Control: the role's own certificate logs it in.
    assert_eq!(login_as(a, &who, "foreign_ca_db").unwrap(), "foreign_ca");
    let foreign = b
        .cluster_ca()
        .expect("a named server has its own cluster CA")
        .issue_role("foreign_ca")
        .unwrap();
    let err = login(
        a,
        &ca_pem(a),
        &who.role,
        &who.password,
        Some((&foreign.cert_pem, &foreign.key_pem)),
        "foreign_ca_db",
    )
    .unwrap_err();
    assert!(
        !err.contains("password authentication failed"),
        "the foreign certificate passed the TLS handshake: {err}"
    );
    assert!(
        [
            "unknown ca",
            "certificate verify failed",
            "bad certificate",
            "certificate unknown"
        ]
        .iter()
        .any(|m| err.contains(m)),
        "{err}"
    );
}

/// R-NF-09, D2: on a named server a role without a client certificate is
/// refused, even with the right password.
#[test]
fn r_nf_09_d2_named_login_without_certificate_is_refused() {
    let server = PgServer::shared_named("alpha", OU).unwrap();
    let who = server.create_login_role("no_cert").unwrap();
    server
        .create_database_for("no_cert_db", &["no_cert"])
        .unwrap();
    let err = login(
        server,
        &ca_pem(server),
        &who.role,
        &who.password,
        None,
        "no_cert_db",
    )
    .unwrap_err();
    assert!(
        err.contains("FATAL:  connection requires a valid client certificate"),
        "{err}"
    );
}

/// ADR-005 D2, design section 4.1: `pg_hba.conf` holds one `hostssl` line
/// per database and role, each with SCRAM and `clientcert=verify-full`. No
/// accepting line names the role `all`. Only the superuser line names the
/// database `all`. The last line rejects.
#[test]
fn adr005_d2_named_hba_has_one_line_per_database_and_role() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    server.create_login_role("hba_r1").unwrap();
    server.create_login_role("hba_r2").unwrap();
    server.create_database_for("hba_db1", &["hba_r1"]).unwrap();
    server
        .create_database_for("hba_db2", &["hba_r1", "hba_r2"])
        .unwrap();
    let rows = server
        .psql(
            "postgres",
            "SELECT type || '|' || array_to_string(database, ',') || '|' \
             || array_to_string(user_name, ',') || '|' || auth_method || '|' \
             || coalesce(array_to_string(options, ','), '-') \
             FROM pg_hba_file_rules ORDER BY line_number",
        )
        .unwrap();
    let rows: Vec<Vec<&str>> = rows.lines().map(|l| l.split('|').collect()).collect();
    let (last, accepting) = rows.split_last().unwrap();
    assert_eq!(last[3], "reject", "{rows:?}");
    for row in accepting {
        assert_eq!(row[0], "hostssl", "{rows:?}");
        assert_eq!(row[3], "scram-sha-256", "{rows:?}");
        assert_eq!(row[4], "clientcert=verify-full", "{rows:?}");
        assert_ne!(row[2], "all", "{rows:?}");
        assert!(!row[2].contains(','), "one role per line: {rows:?}");
        assert!(!row[1].contains(','), "one database per line: {rows:?}");
        if row[1] == "all" {
            assert_eq!(row[2], "fstp_super", "{rows:?}");
        }
    }
    let pairs: Vec<(&str, &str)> = accepting.iter().map(|r| (r[1], r[2])).collect();
    for want in [
        ("hba_db1", "hba_r1"),
        ("hba_db2", "hba_r1"),
        ("hba_db2", "hba_r2"),
    ] {
        assert_eq!(
            pairs.iter().filter(|p| **p == want).count(),
            1,
            "{want:?} in {rows:?}"
        );
    }
    assert!(!pairs.contains(&("hba_db1", "hba_r2")), "{rows:?}");
}

/// ADR-005 D2, B7, design section 4.1: a role logs in only to the
/// databases its `pg_hba` lines name. The refusal comes from `pg_hba.conf`,
/// not from a missing CONNECT grant.
#[test]
fn adr005_d2_named_hba_admits_a_role_only_to_its_own_database() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    let mine = server.create_login_role("own_db_r").unwrap();
    server.create_login_role("other_db_r").unwrap();
    server.create_database_for("own_db", &["own_db_r"]).unwrap();
    server
        .create_database_for("other_db", &["other_db_r"])
        .unwrap();
    // CONNECT on the other database is granted, so only pg_hba can refuse.
    server
        .psql("postgres", "GRANT CONNECT ON DATABASE other_db TO own_db_r")
        .unwrap();
    assert_eq!(login_as(server, &mine, "own_db").unwrap(), "own_db_r");
    let err = login_as(server, &mine, "other_db").unwrap_err();
    assert!(
        err.contains("pg_hba.conf rejects connection") || err.contains("no pg_hba.conf entry"),
        "{err}"
    );
}

/// Design section 2.2: the database grammar is the role grammar, so a name
/// that would break `pg_hba.conf` is refused. A valid name is accepted
/// first.
#[test]
fn pgtest_database_names_outside_the_grammar_are_refused() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    server.create_login_role("db_grammar_r").unwrap();
    server
        .create_database_for("db_grammar_ok", &["db_grammar_r"])
        .unwrap();
    for db in ["", "all", "a b", "a\"b", "a\nb", "Upper"] {
        assert!(
            server.create_database_for(db, &["db_grammar_r"]).is_err(),
            "database name {db:?} was accepted"
        );
    }
}

/// Design section 2.2: `create_database_for` refuses a role the server
/// does not have, so no `pg_hba` line names a missing role.
#[test]
fn pgtest_database_for_an_unknown_role_is_refused() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    server.create_login_role("known_r").unwrap();
    server
        .create_database_for("known_r_db", &["known_r"])
        .unwrap();
    assert!(
        server
            .create_database_for("unknown_r_db", &["never_created_r"])
            .is_err()
    );
}

/// The password and the private key never appear in `RoleLogin`'s
/// `Debug` output.
#[test]
fn role_login_debug_hides_password_and_key() {
    let login = RoleLogin {
        role: "dbg_role".to_owned(),
        password: "secret-password-value".to_owned(),
        cert_pem: b"cert".to_vec(),
        key_pem: b"-----BEGIN PRIVATE KEY-----secret-key".to_vec(),
    };
    let shown = format!("{login:?}");
    assert!(shown.contains("dbg_role"), "{shown}");
    assert!(!shown.contains("secret-password-value"), "{shown}");
    assert!(!shown.contains("secret-key"), "{shown}");
}

/// Design section 4.1, the `fstp_repl` loopback line: a replication role
/// gets one `hostssl replication <role>` line with SCRAM and
/// `clientcert=verify-full`, and the role has REPLICATION and no
/// superuser right.
#[test]
fn adr005_d2_named_replication_role_gets_its_loopback_line() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    server.create_replication_role("repl_r1").unwrap();
    let line = server
        .psql(
            "postgres",
            "SELECT type || '|' || array_to_string(database, ',') || '|' \
             || auth_method || '|' || array_to_string(options, ',') \
             FROM pg_hba_file_rules WHERE user_name = '{repl_r1}'",
        )
        .unwrap();
    assert_eq!(
        line,
        "hostssl|replication|scram-sha-256|clientcert=verify-full"
    );
    let rights = server
        .psql(
            "postgres",
            "SELECT rolreplication::text || rolsuper::text FROM pg_roles \
             WHERE rolname = 'repl_r1'",
        )
        .unwrap();
    assert_eq!(rights, "truefalse");
}

/// Design section 2.2: `RoleLogin::conn_params` names the role's own
/// certificate and the cluster CA of its server as the trust root.
#[test]
fn r_nf_09_d2_role_login_conn_params_trust_the_cluster_ca() {
    let server = PgServer::shared_named("delta", OU).unwrap();
    let who = server.create_login_role("params_r1").unwrap();
    let params = who.conn_params(server, "postgres");
    assert_eq!(
        (
            params.server_ca_pem.to_vec(),
            params.client_cert_pem.to_vec(),
            params.user.clone(),
        ),
        (ca_pem(server), who.cert_pem.clone(), "params_r1".to_owned())
    );
}
