//! Self-tests for the PostgreSQL test harness ("Database" layer of the test
//! plan). They start real servers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::io::Write as _;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fstp_pgtest::{PgServer, Role, ServerOptions, ServerTls, tls as certs};

const CHILD_ENV: &str = "FSTP_PGTEST_ABORT_CHILD";

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn port_open(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

#[test]
fn shared_server_gives_fresh_databases() {
    let server = PgServer::shared().unwrap();
    let a = server.fresh_database().unwrap();
    let b = server.fresh_database().unwrap();
    assert_ne!(a.dbname, b.dbname);
    assert_eq!(a.host, "127.0.0.1");
    assert_eq!(a.port, server.port());
    assert_eq!(a.password.len(), 48);
    // Each database starts empty and is isolated from the other.
    server
        .psql(&a.dbname, "CREATE TABLE only_in_a (x int)")
        .unwrap();
    let in_b = server
        .psql(
            &b.dbname,
            "SELECT count(*) FROM pg_tables WHERE tablename = 'only_in_a'",
        )
        .unwrap();
    assert_eq!(in_b, "0");
    assert!(server.version().contains("PostgreSQL"));
}

#[test]
fn shared_server_is_one_server() {
    let a = PgServer::shared().unwrap();
    let b = PgServer::shared().unwrap();
    assert!(std::ptr::eq(a, b));
}

#[test]
fn server_settings_match_the_harness_contract() {
    let server = PgServer::shared().unwrap();
    let show = |name: &str| server.psql("postgres", &format!("SHOW {name}")).unwrap();
    assert_eq!(show("ssl"), "on");
    assert_eq!(show("password_encryption"), "scram-sha-256");
    assert_eq!(show("fsync"), "off");
    assert_eq!(show("listen_addresses"), "127.0.0.1");
    assert_eq!(show("ssl_min_protocol_version"), "TLSv1.3");
    let sockets = show("unix_socket_directories");
    assert!(
        PathBuf::from(&sockets).starts_with(server.dir()),
        "{sockets}"
    );
    // psql itself connected over TLS.
    let ssl = server
        .psql(
            "postgres",
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        )
        .unwrap();
    assert_eq!(ssl, "t");
    // R-NF-09, D2: psql presented the superuser's certificate as well.
    let client_dn = server
        .psql(
            "postgres",
            "SELECT client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        )
        .unwrap();
    assert!(client_dn.contains("CN=fstp_super"), "{client_dn}");
    // Every pg_hba rule is hostssl with SCRAM and clientcert=verify-full.
    let rules = server
        .psql(
            "postgres",
            "SELECT type || ' ' || auth_method || ' ' || array_to_string(options, ',') \
             FROM pg_hba_file_rules ORDER BY line_number",
        )
        .unwrap();
    assert!(!rules.is_empty());
    for rule in rules.lines() {
        assert_eq!(
            rule, "hostssl scram-sha-256 clientcert=verify-full",
            "rule: {rule}"
        );
    }
    // Every role's password is stored as a SCRAM verifier.
    let verifiers = server
        .psql(
            "postgres",
            "SELECT rolname || ' ' || left(rolpassword, 14) FROM pg_authid \
             WHERE rolcanlogin ORDER BY rolname",
        )
        .unwrap();
    assert_eq!(
        verifiers,
        "fstp_app SCRAM-SHA-256$\nfstp_super SCRAM-SHA-256$"
    );
    // The app role has no special rights.
    let app = server
        .psql(
            "postgres",
            "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls \
             FROM pg_roles WHERE rolname = 'fstp_app'",
        )
        .unwrap();
    assert_eq!(app, "f");
}

/// R-NF-09, D2: the optional-TLS configuration keeps plaintext lines for
/// negative tests, and its hostssl lines still require client
/// certificates.
#[test]
fn r_nf_09_d2_optional_tls_still_requires_client_certificates() {
    let server = PgServer::shared_with(ServerOptions {
        tls: ServerTls::Optional,
    })
    .unwrap();
    let rules = server
        .psql(
            "postgres",
            "SELECT type || ' ' || auth_method || ' ' \
             || coalesce(array_to_string(options, ','), '-') \
             FROM pg_hba_file_rules ORDER BY line_number",
        )
        .unwrap();
    assert_eq!(
        rules,
        "hostssl scram-sha-256 clientcert=verify-full\nhostnossl scram-sha-256 -"
    );
    let err = psql_as(
        server,
        server.superuser(),
        server.superuser_password(),
        None,
    )
    .unwrap_err();
    assert_refused_without_certificate(&err);
}

/// R-NF-09, D2: the app role logs in to a database it owns with its own
/// certificate and password.
#[test]
fn r_nf_09_d2_app_role_logs_in_with_its_certificate() {
    let server = PgServer::shared().unwrap();
    let db = server.fresh_database_as(Role::App).unwrap();
    assert_eq!(db.user, "fstp_app");
    assert_eq!(db.client_cert_pem, certs::APP_CERT_PEM);
    assert_eq!(db.client_key_pem, certs::APP_KEY_PEM);
    let owner = server
        .psql(
            &db.dbname,
            "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
        )
        .unwrap();
    assert_eq!(owner, "fstp_app");
    let user = psql_as(
        server,
        &db.user,
        &db.password,
        Some((db.client_cert_pem, db.client_key_pem)),
    )
    .unwrap();
    assert_eq!(user, "fstp_app");
    // The superuser's certificate does not log in the app role.
    let err = psql_as(
        server,
        &db.user,
        &db.password,
        Some((certs::SUPERUSER_CERT_PEM, certs::SUPERUSER_KEY_PEM)),
    )
    .unwrap_err();
    assert_refused_for_cn_mismatch(server, &err, &db.user);
}

#[test]
fn tls_files_are_private_to_the_server_user() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let server = PgServer::shared().unwrap();
    for name in ["server.pem", "server-key.pem", "ca.pem"] {
        let meta = std::fs::metadata(server.dir().join("tls").join(name)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
    }
    let client = server.dir().join("client");
    assert_eq!(
        std::fs::metadata(&client).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["fstp_super.pem", "fstp_super-key.pem"] {
        let meta = std::fs::metadata(client.join(name)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
    }
    let dir_meta = std::fs::metadata(server.dir()).unwrap();
    assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
    let running_as_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap();
    if running_as_root {
        assert_ne!(dir_meta.uid(), 0, "the server must not run as root");
    }
}

#[test]
fn plaintext_configuration_is_separate_and_explicit() {
    let server = PgServer::start_with(ServerOptions {
        tls: ServerTls::Off,
    })
    .unwrap();
    assert_eq!(server.tls(), ServerTls::Off);
    assert_eq!(server.psql("postgres", "SHOW ssl").unwrap(), "off");
    let rules = server
        .psql("postgres", "SELECT type FROM pg_hba_file_rules")
        .unwrap();
    assert_eq!(rules, "host");
    let db = server.fresh_database().unwrap();
    assert!(db.dbname.starts_with("fstp_test_"));
}

#[test]
fn dropping_a_server_stops_it_and_removes_its_directory() {
    let server = PgServer::start().unwrap();
    let port = server.port();
    let dir = server.dir().to_path_buf();
    assert!(port_open(port));
    assert!(dir.is_dir());
    server.stop();
    // The destructor waits for the watchdog, so both are gone already.
    assert!(!dir.exists(), "directory still exists");
    wait_until("the port to close", || !port_open(port));
}

/// Helper for `no_server_outlives_an_aborted_process`. It does nothing
/// unless the parent test sets the environment variable.
#[test]
fn abort_child_helper() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let server = PgServer::start().unwrap();
    let mut out = std::io::stdout();
    writeln!(
        out,
        "SERVER port={} dir={}",
        server.port(),
        server.dir().display()
    )
    .unwrap();
    out.flush().unwrap();
    // Destructors never run after an abort.
    std::process::abort();
}

#[test]
fn no_server_outlives_an_aborted_process() {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .args([
            "abort_child_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success(), "the child should have aborted");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find_map(|l| l.find("SERVER ").map(|i| &l[i..]))
        .unwrap_or_else(|| panic!("no server line in child output: {stdout}"));
    let mut port = 0u16;
    let mut dir = PathBuf::new();
    for part in line.split_whitespace() {
        if let Some(p) = part.strip_prefix("port=") {
            port = p.parse().unwrap();
        }
        if let Some(d) = part.strip_prefix("dir=") {
            dir = PathBuf::from(d);
        }
    }
    assert_ne!(port, 0);
    wait_until("the aborted child's server to stop", || !port_open(port));
    wait_until("the aborted child's directory to go", || !dir.exists());
}

const ARGV_CHILD_ENV: &str = "FSTP_PGTEST_ARGV_CHILD";

/// Helper for `psql_sql_never_goes_on_the_command_line`. It does nothing
/// unless the parent test sets the environment variable.
#[test]
fn argv_child_helper() {
    if std::env::var_os(ARGV_CHILD_ENV).is_none() {
        return;
    }
    let server = PgServer::start().unwrap();
    assert_eq!(
        server.psql("postgres", "SELECT 'sql-canary'").unwrap(),
        "sql-canary"
    );
    let mut out = std::io::stdout();
    writeln!(out, "APP {}", server.password(Role::App)).unwrap();
    out.flush().unwrap();
}

/// Any user can read a process's command line in `/proc/<pid>/cmdline`.
/// The role password and the SQL must reach psql some other way. A child
/// test process runs with a psql wrapper that logs its arguments.
#[test]
fn psql_sql_never_goes_on_the_command_line() {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink};
    let real = PgServer::shared().unwrap().bindir().to_path_buf();
    let dir = std::env::temp_dir().join(format!("fstp-pgtest-argv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for bin in ["initdb", "pg_ctl", "postgres"] {
        symlink(real.join(bin), dir.join(bin)).unwrap();
    }
    let log = dir.join("argv.log");
    let wrapper = format!(
        "#!/bin/bash\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
        log.display(),
        real.join("psql").display()
    );
    std::fs::write(dir.join("psql"), wrapper).unwrap();
    std::fs::set_permissions(dir.join("psql"), std::fs::Permissions::from_mode(0o755)).unwrap();

    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .args([
            "argv_child_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ARGV_CHILD_ENV, "1")
        .env("FSTP_PG_BIN", &dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let password = stdout
        .lines()
        .find_map(|l| l.find("APP ").map(|i| l[i + 4..].trim().to_owned()))
        .unwrap_or_else(|| panic!("no password line in child output: {stdout}"));
    assert_eq!(password.len(), 48);
    let argv = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    // The wrapper saw both psql runs: the role setup and the query.
    assert_eq!(argv.lines().count(), 2, "{argv}");
    assert!(argv.contains("-f -"), "{argv}");
    assert!(
        !argv.contains(&password),
        "the role password was on the command line"
    );
    assert!(!argv.contains("sql-canary"), "SQL was on the command line");
    assert!(!argv.contains("CREATE ROLE"), "SQL was on the command line");
}

/// Runs `SELECT current_user` with a psql that this test configures
/// itself: TLS verify-full against the test CA, the given role and
/// password, and the given client certificate, if any. `HOME` points at an
/// empty directory, so libpq finds no default certificate in
/// `~/.postgresql`. Returns psql's output or its standard error.
fn psql_as(
    server: &PgServer,
    user: &str,
    password: &str,
    cert: Option<(&[u8], &[u8])>,
) -> Result<String, String> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let home = std::env::temp_dir().join(format!("fstp-pgtest-home-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&home)
        .unwrap();
    let mut cmd = Command::new(server.bindir().join("psql"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", &home)
        .env("PGPASSWORD", password)
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", server.dir().join("tls").join("ca.pem"))
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
        .args(["-d", "postgres", "-c", "SELECT current_user"])
        .stdin(Stdio::null());
    if let Some((chain, key)) = cert {
        let write = |name: &str, data: &[u8]| {
            let path = home.join(name);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(data).unwrap();
            path
        };
        cmd.env("PGSSLCERT", write("client.pem", chain))
            .env("PGSSLKEY", write("client-key.pem", key));
    }
    let out = cmd.output().unwrap();
    std::fs::remove_dir_all(&home).unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// R-NF-09, D2: the default server refuses a TLS client that presents no
/// client certificate, even with the right password.
#[test]
fn r_nf_09_d2_login_without_client_certificate_is_refused() {
    let server = PgServer::shared().unwrap();
    let err = psql_as(
        server,
        server.superuser(),
        server.superuser_password(),
        None,
    )
    .unwrap_err();
    assert_refused_without_certificate(&err);
}

/// R-NF-09, D2: a certificate from the trusted CA whose CN names another
/// role is refused (`clientcert=verify-full`).
#[test]
fn r_nf_09_d2_certificate_for_another_role_is_refused() {
    let server = PgServer::shared().unwrap();
    let err = psql_as(
        server,
        server.superuser(),
        server.superuser_password(),
        Some((certs::APP_CERT_PEM, certs::APP_KEY_PEM)),
    )
    .unwrap_err();
    assert_refused_for_cn_mismatch(server, &err, server.superuser());
}

/// R-NF-09, D2: the role's own certificate and password log in.
#[test]
fn r_nf_09_d2_certificate_matching_the_role_logs_in() {
    let server = PgServer::shared().unwrap();
    let user = psql_as(
        server,
        server.superuser(),
        server.superuser_password(),
        Some((certs::SUPERUSER_CERT_PEM, certs::SUPERUSER_KEY_PEM)),
    )
    .unwrap();
    assert_eq!(user, server.superuser());
}

/// The server's answer to a TLS login without a client certificate on a
/// `clientcert=verify-full` line.
fn assert_refused_without_certificate(err: &str) {
    assert!(
        err.contains("FATAL:  connection requires a valid client certificate"),
        "{err}"
    );
}

/// PostgreSQL reports a CN mismatch to the client as a failed password
/// login, so the server log must show that the certificate check refused
/// it.
fn assert_refused_for_cn_mismatch(server: &PgServer, err: &str, user: &str) {
    assert!(
        err.contains(&format!(
            "FATAL:  password authentication failed for user \"{user}\""
        )),
        "{err}"
    );
    let log = std::fs::read_to_string(server.dir().join("server.log")).unwrap();
    let line = format!(
        "certificate validation (clientcert=verify-full) failed for user \"{user}\": CN mismatch"
    );
    assert!(log.contains(&line), "{log}");
}

/// Design sections 2.2 and 14.3: the parameters of a fixture server name
/// the fixture CA as the trust root, so a client needs no other source.
#[test]
fn conn_params_name_the_fixture_ca_as_trust_root() {
    let server = PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    assert_eq!(db.server_ca_pem, certs::CA_PEM);
}

/// Design section 14.3, the at-rest store view: `dump_data` holds a long
/// value whole, although PostgreSQL stores it compressed and out of line.
/// The control query shows the value is stored compressed.
#[test]
fn dump_data_holds_a_compressed_value_whole() {
    let server = PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let marker = "fstp-pgtest-dump-marker-0123456789abcdef";
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE t (v text);\n\
                 INSERT INTO t VALUES (repeat('abc ', 2000) || '{marker}' || repeat('abc ', 2000));"
            ),
        )
        .unwrap();
    let method = server
        .psql(&db.dbname, "SELECT pg_column_compression(v) FROM t")
        .unwrap();
    assert_eq!(method, "pglz");
    let dump = server.dump_data(&db.dbname).unwrap();
    assert!(
        dump.windows(marker.len()).any(|w| w == marker.as_bytes()),
        "the dump lacks the value"
    );
}

/// `dump_data` fails for a database that does not exist, rather than
/// return an empty dump.
#[test]
fn dump_data_refuses_a_missing_database() {
    let server = PgServer::shared().unwrap();
    assert!(server.dump_data("fstp_no_such_database").is_err());
}
