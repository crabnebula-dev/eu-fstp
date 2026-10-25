//! Self-tests for the PostgreSQL test harness ("Database" layer of the test
//! plan). They start real servers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Write as _;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fstp_pgtest::{MTLS_USER, PgServer, ServerOptions, ServerTls};

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
    // Every pg_hba rule is hostssl with SCRAM.
    let rules = server
        .psql(
            "postgres",
            "SELECT type || ' ' || auth_method FROM pg_hba_file_rules ORDER BY line_number",
        )
        .unwrap();
    for rule in rules.lines() {
        assert_eq!(rule, "hostssl scram-sha-256", "rule: {rule}");
    }
    // The superuser's password is stored as a SCRAM verifier.
    let verifier = server
        .psql(
            "postgres",
            "SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname = current_user",
        )
        .unwrap();
    assert_eq!(verifier, "SCRAM-SHA-256$");
    let mtls = server
        .psql(
            "postgres",
            &format!("SELECT count(*) FROM pg_roles WHERE rolname = '{MTLS_USER}'"),
        )
        .unwrap();
    assert_eq!(mtls, "1");
}

#[test]
fn tls_files_are_private_to_the_server_user() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let server = PgServer::shared().unwrap();
    for name in ["server.pem", "server-key.pem", "ca.pem"] {
        let meta = std::fs::metadata(server.dir().join("tls").join(name)).unwrap();
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
    writeln!(out, "MTLS {}", server.mtls_password()).unwrap();
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
        .find_map(|l| l.find("MTLS ").map(|i| l[i + 5..].trim().to_owned()))
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
