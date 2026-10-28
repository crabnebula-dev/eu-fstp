//! A minimal PostgreSQL 16 server for the role certificate acceptance tests.
//!
//! Layering rule 1 (design section 2.4) keeps `fstp-pgtest` and
//! `fstp-pgwire` out of `fstp-pki`, dev edges included. So this harness
//! runs the server binaries from `FSTP_PG_BIN` directly, and `psql` is the
//! client. OpenSSL inside the server and inside libpq is then the
//! independent judge of every certificate.
//!
//! The server listens on loopback only. A bootstrap role logs in without
//! TLS to create the test roles. Every other login needs TLS, SCRAM and a
//! client certificate whose CN equals the role (`clientcert=verify-full`,
//! ADR-005 D2), as in production `pg_hba` lines (design section 4.1).
//! libpq checks the server certificate with `sslmode=verify-full`.

use std::fs;
use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The bootstrap role. It logs in only without TLS, from loopback.
const BOOT: &str = "fstp_boot";

/// A running test server. Dropping it stops the server and deletes its
/// directory.
pub(crate) struct Pg {
    bin: PathBuf,
    dir: PathBuf,
    port: u16,
}

/// The PEM files a server needs.
pub(crate) struct ServerFiles<'a> {
    /// The cluster CA certificate. The server trusts only it for clients.
    pub(crate) ca_pem: &'a str,
    /// The server certificate.
    pub(crate) cert_pem: &'a str,
    /// The server's PKCS#8 private key.
    pub(crate) key_pem: &'a str,
}

/// The files a client presents.
pub(crate) struct ClientFiles<'a> {
    /// The CA the client trusts for the server.
    pub(crate) ca_pem: &'a str,
    /// The client certificate.
    pub(crate) cert_pem: &'a str,
    /// The client's PKCS#8 private key.
    pub(crate) key_pem: &'a str,
}

/// The password every test role gets. SCRAM runs on top of the
/// certificate check, as ADR-005 D2 requires.
pub(crate) const PASSWORD: &str = "synthetic-test-password-not-a-secret";

static NEXT: AtomicU64 = AtomicU64::new(0);

fn run(cmd: &mut Command) -> Result<Output, String> {
    cmd.output().map_err(|e| format!("{cmd:?}: {e}"))
}

fn ok(cmd: &mut Command) -> Result<String, String> {
    let out = run(cmd)?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{cmd:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

impl Pg {
    /// Starts a server with `files`, then creates each role of `roles`
    /// with LOGIN and [`PASSWORD`].
    ///
    /// # Errors
    ///
    /// Returns a message when `FSTP_PG_BIN` is unset, when the process
    /// runs as root, or when a server step fails.
    pub(crate) fn start(files: &ServerFiles<'_>, roles: &[&str]) -> Result<Pg, String> {
        let bin = PathBuf::from(
            std::env::var_os("FSTP_PG_BIN")
                .ok_or("FSTP_PG_BIN must name the PostgreSQL 16 bin directory")?,
        );
        let uid = ok(Command::new("id").arg("-u"))?;
        if uid.trim() == "0" {
            return Err("initdb refuses root; run the fstp-pki tests as a normal user".into());
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fstp-pki-pg-{}-{nanos}-{n}", std::process::id()));
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let port = free_port()?;
        let pg = Pg { bin, dir, port };
        pg.init(files)?;
        pg.boot_sql("SELECT 1")?;
        for role in roles {
            pg.boot_sql(&format!(
                "CREATE ROLE \"{role}\" LOGIN PASSWORD '{PASSWORD}'"
            ))?;
        }
        Ok(pg)
    }

    fn data(&self) -> PathBuf {
        self.dir.join("data")
    }

    fn init(&self, files: &ServerFiles<'_>) -> Result<(), String> {
        ok(Command::new(self.bin.join("initdb"))
            .arg("-D")
            .arg(self.data())
            .args(["-U", BOOT, "--auth-local=reject", "--auth-host=reject"])
            .args(["--no-sync", "--no-instructions", "-E", "UTF8", "--locale=C"]))?;
        let tls = self.dir.join("server");
        fs::create_dir(&tls).map_err(|e| e.to_string())?;
        write_private(&tls.join("ca.pem"), files.ca_pem)?;
        write_private(&tls.join("server.pem"), files.cert_pem)?;
        write_private(&tls.join("server.key"), files.key_pem)?;
        let hba = format!(
            "hostnossl postgres {BOOT} 127.0.0.1/32 trust\n\
             hostssl all all 127.0.0.1/32 scram-sha-256 clientcert=verify-full\n\
             host all all all reject\n"
        );
        fs::write(self.data().join("pg_hba.conf"), hba).map_err(|e| e.to_string())?;
        let conf = format!(
            "listen_addresses = '127.0.0.1'\n\
             port = {port}\n\
             unix_socket_directories = ''\n\
             ssl = on\n\
             ssl_min_protocol_version = 'TLSv1.3'\n\
             ssl_cert_file = '{cert}'\n\
             ssl_key_file = '{key}'\n\
             ssl_ca_file = '{ca}'\n\
             password_encryption = 'scram-sha-256'\n\
             fsync = off\n",
            port = self.port,
            cert = tls.join("server.pem").display(),
            key = tls.join("server.key").display(),
            ca = tls.join("ca.pem").display(),
        );
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.data().join("postgresql.conf"))
            .map_err(|e| e.to_string())?;
        f.write_all(conf.as_bytes()).map_err(|e| e.to_string())?;
        ok(Command::new(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(self.data())
            .arg("-l")
            .arg(self.dir.join("server.log"))
            .args(["-w", "-t", "60", "start"]))
        .map_err(|e| format!("{e}\nserver log:\n{}", self.log()))?;
        Ok(())
    }

    /// The server log, for failure messages.
    pub(crate) fn log(&self) -> String {
        fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }

    fn boot_sql(&self, sql: &str) -> Result<String, String> {
        ok(Command::new(self.bin.join("psql"))
            .arg(format!(
                "host=127.0.0.1 port={} user={BOOT} dbname=postgres sslmode=disable",
                self.port
            ))
            .args(["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql]))
    }

    /// Logs in as `role` with `client` over TLS and runs `SELECT
    /// current_user`. Returns the role the server reports. libpq checks
    /// the server certificate with `sslmode=verify-full` against the IP
    /// address `127.0.0.1` (ADR-005).
    ///
    /// # Errors
    ///
    /// Returns the client's error output when the server refuses.
    pub(crate) fn login(&self, role: &str, client: &ClientFiles<'_>) -> Result<String, String> {
        self.login_to("127.0.0.1", role, client)
    }

    /// Like [`Pg::login`], with libpq checking the server certificate
    /// against `host` under `sslmode=verify-full`. `host` is a DNS name or
    /// an IP address. The connection goes to `127.0.0.1` through
    /// `hostaddr`, so no name is resolved.
    ///
    /// # Errors
    ///
    /// Returns the client's error output when the server or libpq refuses.
    pub(crate) fn login_to(
        &self,
        host: &str,
        role: &str,
        client: &ClientFiles<'_>,
    ) -> Result<String, String> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let cdir = self.dir.join(format!("client-{n}"));
        fs::create_dir(&cdir).map_err(|e| e.to_string())?;
        fs::set_permissions(&cdir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        write_private(&cdir.join("ca.pem"), client.ca_pem)?;
        write_private(&cdir.join("client.pem"), client.cert_pem)?;
        write_private(&cdir.join("client.key"), client.key_pem)?;
        let conninfo = format!(
            "host={host} hostaddr=127.0.0.1 port={port} user={role} dbname=postgres \
             sslmode=verify-full \
             sslrootcert={ca} sslcert={cert} sslkey={key}",
            port = self.port,
            ca = cdir.join("ca.pem").display(),
            cert = cdir.join("client.pem").display(),
            key = cdir.join("client.key").display(),
        );
        ok(Command::new(self.bin.join("psql"))
            .arg(conninfo)
            .env("PGPASSWORD", PASSWORD)
            .env_remove("PGSERVICEFILE")
            .args(["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"])
            .args(["-c", "SELECT current_user"]))
        .map(|s| s.trim().to_owned())
    }
}

impl Drop for Pg {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(self.data())
            .args(["-m", "immediate", "-w", "stop"])
            .output();
        let _ = fs::remove_dir_all(&self.dir);
    }
}
