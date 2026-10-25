//! Starting, sharing and stopping a PostgreSQL server for tests.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::tls;

/// The superuser that `initdb` creates.
const SUPERUSER: &str = "fstp_super";

/// The login role without special rights that every server has.
const APP_USER: &str = "fstp_app";

/// A login role on every test server.
///
/// Every role logs in with SCRAM and a client certificate from the trusted
/// test CA whose CN equals the role name (`clientcert=verify-full`, D2,
/// R-NF-09). The certificates are committed fixtures in
/// `crates/fstp-tls/testdata/`. The role names are fixed, so tests isolate
/// their data with [`PgServer::fresh_database`] and
/// [`PgServer::fresh_database_as`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// `fstp_super`, the superuser that `initdb` creates.
    Superuser,
    /// `fstp_app`, a login role without superuser, `CREATEDB`, `CREATEROLE`,
    /// replication or row security bypass rights.
    App,
}

impl Role {
    /// The role name, which is also the CN of its client certificate.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Role::Superuser => SUPERUSER,
            Role::App => APP_USER,
        }
    }

    /// The role's client certificate (PEM), issued by [`tls::CA_PEM`].
    #[must_use]
    pub fn client_cert_pem(self) -> &'static [u8] {
        match self {
            Role::Superuser => tls::SUPERUSER_CERT_PEM,
            Role::App => tls::APP_CERT_PEM,
        }
    }

    /// The private key of [`Role::client_cert_pem`] (PEM).
    #[must_use]
    pub fn client_key_pem(self) -> &'static [u8] {
        match self {
            Role::Superuser => tls::SUPERUSER_KEY_PEM,
            Role::App => tls::APP_KEY_PEM,
        }
    }
}

/// The only address the server listens on.
const HOST: &str = "127.0.0.1";

/// The subdirectory of the server directory that holds the superuser's
/// client certificate and key for `psql`. It belongs to the test process's
/// user, since `psql` runs as that user.
const CLIENT_DIR: &str = "client";

/// How many ports to try when another process takes the chosen port first.
const START_ATTEMPTS: u32 = 8;

/// How long [`PgServer`]'s destructor waits for the watchdog to finish.
const STOP_WAIT: Duration = Duration::from_secs(30);

/// The watchdog. It blocks until its standard input reaches end of file,
/// which happens when the test process exits in any way or drops the
/// [`PgServer`]. It then stops the server and deletes the directory.
///
/// `$1` is the temporary directory. The server is stopped with SIGQUIT
/// (immediate shutdown), then SIGKILL after ten seconds. The process name is
/// checked first, so a stale pid file never leads to killing an unrelated
/// process.
const WATCHDOG: &str = r#"
trap '' INT TERM HUP QUIT PIPE
dir="$1"
while IFS= read -r _line; do :; done
pidfile="$dir/data/postmaster.pid"
if [ -f "$pidfile" ]; then
  pid=""
  read -r pid < "$pidfile" || true
  case "$pid" in
    ''|*[!0-9]*) pid="" ;;
  esac
  if [ -n "$pid" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "postgres" ]; then
    kill -QUIT "$pid" 2>/dev/null
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 100 ]; do
      sleep 0.1
      i=$((i + 1))
    done
    kill -KILL "$pid" 2>/dev/null
  fi
fi
rm -rf -- "$dir"
"#;

/// A failure to locate, start or use the test server.
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn io(context: &str, e: &io::Error) -> Self {
        Self::new(format!("{context}: {e}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fstp-pgtest: {}", self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

/// How the server treats TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ServerTls {
    /// `ssl = on`, and `pg_hba.conf` has only `hostssl` lines, each with
    /// `clientcert=verify-full`. The default.
    #[default]
    Required,
    /// `ssl = on`, and `pg_hba.conf` also accepts unencrypted connections
    /// with `hostnossl` lines. A test-only configuration: the server answers
    /// an SSLRequest with `S`, but a client that skips TLS is accepted too.
    /// Its `hostssl` lines still require `clientcert=verify-full`.
    Optional,
    /// `ssl = off`, and `pg_hba.conf` accepts only unencrypted `host`
    /// connections. A test-only configuration: the server answers every
    /// SSLRequest with `N`, so a client that requires TLS must refuse it.
    Off,
}

impl ServerTls {
    fn index(self) -> usize {
        match self {
            ServerTls::Required => 0,
            ServerTls::Optional => 1,
            ServerTls::Off => 2,
        }
    }
}

/// Options for [`PgServer::start_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ServerOptions {
    /// How the server treats TLS. Default [`ServerTls::Required`].
    pub tls: ServerTls,
}

/// Connection parameters for one database on a test server.
///
/// The TLS trust anchor for every test server is [`tls::CA_PEM`]. The server
/// certificate is valid for the name in [`ConnParams::host`]. A TLS server
/// accepts the role only with [`ConnParams::client_cert_pem`] and
/// [`ConnParams::client_key_pem`] (D2, R-NF-09).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnParams {
    /// Always `127.0.0.1`.
    pub host: String,
    /// The server's TCP port.
    pub port: u16,
    /// The role to log in as.
    pub user: String,
    /// The role's password. Printable ASCII.
    pub password: String,
    /// The database name.
    pub dbname: String,
    /// The role's client certificate (PEM). Its CN equals [`ConnParams::user`].
    pub client_cert_pem: &'static [u8],
    /// The private key of [`ConnParams::client_cert_pem`] (PEM).
    pub client_key_pem: &'static [u8],
}

impl fmt::Debug for ConnParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("dbname", &self.dbname)
            .field("client_key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Who runs the PostgreSQL processes.
#[derive(Debug, Clone)]
enum RunAs {
    /// The test process's own user, which is not root.
    Current,
    /// Root runs the processes as `postgres` through `runuser`.
    Postgres { uid: u32, gid: u32 },
}

/// A running PostgreSQL server owned by this test process.
///
/// Dropping a `PgServer` stops the server and deletes its directory, and
/// waits for both. A server returned by [`PgServer::shared`] lives in a
/// static and is stopped by its watchdog when the process exits.
pub struct PgServer {
    bindir: PathBuf,
    dir: PathBuf,
    port: u16,
    password: String,
    app_password: String,
    tls: ServerTls,
    version: String,
    next_db: AtomicU64,
    watchdog: Mutex<Option<Child>>,
}

impl fmt::Debug for PgServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgServer")
            .field("dir", &self.dir)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

static SHARED: [OnceLock<Result<PgServer, Error>>; 3] =
    [OnceLock::new(), OnceLock::new(), OnceLock::new()];

impl PgServer {
    /// Starts a new server with the default options: TLS required, SCRAM
    /// only, loopback only, random port.
    ///
    /// # Errors
    ///
    /// Returns an error when the PostgreSQL binaries cannot be found or the
    /// server does not start. The message includes the end of the server
    /// log when one exists.
    pub fn start() -> Result<PgServer, Error> {
        Self::start_with(ServerOptions::default())
    }

    /// Starts a new server with `options`.
    ///
    /// # Errors
    ///
    /// As for [`PgServer::start`].
    pub fn start_with(options: ServerOptions) -> Result<PgServer, Error> {
        start(options)
    }

    /// The server shared by every test in this test binary, with the default
    /// options. It starts on first use.
    ///
    /// # Errors
    ///
    /// Returns the start error. Every later call returns the same error.
    pub fn shared() -> Result<&'static PgServer, Error> {
        Self::shared_with(ServerOptions::default())
    }

    /// The server with `options` shared by every test in this test binary.
    /// Each distinct option set gets its own server.
    ///
    /// # Errors
    ///
    /// Returns the start error. Every later call returns the same error.
    pub fn shared_with(options: ServerOptions) -> Result<&'static PgServer, Error> {
        let Some(slot) = SHARED.get(options.tls.index()) else {
            return Err(Error::new("no shared slot for these options"));
        };
        slot.get_or_init(|| start(options))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Creates a new, empty database owned by the superuser and returns
    /// parameters for the superuser to connect to it. Each call returns a
    /// different database.
    ///
    /// # Errors
    ///
    /// Returns an error when `psql` fails to create the database.
    pub fn fresh_database(&self) -> Result<ConnParams, Error> {
        self.fresh_database_as(Role::Superuser)
    }

    /// Creates a new, empty database owned by `role` and returns parameters
    /// for `role` to connect to it. Each call returns a different database.
    ///
    /// The owner may create objects in the database's `public` schema.
    /// Roles are shared by the whole server, so tests keep their data apart
    /// by database.
    ///
    /// # Errors
    ///
    /// Returns an error when `psql` fails to create the database.
    pub fn fresh_database_as(&self, role: Role) -> Result<ConnParams, Error> {
        let n = self.next_db.fetch_add(1, Ordering::Relaxed);
        let dbname = format!("fstp_test_{n}");
        self.psql(
            "postgres",
            &format!("CREATE DATABASE {dbname} OWNER {}", role.name()),
        )?;
        Ok(ConnParams {
            host: HOST.to_owned(),
            port: self.port,
            user: role.name().to_owned(),
            password: self.password(role).to_owned(),
            dbname,
            client_cert_pem: role.client_cert_pem(),
            client_key_pem: role.client_key_pem(),
        })
    }

    /// Runs `sql` with `psql` as the superuser in database `dbname` and
    /// returns the unaligned, tuples-only output. For test setup only.
    ///
    /// The SQL reaches `psql` through its standard input, never its command
    /// line. Any user can read a process's command line in
    /// `/proc/<pid>/cmdline`, so a password in the SQL must not go there.
    /// The superuser's password travels in the environment, which only the
    /// same user and root can read. `psql` runs the statements one at a
    /// time and stops at the first error.
    ///
    /// On a server with TLS, `psql` verifies the server certificate in full
    /// and presents the superuser's client certificate, like every other
    /// client (D2).
    ///
    /// # Errors
    ///
    /// Returns an error with `psql`'s standard error when it fails.
    pub fn psql(&self, dbname: &str, sql: &str) -> Result<String, Error> {
        let mut cmd = Command::new(self.bindir.join("psql"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("PGPASSWORD", &self.password);
        match self.tls {
            ServerTls::Required | ServerTls::Optional => {
                let client = self.dir.join(CLIENT_DIR);
                cmd.env("PGSSLMODE", "verify-full")
                    .env("PGSSLROOTCERT", self.dir.join("tls").join("ca.pem"))
                    .env("PGSSLCERT", client.join(format!("{SUPERUSER}.pem")))
                    .env("PGSSLKEY", client.join(format!("{SUPERUSER}-key.pem")));
            }
            ServerTls::Off => {
                cmd.env("PGSSLMODE", "disable");
            }
        }
        cmd.env("PGCONNECT_TIMEOUT", "10")
            .env("PGAPPNAME", "fstp-pgtest")
            .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
            .args(["-h", HOST, "-p", &self.port.to_string(), "-U", SUPERUSER])
            .args(["-d", dbname, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| Error::io("cannot run psql", &e))?;
        let Some(mut stdin) = child.stdin.take() else {
            return Err(Error::new("psql has no standard input"));
        };
        // A separate writer thread, so that a large script and a large
        // output cannot block each other on full pipes.
        let (written, out) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(sql.as_bytes()));
            let out = child.wait_with_output();
            (writer.join(), out)
        });
        let out = out.map_err(|e| Error::io("cannot run psql", &e))?;
        match written {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(Error::io("cannot write the SQL to psql", &e)),
            Err(_) => return Err(Error::new("the thread writing to psql failed")),
        }
        if !out.status.success() {
            return Err(Error::new(format!(
                "psql failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Always `127.0.0.1`.
    #[must_use]
    pub fn host(&self) -> &str {
        HOST
    }

    /// The server's TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The superuser's name.
    #[must_use]
    pub fn superuser(&self) -> &str {
        SUPERUSER
    }

    /// The superuser's random password.
    #[must_use]
    pub fn superuser_password(&self) -> &str {
        &self.password
    }

    /// The random password of `role`.
    #[must_use]
    pub fn password(&self, role: Role) -> &str {
        match role {
            Role::Superuser => &self.password,
            Role::App => &self.app_password,
        }
    }

    /// How this server treats TLS.
    #[must_use]
    pub fn tls(&self) -> ServerTls {
        self.tls
    }

    /// The output of `postgres --version`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The server's temporary directory. It holds the data directory, the
    /// server's TLS files, the superuser's client certificate for `psql`,
    /// the Unix socket and `server.log`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The directory the PostgreSQL binaries were taken from.
    #[must_use]
    pub fn bindir(&self) -> &Path {
        &self.bindir
    }

    /// The end of the server log, for diagnostics.
    #[must_use]
    pub fn log_tail(&self) -> String {
        log_tail(&self.dir.join("server.log"))
    }

    /// Stops the server, deletes its directory and waits for both.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for PgServer {
    fn drop(&mut self) {
        let child = self
            .watchdog
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(child) = child {
            stop_watchdog(child);
        }
    }
}

/// Closes the watchdog's standard input and waits for it to clean up.
fn stop_watchdog(mut child: Child) {
    drop(child.stdin.take());
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if start.elapsed() >= STOP_WAIT => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Finds the directory with `initdb`, `pg_ctl`, `postgres` and `psql`.
fn find_bindir() -> Result<PathBuf, Error> {
    let mut tried = Vec::new();
    if let Some(dir) = std::env::var_os("FSTP_PG_BIN") {
        let dir = PathBuf::from(dir);
        if has_binaries(&dir) {
            return Ok(dir);
        }
        return Err(Error::new(format!(
            "FSTP_PG_BIN={} does not contain initdb, pg_ctl, postgres and psql",
            dir.display()
        )));
    }
    if let Ok(out) = Command::new("pg_config")
        .arg("--bindir")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        && out.status.success()
    {
        let dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        if has_binaries(&dir) {
            return Ok(dir);
        }
        tried.push(dir.display().to_string());
    }
    let mut versions: Vec<(u32, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir("/usr/lib/postgresql") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(version) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let dir = entry.path().join("bin");
            if has_binaries(&dir) {
                versions.push((version, dir));
            }
        }
    }
    versions.sort();
    if let Some((_, dir)) = versions.pop() {
        return Ok(dir);
    }
    tried.push("/usr/lib/postgresql/*/bin".to_owned());
    Err(Error::new(format!(
        "PostgreSQL server binaries not found; set FSTP_PG_BIN (tried {})",
        tried.join(", ")
    )))
}

fn has_binaries(dir: &Path) -> bool {
    ["initdb", "pg_ctl", "postgres", "psql"]
        .iter()
        .all(|b| dir.join(b).is_file())
}

/// Runs a command and returns its trimmed standard output.
fn capture(cmd: &mut Command, what: &str) -> Result<String, Error> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::io(&format!("cannot run {what}"), &e))?;
    if !out.status.success() {
        return Err(Error::new(format!(
            "{what} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn parse_id(text: &str, what: &str) -> Result<u32, Error> {
    text.parse::<u32>()
        .map_err(|_| Error::new(format!("unexpected output from {what}")))
}

fn detect_run_as() -> Result<RunAs, Error> {
    let uid = parse_id(&capture(Command::new("id").arg("-u"), "id -u")?, "id -u")?;
    if uid != 0 {
        return Ok(RunAs::Current);
    }
    let uid = parse_id(
        &capture(
            Command::new("id").args(["-u", "postgres"]),
            "id -u postgres",
        )?,
        "id -u postgres",
    )?;
    let gid = parse_id(
        &capture(
            Command::new("id").args(["-g", "postgres"]),
            "id -g postgres",
        )?,
        "id -g postgres",
    )?;
    Ok(RunAs::Postgres { uid, gid })
}

/// Reads `n` bytes from `/dev/urandom` and returns them as lowercase hex.
fn random_hex(n: usize) -> Result<String, Error> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::io("cannot read /dev/urandom", &e))?;
    let mut out = String::with_capacity(n.saturating_mul(2));
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

/// Paths are written into `postgresql.conf` and shell arguments, so only a
/// conservative character set is accepted.
fn check_path_chars(path: &Path) -> Result<(), Error> {
    let ok = path.to_str().is_some_and(|s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    });
    if ok {
        Ok(())
    } else {
        Err(Error::new(format!(
            "temporary directory path {} contains unsupported characters; set TMPDIR",
            path.display()
        )))
    }
}

fn chown(path: &Path, run_as: &RunAs) -> Result<(), Error> {
    if let RunAs::Postgres { uid, gid } = run_as {
        std::os::unix::fs::chown(path, Some(*uid), Some(*gid))
            .map_err(|e| Error::io(&format!("cannot chown {}", path.display()), &e))?;
    }
    Ok(())
}

/// Writes `contents` to a new file with mode `mode`, owned by the server user.
fn write_private(path: &Path, contents: &[u8], mode: u32, run_as: &RunAs) -> Result<(), Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| Error::io(&format!("cannot create {}", path.display()), &e))?;
    f.write_all(contents)
        .map_err(|e| Error::io(&format!("cannot write {}", path.display()), &e))?;
    // The umask may have removed bits; set the mode explicitly.
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(&format!("cannot chmod {}", path.display()), &e))?;
    chown(path, run_as)
}

/// A command for a PostgreSQL binary, run as the server user.
fn pg_command(bindir: &Path, bin: &str, run_as: &RunAs, cwd: &Path) -> Command {
    let mut cmd = match run_as {
        RunAs::Current => Command::new(bindir.join(bin)),
        RunAs::Postgres { .. } => {
            let mut c = Command::new("runuser");
            c.args(["-u", "postgres", "--"]).arg(bindir.join(bin));
            c
        }
    };
    cmd.current_dir(cwd).env("LC_ALL", "C").stdin(Stdio::null());
    cmd
}

fn log_tail(path: &Path) -> String {
    let text = fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(30);
    lines.get(skip..).unwrap_or_default().join("\n")
}

/// Picks a port that is free right now. Another process can still take it
/// before the server binds, so the caller retries on a bind failure.
fn free_port() -> Result<u16, Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| Error::io("cannot bind a probe socket", &e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::io("cannot read the probe socket address", &e))?
        .port();
    Ok(port)
}

/// Holds the watchdog until the server is fully set up. On an early error
/// it is dropped, which stops whatever was started and deletes the
/// directory.
struct Guard {
    child: Option<Child>,
}

impl Guard {
    fn take(mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            stop_watchdog(child);
        }
    }
}

fn spawn_watchdog(dir: &Path) -> Result<Child, Error> {
    let bash = if Path::new("/bin/bash").is_file() {
        "/bin/bash"
    } else {
        "bash"
    };
    let child = Command::new(bash)
        .arg("-c")
        .arg(WATCHDOG)
        .arg("fstp-pgtest-watchdog")
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Its own process group: a signal to the test's group, such as a
        // Ctrl-C or a CI timeout, must not stop it before it cleans up.
        .process_group(0)
        .spawn()
        .map_err(|e| Error::io("cannot start the watchdog", &e))?;
    Ok(child)
}

fn server_conf(dir: &Path, tls_on: bool) -> String {
    let d = dir.display();
    let ssl = if tls_on { "on" } else { "off" };
    format!(
        "\n# Added by fstp-pgtest.\n\
         listen_addresses = '{HOST}'\n\
         unix_socket_directories = '{d}'\n\
         unix_socket_permissions = 0700\n\
         ssl = {ssl}\n\
         ssl_cert_file = '{d}/tls/server.pem'\n\
         ssl_key_file = '{d}/tls/server-key.pem'\n\
         ssl_ca_file = '{d}/tls/ca.pem'\n\
         ssl_min_protocol_version = 'TLSv1.3'\n\
         password_encryption = 'scram-sha-256'\n\
         fsync = off\n\
         synchronous_commit = off\n\
         full_page_writes = off\n\
         max_connections = 100\n\
         shared_buffers = '32MB'\n\
         logging_collector = off\n\
         log_connections = off\n\
         log_disconnections = off\n\
         log_statement = 'none'\n"
    )
}

/// `pg_hba.conf`. Every `hostssl` line requires SCRAM and a client
/// certificate from the test CA whose CN equals the role name
/// (`clientcert=verify-full`, D2, R-NF-09). Only the negative-test
/// configurations accept unencrypted connections.
fn hba_conf(tls: ServerTls) -> String {
    let mut out = String::from("# Written by fstp-pgtest.\n");
    let hostssl = format!("hostssl all all {HOST}/32 scram-sha-256 clientcert=verify-full\n");
    match tls {
        ServerTls::Required => out.push_str(&hostssl),
        ServerTls::Optional => {
            out.push_str(&hostssl);
            out.push_str(&format!("hostnossl all all {HOST}/32 scram-sha-256\n"));
        }
        ServerTls::Off => {
            out.push_str(&format!("host all all {HOST}/32 scram-sha-256\n"));
        }
    }
    out
}

fn start(options: ServerOptions) -> Result<PgServer, Error> {
    let bindir = find_bindir()?;
    let run_as = detect_run_as()?;
    let version = capture(
        Command::new(bindir.join("postgres")).arg("--version"),
        "postgres --version",
    )?;

    let base = std::env::temp_dir();
    let dir = base.join(format!(
        "fstp-pgtest-{}-{}",
        std::process::id(),
        random_hex(6)?
    ));
    check_path_chars(&dir)?;
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::io(&format!("cannot create {}", dir.display()), &e))?;
    // The watchdog exists from here on, so even a failure in the next steps
    // leaves nothing behind.
    let guard = match spawn_watchdog(&dir) {
        Ok(child) => Guard { child: Some(child) },
        Err(e) => {
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    chown(&dir, &run_as)?;

    let password = random_hex(24)?;
    let app_password = random_hex(24)?;

    // initdb with a random superuser password and SCRAM for every method.
    let pwfile = dir.join("pwfile");
    write_private(&pwfile, password.as_bytes(), 0o600, &run_as)?;
    let data = dir.join("data");
    let mut initdb = pg_command(&bindir, "initdb", &run_as, &dir);
    initdb
        .arg("-D")
        .arg(&data)
        .args(["-U", SUPERUSER, "--auth=scram-sha-256"])
        .arg(format!("--pwfile={}", pwfile.display()))
        .args([
            "--encoding=UTF8",
            "--locale=C",
            "--no-sync",
            "--no-instructions",
        ]);
    capture(&mut initdb, "initdb")?;
    fs::remove_file(&pwfile).map_err(|e| Error::io("cannot remove the password file", &e))?;

    // TLS material, readable only by the server user.
    let tls_dir = dir.join("tls");
    DirBuilder::new()
        .mode(0o700)
        .create(&tls_dir)
        .map_err(|e| Error::io("cannot create the TLS directory", &e))?;
    chown(&tls_dir, &run_as)?;
    write_private(
        &tls_dir.join("server.pem"),
        tls::SERVER_CERT_PEM,
        0o600,
        &run_as,
    )?;
    write_private(
        &tls_dir.join("server-key.pem"),
        tls::SERVER_KEY_PEM,
        0o600,
        &run_as,
    )?;
    write_private(&tls_dir.join("ca.pem"), tls::CA_PEM, 0o600, &run_as)?;

    // The superuser's client certificate and key for psql, which runs as
    // the test process's user. libpq refuses a key that others can read.
    let client_dir = dir.join(CLIENT_DIR);
    DirBuilder::new()
        .mode(0o700)
        .create(&client_dir)
        .map_err(|e| Error::io("cannot create the client certificate directory", &e))?;
    write_private(
        &client_dir.join(format!("{SUPERUSER}.pem")),
        Role::Superuser.client_cert_pem(),
        0o600,
        &RunAs::Current,
    )?;
    write_private(
        &client_dir.join(format!("{SUPERUSER}-key.pem")),
        Role::Superuser.client_key_pem(),
        0o600,
        &RunAs::Current,
    )?;

    let tls_on = !matches!(options.tls, ServerTls::Off);
    let mut conf = OpenOptions::new()
        .append(true)
        .open(data.join("postgresql.conf"))
        .map_err(|e| Error::io("cannot open postgresql.conf", &e))?;
    conf.write_all(server_conf(&dir, tls_on).as_bytes())
        .map_err(|e| Error::io("cannot write postgresql.conf", &e))?;
    drop(conf);
    fs::write(data.join("pg_hba.conf"), hba_conf(options.tls))
        .map_err(|e| Error::io("cannot write pg_hba.conf", &e))?;

    let log = dir.join("server.log");
    let port = start_on_free_port(&bindir, &run_as, &dir, &data, &log)?;

    let server = PgServer {
        bindir,
        dir,
        port,
        password,
        app_password,
        tls: options.tls,
        version,
        next_db: AtomicU64::new(1),
        watchdog: Mutex::new(guard.take()),
    };
    server.psql("postgres", &app_role_sql(&server.app_password))?;
    Ok(server)
}

/// The statement that creates the [`Role::App`] role. It holds the
/// password, so it goes to psql through standard input only. The password
/// is hex, so it needs no quoting beyond the literal.
fn app_role_sql(password: &str) -> String {
    format!(
        "CREATE ROLE {APP_USER} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
         NOREPLICATION NOBYPASSRLS PASSWORD '{password}'"
    )
}

fn start_on_free_port(
    bindir: &Path,
    run_as: &RunAs,
    dir: &Path,
    data: &Path,
    log: &Path,
) -> Result<u16, Error> {
    let mut last = String::new();
    for _ in 0..START_ATTEMPTS {
        let port = free_port()?;
        let mut pg_ctl = pg_command(bindir, "pg_ctl", run_as, dir);
        pg_ctl
            .arg("-D")
            .arg(data)
            .arg("-l")
            .arg(log)
            .args(["-w", "-t", "60", "-s", "-o"])
            .arg(format!("-p {port}"))
            .arg("start");
        let out = pg_ctl
            .output()
            .map_err(|e| Error::io("cannot run pg_ctl", &e))?;
        if out.status.success() {
            return Ok(port);
        }
        let tail = log_tail(log);
        if tail.contains("could not bind") || tail.contains("already in use") {
            last = tail;
            continue;
        }
        return Err(Error::new(format!(
            "pg_ctl start failed ({}): {}\nserver log:\n{tail}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Err(Error::new(format!(
        "no free port after {START_ATTEMPTS} attempts\nserver log:\n{last}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hba_required_has_only_hostssl_lines() {
        let hba = hba_conf(ServerTls::Required);
        for line in hba.lines().filter(|l| !l.starts_with('#')) {
            assert!(line.starts_with("hostssl "), "unexpected line: {line}");
            assert!(line.contains(" scram-sha-256"), "not SCRAM: {line}");
        }
    }

    /// R-NF-09, D2: every hostssl line, in every configuration that allows
    /// TLS, requires a client certificate whose CN equals the role.
    #[test]
    fn r_nf_09_d2_every_hostssl_line_requires_verify_full() {
        for tls in [ServerTls::Required, ServerTls::Optional] {
            let hba = hba_conf(tls);
            let hostssl: Vec<&str> = hba.lines().filter(|l| l.starts_with("hostssl")).collect();
            assert!(!hostssl.is_empty(), "{tls:?}");
            for line in hostssl {
                assert!(
                    line.ends_with(" scram-sha-256 clientcert=verify-full"),
                    "{tls:?}: {line}"
                );
            }
        }
        // Only the negative-test configurations accept plaintext.
        assert!(!hba_conf(ServerTls::Required).contains("nossl"));
        assert!(hba_conf(ServerTls::Optional).contains("hostnossl all all"));
    }

    #[test]
    fn hba_off_has_no_tls_lines() {
        let hba = hba_conf(ServerTls::Off);
        assert!(!hba.contains("hostssl"));
        assert!(hba.contains("host all all 127.0.0.1/32 scram-sha-256"));
    }

    #[test]
    fn conf_switches_ssl() {
        let dir = Path::new("/tmp/x");
        assert!(server_conf(dir, true).contains("ssl = on\n"));
        assert!(server_conf(dir, false).contains("ssl = off\n"));
        assert!(server_conf(dir, true).contains("password_encryption = 'scram-sha-256'"));
        assert!(server_conf(dir, true).contains("fsync = off"));
    }

    #[test]
    fn path_check_rejects_quotes() {
        assert!(check_path_chars(Path::new("/tmp/fstp-pgtest-1-ab")).is_ok());
        assert!(check_path_chars(Path::new("/tmp/it's")).is_err());
        assert!(check_path_chars(Path::new("/tmp/a b")).is_err());
    }

    #[test]
    fn random_hex_has_expected_length() {
        let a = random_hex(24).unwrap();
        let b = random_hex(24).unwrap();
        assert_eq!(a.len(), 48);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn conn_params_debug_hides_password() {
        let p = ConnParams {
            host: HOST.to_owned(),
            port: 1,
            user: "u".to_owned(),
            password: "secret-value".to_owned(),
            dbname: "d".to_owned(),
            client_cert_pem: Role::App.client_cert_pem(),
            client_key_pem: Role::App.client_key_pem(),
        };
        let shown = format!("{p:?}");
        assert!(!shown.contains("secret-value"), "{shown}");
        assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    }

    #[test]
    fn role_names_and_certificates_belong_together() {
        assert_eq!(Role::Superuser.name(), "fstp_super");
        assert_eq!(Role::App.name(), "fstp_app");
        for role in [Role::Superuser, Role::App] {
            assert!(
                role.client_cert_pem()
                    .starts_with(b"-----BEGIN CERTIFICATE-----")
            );
            assert!(
                role.client_key_pem()
                    .starts_with(b"-----BEGIN PRIVATE KEY-----")
            );
        }
        assert_ne!(
            Role::Superuser.client_cert_pem(),
            Role::App.client_cert_pem()
        );
    }
}
