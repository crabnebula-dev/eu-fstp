//! Connection configuration.

use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::proto::backend::DecodeLimits;

/// Longest accepted password, in bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Longest accepted user, database or application name, in bytes.
pub const MAX_NAME_LEN: usize = 1024;

/// The default floor for the SCRAM iteration count. RFC 7677 recommends at
/// least 4096 iterations.
pub const DEFAULT_MIN_SCRAM_ITERATIONS: NonZeroU32 = match NonZeroU32::new(4096) {
    Some(n) => n,
    None => NonZeroU32::MIN,
};

/// A password for SCRAM or, when explicitly allowed, cleartext
/// authentication.
///
/// Only printable ASCII (0x20 to 0x7E) is accepted, 1 to
/// [`MAX_PASSWORD_LEN`] bytes. SCRAM applies SASLprep (RFC 4013) to the
/// password on both sides. On printable ASCII, SASLprep is the identity
/// mapping, so the client's key always matches the server's without an
/// in-house SASLprep implementation. Other passwords are rejected with a
/// clear error instead of risking a silent mismatch.
///
/// [`fmt::Debug`] never shows the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    /// Validates and wraps a password.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Config`](crate::ErrorKind::Config) error when
    /// the password is empty, too long, or contains anything outside
    /// printable ASCII.
    pub fn new(password: impl Into<String>) -> Result<Password, Error> {
        let password = password.into();
        if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
            return Err(Error::config(format!(
                "password must be 1 to {MAX_PASSWORD_LEN} bytes long"
            )));
        }
        if !password.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::config(
                "password must be printable ASCII (0x20 to 0x7E): SASLprep is the identity \
                 mapping only on that set, so other passwords could silently fail to match",
            ));
        }
        Ok(Password(password))
    }

    /// The password bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// An authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// SCRAM-SHA-256-PLUS with `tls-server-end-point` channel binding.
    ScramSha256Plus,
    /// SCRAM-SHA-256 without channel binding.
    ScramSha256,
    /// A cleartext password sent inside TLS.
    Password,
    /// No authentication: the server accepted the connection without
    /// asking for a password.
    None,
}

impl AuthMethod {
    fn bit(self) -> u8 {
        match self {
            AuthMethod::ScramSha256Plus => 1,
            AuthMethod::ScramSha256 => 2,
            AuthMethod::Password => 4,
            AuthMethod::None => 8,
        }
    }
}

/// The set of authentication methods the client accepts.
///
/// The default accepts SCRAM-SHA-256-PLUS and SCRAM-SHA-256 only. Cleartext
/// passwords and unauthenticated connections are rejected unless added
/// explicitly. MD5, Kerberos, GSSAPI and SSPI are never supported: MD5 is
/// broken, and the others have no implementation here.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequireAuth(u8);

impl RequireAuth {
    /// SCRAM with or without channel binding. The default.
    pub const SCRAM: RequireAuth = RequireAuth(1 | 2);
    /// SCRAM with channel binding only.
    pub const SCRAM_PLUS_ONLY: RequireAuth = RequireAuth(1);

    /// A set with exactly the given methods.
    #[must_use]
    pub fn only(methods: &[AuthMethod]) -> RequireAuth {
        RequireAuth(methods.iter().fold(0, |acc, m| acc | m.bit()))
    }

    /// This set plus `method`.
    #[must_use]
    pub fn with(self, method: AuthMethod) -> RequireAuth {
        RequireAuth(self.0 | method.bit())
    }

    /// True when `method` is in the set.
    #[must_use]
    pub fn allows(self, method: AuthMethod) -> bool {
        self.0 & method.bit() != 0
    }
}

impl Default for RequireAuth {
    fn default() -> Self {
        RequireAuth::SCRAM
    }
}

impl fmt::Debug for RequireAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let all = [
            AuthMethod::ScramSha256Plus,
            AuthMethod::ScramSha256,
            AuthMethod::Password,
            AuthMethod::None,
        ];
        f.debug_set()
            .entries(all.iter().filter(|m| self.allows(**m)))
            .finish()
    }
}

/// Resource limits for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest message body accepted after authentication. Default 64 MiB.
    /// A larger message marks the connection broken.
    pub max_message_len: usize,
    /// Largest message body accepted before authentication completes.
    /// Default 16 KiB.
    pub max_startup_message_len: usize,
    /// Largest amount of memory, approximately, that `query` holds for
    /// collected rows. Default 256 MiB. Each row counts its slot in the
    /// result vector, its buffers and their allocator overhead. Many small
    /// rows therefore reach the limit long before their wire size does.
    /// The rest of the result is read and discarded, so the connection
    /// stays usable. Use a row stream for larger results.
    pub max_result_bytes: usize,
    /// Largest number of columns in a result. Default 1664, the server's
    /// own maximum.
    pub max_columns: usize,
    /// Largest number of parameters in a statement description. Default
    /// 65535, the protocol's maximum.
    pub max_parameters: usize,
    /// Smallest SCRAM iteration count accepted from the server. Default
    /// 4096, as RFC 7677 recommends. A server that asks for fewer makes an
    /// offline guess at the password cheap, so the client refuses it before
    /// sending a proof. The type rules out 0.
    pub min_scram_iterations: NonZeroU32,
    /// Largest SCRAM iteration count accepted from the server. Default
    /// 1 000 000. The server chooses the count, so this bounds the CPU time
    /// a misconfigured server can demand.
    pub max_scram_iterations: u32,
    /// Largest number of distinct run-time parameters remembered from
    /// ParameterStatus messages. Default 256.
    pub max_server_parameters: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_len: 64 << 20,
            max_startup_message_len: 16 << 10,
            max_result_bytes: 256 << 20,
            max_columns: 1664,
            max_parameters: 65_535,
            min_scram_iterations: DEFAULT_MIN_SCRAM_ITERATIONS,
            max_scram_iterations: 1_000_000,
            max_server_parameters: 256,
        }
    }
}

impl Limits {
    pub(crate) fn decode(&self) -> DecodeLimits {
        DecodeLimits {
            max_message_len: self.max_message_len,
            max_columns: self.max_columns,
            max_parameters: self.max_parameters,
        }
    }

    pub(crate) fn decode_startup(&self) -> DecodeLimits {
        DecodeLimits {
            max_message_len: self.max_startup_message_len,
            max_columns: self.max_columns,
            max_parameters: self.max_parameters,
        }
    }
}

/// A check of the server's leaf certificate that every connection of a
/// [`Config`] runs ([`Config::server_check`]).
///
/// It receives the DER of the leaf certificate that fstp-tls verified in
/// the TLS handshake, and returns `true` to accept the server. It runs
/// after the handshake and before the startup message, on every
/// connection and every cancel connection opened over the configuration.
/// So a server it refuses never sees the user name, the database name, a
/// SCRAM message or a cancellation key. A caller pins the server identity
/// it checked at start this way, for example the cluster kind OU and the
/// registered SPKI of I-83 (M3 design section 9.2).
///
/// The check must not block: it runs inside the connect future.
/// [`fmt::Debug`] shows no detail of the check.
#[derive(Clone)]
pub struct ServerCheck(Arc<AcceptsLeaf>);

/// The predicate a [`ServerCheck`] holds.
type AcceptsLeaf = dyn Fn(&[u8]) -> bool + Send + Sync;

impl ServerCheck {
    /// A check that accepts the server whose leaf certificate DER makes
    /// `accepts` return `true`.
    pub fn new<F>(accepts: F) -> ServerCheck
    where
        F: Fn(&[u8]) -> bool + Send + Sync + 'static,
    {
        ServerCheck(Arc::new(accepts))
    }

    /// Whether the check accepts the server leaf certificate `cert_der`.
    #[must_use]
    pub fn accepts(&self, cert_der: &[u8]) -> bool {
        (self.0)(cert_der)
    }
}

impl fmt::Debug for ServerCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerCheck(..)")
    }
}

/// Whether every check of `checks` accepts the leaf `cert_der`. A refusal
/// is an [`ErrorKind::ServerRefused`] error.
pub(crate) fn run_server_checks(checks: &[ServerCheck], cert_der: &[u8]) -> Result<(), Error> {
    if checks.iter().all(|c| c.accepts(cert_der)) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::ServerRefused,
            "the server certificate failed a server check of the configuration",
        ))
    }
}

/// Everything needed to open a connection.
///
/// Mutual TLS with full verification is not optional: [`Config::new`]
/// takes a [`ClientTls`] with the role's client certificate, and
/// [`Client::connect`](crate::Client::connect) refuses servers that decline
/// TLS (D2, R-NF-09). The server name for certificate verification is the
/// host unless [`Config::tls_server_name`] overrides it.
///
/// [`fmt::Debug`] never shows the password.
#[derive(Clone)]
pub struct Config {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: Password,
    pub(crate) dbname: String,
    pub(crate) application_name: Option<String>,
    pub(crate) tls: ClientTls,
    pub(crate) tls_server_name: Option<String>,
    pub(crate) require_auth: RequireAuth,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) statement_timeout: Option<Duration>,
    pub(crate) cancel_grace: Duration,
    pub(crate) statement_cache_capacity: usize,
    pub(crate) limits: Limits,
    pub(crate) server_checks: Vec<ServerCheck>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password)
            .field("dbname", &self.dbname)
            .field("application_name", &self.application_name)
            .field("tls", &self.tls)
            .field("tls_server_name", &self.tls_server_name)
            .field("require_auth", &self.require_auth)
            .field("connect_timeout", &self.connect_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("cancel_grace", &self.cancel_grace)
            .field("statement_cache_capacity", &self.statement_cache_capacity)
            .field("limits", &self.limits)
            .field("server_checks", &self.server_checks.len())
            .finish()
    }
}

fn check_name(value: &str, what: &str, allow_empty: bool) -> Result<(), Error> {
    if (!allow_empty && value.is_empty()) || value.len() > MAX_NAME_LEN {
        return Err(Error::config(format!(
            "{what} must be 1 to {MAX_NAME_LEN} bytes long"
        )));
    }
    if value.contains('\0') {
        return Err(Error::config(format!("{what} contains a NUL character")));
    }
    Ok(())
}

/// The TLS settings of a database connection: the trust roots that verify
/// the server certificate, and the role's client certificate and key.
///
/// Every database connection is mutually authenticated (D2, R-NF-09). The
/// server checks the client certificate with `clientcert=verify-full`, so
/// its CN must equal the role given to [`Config::new`]. SCRAM still runs
/// on top. [`ClientTls::new`] is the only constructor and requires a
/// certificate and key. A [`Config`] without them therefore cannot exist,
/// and [`Client::connect`](crate::Client::connect) never connects without
/// one.
///
/// Cheap to clone. [`fmt::Debug`] shows no key material.
#[derive(Clone)]
pub struct ClientTls {
    inner: fstp_tls::ClientConfig,
}

impl fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTls")
            .field("client_certificate", &true)
            .finish_non_exhaustive()
    }
}

/// True when `pem` holds nothing but ASCII whitespace.
fn is_blank(pem: &[u8]) -> bool {
    pem.iter().all(u8::is_ascii_whitespace)
}

impl ClientTls {
    /// Trusts the CA certificates in `roots_pem` for the server, and
    /// presents the certificate chain `client_cert_pem` (leaf first) with
    /// the private key `client_key_pem`.
    ///
    /// The leaf's CN must equal the database role. The server enforces
    /// that; a mismatch fails the login.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Config`](crate::ErrorKind::Config) error when
    /// the client certificate or key is missing, when any PEM input is
    /// invalid, or when the key does not match the certificate. The message
    /// never quotes key material.
    pub fn new(
        roots_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
    ) -> Result<ClientTls, Error> {
        if is_blank(client_cert_pem) {
            return Err(Error::config(
                "no client certificate: every database connection uses mutual TLS (D2, R-NF-09), \
                 so a certificate whose CN is the database role is required",
            ));
        }
        if is_blank(client_key_pem) {
            return Err(Error::config(
                "no client private key: every database connection uses mutual TLS (D2, R-NF-09), \
                 so the key of the role's client certificate is required",
            ));
        }
        let inner = fstp_tls::ClientConfig::mutual(roots_pem, client_cert_pem, client_key_pem)
            .map_err(|e| Error::with_source(ErrorKind::Config, "client TLS settings", e))?;
        Ok(ClientTls { inner })
    }

    /// The fstp-tls configuration, for example to run
    /// [`tls_handshake`](crate::tls_handshake) over a transport the caller
    /// owns. It always presents the client certificate.
    #[must_use]
    pub fn fstp_tls_config(&self) -> &fstp_tls::ClientConfig {
        &self.inner
    }
}

impl Config {
    /// A configuration for `user` with `password` on database `dbname` at
    /// `host:port`, with the TLS settings `tls`.
    ///
    /// The server certificate is verified in full against the roots in
    /// `tls`, and the client certificate in `tls` is presented on every
    /// connection (D2, R-NF-09). Its CN must equal `user`.
    ///
    /// Defaults: connect timeout 10 seconds, no statement timeout, cancel
    /// grace 5 seconds, 256 cached statements, SCRAM only, default
    /// [`Limits`].
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Config`](crate::ErrorKind::Config) error when
    /// a name is empty, too long or contains NUL.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        password: Password,
        dbname: impl Into<String>,
        tls: ClientTls,
    ) -> Result<Config, Error> {
        let host = host.into();
        let user = user.into();
        let dbname = dbname.into();
        check_name(&host, "host", false)?;
        check_name(&user, "user", false)?;
        check_name(&dbname, "database name", false)?;
        Ok(Config {
            host,
            port,
            user,
            password,
            dbname,
            application_name: None,
            tls,
            tls_server_name: None,
            require_auth: RequireAuth::default(),
            connect_timeout: Some(Duration::from_secs(10)),
            statement_timeout: None,
            cancel_grace: Duration::from_secs(5),
            statement_cache_capacity: 256,
            limits: Limits::default(),
            server_checks: Vec::new(),
        })
    }

    /// Sets `application_name`, which the server shows in `pg_stat_activity`.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is too long or contains NUL.
    pub fn application_name(mut self, name: impl Into<String>) -> Result<Config, Error> {
        let name = name.into();
        check_name(&name, "application name", true)?;
        self.application_name = Some(name);
        Ok(self)
    }

    /// Verifies the server certificate against `name` instead of the host.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is empty, too long or contains NUL.
    pub fn tls_server_name(mut self, name: impl Into<String>) -> Result<Config, Error> {
        let name = name.into();
        check_name(&name, "TLS server name", false)?;
        self.tls_server_name = Some(name);
        Ok(self)
    }

    /// Sets the accepted authentication methods.
    #[must_use]
    pub fn require_auth(mut self, methods: RequireAuth) -> Config {
        self.require_auth = methods;
        self
    }

    /// Bounds TCP connect, TLS handshake and authentication together.
    /// `None` waits without limit.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Config {
        self.connect_timeout = timeout;
        self
    }

    /// Bounds each statement. When it passes, the client sends a
    /// CancelRequest and waits up to the cancel grace for the server to
    /// finish the statement. If that fails too, the connection is broken.
    #[must_use]
    pub fn statement_timeout(mut self, timeout: Option<Duration>) -> Config {
        self.statement_timeout = timeout;
        self
    }

    /// How long recovery after a statement timeout may take.
    #[must_use]
    pub fn cancel_grace(mut self, grace: Duration) -> Config {
        self.cancel_grace = grace;
        self
    }

    /// How many prepared statements to keep per connection. 0 disables the
    /// cache: every statement is prepared unnamed and parsed again.
    #[must_use]
    pub fn statement_cache_capacity(mut self, capacity: usize) -> Config {
        self.statement_cache_capacity = capacity;
        self
    }

    /// Replaces the resource limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Config {
        self.limits = limits;
        self
    }

    /// Adds `check` to the checks of the server's verified leaf
    /// certificate ([`ServerCheck`]). Every connection and every cancel
    /// connection over this configuration, and over its clones, runs
    /// every check added. A connection whose server any check refuses
    /// fails with [`ErrorKind::ServerRefused`] before the startup message
    /// is sent. A later call never removes an earlier check.
    #[must_use]
    pub fn server_check(mut self, check: ServerCheck) -> Config {
        self.server_checks.push(check);
        self
    }

    /// The number of server checks this configuration runs on every
    /// connection ([`Config::server_check`]).
    #[must_use]
    pub fn server_check_count(&self) -> usize {
        self.server_checks.len()
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The user.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The database name.
    #[must_use]
    pub fn dbname(&self) -> &str {
        &self.dbname
    }

    /// The name used to verify the server certificate.
    #[must_use]
    pub fn server_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.host)
    }

    /// The TLS settings.
    #[must_use]
    pub fn tls(&self) -> &ClientTls {
        &self.tls
    }

    /// The accepted authentication methods.
    #[must_use]
    pub fn allowed_auth(&self) -> RequireAuth {
        self.require_auth
    }

    /// The resource limits.
    #[must_use]
    pub fn get_limits(&self) -> &Limits {
        &self.limits
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_printable_ascii_only() {
        assert!(Password::new("correct horse battery staple!~").is_ok());
        assert!(Password::new("").is_err());
        assert!(Password::new("caf\u{e9}").is_err());
        assert!(Password::new("tab\there").is_err());
        assert!(Password::new("x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
        assert!(Password::new("x".repeat(MAX_PASSWORD_LEN)).is_ok());
    }

    #[test]
    fn password_debug_is_redacted() {
        let p = Password::new("hunter2").unwrap();
        assert_eq!(format!("{p:?}"), "Password(<redacted>)");
    }

    /// The SCRAM iteration floor follows RFC 7677 by default.
    #[test]
    fn review_pg_scram_no_min_iterations_default() {
        let l = Limits::default();
        assert_eq!(l.min_scram_iterations.get(), 4096);
        assert!(l.max_scram_iterations >= l.min_scram_iterations.get());
    }

    const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
    const CERT: &[u8] = include_bytes!("../../fstp-tls/testdata/role-fstp_app.pem");
    const KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/role-fstp_app-key.pem");
    const OTHER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/role-fstp_super-key.pem");

    /// R-NF-09, D2: TLS settings without a client certificate or key are a
    /// configuration error. No [`Config`] can exist without them, so
    /// `Client::connect` never connects without mutual TLS.
    #[test]
    fn r_nf_09_d2_client_tls_requires_a_certificate_and_key() {
        let cases: [(&[u8], &[u8], &str); 4] = [
            (b"", KEY, "no client certificate"),
            (b" \r\n\t", KEY, "no client certificate"),
            (CERT, b"", "no client private key"),
            (CERT, b"\n", "no client private key"),
        ];
        for (cert, key, expected) in cases {
            let err = ClientTls::new(CA, cert, key).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config, "{err}");
            let shown = err.to_string();
            assert!(shown.contains(expected), "{shown}");
            assert!(shown.contains("mutual TLS"), "{shown}");
        }
        // Invalid input and a key of another certificate fail too, and the
        // error never quotes key material.
        for (cert, key) in [
            (&b"not a certificate"[..], KEY),
            (CERT, b"not a key"),
            (CERT, OTHER_KEY),
        ] {
            let err = ClientTls::new(CA, cert, key).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config, "{err}");
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("PRIVATE KEY"), "{shown}");
        }
        let tls = ClientTls::new(CA, CERT, KEY).unwrap();
        assert!(!format!("{tls:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn require_auth_sets() {
        let d = RequireAuth::default();
        assert!(d.allows(AuthMethod::ScramSha256Plus));
        assert!(d.allows(AuthMethod::ScramSha256));
        assert!(!d.allows(AuthMethod::Password));
        assert!(!d.allows(AuthMethod::None));
        let p = RequireAuth::SCRAM_PLUS_ONLY.with(AuthMethod::Password);
        assert!(p.allows(AuthMethod::Password));
        assert!(!p.allows(AuthMethod::ScramSha256));
        assert_eq!(
            RequireAuth::only(&[AuthMethod::ScramSha256Plus]),
            RequireAuth::SCRAM_PLUS_ONLY
        );
    }
}
