//! The protocol state machine over an established transport.
//!
//! A [`Session`] runs startup, authentication and the extended query
//! protocol over any [`Connection`]. It needs no runtime: timers, TCP and
//! TLS belong to [`Client`](crate::Client), which wraps a session.
//!
//! # Drop safety
//!
//! Every operation is a future that may be dropped at any await point.
//!
//! - A request dropped while its messages were being written leaves a
//!   partial message on the wire. The session notices and marks itself
//!   broken.
//! - A request dropped while its responses were being read leaves the
//!   session waiting for ReadyForQuery. The next operation first reads and
//!   discards the rest of those responses.
//!
//! # Transport security
//!
//! [`Session::startup`] trusts the transport it is given. It is the
//! building block of [`Client::connect`](crate::Client::connect), which
//! always establishes TLS with full verification first. Pass a transport
//! without TLS only in tests and fuzzing; channel binding and cleartext
//! passwords are then unavailable.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use fstp_rt::{Connection, IoExt};

use crate::config::{AuthMethod, Config, Limits};
use crate::error::{DbError, Error, ErrorKind};
use crate::proto::backend::{
    Authentication, BackendDecoder, BackendMessage, ErrorFields, RETAINED_BUFFER_CAPACITY,
    SHRINK_BUFFER_ABOVE, TransactionStatus,
};
use crate::proto::frontend::{self, BindWriter, Target};
use crate::row::{Column, Row, Statement, StatementInner};
use crate::scram::{ChannelBinding, SCRAM_SHA_256, SCRAM_SHA_256_PLUS, ScramClient};
use crate::types::{IsNull, ToSql, Type};

/// Size of the buffer each transport read fills.
const READ_CHUNK: usize = 64 << 10;

/// Fewest row slots `query` adds when its result vector grows.
const MIN_ROWS_GROWTH: usize = 16;

/// The cancellation key of a session: the backend process id and the secret
/// key from BackendKeyData. [`fmt::Debug`] hides the secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BackendKey {
    /// The backend process id.
    pub process_id: i32,
    /// The secret key.
    pub(crate) secret_key: i32,
}

impl fmt::Debug for BackendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendKey")
            .field("process_id", &self.process_id)
            .finish_non_exhaustive()
    }
}

/// A bounded prepared-statement cache with least-recently-used eviction.
struct StatementCache {
    capacity: usize,
    map: HashMap<&'static str, (Arc<StatementInner>, u64)>,
    tick: u64,
}

impl StatementCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            tick: 0,
        }
    }

    fn get(&mut self, sql: &'static str) -> Option<Arc<StatementInner>> {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        self.map.get_mut(sql).map(|(st, used)| {
            *used = tick;
            st.clone()
        })
    }

    fn insert(&mut self, sql: &'static str, st: Arc<StatementInner>) {
        self.tick = self.tick.wrapping_add(1);
        self.map.insert(sql, (st, self.tick));
    }

    fn remove(&mut self, sql: &'static str) -> Option<Arc<StatementInner>> {
        self.map.remove(sql).map(|(st, _)| st)
    }

    fn evict_lru(&mut self) -> Option<Arc<StatementInner>> {
        let oldest = self
            .map
            .iter()
            .min_by_key(|(_, (_, used))| *used)
            .map(|(sql, _)| *sql)?;
        self.remove(oldest)
    }
}

/// Progress of one Bind/Execute/Sync exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortalState {
    /// Waiting for CloseComplete messages and BindComplete.
    Bind,
    /// Receiving rows.
    Rows,
    /// The command finished or failed; waiting for ReadyForQuery.
    Ready,
    /// ReadyForQuery received.
    Done,
}

/// The state of a running statement, kept outside the session so that a
/// row stream can hold it.
pub(crate) struct Portal {
    sql: &'static str,
    columns: Arc<[Column]>,
    state: PortalState,
    closes_left: usize,
    rows_affected: Option<u64>,
    error: Option<Error>,
}

/// A PostgreSQL session over an established transport.
///
/// A session runs startup, authentication and the extended query protocol
/// over any [`Connection`]. It needs no runtime: timers, TCP and TLS belong
/// to [`Client`](crate::Client), which wraps a session.
///
/// # Drop safety
///
/// Every operation is a future that may be dropped at any await point.
/// A request dropped while its messages were being written leaves a
/// partial message on the wire, so the session marks itself broken. A
/// request dropped while its responses were being read leaves the session
/// waiting for ReadyForQuery, so the next operation first reads and
/// discards the rest of those responses.
///
/// # Transport security
///
/// [`Session::startup`] trusts the transport it is given. It is the
/// building block of [`Client::connect`](crate::Client::connect), which
/// always establishes TLS with full verification first. Pass a transport
/// without TLS only in tests and fuzzing; channel binding and cleartext
/// passwords are then unavailable.
pub struct Session {
    io: Box<dyn Connection>,
    decoder: BackendDecoder,
    scratch: Vec<u8>,
    wbuf: Vec<u8>,
    limits: Limits,
    cache: StatementCache,
    server_params: HashMap<String, String>,
    backend_key: Option<BackendKey>,
    auth_method: Option<AuthMethod>,
    tx_status: TransactionStatus,
    /// ReadyForQuery messages still expected, one per Sync sent.
    pub(crate) pending_ready: u32,
    /// True while a request is being written.
    pub(crate) writing: bool,
    broken: Option<String>,
    /// Set when a transaction was dropped without commit or rollback.
    pub(crate) rollback_pending: bool,
    pending_closes: Vec<String>,
    /// A named statement whose Parse was sent but whose reply was not
    /// processed. A dropped prepare leaves it here, and `drain` queues it
    /// for Close.
    unconfirmed_statement: Option<String>,
    /// The SQL of the statement whose portal replies are still expected.
    /// `drain` uses it to invalidate the cache after a dropped stream.
    active_portal: Option<&'static str>,
    next_statement: u64,
    notices: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("tx_status", &self.tx_status)
            .field("auth_method", &self.auth_method)
            .field("broken", &self.broken.is_some())
            .field("cached_statements", &self.cache.map.len())
            .finish_non_exhaustive()
    }
}

/// Parses the row count from a command tag such as `INSERT 0 3` or
/// `UPDATE 2`. Tags without a count, such as `CREATE TABLE`, give 0.
fn rows_from_tag(tag: &str) -> u64 {
    let mut words = tag.split(' ');
    let command = words.next().unwrap_or_default();
    let last = tag.rsplit(' ').next().unwrap_or_default();
    match command {
        "INSERT" | "UPDATE" | "DELETE" | "SELECT" | "MERGE" | "MOVE" | "FETCH" | "COPY" => {
            last.parse().unwrap_or(0)
        }
        _ => 0,
    }
}

impl Session {
    fn new(io: Box<dyn Connection>, config: &Config) -> Session {
        Session {
            io,
            decoder: BackendDecoder::new(config.limits.decode_startup()),
            scratch: vec![0u8; READ_CHUNK],
            wbuf: Vec::new(),
            limits: config.limits,
            cache: StatementCache::new(config.statement_cache_capacity),
            server_params: HashMap::new(),
            backend_key: None,
            auth_method: None,
            tx_status: TransactionStatus::Idle,
            pending_ready: 0,
            writing: false,
            broken: None,
            rollback_pending: false,
            pending_closes: Vec::new(),
            unconfirmed_statement: None,
            active_portal: None,
            next_statement: 0,
            notices: 0,
        }
    }

    /// Runs startup and authentication over `io`.
    ///
    /// `tls_server_cert` is the DER server certificate when `io` is a TLS
    /// session, which enables SCRAM-SHA-256-PLUS. `None` means `io` has no
    /// TLS: then only SCRAM-SHA-256 without channel binding is possible,
    /// and cleartext passwords are refused.
    ///
    /// # Errors
    ///
    /// Returns the server's error (for example SQLSTATE `28P01` for a wrong
    /// password), an [`ErrorKind::Auth`] error when the server's method is
    /// not allowed or its SCRAM signature is wrong, or a protocol or
    /// transport error.
    pub async fn startup(
        io: Box<dyn Connection>,
        config: &Config,
        tls_server_cert: Option<&[u8]>,
    ) -> Result<Session, Error> {
        let mut s = Session::new(io, config);
        let mut params: Vec<(&str, &str)> = vec![
            ("user", config.user.as_str()),
            ("database", config.dbname.as_str()),
            ("client_encoding", "UTF8"),
            ("DateStyle", "ISO"),
        ];
        if let Some(app) = &config.application_name {
            params.push(("application_name", app.as_str()));
        }
        frontend::startup(&params, &mut s.wbuf)?;
        s.send().await?;
        s.authenticate(config, tls_server_cert).await?;
        s.decoder.set_limits(config.limits.decode());
        loop {
            match s.next().await? {
                BackendMessage::BackendKeyData {
                    process_id,
                    secret_key,
                } => {
                    if s.backend_key.is_some() {
                        return Err(s.broken_by(Error::protocol("second BackendKeyData")));
                    }
                    s.backend_key = Some(BackendKey {
                        process_id,
                        secret_key,
                    });
                }
                BackendMessage::ReadyForQuery(status) => {
                    s.tx_status = status;
                    break;
                }
                BackendMessage::ErrorResponse(fields) => {
                    let e = s.db_error(&fields)?;
                    return Err(s.broken_by(e));
                }
                other => return Err(s.unexpected(&other)),
            }
        }
        if s.parameter("client_encoding") != Some("UTF8") {
            return Err(s.broken_by(Error::protocol(
                "server did not confirm client_encoding UTF8",
            )));
        }
        Ok(s)
    }

    async fn authenticate(
        &mut self,
        config: &Config,
        tls_server_cert: Option<&[u8]>,
    ) -> Result<(), Error> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Stage {
            Start,
            SaslSent,
            SaslFinal,
            SaslDone,
            PasswordSent,
        }
        let allow = config.require_auth;
        let mut stage = Stage::Start;
        let mut scram: Option<ScramClient> = None;
        let mut method = AuthMethod::None;
        loop {
            let auth = match self.next().await? {
                BackendMessage::Authentication(a) => a,
                BackendMessage::ErrorResponse(fields) => {
                    let e = self.db_error(&fields)?;
                    return Err(self.broken_by(e));
                }
                BackendMessage::NegotiateProtocolVersion { .. } => {
                    return Err(self.broken_by(Error::protocol(
                        "server cannot speak protocol 3.0 as requested",
                    )));
                }
                other => return Err(self.unexpected(&other)),
            };
            match (stage, auth) {
                (Stage::Start, Authentication::Ok) => {
                    if !allow.allows(AuthMethod::None) {
                        return Err(self.broken_by(Error::auth(
                            "server skipped authentication, which require_auth does not allow",
                        )));
                    }
                    self.auth_method = Some(AuthMethod::None);
                    return Ok(());
                }
                (Stage::Start, Authentication::Sasl { mechanisms }) => {
                    let has = |name: &str| mechanisms.iter().any(|m| m == name);
                    let plus = has(SCRAM_SHA_256_PLUS);
                    let plain = has(SCRAM_SHA_256);
                    let binding = match tls_server_cert {
                        Some(cert) if plus && allow.allows(AuthMethod::ScramSha256Plus) => {
                            match crate::x509::tls_server_end_point(cert) {
                                Ok(data) => ChannelBinding::TlsServerEndPoint(data),
                                Err(e) => return Err(self.broken_by(e)),
                            }
                        }
                        // The server supports channel binding but the
                        // configuration excludes it: "n" is the honest flag.
                        Some(_) if plus && plain && allow.allows(AuthMethod::ScramSha256) => {
                            ChannelBinding::NotSupported
                        }
                        Some(_) if plain && allow.allows(AuthMethod::ScramSha256) => {
                            ChannelBinding::NotOffered
                        }
                        None if plain && allow.allows(AuthMethod::ScramSha256) => {
                            ChannelBinding::NotSupported
                        }
                        _ => {
                            return Err(self.broken_by(Error::auth(format!(
                                "server offered SASL mechanisms {mechanisms:?}, none of which \
                                 require_auth allows"
                            ))));
                        }
                    };
                    method = if matches!(binding, ChannelBinding::TlsServerEndPoint(_)) {
                        AuthMethod::ScramSha256Plus
                    } else {
                        AuthMethod::ScramSha256
                    };
                    let client = match ScramClient::new(
                        &config.password,
                        binding,
                        config.limits.min_scram_iterations,
                        config.limits.max_scram_iterations,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            return Err(self.broken_by(Error::with_source(
                                ErrorKind::Auth,
                                "cannot start SCRAM",
                                e,
                            )));
                        }
                    };
                    frontend::sasl_initial_response(
                        client.mechanism(),
                        &client.client_first(),
                        &mut self.wbuf,
                    )?;
                    self.send().await?;
                    scram = Some(client);
                    stage = Stage::SaslSent;
                }
                (Stage::SaslSent, Authentication::SaslContinue { data }) => {
                    let Some(client) = scram.as_mut() else {
                        return Err(self.broken_by(Error::protocol("SCRAM state lost")));
                    };
                    let reply = match client.handle_server_first(&data) {
                        Ok(r) => r,
                        Err(e) => {
                            return Err(self.broken_by(Error::with_source(
                                ErrorKind::Auth,
                                "SCRAM server-first-message rejected",
                                e,
                            )));
                        }
                    };
                    frontend::sasl_response(&reply, &mut self.wbuf)?;
                    self.send().await?;
                    stage = Stage::SaslFinal;
                }
                (Stage::SaslFinal, Authentication::SaslFinal { data }) => {
                    let Some(client) = scram.as_mut() else {
                        return Err(self.broken_by(Error::protocol("SCRAM state lost")));
                    };
                    if let Err(e) = client.handle_server_final(&data) {
                        return Err(self.broken_by(Error::with_source(
                            ErrorKind::Auth,
                            "SCRAM server-final-message rejected",
                            e,
                        )));
                    }
                    stage = Stage::SaslDone;
                }
                (Stage::SaslSent | Stage::SaslFinal, Authentication::Ok) => {
                    return Err(self.broken_by(Error::auth(
                        "server ended SCRAM before proving its identity",
                    )));
                }
                (Stage::SaslDone, Authentication::Ok) => {
                    if !scram.as_ref().is_some_and(ScramClient::is_done) {
                        return Err(self.broken_by(Error::auth(
                            "server ended SCRAM before proving its identity",
                        )));
                    }
                    self.auth_method = Some(method);
                    return Ok(());
                }
                (Stage::Start, Authentication::CleartextPassword) => {
                    if !allow.allows(AuthMethod::Password) {
                        return Err(self.broken_by(Error::auth(
                            "server asked for a cleartext password, which require_auth does \
                             not allow",
                        )));
                    }
                    if tls_server_cert.is_none() {
                        return Err(self.broken_by(Error::auth(
                            "refusing to send a cleartext password without TLS",
                        )));
                    }
                    frontend::password(config.password.as_bytes(), &mut self.wbuf)?;
                    self.send().await?;
                    stage = Stage::PasswordSent;
                }
                (Stage::PasswordSent, Authentication::Ok) => {
                    self.auth_method = Some(AuthMethod::Password);
                    return Ok(());
                }
                (_, Authentication::Md5Password { .. }) => {
                    return Err(self.broken_by(Error::auth(
                        "server asked for MD5 password authentication, which this client never \
                         supports",
                    )));
                }
                (
                    _,
                    a @ (Authentication::KerberosV5
                    | Authentication::Gss
                    | Authentication::GssContinue { .. }
                    | Authentication::Sspi
                    | Authentication::ScmCredential),
                ) => {
                    return Err(self.broken_by(Error::auth(format!(
                        "server asked for unsupported authentication {a:?}"
                    ))));
                }
                (_, a) => {
                    return Err(self.broken_by(Error::protocol(format!(
                        "unexpected authentication message {a:?}"
                    ))));
                }
            }
        }
    }

    // ----- transport -----

    pub(crate) fn mark_broken(&mut self, reason: &str) {
        if self.broken.is_none() {
            self.broken = Some(reason.to_owned());
        }
    }

    /// Marks the session broken and returns `e`.
    fn broken_by(&mut self, e: Error) -> Error {
        let reason = e.to_string();
        self.mark_broken(&reason);
        e
    }

    fn unexpected(&mut self, msg: &BackendMessage) -> Error {
        let e = match msg {
            BackendMessage::Unsupported { tag, .. } => Error::protocol(format!(
                "server sent a '{}' message; COPY and function calls are not supported",
                char::from(*tag)
            )),
            other => Error::protocol(format!("unexpected message {other:?}")),
        };
        self.broken_by(e)
    }

    fn db_error(&mut self, fields: &ErrorFields) -> Result<Error, Error> {
        match DbError::from_fields(&fields.0) {
            Ok(db) => Ok(Error::db(db)),
            Err(e) => Err(self.broken_by(e)),
        }
    }

    async fn send(&mut self) -> Result<(), Error> {
        if self.writing {
            return Err(self.broken_by(Error::closed("a request is already being written")));
        }
        self.writing = true;
        let result = match self.io.write_all(&self.wbuf).await {
            Ok(()) => self.io.flush().await,
            Err(e) => Err(e),
        };
        self.wbuf.clear();
        // One large request, such as a big bytea parameter, must not pin its
        // buffer for the life of the connection.
        if self.wbuf.capacity() > SHRINK_BUFFER_ABOVE {
            self.wbuf.shrink_to(RETAINED_BUFFER_CAPACITY);
        }
        match result {
            Ok(()) => {
                self.writing = false;
                Ok(())
            }
            Err(e) => Err(self.broken_by(Error::io("cannot write to the server", e))),
        }
    }

    async fn read_message(&mut self) -> Result<BackendMessage, Error> {
        loop {
            match self.decoder.next_message() {
                Ok(Some(m)) => return Ok(m),
                Ok(None) => {}
                Err(e) => return Err(self.broken_by(e)),
            }
            let n = match self.io.read(&mut self.scratch).await {
                Ok(n) => n,
                Err(e) => return Err(self.broken_by(Error::io("cannot read from the server", e))),
            };
            if n == 0 {
                return Err(self.broken_by(Error::closed("server closed the connection")));
            }
            let chunk = self.scratch.get(..n).unwrap_or_default();
            self.decoder.push(chunk);
        }
    }

    /// The next message that is not a notice, notification or parameter
    /// status. Notices are counted and dropped, never logged (R-NF-02).
    async fn next(&mut self) -> Result<BackendMessage, Error> {
        loop {
            match self.read_message().await? {
                BackendMessage::NoticeResponse(_) => {
                    self.notices = self.notices.saturating_add(1);
                }
                BackendMessage::NotificationResponse { .. } => {}
                BackendMessage::ParameterStatus { name, value } => {
                    self.on_parameter(name, value)?;
                }
                other => return Ok(other),
            }
        }
    }

    fn on_parameter(&mut self, name: String, value: String) -> Result<(), Error> {
        let bad = match name.as_str() {
            "client_encoding" => value != "UTF8",
            "integer_datetimes" => value != "on",
            _ => false,
        };
        if bad {
            return Err(self.broken_by(Error::protocol(format!(
                "server reported an unsupported {name} setting"
            ))));
        }
        if self.server_params.contains_key(&name)
            || self.server_params.len() < self.limits.max_server_parameters
        {
            self.server_params.insert(name, value);
        }
        Ok(())
    }

    fn on_ready(&mut self, status: TransactionStatus) {
        self.pending_ready = self.pending_ready.saturating_sub(1);
        self.tx_status = status;
    }

    /// Reads and discards the responses of abandoned requests.
    ///
    /// An error that invalidates the abandoned statement still evicts it
    /// from the cache. A named statement whose prepare was abandoned is
    /// queued for Close; closing a statement that does not exist is not an
    /// error in PostgreSQL.
    pub(crate) async fn drain(&mut self) -> Result<(), Error> {
        while self.pending_ready > 0 {
            match self.next().await? {
                BackendMessage::ReadyForQuery(status) => self.on_ready(status),
                BackendMessage::ErrorResponse(fields) => {
                    let e = self.db_error(&fields)?;
                    if e.as_db_error().is_some_and(DbError::is_fatal) {
                        return Err(self.broken_by(e));
                    }
                    if let Some(sql) = self.active_portal {
                        self.invalidate_statement(sql, &e);
                    }
                }
                m @ BackendMessage::Unsupported { .. } => return Err(self.unexpected(&m)),
                _ => {}
            }
        }
        self.active_portal = None;
        if let Some(name) = self.unconfirmed_statement.take() {
            self.pending_closes.push(name);
        }
        Ok(())
    }

    /// Evicts the cached description of `sql` after an error that
    /// invalidates it: a changed result type (`0A000`) or a lost statement
    /// (`26000`). The next call prepares it again.
    fn invalidate_statement(&mut self, sql: &'static str, e: &Error) {
        let code = e.code();
        if matches!(code, Some("0A000" | "26000"))
            && let Some(old) = self.cache.remove(sql)
            && code == Some("0A000")
        {
            self.pending_closes.push(old.name.clone());
        }
    }

    /// Runs `encode` on an empty write buffer. On an error the buffer is
    /// cleared again, so a partial message is never sent later.
    fn encode_request<T>(
        &mut self,
        encode: impl FnOnce(&mut Session) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.wbuf.clear();
        let result = encode(self);
        if result.is_err() {
            self.wbuf.clear();
        }
        result
    }

    /// Makes the session ready for a new request: fails if it is broken,
    /// finishes abandoned requests, and rolls back a dropped transaction.
    pub(crate) async fn ensure_ready(&mut self) -> Result<(), Error> {
        if let Some(reason) = &self.broken {
            return Err(Error::closed(format!("connection is broken: {reason}")));
        }
        if self.writing {
            return Err(self.broken_by(Error::closed(
                "an earlier request was interrupted while it was being sent",
            )));
        }
        self.drain().await?;
        if self.rollback_pending {
            self.rollback_pending = false;
            if self.tx_status != TransactionStatus::Idle {
                self.run_control("ROLLBACK").await?;
            }
        }
        Ok(())
    }

    /// Runs a transaction control statement through the unnamed statement
    /// and returns its command tag. The caller has called `ensure_ready`.
    pub(crate) async fn run_control(&mut self, sql: &'static str) -> Result<String, Error> {
        self.encode_request(|s| {
            frontend::parse("", sql, &[], &mut s.wbuf)?;
            BindWriter::begin("", "", 0, &mut s.wbuf)?.finish()?;
            frontend::execute("", 0, &mut s.wbuf)?;
            frontend::sync(&mut s.wbuf);
            Ok(())
        })?;
        self.pending_ready = self.pending_ready.saturating_add(1);
        self.send().await?;
        let mut stage = 0u8;
        let mut tag = None;
        let mut error = None;
        loop {
            match self.next().await? {
                BackendMessage::ParseComplete if stage == 0 && error.is_none() => stage = 1,
                BackendMessage::BindComplete if stage == 1 && error.is_none() => stage = 2,
                BackendMessage::CommandComplete(t) if stage == 2 && error.is_none() => {
                    tag = Some(t);
                    stage = 3;
                }
                BackendMessage::ErrorResponse(fields) if error.is_none() => {
                    let e = self.db_error(&fields)?;
                    if e.as_db_error().is_some_and(DbError::is_fatal) {
                        return Err(self.broken_by(e));
                    }
                    error = Some(e);
                }
                BackendMessage::ReadyForQuery(status) if stage == 3 || error.is_some() => {
                    self.on_ready(status);
                    break;
                }
                other => return Err(self.unexpected(&other)),
            }
        }
        if let Some(e) = error {
            return Err(e);
        }
        tag.ok_or_else(|| Error::protocol("command finished without a tag"))
    }

    /// Writes a Close for every queued statement and returns how many. The
    /// queue is emptied only once the whole request is encoded, so an
    /// encoding error loses no name.
    fn write_pending_closes(&mut self) -> Result<usize, Error> {
        for name in &self.pending_closes {
            frontend::close(Target::Statement, name, &mut self.wbuf)?;
        }
        Ok(self.pending_closes.len())
    }

    /// Prepares `sql`, or returns the cached statement. The caller has
    /// called `ensure_ready`.
    async fn prepare_statement(&mut self, sql: &'static str) -> Result<Arc<StatementInner>, Error> {
        if let Some(st) = self.cache.get(sql) {
            return Ok(st);
        }
        let cacheable = self.cache.capacity > 0;
        let name = if cacheable {
            self.next_statement = self.next_statement.wrapping_add(1);
            format!("fstp_{}", self.next_statement)
        } else {
            String::new()
        };
        if cacheable
            && self.cache.map.len() >= self.cache.capacity
            && let Some(old) = self.cache.evict_lru()
        {
            self.pending_closes.push(old.name.clone());
        }
        let mut closes_left = self.encode_request(|s| {
            let closes = s.write_pending_closes()?;
            frontend::parse(&name, sql, &[], &mut s.wbuf)?;
            frontend::describe(Target::Statement, &name, &mut s.wbuf)?;
            frontend::sync(&mut s.wbuf);
            Ok(closes)
        })?;
        self.pending_closes.clear();
        if cacheable {
            self.unconfirmed_statement = Some(name.clone());
        }
        self.pending_ready = self.pending_ready.saturating_add(1);
        self.send().await?;

        let mut parsed = false;
        let mut params: Option<Vec<Type>> = None;
        let mut columns: Option<Arc<[Column]>> = None;
        let mut error: Option<Error> = None;
        loop {
            match self.next().await? {
                BackendMessage::CloseComplete if closes_left > 0 && !parsed && error.is_none() => {
                    closes_left = closes_left.saturating_sub(1);
                }
                BackendMessage::ParseComplete if closes_left == 0 && !parsed && error.is_none() => {
                    parsed = true;
                }
                BackendMessage::ParameterDescription(types)
                    if parsed && params.is_none() && error.is_none() =>
                {
                    params = Some(types.into_iter().map(Type::from_oid).collect());
                }
                BackendMessage::RowDescription(fields)
                    if params.is_some() && columns.is_none() && error.is_none() =>
                {
                    columns = Some(fields.iter().map(Column::from_field).collect());
                }
                BackendMessage::NoData
                    if params.is_some() && columns.is_none() && error.is_none() =>
                {
                    columns = Some(Arc::from(Vec::new()));
                }
                BackendMessage::ErrorResponse(fields) if error.is_none() => {
                    let e = self.db_error(&fields)?;
                    if e.as_db_error().is_some_and(DbError::is_fatal) {
                        return Err(self.broken_by(e));
                    }
                    error = Some(e);
                }
                BackendMessage::ReadyForQuery(status) if error.is_some() || columns.is_some() => {
                    self.on_ready(status);
                    break;
                }
                other => return Err(self.unexpected(&other)),
            }
        }
        self.unconfirmed_statement = None;
        if let Some(e) = error {
            if parsed && cacheable {
                self.pending_closes.push(name);
            }
            return Err(e);
        }
        let (Some(params), Some(columns)) = (params, columns) else {
            return Err(self.broken_by(Error::protocol("incomplete statement description")));
        };
        let st = Arc::new(StatementInner {
            name,
            sql,
            params,
            columns,
        });
        if cacheable {
            self.cache.insert(sql, st.clone());
        }
        Ok(st)
    }

    /// Checks and encodes the parameters, then sends Bind, Execute and Sync.
    async fn start_portal(
        &mut self,
        st: &StatementInner,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Portal, Error> {
        if params.len() != st.params.len() {
            return Err(Error::new(
                ErrorKind::ParameterCount,
                format!(
                    "statement has {} parameters but {} values were given",
                    st.params.len(),
                    params.len()
                ),
            ));
        }
        for (i, (value, ty)) in params.iter().zip(&st.params).enumerate() {
            if !value.accepts(*ty) {
                return Err(Error::new(
                    ErrorKind::TypeMismatch,
                    format!(
                        "parameter ${} has type {ty}, which {} does not match; cast in SQL \
                         or pass the matching Rust type",
                        i.saturating_add(1),
                        value.rust_type()
                    ),
                ));
            }
        }
        let closes_left = self.encode_request(|s| s.encode_bind(st, params))?;
        self.pending_closes.clear();
        self.active_portal = Some(st.sql);
        self.pending_ready = self.pending_ready.saturating_add(1);
        self.send().await?;
        Ok(Portal {
            sql: st.sql,
            columns: st.columns.clone(),
            state: PortalState::Bind,
            closes_left,
            rows_affected: None,
            error: None,
        })
    }

    fn encode_bind(
        &mut self,
        st: &StatementInner,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<usize, Error> {
        let closes = self.write_pending_closes()?;
        let mut bind = BindWriter::begin("", &st.name, params.len(), &mut self.wbuf)?;
        for (i, (value, ty)) in params.iter().zip(&st.params).enumerate() {
            bind.param(|out| match value.to_sql(*ty, out) {
                Ok(IsNull::No) => Ok(true),
                Ok(IsNull::Yes) => Ok(false),
                Err(e) => Err(Error::with_source(
                    ErrorKind::Encode,
                    format!("parameter ${}", i.saturating_add(1)),
                    e,
                )),
            })?;
        }
        bind.finish()?;
        frontend::execute("", 0, &mut self.wbuf)?;
        frontend::sync(&mut self.wbuf);
        Ok(closes)
    }

    /// The next row of a running statement, or `None` once it finished.
    pub(crate) async fn portal_next(&mut self, p: &mut Portal) -> Result<Option<Row>, Error> {
        loop {
            if p.state == PortalState::Done {
                return match p.error.take() {
                    Some(e) => Err(e),
                    None => Ok(None),
                };
            }
            let msg = self.next().await?;
            match (p.state, msg) {
                (PortalState::Bind, BackendMessage::CloseComplete) if p.closes_left > 0 => {
                    p.closes_left = p.closes_left.saturating_sub(1);
                }
                (PortalState::Bind, BackendMessage::BindComplete) if p.closes_left == 0 => {
                    p.state = PortalState::Rows;
                }
                (PortalState::Rows, BackendMessage::DataRow(data)) => {
                    if data.len() != p.columns.len() {
                        return Err(self.broken_by(Error::protocol(format!(
                            "row has {} values but the statement has {} columns",
                            data.len(),
                            p.columns.len()
                        ))));
                    }
                    return Ok(Some(Row::new(p.columns.clone(), data)));
                }
                (PortalState::Rows, BackendMessage::CommandComplete(tag)) => {
                    p.rows_affected = Some(rows_from_tag(&tag));
                    p.state = PortalState::Ready;
                }
                (PortalState::Rows, BackendMessage::EmptyQueryResponse) => {
                    p.rows_affected = Some(0);
                    p.state = PortalState::Ready;
                }
                // In the Ready state the command completed, but the implicit
                // transaction failed at Sync. Examples are a deferred
                // constraint or a serialization failure at commit.
                (
                    PortalState::Bind | PortalState::Rows | PortalState::Ready,
                    BackendMessage::ErrorResponse(fields),
                ) => {
                    let e = self.db_error(&fields)?;
                    if e.as_db_error().is_some_and(DbError::is_fatal) {
                        p.state = PortalState::Done;
                        self.active_portal = None;
                        return Err(self.broken_by(e));
                    }
                    self.invalidate_statement(p.sql, &e);
                    // The command's row count does not count once it failed.
                    p.rows_affected = None;
                    if p.error.is_none() {
                        p.error = Some(e);
                    }
                    p.state = PortalState::Ready;
                }
                (PortalState::Ready, BackendMessage::ReadyForQuery(status)) => {
                    self.on_ready(status);
                    p.state = PortalState::Done;
                    self.active_portal = None;
                }
                (_, other) => {
                    p.state = PortalState::Done;
                    self.active_portal = None;
                    return Err(self.unexpected(&other));
                }
            }
        }
    }

    async fn begin_statement(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Portal, Error> {
        self.ensure_ready().await?;
        let st = self.prepare_statement(sql).await?;
        self.start_portal(&st, params).await
    }

    // ----- public API -----

    /// Prepares `sql` (or takes it from the cache) and returns its
    /// description.
    ///
    /// # Errors
    ///
    /// Returns the server's error, for example SQLSTATE `42601` for a syntax
    /// error, or a connection error.
    pub async fn prepare(&mut self, sql: &'static str) -> Result<Statement, Error> {
        self.ensure_ready().await?;
        let inner = self.prepare_statement(sql).await?;
        Ok(Statement { inner })
    }

    /// Runs `sql` with `params` and collects every row.
    ///
    /// The memory the collected rows hold is charged against
    /// [`Limits::max_result_bytes`] as they arrive. Each row counts its slot
    /// in the result vector and its buffers, so many small rows reach the
    /// limit long before their wire size does.
    ///
    /// # Errors
    ///
    /// Returns a parameter count or type error before anything is sent, the
    /// server's error, [`ErrorKind::ResultTooLarge`] when the rows exceed
    /// [`Limits::max_result_bytes`], or a connection error.
    pub async fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        let mut portal = self.begin_statement(sql, params).await?;
        let limit = self.limits.max_result_bytes;
        let slot = std::mem::size_of::<Row>().max(1);
        let mut rows: Vec<Row> = Vec::new();
        let mut heap = 0usize;
        let mut too_large = false;
        while let Some(row) = self.portal_next(&mut portal).await? {
            if too_large {
                continue;
            }
            heap = heap.saturating_add(row.heap_bytes());
            if rows.len() == rows.capacity() {
                // Grow by hand, so that the vector stays inside the limit.
                let affordable = limit.saturating_sub(heap).checked_div(slot).unwrap_or(0);
                let extra = rows
                    .capacity()
                    .max(MIN_ROWS_GROWTH)
                    .min(affordable.saturating_sub(rows.len()));
                if extra > 0 {
                    rows.reserve_exact(extra);
                }
            }
            let held = heap.saturating_add(rows.capacity().saturating_mul(slot));
            if rows.len() == rows.capacity() || held > limit {
                too_large = true;
                rows = Vec::new();
                continue;
            }
            rows.push(row);
        }
        if too_large {
            return Err(Error::new(
                ErrorKind::ResultTooLarge,
                format!(
                    "result exceeds the limit of {} bytes; use a row stream",
                    self.limits.max_result_bytes
                ),
            ));
        }
        Ok(rows)
    }

    /// Runs `sql` and returns its only row.
    ///
    /// # Errors
    ///
    /// As for [`Session::query`], plus [`ErrorKind::RowCount`] unless exactly
    /// one row is returned.
    pub async fn query_one(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        let rows = self.query(sql, params).await?;
        exactly_one(rows)
    }

    /// Runs `sql` and returns its row, if any.
    ///
    /// # Errors
    ///
    /// As for [`Session::query`], plus [`ErrorKind::RowCount`] when more
    /// than one row is returned.
    pub async fn query_opt(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        let rows = self.query(sql, params).await?;
        at_most_one(rows)
    }

    /// Runs `sql` and returns the number of rows it affected, from the
    /// command tag. Rows it returns are discarded.
    ///
    /// # Errors
    ///
    /// As for [`Session::query`].
    pub async fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        let mut portal = self.begin_statement(sql, params).await?;
        while self.portal_next(&mut portal).await?.is_some() {}
        Ok(portal.rows_affected.unwrap_or(0))
    }

    /// Runs `sql` and returns a stream of its rows, for results too large to
    /// collect.
    ///
    /// # Errors
    ///
    /// As for [`Session::query`], for errors before the first row.
    pub async fn query_stream(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<SessionRowStream<'_>, Error> {
        let portal = self.begin_statement(sql, params).await?;
        Ok(SessionRowStream {
            session: self,
            portal,
        })
    }

    /// Sends Terminate and closes the transport.
    ///
    /// # Errors
    ///
    /// Returns a transport error. The session is gone either way.
    pub async fn close(mut self) -> Result<(), Error> {
        if self.broken.is_some() || self.writing {
            return Ok(());
        }
        self.wbuf.clear();
        frontend::terminate(&mut self.wbuf);
        self.send().await?;
        self.io
            .shutdown()
            .await
            .map_err(|e| Error::io("cannot close the connection", e))
    }

    /// True once the session cannot be used any more.
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    /// The transaction status from the last ReadyForQuery.
    #[must_use]
    pub fn transaction_status(&self) -> TransactionStatus {
        self.tx_status
    }

    /// A run-time parameter the server reported, such as `server_version`.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.server_params.get(name).map(String::as_str)
    }

    /// The cancellation key, if the server sent one.
    #[must_use]
    pub fn backend_key(&self) -> Option<BackendKey> {
        self.backend_key
    }

    /// The authentication method that was used.
    #[must_use]
    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.auth_method
    }

    /// The number of statements in the prepared-statement cache.
    #[must_use]
    pub fn cached_statements(&self) -> usize {
        self.cache.map.len()
    }

    /// The number of notices received and discarded. Notices are never
    /// logged, because they can contain data values (R-NF-02).
    #[must_use]
    pub fn notices_discarded(&self) -> u64 {
        self.notices
    }
}

pub(crate) fn exactly_one(mut rows: Vec<Row>) -> Result<Row, Error> {
    if rows.len() != 1 {
        return Err(Error::new(
            ErrorKind::RowCount,
            format!("expected exactly one row, got {}", rows.len()),
        ));
    }
    rows.pop()
        .ok_or_else(|| Error::new(ErrorKind::RowCount, "expected exactly one row"))
}

pub(crate) fn at_most_one(mut rows: Vec<Row>) -> Result<Option<Row>, Error> {
    if rows.len() > 1 {
        return Err(Error::new(
            ErrorKind::RowCount,
            format!("expected at most one row, got {}", rows.len()),
        ));
    }
    Ok(rows.pop())
}

/// Rows of a running statement on a [`Session`].
///
/// Dropping the stream early is safe: the next operation on the session
/// reads and discards the remaining rows.
pub struct SessionRowStream<'a> {
    session: &'a mut Session,
    portal: Portal,
}

impl fmt::Debug for SessionRowStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRowStream")
            .field("state", &self.portal.state)
            .finish_non_exhaustive()
    }
}

impl SessionRowStream<'_> {
    /// The next row, or `None` when the statement has finished.
    ///
    /// # Errors
    ///
    /// Returns the server's error, which can arrive after some rows, or a
    /// connection error.
    pub async fn next(&mut self) -> Result<Option<Row>, Error> {
        self.session.portal_next(&mut self.portal).await
    }

    /// The columns of the result.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.portal.columns
    }

    /// The number of rows the statement affected, once it has finished.
    #[must_use]
    pub fn rows_affected(&self) -> Option<u64> {
        self.portal.rows_affected
    }
}

impl Portal {
    pub(crate) fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub(crate) fn rows_affected(&self) -> Option<u64> {
        self.rows_affected
    }

    pub(crate) fn is_done(&self) -> bool {
        self.state == PortalState::Done
    }
}

impl Session {
    pub(crate) async fn begin_portal(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Portal, Error> {
        self.begin_statement(sql, params).await
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn command_tags() {
        assert_eq!(rows_from_tag("INSERT 0 5"), 5);
        assert_eq!(rows_from_tag("UPDATE 12"), 12);
        assert_eq!(rows_from_tag("DELETE 0"), 0);
        assert_eq!(rows_from_tag("SELECT 3"), 3);
        assert_eq!(rows_from_tag("MERGE 2"), 2);
        assert_eq!(rows_from_tag("CREATE TABLE"), 0);
        assert_eq!(rows_from_tag("BEGIN"), 0);
        assert_eq!(rows_from_tag(""), 0);
        assert_eq!(rows_from_tag("INSERT 0 x"), 0);
    }

    /// One large request must not pin a large write buffer for the life of
    /// the connection.
    #[test]
    fn review_pg_buffers_never_shrink_write_buffer() {
        let (c, _peer) = fstp_rt::duplex::duplex(4 << 20);
        let tls = crate::ClientTls::new(
            include_bytes!("../../fstp-tls/testdata/ca.pem"),
            include_bytes!("../../fstp-tls/testdata/client.pem"),
            include_bytes!("../../fstp-tls/testdata/client-key.pem"),
        )
        .unwrap();
        let cfg = Config::new(
            "localhost",
            5432,
            "u",
            crate::Password::new("pw").unwrap(),
            "db",
            tls,
        )
        .unwrap();
        let mut s = Session::new(Box::new(c), &cfg);
        s.wbuf.extend_from_slice(&vec![0u8; 1 << 20]);
        fstp_rt::future::block_on(s.send()).unwrap();
        assert!(s.wbuf.is_empty());
        assert!(
            s.wbuf.capacity() <= SHRINK_BUFFER_ABOVE,
            "{}",
            s.wbuf.capacity()
        );
    }
}
