//! The client: TCP, TLS, timeouts, cancellation and transactions on top of
//! a [`Session`].

use std::fmt;
use std::time::Duration;

use fstp_rt::{Connection, IoExt, Runtime, timeout};

use crate::config::{AuthMethod, Config};
use crate::error::{Error, ErrorKind};
use crate::proto::backend::TransactionStatus;
use crate::proto::frontend;
use crate::row::{Column, Row, Statement};
use crate::session::{BackendKey, Portal, Session, at_most_one, exactly_one};
use crate::tls::tls_handshake;
use crate::types::ToSql;

/// Most resolved addresses tried per connection attempt.
const MAX_ADDRESSES: usize = 16;

/// Bytes read from a cancel connection before giving up on a clean close.
const CANCEL_READ_LIMIT: usize = 1024;

/// Applies the statement timeout to one session operation. On timeout the
/// operation's future is dropped and the client recovers the session.
macro_rules! timed {
    ($client:expr, $fut:expr) => {{
        match $client.statement_timeout {
            None => $fut.await,
            Some(d) => match timeout(&$client.rt, d, $fut).await {
                Ok(r) => r,
                Err(_) => Err($client.recover_after_timeout().await),
            },
        }
    }};
}

async fn connect_tcp<R: Runtime>(rt: &R, host: &str, port: u16) -> Result<R::Tcp, Error> {
    let addrs = rt
        .resolve(host, port)
        .await
        .map_err(|e| Error::io("cannot resolve the host", e))?;
    let mut last = None;
    for addr in addrs.into_iter().take(MAX_ADDRESSES) {
        match rt.connect_tcp(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(e) => Error::io("cannot connect", e),
        None => Error::new(ErrorKind::Io, "host resolved to no addresses"),
    })
}

/// A connected PostgreSQL client.
///
/// - TLS with full certificate verification is always used. A server that
///   declines TLS is refused (R-NF-09). A client certificate in the TLS
///   configuration gives mutual TLS.
/// - Authentication is SCRAM-SHA-256-PLUS when the server offers it, else
///   SCRAM-SHA-256, as limited by `require_auth`.
/// - Statements use the extended query protocol only. SQL text is
///   `&'static str`, so it cannot be built from runtime strings; values
///   travel as typed binary parameters.
/// - Prepared statements are cached per connection.
///
/// One request runs at a time: methods take `&mut self`. There is no
/// connection pool in M1. Pooling is per cell under ADR-005 and belongs to
/// M3. Open several clients for concurrency.
pub struct Client<R: Runtime> {
    rt: R,
    session: Session,
    cancel: CancelToken,
    statement_timeout: Option<Duration>,
    cancel_grace: Duration,
}

impl<R: Runtime> fmt::Debug for Client<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("session", &self.session)
            .field("statement_timeout", &self.statement_timeout)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> Client<R> {
    /// Connects over TCP to the configured host and port, negotiates TLS and
    /// authenticates. The connect timeout covers all of it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Timeout`], [`ErrorKind::TlsRequired`],
    /// [`ErrorKind::Tls`], [`ErrorKind::Auth`], the server's error (such as
    /// SQLSTATE `28P01` for a wrong password), or a transport error.
    pub async fn connect(rt: &R, config: &Config) -> Result<Client<R>, Error> {
        let fut = async {
            let tcp = connect_tcp(rt, &config.host, config.port).await?;
            Self::establish(rt, tcp, config).await
        };
        match config.connect_timeout {
            Some(d) => timeout(rt, d, fut)
                .await
                .map_err(|_| Error::timeout("connect"))?,
            None => fut.await,
        }
    }

    /// Like [`Client::connect`], over an existing transport such as an
    /// in-memory duplex or a tunnel. TLS still runs on top of it. The
    /// cancel token connects to the configured host and port.
    ///
    /// # Errors
    ///
    /// As for [`Client::connect`].
    pub async fn connect_over<S: Connection>(
        rt: &R,
        io: S,
        config: &Config,
    ) -> Result<Client<R>, Error> {
        let fut = Self::establish(rt, io, config);
        match config.connect_timeout {
            Some(d) => timeout(rt, d, fut)
                .await
                .map_err(|_| Error::timeout("connect"))?,
            None => fut.await,
        }
    }

    async fn establish<S: Connection>(rt: &R, io: S, config: &Config) -> Result<Client<R>, Error> {
        let tls = tls_handshake(io, &config.tls, config.server_name()).await?;
        let cert = tls
            .peer_end_entity_der()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::new(ErrorKind::Tls, "server presented no certificate"))?;
        let session = Session::startup(Box::new(tls), config, Some(&cert)).await?;
        let cancel = CancelToken {
            host: config.host.clone(),
            port: config.port,
            server_name: config.server_name().to_owned(),
            tls: config.tls.clone(),
            key: session.backend_key(),
            timeout: config.connect_timeout,
        };
        Ok(Client {
            rt: rt.clone(),
            session,
            cancel,
            statement_timeout: config.statement_timeout,
            cancel_grace: config.cancel_grace,
        })
    }

    /// Called after a statement timeout dropped the operation. Sends a
    /// CancelRequest and waits up to the cancel grace for the server to
    /// finish; otherwise marks the connection broken.
    async fn recover_after_timeout(&mut self) -> Error {
        let err = Error::timeout("statement");
        if self.session.writing {
            self.session
                .mark_broken("a statement timed out while it was being sent");
            return err;
        }
        if self.session.pending_ready == 0 {
            return err;
        }
        let token = self.cancel.clone();
        let _ = timeout(&self.rt, self.cancel_grace, token.cancel(&self.rt)).await;
        match timeout(&self.rt, self.cancel_grace, self.session.drain()).await {
            Ok(Ok(())) => {}
            _ => self
                .session
                .mark_broken("the server did not finish a timed-out statement after a cancel"),
        }
        err
    }

    /// Prepares `sql` (or takes it from the cache) and returns its
    /// description.
    ///
    /// # Errors
    ///
    /// Returns the server's error, such as SQLSTATE `42601` for a syntax
    /// error, or a connection error.
    pub async fn prepare(&mut self, sql: &'static str) -> Result<Statement, Error> {
        timed!(self, self.session.prepare(sql))
    }

    /// Runs `sql` with `params` and collects every row.
    ///
    /// Parameter types are checked against the types the server inferred
    /// before anything is sent. A timed-out statement may still have taken
    /// effect on the server.
    ///
    /// # Errors
    ///
    /// See [`Session::query`]; also [`ErrorKind::Timeout`].
    pub async fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        timed!(self, self.session.query(sql, params))
    }

    /// Runs `sql` and returns its only row.
    ///
    /// # Errors
    ///
    /// As for [`Client::query`], plus [`ErrorKind::RowCount`] unless exactly
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
    /// As for [`Client::query`], plus [`ErrorKind::RowCount`] for more than
    /// one row.
    pub async fn query_opt(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        let rows = self.query(sql, params).await?;
        at_most_one(rows)
    }

    /// Runs `sql` and returns the number of rows affected.
    ///
    /// # Errors
    ///
    /// As for [`Client::query`].
    pub async fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        timed!(self, self.session.execute(sql, params))
    }

    /// Runs `sql` and streams its rows. The statement timeout applies to
    /// each wait for the next row.
    ///
    /// # Errors
    ///
    /// As for [`Client::query`], for errors before the first row.
    pub async fn query_stream(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<RowStream<'_, R>, Error> {
        let portal = timed!(self, self.session.begin_portal(sql, params))?;
        Ok(RowStream {
            client: self,
            portal,
        })
    }

    /// Starts a transaction with the server's default isolation level.
    ///
    /// # Errors
    ///
    /// Returns an error when a transaction is already open on this
    /// connection, or the server's or a connection error.
    pub async fn transaction(&mut self) -> Result<Transaction<'_, R>, Error> {
        self.transaction_with(TransactionOptions::default()).await
    }

    /// Starts a transaction with explicit options.
    ///
    /// A BEGIN that fails, for example on the statement timeout, may still
    /// have opened a transaction on the server. So may a BEGIN whose future
    /// the caller drops. The connection then rolls it back before its next
    /// statement, as for a dropped [`Transaction`].
    ///
    /// # Errors
    ///
    /// As for [`Client::transaction`].
    pub async fn transaction_with(
        &mut self,
        options: TransactionOptions,
    ) -> Result<Transaction<'_, R>, Error> {
        timed!(self, self.session.ensure_ready())?;
        if self.session.transaction_status() != TransactionStatus::Idle {
            return Err(Error::new(
                ErrorKind::Config,
                "a transaction is already open on this connection",
            ));
        }
        // A BEGIN that failed, timed out or was dropped by the caller may
        // still have opened a transaction, and so may a server that reports
        // an unexpected status. No Transaction owns it, so the next statement
        // on this connection rolls it back first. The flag is set before
        // BEGIN is sent, because a dropped future runs no code after it.
        self.session.rollback_pending = true;
        timed!(self, self.session.run_control(options.begin_sql()))?;
        if self.session.transaction_status() != TransactionStatus::InTransaction {
            return Err(Error::protocol("server did not open a transaction"));
        }
        self.session.rollback_pending = false;
        Ok(Transaction {
            client: self,
            finished: false,
        })
    }

    async fn end_transaction(&mut self, sql: &'static str) -> Result<String, Error> {
        timed!(self, self.session.ensure_ready())?;
        timed!(self, self.session.run_control(sql))
    }

    /// A token that cancels the statement running on this connection from
    /// any task.
    #[must_use]
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Sends Terminate and closes the connection.
    ///
    /// # Errors
    ///
    /// Returns a transport error. The connection is gone either way.
    pub async fn close(self) -> Result<(), Error> {
        self.session.close().await
    }

    /// True once the connection cannot be used any more.
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.session.is_broken()
    }

    /// The transaction status from the last ReadyForQuery.
    #[must_use]
    pub fn transaction_status(&self) -> TransactionStatus {
        self.session.transaction_status()
    }

    /// A run-time parameter the server reported, such as `server_version`.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.session.parameter(name)
    }

    /// The authentication method that was used.
    #[must_use]
    pub fn auth_method(&self) -> Option<AuthMethod> {
        self.session.auth_method()
    }

    /// The number of statements in the prepared-statement cache.
    #[must_use]
    pub fn cached_statements(&self) -> usize {
        self.session.cached_statements()
    }

    /// The number of notices received and discarded, never logged.
    #[must_use]
    pub fn notices_discarded(&self) -> u64 {
        self.session.notices_discarded()
    }
}

/// Rows of a running statement on a [`Client`].
///
/// Dropping the stream early is safe: the next operation reads and
/// discards the remaining rows.
pub struct RowStream<'a, R: Runtime> {
    client: &'a mut Client<R>,
    portal: Portal,
}

impl<R: Runtime> fmt::Debug for RowStream<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowStream")
            .field("done", &self.portal.is_done())
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> RowStream<'_, R> {
    /// The next row, or `None` when the statement has finished.
    ///
    /// # Errors
    ///
    /// Returns the server's error, a timeout, or a connection error.
    pub async fn next(&mut self) -> Result<Option<Row>, Error> {
        let client = &mut *self.client;
        let portal = &mut self.portal;
        match client.statement_timeout {
            None => client.session.portal_next(portal).await,
            Some(d) => match timeout(&client.rt, d, client.session.portal_next(portal)).await {
                Ok(r) => r,
                Err(_) => Err(client.recover_after_timeout().await),
            },
        }
    }

    /// The columns of the result.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        self.portal.columns()
    }

    /// The number of rows the statement affected, once it has finished.
    #[must_use]
    pub fn rows_affected(&self) -> Option<u64> {
        self.portal.rows_affected()
    }
}

/// Transaction isolation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsolationLevel {
    /// `READ COMMITTED`.
    ReadCommitted,
    /// `REPEATABLE READ`.
    RepeatableRead,
    /// `SERIALIZABLE`.
    Serializable,
}

/// Options for [`Client::transaction_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TransactionOptions {
    /// The isolation level, or the server default.
    pub isolation: Option<IsolationLevel>,
    /// `READ ONLY` instead of the default `READ WRITE`.
    pub read_only: bool,
    /// `DEFERRABLE`. Only takes effect with `SERIALIZABLE` and `read_only`,
    /// and is ignored otherwise.
    pub deferrable: bool,
}

impl TransactionOptions {
    /// The server default: `BEGIN`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the isolation level.
    #[must_use]
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.isolation = Some(level);
        self
    }

    /// Sets `READ ONLY`.
    #[must_use]
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Sets `DEFERRABLE`.
    #[must_use]
    pub fn deferrable(mut self, deferrable: bool) -> Self {
        self.deferrable = deferrable;
        self
    }

    /// The fixed SQL text for these options. Every combination is a
    /// constant, so no SQL is built at run time.
    #[must_use]
    pub fn begin_sql(&self) -> &'static str {
        use IsolationLevel::{ReadCommitted, RepeatableRead, Serializable};
        match (self.isolation, self.read_only, self.deferrable) {
            (None, false, _) => "BEGIN",
            (None, true, _) => "BEGIN READ ONLY",
            (Some(ReadCommitted), false, _) => "BEGIN ISOLATION LEVEL READ COMMITTED",
            (Some(ReadCommitted), true, _) => "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY",
            (Some(RepeatableRead), false, _) => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            (Some(RepeatableRead), true, _) => "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            (Some(Serializable), false, _) => "BEGIN ISOLATION LEVEL SERIALIZABLE",
            (Some(Serializable), true, false) => "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY",
            (Some(Serializable), true, true) => {
                "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
            }
        }
    }
}

/// An open transaction.
///
/// End it with [`Transaction::commit`] or [`Transaction::rollback`]. A
/// transaction dropped without either is rolled back: the connection sends
/// `ROLLBACK` before its next statement. Until then the server keeps the
/// transaction open; closing the connection also ends it.
pub struct Transaction<'a, R: Runtime> {
    client: &'a mut Client<R>,
    finished: bool,
}

impl<R: Runtime> fmt::Debug for Transaction<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> Transaction<'_, R> {
    /// Runs `sql` in the transaction and collects every row.
    ///
    /// # Errors
    ///
    /// As for [`Client::query`].
    pub async fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        self.client.query(sql, params).await
    }

    /// Runs `sql` in the transaction and returns its only row.
    ///
    /// # Errors
    ///
    /// As for [`Client::query_one`].
    pub async fn query_one(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        self.client.query_one(sql, params).await
    }

    /// Runs `sql` in the transaction and returns its row, if any.
    ///
    /// # Errors
    ///
    /// As for [`Client::query_opt`].
    pub async fn query_opt(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        self.client.query_opt(sql, params).await
    }

    /// Runs `sql` in the transaction and returns the rows affected.
    ///
    /// # Errors
    ///
    /// As for [`Client::execute`].
    pub async fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        self.client.execute(sql, params).await
    }

    /// Streams the rows of `sql` in the transaction.
    ///
    /// # Errors
    ///
    /// As for [`Client::query_stream`].
    pub async fn query_stream(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<RowStream<'_, R>, Error> {
        self.client.query_stream(sql, params).await
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::RolledBack`] when the server rolled back
    /// instead, because an earlier statement in the transaction failed. A
    /// server error at commit time, such as a serialization failure, also
    /// means the transaction was rolled back.
    pub async fn commit(mut self) -> Result<(), Error> {
        let result = self.client.end_transaction("COMMIT").await;
        if result.is_ok()
            || result
                .as_ref()
                .err()
                .is_some_and(|e| e.kind() == ErrorKind::Db)
        {
            self.finished = true;
        }
        match result?.as_str() {
            "COMMIT" => Ok(()),
            "ROLLBACK" => Err(Error::new(
                ErrorKind::RolledBack,
                "COMMIT rolled the transaction back because an earlier statement failed",
            )),
            _ => Err(Error::protocol("unexpected command tag for COMMIT")),
        }
    }

    /// Rolls the transaction back.
    ///
    /// # Errors
    ///
    /// Returns the server's or a connection error.
    pub async fn rollback(mut self) -> Result<(), Error> {
        let result = self.client.end_transaction("ROLLBACK").await;
        if result.is_ok() {
            self.finished = true;
        }
        result.map(|_| ())
    }
}

impl<R: Runtime> Drop for Transaction<'_, R> {
    fn drop(&mut self) {
        if !self.finished {
            self.client.session.rollback_pending = true;
        }
    }
}

/// Cancels the statement running on one connection, from any task.
///
/// The CancelRequest goes over a new TLS connection with the same
/// verification and client certificate as the original connection. A
/// cancel can arrive after the statement already finished; the server then
/// ignores it. [`fmt::Debug`] hides the secret key.
#[derive(Clone)]
pub struct CancelToken {
    host: String,
    port: u16,
    server_name: String,
    tls: fstp_tls::ClientConfig,
    key: Option<BackendKey>,
    timeout: Option<Duration>,
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelToken")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl CancelToken {
    /// Sends the CancelRequest and waits for the server to close the cancel
    /// connection. The connect timeout of the original configuration
    /// bounds the whole exchange.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Closed`] when the server sent no cancellation
    /// key, or a connect, TLS or timeout error.
    pub async fn cancel<R: Runtime>(&self, rt: &R) -> Result<(), Error> {
        let Some(key) = self.key else {
            return Err(Error::closed("server sent no cancellation key"));
        };
        let fut = async {
            let tcp = connect_tcp(rt, &self.host, self.port).await?;
            let mut tls = tls_handshake(tcp, &self.tls, &self.server_name).await?;
            tls.write_all(&frontend::cancel_request(key.process_id, key.secret_key))
                .await
                .map_err(|e| Error::io("cannot send the CancelRequest", e))?;
            tls.flush()
                .await
                .map_err(|e| Error::io("cannot send the CancelRequest", e))?;
            // The server answers nothing and closes the connection once the
            // request is processed.
            let mut buf = [0u8; 256];
            let mut seen = 0usize;
            while seen < CANCEL_READ_LIMIT {
                match tls.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen = seen.saturating_add(n),
                }
            }
            Ok(())
        };
        match self.timeout {
            Some(d) => timeout(rt, d, fut)
                .await
                .map_err(|_| Error::timeout("cancel request"))?,
            None => fut.await,
        }
    }

    /// The backend process id this token cancels, if known.
    #[must_use]
    pub fn process_id(&self) -> Option<i32> {
        self.key.map(|k| k.process_id)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn begin_statements_are_constants() {
        let o = TransactionOptions::new();
        assert_eq!(o.begin_sql(), "BEGIN");
        assert_eq!(
            o.isolation(IsolationLevel::Serializable)
                .read_only(true)
                .deferrable(true)
                .begin_sql(),
            "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
        );
        assert_eq!(
            o.isolation(IsolationLevel::RepeatableRead).begin_sql(),
            "BEGIN ISOLATION LEVEL REPEATABLE READ"
        );
        assert_eq!(
            o.deferrable(true).begin_sql(),
            "BEGIN",
            "DEFERRABLE alone is ignored"
        );
    }
}
