//! The test SMTP server ("the sink") for tests and the demo cell (M6 design
//! sections 5.2 and 8). Test only: it never ships.
//!
//! It listens on loopback with implicit TLS from the `fstp-tls` test CA,
//! asks for AUTH PLAIN with a synthetic demo credential and keeps every
//! accepted message byte-exact. It parses commands and DATA with the
//! `fstp-smtp` parsers, which the fuzz target `smtp_sink_command` covers.
//!
//! A one-shot [`Fault`] changes how the next end of DATA is answered:
//! refuse it with a code, drop the connection without a reply, or accept
//! the message and then drop the reply.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use fstp_rt::{Connection, IoExt, JoinHandle, Listener, Runtime};
use fstp_smtp::auth::decode_plain;
use fstp_smtp::client::{Credentials, SmtpClient};
use fstp_smtp::command::{Command, MAX_COMMAND_LINE, parse_command};
use fstp_smtp::data::{DataDecoder, MAX_DATA_LINE};
use fstp_smtp::lines::split_line;
use fstp_smtp::reply::Reply;
use fstp_tls::{ClientConfig, ServerConfig, TlsError};

const CA_PEM: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
const SERVER_PEM: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");

/// The name on the test server certificate.
pub const SINK_SERVER_NAME: &str = "localhost";

/// Largest message the sink keeps.
const MAX_MESSAGE: usize = 10 * 1024 * 1024;

/// Most bytes read in one call.
const READ_CHUNK: usize = 4096;

/// The sink's identity and its synthetic credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkConfig {
    /// The name in the greeting and EHLO reply.
    pub hostname: String,
    /// The AUTH PLAIN user.
    pub username: String,
    /// The AUTH PLAIN password. Synthetic, for tests and the demo only.
    pub password: String,
}

impl Default for SinkConfig {
    fn default() -> Self {
        SinkConfig {
            hostname: "sink.fstp.test".to_owned(),
            username: "demo-mailer".to_owned(),
            password: "demo-mailer-secret".to_owned(),
        }
    }
}

/// How the sink answers the next end of DATA. Each fault applies once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Reply with this code (4yz or 5yz) and keep nothing.
    Refuse(u16),
    /// Close the connection without a reply and keep nothing.
    Drop,
    /// Keep the message, then close the connection without a reply.
    LoseReply,
}

/// One accepted message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkMessage {
    /// Its position, from 1.
    pub seq: u64,
    /// When the sink accepted it, in Unix milliseconds.
    pub at_unix_ms: u64,
    /// The reverse path.
    pub from: String,
    /// The forward paths.
    pub to: Vec<String>,
    /// The message, byte-exact, after dot-unstuffing.
    pub data: Vec<u8>,
}

#[derive(Default)]
struct State {
    messages: Vec<SinkMessage>,
    fault: Option<Fault>,
}

/// The shared state of a sink. Clone it to serve a connection, for
/// example one end of an in-memory duplex.
#[derive(Clone)]
pub struct SinkHandle {
    state: Arc<Mutex<State>>,
    cfg: Arc<SinkConfig>,
    tls: ServerConfig,
}

impl std::fmt::Debug for SinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkHandle")
            .field("hostname", &self.cfg.hostname)
            .finish_non_exhaustive()
    }
}

/// A running sink on loopback. Dropping it stops the listener.
#[derive(Debug)]
pub struct SmtpSink {
    handle: SinkHandle,
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for SmtpSink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl SinkHandle {
    /// A sink state with the test server certificate.
    ///
    /// # Errors
    ///
    /// The TLS configuration error, as an IO error.
    pub fn new(cfg: SinkConfig) -> io::Result<SinkHandle> {
        let tls = ServerConfig::new(SERVER_PEM, SERVER_KEY_PEM).map_err(TlsError::into_io)?;
        Ok(SinkHandle {
            state: Arc::new(Mutex::new(State::default())),
            cfg: Arc::new(cfg),
            tls,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every accepted message, in order.
    pub fn messages(&self) -> Vec<SinkMessage> {
        self.lock().messages.clone()
    }

    /// Sets or clears the fault for the next end of DATA.
    pub fn set_fault(&self, fault: Option<Fault>) {
        self.lock().fault = fault;
    }

    /// A client that trusts the test CA and holds the sink's credential.
    ///
    /// # Errors
    ///
    /// The TLS configuration error, as an IO error.
    pub fn client(&self) -> io::Result<SmtpClient> {
        let tls = ClientConfig::new(CA_PEM).map_err(TlsError::into_io)?;
        Ok(SmtpClient::new(
            tls,
            SINK_SERVER_NAME,
            "cell.fstp.test",
            Credentials::new(&self.cfg.username, &self.cfg.password),
        ))
    }

    /// Serves one connection: the TLS handshake, then an SMTP session.
    pub async fn serve<S: Connection>(&self, conn: S) {
        let Ok(io) = fstp_tls::accept(&self.tls, conn).await else {
            return;
        };
        let mut session = Session {
            sink: self,
            io,
            buf: Vec::new(),
        };
        // A transport failure only ends the session.
        let _ = session.run().await;
    }
}

impl SmtpSink {
    /// Binds a loopback port and serves every connection on `rt`.
    ///
    /// # Errors
    ///
    /// The TLS configuration or socket error.
    pub async fn start<R: Runtime>(rt: &R, cfg: SinkConfig) -> io::Result<SmtpSink> {
        let handle = SinkHandle::new(cfg)?;
        let mut listener = rt
            .bind_tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await?;
        let addr = listener.local_addr()?;
        let h = handle.clone();
        let rt2 = rt.clone();
        let task = rt.spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let h = h.clone();
                drop(rt2.spawn(async move { h.serve(conn).await }));
            }
        });
        Ok(SmtpSink { handle, addr, task })
    }

    /// The loopback address to connect to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The shared state, to serve further connections.
    pub fn handle(&self) -> &SinkHandle {
        &self.handle
    }

    /// Every accepted message, in order.
    pub fn messages(&self) -> Vec<SinkMessage> {
        self.handle.messages()
    }

    /// Sets or clears the fault for the next end of DATA.
    pub fn set_fault(&self, fault: Option<Fault>) {
        self.handle.set_fault(fault);
    }

    /// A client that trusts the test CA and holds the sink's credential.
    ///
    /// # Errors
    ///
    /// The TLS configuration error, as an IO error.
    pub fn client(&self) -> io::Result<SmtpClient> {
        self.handle.client()
    }
}

struct Session<'a, S> {
    sink: &'a SinkHandle,
    io: S,
    buf: Vec<u8>,
}

/// What the session does after a line.
enum Next {
    Continue,
    Close,
}

impl<S: Connection> Session<'_, S> {
    async fn reply(&mut self, code: u16, lines: &[&str]) -> io::Result<()> {
        let lines = lines.iter().map(|l| (*l).to_owned()).collect();
        let bytes = Reply::new(code, lines)
            .or_else(|_| Reply::new(451, vec!["4.3.0 sink error".to_owned()]))
            .map_err(|_| io::Error::other("reply"))?
            .encode();
        self.io.write_all(&bytes).await?;
        self.io.flush().await
    }

    /// The next line with its CRLF. `Ok(None)` at end of stream or on a
    /// framing error.
    async fn line(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            match split_line(&self.buf, max) {
                Ok(Some(n)) => return Ok(Some(self.buf.drain(..n).collect())),
                Ok(None) => {}
                Err(_) => return Ok(None),
            }
            let n = self.io.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend(chunk.get(..n).unwrap_or_default());
        }
    }

    async fn run(&mut self) -> io::Result<()> {
        let host = self.sink.cfg.hostname.clone();
        self.reply(220, &[&format!("{host} ESMTP fstp test sink")])
            .await?;
        let mut authed = false;
        let mut from: Option<String> = None;
        let mut to: Vec<String> = Vec::new();
        loop {
            let Some(line) = self.line(MAX_COMMAND_LINE).await? else {
                return Ok(());
            };
            let Ok(cmd) = parse_command(&line) else {
                self.reply(500, &["5.5.2 syntax error"]).await?;
                continue;
            };
            match cmd {
                Command::Ehlo(_) => {
                    from = None;
                    to.clear();
                    self.reply(250, &[&host, "AUTH PLAIN", "8BITMIME"]).await?;
                }
                Command::AuthPlain(None) => {
                    self.reply(504, &["5.5.4 initial response required"])
                        .await?;
                }
                Command::AuthPlain(Some(b64)) => {
                    let ok = !authed
                        && decode_plain(&b64).is_ok_and(|c| {
                            (c.authzid.is_empty() || c.authzid == c.authcid)
                                && c.authcid == self.sink.cfg.username
                                && c.password == self.sink.cfg.password
                        });
                    if ok {
                        authed = true;
                        self.reply(235, &["2.7.0 authenticated"]).await?;
                    } else {
                        self.reply(535, &["5.7.8 authentication failed"]).await?;
                    }
                }
                Command::MailFrom { path, params } => {
                    let params_ok = params
                        .iter()
                        .all(|p| p == "BODY=8BITMIME" || p == "BODY=7BIT");
                    if !authed {
                        self.reply(530, &["5.7.0 authentication required"]).await?;
                    } else if from.is_some() {
                        self.reply(503, &["5.5.1 sender already given"]).await?;
                    } else if !params_ok {
                        self.reply(555, &["5.5.4 unsupported parameter"]).await?;
                    } else {
                        from = Some(path);
                        self.reply(250, &["2.1.0 ok"]).await?;
                    }
                }
                Command::RcptTo(path) => {
                    if from.is_none() {
                        self.reply(503, &["5.5.1 sender first"]).await?;
                    } else {
                        to.push(path);
                        self.reply(250, &["2.1.5 ok"]).await?;
                    }
                }
                Command::Data => {
                    let Some(sender) = from.take().filter(|_| !to.is_empty()) else {
                        self.reply(503, &["5.5.1 recipients first"]).await?;
                        continue;
                    };
                    let rcpts = std::mem::take(&mut to);
                    if let Next::Close = self.data(sender, rcpts).await? {
                        return Ok(());
                    }
                }
                Command::Rset => {
                    from = None;
                    to.clear();
                    self.reply(250, &["2.0.0 ok"]).await?;
                }
                Command::Noop => self.reply(250, &["2.0.0 ok"]).await?,
                Command::Quit => {
                    self.reply(221, &["2.0.0 bye"]).await?;
                    let _ = self.io.shutdown().await;
                    return Ok(());
                }
            }
        }
    }

    async fn data(&mut self, from: String, to: Vec<String>) -> io::Result<Next> {
        self.reply(354, &["end data with <CRLF>.<CRLF>"]).await?;
        let mut decoder = DataDecoder::new(MAX_MESSAGE);
        loop {
            // End of stream before the final dot: the server never saw
            // the end of DATA and discards the message.
            let Some(line) = self.line(MAX_DATA_LINE).await? else {
                return Ok(Next::Close);
            };
            match decoder.feed_line(&line) {
                Ok(false) => {}
                Ok(true) => break,
                Err(_) => {
                    self.reply(554, &["5.6.0 malformed data"]).await?;
                    return Ok(Next::Close);
                }
            }
        }
        let data = decoder.into_message();
        let fault = self.sink.lock().fault.take();
        let keep = |sink: &SinkHandle| {
            let mut st = sink.lock();
            let seq = u64::try_from(st.messages.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            st.messages.push(SinkMessage {
                seq,
                at_unix_ms: now_ms(),
                from,
                to,
                data,
            });
            seq
        };
        match fault {
            Some(Fault::Refuse(code)) => {
                let text = if code < 500 {
                    "4.3.0 refused by the sink fault"
                } else {
                    "5.3.0 refused by the sink fault"
                };
                self.reply(code, &[text]).await?;
                Ok(Next::Continue)
            }
            Some(Fault::Drop) => Ok(Next::Close),
            Some(Fault::LoseReply) => {
                keep(self.sink);
                Ok(Next::Close)
            }
            None => {
                let seq = keep(self.sink);
                self.reply(250, &[&format!("2.0.0 queued as {seq}")])
                    .await?;
                Ok(Next::Continue)
            }
        }
    }
}
