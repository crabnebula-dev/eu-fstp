//! The submission client: implicit TLS, EHLO, AUTH PLAIN, MAIL, RCPT, DATA.
//!
//! [`SmtpClient::stage`] runs a session up to the body and streams the
//! body without the final `.` CRLF. The server has then accepted nothing.
//! [`Staged::commit`] writes the final dot and reads the reply.
//! [`Staged::abandon`] closes the connection instead, and the server
//! discards the transaction. This is the commit point of M6 design section
//! 5.1 (I-26).
//!
//! The caller opens the transport to port [`SUBMISSION_PORT`]. The client
//! runs over any [`fstp_rt::Connection`], so tests use the in-memory duplex
//! or a loopback socket. Credentials are never printed.

use std::fmt;
use std::io;
use std::time::Duration;

use fstp_rt::{Connection, IoExt, Runtime, timeout};
use fstp_tls::{ClientConfig, TlsError, TlsErrorKind, TlsStream, connect};

use crate::auth::PlainCredentials;
use crate::command::{Command, valid_mailbox};
use crate::data::{BodyError, is_7bit, stuff};
use crate::reply::{Reply, ReplyClass, ReplyError, ReplyLimits, parse_reply};

/// The only port the client is meant for: submission over implicit TLS
/// (RFC 8314 section 3.3).
pub const SUBMISSION_PORT: u16 = 465;

/// Most bytes read from the server in one call.
const READ_CHUNK: usize = 4096;

/// The step of a session where an error happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The TLS handshake.
    Connect,
    /// The 220 greeting.
    Greeting,
    /// EHLO.
    Ehlo,
    /// AUTH PLAIN.
    Auth,
    /// MAIL FROM.
    MailFrom,
    /// RCPT TO.
    RcptTo,
    /// The DATA command.
    Data,
    /// Streaming the body.
    Body,
    /// The final dot and its reply. Only here can the outcome be unknown.
    EndOfData,
}

/// A failed session, typed so the dispatcher can tell a definite failure
/// from an unknown outcome ([`SmtpError::in_doubt`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtpError {
    /// The TLS handshake failed.
    Tls(TlsErrorKind),
    /// The transport failed.
    Io {
        /// Where.
        phase: Phase,
        /// The IO error kind.
        kind: io::ErrorKind,
    },
    /// The per-command deadline passed.
    Timeout {
        /// Where.
        phase: Phase,
    },
    /// The server closed the connection before a complete reply.
    Closed {
        /// Where.
        phase: Phase,
    },
    /// The server sent a malformed reply.
    Malformed {
        /// Where.
        phase: Phase,
        /// What was wrong.
        error: ReplyError,
    },
    /// The server sent bytes after a reply without being asked.
    Unsolicited {
        /// Where.
        phase: Phase,
    },
    /// A 4yz reply.
    Transient {
        /// Where.
        phase: Phase,
        /// The reply.
        reply: Reply,
    },
    /// A 5yz reply.
    Permanent {
        /// Where.
        phase: Phase,
        /// The reply.
        reply: Reply,
    },
    /// A reply of a class this step does not expect.
    Unexpected {
        /// Where.
        phase: Phase,
        /// The reply.
        reply: Reply,
    },
    /// The server lacks an extension the session needs: `AUTH PLAIN`, or
    /// `8BITMIME` for a body with 8-bit octets.
    Unsupported(&'static str),
    /// A sender or recipient address is not a valid mailbox.
    Envelope,
    /// The body cannot be sent.
    Body(BodyError),
}

impl SmtpError {
    /// True when the server may have accepted the message. The final dot
    /// was written, or may have been, and no definite reply was read. Such
    /// a message is IN_DOUBT and never sent again automatically.
    pub fn in_doubt(&self) -> bool {
        match self {
            SmtpError::Transient { .. } | SmtpError::Permanent { .. } => false,
            SmtpError::Io { phase, .. }
            | SmtpError::Timeout { phase }
            | SmtpError::Closed { phase }
            | SmtpError::Malformed { phase, .. }
            | SmtpError::Unsolicited { phase }
            | SmtpError::Unexpected { phase, .. } => *phase == Phase::EndOfData,
            SmtpError::Tls(_)
            | SmtpError::Unsupported(_)
            | SmtpError::Envelope
            | SmtpError::Body(_) => false,
        }
    }
}

impl fmt::Display for SmtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmtpError::Tls(k) => write!(f, "TLS handshake failed: {k:?}"),
            SmtpError::Io { phase, kind } => write!(f, "{phase:?}: transport error {kind:?}"),
            SmtpError::Timeout { phase } => write!(f, "{phase:?}: timed out"),
            SmtpError::Closed { phase } => write!(f, "{phase:?}: connection closed"),
            SmtpError::Malformed { phase, error } => write!(f, "{phase:?}: {error}"),
            SmtpError::Unsolicited { phase } => write!(f, "{phase:?}: unsolicited server data"),
            SmtpError::Transient { phase, reply } => {
                write!(f, "{phase:?}: transient failure {}", reply.code())
            }
            SmtpError::Permanent { phase, reply } => {
                write!(f, "{phase:?}: permanent failure {}", reply.code())
            }
            SmtpError::Unexpected { phase, reply } => {
                write!(f, "{phase:?}: unexpected reply {}", reply.code())
            }
            SmtpError::Unsupported(ext) => write!(f, "server lacks {ext}"),
            SmtpError::Envelope => f.write_str("invalid envelope address"),
            SmtpError::Body(e) => write!(f, "body: {e}"),
        }
    }
}

impl std::error::Error for SmtpError {}

/// Per-command deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// TLS handshake and the 220 greeting.
    pub greeting: Duration,
    /// EHLO, AUTH, MAIL and RCPT replies.
    pub command: Duration,
    /// The 354 reply to DATA.
    pub data_init: Duration,
    /// Streaming the body.
    pub data_block: Duration,
    /// The reply to the final dot.
    pub data_term: Duration,
}

impl Timeouts {
    /// The client values of RFC 5321 section 4.5.3.2: five minutes for the
    /// greeting and for MAIL and RCPT, two for DATA, three per data block
    /// and ten for the final dot.
    pub const RFC5321: Timeouts = Timeouts {
        greeting: Duration::from_secs(300),
        command: Duration::from_secs(300),
        data_init: Duration::from_secs(120),
        data_block: Duration::from_secs(180),
        data_term: Duration::from_secs(600),
    };
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts::RFC5321
    }
}

/// The submission credential, a cell secret. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// A user name and password.
    pub fn new(username: &str, password: &str) -> Self {
        Credentials {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

/// One sender and one recipient. Each message has one recipient, since
/// its idempotency key names one (M6 design section 3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The reverse path.
    pub from: String,
    /// The forward path.
    pub to: String,
}

/// A configured submission client.
#[derive(Clone, Debug)]
pub struct SmtpClient {
    tls: ClientConfig,
    server_name: String,
    helo: String,
    credentials: Credentials,
    timeouts: Timeouts,
}

impl SmtpClient {
    /// A client that trusts `tls`, checks the certificate against
    /// `server_name` and introduces itself as `helo`.
    pub fn new(tls: ClientConfig, server_name: &str, helo: &str, credentials: Credentials) -> Self {
        SmtpClient {
            tls,
            server_name: server_name.to_owned(),
            helo: helo.to_owned(),
            credentials,
            timeouts: Timeouts::default(),
        }
    }

    /// The same client with other deadlines.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// The same client with another credential.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Runs a session over `io` up to the body and streams `body` without
    /// the final dot.
    ///
    /// # Errors
    ///
    /// [`SmtpError`] for any failure. None of them is in doubt, since the
    /// final dot was not sent.
    pub async fn stage<R: Runtime, S: Connection>(
        &self,
        rt: &R,
        io: S,
        envelope: &Envelope,
        body: &[u8],
    ) -> Result<Staged<R, S>, SmtpError> {
        if !valid_mailbox(&envelope.from) || !valid_mailbox(&envelope.to) {
            return Err(SmtpError::Envelope);
        }
        let wire = stuff(body).map_err(SmtpError::Body)?;
        let t = self.timeouts;
        let tls = match timeout(rt, t.greeting, connect(&self.tls, &self.server_name, io)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(match TlsError::from_io(&e) {
                    Some(te) => SmtpError::Tls(te.kind()),
                    None => SmtpError::Io {
                        phase: Phase::Connect,
                        kind: e.kind(),
                    },
                });
            }
            Err(_) => {
                return Err(SmtpError::Timeout {
                    phase: Phase::Connect,
                });
            }
        };
        let mut s = Session {
            rt: rt.clone(),
            io: tls,
            buf: Vec::new(),
        };
        s.expect(Phase::Greeting, t.greeting, ReplyClass::Positive)
            .await?;
        let ehlo = s
            .command(
                &Command::Ehlo(self.helo.clone()),
                Phase::Ehlo,
                t.command,
                ReplyClass::Positive,
            )
            .await?;
        let has = |ext: &str, arg: Option<&str>| {
            ehlo.lines().iter().skip(1).any(|l| {
                let mut words = l.split(' ');
                words.next().is_some_and(|w| w.eq_ignore_ascii_case(ext))
                    && arg.is_none_or(|a| words.any(|w| w.eq_ignore_ascii_case(a)))
            })
        };
        if !has("AUTH", Some("PLAIN")) {
            return Err(SmtpError::Unsupported("AUTH PLAIN"));
        }
        let eight_bit = !is_7bit(&wire);
        if eight_bit && !has("8BITMIME", None) {
            return Err(SmtpError::Unsupported("8BITMIME"));
        }
        let plain =
            PlainCredentials::new("", &self.credentials.username, &self.credentials.password);
        s.command(
            &Command::AuthPlain(Some(plain.encode())),
            Phase::Auth,
            t.command,
            ReplyClass::Positive,
        )
        .await?;
        let params = if eight_bit {
            vec!["BODY=8BITMIME".to_owned()]
        } else {
            Vec::new()
        };
        let mail = Command::MailFrom {
            path: envelope.from.clone(),
            params,
        };
        s.command(&mail, Phase::MailFrom, t.command, ReplyClass::Positive)
            .await?;
        s.command(
            &Command::RcptTo(envelope.to.clone()),
            Phase::RcptTo,
            t.command,
            ReplyClass::Positive,
        )
        .await?;
        s.command(
            &Command::Data,
            Phase::Data,
            t.data_init,
            ReplyClass::Intermediate,
        )
        .await?;
        s.write(&wire, Phase::Body, t.data_block).await?;
        Ok(Staged {
            session: s,
            timeouts: t,
        })
    }
}

/// A session with the whole body sent except the final `.` CRLF.
#[derive(Debug)]
pub struct Staged<R, S> {
    session: Session<R, S>,
    timeouts: Timeouts,
}

impl<R: Runtime, S: Connection> Staged<R, S> {
    /// Sends the final dot and reads the reply. On success, sends QUIT
    /// and closes, ignoring failures there.
    ///
    /// # Errors
    ///
    /// [`SmtpError::Transient`] or [`SmtpError::Permanent`] for a definite
    /// refusal. Every other error here is [`SmtpError::in_doubt`].
    pub async fn commit(mut self) -> Result<Reply, SmtpError> {
        let t = self.timeouts;
        let rt = self.session.rt.clone();
        let s = &mut self.session;
        s.write(b".\r\n", Phase::EndOfData, t.data_block).await?;
        let reply = s
            .expect(Phase::EndOfData, t.data_term, ReplyClass::Positive)
            .await;
        // QUIT is a courtesy. The outcome is already decided.
        if s.send(&Command::Quit, Phase::EndOfData, t.command)
            .await
            .is_ok()
        {
            let _ = timeout(&rt, t.command, s.read_reply(Phase::EndOfData)).await;
        }
        let _ = timeout(&s.rt, t.command, s.io.shutdown()).await;
        reply
    }

    /// Closes the connection without the final dot. The server discards
    /// the transaction. A QUIT here would be read as body text, so none
    /// is sent.
    pub async fn abandon(mut self) {
        let s = &mut self.session;
        let _ = timeout(&s.rt, self.timeouts.data_block, s.io.shutdown()).await;
    }
}

struct Session<R, S> {
    rt: R,
    io: TlsStream<S>,
    buf: Vec<u8>,
}

impl<R, S> fmt::Debug for Session<R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session")
    }
}

impl<R: Runtime, S: Connection> Session<R, S> {
    async fn write(&mut self, bytes: &[u8], phase: Phase, d: Duration) -> Result<(), SmtpError> {
        let io = &mut self.io;
        let res = timeout(&self.rt, d, async {
            io.write_all(bytes).await?;
            io.flush().await
        })
        .await;
        match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(SmtpError::Io {
                phase,
                kind: e.kind(),
            }),
            Err(_) => Err(SmtpError::Timeout { phase }),
        }
    }

    async fn send(&mut self, cmd: &Command, phase: Phase, d: Duration) -> Result<(), SmtpError> {
        let line = cmd.checked_encode().map_err(|_| SmtpError::Envelope)?;
        self.write(&line, phase, d).await
    }

    async fn read_reply(&mut self, phase: Phase) -> Result<Reply, SmtpError> {
        let limits = ReplyLimits::default();
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            match parse_reply(&self.buf, &limits) {
                Ok(Some((reply, n))) => {
                    if n != self.buf.len() {
                        return Err(SmtpError::Unsolicited { phase });
                    }
                    self.buf.clear();
                    return Ok(reply);
                }
                Ok(None) => {}
                Err(error) => return Err(SmtpError::Malformed { phase, error }),
            }
            let n = match self.io.read(&mut chunk).await {
                Ok(0) => return Err(SmtpError::Closed { phase }),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(SmtpError::Closed { phase });
                }
                Err(e) => {
                    return Err(SmtpError::Io {
                        phase,
                        kind: e.kind(),
                    });
                }
            };
            self.buf.extend(chunk.get(..n).unwrap_or_default());
        }
    }

    async fn expect(
        &mut self,
        phase: Phase,
        d: Duration,
        want: ReplyClass,
    ) -> Result<Reply, SmtpError> {
        let rt = self.rt.clone();
        let reply = match timeout(&rt, d, self.read_reply(phase)).await {
            Ok(r) => r?,
            Err(_) => return Err(SmtpError::Timeout { phase }),
        };
        match reply.class() {
            c if c == want => Ok(reply),
            ReplyClass::Transient => Err(SmtpError::Transient { phase, reply }),
            ReplyClass::Permanent => Err(SmtpError::Permanent { phase, reply }),
            _ => Err(SmtpError::Unexpected { phase, reply }),
        }
    }

    async fn command(
        &mut self,
        cmd: &Command,
        phase: Phase,
        d: Duration,
        want: ReplyClass,
    ) -> Result<Reply, SmtpError> {
        self.send(cmd, phase, d).await?;
        self.expect(phase, d, want).await
    }
}
