//! The cell's mail: the proof mail port (design section 8.3 ceremony 2,
//! lane F-CYCLE3) and the platform submission relay (ADR-018 amendment of
//! 2026-11-20, decision D3, lane L4).
//!
//! A self-registration proves its email address with a single-use token
//! that the cell sends to that address. The token never enters the
//! ledger: the route stores only its SHA-256 digest (`auth.token`), and
//! hands the token to a [`ProofMail`].
//!
//! Lane m3/login-m2http adds the magic link and the recovery email proof
//! to the port (Interim, pending Daniel): each goes to the account's login
//! email, which the cell opens from its keyed index (design section 4.2).
//!
//! # Ports
//!
//! - [`NoProofMail`] refuses every send. A cell without a `mail` member in
//!   its configuration uses it, so `POST /auth/signup/options {email}`
//!   answers 503 and no account is created.
//! - [`MailRelay`] submits one message. [`SmtpRelay`] is the production
//!   relay over [`crate::egress::MailEgress`], so every rule of ADR-018
//!   holds. Lane L5's outbox delivery uses the same trait.
//! - [`RelayProofMail`] is the proof mail port over a [`MailRelay`]. A
//!   proof becomes one plain text message with a link to the page that
//!   takes it ([`proof_message`]).
//! - A test world passes a port of its own through
//!   `crate::process::StartOptions` that captures each proof, and says so
//!   in its claims.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fstp_rt::Runtime;
use fstp_smtp::client::{Credentials, Envelope, SmtpError};

use crate::config::Mode;
use crate::egress::{MailEgress, MailFault, MailHost, MailTransport, TcpMailTransport};

/// What a proof mail proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// The email proof of a self-registration.
    Signup,
    /// A magic link to the login email of a Receiving-only account
    /// (ADR-008 "Magic links"). Interim, pending Daniel: M6 sends it
    /// through the outbox, and until then it goes through this port.
    MagicLink,
    /// The email proof of recovery case `case` (design section 8.5), sent
    /// to the holder's login email. The case reference travels with the
    /// token, as a link would carry it.
    Recovery {
        /// The case reference.
        case: [u8; 16],
    },
    /// A one-time enrolment token of recovery case `case`, sent to the
    /// holder's login email after an approval or an accepted operator
    /// ticket (design section 8.5).
    RecoveryEnrolment {
        /// The case reference.
        case: [u8; 16],
    },
}

/// Why a proof mail was not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailRefused {
    /// The cell has no mail delivery.
    NoDelivery,
    /// The address cannot go into an envelope or a header.
    BadAddress,
    /// Too many messages wait for the relay.
    Busy,
}

/// Sends a proof token to an email address (module documentation).
pub trait ProofMail: Send + Sync + 'static {
    /// Sends `token` of `kind` to `to`.
    ///
    /// # Errors
    ///
    /// [`MailRefused`] when the mail was not handed on.
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused>;
}

/// The port of a cell with no mail relay: it sends nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoProofMail;

impl ProofMail for NoProofMail {
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused> {
        let _ = (kind, to, token);
        Err(MailRefused::NoDelivery)
    }
}

// ---------------------------------------------------------------------------
// The relay port.

/// One plain text message to one recipient. The relay adds the sender.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    /// The recipient mailbox.
    pub to: String,
    /// The subject, printable ASCII.
    pub subject: String,
    /// The text, printable ASCII lines.
    pub text: String,
}

impl std::fmt::Debug for OutgoingMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // R-NF-02: an address or a proof link is never shown.
        f.write_str("OutgoingMail(..)")
    }
}

/// Why a relay did not take a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayFault {
    /// The message cannot be encoded: an address or a header line breaks
    /// its rule.
    Message,
    /// The relay was refused, unreachable or answered before the end of
    /// DATA. Nothing was delivered, so a retry is safe.
    NotSent,
    /// The end of DATA was sent and no clear answer came back (I-26). A
    /// retry may deliver twice.
    InDoubt,
}

/// A boxed future of a relay submission.
pub type RelayFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RelayFault>> + Send + 'a>>;

/// Submits one message (module documentation).
pub trait MailRelay: Send + Sync + 'static {
    /// Submits `mail` once: at most one end of DATA (I-26).
    fn submit<'a>(&'a self, mail: &'a OutgoingMail) -> RelayFuture<'a>;
}

/// Whether `s` is one header line value: printable ASCII and spaces, at
/// most 900 bytes, so no line folds and nothing can add a header.
fn header_value_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 900 && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Encodes `mail` from `sender` as an RFC 5322 message with CRLF line
/// ends, 7-bit plain text.
///
/// # Errors
///
/// [`RelayFault::Message`] for a mailbox `fstp_smtp` refuses, a subject
/// that is not one printable line, or a text line that is not printable
/// ASCII of at most 900 bytes.
pub fn encode_message(sender: &str, mail: &OutgoingMail) -> Result<Vec<u8>, RelayFault> {
    use fstp_smtp::command::valid_mailbox;
    if !valid_mailbox(sender) || !valid_mailbox(&mail.to) || !header_value_ok(&mail.subject) {
        return Err(RelayFault::Message);
    }
    let mut out = format!(
        "From: <{sender}>\r\nTo: <{}>\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\n",
        mail.to, mail.subject
    );
    for line in mail.text.split('\n') {
        if line.len() > 900 || !line.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(RelayFault::Message);
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

/// The byte link a [`SmtpRelay`] opens: DNS on port 465 with the public
/// address rule ([`TcpMailTransport`]), or the address the operator
/// pinned for the platform relay (ADR-026 "Relay address", interim,
/// pending Daniel).
#[derive(Clone, Debug)]
pub enum RelayTransport<R> {
    /// The ADR-018 transport.
    Dns(TcpMailTransport<R>),
    /// The pinned address of the platform relay.
    Pinned {
        /// The runtime.
        rt: R,
        /// The relay's socket address.
        addr: SocketAddr,
    },
}

impl<R: Runtime> MailTransport for RelayTransport<R> {
    type Conn = R::Tcp;

    fn open(
        &self,
        host: &MailHost,
        port: u16,
    ) -> impl Future<Output = Result<R::Tcp, MailFault>> + Send {
        let pinned = match self {
            RelayTransport::Dns(_) => None,
            RelayTransport::Pinned { rt, addr } => Some((rt.clone(), *addr)),
        };
        let dns = match self {
            RelayTransport::Dns(t) => Some(t.open(host, port)),
            RelayTransport::Pinned { .. } => None,
        };
        async move {
            match (pinned, dns) {
                (Some((rt, addr)), _) => {
                    let run = rt.connect_tcp(addr);
                    match fstp_rt::timeout(&rt, crate::egress::MAIL_CONNECT_TIMEOUT, run).await {
                        Ok(Ok(c)) => Ok(c),
                        _ => Err(MailFault::Unreachable),
                    }
                }
                (None, Some(open)) => open.await,
                (None, None) => Err(MailFault::Unreachable),
            }
        }
    }
}

/// The platform submission relay (ADR-018 amendment of 2026-11-20).
pub struct SmtpRelay<R: Runtime> {
    egress: MailEgress<R, RelayTransport<R>>,
    sender: String,
}

impl<R: Runtime> std::fmt::Debug for SmtpRelay<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpRelay").finish_non_exhaustive()
    }
}

/// What a [`SmtpRelay`] is built from.
pub struct RelayParts<'a> {
    /// The relay host, which its certificate must name.
    pub relay: &'a str,
    /// The pinned socket address, if the operator named one.
    pub address: Option<SocketAddr>,
    /// The envelope and `From` sender.
    pub sender: &'a str,
    /// The cell host, said in EHLO.
    pub helo: &'a str,
    /// The AUTH PLAIN credential.
    pub credentials: Credentials,
    /// The pinned CA, PEM, if any.
    pub ca_pem: Option<&'a [u8]>,
}

impl<R: Runtime> SmtpRelay<R> {
    /// The relay of a cell in `mode` on `rt`.
    ///
    /// # Errors
    ///
    /// The [`MailFault`] of `MailEgress::new`, and
    /// [`MailFault::Refused`] for a sender `fstp_smtp` refuses.
    pub fn new(mode: Mode, rt: R, parts: RelayParts<'_>) -> Result<SmtpRelay<R>, MailFault> {
        if !fstp_smtp::command::valid_mailbox(parts.sender) {
            return Err(MailFault::Refused(crate::egress::EgressRefusal::MailHost));
        }
        let transport = match parts.address {
            Some(addr) => RelayTransport::Pinned {
                rt: rt.clone(),
                addr,
            },
            None => RelayTransport::Dns(TcpMailTransport::new(rt.clone())),
        };
        let egress = MailEgress::new(
            mode,
            rt,
            transport,
            parts.relay,
            parts.ca_pem,
            parts.helo,
            parts.credentials,
        )?;
        Ok(SmtpRelay {
            egress,
            sender: parts.sender.to_owned(),
        })
    }
}

impl<R: Runtime> MailRelay for SmtpRelay<R> {
    fn submit<'a>(&'a self, mail: &'a OutgoingMail) -> RelayFuture<'a> {
        Box::pin(async move {
            let body = encode_message(&self.sender, mail)?;
            let envelope = Envelope {
                from: self.sender.clone(),
                to: mail.to.clone(),
            };
            let staged = self
                .egress
                .stage(&envelope, &body)
                .await
                .map_err(|_| RelayFault::NotSent)?;
            match staged.commit().await {
                Ok(_) => Ok(()),
                Err(e) if e.in_doubt() => Err(RelayFault::InDoubt),
                Err(SmtpError::Transient { .. } | SmtpError::Permanent { .. }) => {
                    Err(RelayFault::NotSent)
                }
                Err(_) => Err(RelayFault::InDoubt),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Proof mail over a relay.

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The message of a proof of `kind` with `token`, to `to`, for the cell
/// at `host`. The link opens the page that takes the proof, with the
/// token in the fragment, so it never reaches a server log
/// (`web/src/auth/pages`). Opening the link sends nothing by itself.
#[must_use]
pub fn proof_message(host: &str, kind: ProofKind, to: &str, token: &[u8; 32]) -> OutgoingMail {
    let t = hex(token);
    let (subject, intro, link) = match kind {
        ProofKind::Signup => (
            "Confirm your email address",
            "Open this link to confirm your email address and create your account.",
            format!("https://{host}/auth/signup#{t}"),
        ),
        ProofKind::MagicLink => (
            "Your sign-in link",
            "Open this link to sign in.",
            format!("https://{host}/auth/magic#{t}"),
        ),
        ProofKind::Recovery { case } => (
            "Recover your account",
            "Open this link to confirm that you asked to recover your account.",
            format!("https://{host}/auth/recovery#e.{}.{t}", hex(&case)),
        ),
        ProofKind::RecoveryEnrolment { case } => (
            "Add your new passkey",
            "Open this link to add a new passkey to your account.",
            format!("https://{host}/auth/recovery#c.{}.{t}", hex(&case)),
        ),
    };
    OutgoingMail {
        to: to.to_owned(),
        subject: subject.to_owned(),
        text: format!(
            "{intro}\n\n{link}\n\nThe link works once. If you did not ask for this, you can ignore this message."
        ),
    }
}

/// The most proof mails that may wait for the relay at once.
pub const MAX_PENDING: usize = 64;

/// The proof mail port over a [`MailRelay`] (module documentation). Each
/// send queues one task on the runtime. A send is refused when
/// [`MAX_PENDING`] mails wait, or the address cannot go into a message.
pub struct RelayProofMail<R: Runtime> {
    rt: R,
    relay: Arc<dyn MailRelay>,
    host: String,
    pending: Arc<AtomicUsize>,
}

impl<R: Runtime> std::fmt::Debug for RelayProofMail<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayProofMail").finish_non_exhaustive()
    }
}

impl<R: Runtime> RelayProofMail<R> {
    /// The port of the cell at `host`, submitting through `relay` on `rt`.
    pub fn new(rt: R, relay: Arc<dyn MailRelay>, host: &str) -> RelayProofMail<R> {
        RelayProofMail {
            rt,
            relay,
            host: host.to_owned(),
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<R: Runtime> ProofMail for RelayProofMail<R> {
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused> {
        let mail = proof_message(&self.host, kind, to, &token);
        // Checked here, so a refused address is refused to the route.
        encode_message("check@check.invalid", &mail).map_err(|_| MailRefused::BadAddress)?;
        let taken = self
            .pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_PENDING).then(|| n.saturating_add(1))
            });
        if taken.is_err() {
            return Err(MailRefused::Busy);
        }
        let relay = Arc::clone(&self.relay);
        let pending = Arc::clone(&self.pending);
        drop(self.rt.spawn(async move {
            // The outcome is not reported back: the route already answered
            // the same reply for every address (design section 8.3).
            let _ = relay.submit(&mail).await;
            pending.fetch_sub(1, Ordering::SeqCst);
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// ADR-018, R-NF-02: a header value cannot carry a line break, so an
    /// address or subject never adds a header, and the encoding is 7-bit
    /// with CRLF line ends.
    #[test]
    fn adr018_proof_message_is_one_plain_7bit_message() {
        let m = proof_message(
            "grants.example.test",
            ProofKind::Recovery { case: [0xab; 16] },
            "holder@example.test",
            &[0x11; 32],
        );
        let bytes = encode_message("noreply@example.test", &m).unwrap();
        assert!(fstp_smtp::data::is_7bit(&bytes));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(&format!(
            "https://grants.example.test/auth/recovery#e.{}.{}",
            "ab".repeat(16),
            "11".repeat(32)
        )));
        assert!(!text.replace("\r\n", "").contains('\n'));
        let mut evil = m.clone();
        evil.to = "a@b.test>\r\nBcc: <x@y.test".to_owned();
        assert_eq!(
            encode_message("noreply@example.test", &evil),
            Err(RelayFault::Message)
        );
        let mut evil = m;
        evil.subject = "x\r\nBcc: y".to_owned();
        assert_eq!(
            encode_message("noreply@example.test", &evil),
            Err(RelayFault::Message)
        );
    }

    /// R-NF-02: the debug form of a message names neither its address
    /// nor its link.
    #[test]
    fn r_nf_02_outgoing_mail_debug_shows_nothing() {
        let m = proof_message("h.test", ProofKind::Signup, "a@b.test", &[7; 32]);
        assert_eq!(format!("{m:?}"), "OutgoingMail(..)");
    }
}
