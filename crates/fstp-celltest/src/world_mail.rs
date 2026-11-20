//! The world's mail capture (lane F-CYCLE3): the proof mail port of a
//! world cell (`fstp_cell::mail::ProofMail`).
//!
//! A world cell hands each self-registration email proof to this port
//! instead of a mail relay. The capture keeps the address and the token,
//! so a test reads the proof the way the address holder would. Claims
//! built on it say so: no message leaves the host.
//!
//! A cell run by the `fstp-cell` binary (`crate::external_cell`, lane L4)
//! sends its proofs through the platform relay to the test SMTP sink. Its
//! capture then reads them from the sink ([`WorldMail::with_source`]).
//! Such a mail arrives a little after the request that sent it, so a
//! lookup that finds nothing waits up to [`SOURCE_WAIT`] for it.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fstp_cell::mail::{MailRefused, ProofKind, ProofMail};

/// One captured proof mail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedMail {
    /// What it proves.
    pub kind: ProofKind,
    /// The address it was sent to. Synthetic.
    pub to: String,
    /// The proof token.
    pub token: [u8; 32],
}

/// Every proof a sink holds so far, in order.
pub type MailSource = Arc<dyn Fn() -> Vec<CapturedMail> + Send + Sync>;

/// How long a lookup waits for a mail from a source.
pub const SOURCE_WAIT: Duration = Duration::from_secs(20);

/// The mail capture of one world cell. Clones share the capture.
#[derive(Clone, Default)]
pub struct WorldMail {
    captured: Arc<Mutex<Vec<CapturedMail>>>,
    source: Option<MailSource>,
    relay: WorldRelay,
}

impl std::fmt::Debug for WorldMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorldMail")
            .field("sourced", &self.source.is_some())
            .finish_non_exhaustive()
    }
}

impl WorldMail {
    /// A capture that reads every mail from `source`.
    #[must_use]
    pub fn with_source(source: MailSource) -> WorldMail {
        WorldMail {
            captured: Arc::default(),
            source: Some(source),
            relay: WorldRelay::default(),
        }
    }

    /// Every captured mail, in order.
    pub fn captured(&self) -> Vec<CapturedMail> {
        match &self.source {
            Some(s) => s(),
            None => self
                .captured
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// `find` over the captured mail. With a source, it asks again until
    /// it finds one or [`SOURCE_WAIT`] passed.
    fn wait_for<T>(&self, find: impl Fn(&[CapturedMail]) -> Option<T>) -> Option<T> {
        let begun = Instant::now();
        loop {
            let found = find(&self.captured());
            if found.is_some() || self.source.is_none() || begun.elapsed() > SOURCE_WAIT {
                return found;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The token of the latest proof of `kind` sent to `to`.
    pub fn latest(&self, kind: ProofKind, to: &str) -> Option<[u8; 32]> {
        self.wait_for(|all| {
            all.iter()
                .rev()
                .find(|m| m.kind == kind && m.to == to)
                .map(|m| m.token)
        })
    }
}

impl WorldMail {
    /// How many mails were captured so far.
    pub fn count(&self) -> usize {
        self.captured().len()
    }

    /// The token of the first mail of `kind` to `to` captured after the
    /// first `after` mails.
    pub fn since(&self, after: usize, kind: ProofKind, to: &str) -> Option<[u8; 32]> {
        self.wait_for(|all| {
            all.iter()
                .skip(after)
                .find(|m| m.kind == kind && m.to == to)
                .map(|m| m.token)
        })
    }

    /// The case and token of the first recovery email proof to `to`
    /// captured after the first `after` mails (lane m3/login-m2http).
    pub fn recovery_since(&self, after: usize, to: &str) -> Option<([u8; 16], [u8; 32])> {
        self.wait_for(|all| {
            all.iter().skip(after).find_map(|m| match m.kind {
                ProofKind::Recovery { case } if m.to == to => Some((case, m.token)),
                _ => None,
            })
        })
    }
}

impl WorldMail {
    /// The latest enrolment token of recovery case `case` sent to `to`
    /// (lane m3/login-m2http).
    pub fn latest_enrolment(&self, case: [u8; 16], to: &str) -> Option<[u8; 32]> {
        self.latest(ProofKind::RecoveryEnrolment { case }, to)
    }
}

impl ProofMail for WorldMail {
    fn send(&self, kind: ProofKind, to: &str, token: [u8; 32]) -> Result<(), MailRefused> {
        self.captured
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(CapturedMail {
                kind,
                to: to.to_owned(),
                token,
            });
        Ok(())
    }
}
// ---------------------------------------------------------------------------
// The relay of the API core's ports (ADR-026 record of lane L5).

/// The address a world cell's mail is sent from. Synthetic.
pub const WORLD_SENDER: &str = "noreply@fstp-world.invalid";

/// One message the world relay accepted: the envelope recipient and the
/// bytes after the final dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayedMail {
    /// The envelope recipient. Synthetic.
    pub to: String,
    /// The message as sent.
    pub body: Vec<u8>,
}

#[derive(Debug, Default)]
struct RelayState {
    staged: usize,
    sent: Vec<RelayedMail>,
}

/// The relay of a world cell (`fstp_cell::process::Relay`): it accepts
/// every message with 250 and keeps it, so a test reads it as the
/// recipient would. Claims built on it say so: no message leaves the
/// host. Lane L4's configured relay takes its place in production.
#[derive(Clone, Debug, Default)]
pub struct WorldRelay(Arc<Mutex<RelayState>>);

impl WorldRelay {
    /// Every message the relay accepted, in order.
    pub fn sent(&self) -> Vec<RelayedMail> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sent
            .clone()
    }

    /// How many sessions staged a body, sent or not.
    pub fn staged(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).staged
    }
}

struct Staged {
    relay: WorldRelay,
    mail: RelayedMail,
}

impl fstp_cell::process::StagedMail for Staged {
    fn end_of_data(
        self: Box<Self>,
    ) -> fstp_cell::process::RelayFuture<'static, fstp_dispatch::EndOfData> {
        self.relay
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sent
            .push(self.mail);
        Box::pin(std::future::ready(fstp_dispatch::EndOfData::Reply(250)))
    }

    fn abandon(self: Box<Self>) -> fstp_cell::process::RelayFuture<'static, ()> {
        Box::pin(std::future::ready(()))
    }
}

impl fstp_cell::process::Relay for WorldRelay {
    fn sender(&self) -> &str {
        WORLD_SENDER
    }

    fn stage<'a>(
        &'a self,
        envelope: &'a fstp_dispatch::Envelope,
        body: &'a [u8],
    ) -> fstp_cell::process::RelayFuture<
        'a,
        Result<Box<dyn fstp_cell::process::StagedMail>, fstp_dispatch::Refused>,
    > {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        s.staged = s.staged.saturating_add(1);
        let staged: Box<dyn fstp_cell::process::StagedMail> = Box::new(Staged {
            relay: self.clone(),
            mail: RelayedMail {
                to: envelope.to.clone(),
                body: body.to_vec(),
            },
        });
        Box::pin(std::future::ready(Ok(staged)))
    }
}

impl WorldMail {
    /// The relay of the API core's ports, which shares this capture's
    /// life (ADR-026 record of lane L5).
    pub fn relay(&self) -> &WorldRelay {
        &self.relay
    }
}
