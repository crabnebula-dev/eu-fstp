//! The world's mail capture (lane F-CYCLE3): the proof mail port of a
//! world cell (`fstp_cell::mail::ProofMail`).
//!
//! A world cell hands each self-registration email proof to this port
//! instead of a mail relay. The capture keeps the address and the token,
//! so a test reads the proof the way the address holder would. Claims
//! built on it say so: no message leaves the host, and a production cell
//! sends no proof before M6 delivery (`fstp_cell::mail::NoProofMail`).

use std::sync::{Arc, Mutex, PoisonError};

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

/// The mail capture of one world cell. Clones share the capture.
#[derive(Clone, Debug, Default)]
pub struct WorldMail(Arc<Mutex<Vec<CapturedMail>>>);

impl WorldMail {
    /// Every captured mail, in order.
    pub fn captured(&self) -> Vec<CapturedMail> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The token of the latest proof of `kind` sent to `to`.
    pub fn latest(&self, kind: ProofKind, to: &str) -> Option<[u8; 32]> {
        self.captured()
            .iter()
            .rev()
            .find(|m| m.kind == kind && m.to == to)
            .map(|m| m.token)
    }
}

impl WorldMail {
    /// How many mails were captured so far.
    pub fn count(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// The token of the first mail of `kind` to `to` captured after the
    /// first `after` mails.
    pub fn since(&self, after: usize, kind: ProofKind, to: &str) -> Option<[u8; 32]> {
        self.captured()
            .iter()
            .skip(after)
            .find(|m| m.kind == kind && m.to == to)
            .map(|m| m.token)
    }

    /// The case and token of the first recovery email proof to `to`
    /// captured after the first `after` mails (lane m3/login-m2http).
    pub fn recovery_since(&self, after: usize, to: &str) -> Option<([u8; 16], [u8; 32])> {
        self.captured()
            .iter()
            .skip(after)
            .find_map(|m| match m.kind {
                ProofKind::Recovery { case } if m.to == to => Some((case, m.token)),
                _ => None,
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
        self.0
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
