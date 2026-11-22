//! Anonymous drafts with a resume link (ADR-032, Daniel 2026-11-22).
//!
//! A person may start a draft for an open call without an account. The
//! draft is form text kept under a secret link, not a proposal: it has no
//! state in the state machine, no Receiving binding and no ledger record.
//! The proposal, its DRAFT state and the lead's Applicant binding start
//! when a signed-in account claims the draft with `CreateDraft` and
//! `proposal.claim_draft` (`roles-and-sod.md` "Receiving bindings").
//!
//! This module holds the pure rules that the cell routes and the claim
//! share:
//!
//! - [`Token`]: the 32-byte bearer secret of the resume link. Only its
//!   SHA-256 digest is stored, and its `Debug` prints no byte (R-NF-02).
//! - [`Draft`]: the three workspace sections, within the workspace limits,
//!   with no control character other than tab and line breaks. It holds
//!   no identity data (R-SB-01, I-17).
//! - [`expires_at`]: 30 days after the start, or the call's deadline if
//!   that is earlier (ADR-032 open point 3).
//! - [`AnonymousDrafts`]: the store port. [`MemoryAnonymousDrafts`] is
//!   the bounded in-memory store of test cells.
//!
//! No AI pre-check runs on an anonymous draft (ADR-032, interim, pending
//! Daniel): the P-23 account cap cannot apply without an account (TH-29).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};

use fstp_domain::id::CallId;
use fstp_domain::time::Timestamp;

use crate::content::{SUMMARY_LIMIT, TITLE_LIMIT, Workspace};
use crate::port::PortError;

/// The bytes of a resume token.
pub const TOKEN_BYTES: usize = 32;

/// How long an unclaimed draft lives, in microseconds: 30 days (Daniel,
/// 2026-11-22).
pub const LIFETIME_US: i64 = 30 * 86_400 * 1_000_000;

/// The longest title, in bytes (the workspace limit).
pub const MAX_TITLE: usize = TITLE_LIMIT;

/// The longest summary, in bytes (the workspace limit).
pub const MAX_SUMMARY: usize = SUMMARY_LIMIT;

/// The longest narrative, in bytes (the workspace limit).
pub const MAX_NARRATIVE: usize = crate::forms::TEXT_LIMIT;

/// The secret of a resume link: 32 random bytes, written as 64 lowercase
/// hexadecimal characters in the URL fragment. It is a bearer secret, so
/// its `Debug` prints no byte, and only its digest is ever stored.
#[derive(Clone, PartialEq, Eq)]
pub struct Token([u8; TOKEN_BYTES]);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// The token of `bytes`.
    pub const fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Token {
        Token(bytes)
    }

    /// A fresh token from the platform's random source, or `None` when it
    /// fails.
    pub fn fresh() -> Option<Token> {
        fstp_crypto::random_array::<TOKEN_BYTES>().ok().map(Token)
    }

    /// The token written as exactly 64 lowercase hexadecimal characters.
    /// Any other spelling is `None`.
    pub fn parse(s: &str) -> Option<Token> {
        crate::action::from_hex::<TOKEN_BYTES>(s)
            .filter(|_| {
                s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .map(Token)
    }

    /// The token as 64 lowercase hexadecimal characters, for the link.
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(TOKEN_BYTES * 2);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The SHA-256 digest of the token: the only form the store keeps.
    pub fn digest(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.0)
    }
}

/// The form text of an anonymous draft: the three workspace sections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Draft {
    /// The title.
    pub title: String,
    /// The applicant-written neutral summary.
    pub summary: String,
    /// The narrative.
    pub narrative: String,
}

/// Whether `s` holds no control character other than tab, line feed and
/// carriage return, and no Unicode line or paragraph separator.
fn clean(s: &str) -> bool {
    s.chars().all(|c| {
        (!c.is_control() || matches!(c, '\t' | '\n' | '\r'))
            && !matches!(c, '\u{2028}' | '\u{2029}')
    })
}

impl Draft {
    /// Whether every section is within its limit and clean.
    pub fn fits(&self) -> bool {
        self.title.len() <= MAX_TITLE
            && self.summary.len() <= MAX_SUMMARY
            && self.narrative.len() <= MAX_NARRATIVE
            && clean(&self.title)
            && clean(&self.summary)
            && clean(&self.narrative)
    }

    /// The bytes the store seals: the canonical JSON object of the three
    /// sections, as a workspace is sealed. `None` when it does not fit.
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.fits() {
            return None;
        }
        crate::content::encode(&self.to_workspace())
    }

    /// The draft that `bytes` encode, or `None` for anything else.
    /// Fuzzed (`anon_draft_decode`).
    pub fn decode(bytes: &[u8]) -> Option<Draft> {
        let w = crate::content::decode(bytes)?;
        let d = Draft {
            title: w.title,
            summary: w.summary,
            narrative: w.narrative,
        };
        d.fits().then_some(d)
    }

    /// The workspace of the claimed proposal.
    pub(crate) fn to_workspace(&self) -> Workspace {
        Workspace {
            title: self.title.clone(),
            summary: self.summary.clone(),
            narrative: self.narrative.clone(),
        }
    }
}

/// When a draft started at `started` for a call with `deadline` expires:
/// 30 days later, or at the deadline if that is earlier.
pub fn expires_at(started: Timestamp, deadline: Timestamp) -> Timestamp {
    let by_age = Timestamp::from_micros(started.micros().saturating_add(LIFETIME_US));
    if deadline.micros() < by_age.micros() {
        deadline
    } else {
        by_age
    }
}

/// Whether a draft that expires at `expires` is still live at `now`.
pub fn is_live(expires: Timestamp, now: Timestamp) -> bool {
    now.micros() < expires.micros()
}

/// One stored anonymous draft, as the store answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The call the draft is for.
    pub call: CallId,
    /// The form text.
    pub draft: Draft,
    /// When it started.
    pub started: Timestamp,
    /// When it expires.
    pub expires: Timestamp,
}

/// The future of an [`AnonymousDrafts`] call.
pub type AnonFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, PortError>> + Send + 'a>>;

/// The store of anonymous drafts, keyed by the digest of the token. The
/// store seals the text at rest (R-NF-08) and never serves an expired
/// draft.
pub trait AnonymousDrafts: Send + Sync {
    /// Stores a new draft under `digest`. A digest in use is refused.
    fn start(&self, digest: [u8; 32], row: Row) -> AnonFuture<'_, ()>;
    /// The live draft under `digest` at `now`, or `None`.
    fn open(&self, digest: [u8; 32], now: Timestamp) -> AnonFuture<'_, Option<Row>>;
    /// Replaces the text of the live draft under `digest`. `false` when no
    /// live draft has it.
    fn save(&self, digest: [u8; 32], draft: Draft, now: Timestamp) -> AnonFuture<'_, bool>;
    /// Deletes the draft under `digest`. `false` when none had it.
    fn remove(&self, digest: [u8; 32]) -> AnonFuture<'_, bool>;
    /// How many live drafts the store holds at `now`.
    fn live(&self, now: Timestamp) -> AnonFuture<'_, u64>;
    /// Deletes every draft expired at `now` and answers how many.
    fn sweep(&self, now: Timestamp) -> AnonFuture<'_, u64>;
}

/// The most drafts a [`MemoryAnonymousDrafts`] holds.
pub const MEMORY_BOUND: usize = 100_000;

/// The in-memory store of test cells. It keeps the rows as they are, so
/// it is never used where data rests on disk.
#[derive(Debug, Default)]
pub struct MemoryAnonymousDrafts {
    rows: Mutex<BTreeMap<[u8; 32], Row>>,
}

impl MemoryAnonymousDrafts {
    /// An empty store.
    pub fn new() -> MemoryAnonymousDrafts {
        MemoryAnonymousDrafts::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut BTreeMap<[u8; 32], Row>) -> T) -> T {
        let mut rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut rows)
    }

    /// How many rows the store holds, expired ones included.
    pub fn len(&self) -> usize {
        self.with(|r| r.len())
    }

    /// Whether the store holds no row.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AnonymousDrafts for MemoryAnonymousDrafts {
    fn start(&self, digest: [u8; 32], row: Row) -> AnonFuture<'_, ()> {
        let r = self.with(|rows| {
            if rows.contains_key(&digest) || rows.len() >= MEMORY_BOUND || !row.draft.fits() {
                return Err(PortError::Refused);
            }
            rows.insert(digest, row);
            Ok(())
        });
        Box::pin(std::future::ready(r))
    }

    fn open(&self, digest: [u8; 32], now: Timestamp) -> AnonFuture<'_, Option<Row>> {
        let r = self.with(|rows| {
            rows.get(&digest)
                .filter(|row| is_live(row.expires, now))
                .cloned()
        });
        Box::pin(std::future::ready(Ok(r)))
    }

    fn save(&self, digest: [u8; 32], draft: Draft, now: Timestamp) -> AnonFuture<'_, bool> {
        let r = self.with(|rows| match rows.get_mut(&digest) {
            Some(row) if is_live(row.expires, now) => {
                if !draft.fits() {
                    return Err(PortError::Refused);
                }
                row.draft = draft;
                Ok(true)
            }
            _ => Ok(false),
        });
        Box::pin(std::future::ready(r))
    }

    fn remove(&self, digest: [u8; 32]) -> AnonFuture<'_, bool> {
        let r = self.with(|rows| rows.remove(&digest).is_some());
        Box::pin(std::future::ready(Ok(r)))
    }

    fn live(&self, now: Timestamp) -> AnonFuture<'_, u64> {
        let r = self.with(|rows| {
            rows.values()
                .filter(|row| is_live(row.expires, now))
                .count()
        });
        Box::pin(std::future::ready(Ok(u64::try_from(r).unwrap_or(u64::MAX))))
    }

    fn sweep(&self, now: Timestamp) -> AnonFuture<'_, u64> {
        let r = self.with(|rows| {
            let before = rows.len();
            rows.retain(|_, row| is_live(row.expires, now));
            before.saturating_sub(rows.len())
        });
        Box::pin(std::future::ready(Ok(u64::try_from(r).unwrap_or(u64::MAX))))
    }
}
