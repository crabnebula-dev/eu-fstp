//! The replies a world cell gave to sessions (design section 14.4, I-17,
//! lane m3/cycle-steps).
//!
//! `i17_canary_attributes_never_reach_judging_responses` scans every
//! response body and header for a Judging or Drafting session. The auth
//! client of a cycle ([`crate::mc::auth_model::http::AuthClient`]) records
//! each reply to a request that carried a session cookie it knows, with
//! the cell account of that session, into the cell's [`ResponseLog`]. A
//! request with no session, such as a login or a public page, is not
//! recorded: no session reads it.
//!
//! [`ResponseLog::stores_of`] gives the replies to some accounts as a
//! [`StoreSet`] for [`crate::scan::scan`]. Each store is one reply: its
//! status line, its header fields and its body, as the client read them
//! above TLS.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fstp_domain::id::AccountId;

use crate::scan::StoreSet;
use crate::world::HttpReply;

/// One reply to a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReply {
    /// The cell account of the session.
    pub account: AccountId,
    /// The request method.
    pub method: String,
    /// The request path.
    pub path: String,
    /// The reply.
    pub reply: HttpReply,
}

impl SessionReply {
    /// The reply as the bytes a scan reads: the status line, each header
    /// field and the body.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {}\r\n", self.reply.status).into_bytes();
        for (name, value) in &self.reply.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.reply.body);
        out
    }
}

/// The replies a cell gave to sessions, in order.
#[derive(Debug, Default)]
pub struct ResponseLog(Mutex<Vec<SessionReply>>);

impl ResponseLog {
    fn lock(&self) -> MutexGuard<'_, Vec<SessionReply>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `reply` to a request of `method` and `path` in a session
    /// of the cell account `account`.
    pub fn record(&self, account: AccountId, method: &str, path: &str, reply: &HttpReply) {
        self.lock().push(SessionReply {
            account,
            method: method.to_owned(),
            path: path.to_owned(),
            reply: reply.clone(),
        });
    }

    /// How many replies were recorded.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no reply was recorded.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The replies to sessions of the accounts in `accounts`, one store
    /// per reply, named `responses/<n>/<account>/<method> <path>`.
    pub fn stores_of(&self, accounts: &BTreeSet<AccountId>) -> StoreSet {
        let mut set = StoreSet::default();
        for (n, r) in self.lock().iter().enumerate() {
            if accounts.contains(&r.account) {
                set.push(
                    format!("responses/{n}/{}/{} {}", r.account.raw(), r.method, r.path),
                    r.bytes(),
                );
            }
        }
        set
    }
}
