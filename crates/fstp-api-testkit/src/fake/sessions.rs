//! Fake M3 sessions (`authentication.md`, R-LG-04).
//!
//! A test logs an account in with a method and gets the session cookie
//! value. The fake resolves only `Credential::SessionCookie`. A bearer
//! token is not a session, so it gets `PortError::Refused`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    LoginMethod, PortError, SessionId, SessionInfo, SessionPrincipal, Sessions, SessionsAdmin,
};
use fstp_api_core::{Credential, RequestHead};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

use super::{FakeClock, FakeTenant, lock};

/// The first session id the fake draws.
const FIRST_SESSION: u128 = 0x5e55_0000;

/// What a login gave the test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebLogin {
    /// The `__Host-` session cookie value.
    pub cookie: Vec<u8>,
    /// The session.
    pub session: SessionId,
    /// The account.
    pub account: AccountId,
}

/// Whether `method` is phishing-resistant (I-77).
pub const fn phishing_resistant(method: LoginMethod) -> bool {
    matches!(method, LoginMethod::Passkey | LoginMethod::EudiWallet)
}

#[derive(Debug)]
struct Row {
    account: AccountId,
    session: SessionId,
    method: LoginMethod,
    started: Timestamp,
    ended: bool,
}

#[derive(Debug)]
struct State {
    rows: BTreeMap<Vec<u8>, Row>,
    next: u128,
}

/// The fake sessions and sessions admin port. Cloning shares the sessions.
#[derive(Clone, Debug)]
pub struct FakeSessions {
    state: Arc<Mutex<State>>,
    clock: FakeClock,
    tenant: FakeTenant,
}

impl FakeSessions {
    /// No session yet. Logins read `clock` and the admin set of `tenant`.
    pub fn new(clock: FakeClock, tenant: FakeTenant) -> FakeSessions {
        FakeSessions {
            state: Arc::new(Mutex::new(State {
                rows: BTreeMap::new(),
                next: FIRST_SESSION,
            })),
            clock,
            tenant,
        }
    }

    /// Logs `account` in with `method` and returns the cookie value.
    pub fn login(&self, account: AccountId, method: LoginMethod) -> WebLogin {
        let mut s = lock(&self.state);
        let n = s.next;
        s.next = n.saturating_add(1);
        let session = SessionId::from_raw(n);
        // Text, so the value travels in a real `Cookie` header of the e2e
        // cell.
        let cookie = format!("fake-session-{n:032x}").into_bytes();
        s.rows.insert(
            cookie.clone(),
            Row {
                account,
                session,
                method,
                started: self.clock.read(),
                ended: false,
            },
        );
        WebLogin {
            cookie,
            session,
            account,
        }
    }

    /// Ends `session`. Its cookie no longer resolves.
    pub fn end_session(&self, session: SessionId) {
        let mut s = lock(&self.state);
        for row in s.rows.values_mut() {
            if row.session == session {
                row.ended = true;
            }
        }
    }

    fn resolve(&self, cookie: &[u8]) -> Result<SessionPrincipal, PortError> {
        let s = lock(&self.state);
        let row = s.rows.get(cookie).ok_or(PortError::Refused)?;
        if row.ended {
            return Err(PortError::Refused);
        }
        Ok(SessionPrincipal {
            account: row.account,
            session: row.session,
            method: row.method,
            phishing_resistant: phishing_resistant(row.method),
            tenant_admin: self.tenant.holds_admin(row.account),
        })
    }
}

impl Sessions for FakeSessions {
    async fn principal(
        &self,
        head: &RequestHead,
        cred: &Credential,
        now: Timestamp,
    ) -> Result<SessionPrincipal, PortError> {
        let _ = (head, now);
        match cred {
            Credential::SessionCookie(c) => self.resolve(c),
            Credential::None | Credential::Bearer(_) => Err(PortError::Refused),
        }
    }
}

impl SessionsAdmin for FakeSessions {
    async fn list(&self, a: AccountId) -> Result<Vec<SessionInfo>, PortError> {
        let s = lock(&self.state);
        Ok(s.rows
            .values()
            .filter(|r| r.account == a && !r.ended)
            .map(|r| SessionInfo {
                session: r.session,
                method: r.method,
                started: r.started,
            })
            .collect())
    }

    async fn end(&self, a: AccountId, session: SessionId) -> Result<(), PortError> {
        let mut s = lock(&self.state);
        let row = s
            .rows
            .values_mut()
            .find(|r| r.session == session && r.account == a)
            .ok_or(PortError::Refused)?;
        row.ended = true;
        Ok(())
    }
}
