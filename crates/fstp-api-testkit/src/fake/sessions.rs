//! Fake M3 sessions (`authentication.md`, R-LG-04).
//!
//! A test logs an account in with a method and gets the session cookie
//! value. The fake resolves only `Credential::SessionCookie`. A bearer
//! token is not a session, so it gets `PortError::Refused`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    LoginMethod, PasskeyRegistration, PortError, SessionId, SessionInfo, SessionPrincipal,
    Sessions, SessionsAdmin, StepUpProof,
};
use fstp_api_core::{Credential, RequestHead};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;

use super::{FakeClock, FakeTenant, lock};

/// The first session id the fake draws.
const FIRST_SESSION: u128 = 0x5e55_0000;

/// The relying party of the fake cell's passkeys: its exact host.
pub const PASSKEY_RP: &str = "cell.fstp.test";

/// How long a creation challenge lives, as the cell's `/auth` routes keep
/// their challenges: 5 minutes.
const CHALLENGE_US: i64 = 300_000_000;

/// The creation options of `POST /auth/passkeys/options` for one session:
/// the single-use challenge and the relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasskeyOptions {
    /// The id the registration names.
    pub challenge_id: [u8; 16],
    /// The challenge the authenticator signs over.
    pub challenge: [u8; 32],
    /// The relying party id.
    pub rp_id: &'static str,
}

/// The ceremony's form of a login method.
const fn auth_method(m: LoginMethod) -> fstp_auth::Method {
    match m {
        LoginMethod::Passkey => fstp_auth::Method::Passkey,
        LoginMethod::MagicLink => fstp_auth::Method::MagicLink,
        LoginMethod::Opaque => fstp_auth::Method::Opaque,
        LoginMethod::EudiWallet => fstp_auth::Method::EudiWallet,
    }
}

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
    /// The open creation challenges of `/auth/passkeys/options`, by id:
    /// the session, the challenge and when it was issued.
    challenges: BTreeMap<[u8; 16], (SessionId, [u8; 32], Timestamp)>,
    /// The credential ids each account registered through the ceremony.
    passkeys: BTreeMap<AccountId, Vec<Vec<u8>>>,
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
                challenges: BTreeMap::new(),
                passkeys: BTreeMap::new(),
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

    /// `POST /auth/passkeys/options` of the cell (R-LG-04, design section
    /// 8.3): a fresh single-use creation challenge for the live session
    /// `session`. A session the fake does not hold, or one that ended, is
    /// refused.
    pub fn passkey_options(&self, session: SessionId) -> Result<PasskeyOptions, PortError> {
        let challenge_id = fstp_crypto::random_array::<16>().map_err(|_| PortError::Unavailable)?;
        let challenge = fstp_crypto::random_array::<32>().map_err(|_| PortError::Unavailable)?;
        let now = self.clock.read();
        let mut s = lock(&self.state);
        if !s.rows.values().any(|r| r.session == session && !r.ended) {
            return Err(PortError::Refused);
        }
        s.challenges.insert(challenge_id, (session, challenge, now));
        Ok(PasskeyOptions {
            challenge_id,
            challenge,
            rp_id: PASSKEY_RP,
        })
    }

    /// The credential ids `account` registered through the ceremony.
    pub fn passkeys_of(&self, account: AccountId) -> Vec<Vec<u8>> {
        lock(&self.state)
            .passkeys
            .get(&account)
            .cloned()
            .unwrap_or_default()
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

    /// The ceremony of the cell's `POST /auth/passkeys`, as the gate's
    /// `fstp_cell_core::gate::admit_add_passkey` runs it: the challenge
    /// of the session's options is taken once and must be fresh, the
    /// registration verifies through `fstp-webauthn` with a credential id
    /// new to the cell (`fstp_auth::ceremony::verify_fresh_passkey`), and
    /// the account holds a passkey already in a phishing-resistant session
    /// (`fstp_auth::ceremony::admit_add_passkey`). The API core took the
    /// step-up of `proof`. Interim: the fake holds no roles, so it asks
    /// user verification of every account, the strictest reading of
    /// ADR-008 "User verification".
    async fn add_passkey(
        &self,
        a: AccountId,
        session: SessionId,
        reg: PasskeyRegistration,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = proof;
        let now = self.clock.read();
        let mut s = lock(&self.state);
        let (method, started) = s
            .rows
            .values()
            .find(|r| r.session == session && r.account == a && !r.ended)
            .map(|r| (r.method, r.started))
            .ok_or(PortError::Refused)?;
        let (owner, challenge, issued) = s
            .challenges
            .remove(&reg.challenge_id)
            .ok_or(PortError::Refused)?;
        let age = now.micros().saturating_sub(issued.micros());
        if owner != session || !(0..CHALLENGE_US).contains(&age) {
            return Err(PortError::Refused);
        }
        let rp =
            fstp_webauthn::RelyingParty::new(PASSKEY_RP).map_err(|_| PortError::Unavailable)?;
        let response = fstp_webauthn::RegistrationResponse {
            client_data_json: reg.client_data_json,
            attestation_object: reg.attestation_object,
        };
        let registration = fstp_auth::ceremony::Registration {
            response: &response,
            rp: &rp,
            challenge,
        };
        let view = fstp_auth::SessionView {
            id: session.raw().to_be_bytes(),
            account: a,
            method: auth_method(method),
            started,
            last_used: now,
        };
        let has_passkey =
            method == LoginMethod::Passkey || s.passkeys.get(&a).is_some_and(|v| !v.is_empty());
        let known: std::collections::BTreeSet<Vec<u8>> =
            s.passkeys.values().flatten().cloned().collect();
        let known = |id: &[u8]| known.contains(id);
        let cred = fstp_auth::ceremony::verify_fresh_passkey(&registration, true, &known)
            .map_err(|_| PortError::Refused)?;
        fstp_auth::ceremony::admit_add_passkey(has_passkey, &view, Ok(()))
            .map_err(|_| PortError::Refused)?;
        s.passkeys.entry(a).or_default().push(cred.id);
        Ok(())
    }
}
