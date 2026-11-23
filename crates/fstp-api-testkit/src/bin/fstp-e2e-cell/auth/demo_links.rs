//! The email links of the demo (ADR-008 record of lane L37; Daniel,
//! 2026-11-22). Test only: this module lives in `fstp-e2e-cell`, and its
//! routes exist only on a cell started with `--demo-signin`.
//!
//! The demo cell sends no mail. Each link below goes into the cell's
//! mailbox, which the demo inbox `/demo/inbox` lists with its code, so a
//! person opens it by clicking:
//!
//! - `POST /auth/magic/request {email}`: a sign-in link `/auth/magic#<t>`
//!   for a Receiving-only account, and the same 202 for every address. A
//!   tenant admin or a holder of any binding outside the Receiving group,
//!   a suspended one included, gets no link (I-77).
//! - `POST /auth/magic/consume {token}`: takes the token once, reads the
//!   holdings again and opens a magic-link session (I-77).
//! - `POST /auth/passkey-link {}` in a session: for an account with no
//!   passkey, the link `/auth/recovery#e.<case>.<t>` of an "email link,
//!   then create passkey" case (ADR-008 "Later passkey"), and 202. An
//!   account with a passkey gets 409 `passkey`.
//! - `POST /auth/recovery/{case}/email {token}`: the email proof, taken
//!   once, answers `{path: "EmailThenPasskey", enrolment}`.
//! - `POST /auth/recovery/{case}/complete {token}`: the creation options
//!   of the new passkey, then with the credential the passkey itself and
//!   a passkey session.
//!
//! The tokens are single use and do not expire, as the demo cell's
//! proof tokens already do not (Interim, pending Daniel).

use fstp_api_core::port::LoginMethod;
use fstp_domain::id::AccountId;
use fstp_domain::roles::Group;
use fstp_http::{Request, Response, StatusCode};
use fstp_json::Value;

use super::{COOKIE, Purpose, id_member, open_session, session};
use crate::wire::{self, hex, obj, refuse, str_member};
use crate::{Inner, SiteInfo, lock};

/// One open "email link, then create passkey" case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Case {
    /// The account the case is for.
    account: AccountId,
    /// The email proof token, until it is taken.
    proof: Option<String>,
    /// The enrolment token, once the proof was taken.
    enrolment: Option<String>,
}

/// A fresh token: 32 random bytes in lowercase hex, as the cell's own.
fn token() -> Result<String, String> {
    Ok(hex(&wire::random::<32>()?))
}

/// The one reply of a request that may send a link (ADR-008).
fn accepted() -> Response {
    wire::json(
        StatusCode::ACCEPTED,
        &obj(vec![("status", "accepted".into())]),
    )
}

/// Whether `account` holds a management role (I-77, ADR-008
/// "Holdings"): a tenant admin, or a binding outside the Receiving group
/// that is not voided, a suspended one included.
pub(crate) fn manages(inner: &Inner, account: AccountId) -> bool {
    inner.ports.tenant.holds_admin(account)
        || inner
            .ports
            .engine
            .state()
            .core
            .roster()
            .bindings()
            .any(|(_, b)| b.account == account && !b.voided() && b.group() != Group::Receiving)
}

/// `POST /auth/magic/request {email}` (module documentation).
pub(super) fn magic_request(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(email) = str_member(&body, "email") else {
        return wire::bad("email");
    };
    let account = lock(&inner.auth).account(email);
    if let Some(a) = account
        && !manages(inner, a)
    {
        let Ok(t) = token() else {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
        };
        let mut auth = lock(&inner.auth);
        auth.magic.insert(t.clone(), a);
        auth.mail(email, "magic", format!("{}/auth/magic#{t}", info.origin));
    }
    accepted()
}

/// `POST /auth/magic/consume {token}` (module documentation).
pub(super) fn magic_consume(inner: &Inner, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(t) = str_member(&body, "token") else {
        return wire::bad("token");
    };
    let Some(account) = lock(&inner.auth).magic.remove(t) else {
        return refuse(StatusCode::UNAUTHORIZED, "token");
    };
    // I-77: the holdings are read again at the use of the link.
    if manages(inner, account) {
        return refuse(StatusCode::UNAUTHORIZED, "token");
    }
    let login = inner.ports.sessions.login(account, LoginMethod::MagicLink);
    let mut r = wire::ok_empty();
    let value = format!(
        "{COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        String::from_utf8_lossy(&login.cookie)
    );
    let _ = r.headers.try_insert("set-cookie", value.as_str());
    r
}

/// `POST /auth/passkey-link {}` (module documentation).
pub(super) async fn passkey_link(info: &SiteInfo, inner: &Inner, req: &Request) -> Response {
    let Some((_, account)) = session(inner, req).await else {
        return refuse(StatusCode::UNAUTHORIZED, "session");
    };
    let (Ok(case), Ok(proof)) = (wire::random::<16>(), token()) else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
    };
    let case = hex(&case);
    let mut a = lock(&inner.auth);
    if a.passkeys.values().any(|p| p.account == account) {
        return refuse(StatusCode::CONFLICT, "passkey");
    }
    let Some(email) = a.email_of(account).map(str::to_owned) else {
        return accepted();
    };
    a.recoveries.insert(
        case.clone(),
        Case {
            account,
            proof: Some(proof.clone()),
            enrolment: None,
        },
    );
    a.mail(
        &email,
        "passkey_link",
        format!("{}/auth/recovery#e.{case}.{proof}", info.origin),
    );
    accepted()
}

/// `POST /auth/recovery/{case}/email {token}` (module documentation).
pub(super) fn recovery_email(inner: &Inner, case: &str, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(t) = str_member(&body, "token") else {
        return wire::bad("token");
    };
    let Ok(enrolment) = token() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
    };
    let mut a = lock(&inner.auth);
    match a.recoveries.get_mut(case) {
        Some(c) if c.proof.as_deref() == Some(t) => {
            c.proof = None;
            c.enrolment = Some(enrolment.clone());
            wire::json(
                StatusCode::OK,
                &obj(vec![
                    ("path", "EmailThenPasskey".into()),
                    ("enrolment", enrolment.as_str().into()),
                ]),
            )
        }
        _ => refuse(StatusCode::UNAUTHORIZED, "token"),
    }
}

/// `POST /auth/recovery/{case}/complete` (module documentation): the
/// enrolment token alone answers the creation options, and with a
/// credential the route stores the passkey and opens a passkey session.
pub(super) fn recovery_complete(inner: &Inner, case: &str, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(t) = str_member(&body, "token").map(str::to_owned) else {
        return wire::bad("token");
    };
    let purpose = Purpose::Recovery {
        case: case.to_owned(),
        token: t.clone(),
    };
    let registered = {
        let mut a = lock(&inner.auth);
        let Some(c) = a.recoveries.get(case).cloned() else {
            return refuse(StatusCode::UNAUTHORIZED, "token");
        };
        if c.enrolment.as_deref() != Some(t.as_str()) {
            return refuse(StatusCode::UNAUTHORIZED, "token");
        }
        if body.get("challenge_id").is_none() {
            let Ok((id, bytes)) = a.challenge(purpose) else {
                return refuse(StatusCode::SERVICE_UNAVAILABLE, "random");
            };
            let email = a
                .email_of(c.account)
                .unwrap_or("synthetic@e2e.invalid")
                .to_owned();
            let options = a.creation(c.account, &email, &bytes);
            return wire::json(
                StatusCode::OK,
                &obj(vec![
                    ("challenge_id", Value::from(hex(&id))),
                    ("public_key", options),
                ]),
            );
        }
        let Some(id) = id_member(&body, "challenge_id") else {
            return wire::bad("challenge_id");
        };
        let Some(ch) = a.challenges.remove(&id) else {
            return refuse(StatusCode::UNAUTHORIZED, "challenge");
        };
        if ch.purpose != purpose {
            return refuse(StatusCode::UNAUTHORIZED, "challenge");
        }
        match a.register(&body, &ch.bytes, c.account) {
            Ok(passkey) => {
                a.recoveries.remove(case);
                (c.account, passkey)
            }
            Err(why) => return refuse(StatusCode::UNAUTHORIZED, why),
        }
    };
    open_session(inner, registered.0, registered.1)
}
