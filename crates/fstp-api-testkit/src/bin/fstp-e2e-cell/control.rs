//! The test-control routes of one cell, on its loopback control base only
//! (layering rule A9, design section 8.7). No cell origin answers them.
//!
//! - `POST /test/reset`: the cell at first start. Its ledger holds only
//!   the provisioning record of its SaaS tenant (`crate::onboarding`),
//!   the synthetic vault knows only the first tenant admin, and the reply
//!   is `{first_admin: {url, email}}`, the admin's one-time enrolment link.
//! - `GET /test/mailbox?to=<email>`: `{messages: [{kind, link}]}`, oldest
//!   first.
//! - `GET /test/account?email=<email>`: `{account}`.
//! - `POST /test/clock/advance {micros}`: moves the cell clock forward.
//! - `POST /test/vault/verify {account, same_identity_as?}`: a completed
//!   identity verification in the synthetic vault, as a wallet or document
//!   check would record it. With `same_identity_as`, the verification
//!   names that account's person (the Sybil case of I-67).
//! - `POST /test/scenario/applicant {at}` and
//!   `POST /test/scenario/review {stage}`: a fresh cell seeded through
//!   production commands ([`crate::scenario`]).
//! - `POST /test/scenario/setup`: a fresh cell where programme manager M1
//!   holds a fully built programme draft ([`crate::scenario::setup`]).
//!
//! - `POST /test/precheck`: one run of the fake pre-check provider
//!   ([`crate::precheck`], Q38 C).
//! - `GET /demo` and its links: the demo page for a person ([`crate::demo`]).
//!
//! A request that carries `Origin`, or a `Sec-Fetch-Site` other than
//! `none`, is refused, so no browser page can reset the cell or mark an
//! identity verified while a demo runs. So is one whose `Host` is not the
//! loopback control address.
//!
//! Interim, pending Daniel: the first admin's token is one value, not the
//! two halves of design section 8.3 (Q35).

use std::collections::BTreeSet;

use fstp_api_testkit::fake::fixture::World;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_http::{Method, Request, Response, StatusCode};
use fstp_json::{Array, Value};
use fstp_ledger::MemStore;

use crate::auth::AuthState;
use crate::wire::{self, dec, dec_member, obj, str_member};
use crate::{Inner, Site, SiteInfo, lock, scenario};

/// The first tenant admin of a reset cell.
pub(crate) const FIRST_ADMIN: AccountId = AccountId::from_raw(0x0a01);

/// The synthetic identity of [`FIRST_ADMIN`].
const FIRST_ADMIN_IDENTITY: IdentityTag = IdentityTag::new(0x0a01);

/// When the clock of a reset cell starts: 2026-10-30T09:00:00Z.
pub(crate) const RESET_START: Timestamp = Timestamp::from_micros(1_793_350_800_000_000);

/// A reset cell and its first admin's enrolment link.
pub(crate) struct Fresh {
    /// The state.
    pub(crate) inner: Inner,
    /// `<origin>/auth/invite#<token>`.
    pub(crate) url: String,
    /// The first admin's login email.
    pub(crate) email: String,
}

/// A synthetic login email under the reserved `.invalid` domain.
pub(crate) fn email(tag: &str) -> Result<String, String> {
    let r = wire::random::<6>()?;
    Ok(format!("synthetic-{tag}-{}@e2e.invalid", wire::hex(&r)))
}

/// The cell at first start: its ledger holds the provisioning record of a
/// SaaS tenant whose first admin is invited (Q31 A, `crate::onboarding`).
pub(crate) fn fresh(info: &SiteInfo) -> Result<Fresh, String> {
    let mut truth = GroundTruth::new();
    truth.set_identity(FIRST_ADMIN, FIRST_ADMIN_IDENTITY);
    let mut store = MemStore::new();
    crate::onboarding::provision(&mut store, FIRST_ADMIN, RESET_START.micros())?;
    let world = World {
        store,
        truth,
        start: RESET_START,
        admins: BTreeSet::from([FIRST_ADMIN]),
    };
    let mut auth = AuthState::new(info);
    let email = email("a1")?;
    auth.person(&email, FIRST_ADMIN);
    let url = auth.invite(FIRST_ADMIN)?;
    let inner = Inner::new(
        info,
        &world,
        auth,
        fstp_domain_testkit::r#gen::policy::MODEL_A,
    )?;
    Ok(Fresh { inner, url, email })
}

/// Whether `req` may use the control routes. A browser page is refused:
/// it sends `Origin` with every cross-origin POST and every fetch, and
/// `Sec-Fetch-Site` with every request it makes. A page that rebinds its
/// own DNS name to loopback is refused too, since its `Host` names that
/// name. The test runner and `tools/demo/run.sh` send neither header,
/// and a `Host` of `127.0.0.1` with the control port or no port.
fn local(info: &SiteInfo, req: &Request) -> bool {
    if req.headers.get("origin").is_some() {
        return false;
    }
    if req
        .headers
        .get("sec-fetch-site")
        .is_some_and(|v| v.as_bytes() != b"none")
    {
        return false;
    }
    loopback_host(info, req)
}

/// Whether `req` names the loopback control address as its one `Host`,
/// with the control port or no port.
pub(crate) fn loopback_host(info: &SiteInfo, req: &Request) -> bool {
    let port = info
        .control
        .trim_start_matches("http://")
        .rsplit_once(':')
        .map(|(_, p)| p);
    let mut hosts = req.headers.get_all("host");
    let (Some(host), None) = (hosts.next().and_then(|h| h.to_str()), hosts.next()) else {
        return false;
    };
    match host.split_once(':') {
        None => host == "127.0.0.1",
        Some((name, p)) => name == "127.0.0.1" && Some(p) == port,
    }
}

/// Answers one control request.
pub(crate) async fn handle(site: &Site, req: Request) -> Response {
    let path = req.target.path();
    if path == "/demo" || path.starts_with("/demo/") {
        return crate::demo::handle(site, req).await;
    }
    if !local(&site.info, &req) {
        return wire::refuse(StatusCode::FORBIDDEN, "control");
    }
    let path = req.target.path().to_owned();
    let get = req.method == Method::GET;
    match (get, path.as_str()) {
        (false, "/test/reset") => reset(site),
        (true, "/test/mailbox") => mailbox(site, &req),
        (true, "/test/account") => account(site, &req),
        (false, "/test/clock/advance") => advance(site, &req),
        (false, "/test/vault/verify") => verify(site, &req),
        (false, "/test/scenario/applicant") => scenario::applicant(site, &req).await,
        (false, "/test/scenario/review") => scenario::review(site, &req).await,
        (false, "/test/scenario/grant") => scenario::postgrant::control(site, &req).await,
        (false, "/test/scenario/setup") => scenario::setup::control(site).await,
        (false, "/test/precheck") => crate::precheck::handle(),
        _ => wire::not_found(),
    }
}

fn reset(site: &Site) -> Response {
    match fresh(&site.info) {
        Ok(f) => {
            site.replace(f.inner);
            wire::json(
                StatusCode::OK,
                &obj(vec![(
                    "first_admin",
                    obj(vec![("url", f.url.into()), ("email", f.email.into())]),
                )]),
            )
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

fn mailbox(site: &Site, req: &Request) -> Response {
    let Some(to) = wire::query_param(req, "to") else {
        return wire::bad("to");
    };
    let inner = site.inner();
    let messages: Vec<Value> = lock(&inner.auth)
        .messages(&to)
        .into_iter()
        .map(|m| obj(vec![("kind", m.kind.into()), ("link", m.link.into())]))
        .collect();
    wire::json(
        StatusCode::OK,
        &obj(vec![("messages", Value::Array(Array::from(messages)))]),
    )
}

fn account(site: &Site, req: &Request) -> Response {
    let Some(email) = wire::query_param(req, "email") else {
        return wire::bad("email");
    };
    let inner = site.inner();
    match lock(&inner.auth).account(&email) {
        Some(a) => wire::json(StatusCode::OK, &obj(vec![("account", dec(a.raw()))])),
        None => wire::refuse(StatusCode::NOT_FOUND, "account"),
    }
}

fn advance(site: &Site, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(n) = dec_member(&body, "micros").and_then(|n| i64::try_from(n).ok()) else {
        return wire::bad("micros");
    };
    if n < 0 {
        return wire::bad("micros");
    }
    let inner = site.inner();
    inner.ports.clock.advance(n);
    wire::json(
        StatusCode::OK,
        &obj(vec![("now", dec(inner.ports.clock.read().micros()))]),
    )
}

fn verify(site: &Site, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let Some(account) = dec_member(&body, "account").and_then(|a| u128::try_from(a).ok()) else {
        return wire::bad("account");
    };
    let account = AccountId::from_raw(account);
    let same = match str_member(&body, "same_identity_as") {
        None => None,
        Some(_) => match dec_member(&body, "same_identity_as").and_then(|a| u128::try_from(a).ok())
        {
            Some(a) => Some(AccountId::from_raw(a)),
            None => return wire::bad("same_identity_as"),
        },
    };
    let inner = site.inner();
    // A fresh synthetic identity, drawn before the vault is changed, for
    // an account the vault does not know yet. Its id is never truncated
    // into a tag, so two accounts never share a person by accident (I-67).
    let Some(fresh) = lock(&inner.auth).fresh_identity() else {
        return wire::refuse(StatusCode::SERVICE_UNAVAILABLE, "identity");
    };
    let mut refused = false;
    inner.ports.vault.change(|t| {
        let tag = match same {
            Some(other) => match t.identity_of(other) {
                Some(tag) => tag,
                None => {
                    refused = true;
                    return;
                }
            },
            None => t.identity_of(account).unwrap_or(fresh),
        };
        t.set_identity(account, tag);
        t.verify(account);
    });
    if refused {
        return wire::refuse(StatusCode::NOT_FOUND, "same_identity_as");
    }
    wire::ok_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_http::{Method, Request, RequestTarget};

    fn site() -> SiteInfo {
        SiteInfo {
            name: "a",
            host: "a.fstp.localhost".to_owned(),
            origin: "http://a.fstp.localhost:8640".to_owned(),
            control: "http://127.0.0.1:8641".to_owned(),
            assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
                .unwrap(),
            auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
            demo_signin: false,
        }
    }

    fn request(headers: &[(&str, &str)]) -> Request {
        let mut r = Request::new(Method::POST, RequestTarget::origin("/test/reset").unwrap());
        for (k, v) in headers {
            r.headers.try_append(k, *v).unwrap();
        }
        r
    }

    /// Layering rule A9, design section 8.7: the control routes answer
    /// the test runner on loopback only. A request a browser page sends,
    /// or one whose `Host` names another host or port, is refused.
    #[test]
    fn a9_control_routes_refuse_browser_pages() {
        let s = site();
        assert!(local(&s, &request(&[("host", "127.0.0.1:8641")])));
        assert!(local(&s, &request(&[("host", "127.0.0.1")])));
        assert!(local(
            &s,
            &request(&[("host", "127.0.0.1:8641"), ("sec-fetch-site", "none")])
        ));
        for refused in [
            vec![
                ("host", "127.0.0.1:8641"),
                ("origin", "http://evil.example"),
            ],
            vec![("host", "127.0.0.1:8641"), ("origin", "null")],
            vec![("host", "127.0.0.1:8641"), ("sec-fetch-site", "cross-site")],
            vec![("host", "rebound.example:8641")],
            vec![("host", "127.0.0.1:8640")],
            vec![("host", "localhost:8641")],
            vec![("host", "127.0.0.1:8641"), ("host", "127.0.0.1:8641")],
            vec![],
        ] {
            assert!(!local(&s, &request(&refused)), "{refused:?}");
        }
    }

    /// I-67: each account the vault does not know gets its own synthetic
    /// identity, even when two account ids share their low 64 bits.
    #[test]
    fn i67_synthetic_identities_are_never_shared() {
        let mut a = AuthState::new(&site());
        let first = a.fresh_identity().unwrap();
        let second = a.fresh_identity().unwrap();
        assert_ne!(first, second);
        assert!(first.raw() > FIRST_ADMIN_IDENTITY.raw());
    }
}
