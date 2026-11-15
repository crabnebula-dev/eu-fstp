//! The page gate of SA-09 over the demo scenes: a table test.
//!
//! For each scene the demo page builds, each person of the scene and
//! each row of the page table (`fstp_access::PAGES`), with every id of
//! the scene and one unknown id in each parameter, the cell serves the
//! page exactly when the API admits the page's read:
//!
//! - a passkey session: 200 with the shell when the read answers 200
//!   (and lists the page's own id, for a [`fstp_access::Listed`] row),
//!   else 303 to home `/app/` with the bytes of an unknown path (SA-09
//!   amendment);
//! - a magic-link session: as above, and 303 to a passkey sign-in where
//!   the read is refused for the login strength alone (I-77);
//! - no session: 200 where the read admits anyone, else 303 to the login
//!   page with the page as its return path.
//!
//! The reads go through `/api/v1` of the same cell, so the oracle is the
//! dispatch itself, never a second copy of the rules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_access::{PAGES, PageNeed, PageRow};
use fstp_api_core::port::LoginMethod;
use fstp_domain::id::AccountId;
use fstp_domain::roles::BindingScope;
use fstp_http::{Method, Request, RequestTarget, Response};
use fstp_json::Value;
use fstp_rt::future::block_on;

use crate::{Inner, SiteInfo, control, scenario};

/// An id no scene holds.
const UNKNOWN: &str = "987654321987";

/// The pages no person of the checked scenes may open, so the table test
/// sees each of them refused only.
const NEVER_OPEN: &[&str] = &[
    // No scene holds a pending action of an agent client.
    "/app/pending/{pending}",
    // The ids of cut-off rounds live in the journal of the API core,
    // which the table test does not read, so only an unknown id is tried.
    "/app/cut-off-rounds/{round}",
];

fn info() -> SiteInfo {
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

/// `GET path` on the cell origin with the session cookie `cookie`.
fn get(inner: &Inner, path: &str, cookie: Option<&[u8]>) -> Response {
    let mut req = Request::new(Method::GET, RequestTarget::origin(path).unwrap());
    req.headers.try_append("host", "a.fstp.localhost").unwrap();
    req.headers
        .try_append("accept", "application/json")
        .unwrap();
    if let Some(c) = cookie {
        let v = format!("__Host-fstp={}", String::from_utf8_lossy(c));
        req.headers.try_append("cookie", v.as_str()).unwrap();
    }
    block_on(inner.web.serve(req))
}

/// The ids of each parameter name in the scene's state, each with
/// [`UNKNOWN`].
fn ids(inner: &Inner, name: &str) -> Vec<String> {
    let state = inner.ports.engine.state();
    let core = &state.core;
    let mut set: BTreeSet<u128> = BTreeSet::new();
    let roster = core.roster();
    let bindings: Vec<_> = roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
        .collect();
    match name {
        "programme" => {
            set.extend(core.calls().iter().map(|(_, c)| c.programme().raw()));
            set.extend(bindings.iter().map(|b| b.programme.raw()));
        }
        "call" => set.extend(core.calls().iter().map(|(c, _)| c.raw())),
        "proposal" => {
            for b in &bindings {
                if let BindingScope::Proposal { proposal, .. } = b.scope {
                    set.insert(proposal.raw());
                }
            }
        }
        "assignment" | "irc_assignment" => {
            set.extend(core.review().assignments().map(|(a, _)| a.raw()));
        }
        "request" => set.extend(core.payments().summaries().map(|s| s.request.raw())),
        _ => {}
    }
    let mut out: Vec<String> = set.into_iter().map(|n| n.to_string()).collect();
    out.push(UNKNOWN.to_owned());
    out
}

/// Every path of `row` in the scene: each combination of its
/// parameters' values.
fn paths(inner: &Inner, row: &PageRow) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = vec![(String::new(), Vec::new())];
    for seg in row.pattern.split('/').skip(1) {
        let choices: Vec<(String, Option<String>)> =
            match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => {
                    let vals = match row.values_of(name) {
                        Some(v) => v.iter().map(|s| (*s).to_owned()).collect(),
                        None => ids(inner, name),
                    };
                    vals.into_iter()
                        .map(|v| (v, Some(name.to_owned())))
                        .collect()
                }
                None => vec![(seg.to_owned(), None)],
            };
        let mut next = Vec::new();
        for (p, params) in &out {
            for (v, name) in &choices {
                let mut params = params.clone();
                if let Some(n) = name {
                    params.push((n.clone(), v.clone()));
                }
                next.push((format!("{p}/{v}"), params));
            }
        }
        out = next;
    }
    out
}

/// The API path of the read `name` with the page's parameters.
fn api_path(name: &str, params: &[(String, String)]) -> String {
    let spec = fstp_access::page_read(name).unwrap();
    let (_, route) = spec.route.unwrap();
    let filled: Vec<String> = route
        .split('/')
        .map(
            |s| match s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(p) => params
                    .iter()
                    .find(|(n, _)| n == p)
                    .map(|(_, v)| v.clone())
                    .unwrap(),
                None => s.to_owned(),
            },
        )
        .collect();
    format!("/api/v1{}", filled.join("/"))
}

/// Whether `v` holds an object whose member `key` is `id`.
fn holds(v: &Value, key: &str, id: &str) -> bool {
    match v {
        Value::Object(o) => o.iter().any(|(k, x)| {
            (k == key
                && (x.as_str() == Some(id) || matches!(x, Value::Number(n) if n.to_string() == id)))
                || holds(x, key, id)
        }),
        Value::Array(a) => a.iter().any(|x| holds(x, key, id)),
        _ => false,
    }
}

/// What the API answers the page's reads: `Some(true)` when one admits
/// the viewer (and lists the page's own id), `Some(false)` when every
/// refusal was for the login strength alone, `None` otherwise.
fn oracle(
    inner: &Inner,
    row: &PageRow,
    params: &[(String, String)],
    cookie: Option<&[u8]>,
) -> Option<bool> {
    let mut weak = false;
    for name in row.reads() {
        let r = get(inner, &api_path(name, params), cookie);
        let body = String::from_utf8_lossy(&r.body).into_owned();
        if r.status.as_u16() == 200 {
            let Some((param, how)) = row.listed else {
                return Some(true);
            };
            let key = match how {
                fstp_access::Listed::PaymentRequest => "request",
                fstp_access::Listed::PendingAction => "id",
                _ => "assignment",
            };
            let id = &params.iter().find(|(n, _)| n == param).unwrap().1;
            let v = fstp_json::parse_str(&body).unwrap();
            let irc = how == fstp_access::Listed::IrcAssignment;
            if holds(&v, key, id) && (!irc || body.contains("\"irc\"")) {
                return Some(true);
            }
            return None;
        }
        if body.contains("\"login_strength\"") {
            weak = true;
        }
    }
    weak.then_some(false)
}

/// The people of the scene: those the demo page lists.
fn people(inner: &Inner) -> Vec<AccountId> {
    crate::demo::scene_people(inner, control::FIRST_ADMIN)
        .into_iter()
        .map(|p| p.account)
        .collect()
}

/// Checks every page row for every person of the scene `scene`, and
/// for a visitor with no session. It returns the failures.
fn check_scene(
    scene: &str,
    inner: &Inner,
    magic: bool,
    seen: &mut BTreeSet<(&'static str, &'static str)>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut viewers: Vec<(String, Option<Vec<u8>>)> = vec![("no session".to_owned(), None)];
    for a in people(inner) {
        // A fresh minute of the clock for each viewer, so no rate limit
        // of design section 3.7 step 4 refuses the oracle's reads.
        inner.ports.clock.advance(61_000_000);
        let method = if magic {
            LoginMethod::MagicLink
        } else {
            LoginMethod::Passkey
        };
        let login = inner.ports.sessions.login(a, method);
        viewers.push((format!("account {}", a.raw()), Some(login.cookie)));
    }
    for (who, cookie) in &viewers {
        let cookie = cookie.as_deref();
        let missing = get(inner, "/app/no-such-page", cookie);
        assert_eq!(missing.status.as_u16(), 303);
        assert_eq!(
            missing.headers.get("location").and_then(|v| v.to_str()),
            Some("/app/")
        );
        for row in PAGES {
            for (path, params) in paths(inner, row) {
                let r = get(inner, &path, cookie);
                let status = r.status.as_u16();
                let location = r
                    .headers
                    .get("location")
                    .and_then(|v| v.to_str())
                    .unwrap_or("")
                    .to_owned();
                let want = match (row.need, cookie) {
                    (PageNeed::Anyone, _) => Want::Shell,
                    (PageNeed::Account, None) => Want::SignIn,
                    (PageNeed::Account, Some(_)) => Want::Shell,
                    (PageNeed::Reads(_), _) => match oracle(inner, row, &params, cookie) {
                        Some(true) => Want::Shell,
                        _ if cookie.is_none() => Want::SignIn,
                        Some(false) => Want::Passkey,
                        None => Want::NotFound,
                    },
                };
                seen.insert((row.pattern, want.name()));
                let ok = match want {
                    Want::Shell => status == 200,
                    Want::NotFound => {
                        status == 303 && location == "/app/" && r.body == missing.body
                    }
                    Want::SignIn => {
                        status == 303
                            && location.starts_with("/auth/login")
                            && !location.contains("method=passkey")
                    }
                    Want::Passkey => status == 303 && location.contains("method=passkey"),
                };
                if !ok {
                    let api = row.reads().first().map(|n| {
                        let r = get(inner, &api_path(n, &params), cookie);
                        format!("{} {}", r.status.as_u16(), String::from_utf8_lossy(&r.body))
                    });
                    failures.push(format!(
                        "{scene}, {who}: {path}: want {want:?}, got {status} {location}; API {api:?}"
                    ));
                }
            }
        }
    }
    failures
}

#[derive(Clone, Copy, Debug)]
enum Want {
    Shell,
    NotFound,
    SignIn,
    Passkey,
}

impl Want {
    fn name(self) -> &'static str {
        match self {
            Want::Shell => "shell",
            Want::NotFound => "not found",
            Want::SignIn => "sign in",
            Want::Passkey => "passkey",
        }
    }
}

/// SA-09 rules 2, 3 and 5, R-AC-01, ADR-021: over the demo scenes, every
/// person and every page row, the cell serves a page exactly when the
/// API admits the page's read; a visitor with no session goes to sign
/// in; a viewer the read refuses gets the answer of an unknown path, 303
/// to home (SA-09 amendment).
#[test]
fn sa09_r_ac_01_pages_are_served_exactly_when_their_read_is_admitted() {
    let info = info();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    let reset = control::fresh(&info).unwrap();
    failures.extend(check_scene("reset", &reset.inner, false, &mut seen));
    for stage in [
        scenario::ReviewAt::Stage1,
        scenario::ReviewAt::Stage2,
        scenario::ReviewAt::IrcReview,
    ] {
        let (inner, _) = block_on(scenario::build_review(&info, stage)).unwrap();
        failures.extend(check_scene(&format!("{stage:?}"), &inner, false, &mut seen));
    }
    for at in ["DRAFT", "NEGOTIATION"] {
        let (inner, _) = block_on(scenario::build_applicant(
            &info,
            scenario::At::parse(at).unwrap(),
        ))
        .unwrap();
        failures.extend(check_scene(at, &inner, false, &mut seen));
    }
    let (inner, _) = block_on(scenario::setup::build(&info)).unwrap();
    failures.extend(check_scene("setup", &inner, false, &mut seen));
    let (inner, _) = block_on(scenario::postgrant::build(
        &info,
        scenario::postgrant::GrantAt::parse("UNDER_REVIEW").unwrap(),
    ))
    .unwrap();
    failures.extend(check_scene("UNDER_REVIEW", &inner, false, &mut seen));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    for want in ["shell", "not found", "sign in"] {
        assert!(seen.iter().any(|(_, w)| *w == want), "no case wants {want}");
    }
    let never: Vec<&str> = PAGES
        .iter()
        .map(|r| r.pattern)
        .filter(|p| !seen.contains(&(*p, "shell")))
        .collect();
    assert_eq!(
        never, NEVER_OPEN,
        "the pages no person of the scenes may open"
    );
}

/// SA-09 rule 4, I-77: a magic-link session on a page whose read needs a
/// passkey is sent to sign in with a passkey; every other page answers
/// as for a passkey session.
#[test]
fn sa09_i77_weak_login_signs_in_with_a_passkey() {
    let info = info();
    let (inner, _) = block_on(scenario::build_review(&info, scenario::ReviewAt::Stage1)).unwrap();
    let mut seen = BTreeSet::new();
    let failures = check_scene("stage1 magic", &inner, true, &mut seen);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        seen.iter().any(|(_, w)| *w == "passkey"),
        "no page wants a passkey"
    );
}
