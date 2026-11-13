//! The `/p` routes of a cell's own router (R-PB-04, R-PB-03, TH-37;
//! M4 design section 3.10).
//!
//! `r_pb_04_public_pages_scriptless.rs` checks the stub configuration of
//! `fstp_web::handle_op_request`. These tests mount `fstp_web::router` over
//! an `ApiCore` of fake ports, as `fstp-cell` and `fstp-e2e-cell` do, on
//! the I-85 world: programme P1 with call 3 published and the lead's
//! draft proposal PX in it. The lead is signed in, so the session cookie
//! of each request is a live one. A canary text is stored as PX's
//! proposal text.
//!
//! The rules hold for whatever `/p` answers: exactly the public CSP, no
//! `Set-Cookie`, a live session cookie that changes nothing, no script,
//! and no proposal text (R-PB-03). P1 has no public slug, since its draft
//! was opened from the setup's own policy, so these paths name the
//! SuperSAFE slug and the programme id both. The pages with content are
//! checked in `fstp-public` and in `e2e/site`.
//!
//! Status: green on the 501 stub of `/p`. They pin the headers on the
//! cell's router before the public pages land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::sync::Arc;

use fstp_api_core::port::{LoginMethod, TextClass, TextOwner, api_core};
use fstp_api_testkit::fake::fixture::{LEAD, PX, World, pending_world, pending_world_pinning};
use fstp_api_testkit::fake::{FakePorts, port_seams};
use fstp_http::{Parsed, parse_request};
use fstp_web::{PUBLIC_CSP, SESSION_COOKIE, WebConfig, WebRouter, limits, parse_origin_header};

/// The tenant origin of the cell.
const ORIGIN: &str = "https://tenant.fstp.test";

/// The canary stored as PX's proposal text. Synthetic.
const CANARY: &str = "PROPOSAL-TEXT-CANARY-PX-SYNTHETIC";

/// Every public route of design section 3.10, by slug and by id.
const PATHS: &[&str] = &[
    "/p/supersafe/",
    "/p/supersafe/calls/3",
    "/p/supersafe/calls/3/guide",
    "/p/supersafe/funded",
    "/p/supersafe/finished",
    "/p/supersafe/feed.json",
    "/p/1/",
    "/p/1/calls/3",
    "/p/1/calls/3/guide",
    "/p/1/funded",
    "/p/1/finished",
    "/p/1/feed.json",
    "/p/no-such-programme/",
];

/// The cell: the router, and the lead's session cookie value.
struct Cell {
    router: WebRouter,
    cookie: Vec<u8>,
}

fn cell() -> Cell {
    cell_of(pending_world().unwrap_or_else(|e| panic!("the I-85 world: {e}")))
}

/// The cell over `world`.
fn cell_of(world: World) -> Cell {
    let seams = port_seams().unwrap_or_else(|e| panic!("{e}"));
    let ports = FakePorts::new(&world, seams).unwrap_or_else(|e| panic!("{e}"));
    let _ = ports.texts.put_now(
        TextClass::Confidential,
        TextOwner::Proposal(PX),
        CANARY.as_bytes(),
    );
    let login = ports.sessions.login(LEAD, LoginMethod::Passkey);
    let core = Arc::new(api_core(ports));
    let origin = parse_origin_header(ORIGIN.as_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
    let assets = fstp_web::AssetSet::from_files(
        "main.js",
        &[(
            "main.js",
            b"// public routes test asset set\nexport {};\n".as_slice(),
        )],
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let router =
        fstp_web::router(core, WebConfig::new(origin, assets)).unwrap_or_else(|e| panic!("{e:?}"));
    Cell {
        router,
        cookie: login.cookie,
    }
}

/// One response: status, lowercase field names with values, and body.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    status: u16,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Reply {
    fn values(&self, name: &str) -> Vec<String> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }
}

/// A `GET` of `path`, with the lead's live session cookie when `signed_in`.
fn get(c: &Cell, path: &str, signed_in: bool) -> Reply {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: tenant.fstp.test\r\n");
    if signed_in {
        raw.push_str(&format!(
            "Cookie: {SESSION_COOKIE}={}\r\n",
            String::from_utf8_lossy(&c.cookie)
        ));
    }
    raw.push_str("\r\n");
    let req = match parse_request(raw.as_bytes(), &limits()) {
        Ok(Parsed::Complete { message, .. }) => message,
        other => panic!("{path}: {other:?}"),
    };
    let r = fstp_rt::future::block_on(c.router.serve(req));
    Reply {
        status: r.status.as_u16(),
        fields: r
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect(),
        body: r.body,
    }
}

/// R-PB-04, TH-37: every `/p` answer of the cell's router carries exactly
/// the public CSP and sets no cookie, signed in or not.
#[test]
fn r_pb_04_cell_router_public_answers_carry_the_csp_and_set_no_cookie() {
    let c = cell();
    let mut failures = Vec::new();
    for path in PATHS {
        for signed_in in [false, true] {
            let r = get(&c, path, signed_in);
            if r.values("content-security-policy") != [PUBLIC_CSP] {
                failures.push(format!(
                    "{path} ({signed_in}): CSP {:?}",
                    r.values("content-security-policy")
                ));
            }
            if !r.values("set-cookie").is_empty() {
                failures.push(format!(
                    "{path} ({signed_in}): Set-Cookie {:?}",
                    r.values("set-cookie")
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// R-PB-04, TH-37: a live session cookie is ignored on `/p`. The answer
/// with it equals the answer without it, byte for byte.
#[test]
fn r_pb_04_cell_router_ignores_a_live_session_cookie() {
    let c = cell();
    for path in PATHS {
        assert_eq!(get(&c, path, false), get(&c, path, true), "{path}");
    }
}

/// R-PB-04, R-PB-03: no `/p` answer holds a script or the canary stored
/// as a proposal's text.
#[test]
fn r_pb_03_cell_router_public_answers_hold_no_script_and_no_proposal_text() {
    let c = cell();
    for path in PATHS {
        for signed_in in [false, true] {
            let r = get(&c, path, signed_in);
            let body = String::from_utf8_lossy(&r.body);
            assert!(
                !body.to_ascii_lowercase().contains("<script"),
                "{path}: {body}"
            );
            assert!(
                !body.contains(CANARY),
                "{path}: the proposal text reached {body}"
            );
        }
    }
}

/// I-69, M9 design section 2.4: a public page served by the cell carries
/// the funder visibility elements of the profile its programme pins
/// through P-53, inside the footer. Here every programme pins Horizon
/// Europe version 1, whose two elements are `acknowledgement` and
/// `emblem`. The setup world pins no shipped profile, so its pages keep
/// the platform element only.
#[test]
fn i69_cell_public_page_footer_carries_the_pinned_profile_elements() {
    let he = fstp_programme::FunderProfile::horizon_europe()
        .policy_ref()
        .unwrap_or_else(|| panic!("the Horizon Europe P-53 value"));
    let pinned = cell_of(pending_world_pinning(he).unwrap_or_else(|e| panic!("the world: {e}")));
    let plain = cell();
    for path in ["/p/1/", "/p/1/funded", "/p/1/finished"] {
        let r = get(&pinned, path, false);
        let body = String::from_utf8_lossy(&r.body);
        assert_eq!(r.status, 200, "{path}: {body}");
        let footer = body.split("<footer").nth(1).unwrap_or("");
        for key in ["acknowledgement", "emblem"] {
            assert!(
                footer.contains(&format!("data-mandatory=\"funder_visibility.{key}\"")),
                "{path}: no {key} element in {footer}"
            );
        }
        assert!(footer.contains("horizon-europe"), "{path}: {footer}");
        let r = get(&plain, path, false);
        let body = String::from_utf8_lossy(&r.body);
        assert!(
            body.contains("data-mandatory=\"funder_visibility\""),
            "{path}: {body}"
        );
        assert!(!body.contains("funder_visibility."), "{path}: {body}");
    }
}
