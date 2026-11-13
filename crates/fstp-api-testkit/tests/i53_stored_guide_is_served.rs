//! The public Guide page and `calls.guide` serve the stored Guide, never
//! a regenerated one (I-53, R-GA-01, R-PB-04; M4 design section 3.10).
//!
//! The ledger comes from the Guide world of `r_ga_support.rs`, where the
//! publication stored the Guide of call 1. A cell of fake ports replays
//! it. Its own creator environment supplies no Guide facts, so nothing it
//! serves can come from a binding of its own: only the stored bytes can
//! reach the answer. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "r_ga_support.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use fstp_api_core::port::api_core;
use fstp_api_testkit::fake::fixture::World as CellWorld;
use fstp_api_testkit::fake::{FakePorts, port_seams};
use fstp_domain::id::TextId;
use fstp_domain_testkit::r#gen::roster::{T0, sod_truth};
use fstp_http::{Parsed, parse_request};
use fstp_json::Value;
use fstp_public::{Chrome, ProgrammeIdentity, PublicPage, PublicTexts, public_view, render_html};
use fstp_web::{WebConfig, WebRouter, limits, parse_origin_header};
use support::{GUIDE_CALL, GuideEnv, UNPUBLISHED_CALL, world_with};

/// The tenant origin of the cell.
const ORIGIN: &str = "https://tenant.fstp.test";

/// A router over fake ports that replay the Guide world's ledger.
fn router(w: &support::World) -> WebRouter {
    let world = CellWorld {
        store: w.engine.store().clone(),
        truth: sod_truth(),
        start: T0,
        admins: BTreeSet::new(),
    };
    let seams = port_seams().unwrap_or_else(|e| panic!("{e}"));
    let ports = FakePorts::new(&world, seams).unwrap_or_else(|e| panic!("{e}"));
    let core = Arc::new(api_core(ports));
    let origin = parse_origin_header(ORIGIN.as_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
    let assets = fstp_web::AssetSet::from_files(
        "main.js",
        &[(
            "main.js",
            b"// guide test asset set\nexport {};\n".as_slice(),
        )],
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    fstp_web::router(core, WebConfig::new(origin, assets)).unwrap_or_else(|e| panic!("{e:?}"))
}

/// The status and body of an anonymous `GET` of `path`.
fn get(r: &WebRouter, path: &str) -> (u16, Vec<u8>) {
    let raw = format!("GET {path} HTTP/1.1\r\nHost: tenant.fstp.test\r\n\r\n");
    let req = match parse_request(raw.as_bytes(), &limits()) {
        Ok(Parsed::Complete { message, .. }) => message,
        other => panic!("{path}: {other:?}"),
    };
    let resp = fstp_rt::future::block_on(r.serve(req));
    (resp.status.as_u16(), resp.body)
}

/// Whether `v` holds the string `s` anywhere.
fn holds(v: &Value, s: &str) -> bool {
    match v {
        Value::String(x) => x == s,
        Value::Array(a) => a.iter().any(|x| holds(x, s)),
        Value::Object(o) => o.iter().any(|(_, x)| holds(x, s)),
        _ => false,
    }
}

/// I-53, R-GA-01: `calls.guide` answers the stored page of call 1 byte
/// for byte, with its version and digest, from a cell that cannot bind
/// a Guide of its own.
#[test]
fn i53_calls_guide_serves_the_stored_bytes() {
    let w = world_with(GuideEnv::supersafe(), true);
    let stored = fstp_domain::programme::stored_guide(&w.state().core, GUIDE_CALL)
        .unwrap()
        .clone();
    let r = router(&w);
    let (status, body) = get(&r, "/api/v1/calls/1/guide");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let v = fstp_json::parse(&body).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(holds(&v, stored.page()), "the stored page is not served");
    let hex: String = stored
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(holds(&v, &hex), "the digest is not served");
}

/// R-GA-01: a call with no stored Guide has none to serve, so
/// `calls.guide` refuses it, never answering a Guide bound per request.
#[test]
fn r_ga_01_calls_guide_of_a_call_without_a_stored_guide_is_refused() {
    let w = world_with(GuideEnv::supersafe(), true);
    let r = router(&w);
    let (status, body) = get(
        &r,
        &format!("/api/v1/calls/{}/guide", UNPUBLISHED_CALL.raw()),
    );
    // The read rule refuses a call that is not public before dispatch
    // looks for a Guide, so either refusal holds no Guide.
    assert!(matches!(status, 403 | 404), "{status}");
    assert!(!String::from_utf8_lossy(&body).contains("<!DOCTYPE html>"));
}

/// I-53, R-PB-04, R-GA-02: the public Guide page of an open call is the
/// stored page byte for byte, with no script.
#[test]
fn i53_public_guide_page_serves_the_stored_bytes_with_no_script() {
    let w = world_with(GuideEnv::supersafe(), true);
    let core = &w.state().core;
    let stored = fstp_domain::programme::stored_guide(core, GUIDE_CALL)
        .unwrap()
        .clone();
    let served =
        fstp_public::guide::served_guide(core, GUIDE_CALL, None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(served.document, stored.page());
    let mut texts = PublicTexts::new(ProgrammeIdentity {
        slug: "supersafe".to_owned(),
        name: "SuperSAFE".to_owned(),
        narrative: String::new(),
    });
    let view = fstp_domain::programme::call(core, GUIDE_CALL).unwrap();
    texts.insert(view.text().id(), "Synthetic call title");
    let knock_outs: Vec<TextId> = view
        .frozen()
        .unwrap()
        .values()
        .p09
        .0
        .iter()
        .map(|k| k.text.id())
        .collect();
    for id in knock_outs {
        texts.insert(id, "Synthetic knock-out criterion");
    }
    texts.insert_guide(GUIDE_CALL, served);
    let pv = public_view(core, view.programme(), &texts, T0).unwrap_or_else(|e| panic!("{e}"));
    let page = render_html(
        &pv,
        &PublicPage::Guide("1".to_owned()),
        &Chrome {
            stylesheet: None,
            funder: None,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(page.as_bytes(), stored.page().as_bytes());
    assert!(!page.as_str().contains("<script"));
}
