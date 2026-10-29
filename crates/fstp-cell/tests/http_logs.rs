//! Typed request logs of the cell HTTP layer (R-NF-02, B10, design
//! section 11.1).
//!
//! `fstp_obs::LogEvent` takes no free text by construction. These tests
//! check what the HTTP layer puts in it: the route template that matched,
//! never the concrete path, and `fstp_obs::UNROUTED` for a path that
//! matched nothing. Lane W3a's test author wrote them before the HTTP
//! layer exists. They read the cell's events through
//! `http_common::TestCell::logs`, which refuses until the production test
//! front exists, so each is red for that reason only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod http_common;

use fstp_obs::{LogEvent, UNROUTED, encode_log};

use http_common::{
    HOST_A, PARAM, SECTION_8_7, Who, cell_a, concrete, contains, label, serve, session,
    through_front, tunnel_rows, with_body, with_cookie,
};

/// The route field of a request event, if the event is one.
fn route_of(e: &LogEvent) -> Option<&'static str> {
    match *e {
        LogEvent::Request { route, .. } | LogEvent::Refused { route, .. } => Some(route),
        _ => None,
    }
}

fn logs(cell: &http_common::TestCell) -> Vec<LogEvent> {
    cell.logs().unwrap_or_else(|e| panic!("{e}"))
}

/// R-NF-02, design section 11.1: each request to a table route is logged
/// with its route template. Every request event the cell writes names a
/// template of the table or `UNROUTED`, and never a concrete path.
#[test]
fn r_nf_02_requests_are_logged_by_route_template() {
    let cell = cell_a();
    for s in tunnel_rows() {
        let before = logs(&cell).len();
        let _ = serve(&cell, through_front(s.method, &concrete(s.path), HOST_A));
        let after = logs(&cell);
        let new = &after[before.min(after.len())..];
        assert!(
            new.iter().any(|e| route_of(e) == Some(s.path)),
            "{} wrote no request event with its template: {new:?}",
            label(s)
        );
        for e in new {
            if let Some(r) = route_of(e) {
                assert!(
                    r == UNROUTED || SECTION_8_7.iter().any(|x| x.path == r),
                    "{} logged the route {r:?}",
                    label(s)
                );
            }
        }
    }
}

/// R-NF-02, design section 11.1: a request that matches no route is logged
/// as `UNROUTED`. Its path, which here holds a canary, reaches no event.
#[test]
fn r_nf_02_unlisted_paths_are_logged_as_unrouted() {
    let cell = cell_a();
    let path = "/auth/cnry-a1-email-0123456789abcdef0123456789abcdef";
    let before = logs(&cell).len();
    let _ = serve(&cell, through_front("GET", path, HOST_A));
    let after = logs(&cell);
    let new = &after[before.min(after.len())..];
    let routes: Vec<_> = new.iter().filter_map(route_of).collect();
    assert!(!routes.is_empty(), "the request wrote no request event");
    assert!(
        routes.iter().all(|r| *r == UNROUTED),
        "an unrouted request logged {routes:?}"
    );
}

/// R-NF-02, B10: no encoded log line holds a byte the request carried
/// beyond its route: not a path parameter, not the session cookie, and
/// not a canary in the body.
#[test]
fn r_nf_02_log_lines_hold_no_request_bytes() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    let canary = "CNRY-a1-text-fedcba9876543210fedcba9876543210";
    let body = http_common::magic_request_body(&format!("{canary}@fstp.test"));
    let _ = serve(
        &cell,
        with_body("POST", "/auth/magic/request", HOST_A, &body),
    );
    let _ = serve(
        &cell,
        with_cookie(
            through_front("DELETE", &concrete("/auth/sessions/{id}"), HOST_A),
            &cookie,
        ),
    );
    let value = cookie
        .iter()
        .position(|b| *b == b'=')
        .map(|i| cookie[i + 1..].to_vec())
        .unwrap_or_else(|| panic!("the seeded cookie has no value"));
    for e in logs(&cell) {
        let line = encode_log(&e).unwrap_or_else(|err| panic!("{e:?}: {err}"));
        for needle in [PARAM.as_bytes(), value.as_slice(), canary.as_bytes()] {
            assert!(
                !contains(line.as_bytes(), needle),
                "a log line holds request bytes: {line}"
            );
        }
    }
}
