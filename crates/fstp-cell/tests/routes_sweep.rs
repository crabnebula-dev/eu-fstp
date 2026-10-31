//! The route-table sweep over HTTP (I-77, I-78, B11, TH-05, H-01, ADR-007,
//! ADR-008, ADR-009, design sections 8.2, 8.7 and 11.2).
//!
//! Each test walks the routes of design section 8.7 through an in-process
//! cell front and checks one rule of the class or the HTTP layer. Lane
//! W3a's test author wrote them before the routes exist. They reach the
//! cell through `http_common::TestCell`, which refuses until the
//! production test front exists, so each is red for that reason only.
//!
//! The status codes and the order of the front checks follow the readings
//! in `http_common`. A test that relies on one says so.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod http_common;

use http_common::{
    CELL_CSP, Class, HOST_A, HOST_B, OVERSIZE_BODY, SECTION_8_7, Spec, Who, bare, cell_a, cell_b,
    concrete, field_values, label, magic_request_body, origin_of, serve, session, state_changing,
    status, through_front, tunnel_rows, with_body, with_cookie,
};

/// Every tunnel route that needs a session.
fn session_rows() -> impl Iterator<Item = &'static Spec> {
    tunnel_rows().filter(|s| s.class.needs_session())
}

/// Every tunnel route of a state-changing method.
fn state_changing_rows() -> impl Iterator<Item = &'static Spec> {
    tunnel_rows().filter(|s| state_changing(s.method))
}

/// Every tunnel POST route.
fn post_rows() -> impl Iterator<Item = &'static Spec> {
    tunnel_rows().filter(|s| s.method == "POST")
}

// ---------------------------------------------------------------------------
// Sessions.

/// TH-05, I-77, design section 5.4: every route whose class needs a
/// session refuses a request that carries none. The request passes the
/// front, so the refusal is the session's (401).
#[test]
fn th_05_session_routes_refuse_a_request_without_a_session() {
    let cell = cell_a();
    for s in session_rows() {
        let resp = serve(&cell, through_front(s.method, &concrete(s.path), HOST_A));
        assert_eq!(status(&resp), 401, "{}", label(s));
    }
}

/// B11, I-19, ADR-008 "Relying party id": a valid session cookie of cell B
/// is refused by cell A on every session route. Both cells run the same
/// code, so the only difference is the cell id in the cookie.
#[test]
fn b11_i19_session_routes_refuse_another_cells_cookie() {
    let a = cell_a();
    let b = cell_b();
    let foreign = session(&b, Who::Admin);
    for s in session_rows() {
        let req = with_cookie(through_front(s.method, &concrete(s.path), HOST_A), &foreign);
        assert_eq!(status(&serve(&a, req)), 401, "{}", label(s));
    }
}

/// B11, ADR-008 "Sessions": malformed session cookies are refused on every
/// session route. The cases cut, extend and corrupt a valid cookie of the
/// same cell, and send cookies that only look like the session cookie.
#[test]
fn adr008_session_routes_refuse_a_malformed_cookie() {
    let cell = cell_a();
    let good = session(&cell, Who::Admin);
    let value = good
        .iter()
        .position(|b| *b == b'=')
        .map(|i| good[i + 1..].to_vec())
        .unwrap_or_else(|| panic!("the seeded cookie has no value"));
    let mut cases: Vec<Vec<u8>> = vec![
        b"__Host-fstp=".to_vec(),
        b"__Host-fstp=x".to_vec(),
        [b"fstp=".as_slice(), &value].concat(),
        [b"__host-fstp=".as_slice(), &value].concat(),
        [b"__Host-fstp=".as_slice(), &value[..value.len() - 1]].concat(),
        [b"__Host-fstp=".as_slice(), &value, b"0"].concat(),
    ];
    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    cases.push(flipped);
    for s in session_rows() {
        for c in &cases {
            let req = with_cookie(through_front(s.method, &concrete(s.path), HOST_A), c);
            assert_eq!(
                status(&serve(&cell, req)),
                401,
                "{} with cookie case {:?}",
                label(s),
                String::from_utf8_lossy(c)
            );
        }
    }
}

/// I-77, R-LG-04, design section 8.2: the positive twin of the session
/// sweeps. A Receiving account's magic-link session lists its own
/// sessions and devices. So the 401s above are not a cell that refuses
/// every session.
#[test]
fn i77_r_lg_04_receiving_magic_link_session_lists_sessions_and_devices() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Applicant);
    for path in ["/auth/sessions", "/auth/devices"] {
        let resp = serve(
            &cell,
            with_cookie(through_front("GET", path, HOST_A), &cookie),
        );
        assert_eq!(status(&resp), 200, "GET {path}");
    }
}

// ---------------------------------------------------------------------------
// Step-up.

/// I-78, design sections 8.4 and 8.7: a tenant admin's passkey session
/// with no step-up never completes a high-risk route. A step-up is named
/// by the request, and these requests name none.
///
/// Reading: the refusal is any 4xx. The design does not say whether a body
/// with no step-up member is malformed (400) or refused by the gate (403).
#[test]
fn i78_high_risk_routes_never_succeed_without_a_step_up() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    for s in tunnel_rows().filter(|s| s.class.high_risk().is_some()) {
        let req = with_cookie(through_front(s.method, &concrete(s.path), HOST_A), &cookie);
        let code = status(&serve(&cell, req));
        assert!((400..500).contains(&code), "{} gave {code}", label(s));
    }
}

/// I-78, design section 8.3: a magic-link session never completes a
/// high-risk route. In particular it can never add a passkey.
#[test]
fn i78_high_risk_routes_refuse_a_magic_link_session() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Applicant);
    for s in tunnel_rows().filter(|s| s.class.high_risk().is_some()) {
        let req = with_cookie(through_front(s.method, &concrete(s.path), HOST_A), &cookie);
        let code = status(&serve(&cell, req));
        assert!((400..500).contains(&code), "{} gave {code}", label(s));
    }
}

// ---------------------------------------------------------------------------
// Class rules of single routes.

/// ADR-007, G30, design section 8.7: the audit anchors and the erasure log
/// are refused to a Receiving account's session (403).
#[test]
fn adr007_g30_audit_routes_refuse_a_receiving_session() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Applicant);
    for s in tunnel_rows().filter(|s| s.class == Class::AuditorOrAdmin) {
        let req = with_cookie(through_front(s.method, s.path, HOST_A), &cookie);
        assert_eq!(status(&serve(&cell, req)), 403, "{}", label(s));
    }
}

/// ADR-007, G30, design section 8.7: the positive twin. A tenant admin's
/// session reads the audit anchors and the erasure log.
#[test]
fn adr007_g30_audit_routes_serve_a_tenant_admin() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    for s in tunnel_rows().filter(|s| s.class == Class::AuditorOrAdmin) {
        let req = with_cookie(through_front(s.method, s.path, HOST_A), &cookie);
        assert_eq!(status(&serve(&cell, req)), 200, "{}", label(s));
    }
}

/// ADR-008 "Manual identity checks", design section 8.7: a verification
/// write ticket goes only to a tenant admin with a verified identity. A
/// Receiving account and the seeded unverified tenant admin are both
/// refused, and no ticket reaches either.
#[test]
fn adr008_verifications_route_refuses_unverified_or_non_admin_sessions() {
    let cell = cell_a();
    for who in [Who::Applicant, Who::Admin] {
        let cookie = session(&cell, who);
        let req = with_cookie(
            through_front("POST", "/api/v1/verifications", HOST_A),
            &cookie,
        );
        let code = status(&serve(&cell, req));
        assert!((400..500).contains(&code), "{who:?} gave {code}");
    }
}

/// I-18, R-ID-04, NOTE 14, design section 15: `POST /api/v1/commands`
/// refuses a body with a `minor` member as malformed (400), for a valid
/// session that passes the front. The flag never comes from a request.
#[test]
fn i18_commands_route_refuses_a_minor_member() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    let body = format!(
        "{{\"command_id\":\"{}\",\"minor\":true}}",
        http_common::hex(&[7; 16])
    );
    let req = with_cookie(
        with_body("POST", "/api/v1/commands", HOST_A, body.as_bytes()),
        &cookie,
    );
    assert_eq!(status(&serve(&cell, req)), 400);
}

/// ADR-008, design section 8.7: `POST /auth/magic/request` gives the same
/// response whether or not the account exists. Status, header fields and
/// body are compared byte for byte, so the response cannot tell an
/// attacker which emails hold accounts.
#[test]
fn adr008_magic_request_gives_one_response_whether_or_not_the_account_exists() {
    let cell = cell_a();
    let known = cell.applicant_email().unwrap_or_else(|e| panic!("{e}"));
    let unknown = "nobody.CNRY-a1-email-00000000000000000000000000000000@fstp.test";
    let reply = |email: &str| {
        serve(
            &cell,
            with_body(
                "POST",
                "/auth/magic/request",
                HOST_A,
                &magic_request_body(email),
            ),
        )
    };
    let a = reply(&known);
    let b = reply(unknown);
    assert!(
        a.status.is_success(),
        "the request for a known account was refused: {}",
        status(&a)
    );
    let fields = |r: &fstp_http::Response| {
        r.headers
            .iter()
            .map(|(n, v)| (n.as_str().to_ascii_lowercase(), v.as_bytes().to_vec()))
            .collect::<Vec<_>>()
    };
    assert_eq!(status(&a), status(&b));
    assert_eq!(fields(&a), fields(&b));
    assert_eq!(a.body, b.body);
}

// ---------------------------------------------------------------------------
// Origin and CSRF.

/// The `Origin` cases a state-changing route refuses. Each is one field
/// line value, except the empty list (no field) and the pair.
fn foreign_origins() -> Vec<Vec<String>> {
    vec![
        Vec::new(),
        vec!["null".to_owned()],
        vec![format!("http://{HOST_A}")],
        vec![format!("https://id.{HOST_A}")],
        vec![origin_of(HOST_B)],
        vec![format!("https://{HOST_A}:8443")],
        vec![format!("https://{HOST_A}.evil.test")],
        vec![format!("https://{}", HOST_A.to_ascii_uppercase())],
        vec![format!("https://{HOST_A}/")],
        vec![origin_of(HOST_A), origin_of(HOST_A)],
        vec![origin_of(HOST_B), origin_of(HOST_A)],
    ]
}

/// ADR-008 "Sessions", design section 8.2: every state-changing route
/// refuses a request whose `Origin` is missing, opaque, of another scheme,
/// port, host or cell, of the vault origin, or given twice (403). The
/// requests carry a valid session cookie of the cell, as a cross-site or
/// same-site forgery would.
///
/// Reading (`http_common`): the `Origin` check runs in the front, before
/// the session and the gate.
#[test]
fn adr008_state_changing_routes_refuse_a_foreign_or_missing_origin() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    for s in state_changing_rows() {
        for origins in foreign_origins() {
            let mut req = bare(s.method, &concrete(s.path), HOST_A);
            for o in &origins {
                req = req
                    .try_with_header("origin", o.clone())
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            if s.method == "POST" {
                req = req
                    .try_with_header("content-type", "application/json")
                    .unwrap_or_else(|e| panic!("{e}"));
                req.body = b"{}".to_vec();
            }
            let req = with_cookie(req, &cookie);
            assert_eq!(
                status(&serve(&cell, req)),
                403,
                "{} with Origin {origins:?}",
                label(s)
            );
        }
    }
}

/// ADR-008 "Sessions": the positive twin of the `Origin` sweep. A request
/// with the cell origin and a JSON body reaches a public route, and an
/// unknown email still gets the uniform success response.
#[test]
fn adr008_cell_origin_passes_the_origin_check() {
    let cell = cell_a();
    let body =
        magic_request_body("nobody.CNRY-a1-email-11111111111111111111111111111111@fstp.test");
    let resp = serve(
        &cell,
        with_body("POST", "/auth/magic/request", HOST_A, &body),
    );
    assert!(resp.status.is_success(), "status {}", status(&resp));
}

/// ADR-008 "Sessions": GET routes do not change state, so they need no
/// `Origin`. A tenant admin reads its sessions with no `Origin` field.
#[test]
fn adr008_get_routes_need_no_origin() {
    let cell = cell_a();
    let cookie = session(&cell, Who::Admin);
    let req = with_cookie(bare("GET", "/auth/sessions", HOST_A), &cookie);
    assert_eq!(status(&serve(&cell, req)), 200);
}

/// ADR-008 "Sessions": state-changing routes accept only JSON bodies. Every
/// POST route refuses a missing `Content-Type` and the types a plain HTML
/// form or a no-preflight `fetch` can send (415).
///
/// Reading (`http_common`): the type check runs in the front, before the
/// session.
#[test]
fn adr008_post_routes_accept_only_json_bodies() {
    let cell = cell_a();
    let types: [Option<&str>; 5] = [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        Some("text/json"),
    ];
    for s in post_rows() {
        for t in types {
            let mut req = bare("POST", &concrete(s.path), HOST_A)
                .try_with_header("origin", origin_of(HOST_A))
                .unwrap_or_else(|e| panic!("{e}"));
            if let Some(t) = t {
                req = req
                    .try_with_header("content-type", t)
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            req.body = b"{}".to_vec();
            assert_eq!(
                status(&serve(&cell, req)),
                415,
                "{} with Content-Type {t:?}",
                label(s)
            );
        }
    }
}

/// TH-26, design section 15: every POST route refuses a body over its limit
/// (413). The body is a JSON string padded past any M3 route's need.
#[test]
fn th_26_post_routes_refuse_an_oversize_body() {
    let cell = cell_a();
    let mut body = Vec::with_capacity(OVERSIZE_BODY);
    body.push(b'"');
    body.resize(OVERSIZE_BODY - 1, b'a');
    body.push(b'"');
    for s in post_rows() {
        let req = with_body("POST", &concrete(s.path), HOST_A, &body);
        assert_eq!(status(&serve(&cell, req)), 413, "{}", label(s));
    }
}

// ---------------------------------------------------------------------------
// Headers on every response.

/// A request for every tunnel route, plus an unknown path and a listed
/// path with another method. Together they reach a handler, the
/// session refusal, the router's 404 and its 405.
fn every_kind_of_request() -> Vec<(String, fstp_http::Request)> {
    let mut out: Vec<(String, fstp_http::Request)> = tunnel_rows()
        .map(|s| (label(s), through_front(s.method, &concrete(s.path), HOST_A)))
        .collect();
    out.push((
        "GET /auth/unknown".to_owned(),
        bare("GET", "/auth/unknown", HOST_A),
    ));
    out.push((
        "PUT /api/v1/commands".to_owned(),
        through_front("PUT", "/api/v1/commands", HOST_A),
    ));
    out
}

/// ADR-003, ADR-009, design section 11.2: every response of the cell
/// origin carries exactly one `Content-Security-Policy` field, equal to
/// the design's policy. That holds for refusals and router errors too.
#[test]
fn adr009_every_cell_response_carries_the_cell_csp() {
    let cell = cell_a();
    for (what, req) in every_kind_of_request() {
        let resp = serve(&cell, req);
        let csp = field_values(&resp, "content-security-policy");
        assert_eq!(
            csp,
            vec![CELL_CSP.as_bytes()],
            "{what} (status {})",
            status(&resp)
        );
    }
}

/// ADR-008, I-19: no response grants cross-origin access. No response
/// carries an `Access-Control-Allow-*` field, and a CORS preflight from
/// the vault origin is not answered with success.
#[test]
fn adr008_no_response_grants_cross_origin_access() {
    let cell = cell_a();
    let mut requests = every_kind_of_request();
    for s in state_changing_rows() {
        let req = bare("OPTIONS", &concrete(s.path), HOST_A)
            .try_with_header("origin", format!("https://id.{HOST_A}"))
            .and_then(|r| r.try_with_header("access-control-request-method", s.method))
            .unwrap_or_else(|e| panic!("{e}"));
        requests.push((format!("OPTIONS {}", s.path), req));
    }
    for (what, req) in requests {
        let preflight = what.starts_with("OPTIONS");
        let resp = serve(&cell, req);
        let cors: Vec<String> = resp
            .headers
            .iter()
            .map(|(n, _)| n.as_str().to_ascii_lowercase())
            .filter(|n| n.starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "{what} answered with {cors:?}");
        assert!(
            !(preflight && resp.status.is_success()),
            "{what} answered the preflight with {}",
            status(&resp)
        );
    }
}

// ---------------------------------------------------------------------------
// Router edges.

/// H-01, design section 8.7: the cell serves no path outside the table.
/// Unknown paths under `/auth` and `/api`, another API version, and the
/// test clock path of the `fstp-celltest` auth client all get 404. A test
/// clock route in a shipped cell would let a client move session time.
#[test]
fn h_01_unlisted_paths_get_404() {
    let cell = cell_a();
    for (m, p) in [
        ("GET", "/auth/unknown"),
        ("POST", "/auth/unknown"),
        ("GET", "/api/v1/unknown"),
        ("POST", "/api/v2/commands"),
        ("POST", "/test/clock"),
        ("GET", "/api/v1/commands/extra"),
        ("GET", "/auth/sessions/a/b"),
    ] {
        assert_eq!(
            status(&serve(&cell, through_front(m, p, HOST_A))),
            404,
            "{m} {p}"
        );
    }
}

/// H-01, `fstp-http` router rules: a listed path asked with a method the
/// table does not list for it gets 405. So no method reaches a handler
/// without its row's risk class.
#[test]
fn h_01_listed_paths_refuse_other_methods_with_405() {
    let cell = cell_a();
    for s in tunnel_rows() {
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            let listed = SECTION_8_7
                .iter()
                .any(|x| x.path == s.path && x.method == m);
            if listed {
                continue;
            }
            let resp = serve(&cell, through_front(m, &concrete(s.path), HOST_A));
            assert_eq!(status(&resp), 405, "{m} {}", s.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Health.

/// ADR-009, design section 2.3: `GET /healthz` is served on the loopback
/// health listener and not on the tunnel listener, so the edge never
/// reaches it.
#[test]
fn adr009_healthz_is_served_on_the_health_listener_only() {
    let cell = cell_a();
    let health = cell
        .serve_health(bare("GET", "/healthz", "127.0.0.1"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(status(&health), 200, "health listener");
    let tunnel = serve(&cell, bare("GET", "/healthz", HOST_A));
    assert_eq!(status(&tunnel), 404, "tunnel listener");
}

/// ADR-009, design section 8.7: the health body is fixed. Requests with a
/// query, a session cookie or another `Host`, to either cell, all get the
/// same status and the same body bytes.
#[test]
fn adr009_healthz_body_is_fixed() {
    let a = cell_a();
    let b = cell_b();
    let cookie = session(&a, Who::Admin);
    let health = |cell: &http_common::TestCell, req| {
        cell.serve_health(req).unwrap_or_else(|e| panic!("{e}"))
    };
    let first = health(&a, bare("GET", "/healthz", "127.0.0.1"));
    let others = [
        health(&a, bare("GET", "/healthz?x=1", "127.0.0.1")),
        health(
            &a,
            with_cookie(bare("GET", "/healthz", "localhost"), &cookie),
        ),
        health(&b, bare("GET", "/healthz", "127.0.0.1")),
    ];
    for o in &others {
        assert_eq!(status(o), status(&first));
        assert_eq!(o.body, first.body);
    }
}

/// ADR-009, design section 2.3: the health listener serves `/healthz` and
/// nothing else. Every tunnel route asked there gets 404.
#[test]
fn adr009_health_listener_serves_no_other_route() {
    let cell = cell_a();
    for s in tunnel_rows() {
        let resp = cell
            .serve_health(through_front(s.method, &concrete(s.path), "127.0.0.1"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(status(&resp), 404, "{}", label(s));
    }
}
