//! The route table of the cell (I-78, H-01, R-NF-02, design sections 5.4,
//! 8.4 and 8.7).
//!
//! Lane W3a's test author wrote these tests before the route table
//! exists. They read it through `http_common::production_routes`, which
//! refuses until `fstp-cell` exposes its table, so each is red for that
//! reason only.
//!
//! Reading: the W0 `RiskClass` has two variants, `Normal` and
//! `HighRisk(action)`. Every route that section 8.7 does not mark high
//! risk is `Normal`. That holds for `POST /api/v1/commands` and
//! `POST /api/v1/vault-tickets` too, which section 8.7 classes per command
//! and per scope through `HighRiskAction::of`. The behaviour of the other
//! classes is swept over HTTP in `routes_sweep.rs`.
//!
//! The compile-fail twin `i78_route_without_risk_class_does_not_compile`
//! is a doctest in `fstp_celltest::reference::auth` (lane W1b).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod http_common;

use std::collections::BTreeSet;

use fstp_cell::routes::{RiskClass, Route};
use fstp_cell_core::gate::HIGH_RISK_TABLE;
use fstp_http::{Method, Request, Response, Router, StatusCode, handler_fn};
use fstp_obs::{LogEvent, encode_log};

use http_common::{SECTION_8_7, label, production_routes};

fn routes() -> Vec<Route> {
    production_routes().unwrap_or_else(|e| panic!("{e}"))
}

fn keys(routes: &[Route]) -> BTreeSet<(&'static str, &'static str)> {
    routes
        .iter()
        .map(|r| {
            let (m, p, _) = r.parts();
            (m, p)
        })
        .collect()
}

/// I-78, H-01, design section 8.7: the production table serves exactly
/// the routes of section 8.7, by method and path template. A route the
/// section does not list is a route no risk class was reviewed for, and a
/// missing route is a gap in the sweep.
#[test]
fn i78_h_01_production_routes_are_exactly_section_8_7() {
    let got = keys(&routes());
    let want: BTreeSet<(&str, &str)> = SECTION_8_7.iter().map(|s| (s.method, s.path)).collect();
    let missing: Vec<_> = want.difference(&got).collect();
    let extra: Vec<_> = got.difference(&want).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "section 8.7 routes missing from production: {missing:?}; \
         production routes section 8.7 does not list: {extra:?}"
    );
}

/// I-78, design sections 5.4 and 8.7: each production route has the risk
/// class of its section 8.7 row. A high-risk row names the same
/// `HighRiskAction`, and every other row is `RiskClass::Normal`.
#[test]
fn i78_production_risk_classes_match_section_8_7() {
    let routes = routes();
    for want in SECTION_8_7 {
        let got = routes
            .iter()
            .map(Route::parts)
            .find(|(m, p, _)| *m == want.method && *p == want.path)
            .map(|(_, _, risk)| risk)
            .unwrap_or_else(|| panic!("production has no route {}", label(want)));
        let expected = match want.class.high_risk() {
            Some(action) => RiskClass::HighRisk(action),
            None => RiskClass::Normal,
        };
        assert_eq!(got, expected, "{}", label(want));
    }
}

/// I-78, design section 8.4: every action a high-risk route names is an
/// action of `HIGH_RISK_TABLE`, the single high-risk table. A route can
/// therefore never ask for a step-up class the gate does not know.
#[test]
fn i78_high_risk_route_actions_are_in_the_high_risk_table() {
    let table: BTreeSet<_> = HIGH_RISK_TABLE.iter().map(|e| e.action).collect();
    for r in routes() {
        if let (m, p, RiskClass::HighRisk(action)) = r.parts() {
            assert!(
                table.contains(&action),
                "{m} {p} names {action:?}, which HIGH_RISK_TABLE lacks"
            );
        }
    }
}

/// H-01, design section 5.4: no method and path appears twice in the
/// table, so no route has two risk classes.
#[test]
fn h_01_route_table_has_no_duplicate_route() {
    let routes = routes();
    let unique = keys(&routes);
    assert_eq!(
        unique.len(),
        routes.len(),
        "the route table lists a method and path twice"
    );
}

/// H-01, `fstp-http` router rules: the router accepts every pattern of the
/// table, and no two routes share a method and shape. A shape clash would
/// let one route answer for another's risk class.
#[test]
fn h_01_every_route_pattern_is_accepted_by_the_router() {
    let mut router = Router::new();
    for r in routes() {
        let (m, p, _) = r.parts();
        let method = Method::from_bytes(m.as_bytes()).unwrap_or_else(|e| panic!("{m}: {e}"));
        let handler = handler_fn(|_req: Request| async { Response::new(StatusCode::OK) });
        router = router
            .route(method, p, handler)
            .unwrap_or_else(|e| panic!("{m} {p}: {e}"));
    }
}

/// R-NF-02, design section 11.1: paths are logged as route templates. Each
/// path template of the table passes the `fstp-obs` template check, so a
/// request log of any route can be written.
#[test]
fn r_nf_02_every_route_path_is_a_loggable_template() {
    for r in routes() {
        let (_, p, _) = r.parts();
        let event = LogEvent::Request {
            method: fstp_obs::Method::Get,
            route: p,
            status: 200,
            elapsed: std::time::Duration::ZERO,
        };
        assert!(
            encode_log(&event).is_ok(),
            "{p} is not a route template fstp-obs can log"
        );
    }
}
