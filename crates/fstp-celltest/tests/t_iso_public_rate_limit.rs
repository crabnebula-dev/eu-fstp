//! T-ISO for the public route rate limit (ADR-024, exit audit item 7, M4
//! design section 8.6, lane m4/pubtext): the rate limit keys of one
//! cell's public routes are that cell's own.
//!
//! Two cells of one world each limit their public routes to a few
//! requests per peer. Every client of the world connects from loopback,
//! so both cells see the same peer. The peer spends its budget on one
//! cell, which then refuses it. The other cell still admits the same peer
//! for a budget of its own. The world's clock does not move, so no window
//! slides during the test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};

/// The public requests one peer may make per window on each cell.
const BUDGET: usize = 5;

/// The body of a refused public request, as the web adapter answers it.
const RATE: &[u8] = br#"{"code":"rate_limited","rule":"rate"}"#;

/// `GET path` on `cell`, with the cell host.
fn get(cell: &CellHandle, path: &str) -> HttpReply {
    cell.request(&HttpRequest::new("GET", path).header("host", cell.host()))
        .unwrap_or_else(|e| panic!("GET {path}: {e}"))
}

/// Whether `haystack` holds `needle`.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// ADR-024, T-ISO (`t_iso_public_rate_limit_keys_are_per_cell`): a peer
/// that spent its public budget on one cell is refused there, on a public
/// route and on an unknown public path alike, while the other cell admits
/// the same peer for its own full budget. A refusal names no peer
/// address. The platform stylesheet is not charged.
#[test]
fn t_iso_public_rate_limit_keys_are_per_cell() {
    let w = World::start_with_public_limit(
        WorldSpec {
            cells: 2,
            mode: DbMode::Shared,
            vault_layout: VaultLayout::SeparateCluster,
            self_hosted: false,
            process_mode: false,
        },
        fstp_cell::routes::Limit {
            count: BUDGET,
            window_us: 60_000_000,
        },
    )
    .unwrap_or_else(|e| panic!("the world did not start: {e}"));
    let (a, b) = (w.cell(0).unwrap(), w.cell(1).unwrap());
    let mut failures = Vec::new();
    for i in 0..BUDGET {
        let r = get(a, "/p/rate-iso/");
        if r.status == 429 {
            failures.push(format!("cell 0 refused request {i} within its budget"));
        }
    }
    for path in ["/p/rate-iso/", "/p/rate-iso/feed.json", "/p/rate-iso/nope"] {
        let r = get(a, path);
        if r.status != 429 || r.body != RATE {
            failures.push(format!(
                "cell 0 GET {path} after the budget: status {} body {:?}, where 429 {:?}",
                r.status,
                String::from_utf8_lossy(&r.body),
                String::from_utf8_lossy(RATE)
            ));
        }
        for addr in ["127.0.0.1", "::1"] {
            if holds(&r.body, addr) || r.headers.iter().any(|(_, v)| holds(v, addr)) {
                failures.push(format!("cell 0 GET {path}: the refusal names {addr}"));
            }
        }
    }
    let sheet = fstp_cell::http::site::sheet_paths().next().unwrap();
    let r = get(a, sheet);
    if r.status != 200 {
        failures.push(format!(
            "cell 0 GET {sheet}: status {} after the budget",
            r.status
        ));
    }
    // The other cell keeps its own keys: the same peer has a full budget.
    for i in 0..BUDGET {
        let r = get(b, "/p/rate-iso/");
        if r.status == 429 {
            failures.push(format!(
                "cell 1 refused request {i} of a peer only cell 0 refused (ADR-024)"
            ));
        }
    }
    // Non-vacuity: cell 1 enforces its own limit too.
    let r = get(b, "/p/rate-iso/");
    if r.status != 429 {
        failures.push(format!(
            "cell 1 admitted request {BUDGET} beyond its budget: status {}",
            r.status
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
