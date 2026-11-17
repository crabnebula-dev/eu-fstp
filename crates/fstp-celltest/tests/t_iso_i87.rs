//! T-ISO for I-87 and TH-06: two cells never cross on their public
//! surface (M4 design sections 3.10, 8.4 and 8.6, lane m4/cellpub).
//!
//! Two cells of one world each create a distinct synthetic programme and
//! publish a call through the cycle, over HTTP. Each cell then serves its
//! `/p` pages, its feed and its public tools over the world's edge. Every
//! answer of a cell must name only that cell's programme and call, and
//! none of the other cell's names, slugs, call ids or texts.
//!
//! Interim, pending Daniel: the cell text store has no public class yet,
//! so a production cell shows no open call (`fstp_cell::public`). Each
//! world cell holds its own public texts instead
//! (`fstp_celltest::world_public`), which the cycle's `publish-call`
//! fills with the synthetic title and P-09 wording of the call it
//! published. Each cell reads only its own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::world::{
    CellHandle, CycleScript, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_celltest::world_public::WorldIdentity;

/// One day, in microseconds.
const DAY: i64 = 86_400_000_000;

/// The CSP of every `/p` answer, M4 design section 3.10.
const PUBLIC_CSP: &str = "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The programme and call each cell publishes. The call ids are long and
/// distinct, so no date, amount or other number of a page holds one.
fn identity(i: u8) -> WorldIdentity {
    match i {
        0 => WorldIdentity {
            slug: "alpha-iso".to_owned(),
            name: "Alpha Isolation Programme".to_owned(),
            first_call: 730_117_301,
        },
        _ => WorldIdentity {
            slug: "bravo-iso".to_owned(),
            name: "Bravo Isolation Programme".to_owned(),
            first_call: 840_228_402,
        },
    }
}

/// The strings that name cell `i`'s programme and call on any public
/// answer: its slug, its name, its call id and its call title.
fn needles(i: u8) -> Vec<String> {
    let id = identity(i);
    vec![
        id.slug.clone(),
        id.name.clone(),
        id.first_call.to_string(),
        format!("{} synthetic call {}", id.name, id.first_call),
    ]
}

/// `GET path` on `cell`, with the cell host.
fn get(cell: &CellHandle, path: &str) -> HttpReply {
    cell.request(&HttpRequest::new("GET", path).header("host", cell.host()))
        .unwrap_or_else(|e| panic!("GET {path}: {e}"))
}

/// Every public path of cell `i`'s programme and call.
fn public_paths(i: u8) -> Vec<String> {
    let id = identity(i);
    let (s, c) = (&id.slug, id.first_call);
    vec![
        format!("/p/{s}/"),
        format!("/p/{s}/calls/{c}"),
        format!("/p/{s}/calls/{c}/guide"),
        format!("/p/{s}/funded"),
        format!("/p/{s}/finished"),
        format!("/p/{s}/feed.json"),
        format!("/p/{s}/calls"),
        format!("/p/{s}/deadlines"),
        format!("/p/{s}/eligibility"),
    ]
}

/// Whether `haystack` holds `needle`.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// I-87, TH-06, T-ISO (`i87_two_cells_never_cross`): two cells that each
/// publish a distinct programme and call serve, over HTTP, `/p` pages, a
/// feed and public tool answers that name only their own programme and
/// call. Non-vacuity: each cell's programme page, call page, feed and
/// open calls tool show its own call.
#[test]
fn i87_two_cells_never_cross() {
    let w = World::start(WorldSpec {
        cells: 2,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"));
    let script = CycleScript {
        steps: ["login", "create-programme", "publish-call"]
            .map(str::to_owned)
            .to_vec(),
    };
    for i in 0..2u8 {
        let cell = w.cell(i).unwrap();
        cell.public().set_identity(identity(i));
        w.run_cycle(i, &script)
            .result
            .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
        // The call opens a day after its publication.
        cell.clock().advance(2 * DAY);
    }
    let mut failures = Vec::new();
    for own in 0..2u8 {
        let other = 1 - own;
        let cell = w.cell(own).unwrap();
        let mine = needles(own);
        let theirs = needles(other);
        let id = identity(own);
        let title = format!("{} synthetic call {}", id.name, id.first_call);
        for path in public_paths(own) {
            let r = get(cell, &path);
            if r.header("content-security-policy") != Some(PUBLIC_CSP.as_bytes()) {
                failures.push(format!("cell {own} GET {path}: not the public CSP"));
            }
            if r.header("set-cookie").is_some() {
                failures.push(format!("cell {own} GET {path}: sets a cookie (R-PB-04)"));
            }
            for n in &theirs {
                if holds(&r.body, n) || r.headers.iter().any(|(_, v)| holds(v, n)) {
                    failures.push(format!(
                        "cell {own} GET {path} names cell {other}'s {n:?} (I-87, TH-06)"
                    ));
                }
            }
            // Non-vacuity: the programme page, the call page, the Guide,
            // the feed and the open calls tool answer and show this
            // cell's own programme and call.
            let shows_call = path.ends_with('/')
                || path.ends_with(&format!("/calls/{}", id.first_call))
                || path.ends_with("/feed.json")
                || path.ends_with("/calls");
            if (shows_call || path.ends_with("/guide")) && r.status != 200 {
                failures.push(format!(
                    "cell {own} GET {path}: status {} where its own page is public: {}",
                    r.status,
                    String::from_utf8_lossy(&r.body)
                ));
            }
            if shows_call && !holds(&r.body, &title) {
                failures.push(format!(
                    "cell {own} GET {path}: its own call title {title:?} is missing, so the \
                     comparison would be vacuous"
                ));
            }
            if path.ends_with('/') && !mine.iter().all(|n| holds(&r.body, n)) {
                failures.push(format!(
                    "cell {own} GET {path}: its own programme page does not name {mine:?}"
                ));
            }
        }
        // The other cell's programme and call are not found here, under
        // either cell's slug.
        let mine_slug = &identity(own).slug;
        let their = identity(other);
        for path in public_paths(other).into_iter().chain([
            format!("/p/{mine_slug}/calls/{}", their.first_call),
            format!("/p/{mine_slug}/calls/{}/guide", their.first_call),
        ]) {
            let r = get(cell, &path);
            if r.status != 404 {
                failures.push(format!(
                    "cell {own} GET {path}: status {} for cell {other}'s programme or call, \
                     where it must be not found",
                    r.status
                ));
            }
            for n in &theirs {
                if holds(&r.body, n) {
                    failures.push(format!(
                        "cell {own} GET {path} names cell {other}'s {n:?} (I-87, TH-06)"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
