//! TH-48, R-SW-02, design section 3.7 step 3: removing an erased cell's
//! routes from the routes an edge serves. Lane m3/erase-cell-2.
//!
//! After the removal, a hello for the cell host or its vault origin host
//! closes as an unknown host, and every other cell routes as before. A
//! retried removal changes nothing. The hellos come from the independent
//! writer in `support/hello.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/hello.rs"]
mod hello;

use std::net::SocketAddr;
use std::sync::Arc;

use fstp_edge::{
    CELL_ID_LEN, CellEndpoint, CloseReason, Decision, HostName, LiveRoutes, RouteKind, RouteTable,
    decide,
};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use hello::Hello;

fn endpoint(cell: u8, port: u16) -> CellEndpoint {
    CellEndpoint {
        cell: [cell; CELL_ID_LEN],
        address: SocketAddr::from(([10, 0, 1, cell], port)),
        tls_name: "tunnel.cell.internal".to_owned(),
    }
}

fn host(cell: u8) -> String {
    format!("cell{cell}.example")
}

fn add(routes: &LiveRoutes, cell: u8) {
    routes
        .add_cell(
            HostName::parse(host(cell).as_bytes()).unwrap(),
            endpoint(cell, 8443),
            endpoint(cell, 9443),
        )
        .unwrap();
}

/// How the table routes a hello for `name`: the cell and kind, or the
/// close reason.
fn route_of(table: &RouteTable, name: &str) -> Result<([u8; CELL_ID_LEN], RouteKind), CloseReason> {
    let bytes = Hello::tls13(Some(name.as_bytes())).record();
    match decide(table, &bytes) {
        Decision::Forward { endpoint, kind, .. } => Ok((endpoint.cell, kind)),
        Decision::Close(r) => Err(r),
        Decision::NeedMore => panic!("a whole hello needs more"),
    }
}

/// TH-48, design section 3.7 step 3: removal by cell id takes both routes
/// of the erased cell from the live table. Hellos for its host and its
/// vault origin then close as unknown hosts, and the other cell still
/// routes. A table taken before the removal is unchanged, and a second
/// removal changes nothing.
#[test]
fn th48_removed_cell_closes_new_connections_and_others_still_route() {
    let routes = LiveRoutes::new(RouteTable::new());
    add(&routes, 1);
    add(&routes, 2);
    let before = routes.current();
    assert_eq!(
        route_of(&before, "cell1.example"),
        Ok(([1; CELL_ID_LEN], RouteKind::Cell))
    );
    assert_eq!(
        route_of(&before, "id.cell1.example"),
        Ok(([1; CELL_ID_LEN], RouteKind::VaultOrigin))
    );

    assert_eq!(routes.remove_cell_by_id(&[1; CELL_ID_LEN]), 2);
    let after = routes.current();
    for name in ["cell1.example", "id.cell1.example"] {
        assert_eq!(
            route_of(&after, name),
            Err(CloseReason::UnknownHost),
            "{name}"
        );
    }
    assert_eq!(
        route_of(&after, "id.cell2.example"),
        Ok(([2; CELL_ID_LEN], RouteKind::VaultOrigin))
    );
    assert_eq!(before.len(), 4, "a table already taken changed");

    assert_eq!(routes.remove_cell_by_id(&[1; CELL_ID_LEN]), 0);
    assert!(Arc::ptr_eq(&after, &routes.current()));
}

/// TH-48, I-19: over random sets of cells, removing one cell leaves no
/// route to it, and every other cell routes both hosts as before.
#[test]
fn th48_removal_takes_exactly_the_erased_cells_routes() {
    check("th48_removal_takes_exactly_the_erased_cells_routes", |g| {
        let routes = LiveRoutes::default();
        let cells: Vec<u8> = (1..=g.u8_in(1..=8)).collect();
        for c in &cells {
            add(&routes, *c);
        }
        let erased = cells[g.usize_in(0..=cells.len() - 1)];
        g.note("erased", &erased);
        prop_assert_eq!(routes.remove_cell_by_id(&[erased; CELL_ID_LEN]), 2);
        let table = routes.current();
        prop_assert_eq!(table.len(), 2 * (cells.len() - 1));
        for c in &cells {
            let app = route_of(&table, &host(*c));
            let vault = route_of(&table, &format!("id.{}", host(*c)));
            if *c == erased {
                prop_assert_eq!(app, Err(CloseReason::UnknownHost));
                prop_assert_eq!(vault, Err(CloseReason::UnknownHost));
            } else {
                prop_assert_eq!(app, Ok(([*c; CELL_ID_LEN], RouteKind::Cell)));
                prop_assert_eq!(vault, Ok(([*c; CELL_ID_LEN], RouteKind::VaultOrigin)));
            }
        }
        prop_assert!(routes.remove_cell_by_id(&[erased; CELL_ID_LEN]) == 0);
        Ok(())
    });
}

/// I-19: a refused addition leaves the live table as it was.
#[test]
fn i19_live_routes_refused_change_leaves_the_table() {
    let routes = LiveRoutes::default();
    add(&routes, 1);
    let before = routes.current();
    let again = routes.add_cell(
        HostName::parse(b"cell1.example").unwrap(),
        endpoint(3, 8443),
        endpoint(3, 9443),
    );
    assert!(again.is_err());
    assert!(Arc::ptr_eq(&before, &routes.current()));
}
