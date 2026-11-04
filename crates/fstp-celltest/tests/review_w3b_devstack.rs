//! Independent review reproducer for lane W3b (the dev stack).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell::routes::{Access, Endpoint, RiskClass, page_table, table};

/// Design sections 2.3 and 8.3, step W3b of section 19: `fstp-devstack`
/// prints a tenant admin enrolment link `<cell origin>/auth/invite#...`
/// that opens the invitation page. The review found that the cell served
/// no page at that path, so the printed link was a 404.
///
/// Where the page is served: design section 8.7 lists the cell routes
/// and has no `GET /auth/invite`. Section 11.2 puts the `web/auth/` pages
/// on the cell origin. So the page is a public `GET` of the page table
/// `fstp_cell::routes::page_table`, outside the section 8.7 table, as
/// `i78_page_routes_are_public_gets_outside_the_section_8_7_table` pins.
/// The finding holds while no such row serves the page shell.
#[test]
fn review_w3b_devstack_enrol_link_page_is_served() {
    let page: Vec<_> = page_table()
        .iter()
        .filter(|r| r.parts().1 == "/auth/invite")
        .map(|r| (r.parts(), r.access(), r.endpoint()))
        .collect();
    assert_eq!(
        page,
        vec![(
            ("GET", "/auth/invite", RiskClass::Normal),
            Access::Public,
            Endpoint::PageShell
        )],
        "the cell serves no page at /auth/invite, the page the fstp-devstack enrolment link opens"
    );
    assert!(
        table().iter().all(|r| r.parts().1 != "/auth/invite"),
        "/auth/invite is a row of the section 8.7 table"
    );
}
