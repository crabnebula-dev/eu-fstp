//! Independent review reproducer for lane W3b (the dev stack).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Design sections 2.3 and 8.3, step W3b of section 19: `fstp-devstack`
/// prints a tenant admin enrolment link `<cell origin>/auth/invite#...`
/// that opens the invitation page. The cell's route table serves no page
/// at that path, nor any page of `web/src/auth`. So the printed link is
/// a 404 on the cell origin, and the stack offers no way to enrol.
#[test]
fn review_w3b_devstack_enrol_link_page_is_served() {
    let served = fstp_cell::routes::table()
        .iter()
        .any(|r| matches!(r.parts(), ("GET", "/auth/invite", _)));
    assert!(
        served,
        "the cell serves no GET /auth/invite, the page the fstp-devstack enrolment link opens"
    );
}
