//! Review reproducer for the route template check (R-NF-02, M3 design
//! section 11.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use fstp_obs::{LogEvent, Method, ObsError, encode_log};

/// R-NF-02: a route template never holds `@`, so a leaked concrete path
/// carrying an email address must be refused, not logged verbatim. Today
/// the route alphabet admits `@` (and `'`, `+`, `=`, `&`, `,`, `;`, `:`,
/// `!`, `$`), so the line below logs the address.
#[test]
fn review_route_check_refuses_an_email_address() {
    let e = LogEvent::Request {
        method: Method::Get,
        route: "/users/alice@example.com",
        status: 200,
        elapsed: Duration::ZERO,
    };
    let got = encode_log(&e);
    assert_eq!(got, Err(ObsError::InvalidRoute), "logged: {got:?}");
}
