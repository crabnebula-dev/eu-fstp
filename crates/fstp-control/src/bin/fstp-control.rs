//! The `fstp-control` binary (M3 design section 2.3, ADR-009 "Pilot route
//! feed").
//!
//! With no argument it decodes the configuration named by
//! `FSTP_CONTROL_CONFIG` and serves the `CellToCp` listener through
//! `fstp_control::service::run`, on the one tokio runtime behind
//! `fstp_rt`, until SIGTERM drains it.
//!
//! The pilot of lane L15 runs only the signed route feed, and reads a
//! route feed configuration from the same variable
//! (`fstp_control::route_feed`):
//!
//! - `route-feed`: serve the feed and the operator socket until SIGTERM;
//! - `init-route-feed <out dir>`: create the feed signing key through
//!   `fstp-keyd` and the first table, and write `route-feed.pub` to `out`;
//! - `route add <route file>`: publish the one route of the file;
//! - `route remove <cell id>`: remove every route of the cell;
//! - `route list <out file>`: write the served routes to the file.
//!
//! `route add` and `route remove` only propose a change. A staff member
//! approves it with a passkey step-up on the operator page, and the
//! command waits for that, at most 5 minutes.
//!
//! A refused configuration, route or usage exits with status 2, any other
//! failure with status 1. The binary writes typed events only (R-NF-02).

use std::path::Path;
use std::process::ExitCode;

use fstp_control::{ControlError, route_feed};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match args.as_slice() {
        [] => fstp_control::service::run(),
        ["route-feed"] => route_feed::run(),
        ["init-route-feed", out] => route_feed::init(Path::new(out)),
        ["route", "add", file] => route_feed::route_add(Path::new(file)).map(|_| ()),
        ["route", "remove", cell] => route_feed::route_remove(cell).map(|_| ()),
        ["route", "list", out] => route_feed::route_list(Path::new(out)).map(|_| ()),
        _ => Err(ControlError::Config("usage")),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        // A refused configuration or route exits with the usage status. No
        // event names it, since `LogEvent` has no variant for it (R-NF-02).
        Err(ControlError::Config(_) | ControlError::Request(_)) => ExitCode::from(2),
        Err(_) => ExitCode::FAILURE,
    }
}
