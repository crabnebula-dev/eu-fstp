//! The `fstp-devstack` binary (M3 design section 2.3). Local development
//! only. Lane W3b owns it. W0 stub: it refuses to start with a
//! `NotImplemented` message.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "fstp-devstack: {} (NotImplemented)",
        fstp_celltest::NotImplemented::new("fstp-devstack")
    );
    ExitCode::FAILURE
}
