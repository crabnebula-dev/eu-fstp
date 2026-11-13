//! The `fstp-world-host` binary: the process that runs every cell and
//! vault of a test world in process mode (`fstp_celltest::world_host`,
//! lane m3/custody-decisions). Test only. Each cell's custody runs in a
//! `fstp-custody-sim --serve` process that the test started.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_celltest::world_host::host_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-world-host: {e}");
            ExitCode::FAILURE
        }
    }
}
