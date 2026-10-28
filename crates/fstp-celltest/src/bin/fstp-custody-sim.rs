//! The `fstp-custody-sim` binary (M3 design section 2.3). Test and local development
//! only. W0 stub: it refuses to start with a `NotImplemented` message.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_celltest::custody_sim::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-custody-sim: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
