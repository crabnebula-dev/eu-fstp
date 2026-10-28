//! The `fstp-cell` binary (M3 design section 2.3). W0 stub: it refuses to
//! start with a `NotImplemented` message.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_cell::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-cell: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
