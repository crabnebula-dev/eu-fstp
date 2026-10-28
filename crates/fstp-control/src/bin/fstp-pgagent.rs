//! The `fstp-pgagent` binary (M3 design section 2.3). W0 stub: it refuses to
//! start with a `NotImplemented` message.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_control::pgagent::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-pgagent: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
