//! The `fstp-licence-svc` binary (M3 design section 2.3). W0 stub: it refuses to
//! start with a `NotImplemented` message.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_release_svc::run_licence_service() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-licence-svc: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
