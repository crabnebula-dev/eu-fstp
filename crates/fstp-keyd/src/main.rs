//! The `fstp-keyd` binary (M3 design section 2.3). W0 stub: it refuses to
//! start and logs a `NotImplemented` event.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_keyd::serve(
        std::path::Path::new("/run/fstp-keyd.sock"),
        std::path::Path::new("/var/lib/fstp-keyd"),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // R-NF-02: a typed event, never the error text.
            let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::NotImplemented);
            ExitCode::FAILURE
        }
    }
}
