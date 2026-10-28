//! The `fstp-keyd` binary (M3 design section 2.3). W0 stub: it refuses to
//! start with a `NotImplemented` message.

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_keyd::serve(
        std::path::Path::new("/run/fstp-keyd.sock"),
        std::path::Path::new("/var/lib/fstp-keyd"),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-keyd: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
