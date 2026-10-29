//! The `fstp-vault-seeded` binary (M3 design section 2.3). Test and local development
//! only. W0 stub: it refuses to start with a `NotImplemented` message.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match fstp_celltest::vault_seed::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-vault-seeded: {e} (NotImplemented)");
            ExitCode::FAILURE
        }
    }
}
