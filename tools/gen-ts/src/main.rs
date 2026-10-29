//! `gen-ts` writes `web/src/gen/api.ts` from the `OPS` registry of
//! `fstp-access`: the types, the operation table, the route segments and
//! the structural validators. CI runs it with `--check`, as
//! `gen-sqlstate.sh --check` runs. It is a build tool and never ships.
//!
//! Usage: `gen-ts [--check] [--root <dir>]`.
//!
//! Status: W0 skeleton. Lane W3a (L-ACCESS) owns this tool and
//! `web/src/gen/api.ts`. Until W3a writes the generator, every run exits
//! with status 2 and writes nothing, so `--check` never passes. The
//! checked-in `web/src/gen/api.ts` is the W0 stub, not generator output.
//! The skeleton prints nothing, since the R-NF-02 print ban covers every
//! shipped workspace member and only `fstp-obs` may write the streams.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The registry the generator will read. It is empty in W0.
    let _ = fstp_access::OPS;
    ExitCode::from(2)
}
