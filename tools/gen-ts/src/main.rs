//! `gen-ts` writes `web/src/gen/api.ts` from the `OPS` registry of
//! `fstp-access`: the types, the operation table, the route segments and
//! the structural validators (M4 design sections 1.1 and 3.9, ADR-014).
//! CI runs it with `--check`, as `gen-sqlstate.sh --check` runs. It is a
//! build tool and never ships.
//!
//! Usage: `gen-ts [--check] [--root <dir>]`. The root defaults to the
//! current directory.
//!
//! - Without `--check`, it writes the file under the root. The directory
//!   `web/src/gen` must exist, so a wrong root writes nothing.
//! - With `--check`, it compares the file with the output and never
//!   writes. A missing or different file fails.
//!
//! It prints nothing, since the R-NF-02 print ban covers every workspace
//! member and only `fstp-obs` may write the streams. The exit status is
//! its only answer: 0 for success, 1 for a stale or missing file under
//! `--check`, and 2 for a usage or I/O error.

mod render;

use std::path::PathBuf;
use std::process::ExitCode;

/// The generated file, relative to the root.
const API_TS: &str = "web/src/gen/api.ts";

/// What one run does.
struct Args {
    check: bool,
    root: PathBuf,
}

/// Parses the arguments. Any unknown or repeated argument refuses.
fn parse(mut args: impl Iterator<Item = String>) -> Option<Args> {
    let mut check = false;
    let mut root: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check" if !check => check = true,
            "--root" if root.is_none() => root = Some(PathBuf::from(args.next()?)),
            _ => return None,
        }
    }
    Some(Args {
        check,
        root: root.unwrap_or_else(|| PathBuf::from(".")),
    })
}

fn main() -> ExitCode {
    let Some(args) = parse(std::env::args().skip(1)) else {
        return ExitCode::from(2);
    };
    let path = args.root.join(API_TS);
    let out = render::render(fstp_access::OPS);
    if args.check {
        return match std::fs::read(&path) {
            Ok(bytes) if bytes == out.as_bytes() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::from(1),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ExitCode::from(1),
            Err(_) => ExitCode::from(2),
        };
    }
    match std::fs::write(&path, out.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}
