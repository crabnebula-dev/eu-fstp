//! `unorm-gen` writes `crates/fstp-unorm/src/tables.rs` from the vendored
//! Unicode Character Database under `third_party/unicode/<version>/`
//! (ADR-029). It is a build tool and never ships.
//!
//! Usage: `unorm-gen [--check] [--root <dir>]`. The root defaults to the
//! current directory.
//!
//! - Without `--check`, it writes the file under the root. The directory
//!   `crates/fstp-unorm/src` must exist, so a wrong root writes nothing.
//! - With `--check`, it compares the file with the output and never
//!   writes. A missing or different file fails.
//!
//! It prints nothing, since the R-NF-02 print ban covers every workspace
//! member. The exit status is its only answer: 0 for success, 1 for a
//! stale or missing file under `--check`, and 2 for a usage, I/O or parse
//! error.

use std::path::PathBuf;
use std::process::ExitCode;

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
    let Ok(out) = unorm_gen::generate(&args.root.join(unorm_gen::UCD_DIR)) else {
        return ExitCode::from(2);
    };
    let path = args.root.join(unorm_gen::TABLES_RS);
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
