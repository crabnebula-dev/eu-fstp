//! `corpus` writes the synthetic corpus `corpus/v1` from its seed (M7
//! design section 5). CI runs it with `--check`, as `gen-ts --check`
//! runs. It is a build tool and never ships.
//!
//! Usage: `corpus [--check] [--dir <dir>]`. The directory defaults to
//! `corpus/v1` of this repository.
//!
//! - Without `--check`, it writes the manifest, the items and the fixture
//!   pages, and removes stale files among them. `recordings/` and `panel/`
//!   are never touched.
//! - With `--check`, it compares and never writes.
//!
//! It prints nothing, since the R-NF-02 print ban covers every workspace
//! member. The exit status is its answer: 0 for success, 1 for a stale
//! corpus under `--check`, and 2 for a usage or I/O error.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut check = false;
    let mut dir: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check" if !check => check = true,
            "--dir" if dir.is_none() => match args.next() {
                Some(d) => dir = Some(PathBuf::from(d)),
                None => return ExitCode::from(2),
            },
            _ => return ExitCode::from(2),
        }
    }
    let dir = dir.unwrap_or_else(corpus::default_dir);
    let generated = corpus::generate(corpus::V1_SEED);
    if check {
        match generated.check_against(&dir) {
            Ok(stale) if stale.is_empty() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::from(1),
            Err(_) => ExitCode::from(2),
        }
    } else {
        match generated.write_to(&dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(2),
        }
    }
}
