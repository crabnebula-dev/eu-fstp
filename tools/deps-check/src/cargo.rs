//! Runs `cargo metadata`.

use std::path::Path;
use std::process::Command;

/// One `cargo metadata` invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Query<'a> {
    /// Target triple for `--filter-platform`, or `None` for every target.
    pub(crate) platform: Option<&'a str>,
    /// Whether to pass `--all-features`.
    pub(crate) all_features: bool,
    /// Whether to pass `--offline`.
    pub(crate) offline: bool,
}

/// Runs `cargo metadata --format-version 1 --locked` with the options in
/// `q` for the project whose manifest is in `dir`, and returns its output.
///
/// The cargo binary comes from `CARGO` when deps-check runs under `cargo run`,
/// so the same toolchain answers, and from `PATH` otherwise.
pub(crate) fn metadata(dir: &Path, q: Query<'_>) -> Result<Vec<u8>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(dir)
        .arg("metadata")
        .args(["--format-version", "1", "--locked"])
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"));
    if let Some(p) = q.platform {
        cmd.args(["--filter-platform", p]);
    }
    if q.all_features {
        cmd.arg("--all-features");
    }
    if q.offline {
        cmd.arg("--offline");
    }
    let out = cmd.output().map_err(|e| format!("cannot run cargo: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        Err(format!(
            "cargo metadata failed ({}): {}",
            out.status,
            tail.join(" | ")
        ))
    }
}
