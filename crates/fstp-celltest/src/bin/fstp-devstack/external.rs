//! `fstp-devstack external-cell [--resolver-rules]` (lane L4,
//! `docs/handoff/production-mcp-design.md` section 4): the stack of the
//! default mode, with its cell run by the production `fstp-cell` binary
//! from a configuration file instead of in this process.
//!
//! The stack starts two `fstp-custody-sim --serve` processes, one for the
//! cell's App chain and one for the dedicated root of the cell key file. It
//! assembles the compiled web assets (`web/dist/auth` with the shell and
//! stylesheets of `web/src/auth`, and `web/dist/app`) into one assets
//! directory. The world then writes `cell.json` and the credentials
//! directory, runs `fstp-cell first-admin`, and starts `fstp-cell` with
//! `FSTP_CELL_CONFIG` (`fstp_celltest::world::World::start_external`).
//!
//! It prints the lines of the default mode, and before them `config
//! <path>`: the configuration file the binary reads. Proof mail goes to
//! the test SMTP sink of the stack. SIGTERM stops the binary, then the
//! world, then custody.
//!
//! The binary must be built first: `tools/devstack/run.sh external-cell`
//! builds it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fstp_celltest::external_cell::ExternalSpec;
use fstp_celltest::world::{DbMode, VaultLayout, World, WorldError, WorldSpec};
use fstp_celltest::world_host::{SimProcess, bin_path};
use fstp_rt::signal::{Signals as _, TerminationListener as _};
use fstp_rt::tokio::TokioRuntime;

/// The one SaaS-mode world of the stack.
const SPEC: WorldSpec = WorldSpec {
    cells: 1,
    mode: DbMode::Shared,
    vault_layout: VaultLayout::SeparateCluster,
    self_hosted: false,
    process_mode: false,
};

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("{what}: {e}"))
}

/// Copies the directory `from` into `to`, files and subdirectories.
fn copy_dir(from: &Path, to: &Path) -> Result<(), WorldError> {
    std::fs::create_dir_all(to).map_err(|e| fail("the assets directory", &e))?;
    for entry in std::fs::read_dir(from).map_err(|e| fail("the compiled assets", &e))? {
        let entry = entry.map_err(|e| fail("the compiled assets", &e))?;
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target)?;
        } else {
            std::fs::copy(&path, &target).map_err(|e| fail("the compiled assets", &e))?;
        }
    }
    Ok(())
}

/// The assets directory of ADR-026 in `dir`: `auth/` holds the compiled
/// auth pages with the shell and stylesheets beside them, and `app/` the
/// compiled journey UI with its manifest.
fn assemble_assets(dir: &Path) -> Result<PathBuf, WorldError> {
    let web = fstp_celltest::mc::place_model::db::workspace_root().join("web");
    let assets = dir.join("assets");
    let (dist_auth, dist_app) = (web.join("dist").join("auth"), web.join("dist").join("app"));
    if !dist_auth.is_dir() || !dist_app.is_dir() {
        return Err(fail(
            "the compiled web assets",
            &"web/dist/auth or web/dist/app is missing; run tools/devstack/run.sh external-cell",
        ));
    }
    copy_dir(&dist_auth, &assets.join("auth"))?;
    let src = web.join("src").join("auth");
    for entry in std::fs::read_dir(&src).map_err(|e| fail("web/src/auth", &e))? {
        let entry = entry.map_err(|e| fail("web/src/auth", &e))?;
        let name = entry.file_name();
        let keep = name
            .to_str()
            .is_some_and(|n| n == "shell.html" || n.ends_with(".css"));
        if keep {
            std::fs::copy(entry.path(), assets.join("auth").join(&name))
                .map_err(|e| fail("web/src/auth", &e))?;
        }
    }
    copy_dir(&dist_app, &assets.join("app"))?;
    Ok(assets)
}

/// A short private directory of this run, for sockets and files.
fn run_dir() -> Result<PathBuf, WorldError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let tag = fstp_crypto::random_array::<6>().map_err(|e| fail("a directory name", &e))?;
    let dir = std::env::temp_dir().join(format!(
        "fstp-ext-{}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| fail("the run directory", &e))?;
    Ok(dir)
}

/// Runs the mode (module documentation).
pub(crate) fn run(args: &[String]) -> ExitCode {
    let resolver = match args {
        [] => false,
        [flag] if flag == "--resolver-rules" => true,
        _ => {
            eprintln!("usage: fstp-devstack external-cell [--resolver-rules]");
            return ExitCode::from(2);
        }
    };
    let rt = match TokioRuntime::new_multi_thread(2) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fstp-devstack external-cell: no runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut term = match rt.listen_termination() {
        Ok(term) => term,
        Err(e) => {
            eprintln!("fstp-devstack external-cell: {e}");
            return ExitCode::FAILURE;
        }
    };
    let started = (|| -> Result<_, WorldError> {
        let binary = bin_path("fstp-cell")?;
        let dir = run_dir()?;
        let assets = assemble_assets(&dir)?;
        let custody = SimProcess::spawn(0, &dir)?;
        let key_file_custody = SimProcess::spawn(1, &dir)?;
        let spec = ExternalSpec {
            binary,
            dir: dir.clone(),
            key_file_custody: key_file_custody.socket().to_path_buf(),
            assets_dir: Some(assets),
        };
        let world = World::start_external(SPEC, custody.socket().to_path_buf(), &spec)?;
        Ok((world, custody, key_file_custody, dir))
    })();
    let (world, custody, key_file_custody, dir) = match started {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fstp-devstack external-cell: the stack did not start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let config = world
        .cell(0)
        .and_then(|c| c.external())
        .map(|e| e.config_path().display().to_string())
        .unwrap_or_default();
    let lines = match crate::announce(&world, resolver) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("fstp-devstack external-cell: the world gives no URLs: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout().lock();
    let printed = writeln!(out, "config {config}")
        .and_then(|()| {
            lines
                .iter()
                .try_for_each(|(name, url)| writeln!(out, "{name} {url}"))
        })
        .and_then(|()| writeln!(out, "ready"))
        .and_then(|()| out.flush());
    drop(out);
    if let Err(e) = printed {
        eprintln!("fstp-devstack external-cell: cannot write the URLs: {e}");
        return ExitCode::FAILURE;
    }
    let which = rt.block_on(term.recv());
    eprintln!("fstp-devstack external-cell: {which:?} received, stopping");
    // The binary drains first, then the world, then custody.
    drop(world);
    drop(key_file_custody);
    drop(custody);
    let _ = std::fs::remove_dir_all(&dir);
    ExitCode::SUCCESS
}
