//! `fstp-devstack external-cell [--resolver-rules] [--route-feed]` (lane L4,
//! `docs/handoff/production-mcp-design.md` section 4): the stack of the
//! default mode, with its cell run by the production `fstp-cell` binary
//! from a configuration file instead of in this process.
//!
//! The stack starts two `fstp-custody-sim --serve` processes, one for the
//! cell's App chain and one for the dedicated root of the cell key file. It
//! assembles the compiled web assets (`web/dist/auth` with the shell and
//! stylesheets of `web/src/auth`, and `web/dist/app`) into one assets
//! directory. The world then writes `cell.json` and the credentials
//! directory, runs `fstp-cell provision-tenant` and `fstp-cell first-admin
//! --email` with the first admin's synthetic login email, and starts
//! `fstp-cell` with `FSTP_CELL_CONFIG`
//! (`fstp_celltest::world::World::start_external`). As on a pilot, the
//! organisation is not active until onboarding opens it (ADR-026 record
//! of lane L18). The configuration has no `organisation_active` member.
//!
//! It prints the lines of the default mode, and before them `config
//! <path>`: the configuration file the binary reads. SIGTERM stops the
//! binary, then the world, then custody.
//!
//! The stack runs a mail relay of its own (ADR-026 record of lane L20):
//! the `fstp-devstack-relay` process of `fstp-api-testkit`, since rule A9
//! keeps the test SMTP sink out of this binary. The cell submits to it,
//! and each accepted message lands in `<run dir>/mail/<n>.eml`, printed
//! as `mail-dir <path>`. Open the second admin's invitation link there.
//! The same process runs a fake resolver, which the cell's `shell`
//! member names with the DKIM selector printed as `dkim-selector`. It
//! answers SPF, DKIM and DMARC for any name, so any sending domain passes
//! the Domains and email step, and the Channels step passes too.
//!
//! With `--route-feed` (lane L15, ADR-009 "Pilot route feed") it also starts
//! the `fstp-control route-feed` and `fstp-edge` binaries in front of the
//! cell, from a third custody process, and adds the cell's route through
//! `fstp-control route add`. It then prints `route-feed-edge <address>`,
//! where the edge binary listens, `control-config <path>`, the file that
//! `FSTP_CONTROL_CONFIG` names for `fstp-control route add` and `route
//! remove`, and `route-file <path>`, the cell's route file. A developer can
//! then remove and add the route by hand and watch the edge follow without
//! a restart. The URLs of the other lines still name the world's own edge.
//!
//! The binaries must be built first: `tools/devstack/run.sh external-cell`
//! builds them.

#![allow(
    clippy::disallowed_macros,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fstp_celltest::external_cell::{ExternalRelay, ExternalShell, ExternalSpec};
use fstp_celltest::external_edge::PilotFeed;
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
    let mut resolver = false;
    let mut route_feed = false;
    for flag in args {
        match flag.as_str() {
            "--resolver-rules" => resolver = true,
            "--route-feed" => route_feed = true,
            _ => {
                eprintln!("usage: fstp-devstack external-cell [--resolver-rules] [--route-feed]");
                return ExitCode::from(2);
            }
        }
    }
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
        // ADR-026 record of lane L20: the relay and resolver process, so
        // onboarding runs end to end.
        let relay = start_relay(&dir)?;
        let spec = ExternalSpec {
            binary,
            dir: dir.clone(),
            key_file_custody: key_file_custody.socket().to_path_buf(),
            assets_dir: Some(assets),
            // Rule A9 keeps the test SMTP sink out of this binary, so it
            // runs in the relay process of `fstp-api-testkit`.
            relay: Some(relay.relay.clone()),
            shell: Some(ExternalShell {
                resolver: relay.resolver,
                dkim_selector: DKIM_SELECTOR.to_owned(),
            }),
        };
        let world = World::start_external(SPEC, custody.socket().to_path_buf(), &spec)?;
        let feed = if route_feed {
            Some(start_route_feed(&world, &dir)?)
        } else {
            None
        };
        Ok((world, custody, key_file_custody, dir, feed, relay))
    })();
    let (world, custody, key_file_custody, dir, feed, relay) = match started {
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
    let feed_lines = feed
        .as_ref()
        .map(|(f, _, file)| {
            format!(
                "route-feed-edge {}\ncontrol-config {}\nroute-file {}\n",
                f.edge_addr(),
                f.control_config().display(),
                file.display()
            )
        })
        .unwrap_or_default();
    let relay_lines = format!(
        "mail-dir {}\ndkim-selector {DKIM_SELECTOR}\n",
        relay.mail_dir.display()
    );
    let printed = writeln!(out, "config {config}")
        .and_then(|()| write!(out, "{relay_lines}"))
        .and_then(|()| write!(out, "{feed_lines}"))
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
    // The edge and the route feed stop before the cell.
    drop(feed);
    drop(world);
    drop(key_file_custody);
    drop(relay);
    drop(custody);
    let _ = std::fs::remove_dir_all(&dir);
    ExitCode::SUCCESS
}

/// Starts the pilot route feed and edge binaries in front of `world`'s
/// cell from a third custody process, and adds the cell's route through
/// `fstp-control route add` (lane L15). Returns the feed, its custody
/// process and the route file.
fn start_route_feed(
    world: &World,
    dir: &Path,
) -> Result<(PilotFeed, SimProcess, PathBuf), WorldError> {
    let custody = SimProcess::spawn(2, dir)?;
    let feed = PilotFeed::start(world, dir, custody.socket(), 1)?;
    let routes = feed.pinned_routes()?;
    let route = routes
        .first()
        .ok_or_else(|| fail("the route feed", &"the world has no route"))?;
    let file = feed.route_file(route, "cell-route")?;
    let added = feed.add(&file)?;
    if !added.success() {
        return Err(fail("fstp-control route add", &added));
    }
    Ok((feed, custody, file))
}

/// The fstp-tls test CA, which issued the relay's `localhost` certificate.
const RELAY_CA: &[u8] = include_bytes!("../../../../fstp-tls/testdata/ca.pem");

/// The DKIM selector the cell's `shell` member names. The fake resolver
/// answers every selector.
const DKIM_SELECTOR: &str = "devstack";

/// The `fstp-devstack-relay` process of the stack (ADR-026 record of lane
/// L20). It ends when its standard input closes, so dropping this ends
/// it.
struct DevRelay {
    child: std::process::Child,
    relay: ExternalRelay,
    resolver: std::net::SocketAddr,
    mail_dir: PathBuf,
}

impl Drop for DevRelay {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

/// Starts `fstp-devstack-relay` with its mail directory in `dir` and
/// reads the lines of its ready file.
fn start_relay(dir: &Path) -> Result<DevRelay, WorldError> {
    let mail_dir = dir.join("mail");
    let ready = dir.join("relay.ready");
    let mut child = std::process::Command::new(bin_path("fstp-devstack-relay")?)
        .arg(&mail_dir)
        .arg(&ready)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| fail("fstp-devstack-relay", &e))?;
    let start = std::time::Instant::now();
    while !ready.exists() {
        let ended = child
            .try_wait()
            .map_err(|e| fail("fstp-devstack-relay", &e))?;
        if let Some(status) = ended {
            return Err(fail("fstp-devstack-relay", &status));
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            return Err(fail("fstp-devstack-relay", &"not ready within 30 seconds"));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let text = std::fs::read_to_string(&ready).map_err(|e| fail("fstp-devstack-relay", &e))?;
    let mut got = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line == "ready" {
            break;
        }
        if let Some((k, v)) = line.split_once(' ') {
            got.insert(k.to_owned(), v.to_owned());
        }
    }
    let word = |k: &str| -> Result<String, WorldError> {
        got.get(k)
            .cloned()
            .ok_or_else(|| fail("fstp-devstack-relay", &format!("no {k} line")))
    };
    let parse = |k: &str| -> Result<std::net::SocketAddr, WorldError> {
        word(k)?
            .parse()
            .map_err(|e| fail("fstp-devstack-relay", &e))
    };
    let files = mail_dir.clone();
    let relay = ExternalRelay {
        address: parse("relay")?,
        relay: "localhost".to_owned(),
        username: word("user")?,
        password: word("password")?,
        ca_pem: RELAY_CA.to_vec(),
        // The files hold the messages; the recipient is in each header.
        messages: std::sync::Arc::new(move || {
            let mut names: Vec<PathBuf> = std::fs::read_dir(&files)
                .map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            names.retain(|p| p.extension().is_some_and(|x| x == "eml"));
            names.sort();
            names
                .into_iter()
                .filter_map(|p| std::fs::read(p).ok())
                .map(|data| (String::new(), data))
                .collect()
        }),
    };
    Ok(DevRelay {
        child,
        relay,
        resolver: parse("resolver")?,
        mail_dir,
    })
}
