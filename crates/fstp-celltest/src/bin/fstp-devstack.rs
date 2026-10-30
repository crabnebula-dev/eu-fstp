//! The `fstp-devstack` binary (M3 design sections 0.1 and 2.3). Local
//! development only. Lane W3b owns it. `tools/devstack/run.sh` builds and
//! runs it.
//!
//! The contract that `tests/slice_devstack.rs` checks: the binary starts
//! one SaaS-mode world on localhost, with its clusters, a cell, the vault
//! and the witness. On standard output it prints one line `<name> <url>`
//! for each of `cell`, `vault`, `witness`, `health` and `enrol`, then the
//! line `ready`. The vault URL is on `id.<cell host>`. The `health` URL is
//! `http://<loopback ip>:<port>/healthz`. The `enrol` link is on the cell
//! origin and carries the random first-admin token, so no default
//! credential exists (R-NF-05). On SIGTERM it drains, stops the world and
//! exits with success.
//!
//! The enrolment link opens the invitation page `/auth/invite`, with both
//! halves of the split first-admin token in its fragment, first half
//! first (design section 8.3, `web/src/auth/pages/invite.ts`). A
//! fragment never reaches a server log or a `Referer` field. The link is
//! printed only when the cell's route table has `GET /auth/invite` and
//! that page answers 200 on the cell origin. Today the cell serves no
//! page of `web/src/auth` (lanes W3a and W3c), so the stack refuses with
//! [`ENROL_PAGE_SEAM`] rather than print a link that opens nothing.
//!
//! The binary registers its termination handlers before the world starts,
//! so a SIGTERM during the start is queued rather than fatal. A world that
//! does not start, or a URL it cannot give, ends the binary with failure
//! and the reason on standard error. Nothing is printed that the world did
//! not report, so a missing part never looks like a running stack.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::io::Write as _;
use std::process::ExitCode;

use fstp_celltest::NotImplemented;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpRequest, VaultLayout, World, WorldError, WorldSpec,
};
use fstp_rt::signal::{Signals as _, TerminationListener as _};
use fstp_rt::tokio::TokioRuntime;

/// The page the enrolment link opens (design section 8.3).
const ENROL_PAGE: &str = "/auth/invite";

/// The refusal when the cell does not serve [`ENROL_PAGE`].
const ENROL_PAGE_SEAM: &str = "fstp-devstack enrolment link: the cell route table fstp_cell::routes::table has no GET /auth/invite, and the cell serves no tsc-compiled page of web/src/auth, so the link would open nothing (lanes W3a and W3c)";

/// Checks that the cell serves [`ENROL_PAGE`]: its route table has the
/// page, and a `GET` of it on the cell origin answers 200.
fn check_enrol_page(cell: &CellHandle, origin: &str) -> Result<(), WorldError> {
    let routed = fstp_cell::routes::table()
        .iter()
        .any(|r| matches!(r.parts(), ("GET", ENROL_PAGE, _)));
    if !routed {
        return Err(WorldError::NotImplemented(NotImplemented::new(
            ENROL_PAGE_SEAM,
        )));
    }
    let authority = origin
        .strip_prefix("https://")
        .unwrap_or(origin)
        .trim_end_matches('/');
    let reply = cell.request(&HttpRequest::new("GET", ENROL_PAGE).header("Host", authority))?;
    if reply.status != 200 {
        return Err(WorldError::Store(format!(
            "GET {ENROL_PAGE} on the cell origin answered {}",
            reply.status
        )));
    }
    Ok(())
}

/// The one SaaS-mode world of the stack.
const SPEC: WorldSpec = WorldSpec {
    cells: 1,
    mode: DbMode::Shared,
    vault_layout: VaultLayout::SeparateCluster,
    self_hosted: false,
    process_mode: false,
};

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `<name> <url>` lines of a started world, in the order printed.
fn announce(world: &World) -> Result<Vec<(&'static str, String)>, WorldError> {
    let cell = world
        .cell(0)
        .ok_or_else(|| WorldError::Store("the one-cell world holds no cell 0".to_owned()))?;
    let urls = cell.urls()?;
    let witness = world.witness_url()?;
    check_enrol_page(cell, &urls.cell)?;
    let invitation = cell.first_admin_invitation()?;
    let enrol = format!(
        "{}{ENROL_PAGE}#{}{}",
        urls.cell.trim_end_matches('/'),
        hex(&invitation.first),
        hex(&invitation.second)
    );
    Ok(vec![
        ("cell", urls.cell),
        ("vault", urls.vault),
        ("witness", witness),
        ("health", urls.health),
        ("enrol", enrol),
    ])
}

fn main() -> ExitCode {
    let rt = match TokioRuntime::new_multi_thread(2) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fstp-devstack: no runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut term = match rt.listen_termination() {
        Ok(term) => term,
        Err(e) => {
            eprintln!("fstp-devstack: {e}");
            return ExitCode::FAILURE;
        }
    };
    let world = match World::start(SPEC) {
        Ok(world) => world,
        Err(e) => {
            eprintln!("fstp-devstack: the world did not start: {e}");
            return ExitCode::FAILURE;
        }
    };
    let lines = match announce(&world) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("fstp-devstack: the world gives no URLs: {e}");
            drop(world);
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout().lock();
    let printed = lines
        .iter()
        .try_for_each(|(name, url)| writeln!(out, "{name} {url}"))
        .and_then(|()| writeln!(out, "ready"))
        .and_then(|()| out.flush());
    drop(out);
    if let Err(e) = printed {
        eprintln!("fstp-devstack: cannot write the URLs: {e}");
        drop(world);
        return ExitCode::FAILURE;
    }
    let which = rt.block_on(term.recv());
    eprintln!("fstp-devstack: {which:?} received, stopping");
    // The world ends with its handle. Its clusters stop when the process
    // exits, through the fstp-pgtest watchdog. A world that starts cells
    // drains them when its handle drops (lane W3b, with the cell start).
    drop(world);
    ExitCode::SUCCESS
}
