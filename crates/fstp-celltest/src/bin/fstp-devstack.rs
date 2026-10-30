//! The `fstp-devstack` binary (M3 design sections 0.1 and 2.3). Local
//! development only. Lane W3b owns it. `tools/devstack/run.sh` compiles
//! the auth pages with the pinned `tsc`, then builds and runs it.
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
//! fragment never reaches a server log or a `Referer` field. The page is
//! one of the compiled auth pages (`fstp_cell::http::pages::PAGE_PATHS`),
//! not a route of `fstp_cell::routes::table`, which transcribes design
//! section 8.7 (a conflict with `tests/slice_devstack.rs`, raised by lane
//! int4). So the stack first loads the compiled pages
//! (`fstp_celltest::world::auth_pages`) and refuses to start without
//! them: a link that opens nothing is never printed. It passes them to
//! the world (`World::start_with_pages`), whose cell serves them. The
//! cell and vault URLs are printed only as the exact origins, with no
//! port, since the relying party origin carries none (I-20). Once the
//! world runs a cell, the link is printed only when `GET /auth/invite`
//! answers 200 on the cell origin.
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

use fstp_cell::http::pages::PAGE_PATHS;
use fstp_celltest::world::{
    AUTH_PAGES_ENV, CellHandle, CellUrls, DbMode, HttpRequest, VaultLayout, World, WorldError,
    WorldSpec, auth_pages,
};
use fstp_rt::signal::{Signals as _, TerminationListener as _};
use fstp_rt::tokio::TokioRuntime;

/// The page the enrolment link opens (design section 8.3).
const ENROL_PAGE: &str = "/auth/invite";

/// Checks that the cell serves [`ENROL_PAGE`]: it is a compiled page
/// path, and a `GET` of it on the cell origin answers 200.
fn check_enrol_page(cell: &CellHandle, origin: &str) -> Result<(), WorldError> {
    if !PAGE_PATHS.contains(&ENROL_PAGE) {
        return Err(WorldError::Store(format!(
            "{ENROL_PAGE} is not a page path of fstp_cell::http::pages"
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

/// Checks that the cell and vault URLs are the exact origins
/// `https://<host>/` and `https://id.<host>/`, with no port. The relying
/// party origin carries no port (I-20, `fstp_webauthn::RelyingParty`),
/// and the cell checks `Origin` and the client data against it byte for
/// byte. So a URL on another port would let a browser load the pages and
/// then refuse every login with 403. The world's edge listens on loopback
/// port 443 (`fstp_celltest::world::CELL_FRONT_SEAM`).
fn check_origins(cell: &CellHandle, urls: &CellUrls) -> Result<(), WorldError> {
    let host = cell.host();
    for (name, got, want) in [
        ("cell", &urls.cell, format!("https://{host}/")),
        ("vault", &urls.vault, format!("https://id.{host}/")),
    ] {
        if *got != want {
            return Err(WorldError::Store(format!(
                "the {name} URL {got} is not the origin {want}: the relying party origin carries no port"
            )));
        }
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
    check_origins(cell, &urls)?;
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
    // Before the slow world start: a browser needs the compiled pages.
    let pages = match auth_pages() {
        Ok(Some(pages)) => pages,
        Ok(None) => {
            eprintln!(
                "fstp-devstack: the auth pages are not compiled (web/dist/auth, or {AUTH_PAGES_ENV}); run tools/devstack/run.sh, which compiles web/src/auth with web/node_modules/.bin/tsc"
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("fstp-devstack: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Each cell of the world serves the loaded pages on its origin.
    let world = match World::start_with_pages(SPEC, Some(pages)) {
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
