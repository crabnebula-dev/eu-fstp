//! Routes of the edge (ADR-028 "Plain route changes" and "Routes before
//! lane L15", ADR-009).
//!
//! `setup` adds the host's own route, and `renew` updates its pins
//! whenever a tunnel certificate is issued again, so an operator never
//! types a route command on a pilot. `fstp-admin route` stays for rare
//! manual changes.
//!
//! The seam: on `main` the edge reads a route file, so a change rewrites
//! that file and restarts the edge. Once lane L15 merges, [`ROUTE_FEED`]
//! turns true and a change goes through `fstp-control route add`,
//! `route remove` and `route list`, which apply at once with no restart.

use std::path::Path;
use std::process::Command;

use crate::fail::{Cause, Fail};
use crate::layout::Layout;
use crate::render::{self, Route};
use crate::say::{Part, out};
use crate::state::write_atomic;
use crate::svc::{Manager, run_logged};

/// Whether routes go through the route feed of lane L15. False until that
/// lane is on `main`.
pub const ROUTE_FEED: bool = false;

/// The DER of the first certificate of a PEM text.
#[must_use]
pub fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return None;
    }
    fstp_pgwire::base64::decode(body.as_bytes()).ok()
}

/// The pin of the first certificate of a PEM text: the SHA-256 of its
/// DER, as 64 lowercase hex digits.
#[must_use]
pub fn pem_pin(pem: &str) -> Option<String> {
    pem_der(pem).map(|d| crate::pki::cert_pin(&d))
}

fn log_change(layout: &Layout, action: &str, r: &Route) {
    let line = format!("{} {action} {} {}\n", crate::pki::now(), r.host, r.cell);
    let path = layout.route_log();
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write as _;
        let _ = f.write_all(line.as_bytes());
    }
}

fn control(layout: &Layout, args: &[&std::ffi::OsStr]) -> Result<(), Fail> {
    let mut c = Command::new(layout.bin("fstp-control"));
    c.env("FSTP_CONTROL_CONFIG", layout.config_file("control"))
        .args(args);
    match run_logged(&mut c, &Manager::new(layout).log())
        .map_err(|e| Fail::Step("route", e.into()))?
    {
        Some(0) => Ok(()),
        code => Err(Fail::Refused("fstp-control route", code)),
    }
}

/// The routes the edge serves now.
///
/// # Errors
///
/// [`Fail`] when the list does not read.
pub fn list(layout: &Layout) -> Result<Vec<Route>, Fail> {
    if ROUTE_FEED {
        let tmp = layout.admin_dir().join("routes.list");
        let _ = std::fs::remove_file(&tmp);
        control(
            layout,
            &["route".as_ref(), "list".as_ref(), tmp.as_os_str()],
        )?;
        let text = std::fs::read_to_string(&tmp).map_err(|_| Fail::Step("route", Cause::Io))?;
        let _ = std::fs::remove_file(&tmp);
        return Ok(render::parse_routes(&text));
    }
    match std::fs::read_to_string(layout.edge_routes()) {
        Ok(t) => Ok(render::parse_routes(&t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(Fail::Step("route", Cause::Io)),
    }
}

fn write_file(layout: &Layout, m: &Manager, routes: &[Route]) -> Result<(), Fail> {
    write_atomic(
        &layout.edge_routes(),
        render::routes(routes).as_bytes(),
        0o644,
    )
    .map_err(|_| Fail::Step("route", Cause::Io))?;
    if layout.cfg.services == crate::config::Services::Systemd {
        let mut c = Command::new("chown");
        c.arg(format!("{0}:{0}", crate::stack::EDGE_USER))
            .arg(layout.edge_routes());
        let _ = run_logged(&mut c, &m.log());
    }
    let edge = crate::stack::edge(layout);
    if m.running(&edge) {
        // A change of the route file needs a restart of the edge.
        m.stop(&edge).map_err(|e| Fail::Step("route", e.into()))?;
        m.ensure(&edge).map_err(|e| Fail::Step("route", e.into()))?;
    }
    Ok(())
}

/// Adds `r`, or replaces the route of its cell.
///
/// # Errors
///
/// [`Fail`] when the change does not apply.
pub fn add(layout: &Layout, m: &Manager, r: &Route) -> Result<(), Fail> {
    if ROUTE_FEED {
        let tmp = layout.admin_dir().join("route.json");
        write_atomic(
            &tmp,
            render::routes(std::slice::from_ref(r)).as_bytes(),
            0o600,
        )
        .map_err(|_| Fail::Step("route", Cause::Io))?;
        control(layout, &["route".as_ref(), "add".as_ref(), tmp.as_os_str()])?;
        let _ = std::fs::remove_file(&tmp);
    } else {
        let mut routes: Vec<Route> = list(layout)?
            .into_iter()
            .filter(|x| x.cell != r.cell && x.host != r.host)
            .collect();
        routes.push(r.clone());
        write_file(layout, m, &routes)?;
    }
    log_change(layout, "add", r);
    Ok(())
}

/// Removes every route of the cell `cell` (32 hex digits).
///
/// # Errors
///
/// [`Fail`] when the change does not apply.
pub fn remove(layout: &Layout, m: &Manager, cell: &str) -> Result<bool, Fail> {
    let before = list(layout)?;
    let Some(gone) = before.iter().find(|x| x.cell == cell).cloned() else {
        return Ok(false);
    };
    if ROUTE_FEED {
        control(
            layout,
            &["route".as_ref(), "remove".as_ref(), cell.as_ref()],
        )?;
    } else {
        let routes: Vec<Route> = before.into_iter().filter(|x| x.cell != cell).collect();
        write_file(layout, m, &routes)?;
    }
    log_change(layout, "remove", &gone);
    Ok(true)
}

/// Makes sure the edge routes this host's cell with the pins of its
/// current tunnel certificates. Returns whether it changed the route.
///
/// # Errors
///
/// [`Fail`] when the change does not apply.
pub fn ensure_own(layout: &Layout, m: &Manager, cell: [u8; 16]) -> Result<bool, Fail> {
    let want = crate::setup::own_route(layout, cell);
    let have = list(layout)?;
    if have.contains(&want) {
        out(&[
            Part::T("  skipped  route of "),
            Part::Name(&want.host),
            Part::T(" (current)"),
        ]);
        return Ok(false);
    }
    if !ROUTE_FEED && !layout.edge_routes().is_file() {
        // The first route file, before the edge ever started.
        write_atomic(
            &layout.edge_routes(),
            render::routes(std::slice::from_ref(&want)).as_bytes(),
            0o644,
        )
        .map_err(|_| Fail::Step("route", Cause::Io))?;
        log_change(layout, "add", &want);
    } else {
        add(layout, m, &want)?;
    }
    out(&[Part::T("  done     route of "), Part::Name(&want.host)]);
    Ok(true)
}

/// Whether the served route of this host's cell has the current pins.
#[must_use]
pub fn own_is_current(layout: &Layout, cell: [u8; 16]) -> Option<bool> {
    let want = crate::setup::own_route(layout, cell);
    let have = list(layout).ok()?;
    Some(have.contains(&want))
}

/// Reads a route file the admin wrote for `route add`.
///
/// # Errors
///
/// [`Fail::Missing`] when it does not read, [`Fail::Usage`] when it holds
/// no route.
pub fn read_file(path: &Path) -> Result<Vec<Route>, Fail> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| Fail::Missing(path.to_owned(), "the route file"))?;
    let routes = render::parse_routes(&text);
    if routes.is_empty()
        || routes.iter().any(|r| {
            r.cell.len() != 32
                || r.host.is_empty()
                || r.app_pin.len() != 64
                || r.vault_pin.len() != 64
        })
    {
        return Err(Fail::Usage);
    }
    Ok(routes)
}
