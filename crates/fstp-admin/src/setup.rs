//! `fstp-admin setup` (ADR-028 "One operator command" and "Setup is
//! resumable").
//!
//! The steps run in a fixed order. Each one checks its own result first
//! and skips when it is done, saying so. A failed step stops the run and
//! names what to fix. The next run starts again from the top and skips
//! what is done.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_pki::cert::CertKind;

use crate::config::Services;
use crate::fail::{Cause, Fail};
use crate::layout::{Cluster, Entry, Layout};
use crate::pki::{Ca, Issued, Leaf, needs_issue, random_hex, write_pair};
use crate::render::{self, CELL_TUNNEL_NAME, Facts, Route, VAULT_TUNNEL_NAME, WITNESS_NAME};
use crate::say::{Part, out};
use crate::stack;
use crate::state::{State, write_atomic};
use crate::svc::{Manager, run_logged, run_ok};

const LOOPBACK: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::LOCALHOST)];

/// The host CAs.
pub struct Cas {
    /// The application cluster CA.
    pub app_db: Ca,
    /// The vault cluster CA.
    pub vault_db: Ca,
    /// The cell CA.
    pub cell: Ca,
    /// The tunnel CA.
    pub tunnel: Ca,
    /// The witness CA.
    pub witness: Ca,
    /// The self-signed origin CA, when the admin named no certificate.
    pub origin: Option<Ca>,
}

/// Opens or creates the host CAs.
///
/// # Errors
///
/// [`Fail::Step`] when a CA does not open or write.
pub fn cas(layout: &Layout) -> Result<Cas, Fail> {
    let dir = layout.ca_dir();
    let f = |e| Fail::Step("certificates", Cause::Pki(e));
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("certificates", Cause::Io))?;
    Ok(Cas {
        app_db: Ca::open_or_create(&dir, "fstp-app-db-ca").map_err(f)?,
        vault_db: Ca::open_or_create(&dir, "fstp-vault-db-ca").map_err(f)?,
        cell: Ca::open_or_create(&dir, "fstp-cell-ca").map_err(f)?,
        tunnel: Ca::open_or_create(&dir, "fstp-tunnel-ca").map_err(f)?,
        witness: Ca::open_or_create(&dir, "fstp-witness-ca").map_err(f)?,
        origin: match layout.cfg.tls {
            Some(_) => None,
            None => Some(Ca::open_or_create(&dir, "fstp-self-signed-origin-ca").map_err(f)?),
        },
    })
}

fn say_done(step: &'static str, did: bool) {
    if did {
        out(&[Part::T("  done     "), Part::T(step)]);
    } else {
        out(&[
            Part::T("  skipped  "),
            Part::T(step),
            Part::T(" (already done)"),
        ]);
    }
}

fn step_err(step: &'static str) -> impl Fn(Cause) -> Fail {
    move |c| Fail::Step(step, c)
}

fn io(step: &'static str) -> impl Fn(std::io::Error) -> Fail {
    move |_| Fail::Step(step, Cause::Io)
}

/// The cell id of the host, drawn once.
///
/// # Errors
///
/// [`Fail::Step`] when the state does not write.
pub fn cell_id(state: &mut State) -> Result<[u8; 16], Fail> {
    let hex = match state.get("cell") {
        Some(h) => h.to_owned(),
        None => {
            let h = random_hex(16).map_err(|e| Fail::Step("ids", Cause::Pki(e)))?;
            state.set("cell", &h).map_err(io("ids"))?;
            h
        }
    };
    let bytes = crate::witness::unhex(&hex).ok_or(Fail::Step("ids", Cause::Io))?;
    bytes.try_into().map_err(|_| Fail::Step("ids", Cause::Io))
}

/// Gives `path` to `user` in systemd mode.
pub fn own_path(layout: &Layout, path: &Path, user: &str) -> Result<(), Cause> {
    if layout.cfg.services == Services::Systemd {
        let mut c = Command::new("chown");
        c.arg("-R").arg(format!("{user}:{user}")).arg(path);
        run_ok(&mut c, &Manager::new(layout).log())?;
    }
    Ok(())
}

fn need_file(path: &Path, what: &'static str) -> Result<(), Fail> {
    if path.is_file() {
        Ok(())
    } else {
        Err(Fail::Missing(path.to_owned(), what))
    }
}

/// Checks what the admin supplies before anything changes.
///
/// # Errors
///
/// [`Fail`] naming the first thing missing.
pub fn preflight(layout: &Layout) -> Result<(), Fail> {
    let cfg = &layout.cfg;
    match cfg.services {
        Services::Systemd => {
            let uid = Command::new("id").arg("-u").output().ok();
            let root = uid.is_some_and(|o| o.stdout.starts_with(b"0\n"));
            if !root {
                return Err(Fail::NotRoot);
            }
            need_file(&layout.bin("fstp-keyd"), "the fstp-keyd binary")?;
        }
        Services::Direct => {
            if std::env::var("FSTP_DEPLOYMENT_MODE").as_deref() != Ok("development") {
                return Err(Fail::NotDevelopment);
            }
            match &cfg.custody_simulator {
                Some(p) => need_file(p, "the custody simulator binary")?,
                None => return Err(Fail::NoSimulator),
            }
        }
    }
    for b in [
        "fstp-cell",
        "fstp-vault",
        "fstp-witness",
        "fstp-edge",
        "fstp-pgagent",
    ] {
        need_file(&layout.bin(b), "a platform binary")?;
    }
    if cfg.backup.is_some() {
        need_file(&layout.bin("fstp-backup"), "the fstp-backup binary")?;
    }
    for b in ["initdb", "postgres", "psql"] {
        need_file(&layout.pg_bin(b), "a PostgreSQL 16 program (paths.pg_bin)")?;
    }
    for c in Cluster::ALL {
        let dir = layout.migrations(c);
        if !dir.is_dir() {
            return Err(Fail::Missing(dir, "the migration files (paths.share)"));
        }
    }
    need_file(
        &cfg.mail.password_file,
        "the mail relay password (mail.password_file)",
    )?;
    if let Some(t) = &cfg.tls {
        need_file(&t.cert, "the public certificate (tls.cert)")?;
        need_file(&t.key, "the public certificate key (tls.key)")?;
    }
    if let Some(b) = &cfg.backup {
        need_file(
            &b.access_key_file,
            "the object store access key id (backup.access_key_file)",
        )?;
        need_file(
            &b.secret_key_file,
            "the object store secret key (backup.secret_key_file)",
        )?;
    }
    Ok(())
}

fn users(layout: &Layout) -> Result<bool, Fail> {
    if layout.cfg.services != Services::Systemd {
        return Ok(false);
    }
    let mut did = false;
    for u in stack::USERS {
        if stack::gid_of(u).is_some() {
            continue;
        }
        let mut c = Command::new("useradd");
        c.args([
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            u,
        ]);
        run_ok(&mut c, &Manager::new(layout).log()).map_err(|e| Fail::Step("users", e.into()))?;
        did = true;
    }
    Ok(did)
}

fn keyd(layout: &Layout, m: &Manager, entries: &[Entry]) -> Result<bool, Fail> {
    let mut did = false;
    for e in entries {
        let pass = layout.keyd_passphrase(*e);
        if !pass.is_file() {
            let p = random_hex(32).map_err(|c| Fail::Step("key custody", Cause::Pki(c)))?;
            write_atomic(&pass, format!("{p}\n").as_bytes(), 0o600).map_err(io("key custody"))?;
            did = true;
        }
        if layout.cfg.services == Services::Direct {
            for role in e.roles() {
                if let Some(dir) = layout.keyd_socket(*e, role).parent() {
                    std::fs::create_dir_all(dir).map_err(io("key custody"))?;
                }
            }
        }
        for s in stack::keyd(layout, *e) {
            did |= m
                .ensure(&s)
                .map_err(|c| Fail::Step("key custody", c.into()))?;
        }
    }
    Ok(did)
}

fn issue_to(
    ca: &Ca,
    dir: &Path,
    cert: &str,
    key: &str,
    leaf: &Leaf<'_>,
    step: &'static str,
) -> Result<Option<Issued>, Fail> {
    if !needs_issue(&dir.join(cert)) {
        return Ok(None);
    }
    let issued = ca
        .issue(leaf)
        .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
    write_pair(dir, cert, key, &issued).map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
    Ok(Some(issued))
}

fn copy(from: &Path, to: &Path, step: &'static str) -> Result<(), Fail> {
    let bytes = std::fs::read(from).map_err(io(step))?;
    write_atomic(to, &bytes, 0o600).map_err(io(step))
}

fn put(to: &Path, bytes: &[u8], step: &'static str) -> Result<(), Fail> {
    if std::fs::read(to).is_ok_and(|b| b == bytes) {
        return Ok(());
    }
    write_atomic(to, bytes, 0o600).map_err(io(step))
}

/// Writes the origin certificate of `hosts` to `dir`: the admin's, or one
/// from the self-signed origin CA.
fn origin(
    layout: &Layout,
    cas: &Cas,
    dir: &Path,
    hosts: &[&str],
    step: &'static str,
) -> Result<(), Fail> {
    match (&layout.cfg.tls, &cas.origin) {
        (Some(t), _) => {
            copy(&t.cert, &dir.join("origin.pem"), step)?;
            copy(&t.key, &dir.join("origin.key"), step)
        }
        (None, Some(ca)) => {
            issue_to(
                ca,
                dir,
                "origin.pem",
                "origin.key",
                &Leaf {
                    cn: hosts.first().copied().unwrap_or("origin"),
                    ou: None,
                    kind: CertKind::Server,
                    dns: hosts,
                    ips: &[],
                },
                step,
            )?;
            Ok(())
        }
        (None, None) => Err(Fail::Step(step, Cause::Io)),
    }
}

/// The certificates and credentials of every service, issued again when
/// they near their end (`renew` runs this too). Returns the facts the
/// configuration files need.
///
/// # Errors
///
/// [`Fail::Step`] naming the step.
pub fn credentials(
    layout: &Layout,
    state: &mut State,
    cas: &Cas,
    cell: [u8; 16],
) -> Result<Facts, Fail> {
    let step = "credentials";
    let mkdir = |d: &Path| std::fs::create_dir_all(d).map_err(io(step));
    // Cell.
    let c = layout.creds("cell");
    mkdir(&c)?;
    put(&c.join("db-ca.pem"), &cas.app_db.pem, step)?;
    for stem in crate::pg::service_logins(Cluster::App) {
        let name = crate::pg::role(Cluster::App, &cell, stem);
        issue_to(
            &cas.app_db,
            &c,
            &format!("{stem}.pem"),
            &format!("{stem}.key"),
            &Leaf {
                cn: &name,
                ou: None,
                kind: CertKind::Client,
                dns: &[],
                ips: &[],
            },
            step,
        )?;
    }
    issue_to(
        &cas.tunnel,
        &c,
        "tunnel.pem",
        "tunnel.key",
        &Leaf {
            cn: CELL_TUNNEL_NAME,
            ou: None,
            kind: CertKind::Server,
            dns: &[CELL_TUNNEL_NAME],
            ips: &[],
        },
        step,
    )?;
    put(&c.join("tunnel-ca.pem"), &cas.tunnel.pem, step)?;
    let domain = layout.cfg.domain.clone();
    origin(layout, cas, &c, &[&domain], step)?;
    issue_to(
        &cas.cell,
        &c,
        "internal.pem",
        "internal.key",
        &Leaf {
            cn: "cell",
            ou: None,
            kind: CertKind::Server,
            dns: &["localhost"],
            ips: &LOOPBACK,
        },
        step,
    )?;
    put(&c.join("cell-ca.pem"), &cas.cell.pem, step)?;
    issue_to(
        &cas.cell,
        &c,
        "witness.pem",
        "witness.key",
        &Leaf {
            cn: "cell-witness",
            ou: Some("cell-witness"),
            kind: CertKind::Client,
            dns: &[],
            ips: &[],
        },
        step,
    )?;
    put(&c.join("witness-ca.pem"), &cas.witness.pem, step)?;
    issue_to(
        &cas.cell,
        &c,
        "vault.pem",
        "vault.key",
        &Leaf {
            cn: "cell-app",
            ou: Some("cell-app"),
            kind: CertKind::Client,
            dns: &[],
            ips: &[],
        },
        step,
    )?;
    put(&c.join("vault-ca.pem"), &cas.cell.pem, step)?;
    copy(
        &layout.cfg.mail.password_file,
        &c.join("mail.password"),
        step,
    )?;
    if let Some(ca) = &layout.cfg.mail.ca_file {
        copy(ca, &c.join("mail-ca.pem"), step)?;
    }
    // Vault.
    let v = layout.creds("vault");
    mkdir(&v)?;
    put(&v.join("db-ca.pem"), &cas.vault_db.pem, step)?;
    for stem in crate::pg::service_logins(Cluster::Vault) {
        let name = crate::pg::role(Cluster::Vault, &cell, stem);
        issue_to(
            &cas.vault_db,
            &v,
            &format!("{stem}.pem"),
            &format!("{stem}.key"),
            &Leaf {
                cn: &name,
                ou: None,
                kind: CertKind::Client,
                dns: &[],
                ips: &[],
            },
            step,
        )?;
    }
    issue_to(
        &cas.cell,
        &v,
        "internal.pem",
        "internal.key",
        &Leaf {
            cn: "vault",
            ou: None,
            kind: CertKind::Server,
            dns: &["localhost"],
            ips: &LOOPBACK,
        },
        step,
    )?;
    put(&v.join("cell-ca.pem"), &cas.cell.pem, step)?;
    issue_to(
        &cas.tunnel,
        &v,
        "tunnel.pem",
        "tunnel.key",
        &Leaf {
            cn: VAULT_TUNNEL_NAME,
            ou: None,
            kind: CertKind::Server,
            dns: &[VAULT_TUNNEL_NAME],
            ips: &[],
        },
        step,
    )?;
    put(&v.join("tunnel-ca.pem"), &cas.tunnel.pem, step)?;
    let vault_host = layout.vault_host();
    origin(layout, cas, &v, &[&vault_host], step)?;
    issue_to(
        &cas.cell,
        &v,
        "witness.pem",
        "witness.key",
        &Leaf {
            cn: "vault-witness",
            ou: Some("vault-witness"),
            kind: CertKind::Client,
            dns: &[],
            ips: &[],
        },
        step,
    )?;
    put(&v.join("witness-ca.pem"), &cas.witness.pem, step)?;
    // Witness.
    let w = layout.creds("witness");
    mkdir(&w)?;
    issue_to(
        &cas.witness,
        &w,
        "server.pem",
        "server.key",
        &Leaf {
            cn: WITNESS_NAME,
            ou: None,
            kind: CertKind::Server,
            dns: &[WITNESS_NAME],
            ips: &LOOPBACK,
        },
        step,
    )?;
    put(&w.join("cell-ca.pem"), &cas.cell.pem, step)?;
    // Edge.
    let e = layout.creds("edge");
    mkdir(&e)?;
    issue_to(
        &cas.tunnel,
        &e,
        "tunnel.pem",
        "tunnel.key",
        &Leaf {
            cn: "edge",
            ou: None,
            kind: CertKind::Client,
            dns: &[],
            ips: &[],
        },
        step,
    )?;
    put(&e.join("tunnel-ca.pem"), &cas.tunnel.pem, step)?;
    // The database superusers renew with the rest.
    for (cl, ca) in [(Cluster::App, &cas.app_db), (Cluster::Vault, &cas.vault_db)] {
        if needs_issue(&layout.pg_dir(cl).join("super.pem")) && layout.pg_dir(cl).is_dir() {
            crate::pg::issue_super(layout, cl, ca).map_err(|e| Fail::Step(step, e.into()))?;
        }
        let tls = layout.pg_data(cl).join("tls");
        if tls.is_dir()
            && let Some(i) = issue_to(
                ca,
                &tls,
                "server.pem",
                "server.key",
                &Leaf {
                    cn: "127.0.0.1",
                    ou: Some(cl.kind()),
                    kind: CertKind::Server,
                    dns: &["localhost"],
                    ips: &LOOPBACK,
                },
                step,
            )?
        {
            state
                .set(
                    &format!("server-spki.{}", cl.name()),
                    &crate::pki::hex(&i.spki_sha256),
                )
                .map_err(io(step))?;
        }
    }
    if layout.cfg.services == Services::Systemd {
        for (dir, user) in [
            (&c, stack::CELL_USER),
            (&v, stack::VAULT_USER),
            (&w, stack::WITNESS_USER),
            (&e, stack::EDGE_USER),
        ] {
            own_path(layout, dir, user).map_err(step_err(step))?;
        }
    }
    facts(layout, state, cell)
}

/// The facts of the configuration files, from the files on disk.
///
/// # Errors
///
/// [`Fail::Step`] when a needed file is missing.
pub fn facts(layout: &Layout, state: &State, cell: [u8; 16]) -> Result<Facts, Fail> {
    let step = "configuration files";
    let spki = |c: Cluster| -> Result<[u8; 32], Fail> {
        state
            .get(&format!("server-spki.{}", c.name()))
            .and_then(crate::witness::unhex)
            .and_then(|b| b.try_into().ok())
            .ok_or(Fail::Step(step, Cause::Io))
    };
    let witness_ca = Ca::open_or_create(&layout.ca_dir(), "fstp-witness-ca")
        .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
    let public = layout.public_dir();
    let receipt = std::fs::read_to_string(public.join("receipt.pub")).ok();
    let ticket = std::fs::read_to_string(public.join("ticket.pub")).ok();
    Ok(Facts {
        cell,
        app_server_spki: spki(Cluster::App)?,
        vault_server_spki: spki(Cluster::Vault)?,
        witness_ca_spki: witness_ca.spki_sha256(),
        receipt_keys: receipt
            .map(|r| vec![r.trim().to_owned()])
            .unwrap_or_default(),
        ticket_key: ticket.map(|t| t.trim().to_owned()),
        assets: layout.assets().is_dir(),
    })
}

/// Writes every service's configuration file whose inputs exist.
///
/// # Errors
///
/// [`Fail::Step`] when a file does not write.
pub fn write_configs(layout: &Layout, f: &Facts) -> Result<(), Fail> {
    let step = "configuration files";
    let cell_dir = layout.creds("cell");
    if !f.receipt_keys.is_empty() {
        let mut lines = String::new();
        for k in &f.receipt_keys {
            lines.push_str(k);
            lines.push('\n');
        }
        put(
            &cell_dir.join("witness-receipt-keys"),
            lines.as_bytes(),
            step,
        )?;
    }
    let write = |name: &str, text: &str| -> Result<(), Fail> {
        let path = layout.config_file(name);
        if std::fs::read_to_string(&path).is_ok_and(|t| t == text) {
            return Ok(());
        }
        write_atomic(&path, text.as_bytes(), 0o644).map_err(io(step))
    };
    write("cell", &render::cell(layout, f))?;
    if let Some(v) = render::vault(layout, f) {
        write("vault", &v)?;
    }
    write("witness", &render::witness(layout))?;
    write("edge", &render::edge(layout))?;
    Ok(())
}

/// This host's own route.
#[must_use]
pub fn own_route(layout: &Layout, cell: [u8; 16]) -> Route {
    let pin = |p: PathBuf| {
        let pem = std::fs::read_to_string(p).unwrap_or_default();
        crate::route::pem_pin(&pem).unwrap_or_default()
    };
    Route {
        cell: crate::pki::hex(&cell),
        host: layout.cfg.domain.clone(),
        app: layout.cell_tunnel().to_string(),
        app_pin: pin(layout.creds("cell").join("tunnel.pem")),
        vault: layout.vault_origin().to_string(),
        vault_pin: pin(layout.creds("vault").join("tunnel.pem")),
    }
}

/// Runs `fstp-cell <args>` (or another service binary) as its user, with
/// its configuration, and requires status 0.
fn host_command(
    layout: &Layout,
    user: &str,
    binary: &str,
    env: (&str, PathBuf),
    args: &[&std::ffi::OsStr],
    step: &'static str,
) -> Result<(), Fail> {
    let mut c = stack::as_user(layout, user, &layout.bin(binary));
    c.env(env.0, env.1).args(args);
    match run_logged(&mut c, &Manager::new(layout).log()).map_err(|e| Fail::Step(step, e.into()))? {
        Some(0) => Ok(()),
        code => Err(Fail::Step(
            step,
            Cause::Run(crate::svc::RunFail::Exit(layout.bin(binary), code)),
        )),
    }
}

/// Runs every step of `setup`.
///
/// # Errors
///
/// [`Fail`] naming the step that stopped the run.
#[allow(
    clippy::too_many_lines,
    reason = "the steps read in order in one place"
)]
pub fn run(layout: &Layout) -> Result<(), Fail> {
    preflight(layout)?;
    let m = Manager::new(layout);
    std::fs::create_dir_all(layout.admin_dir()).map_err(io("state"))?;
    let mut state = State::load(&layout.admin_dir().join("state")).map_err(io("state"))?;
    let cell = cell_id(&mut state)?;
    out(&[
        Part::T("Setting up "),
        Part::Name(&layout.cfg.domain),
        Part::T(", cell "),
        Part::Name(&crate::pki::hex(&cell)),
    ]);

    say_done("operating system users", users(layout)?);

    // Key custody: the four fstp-keyd entries.
    say_done(
        "key custody (fstp-keyd)",
        keyd(layout, &m, &[Entry::Cell, Entry::CellKeys, Entry::Vault])?,
    );

    let cas = cas(layout)?;
    say_done("certificate authorities", true);

    // PostgreSQL.
    let mut created = false;
    for (c, ca) in [(Cluster::App, &cas.app_db), (Cluster::Vault, &cas.vault_db)] {
        // The server key digest, for `registered_servers`; `credentials`
        // records a renewed one.
        if let Some(spki) =
            crate::pg::init_cluster(layout, c, ca).map_err(|e| Fail::Step("databases", e.into()))?
        {
            state
                .set(
                    &format!("server-spki.{}", c.name()),
                    &crate::pki::hex(&spki),
                )
                .map_err(io("databases"))?;
            created = true;
        }
        crate::pg::write_agent(layout, c, ca, &cas.tunnel)
            .map_err(|e| Fail::Step("databases", e.into()))?;
        m.ensure(&crate::pg::service(layout, c))
            .map_err(|e| Fail::Step("databases", e.into()))?;
    }
    say_done("database clusters", created);

    credentials(layout, &mut state, &cas, cell)?;
    for c in Cluster::ALL {
        let creds = layout.creds(match c {
            Cluster::App => "cell",
            Cluster::Vault => "vault",
        });
        crate::pg::provision(layout, &mut state, c, &cell, &creds)
            .map_err(|e| Fail::Step("databases", e.into()))?;
    }
    if layout.cfg.services == Services::Systemd {
        own_path(layout, &layout.creds("cell"), stack::CELL_USER).map_err(step_err("databases"))?;
        own_path(layout, &layout.creds("vault"), stack::VAULT_USER)
            .map_err(step_err("databases"))?;
    }
    say_done("cell databases, roles and migrations", true);

    // The witness's custody and its receipt key.
    keyd(layout, &m, &[Entry::Witness]).map_err(|f| match f {
        Fail::Step(_, Cause::Run(crate::svc::RunFail::NotReady(_))) if layout.cfg.services == Services::Systemd => {
            Fail::Waits("fstp-keyd on main serves no ControlPlane socket for the witness (ADR-028 \"Witness custody\", a decision of Daniel)")
        }
        other => other,
    })?;
    let public = layout.public_dir();
    std::fs::create_dir_all(&public).map_err(io("witness keys"))?;
    write_atomic(
        &layout.config_file("witness"),
        render::witness(layout).as_bytes(),
        0o644,
    )
    .map_err(io("witness keys"))?;
    own_path(layout, &layout.creds("witness"), stack::WITNESS_USER)
        .map_err(step_err("witness keys"))?;
    let did = crate::witness::init_keys(layout, &public)
        .map_err(|e| Fail::Step("witness keys", e.into()))?;
    say_done("witness receipt key", did);

    // The cell's files and keys.
    let f = facts(layout, &state, cell)?;
    write_configs(layout, &f)?;
    let cell_key_file = layout.creds("cell").join("cell-keys.sealed");
    if cell_key_file.is_file() && public.join("ticket.pub").is_file() {
        say_done("cell keys", false);
    } else {
        let tmp = layout.admin_dir().join("cell-public");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(io("cell keys"))?;
        own_path(layout, &tmp, stack::CELL_USER).map_err(step_err("cell keys"))?;
        host_command(
            layout,
            stack::CELL_USER,
            "fstp-cell",
            ("FSTP_CELL_CONFIG", layout.config_file("cell")),
            &["init-keys".as_ref(), tmp.as_os_str()],
            "cell keys",
        )?;
        copy(
            &tmp.join("anchor.pub"),
            &public.join("anchor.pub"),
            "cell keys",
        )?;
        copy(
            &tmp.join("ticket.pub"),
            &public.join("ticket.pub"),
            "cell keys",
        )?;
        say_done("cell keys", true);
    }

    // The vault's file and keys.
    let f = facts(layout, &state, cell)?;
    write_configs(layout, &f)?;
    if public.join("vault-anchor.pub").is_file() {
        say_done("vault keys", false);
    } else {
        let tmp = layout.admin_dir().join("vault-public");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(io("vault keys"))?;
        own_path(layout, &tmp, stack::VAULT_USER).map_err(step_err("vault keys"))?;
        host_command(
            layout,
            stack::VAULT_USER,
            "fstp-vault",
            ("FSTP_VAULT_CONFIG", layout.config_file("vault")),
            &["init-keys".as_ref(), tmp.as_os_str()],
            "vault keys",
        )?;
        copy(
            &tmp.join("anchor.pub"),
            &public.join("vault-anchor.pub"),
            "vault keys",
        )?;
        say_done("vault keys", true);
    }

    // Register the cell with the witness, then start the witness.
    if state.done("witness-register") {
        say_done("witness registration", false);
    } else {
        let w = stack::witness(layout);
        m.stop(&w)
            .map_err(|e| Fail::Step("witness registration", e.into()))?;
        crate::witness::register(layout, &crate::pki::hex(&cell), &public)
            .map_err(|e| Fail::Step("witness registration", e.into()))?;
        state
            .mark("witness-register")
            .map_err(io("witness registration"))?;
        say_done("witness registration", true);
    }
    if layout.cfg.services == Services::Systemd {
        own_path(layout, &layout.witness_store(), stack::WITNESS_USER)
            .map_err(step_err("witness"))?;
        own_path(layout, &layout.creds("witness"), stack::WITNESS_USER)
            .map_err(step_err("witness"))?;
    }
    say_done(
        "witness running",
        m.ensure(&stack::witness(layout))
            .map_err(|e| Fail::Step("witness", e.into()))?,
    );
    say_done(
        "vault running",
        m.ensure(&stack::vault(layout))
            .map_err(|e| Fail::Step("vault", e.into()))?,
    );

    // The first admin, then the cell.
    if state.done("first-admin") {
        say_done("first admin invitation", false);
    } else {
        let token = layout.token_file();
        if token.exists() {
            return Err(Fail::Missing(
                token,
                "nothing: move the old first admin token file away",
            ));
        }
        m.stop(&stack::cell(layout))
            .map_err(|e| Fail::Step("first admin", e.into()))?;
        let tmp = layout.admin_dir().join("first-admin");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).map_err(io("first admin"))?;
        own_path(layout, &tmp, stack::CELL_USER).map_err(step_err("first admin"))?;
        let out_file = tmp.join("token");
        crate::cellcmd::first_admin(layout, &layout.cfg.operator_email, &out_file)?;
        let bytes = std::fs::read(&out_file).map_err(io("first admin"))?;
        write_atomic(&token, &bytes, 0o600).map_err(io("first admin"))?;
        let _ = std::fs::remove_dir_all(&tmp);
        state.mark("first-admin").map_err(io("first admin"))?;
        say_done("first admin invitation", true);
    }
    say_done(
        "cell running",
        m.ensure(&stack::cell(layout))
            .map_err(|e| Fail::Step("cell", e.into()))?,
    );

    // The edge and this cell's route.
    crate::route::ensure_own(layout, &m, cell)?;
    say_done(
        "edge running",
        m.ensure(&stack::edge(layout))
            .map_err(|e| Fail::Step("edge", e.into()))?,
    );

    // Backups.
    match crate::ops::setup_backups(layout, &m, &mut state, &cas)? {
        Some(did) => say_done("backups", did),
        None => out(&[Part::T(
            "  waiting  backups: add \"backup\" to the configuration file to turn them on",
        )]),
    }
    m.timer(
        "fstp-admin-renew",
        &layout.bin("fstp-admin"),
        "renew",
        "daily",
    )
    .map_err(|e| Fail::Step("timers", e.into()))?;

    out(&[Part::T("")]);
    out(&[Part::T("Setup is complete.")]);
    if !state.done("first-admin-delivered") {
        out(&[
            Part::T("The first admin's invitation is in "),
            Part::P(&layout.token_file()),
            Part::T("."),
        ]);
        out(&[Part::T(
            "Hand each of its two lines to the first admin through a different channel, then delete the file.",
        )]);
        out(&[
            Part::T("They open https://"),
            Part::Name(&layout.cfg.domain),
            Part::T("/auth/invite#<line 1><line 2> and enrol a passkey."),
        ]);
    }
    out(&[
        Part::T("Copy the four passphrases in "),
        Part::P(&layout.etc("keyd")),
        Part::T(" off this host once, for example into a password manager."),
    ]);
    out(&[Part::T(
        "Run fstp-admin status at any time to see what to do next.",
    )]);
    Ok(())
}
