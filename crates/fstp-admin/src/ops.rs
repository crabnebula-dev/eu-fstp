//! The day-to-day commands: backups, restore, the off-host key copy,
//! certificate renewal, start and stop (ADR-028).

use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_pki::cert::CertKind;

use crate::config::Services;
use crate::fail::{Cause, Fail};
use crate::layout::{Cluster, Entry, Layout};
use crate::pki::{Leaf, random_hex, write_pair};
use crate::say::{Part, out};
use crate::setup::Cas;
use crate::stack;
use crate::state::{State, write_atomic};
use crate::svc::{Manager, RunFail, run_logged, run_ok};

/// The replication role of every cluster (ADR-005, `HBA_REPLICATION_LINE`).
pub const REPL_ROLE: &str = "fstp_repl";

fn io(step: &'static str) -> impl Fn(std::io::Error) -> Fail {
    move |_| Fail::Step(step, Cause::Io)
}

fn backup_env(layout: &Layout, c: Cluster) -> (&'static str, PathBuf) {
    (
        "FSTP_BACKUP_CONFIG",
        layout.config_file(&format!("backup-{}", c.name())),
    )
}

/// Sets up the backup agent of each cluster when the configuration names
/// an object store. `None` when it names none.
///
/// # Errors
///
/// [`Fail::Step`] naming the part that failed.
pub fn setup_backups(
    layout: &Layout,
    m: &Manager,
    state: &mut State,
    cas: &Cas,
) -> Result<Option<bool>, Fail> {
    let Some(b) = layout.cfg.backup.clone() else {
        return Ok(None);
    };
    let step = "backups";
    let mut did = false;
    for (c, ca) in [(Cluster::App, &cas.app_db), (Cluster::Vault, &cas.vault_db)] {
        let dir = layout.creds(&format!("backup-{}", c.name()));
        std::fs::create_dir_all(&dir).map_err(io(step))?;
        std::fs::create_dir_all(layout.backup_state(c)).map_err(io(step))?;
        for (from, to) in [
            (&b.access_key_file, "s3-access-key-id"),
            (&b.secret_key_file, "s3-secret-access-key"),
        ] {
            let bytes = std::fs::read(from).map_err(io(step))?;
            write_atomic(&dir.join(to), &bytes, 0o640).map_err(io(step))?;
        }
        write_atomic(&dir.join("db-ca.pem"), &ca.pem, 0o600).map_err(io(step))?;
        if crate::pki::needs_issue(&dir.join("repl.pem")) {
            let i = ca
                .issue(&Leaf {
                    cn: REPL_ROLE,
                    ou: None,
                    kind: CertKind::Client,
                    dns: &[],
                    ips: &[],
                })
                .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
            write_pair(&dir, "repl.pem", "repl.key", &i)
                .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
        }
        let password = match std::fs::read_to_string(dir.join("repl.password")) {
            Ok(p) if !p.trim().is_empty() => p.trim().to_owned(),
            _ => {
                let p = random_hex(24).map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
                write_atomic(&dir.join("repl.password"), p.as_bytes(), 0o600).map_err(io(step))?;
                p
            }
        };
        crate::pg::psql(
            layout,
            c,
            "postgres",
            &format!(
                "DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{REPL_ROLE}') THEN \
                 CREATE ROLE {REPL_ROLE} LOGIN REPLICATION PASSWORD '{password}'; \
                 ELSE ALTER ROLE {REPL_ROLE} LOGIN REPLICATION PASSWORD '{password}'; END IF; END$$;\n"
            ),
            "the login roles",
        )
        .map_err(|e| Fail::Step(step, e.into()))?;
        let id = match state.get(&format!("cluster.{}", c.name())) {
            Some(id) => id.to_owned(),
            None => return Err(Fail::Step(step, Cause::Io)),
        };
        if let Some(text) = crate::render::backup(layout, c, &id) {
            write_atomic(&backup_env(layout, c).1, text.as_bytes(), 0o644).map_err(io(step))?;
        }
        if layout.cfg.services == Services::Systemd {
            // archive_command runs as postgres: it reads the object store
            // keys and the key file, never the replication login.
            let mut g = Command::new("chown");
            g.arg("-R").arg("root:postgres").arg(&dir);
            run_ok(&mut g, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            let mut d = Command::new("chmod");
            d.arg("0750").arg(&dir);
            run_ok(&mut d, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
        }
        if !dir.join("cluster-backup.key").is_file() {
            let mut cmd = Command::new(layout.bin("fstp-backup"));
            let (k, v) = backup_env(layout, c);
            cmd.env(k, v).arg("init-keys");
            run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            if layout.cfg.services == Services::Systemd {
                let mut g = Command::new("chmod");
                g.arg("0640").arg(dir.join("cluster-backup.key"));
                run_ok(&mut g, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            }
            did = true;
        }
        if crate::pg::enable_archive(layout, c, &backup_env(layout, c).1)
            .map_err(|e| Fail::Step(step, e.into()))?
        {
            let s = crate::pg::service(layout, c);
            m.stop(&s).map_err(|e| Fail::Step(step, e.into()))?;
            m.ensure(&s).map_err(|e| Fail::Step(step, e.into()))?;
            did = true;
        }
    }
    m.timer(
        "fstp-admin-backup",
        &layout.bin("fstp-admin"),
        "backup",
        "*-*-* 02:30:00",
    )
    .map_err(|e| Fail::Step(step, e.into()))?;
    Ok(Some(did))
}

/// `fstp-admin backup`: a base backup of both clusters now.
///
/// # Errors
///
/// [`Fail::Waits`] without an object store, [`Fail::Step`] when a backup
/// fails.
pub fn backup(layout: &Layout) -> Result<(), Fail> {
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "backups need \"backup\" in the configuration file, then fstp-admin setup",
        ));
    }
    let m = Manager::new(layout);
    for c in Cluster::ALL {
        let mut cmd = Command::new(layout.bin("fstp-backup"));
        let (k, v) = backup_env(layout, c);
        cmd.env(k, v).arg("base-backup");
        run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step("backup", e.into()))?;
        out(&[
            Part::T("  done     base backup of the "),
            Part::T(c.name()),
            Part::T(" database"),
        ]);
    }
    Ok(())
}

/// The time of the newest base backup of `c`, from the agent's index.
#[must_use]
pub fn last_backup(layout: &Layout, c: Cluster) -> Option<i64> {
    let text = std::fs::read_to_string(layout.backup_state(c).join("base-backups.index")).ok()?;
    let line = text.lines().last()?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// `fstp-admin restore`: both clusters from their newest base backups,
/// with the services stopped. The old data directories stay beside the
/// new ones.
///
/// # Errors
///
/// [`Fail::Step`] when a part fails. The services start again either way.
pub fn restore(layout: &Layout) -> Result<(), Fail> {
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "restore needs \"backup\" in the configuration file",
        ));
    }
    let m = Manager::new(layout);
    for s in [
        stack::edge(layout),
        stack::cell(layout),
        stack::vault(layout),
    ] {
        m.stop(&s).map_err(|e| Fail::Step("restore", e.into()))?;
    }
    let stamp = crate::pki::now();
    let mut result = Ok(());
    for c in Cluster::ALL {
        let pg = crate::pg::service(layout, c);
        m.stop(&pg).map_err(|e| Fail::Step("restore", e.into()))?;
        let data = layout.pg_data(c);
        let fresh = data.with_file_name(format!("{}.restored-{stamp}", c.name()));
        let mut cmd = Command::new(layout.bin("fstp-backup"));
        let (k, v) = backup_env(layout, c);
        cmd.env(k, v).arg("restore").arg(&fresh);
        if let Err(e) = run_ok(&mut cmd, &m.log()) {
            result = Err(Fail::Step("restore", e.into()));
            break;
        }
        let old = data.with_file_name(format!("{}.before-restore-{stamp}", c.name()));
        std::fs::rename(&data, &old).map_err(io("restore"))?;
        std::fs::rename(&fresh, &data).map_err(io("restore"))?;
        if layout.cfg.services == Services::Systemd {
            let mut g = Command::new("chown");
            g.arg("-R").arg("postgres:postgres").arg(&data);
            run_ok(&mut g, &m.log()).map_err(|e| Fail::Step("restore", e.into()))?;
        }
        out(&[
            Part::T("  done     restored the "),
            Part::T(c.name()),
            Part::T(" database; the old one is in "),
            Part::P(&old),
        ]);
    }
    start(layout)?;
    result
}

/// The copy id in a key copy's clear header: bytes 26 to 41 (ADR-004
/// record of lane L16).
#[must_use]
pub fn copy_id(bytes: &[u8]) -> Option<String> {
    if bytes.get(0..4) != Some(b"FKX1".as_slice()) {
        return None;
    }
    bytes.get(26..42).map(crate::pki::hex)
}

/// `fstp-admin backup-keys <dest>`: one passphrase-sealed copy per custody
/// entry, each with its copy id in `<entry>.fkx.id`, and the sealed key
/// files beside them (ADR-028 "Simple key backup", lane L16). Each entry
/// stops for its copy and starts again.
///
/// # Errors
///
/// [`Fail::Waits`] in direct mode or when `fstp-keyd` has no `export` yet.
pub fn backup_keys(layout: &Layout, state: &mut State, dest: &Path) -> Result<(), Fail> {
    if layout.cfg.custody_simulator.is_some() {
        return Err(Fail::Waits(
            "the custody simulator keeps its keys in memory, so there is nothing to copy",
        ));
    }
    let step = "key copy";
    std::fs::create_dir_all(dest).map_err(io(step))?;
    let m = Manager::new(layout);
    for e in Entry::ALL {
        let file = dest.join(format!("{}.fkx", e.name()));
        if file.exists() {
            return Err(Fail::Missing(
                file,
                "nothing: pick an empty directory for the copy",
            ));
        }
        let services = stack::keyd(layout, e);
        for s in &services {
            m.stop(s).map_err(|c| Fail::Step(step, c.into()))?;
        }
        let creds = layout.admin_dir().join("keyd-credential");
        let _ = std::fs::remove_dir_all(&creds);
        let pass = std::fs::read(layout.keyd_passphrase(e)).map_err(io(step));
        let r = pass.and_then(|p| {
            write_atomic(&creds.join(fstp_keyd_credential()), &p, 0o600).map_err(io(step))?;
            let mut c = Command::new(layout.bin("fstp-keyd"));
            c.env("CREDENTIALS_DIRECTORY", &creds)
                .arg("export")
                .arg(layout.keyd_volume(e))
                .arg(&file);
            run_logged(&mut c, &m.log()).map_err(|e| Fail::Step(step, e.into()))
        });
        let _ = std::fs::remove_dir_all(&creds);
        for s in &services {
            m.ensure(s).map_err(|c| Fail::Step(step, c.into()))?;
        }
        match r? {
            Some(0) => {}
            Some(2) => {
                return Err(Fail::Waits(
                    "the installed fstp-keyd has no export command yet (lane L16)",
                ));
            }
            code => {
                return Err(Fail::Step(
                    step,
                    Cause::Run(RunFail::Exit(layout.bin("fstp-keyd"), code)),
                ));
            }
        }
        let bytes = std::fs::read(&file).map_err(io(step))?;
        let id = copy_id(&bytes).ok_or(Fail::Step(step, Cause::Io))?;
        write_atomic(
            &dest.join(format!("{}.fkx.id", e.name())),
            format!("{id}\n").as_bytes(),
            0o600,
        )
        .map_err(io(step))?;
        out(&[
            Part::T("  done     copy of the "),
            Part::T(e.name()),
            Part::T(" entry, id "),
            Part::Name(&id),
        ]);
    }
    for (from, to) in [
        (
            layout.creds("cell").join("cell-keys.sealed"),
            "cell-keys.sealed",
        ),
        (
            layout.creds("witness").join("receipt.key"),
            "witness-receipt.key",
        ),
        (
            layout.creds("backup-app").join("cluster-backup.key"),
            "backup-app.key",
        ),
        (
            layout.creds("backup-vault").join("cluster-backup.key"),
            "backup-vault.key",
        ),
    ] {
        if let Ok(b) = std::fs::read(&from) {
            write_atomic(&dest.join(to), &b, 0o600).map_err(io(step))?;
        }
    }
    state.mark("keys-copied").map_err(io(step))?;
    state
        .set(
            crate::status::KEYS_COPIED_AT,
            &crate::pki::now().to_string(),
        )
        .map_err(io(step))?;
    out(&[
        Part::T("The copy is in "),
        Part::P(dest),
        Part::T(". It opens only with the passphrases in "),
        Part::P(&layout.etc("keyd")),
        Part::T(": keep those apart from the copy."),
    ]);
    Ok(())
}

fn fstp_keyd_credential() -> &'static str {
    "fstp-keyd-passphrase"
}

fn sidecars(layout: &Layout) -> String {
    let mut out = String::new();
    for dir in ["cell", "vault", "witness", "edge"] {
        if let Ok(rd) = std::fs::read_dir(layout.creds(dir)) {
            let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            names.sort();
            for p in names {
                if p.extension().is_some_and(|x| x == "expires") {
                    out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                }
            }
        }
    }
    out
}

/// `fstp-admin renew`: issues again every certificate near its end,
/// restarts the services that read them, and updates the host's route
/// with the new pins (ADR-028 "Certificates").
///
/// # Errors
///
/// [`Fail::Step`] naming the part that failed.
pub fn renew(layout: &Layout) -> Result<(), Fail> {
    let mut state = State::load(&layout.admin_dir().join("state")).map_err(io("renew"))?;
    let cell = crate::setup::cell_id(&mut state)?;
    let cas = crate::setup::cas(layout)?;
    let before = sidecars(layout);
    let spki_before = (
        state.get("server-spki.app").map(str::to_owned),
        state.get("server-spki.vault").map(str::to_owned),
    );
    let facts = crate::setup::credentials(layout, &mut state, &cas, cell)?;
    crate::setup::write_configs(layout, &facts)?;
    let spki_after = (
        state.get("server-spki.app").map(str::to_owned),
        state.get("server-spki.vault").map(str::to_owned),
    );
    let m = Manager::new(layout);
    if before == sidecars(layout) && spki_before == spki_after {
        out(&[Part::T("  skipped  certificates (none near its end)")]);
    } else {
        let mut services = Vec::new();
        if spki_before != spki_after {
            services.extend(Cluster::ALL.iter().map(|c| crate::pg::service(layout, *c)));
        }
        services.extend([
            stack::witness(layout),
            stack::vault(layout),
            stack::cell(layout),
        ]);
        if crate::route::ROUTE_FEED {
            services.push(stack::control(layout));
        }
        services.push(stack::edge(layout));
        for s in services.iter().rev() {
            m.stop(s).map_err(|e| Fail::Step("renew", e.into()))?;
        }
        for s in &services {
            m.ensure(s).map_err(|e| Fail::Step("renew", e.into()))?;
        }
        out(&[Part::T(
            "  done     certificates renewed and services restarted",
        )]);
    }
    crate::route::ensure_own(layout, &m, cell)?;
    Ok(())
}

/// `fstp-admin start`: every service in order.
///
/// # Errors
///
/// [`Fail::Step`] naming the service that did not start.
pub fn start(layout: &Layout) -> Result<(), Fail> {
    let m = Manager::new(layout);
    for s in stack::all(layout) {
        m.ensure(&s).map_err(|e| Fail::Step("start", e.into()))?;
    }
    Ok(())
}

/// `fstp-admin stop`: every service in reverse order.
///
/// # Errors
///
/// [`Fail::Step`] naming the service that did not stop.
pub fn stop(layout: &Layout) -> Result<(), Fail> {
    let m = Manager::new(layout);
    for s in stack::all(layout).iter().rev() {
        m.stop(s).map_err(|e| Fail::Step("stop", e.into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-004 record of lane L16: the copy id stands in bytes 26 to 41 of
    /// the clear header.
    #[test]
    fn adr004_l16_copy_id_is_read_from_the_header() {
        let mut h = b"FKX1".to_vec();
        h.extend_from_slice(&[0u8; 22]);
        h.extend_from_slice(&[0xab; 16]);
        h.extend_from_slice(&[0u8; 8]);
        assert_eq!(copy_id(&h).as_deref(), Some("ab".repeat(16).as_str()));
        assert_eq!(copy_id(b"XXXX"), None);
    }
}
