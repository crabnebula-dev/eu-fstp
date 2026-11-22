//! Lane L19 (ADR-028): `fstp-admin setup` stands a host up from one
//! configuration file, against local PostgreSQL 16 and the real
//! binaries, in a temporary root; `status` reports it; a second `setup`
//! skips what is done; `route add` applies a route.
//!
//! The host runs in `direct` mode with the custody simulator in place of
//! `fstp-keyd`, the test seam of every end-to-end test of the stack
//! (ADR-028 "Custody simulator"). Everything else is the production
//! binary: `fstp-pgagent run-job` for the provisioning jobs,
//! `fstp-witness init-keys` and `register`, `fstp-cell init-keys` and
//! `first-admin`, `fstp-vault init-keys`, and the cell, vault, witness
//! and edge services. Every value is synthetic.
//!
//! The consistency checks at the top tie the constants `fstp-admin`
//! carries without linking the service crates (ADR-028 "Layering") to
//! their sources.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fstp_control::pg::{CellDatabase, render_hba, roles_of};

/// ADR-028 "Database provisioning", I-82: the first `pg_hba.conf` of a
/// cluster is exactly what `render_hba` gives for no cell.
#[test]
fn i82_l19_initial_hba_is_the_renderers() {
    for db in [CellDatabase::App, CellDatabase::Vault] {
        assert_eq!(render_hba(db, &[]).unwrap(), fstp_admin::pg::INITIAL_HBA);
    }
}

/// ADR-028 "Layering", ADR-011: the role suffixes `fstp-admin` creates are
/// the role plan's, in its order.
#[test]
fn adr011_l19_role_suffixes_are_the_plans() {
    use fstp_admin::layout::Cluster;
    for (c, db) in [
        (Cluster::App, CellDatabase::App),
        (Cluster::Vault, CellDatabase::Vault),
    ] {
        let plan: Vec<&str> = roles_of(db).iter().map(|r| r.suffix()).collect();
        assert_eq!(plan, fstp_admin::pg::role_suffixes(c));
    }
}

/// ADR-028 "Migrations": the installed migration files are the sets the
/// cell and the vault compile in, version, name and text alike.
#[test]
fn adr028_l19_migration_files_are_the_compiled_sets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for (dir, set) in [
        ("fstp-pgstore/migrations/app", fstp_pgstore::MIGRATIONS),
        ("fstp-vault/migrations/vault", fstp_vault::MIGRATIONS),
    ] {
        let files = fstp_admin::pg::migration_files(&root.join(dir)).unwrap();
        assert_eq!(files.len(), set.len(), "{dir}");
        for ((v, path), m) in files.iter().zip(set) {
            assert_eq!(*v, m.version, "{dir}");
            let name = path.file_stem().unwrap().to_str().unwrap();
            assert_eq!(name.split_once('_').unwrap().1, m.name, "{dir}");
            assert_eq!(std::fs::read_to_string(path).unwrap(), m.sql, "{dir}");
        }
    }
}

/// R-NF-09: the OUs of the internal client certificates `fstp-admin`
/// issues are the ones the vault and the witness admit.
#[test]
fn r_nf_09_l19_client_ous_are_the_services() {
    assert_eq!(fstp_vault::service::CELL_APP_OU, "cell-app");
    assert_eq!(fstp_witness::peer::OU_CELL_WITNESS, "cell-witness");
    assert_eq!(fstp_witness::peer::OU_VAULT_WITNESS, "vault-witness");
}

fn bin(name: &str) -> PathBuf {
    fstp_celltest::world_host::bin_path(name).unwrap_or_else(|e| {
        panic!(
            "{e:?}: build it first: cargo build -p fstp-admin -p fstp-cell -p fstp-vault \
             -p fstp-witness -p fstp-edge --bins, -p fstp-control --bin fstp-pgagent and \
             -p fstp-celltest --bin fstp-custody-sim"
        )
    })
}

fn pg_bin() -> PathBuf {
    if let Some(d) = std::env::var_os("FSTP_PG_BIN") {
        return PathBuf::from(d);
    }
    let out = Command::new("pg_config").arg("--bindir").output().unwrap();
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

/// A base port with the ten ports above it free, and a public port.
fn ports() -> (u16, u16) {
    for _ in 0..200 {
        let r = fstp_crypto::random_array::<2>().unwrap();
        let base = 20_000 + u16::from_be_bytes(r) % 20_000;
        let held: Vec<_> = (0..11u16)
            .map(|i| TcpListener::bind((Ipv4Addr::LOCALHOST, base + i)))
            .collect();
        if held.iter().all(Result::is_ok) {
            return (base, base + 10);
        }
    }
    panic!("no free port range");
}

struct Host {
    root: PathBuf,
    config: PathBuf,
}

impl Host {
    fn admin(&self, args: &[&str]) -> Output {
        Command::new(bin("fstp-admin"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("FSTP_DEPLOYMENT_MODE", "development")
            .output()
            .unwrap()
    }

    fn logs(&self) -> String {
        let mut s = String::new();
        if let Ok(rd) = std::fs::read_dir(self.root.join("state/admin/logs")) {
            for e in rd.flatten() {
                let text = std::fs::read_to_string(e.path()).unwrap_or_default();
                let tail: Vec<&str> = text.lines().rev().take(40).collect();
                s.push_str(&format!("--- {}\n", e.path().display()));
                for l in tail.into_iter().rev() {
                    s.push_str(l);
                    s.push('\n');
                }
            }
        }
        s
    }

    fn expect_ok(&self, args: &[&str]) -> String {
        let out = self.admin(args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "fstp-admin {args:?} exited {:?}:\n{text}\n{}",
            out.status.code(),
            self.logs()
        );
        text
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.admin(&["stop"]);
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn link(from: &Path, to: &Path) {
    std::os::unix::fs::symlink(from, to).unwrap();
}

fn host() -> Host {
    let tag = fstp_crypto::random_array::<4>().unwrap();
    // A Unix socket path must stay short, so the root sits under /tmp.
    let root = PathBuf::from(format!("/tmp/fstp-l19-{}", fstp_admin::pki::hex(&tag)));
    let bins = root.join("bin");
    std::fs::create_dir_all(&bins).unwrap();
    for name in [
        "fstp-admin",
        "fstp-cell",
        "fstp-vault",
        "fstp-witness",
        "fstp-edge",
        "fstp-pgagent",
        "fstp-control",
    ] {
        link(&bin(name), &bins.join(name));
    }
    let share = root.join("share/migrations");
    std::fs::create_dir_all(&share).unwrap();
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap();
    link(
        &crates.join("fstp-pgstore/migrations/app"),
        &share.join("app"),
    );
    link(
        &crates.join("fstp-vault/migrations/vault"),
        &share.join("vault"),
    );
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("mail.password"), "synthetic-relay-password\n").unwrap();
    let (base, public) = ports();
    let config = etc.join("fstp.json");
    let text = format!(
        r#"{{
  "domain": "grants.l19.example.eu",
  "operator_email": "admin@l19.example.eu",
  "mail": {{"relay": "smtp.l19.example.eu", "username": "cell"}},
  "paths": {{
    "bin": "{bin}",
    "share": "{share}",
    "etc": "{etc}",
    "state": "{state}",
    "pg_bin": "{pg}",
    "token_dir": "{tokens}"
  }},
  "ports": {{"public": {public}, "base": {base}}},
  "services": "direct",
  "custody_simulator": "{sim}"
}}
"#,
        bin = bins.display(),
        share = root.join("share").display(),
        etc = etc.display(),
        state = root.join("state").display(),
        pg = pg_bin().display(),
        tokens = root.join("tokens").display(),
        sim = bin("fstp-custody-sim").display(),
    );
    std::fs::write(&config, text).unwrap();
    Host { root, config }
}

/// ADR-028 "One operator command", "Setup is resumable", "Status" and
/// "Plain route changes"; R-NF-05 (no default credentials), R-NF-08
/// (separate custody entries), R-NF-09 (verified TLS between parts),
/// I-82 and I-83 (placement and roles).
#[test]
fn adr028_l19_setup_status_and_route_add_on_a_fresh_host() {
    let h = host();
    let first = h.expect_ok(&["setup"]);
    assert!(first.contains("Setup is complete."), "{first}");
    assert!(
        h.root.join("tokens/fstp-first-admin.token").is_file(),
        "no first admin token"
    );

    // Every service answers.
    let status = h.admin(&["status"]);
    let text = String::from_utf8_lossy(&status.stdout).into_owned();
    assert_eq!(status.status.code(), Some(0), "{text}\n{}", h.logs());
    assert!(text.contains("Next: "), "{text}");
    assert!(
        !text.contains("STOPPED") && !text.contains("UNHEALTHY"),
        "{text}"
    );
    assert!(text.contains("route      current"), "{text}");
    assert!(first.contains("done     tenant provisioning"), "{first}");

    // ADR-028 "Verify the first admins", ADR-008: status names the first
    // admin's account in the form the vault command takes, and `verify`
    // records the in-person check through `fstp-vault verify-first-admin`.
    let account = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("admin 1"))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no admin account in status:\n{text}"))
        .to_owned();
    assert_eq!(account.len(), 36, "{account}");
    let id = h.root.join("admin-1.json");
    std::fs::write(
        &id,
        r#"{"method":"manual","document_type":"passport","checks":["document_authentic","document_valid","photo_match"],"identity":{"family_names":"Synthetic","given_names":"Ada","birth_date":"1990-01-31","issuing_state":"DEU"}}"#,
    )
    .unwrap();
    h.expect_ok(&["verify", &account, id.to_str().unwrap()]);
    let after = String::from_utf8_lossy(&h.admin(&["status"]).stdout).into_owned();
    assert!(
        after.contains(&format!("admin 1    {account}  verified")),
        "{after}"
    );

    // A second run skips what is done and changes nothing.
    let second = h.expect_ok(&["setup"]);
    assert!(second.contains("skipped  cell keys"), "{second}");
    assert!(second.contains("skipped  edge running"), "{second}");
    assert!(second.contains("skipped  witness registration"), "{second}");

    // The host's own route is served, and a manual route applies.
    let list = h.expect_ok(&["route", "list"]);
    assert!(list.contains("grants.l19.example.eu"), "{list}");
    let route = h.root.join("other-route.json");
    std::fs::write(
        &route,
        format!(
            r#"{{"routes":[{{"cell":"{cell}","host":"other.l19.example.eu",
            "app":{{"address":"127.0.0.1:9","server_name":"cell.tunnel.fstp.internal","cert_sha256":"{a}"}},
            "vault":{{"address":"127.0.0.1:10","server_name":"vault.tunnel.fstp.internal","cert_sha256":"{v}"}}}}]}}"#,
            cell = "ab".repeat(16),
            a = "01".repeat(32),
            v = "02".repeat(32),
        ),
    )
    .unwrap();
    h.expect_ok(&["route", "add", route.to_str().unwrap()]);
    let list = h.expect_ok(&["route", "list"]);
    assert!(list.contains("other.l19.example.eu"), "{list}");
    assert!(list.contains("grants.l19.example.eu"), "{list}");
    let log = std::fs::read_to_string(h.root.join("state/admin/routes.log")).unwrap();
    assert!(log.contains(" add other.l19.example.eu "), "{log}");

    // The edge still serves after the change.
    let status = h.admin(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&status.stdout)
    );
}
