//! The services of a host, in start order (ADR-028 "Services" and
//! "Custody entries").

use std::path::PathBuf;
use std::process::Command;

use crate::config::Services;
use crate::layout::{Cluster, Entry, Layout};
use crate::svc::{Ready, Service};

/// The OS user of a service in systemd mode.
pub const CELL_USER: &str = "fstp-cell";
/// The vault's OS user.
pub const VAULT_USER: &str = "fstp-vault";
/// The witness's OS user.
pub const WITNESS_USER: &str = "fstp-witness";
/// The edge's OS user.
pub const EDGE_USER: &str = "fstp-edge";
/// The custody OS user.
pub const KEYD_USER: &str = "fstp-keyd";

/// Every OS user `setup` creates in systemd mode.
pub const USERS: [&str; 5] = [CELL_USER, VAULT_USER, WITNESS_USER, EDGE_USER, KEYD_USER];

/// The client user of a custody socket role, if it has one.
#[must_use]
pub fn role_user(role: &str) -> Option<&'static str> {
    match role {
        "cell" => Some(CELL_USER),
        "vault" => Some(VAULT_USER),
        "control" => Some(WITNESS_USER),
        _ => None,
    }
}

/// `program` run as `user` in systemd mode, and as this user otherwise.
#[must_use]
pub fn as_user(layout: &Layout, user: &str, program: &std::path::Path) -> Command {
    match layout.cfg.services {
        Services::Systemd => {
            let mut c = Command::new("runuser");
            c.arg("-u").arg(user).arg("--").arg(program);
            c
        }
        Services::Direct => Command::new(program),
    }
}

/// The group id of `user`, from `id -g`.
#[must_use]
pub fn gid_of(user: &str) -> Option<u32> {
    let out = Command::new("id").arg("-g").arg(user).output().ok()?;
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

/// The custody services of `e`: one `fstp-keyd` in systemd mode, or one
/// custody simulator per socket in direct mode.
#[must_use]
pub fn keyd(layout: &Layout, e: Entry) -> Vec<Service> {
    match (&layout.cfg.services, &layout.cfg.custody_simulator) {
        (Services::Direct, Some(sim)) => e
            .roles()
            .iter()
            .map(|role| Service {
                name: format!("fstp-keyd-{}-{role}", e.name()),
                what: "custody simulator (development only)",
                program: sim.clone(),
                args: vec![
                    "--serve".into(),
                    layout.keyd_socket(e, role).into_os_string(),
                ],
                env: Vec::new(),
                user: None,
                unit_lines: Vec::new(),
                direct_credentials: None,
                ready: Ready::Socket(layout.keyd_socket(e, role)),
                after: Vec::new(),
            })
            .collect(),
        _ => {
            let mut env: Vec<(String, std::ffi::OsString)> = Vec::new();
            let mut groups = Vec::new();
            for role in e.roles() {
                if let Some(user) = role_user(role) {
                    if let Some(gid) = gid_of(user) {
                        env.push((
                            format!("FSTP_KEYD_GROUP_{}", role.to_ascii_uppercase()),
                            gid.to_string().into(),
                        ));
                    }
                    groups.push(user);
                }
            }
            let volume = layout.keyd_volume(e);
            let run = layout.keyd_socket(e, "console");
            let run_dir = run.parent().map(PathBuf::from).unwrap_or_default();
            let mut unit_lines = vec![
                format!("StateDirectory=fstp-keyd-{}", e.name()),
                format!("RuntimeDirectory=fstp-keyd-{}", e.name()),
                "RuntimeDirectoryPreserve=yes".into(),
                format!(
                    "BindPaths={}:/var/lib/fstp-keyd {}:/run/fstp-keyd",
                    volume.display(),
                    run_dir.display()
                ),
                format!(
                    "LoadCredential=fstp-keyd-passphrase:{}",
                    layout.keyd_passphrase(e).display()
                ),
            ];
            if !groups.is_empty() {
                unit_lines.push(format!("SupplementaryGroups={}", groups.join(" ")));
            }
            let first_role = e.roles().first().copied().unwrap_or("console");
            vec![Service {
                name: format!("fstp-keyd-{}", e.name()),
                what: "key custody",
                program: layout.bin("fstp-keyd"),
                args: Vec::new(),
                env,
                user: Some(KEYD_USER.into()),
                unit_lines,
                direct_credentials: None,
                ready: Ready::Socket(layout.keyd_socket(e, first_role)),
                after: Vec::new(),
            }]
        }
    }
}

fn keyd_names(layout: &Layout, entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .flat_map(|e| keyd(layout, *e))
        .map(|s| s.name)
        .collect()
}

/// The witness service.
#[must_use]
pub fn witness(layout: &Layout) -> Service {
    Service {
        name: "fstp-witness".into(),
        what: "witness",
        program: layout.bin("fstp-witness"),
        args: Vec::new(),
        env: vec![(
            "FSTP_WITNESS_CONFIG".into(),
            layout.config_file("witness").into_os_string(),
        )],
        user: Some(WITNESS_USER.into()),
        unit_lines: Vec::new(),
        direct_credentials: None,
        ready: Ready::Tcp(layout.witness()),
        after: keyd_names(layout, &[Entry::Witness]),
    }
}

/// The vault service.
#[must_use]
pub fn vault(layout: &Layout) -> Service {
    let mut after = keyd_names(layout, &[Entry::Vault]);
    after.push("fstp-witness".into());
    after.push(crate::pg::service(layout, Cluster::Vault).name);
    Service {
        name: "fstp-vault".into(),
        what: "identity vault",
        program: layout.bin("fstp-vault"),
        args: Vec::new(),
        env: vec![(
            "FSTP_VAULT_CONFIG".into(),
            layout.config_file("vault").into_os_string(),
        )],
        user: Some(VAULT_USER.into()),
        unit_lines: Vec::new(),
        direct_credentials: None,
        ready: Ready::Tcp(layout.vault_internal()),
        after,
    }
}

/// The cell service.
#[must_use]
pub fn cell(layout: &Layout) -> Service {
    let mut after = keyd_names(layout, &[Entry::Cell, Entry::CellKeys]);
    after.push("fstp-vault".into());
    after.push(crate::pg::service(layout, Cluster::App).name);
    Service {
        name: "fstp-cell".into(),
        what: "platform cell",
        program: layout.bin("fstp-cell"),
        args: Vec::new(),
        env: vec![(
            "FSTP_CELL_CONFIG".into(),
            layout.config_file("cell").into_os_string(),
        )],
        user: Some(CELL_USER.into()),
        unit_lines: Vec::new(),
        direct_credentials: None,
        ready: Ready::Health(layout.cell_health()),
        after,
    }
}

/// The edge service.
#[must_use]
pub fn edge(layout: &Layout) -> Service {
    Service {
        name: "fstp-edge".into(),
        what: "public edge",
        program: layout.bin("fstp-edge"),
        args: Vec::new(),
        env: vec![(
            "FSTP_EDGE_CONFIG".into(),
            layout.config_file("edge").into_os_string(),
        )],
        user: Some(EDGE_USER.into()),
        unit_lines: vec!["AmbientCapabilities=CAP_NET_BIND_SERVICE".into()],
        direct_credentials: None,
        ready: Ready::Tcp(layout.edge_public()),
        after: vec!["fstp-cell".into()],
    }
}

/// Every long-running service of the host, in start order.
#[must_use]
pub fn all(layout: &Layout) -> Vec<Service> {
    let mut out = Vec::new();
    for e in Entry::ALL {
        out.extend(keyd(layout, e));
    }
    for c in Cluster::ALL {
        out.push(crate::pg::service(layout, c));
    }
    out.push(witness(layout));
    out.push(vault(layout));
    out.push(cell(layout));
    out.push(edge(layout));
    out
}
