//! Where everything lives on a host, derived from the configuration
//! (ADR-028). Nothing here is configured on its own.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::config::{HostConfig, Services};

/// A custody entry: one `fstp-keyd` with its own volume and passphrase
/// (ADR-028 "Custody entries").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Entry {
    /// The cell's App and CellBackup chains, and the app cluster's backups.
    Cell,
    /// The dedicated root of the cell key file.
    CellKeys,
    /// The Vault chain, and the vault cluster's backups.
    Vault,
    /// The witness's ControlPlane entry.
    Witness,
}

impl Entry {
    /// Every entry, in start order.
    pub const ALL: [Entry; 4] = [Entry::Cell, Entry::CellKeys, Entry::Vault, Entry::Witness];

    /// The entry's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Entry::Cell => "cell",
            Entry::CellKeys => "cell-keys",
            Entry::Vault => "vault",
            Entry::Witness => "witness",
        }
    }

    /// The client sockets the entry serves, by `fstp-keyd` role name.
    #[must_use]
    pub fn roles(self) -> &'static [&'static str] {
        match self {
            Entry::Cell => &["cell", "console"],
            Entry::CellKeys => &["cell"],
            Entry::Vault => &["vault", "console"],
            Entry::Witness => &["control"],
        }
    }
}

/// A database cluster on the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cluster {
    /// The application cluster, database `c_<cell>`.
    App,
    /// The vault cluster, database `v_<cell>`.
    Vault,
}

impl Cluster {
    /// Both clusters.
    pub const ALL: [Cluster; 2] = [Cluster::App, Cluster::Vault];

    /// The cluster's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Cluster::App => "app",
            Cluster::Vault => "vault",
        }
    }

    /// The OU of its server certificate (I-83).
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Cluster::App => "application",
            Cluster::Vault => "vault",
        }
    }

    /// The prefix of its cell database.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Cluster::App => "c",
            Cluster::Vault => "v",
        }
    }
}

/// The host's places.
#[derive(Clone, Debug)]
pub struct Layout {
    /// The configuration.
    pub cfg: HostConfig,
}

fn lo(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

impl Layout {
    /// The layout of `cfg`.
    #[must_use]
    pub fn new(cfg: HostConfig) -> Layout {
        Layout { cfg }
    }

    fn port(&self, offset: u16) -> u16 {
        self.cfg.base_port.saturating_add(offset)
    }

    /// The cell's tunnel listener.
    #[must_use]
    pub fn cell_tunnel(&self) -> SocketAddr {
        lo(self.port(0))
    }
    /// The cell's internal listener.
    #[must_use]
    pub fn cell_internal(&self) -> SocketAddr {
        lo(self.port(1))
    }
    /// The cell's health listener.
    #[must_use]
    pub fn cell_health(&self) -> SocketAddr {
        lo(self.port(2))
    }
    /// The vault's internal listener.
    #[must_use]
    pub fn vault_internal(&self) -> SocketAddr {
        lo(self.port(3))
    }
    /// The vault's origin (tunnel) listener.
    #[must_use]
    pub fn vault_origin(&self) -> SocketAddr {
        lo(self.port(4))
    }
    /// The witness listener.
    #[must_use]
    pub fn witness(&self) -> SocketAddr {
        lo(self.port(5))
    }
    /// A cluster's port.
    #[must_use]
    pub fn pg_port(&self, c: Cluster) -> u16 {
        match c {
            Cluster::App => self.port(6),
            Cluster::Vault => self.port(7),
        }
    }
    /// The edge's public listener.
    #[must_use]
    pub fn edge_public(&self) -> SocketAddr {
        let ip = match self.cfg.services {
            Services::Systemd => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Services::Direct => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        SocketAddr::new(ip, self.cfg.public_port)
    }

    /// The vault origin host.
    #[must_use]
    pub fn vault_host(&self) -> String {
        format!("id.{}", self.cfg.domain)
    }

    /// `<etc>/<leaf>`.
    #[must_use]
    pub fn etc(&self, leaf: &str) -> PathBuf {
        self.cfg.paths.etc.join(leaf)
    }
    /// `<state>/<leaf>`.
    #[must_use]
    pub fn state(&self, leaf: &str) -> PathBuf {
        self.cfg.paths.state.join(leaf)
    }
    /// A binary.
    #[must_use]
    pub fn bin(&self, name: &str) -> PathBuf {
        self.cfg.paths.bin.join(name)
    }
    /// A PostgreSQL binary.
    #[must_use]
    pub fn pg_bin(&self, name: &str) -> PathBuf {
        self.cfg.paths.pg_bin.join(name)
    }
    /// The admin's own state directory.
    #[must_use]
    pub fn admin_dir(&self) -> PathBuf {
        self.state("admin")
    }
    /// The CA directory.
    #[must_use]
    pub fn ca_dir(&self) -> PathBuf {
        self.etc("ca")
    }
    /// A service's credentials directory.
    #[must_use]
    pub fn creds(&self, service: &str) -> PathBuf {
        self.etc(service)
    }
    /// The directory of public keys the services wrote.
    #[must_use]
    pub fn public_dir(&self) -> PathBuf {
        self.etc("public")
    }
    /// A cluster's data directory.
    #[must_use]
    pub fn pg_data(&self, c: Cluster) -> PathBuf {
        self.state("pg").join(c.name())
    }
    /// A cluster's TLS and superuser login directory.
    #[must_use]
    pub fn pg_dir(&self, c: Cluster) -> PathBuf {
        self.etc("pg").join(c.name())
    }
    /// The volume of a custody entry.
    #[must_use]
    pub fn keyd_volume(&self, e: Entry) -> PathBuf {
        match self.cfg.services {
            Services::Systemd => PathBuf::from(format!("/var/lib/fstp-keyd-{}", e.name())),
            Services::Direct => self.state("keyd").join(e.name()),
        }
    }
    /// The socket of `role` of a custody entry.
    #[must_use]
    pub fn keyd_socket(&self, e: Entry, role: &str) -> PathBuf {
        let dir = match self.cfg.services {
            Services::Systemd => PathBuf::from(format!("/run/fstp-keyd-{}", e.name())),
            Services::Direct => self.state("run").join(format!("keyd-{}", e.name())),
        };
        dir.join(format!("{role}.sock"))
    }
    /// The passphrase credential of a custody entry.
    #[must_use]
    pub fn keyd_passphrase(&self, e: Entry) -> PathBuf {
        self.etc("keyd").join(format!("{}.passphrase", e.name()))
    }
    /// A service's configuration file.
    #[must_use]
    pub fn config_file(&self, service: &str) -> PathBuf {
        self.etc(&format!("{service}.json"))
    }
    /// The first admin's token file.
    #[must_use]
    pub fn token_file(&self) -> PathBuf {
        self.cfg.paths.token_dir.join("fstp-first-admin.token")
    }
    /// A migration set's directory.
    #[must_use]
    pub fn migrations(&self, c: Cluster) -> PathBuf {
        self.cfg.paths.share.join("migrations").join(c.name())
    }
    /// The web assets.
    #[must_use]
    pub fn assets(&self) -> PathBuf {
        self.cfg.paths.share.join("web")
    }
    /// The witness file store.
    #[must_use]
    pub fn witness_store(&self) -> PathBuf {
        self.state("witness")
    }
    /// The backup agent's state directory of a cluster.
    #[must_use]
    pub fn backup_state(&self, c: Cluster) -> PathBuf {
        self.state("backup").join(c.name())
    }
    /// The route log.
    #[must_use]
    pub fn route_log(&self) -> PathBuf {
        self.admin_dir().join("routes.log")
    }
    /// The edge route file.
    #[must_use]
    pub fn edge_routes(&self) -> PathBuf {
        self.etc("edge-routes.json")
    }
    /// The systemd unit directory.
    #[must_use]
    pub fn unit_dir(&self) -> &'static Path {
        Path::new("/etc/systemd/system")
    }
}
