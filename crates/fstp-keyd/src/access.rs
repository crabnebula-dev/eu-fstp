//! Access to `fstp-keyd` (ADR-004 part 2 "Access to `fstp-keyd`",
//! R-NF-08).
//!
//! `fstp-keyd` listens on one Unix socket per client OS user. Each socket
//! serves a fixed set of chains and keys, given by its [`ClientRole`]:
//!
//! | Role | Client | Chains | CA sign keys |
//! | --- | --- | --- | --- |
//! | [`ClientRole::Cell`] | `fstp-cell` | App, CellBackup | the cell CA |
//! | [`ClientRole::Vault`] | `fstp-vault` | Vault | none |
//! | [`ClientRole::PgAgent`] | `fstp-pgagent` | none | the local cluster CAs |
//! | [`ClientRole::Console`] | root, at the host console | CellBackup, ClusterBackup | none |
//!
//! So a compromise of application keys does not expose the vault. A
//! request for a chain outside its socket's set is refused with
//! [`fstp_custody::Refusal::NotPermitted`] and logged.
//!
//! Sign permission goes by the class byte of the key handle
//! ([`SignKeyClass`]), not by role alone. ADR-004 part 2 "CA keys in
//! custody" holds the cell CA key in the cell's App custody entry, so
//! the `fstp-cell` socket signs with it. The local cluster CA keys are
//! for `fstp-pgagent`. The record of this mapping beside the socket
//! layout in ADR-004 is with the lead.
//!
//! The console row follows two readings that wait on the lead: the
//! restore command reads keystore snapshots under CellBackup, and the
//! open point of ADR-004 part 2 proposes that self-hosted cluster backups
//! use ClusterBackup through the console socket only. The ControlPlane
//! entry for a self-hosted witness is an open point too, so no socket
//! serves that chain yet.
//!
//! # Permissions
//!
//! std alone sets them. A socket with no [`ClientSocket::group`] admits
//! only the `fstp-keyd` OS user and root (mode 0600). A socket with a
//! group is handed to that group (mode 0660), so the install gives each
//! client OS user its own group. Each socket is bound inside a fresh
//! private directory (mode 0700), restricted, and only then renamed to
//! its path. No client can connect while the socket still has the
//! permissions the umask gave it.

use std::path::{Path, PathBuf};

use fstp_custody::Chain;
use fstp_custody::keyd::Request;

/// The client a socket serves. It fixes the chains and keys the socket
/// reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientRole {
    /// `fstp-cell`: the App and CellBackup chains, and the cell CA key.
    Cell,
    /// `fstp-vault`: the Vault chain only.
    Vault,
    /// `fstp-pgagent`: the local cluster CA sign keys only.
    PgAgent,
    /// The root-only host console: the restore command and recovery.
    Console,
}

impl ClientRole {
    /// Every role.
    pub const ALL: [ClientRole; 4] = [
        ClientRole::Cell,
        ClientRole::Vault,
        ClientRole::PgAgent,
        ClientRole::Console,
    ];

    /// The one-byte code of the role in the usage log. Code 0 is a
    /// request served outside a socket.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ClientRole::Cell => 1,
            ClientRole::Vault => 2,
            ClientRole::PgAgent => 3,
            ClientRole::Console => 4,
        }
    }

    /// The short name of the role, as its socket file name uses it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ClientRole::Cell => "cell",
            ClientRole::Vault => "vault",
            ClientRole::PgAgent => "pgagent",
            ClientRole::Console => "console",
        }
    }

    /// The chains a socket of this role reaches.
    #[must_use]
    pub const fn chains(self) -> &'static [Chain] {
        match self {
            ClientRole::Cell => &[Chain::App, Chain::CellBackup],
            ClientRole::Vault => &[Chain::Vault],
            ClientRole::PgAgent => &[],
            ClientRole::Console => &[Chain::CellBackup, Chain::ClusterBackup],
        }
    }

    /// The classes of CA sign key a socket of this role reaches.
    #[must_use]
    pub const fn sign_keys(self) -> &'static [SignKeyClass] {
        match self {
            ClientRole::Cell => &[SignKeyClass::CellCa],
            ClientRole::PgAgent => &[SignKeyClass::ClusterCa],
            ClientRole::Vault | ClientRole::Console => &[],
        }
    }

    /// Whether a socket of this role may sign with the key of `handle`.
    #[must_use]
    pub fn signs_with(self, handle: &[u8]) -> bool {
        SignKeyClass::of(handle).is_some_and(|c| self.sign_keys().contains(&c))
    }

    /// Whether a socket of this role may make `request`.
    #[must_use]
    pub fn permits(self, request: &Request) -> bool {
        match request {
            Request::CreateRoot { chain, .. } => self.chains().contains(chain),
            Request::Wrap { root, .. }
            | Request::Unwrap { root, .. }
            | Request::Destroy { root, .. }
            | Request::UsageSince { root, .. } => self.chains().contains(&root.chain),
            Request::Sign { key, .. } => self.signs_with(key),
        }
    }
}

/// The class of a CA sign key, named by the first byte of its handle:
/// `class u8 | name`, with at least one byte of name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignKeyClass {
    /// A cell CA key, held in the cell's App custody entry
    /// ([`fstp_custody::keyd::SIGN_KEY_CELL_CA`]).
    CellCa,
    /// A local cluster CA key
    /// ([`fstp_custody::keyd::SIGN_KEY_CLUSTER_CA`]).
    ClusterCa,
}

impl SignKeyClass {
    /// The class of `handle`, or `None` for an empty name or an unknown
    /// class byte.
    #[must_use]
    pub fn of(handle: &[u8]) -> Option<SignKeyClass> {
        match handle.split_first()? {
            (_, []) => None,
            (&fstp_custody::keyd::SIGN_KEY_CELL_CA, _) => Some(SignKeyClass::CellCa),
            (&fstp_custody::keyd::SIGN_KEY_CLUSTER_CA, _) => Some(SignKeyClass::ClusterCa),
            _ => None,
        }
    }
}

/// One socket of `fstp-keyd`: its path, its client role and, optionally,
/// the group of its client OS user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSocket {
    /// The socket path.
    pub path: PathBuf,
    /// The client the socket serves.
    pub role: ClientRole,
    /// The group id the socket is handed to (mode 0660). `None` keeps
    /// the socket to the `fstp-keyd` OS user and root (mode 0600). The
    /// `fstp-keyd` OS user must be a member of the group.
    pub group: Option<u32>,
}

impl ClientSocket {
    /// A socket at `path` for `role` that only the `fstp-keyd` OS user
    /// and root can use (mode 0600).
    #[must_use]
    pub fn owner_only(path: &Path, role: ClientRole) -> ClientSocket {
        ClientSocket {
            path: path.to_path_buf(),
            role,
            group: None,
        }
    }

    /// The mode of the socket file.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        if self.group.is_some() { 0o660 } else { 0o600 }
    }
}
