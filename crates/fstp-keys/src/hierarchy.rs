//! The key hierarchy as built (M3 design section 3.1, ADR-004 part 2).
//!
//! Chain codes come from ADR-004 part 1: App 1, Vault 2, CellBackup 3,
//! ClusterBackup 4, ControlPlane 5. Purpose codes are the table of
//! [`Purpose::code`]. ADR-004 part 1 says the purpose table is recorded
//! at first use and frozen once written. Lane W2f wrote it here first.
//! Its record in ADR-004 is with the lead, so the codes are proposed
//! until that record lands. No code is ever reused or renumbered.

/// A cell identifier, 16 random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(pub [u8; 16]);

/// A key chain. Each chain has its own custody root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chain {
    /// The cell's application database.
    App,
    /// The cell's vault database.
    Vault,
    /// The cell's backups.
    CellBackup,
    /// Cluster-wide backups.
    ClusterBackup,
    /// The control plane.
    ControlPlane,
}

impl Chain {
    /// Every chain, in code order.
    pub const ALL: [Chain; 5] = [
        Chain::App,
        Chain::Vault,
        Chain::CellBackup,
        Chain::ClusterBackup,
        Chain::ControlPlane,
    ];

    /// The ADR-004 part 1 chain code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Chain::App => 1,
            Chain::Vault => 2,
            Chain::CellBackup => 3,
            Chain::ClusterBackup => 4,
            Chain::ControlPlane => 5,
        }
    }

    /// The chain of an ADR-004 part 1 chain code, if the code is known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Chain> {
        match code {
            1 => Some(Chain::App),
            2 => Some(Chain::Vault),
            3 => Some(Chain::CellBackup),
            4 => Some(Chain::ClusterBackup),
            5 => Some(Chain::ControlPlane),
            _ => None,
        }
    }

    /// A short lower-case name, as file custody spells it in file names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Chain::App => "app",
            Chain::Vault => "vault",
            Chain::CellBackup => "cellbackup",
            Chain::ClusterBackup => "clusterbackup",
            Chain::ControlPlane => "controlplane",
        }
    }
}

/// What a sealed object or a level 2 key is for (ADR-004 part 2 "Chains").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Purpose {
    /// A ledger entry.
    Ledger,
    /// A text of the text store.
    Text,
    /// An audit event body.
    AuditEvent,
    /// A checkpoint of the projections.
    Checkpoint,
    /// A backup chunk.
    Backup,
    /// The HMAC key of the login email index (App chain, G24).
    Lookup,
    /// The HMAC key of the credential id index (App chain, G24).
    CredLookup,
    /// The vault ticket key (App chain, Ed25519).
    Ticket,
    /// A chain's composite anchor key.
    Anchor,
    /// An identity attribute (Vault chain).
    Attribute,
    /// An identity document (Vault chain, one group per document).
    Document,
    /// A vault fact (Vault chain).
    Fact,
    /// The identity match key (Vault chain, G24).
    Match,
}

impl Purpose {
    /// Every purpose, in code order.
    pub const ALL: [Purpose; 13] = [
        Purpose::Ledger,
        Purpose::Text,
        Purpose::AuditEvent,
        Purpose::Checkpoint,
        Purpose::Backup,
        Purpose::Lookup,
        Purpose::CredLookup,
        Purpose::Ticket,
        Purpose::Anchor,
        Purpose::Attribute,
        Purpose::Document,
        Purpose::Fact,
        Purpose::Match,
    ];

    /// The purpose code that a seal context binds (ADR-004 part 1). The
    /// table is frozen: a code is never reused or renumbered, and code 0
    /// names no purpose.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Purpose::Ledger => 1,
            Purpose::Text => 2,
            Purpose::AuditEvent => 3,
            Purpose::Checkpoint => 4,
            Purpose::Backup => 5,
            Purpose::Lookup => 6,
            Purpose::CredLookup => 7,
            Purpose::Ticket => 8,
            Purpose::Anchor => 9,
            Purpose::Attribute => 10,
            Purpose::Document => 11,
            Purpose::Fact => 12,
            Purpose::Match => 13,
        }
    }

    /// The purpose of a code, if the code is known.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Purpose> {
        Purpose::ALL.into_iter().find(|p| p.code() == code)
    }

    /// Whether the purpose names a keyed digest key: `Lookup`,
    /// `CredLookup` or `Match` (design section 3.5, G24). Such a group
    /// holds no data keys.
    #[must_use]
    pub const fn is_keyed_digest(self) -> bool {
        matches!(self, Purpose::Lookup | Purpose::CredLookup | Purpose::Match)
    }
}

/// A root epoch. Erasure rotates it (ADR-004 part 2, ADR-007).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u64);

/// A key group, sealed together under one group key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub [u8; 16]);

/// A data key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DekId(pub [u8; 16]);

/// The object a sealed blob belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub [u8; 16]);
