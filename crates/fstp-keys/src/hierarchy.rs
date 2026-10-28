//! The key hierarchy as built (M3 design section 3.1).

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

/// What a sealed object is for.
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
}

/// A root epoch. Erasure rotates it (ADR-007).
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
