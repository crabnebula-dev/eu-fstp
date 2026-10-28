//! Multi-cell worlds (design section 14.3). Lane W1a.

use crate::NotImplemented;
use crate::egress::EgressLog;
use crate::scan::StoreSet;

/// How cells share database clusters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbMode {
    /// Cells share clusters, one database per cell.
    Shared,
    /// Each cell has its own clusters.
    Dedicated,
}

/// Where the vault databases live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultLayout {
    /// A vault cluster apart from the application cluster (I-83).
    SeparateCluster,
}

/// What a world holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldSpec {
    /// The number of cells.
    pub cells: u8,
    /// The database mode.
    pub mode: DbMode,
    /// The vault layout.
    pub vault_layout: VaultLayout,
    /// Whether the cells are self-hosted.
    pub self_hosted: bool,
    /// Whether components run as real processes.
    pub process_mode: bool,
}

/// One cell of a world: an HTTP client with a software authenticator.
#[derive(Debug)]
pub struct CellHandle {
    index: u8,
}

impl CellHandle {
    /// The cell's index in its world.
    pub fn index(&self) -> u8 {
        self.index
    }
}

/// A scripted call cycle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CycleScript {
    /// The steps, by name.
    pub steps: Vec<String>,
}

/// The result of a cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleReport {
    /// Whether the cycle completed, or why not.
    pub result: Result<(), NotImplemented>,
}

/// A running world: clusters, cells, control plane, edge, witness, custody
/// simulator and recorders.
#[derive(Debug)]
pub struct World {
    cells: Vec<CellHandle>,
    egress: EgressLog,
}

impl World {
    /// Starts a world.
    pub fn start(spec: WorldSpec) -> Result<World, NotImplemented> {
        let _ = spec;
        Err(NotImplemented::new("fstp_celltest::world::World::start"))
    }

    /// The cell at index `i`.
    pub fn cell(&self, i: u8) -> Option<&CellHandle> {
        self.cells.get(usize::from(i))
    }

    /// Runs a call cycle on one cell.
    pub fn run_cycle(&self, cell: u8, script: &CycleScript) -> CycleReport {
        let _ = (cell, script);
        CycleReport {
            result: Err(NotImplemented::new(
                "fstp_celltest::world::World::run_cycle",
            )),
        }
    }

    /// Every database, object directory, log and metrics sink.
    pub fn stores(&self) -> Result<StoreSet, NotImplemented> {
        Err(NotImplemented::new("fstp_celltest::world::World::stores"))
    }

    /// The plaintext captures above TLS on every outbound client.
    pub fn egress(&self) -> &EgressLog {
        &self.egress
    }
}
