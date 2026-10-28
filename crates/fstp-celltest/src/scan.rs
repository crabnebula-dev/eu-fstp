//! Scanners over raw bytes and their encodings (design section 14.1). Lane
//! W1a. A stub scanner refuses rather than report "nothing found".

use std::collections::BTreeSet;

use crate::NotImplemented;
use crate::canary::Canary;

/// Every store of a world: databases, object directories, logs and
/// metrics sinks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSet {
    /// Each store's name and bytes.
    pub stores: Vec<(String, Vec<u8>)>,
}

/// What a scan found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Each hit: store name and canary text.
    pub hits: Vec<(String, String)>,
}

/// A dump of one cell's identifiers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellDump {
    /// The identifiers.
    pub identifiers: BTreeSet<Vec<u8>>,
}

/// Constants that may appear in every cell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicConstants {
    /// The constants.
    pub values: BTreeSet<Vec<u8>>,
}

/// Searches every store for every canary in every encoding.
pub fn scan(stores: &StoreSet, canaries: &[Canary]) -> Result<ScanReport, NotImplemented> {
    let _ = (stores, canaries);
    Err(NotImplemented::new("fstp_celltest::scan::scan"))
}

/// The identifiers two cells share, beyond the public constants (I-20).
pub fn shared_identifiers(
    a: &CellDump,
    b: &CellDump,
    allow: &PublicConstants,
) -> Result<BTreeSet<Vec<u8>>, NotImplemented> {
    let _ = (a, b, allow);
    Err(NotImplemented::new(
        "fstp_celltest::scan::shared_identifiers",
    ))
}
