//! Process memory reading for the I-80 root canary tests (design section
//! 14.4). Lane W1a. The `/proc/<pid>/maps` reader is a test-only parser
//! with its own fuzz target (`proc_maps_decode`).

use crate::NotImplemented;

/// One mapped region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRegion {
    /// The start address.
    pub start: u64,
    /// The end address.
    pub end: u64,
    /// Whether the region is readable.
    pub readable: bool,
    /// The mapped path, if any.
    pub path: Option<String>,
}

/// Decodes the text of `/proc/<pid>/maps`. Fuzzed (`proc_maps_decode`).
pub fn decode_proc_maps(bytes: &[u8]) -> Result<Vec<MapRegion>, NotImplemented> {
    let _ = bytes;
    Err(NotImplemented::new(
        "fstp_celltest::procmem::decode_proc_maps",
    ))
}
