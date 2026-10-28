//! The cell envelope codec (design section 5.1). Each decoder is fuzzed.

use crate::{CellCommand, CellRecord};

/// Why a cell record or command did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The codec is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Decodes a cell record. Fuzzed (`cell_record_decode`).
pub fn decode_cell_record(bytes: &[u8]) -> Result<CellRecord, DecodeError> {
    let _ = bytes;
    Err(DecodeError::NotImplemented(
        "fstp_cell_core::decode_cell_record",
    ))
}

/// Decodes a cell command. Fuzzed (`cell_command_decode`).
pub fn decode_cell_command(bytes: &[u8]) -> Result<CellCommand, DecodeError> {
    let _ = bytes;
    Err(DecodeError::NotImplemented(
        "fstp_cell_core::decode_cell_command",
    ))
}

/// Decodes a record from its canonical text at a schema version. This is
/// the decode function `fstp-cell` passes to `PgRecordStore`.
pub fn record_from_canonical_at(canonical: &[u8], schema: u16) -> Result<CellRecord, DecodeError> {
    let _ = (canonical, schema);
    Err(DecodeError::NotImplemented(
        "fstp_cell_core::record_from_canonical_at",
    ))
}
