//! Fuzz target `cell_command_decode` of `fstp-cell-core` (TH-26, H-05, M3
//! design section 15).
//!
//! Design checks: decoding never panics; every accepted input re-encodes
//! byte for byte, so the step-up action digest names one command (I-78,
//! design section 8.4).
//!
//! [`reencode`] is `fstp_cell_core::encode_cell_command`.

#![no_main]

use fstp_cell_core::{CellCommand, decode_cell_command};
use libfuzzer_sys::fuzz_target;

/// The canonical bytes of `c`.
fn reencode(c: &CellCommand) -> Option<Vec<u8>> {
    Some(fstp_cell_core::encode_cell_command(c))
}

fuzz_target!(|data: &[u8]| {
    let decoded = decode_cell_command(data);
    assert!(!format!("{decoded:?}").is_empty());
    if let Ok(c) = &decoded
        && let Some(bytes) = reencode(c)
    {
        assert_eq!(
            bytes.as_slice(),
            data,
            "accepted bytes re-encode differently"
        );
    }
});
