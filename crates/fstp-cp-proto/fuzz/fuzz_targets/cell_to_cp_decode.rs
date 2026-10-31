//! Fuzz target `cell_to_cp_decode` of `fstp-cp-proto` (TH-26, H-05, I-19,
//! M3 design section 15).
//!
//! Design checks: no panic; round trip; only declared field classes decode.
//!
//! On every input the decoder returns without a panic, and its result
//! formats. On an accepted frame:
//!
//! - only declared field classes decode: the proof of possession and the
//!   SCRAM verifier pass their own grammars again, unchanged;
//! - the frame round-trips: `encode_cell_to_cp(&m)` gives `data` back;
//! - the frame has one spelling: the frame without its last byte, with a
//!   byte appended, or with any one byte changed never decodes to the same
//!   message. A byte the message leaves free could carry tenant data.

#![no_main]

use fstp_cp_proto::{CellToCp, PopSig, ScramVerifier, decode_cell_to_cp, encode_cell_to_cp};
use libfuzzer_sys::fuzz_target;

/// The longest frame whose every byte is changed in turn.
const MAX_CHANGED: usize = 4096;

fn same(bytes: &[u8], m: &CellToCp) -> bool {
    decode_cell_to_cp(bytes).ok().as_ref() == Some(m)
}

fuzz_target!(|data: &[u8]| {
    let first = decode_cell_to_cp(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    let Ok(m) = first else {
        return;
    };
    assert_eq!(
        encode_cell_to_cp(&m).as_deref(),
        Ok(data),
        "{m:?} does not round-trip"
    );
    match &m {
        CellToCp::RoleCredential {
            pop,
            scram_verifier,
            ..
        } => {
            assert_eq!(PopSig::parse(pop.as_bytes()).as_ref(), Ok(pop));
            assert_eq!(
                ScramVerifier::parse(scram_verifier.as_bytes()).as_ref(),
                Ok(scram_verifier)
            );
        }
        CellToCp::CertRenewal { pop, .. } => {
            assert_eq!(PopSig::parse(pop.as_bytes()).as_ref(), Ok(pop));
        }
        CellToCp::Heartbeat { .. } | CellToCp::Metering { .. } => {}
    }
    if let Some((_, init)) = data.split_last() {
        assert!(!same(init, &m), "a cut frame decodes to {m:?}");
    }
    for extra in [0x00, b' ', b'\n', 0xff] {
        let mut longer = data.to_vec();
        longer.push(extra);
        assert!(!same(&longer, &m), "an extended frame decodes to {m:?}");
    }
    for i in 0..data.len().min(MAX_CHANGED) {
        for delta in [0x01, 0x20, 0x80] {
            let mut changed = data.to_vec();
            if let Some(b) = changed.get_mut(i) {
                *b = b.wrapping_add(delta);
            }
            assert!(!same(&changed, &m), "byte {i} is free in {m:?}");
        }
    }
});
