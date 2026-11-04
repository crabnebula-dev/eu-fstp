//! Fuzz target `cp_to_cell_decode` of `fstp-cp-proto` (TH-26, H-05, I-19,
//! M3 design section 15).
//!
//! Design checks: no panic; round trip; only declared field classes decode.
//!
//! On every input the decoder returns without a panic, and its result
//! formats. On an accepted frame:
//!
//! - only declared field classes decode: a certificate and an operator
//!   ticket's composite signature pass their own grammars again,
//!   unchanged;
//! - the frame round-trips: `encode_cp_to_cell(&m)` gives `data` back;
//! - the frame has one spelling: the frame without its last byte, with a
//!   byte appended, or with any one byte changed never decodes to the same
//!   message. A byte the message leaves free could carry tenant data.

#![no_main]

use fstp_cp_proto::{CertDer, CompositeSig, CpToCell, decode_cp_to_cell, encode_cp_to_cell};
use libfuzzer_sys::fuzz_target;

/// The longest frame whose every byte is changed in turn.
const MAX_CHANGED: usize = 4096;

fn same(bytes: &[u8], m: &CpToCell) -> bool {
    decode_cp_to_cell(bytes).ok().as_ref() == Some(m)
}

fuzz_target!(|data: &[u8]| {
    let first = decode_cp_to_cell(data);
    let shown = format!("{first:?}");
    assert!(!shown.is_empty());
    let Ok(m) = first else {
        return;
    };
    assert_eq!(
        encode_cp_to_cell(&m).as_deref(),
        Ok(data),
        "{m:?} does not round-trip"
    );
    match &m {
        CpToCell::Certificate(c) => {
            assert_eq!(CertDer::parse(c.as_bytes()).as_ref(), Ok(c));
        }
        CpToCell::OperatorTicket { sig, .. } => {
            assert_eq!(CompositeSig::parse(sig.as_bytes()).as_ref(), Ok(sig));
        }
        CpToCell::Ack | CpToCell::BreakGlassRequest { .. } | CpToCell::EraseScheduled { .. } => {}
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
