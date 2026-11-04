//! Fuzz target `cert_names_decode` of `fstp-witness` (TH-26, H-05,
//! ADR-010 "Witnesses", lane int5).
//!
//! The witness reads the issuer, the signed bytes, the signature, the key
//! identifiers and the subject OU of a client certificate to tell its
//! sender. Checks:
//!
//! - no panic on any input, and the reading is deterministic;
//! - `read_cert_names` agrees with `read_cert`;
//! - `sender_of` never names a sender for a certificate that does not
//!   read, whatever the pinned CAs.

#![no_main]

use fstp_audit::CellId;
use fstp_witness::peer::{PinnedCa, read_cert, read_cert_names, sender_of};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parts = read_cert(data);
    assert_eq!(parts, read_cert(data), "reading is not deterministic");
    let names = read_cert_names(data);
    assert_eq!(
        names.as_ref().ok(),
        parts.as_ref().ok().map(|p| &p.names),
        "the two readers disagree"
    );
    let pins = [PinnedCa {
        cell: CellId([0x11; 16]),
        key_id: data.iter().take(32).copied().collect(),
        subject: data.iter().take(64).copied().collect(),
        spki: data.iter().rev().take(91).copied().collect(),
    }];
    if parts.is_err() {
        assert!(
            sender_of(data, &pins).is_none(),
            "a sender from an unreadable certificate"
        );
    }
});
