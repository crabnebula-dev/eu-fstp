//! I-19, design sections 9.1 and 15, ADR-009: the `CellToCp` and `CpToCell`
//! decoders.
//!
//! The protocol is the only path between a cell and the control plane. In
//! M3 it cannot carry tenant data, so its decoders must be total and
//! closed. Each test checks four things on arbitrary input:
//!
//! - every input gets an answer, never a stub refusal;
//! - only declared field classes decode: every byte-carrying field of an
//!   accepted message passes its own grammar again, unchanged;
//! - an accepted frame has one spelling: cutting its last byte, adding a
//!   byte, or changing any one byte never decodes to the same message. A
//!   byte that the message does not determine would be a free channel for
//!   tenant data, such as the canary that
//!   `i19_teeth_canary_in_heartbeat_is_caught` appends;
//! - empty input and free text are refused.
//!
//! Gap, recorded for lane W2h: the stub exports no encoder, and the design
//! names none. So these tests cannot build a valid frame, and the round
//! trip of design section 15 is not tested here. Once `encode_cell_to_cp`
//! and `encode_cp_to_cell` exist, the round trip `decode(encode(m)) == m`
//! and `encode(decode(b)) == b` belong in this file and in both fuzz
//! targets.
//!
//! Lane W2h test author. Red until lane W2h writes the codec: both
//! decoders are W0 stubs that refuse with `ProtoError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{is_stub, refused};
use fstp_cp_proto::{
    CellToCp, CertDer, CompositeSig, CpToCell, PopSig, ProtoError, ScramVerifier,
    decode_cell_to_cp, decode_cp_to_cell,
};
use fstp_prop::{Gen, prop_assert, prop_assert_ne};

/// Free text and look-alike frames that no closed decoder accepts.
const FREE_TEXT: &[&[u8]] = &[
    b"",
    b"\0",
    b"heartbeat",
    b"heartbeat:Ada Lovelace",
    b"{}",
    b"[]",
    b"null",
    b"{\"note\":\"tenant text\"}",
    b"SELECT * FROM ledger.entry",
    b"\xff\xfe\xfd",
];

/// Inputs for the decoders: arbitrary bytes, printable text, and JSON-like
/// text, so a text codec is reached too.
fn frame(g: &mut Gen) -> Vec<u8> {
    match g.u8_in(0..=2) {
        0 => g.bytes(0..=512),
        1 => g.ascii_string(0..=256).into_bytes(),
        _ => {
            let key = *g.pick(&[
                "Heartbeat",
                "RoleCredential",
                "CertRenewal",
                "Metering",
                "Ack",
                "Certificate",
                "OperatorTicket",
                "BreakGlassRequest",
                "EraseScheduled",
            ]);
            let body = g.ascii_string(0..=64);
            format!("{{\"{key}\":{body}}}").into_bytes()
        }
    }
}

/// The neighbours of an accepted frame that must not decode to the same
/// message: the frame without its last byte, with one byte added at the
/// end or the start, and with one byte changed.
fn neighbours(g: &mut Gen, b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if !b.is_empty() {
        out.push(b[..b.len() - 1].to_vec());
        let mut changed = b.to_vec();
        let i = g.usize_in(0..=b.len() - 1);
        changed[i] = changed[i].wrapping_add(g.u8_in(1..=255));
        out.push(changed);
    }
    let extra = g.u8();
    let mut longer = b.to_vec();
    longer.push(extra);
    out.push(longer);
    let mut earlier = vec![extra];
    earlier.extend_from_slice(b);
    out.push(earlier);
    out
}

/// Every byte-carrying field of `m` passes its grammar again, unchanged.
fn cell_to_cp_fields_closed(m: &CellToCp) -> Result<(), String> {
    match m {
        CellToCp::RoleCredential {
            pop,
            scram_verifier,
            ..
        } => {
            prop_assert!(PopSig::parse(pop.as_bytes()).as_ref() == Ok(pop), "{m:?}");
            prop_assert!(
                ScramVerifier::parse(scram_verifier.as_bytes()).as_ref() == Ok(scram_verifier),
                "{m:?}"
            );
        }
        CellToCp::CertRenewal { pop, .. } => {
            prop_assert!(PopSig::parse(pop.as_bytes()).as_ref() == Ok(pop), "{m:?}");
        }
        CellToCp::Heartbeat { .. } | CellToCp::Metering { .. } => {}
    }
    Ok(())
}

/// The same for `CpToCell`.
fn cp_to_cell_fields_closed(m: &CpToCell) -> Result<(), String> {
    match m {
        CpToCell::Certificate(c) => {
            prop_assert!(CertDer::parse(c.as_bytes()).as_ref() == Ok(c), "{m:?}");
        }
        CpToCell::OperatorTicket { sig, .. } => {
            prop_assert!(
                CompositeSig::parse(sig.as_bytes()).as_ref() == Ok(sig),
                "{m:?}"
            );
        }
        CpToCell::Ack | CpToCell::BreakGlassRequest { .. } | CpToCell::EraseScheduled { .. } => {}
    }
    Ok(())
}

/// The shared body of the two decoder properties.
fn total_and_closed<M: PartialEq + std::fmt::Debug>(
    g: &mut Gen,
    decode: fn(&[u8]) -> Result<M, ProtoError>,
    closed: fn(&M) -> Result<(), String>,
) -> Result<(), String> {
    let b = frame(g);
    match decode(&b) {
        Err(e) if is_stub(&e) => Err(format!("{e:?}")),
        Err(_) => Ok(()),
        Ok(m) => {
            closed(&m)?;
            for n in neighbours(g, &b) {
                match decode(&n) {
                    Err(e) if is_stub(&e) => return Err(format!("{e:?}")),
                    Ok(other) => {
                        prop_assert_ne!(&other, &m, "{:02x?} and {n:02x?} decode to one message", b)
                    }
                    Err(_) => {}
                }
            }
            Ok(())
        }
    }
}

/// I-19, design section 15 (`cell_to_cp_decode`): the cell-to-control-plane
/// decoder answers every input, decodes only declared field classes, and
/// gives each message one spelling.
#[test]
fn i19_cell_to_cp_decode_is_total_and_closed() {
    fstp_prop::check(
        "i19_cell_to_cp_decode_is_total_and_closed",
        |g: &mut Gen| total_and_closed(g, decode_cell_to_cp, cell_to_cp_fields_closed),
    );
}

/// I-19, design section 15 (`cp_to_cell_decode`): the same for the
/// control-plane-to-cell decoder.
#[test]
fn i19_cp_to_cell_decode_is_total_and_closed() {
    fstp_prop::check(
        "i19_cp_to_cell_decode_is_total_and_closed",
        |g: &mut Gen| total_and_closed(g, decode_cp_to_cell, cp_to_cell_fields_closed),
    );
}

/// I-19, design section 9.1: empty input, free text and look-alike frames
/// are refused by the cell-to-control-plane decoder.
#[test]
fn i19_cell_to_cp_refuses_empty_and_free_text() {
    let failures: Vec<String> = FREE_TEXT
        .iter()
        .filter_map(|b| refused(&String::from_utf8_lossy(b), decode_cell_to_cp(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// I-19, design section 9.1: the same for the control-plane-to-cell
/// decoder.
#[test]
fn i19_cp_to_cell_refuses_empty_and_free_text() {
    let failures: Vec<String> = FREE_TEXT
        .iter()
        .filter_map(|b| refused(&String::from_utf8_lossy(b), decode_cp_to_cell(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
