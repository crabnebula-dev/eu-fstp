//! I-19, design section 15: the round trip of the `CellToCp` and `CpToCell`
//! codec.
//!
//! Design section 15 asks the codec for a round trip. Every generated
//! message encodes, decodes to itself, and its frame is the only one that
//! decodes to it: a frame with one byte changed decodes to another
//! message or none. A frame never decodes in the other direction.
//!
//! Lane W2h implementer. The message generators build every field from
//! its specification through the test helpers, never from the codec.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{certificate, raw_signature, verifier};
use fstp_cp_proto::{
    BreakGlassScope, CaseRef, CellId, CellToCp, CertDer, Component, CompositeSig, CounterKind,
    CpToCell, DegradedReason, Health, PopSig, ProductVersion, ProtoError, RoleName, ScramVerifier,
    SpkiDigest, StaffRef, TicketKind, decode_cell_to_cp, decode_cp_to_cell, encode_cell_to_cp,
    encode_cp_to_cell,
};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

fn arr<const N: usize>(g: &mut Gen) -> [u8; N] {
    g.bytes(N..=N).try_into().unwrap()
}

fn pop(g: &mut Gen) -> PopSig {
    let der = fstp_pki::cert::ecdsa_sig_value_from_raw(&raw_signature(g));
    PopSig::parse(&der).unwrap()
}

fn health(g: &mut Gen) -> Health {
    match g.u8_in(0..=2) {
        0 => Health::Ok,
        1 => Health::Degraded(*g.pick(&[
            DegradedReason::Database,
            DegradedReason::Vault,
            DegradedReason::Witness,
            DegradedReason::Custody,
        ])),
        _ => Health::Maintenance,
    }
}

fn cell_to_cp(g: &mut Gen) -> CellToCp {
    match g.u8_in(0..=3) {
        0 => CellToCp::Heartbeat {
            cell: CellId(arr(g)),
            version: ProductVersion::new(g.u16(), g.u16(), g.u16()),
            health: health(g),
        },
        1 => CellToCp::RoleCredential {
            role: *g.pick(&RoleName::ALL),
            spki: SpkiDigest(arr(g)),
            pop: pop(g),
            scram_verifier: ScramVerifier::parse(verifier(g).text().as_bytes()).unwrap(),
        },
        2 => CellToCp::CertRenewal {
            component: *g.pick(&[Component::Cell, Component::Vault, Component::Backup]),
            spki: SpkiDigest(arr(g)),
            pop: pop(g),
        },
        _ => {
            let kinds = [
                CounterKind::ActiveAccounts,
                CounterKind::Proposals,
                CounterKind::StoredBytes,
            ];
            let mut counters = Vec::new();
            for k in kinds {
                if g.bool() {
                    counters.push((k, g.u64()));
                }
            }
            CellToCp::Metering {
                cell: CellId(arr(g)),
                period: g.i64_in(i64::MIN..=i64::MAX),
                counters,
            }
        }
    }
}

fn cp_to_cell(g: &mut Gen) -> CpToCell {
    match g.u8_in(0..=4) {
        0 => CpToCell::Ack,
        1 => CpToCell::Certificate(CertDer::parse(&certificate(g)).unwrap()),
        2 => CpToCell::OperatorTicket {
            case: CaseRef(arr(g)),
            kind: *g.pick(&[TicketKind::Recovery, TicketKind::BreakGlass]),
            issued_at: g.i64_in(i64::MIN..=i64::MAX),
            sig: CompositeSig::parse(&g.bytes(3373..=3373)).unwrap(),
        },
        3 => CpToCell::BreakGlassRequest {
            staff: StaffRef(arr(g)),
            scope: *g.pick(&[BreakGlassScope::ReadContent, BreakGlassScope::ReadAudit]),
            until: g.i64_in(i64::MIN..=i64::MAX),
        },
        _ => CpToCell::EraseScheduled {
            at: g.i64_in(i64::MIN..=i64::MAX),
        },
    }
}

/// I-19, design section 15: every cell message round-trips, its frame has
/// one spelling, and the frame is no control-plane message.
#[test]
fn i19_cell_to_cp_round_trips_with_one_spelling() {
    fstp_prop::check(
        "i19_cell_to_cp_round_trips_with_one_spelling",
        |g: &mut Gen| {
            let m = cell_to_cp(g);
            let frame = encode_cell_to_cp(&m).map_err(|e| format!("{m:?}: {e}"))?;
            prop_assert_eq!(decode_cell_to_cp(&frame), Ok(m.clone()));
            prop_assert!(decode_cp_to_cell(&frame).is_err(), "{m:?}");
            let i = g.usize_in(0..=frame.len() - 1);
            let mut changed = frame.clone();
            changed[i] = changed[i].wrapping_add(g.u8_in(1..=255));
            prop_assert!(
                decode_cell_to_cp(&changed).as_ref() != Ok(&m),
                "byte {i} of {m:?} is free"
            );
            Ok(())
        },
    );
}

/// I-19, design section 15: the same for control-plane messages.
#[test]
fn i19_cp_to_cell_round_trips_with_one_spelling() {
    fstp_prop::check(
        "i19_cp_to_cell_round_trips_with_one_spelling",
        |g: &mut Gen| {
            let m = cp_to_cell(g);
            let frame = encode_cp_to_cell(&m).map_err(|e| format!("{m:?}: {e}"))?;
            prop_assert_eq!(decode_cp_to_cell(&frame), Ok(m.clone()));
            prop_assert!(decode_cell_to_cp(&frame).is_err(), "{m:?}");
            let i = g.usize_in(0..=frame.len() - 1);
            let mut changed = frame.clone();
            changed[i] = changed[i].wrapping_add(g.u8_in(1..=255));
            prop_assert!(
                decode_cp_to_cell(&changed).as_ref() != Ok(&m),
                "byte {i} of {m:?} is free"
            );
            Ok(())
        },
    );
}

/// I-19: no placeholder value and no counter set out of kind order is
/// encoded, so no frame holds a value that its decoder would refuse.
#[test]
fn i19_encoders_refuse_placeholders_and_unordered_counters() {
    let cell = CellId([1; 16]);
    let cases: Vec<(&str, Result<Vec<u8>, ProtoError>)> = vec![
        (
            "empty PopSig",
            encode_cell_to_cp(&CellToCp::CertRenewal {
                component: Component::Cell,
                spki: SpkiDigest([0; 32]),
                pop: PopSig::empty(),
            }),
        ),
        (
            "empty CertDer",
            encode_cp_to_cell(&CpToCell::Certificate(CertDer::empty())),
        ),
        (
            "empty CompositeSig",
            encode_cp_to_cell(&CpToCell::OperatorTicket {
                case: CaseRef([0; 16]),
                kind: TicketKind::Recovery,
                issued_at: 0,
                sig: CompositeSig::empty(),
            }),
        ),
        (
            "counters out of order",
            encode_cell_to_cp(&CellToCp::Metering {
                cell,
                period: 1,
                counters: vec![
                    (CounterKind::Proposals, 1),
                    (CounterKind::ActiveAccounts, 2),
                ],
            }),
        ),
        (
            "a counter twice",
            encode_cell_to_cp(&CellToCp::Metering {
                cell,
                period: 1,
                counters: vec![(CounterKind::Proposals, 1), (CounterKind::Proposals, 2)],
            }),
        ),
    ];
    let accepted: Vec<&str> = cases
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(w, _)| *w)
        .collect();
    assert!(accepted.is_empty(), "encoded: {accepted:?}");
}
