//! M7 Q4, I-17 (ADR-033 records of lanes L31 and L40): the vault's mask
//! answer and the cap the cell's pieces keep.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fstp_vault_core::mask::{
    MASK_PIECE_BYTES, MASK_PIECES_PER_REQUEST, MaskPerson, mask_pieces, mask_spans,
};
use fstp_vault_core::mask_wire_spans;
use fstp_vault_proto::{MAX_MASK_SPANS, MAX_MASK_TEXT_BYTES, MAX_MASK_TEXTS, WireMaskClass};

/// M7 Q4 (lane L40): the cell cuts its pieces to the vault's own cap,
/// which stays as it was.
#[test]
fn m7_q4_pieces_keep_the_vault_request_cap() {
    assert_eq!(MASK_PIECE_BYTES, MAX_MASK_TEXT_BYTES);
    assert_eq!(MASK_PIECES_PER_REQUEST, MAX_MASK_TEXTS);
    assert_eq!(MAX_MASK_TEXT_BYTES, 64 << 10);
    let long = "Maradine Quist wrote this.\n".repeat(8_000);
    let pieces = mask_pieces(&long, MASK_PIECE_BYTES).unwrap();
    assert!(pieces.iter().all(|r| r.len() <= MAX_MASK_TEXT_BYTES));
}

/// M7 Q4, I-17 (lane L40): the vault answers every span of a text or
/// none. A text with more spans than an answer may carry is refused, so
/// the cell fails closed, rather than answered in part with names left
/// unmasked.
#[test]
fn m7_q4_i17_vault_never_answers_part_of_a_mask() {
    let p = [MaskPerson::new("Quist", "Maradine", Some("1990-04-07"))];
    let few = "Maradine Quist, 1990-04-07.";
    let spans = mask_wire_spans(few, &p).unwrap();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[1].class, WireMaskClass::BirthDate);
    assert_eq!(spans.len(), mask_spans(few, &p).len());
    let many = "Maradine, ".repeat(MAX_MASK_SPANS + 1);
    assert!(many.len() <= MAX_MASK_TEXT_BYTES);
    assert_eq!(mask_spans(&many, &p).len(), MAX_MASK_SPANS + 1);
    assert!(mask_wire_spans(&many, &p).is_none());
    let most = "Maradine, ".repeat(MAX_MASK_SPANS);
    assert_eq!(mask_wire_spans(&most, &p).unwrap().len(), MAX_MASK_SPANS);
}
