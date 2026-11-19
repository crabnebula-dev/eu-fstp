//! Issue 6 L11 (I-79, ADR-008 "Recovery"): an operator recovery ticket
//! names the cell it is for and an expiry in its signed bytes. The cell
//! refuses a ticket for another cell, an expired ticket and one whose
//! expiry lies further ahead than the ticket lifetime.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_auth::codec::{decode_operator_ticket, encode_operator_ticket};
use fstp_auth::recovery::{
    OperatorTicket, StaffRef, TICKET_CONTEXT, TICKET_LIFETIME_US, TICKET_MESSAGE_LEN, TicketDeny,
    accept_stored_ticket, accept_ticket,
};

const CELL: [u8; 16] = [0xC1; 16];
const CASE: [u8; 16] = [0xCA; 16];
const NOW: i64 = 1_798_761_600_000_000;

fn ticket(cell: [u8; 16], expires_at: i64) -> OperatorTicket {
    OperatorTicket {
        cell,
        case: CASE,
        staff_1: StaffRef([1; 16]),
        staff_2: StaffRef([2; 16]),
        expires_at,
    }
}

fn signed(key: &fstp_crypto::composite::CompositeSigningKey, t: &OperatorTicket) -> Vec<u8> {
    let sig = key
        .sign_with_context(&t.message(), TICKET_CONTEXT)
        .unwrap()
        .to_bytes();
    encode_operator_ticket(t, &sig).unwrap()
}

/// Issue 6 L11: the signed bytes are `cell || case || staff_1 || staff_2
/// || expires_at`, so neither the cell nor the expiry can change without
/// breaking the signature.
#[test]
fn issue6_l11_i79_ticket_signs_the_cell_and_the_expiry() {
    let t = ticket(CELL, NOW + 60_000_000);
    let m = t.message();
    assert_eq!(m.len(), TICKET_MESSAGE_LEN);
    assert_eq!(&m[..16], &CELL);
    assert_eq!(&m[16..32], &CASE);
    assert_eq!(&m[64..72], &(NOW + 60_000_000).to_be_bytes());
    let key = fstp_crypto::composite::generate().unwrap();
    let bytes = signed(&key, &t);
    assert_eq!(decode_operator_ticket(&bytes).unwrap().ticket, t);
    // A respelt cell or expiry breaks the signature.
    let pk = key.public_key().to_bytes().to_vec();
    for at in [0, 70] {
        let mut b = bytes.clone();
        b[at] ^= 1;
        assert_eq!(
            accept_ticket(&b, CELL, CASE, NOW, &pk),
            Err(TicketDeny::Signature)
        );
    }
}

/// Issue 6 L11: the cell, the expiry and the lifetime are checked when
/// the cell accepts a ticket.
#[test]
fn issue6_l11_i79_ticket_for_another_cell_or_out_of_time_is_refused() {
    let key = fstp_crypto::composite::generate().unwrap();
    let pk = key.public_key().to_bytes().to_vec();
    let good = signed(&key, &ticket(CELL, NOW + TICKET_LIFETIME_US));
    assert!(accept_ticket(&good, CELL, CASE, NOW, &pk).is_ok());
    assert_eq!(
        accept_ticket(&good, [0xC2; 16], CASE, NOW, &pk),
        Err(TicketDeny::OtherCell)
    );
    let at_expiry = NOW + TICKET_LIFETIME_US;
    assert!(accept_ticket(&good, CELL, CASE, at_expiry, &pk).is_ok());
    assert_eq!(
        accept_ticket(&good, CELL, CASE, at_expiry + 1, &pk),
        Err(TicketDeny::Expired)
    );
    let too_long = signed(&key, &ticket(CELL, NOW + TICKET_LIFETIME_US + 1));
    assert_eq!(
        accept_ticket(&too_long, CELL, CASE, NOW, &pk),
        Err(TicketDeny::Lifetime)
    );
    // A ticket the cell accepted and kept is checked again at completion
    // for its signature, cell and case, but not for time.
    assert!(accept_stored_ticket(&good, CELL, CASE, &pk).is_ok());
    assert_eq!(
        accept_stored_ticket(&good, [0xC2; 16], CASE, &pk),
        Err(TicketDeny::OtherCell)
    );
}

/// The ticket lifetime is the staff-assertion lifetime that Daniel
/// accepted on 2026-11-15 (ADR-008): 15 minutes.
#[test]
fn issue6_l11_adr008_ticket_lifetime_is_fifteen_minutes() {
    assert_eq!(TICKET_LIFETIME_US, 900_000_000);
}
