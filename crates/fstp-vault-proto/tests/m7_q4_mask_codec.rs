//! The vault name mask on the wire (M7 Q4, ADR-033 record of lane L31,
//! `overview.md` "Masks"): one canonical spelling, against the hand-written
//! oracle of `common::wire`, and the request and answer bounds.

#![allow(clippy::unwrap_used, reason = "test code")]

mod common;

use common::wire;
use fstp_vault_proto::{
    MAX_MASK_ACCOUNTS, MAX_MASK_TEXT_BYTES, MAX_MASK_TEXTS, VaultRequest, VaultResponse,
    WireAccount, WireMaskClass, WireSpan, decode_request, decode_response, encode_request,
    encode_response,
};

fn accounts(n: u128) -> Vec<WireAccount> {
    (1..=n).map(WireAccount).collect()
}

fn span(start: u32, end: u32, person: u32, class: WireMaskClass) -> WireSpan {
    WireSpan {
        start,
        end,
        person,
        class,
    }
}

/// M7 Q4, TH-26: a mask request and its answer have one spelling, the
/// oracle's, and decode back to themselves. Texts keep every byte.
#[test]
fn m7_q4_mask_request_and_answer_round_trip() {
    let r = VaultRequest::Mask {
        accounts: accounts(2),
        texts: vec!["Lead: Maradine \"Vel\"\n\u{1}é".to_owned(), String::new()],
    };
    let bytes = encode_request(&r).unwrap();
    assert_eq!(bytes, wire::request(&r));
    assert_eq!(decode_request(&bytes).unwrap(), r);

    let a = VaultResponse::Masks(vec![
        vec![
            span(6, 14, 0, WireMaskClass::Name),
            span(20, 30, 1, WireMaskClass::BirthDate),
        ],
        Vec::new(),
    ]);
    let bytes = encode_response(&a).unwrap();
    assert_eq!(bytes, wire::response(&a));
    assert_eq!(decode_response(&bytes).unwrap(), a);
}

/// M7 Q4, I-17: requests outside the bounds are refused both ways: no
/// account, accounts out of order, more than `MAX_MASK_ACCOUNTS`, no text,
/// more than `MAX_MASK_TEXTS`, and a text over `MAX_MASK_TEXT_BYTES`.
#[test]
fn m7_q4_mask_request_bounds() {
    let text = || vec!["x".to_owned()];
    let bad = [
        VaultRequest::Mask {
            accounts: Vec::new(),
            texts: text(),
        },
        VaultRequest::Mask {
            accounts: vec![WireAccount(2), WireAccount(1)],
            texts: text(),
        },
        VaultRequest::Mask {
            accounts: accounts(u128::try_from(MAX_MASK_ACCOUNTS).unwrap() + 1),
            texts: text(),
        },
        VaultRequest::Mask {
            accounts: accounts(1),
            texts: Vec::new(),
        },
        VaultRequest::Mask {
            accounts: accounts(1),
            texts: vec!["x".to_owned(); MAX_MASK_TEXTS + 1],
        },
        VaultRequest::Mask {
            accounts: accounts(1),
            texts: vec!["x".repeat(MAX_MASK_TEXT_BYTES + 1)],
        },
    ];
    for r in bad {
        assert!(encode_request(&r).is_err(), "{r:?}");
        assert!(decode_request(&wire::request(&r)).is_err());
    }
}

/// M7 Q4: an answer whose spans are empty, out of order, overlapping, name
/// a person past the account bound, or name an unknown class is refused,
/// so the cell never applies a malformed mask.
#[test]
fn m7_q4_mask_answer_bounds() {
    let bad = [
        vec![span(3, 3, 0, WireMaskClass::Name)],
        vec![
            span(5, 8, 0, WireMaskClass::Name),
            span(1, 2, 0, WireMaskClass::Name),
        ],
        vec![
            span(1, 5, 0, WireMaskClass::Name),
            span(4, 8, 0, WireMaskClass::Name),
        ],
        vec![span(
            1,
            2,
            u32::try_from(MAX_MASK_ACCOUNTS).unwrap(),
            WireMaskClass::Name,
        )],
    ];
    for spans in bad {
        let a = VaultResponse::Masks(vec![spans]);
        assert!(encode_response(&a).is_err(), "{a:?}");
        assert!(decode_response(&wire::response(&a)).is_err());
    }
    let unknown = br#"{"masks":[[{"class":"email","end":2,"person":0,"start":1}]],"type":"masks"}"#;
    assert!(decode_response(unknown).is_err());
}
