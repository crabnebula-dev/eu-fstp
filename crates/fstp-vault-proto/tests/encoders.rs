//! The encoders of `fstp-vault-proto` against the reference spelling in
//! `common::wire` (design section 6.2, TH-26, H-05, NOTE 5, ADR-009
//! "Format").
//!
//! The cell and the vault both encode, so each encoder must write exactly
//! the one spelling its decoder accepts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::wire::{self, RTicket};
use common::{gen_query, gen_request, gen_response};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_proto::{
    TicketClaims, TicketKind, VaultResponse, WireAccount, WireAnswer, WireProposal, WriteKind,
    decode_query, encode_request, encode_response,
};

/// TH-26, H-05: `encode_request` writes the reference spelling of every
/// request.
#[test]
fn th_26_encode_request_writes_the_reference_spelling() {
    fstp_prop::check(
        "th_26_encode_request_writes_the_reference_spelling",
        |g: &mut Gen| {
            let r = gen_request(g);
            prop_assert_eq!(encode_request(&r), Ok(wire::request(&r)));
            Ok(())
        },
    );
}

/// TH-26, H-05: `encode_response` writes the reference spelling of every
/// response.
#[test]
fn th_26_encode_response_writes_the_reference_spelling() {
    fstp_prop::check(
        "th_26_encode_response_writes_the_reference_spelling",
        |g: &mut Gen| {
            let r = gen_response(g);
            prop_assert_eq!(encode_response(&r), Ok(wire::response(&r)));
            Ok(())
        },
    );
}

/// Design section 6.2: a decoded query encodes back to its own wire bytes.
#[test]
fn th_26_typed_queries_round_trip_to_their_wire_bytes() {
    fstp_prop::check(
        "th_26_typed_queries_round_trip_to_their_wire_bytes",
        |g: &mut Gen| {
            let w = gen_query(g).wire();
            let q = decode_query(&w).map_err(|e| format!("{e:?}"))?;
            prop_assert_eq!(q.to_wire(), Ok(w));
            Ok(())
        },
    );
}

/// NOTE 5: the encoder refuses an answer whose set disagrees with its bit
/// or is out of order, so the vault never sends one.
#[test]
fn note5_encode_response_refuses_unlawful_answers() {
    let bad = [
        WireAnswer {
            holds: false,
            accounts: Some(vec![WireAccount(1)]),
            epoch: 1,
        },
        WireAnswer {
            holds: true,
            accounts: Some(vec![WireAccount(2), WireAccount(1)]),
            epoch: 1,
        },
    ];
    for a in bad {
        assert!(
            encode_response(&VaultResponse::Answers(vec![a.clone()])).is_err(),
            "{a:?}"
        );
    }
    assert!(encode_response(&VaultResponse::Epoch(1 << 53)).is_err());
}

/// ADR-009 "Format", I-17: the claims encoder writes the reference body,
/// and the parser reads it back. Any other spelling is refused.
#[test]
fn i17_ticket_claims_have_one_spelling() {
    fstp_prop::check("i17_ticket_claims_have_one_spelling", |g: &mut Gen| {
        let kinds = [
            "release",
            "write:country_stated",
            "write:guardian_consent",
            "write:partner_staff_declared",
        ];
        let kind = *g.pick(&kinds);
        let r = RTicket {
            kind: kind.to_owned(),
            cell: [g.u8(); 16],
            account: u128::from(g.u64()),
            proposal: g.option(|g| u128::from(g.u64())),
            scope: format!("programme:{}", g.u8()),
            issued_at: g.i64_in(0..=1 << 50),
            expires_at: g.i64_in(0..=1 << 50),
            nonce: [g.u8(); 16],
        };
        let c = TicketClaims {
            kind: TicketKind::from_label(kind).unwrap(),
            cell: r.cell,
            account: WireAccount(r.account),
            proposal: r.proposal.map(WireProposal),
            scope: r.scope.clone(),
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            nonce: r.nonce,
        };
        prop_assert_eq!(c.canonical(), Ok(r.body()));
        prop_assert_eq!(TicketClaims::parse(&r.body()), Ok(c));
        let spaced = String::from_utf8(r.body()).unwrap().replacen(':', ": ", 1);
        prop_assert!(TicketClaims::parse(spaced.as_bytes()).is_err());
        Ok(())
    });
}

/// ADR-009 "Write kinds": every write kind's label round-trips, and an
/// unknown label names no kind.
#[test]
fn i17_ticket_kind_labels_are_closed() {
    for k in WriteKind::ALL {
        let t = TicketKind::Write(k);
        assert_eq!(TicketKind::from_label(&t.label()), Some(t));
    }
    assert_eq!(TicketKind::from_label("release"), Some(TicketKind::Release));
    for bad in [
        "",
        "releases",
        "write:",
        "write:Country_stated",
        "write:seal",
    ] {
        assert_eq!(TicketKind::from_label(bad), None, "{bad}");
    }
}
