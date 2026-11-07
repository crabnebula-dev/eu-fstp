//! The two M5 vault queries on the wire (M5 design 12.1, Q1 A): codes 11
//! and 12, with the arguments `fstp_celltest::reference::vault::wire`
//! spells, and one bit per answer (I-33, I-86, R-PR-04, R-PR-05).

#![allow(clippy::unwrap_used, reason = "test code")]

use fstp_vault_proto::{
    Query, QueryKind, VaultRequest, WireAccount, WireAnswer, WireEvidence, WireProposal, WireQuery,
    check_answers, decode_query, decode_request, encode_request,
};

fn wq(kind: u16, args: &str) -> WireQuery {
    WireQuery {
        kind,
        args: args.as_bytes().to_vec(),
    }
}

/// I-33, Q1 A: `BankReleasable` is code 11 and `HardshipEvidenceVerified`
/// code 12, the indexes of the domain's `QueryKind::ALL`.
#[test]
fn i_33_bank_and_hardship_queries_take_codes_11_and_12() {
    assert_eq!(QueryKind::BankReleasable.code(), 11);
    assert_eq!(QueryKind::HardshipEvidenceVerified.code(), 12);
    assert_eq!(QueryKind::from_code(11), Some(QueryKind::BankReleasable));
    assert_eq!(
        QueryKind::from_code(12),
        Some(QueryKind::HardshipEvidenceVerified)
    );
    assert_eq!(QueryKind::from_code(13), None);
}

/// I-33: the arguments are the reference spelling, and they round-trip.
#[test]
fn i_33_bank_releasable_args_round_trip_in_the_reference_spelling() {
    let q = Query::BankReleasable {
        grant: WireProposal(42),
        at: -5,
        hold: 7,
    };
    let w = q.to_wire().unwrap();
    assert_eq!(w.kind, 11);
    assert_eq!(w.args, b"{\"at\":-5,\"grant\":\"42\",\"hold\":7}");
    assert_eq!(decode_query(&w).unwrap(), q);
    let h = Query::HardshipEvidenceVerified {
        grant: WireProposal(42),
        evidence: WireEvidence(9),
    };
    let w = h.to_wire().unwrap();
    assert_eq!(w.kind, 12);
    assert_eq!(w.args, b"{\"evidence\":\"9\",\"grant\":\"42\"}");
    assert_eq!(decode_query(&w).unwrap(), h);
}

/// I-33: an ask that carries both queries encodes and decodes, and wrong
/// members, a hold beyond u16 or another kind's arguments are refused.
#[test]
fn i_33_bank_query_args_are_checked_against_their_kind() {
    let ask = VaultRequest::Ask {
        at: 1,
        reaction_for: None,
        queries: vec![
            wq(11, "{\"at\":1,\"grant\":\"3\",\"hold\":7}"),
            wq(12, "{\"evidence\":\"4\",\"grant\":\"3\"}"),
        ],
    };
    let bytes = encode_request(&ask).unwrap();
    assert_eq!(decode_request(&bytes).unwrap(), ask);
    for (kind, args) in [
        (11, "{\"at\":1,\"grant\":\"3\"}"),
        (11, "{\"at\":1,\"grant\":\"3\",\"hold\":65536}"),
        (11, "{\"at\":1,\"grant\":\"3\",\"hold\":-1}"),
        (12, "{\"grant\":\"3\"}"),
        (12, "{\"account\":\"7\"}"),
        (11, "{\"evidence\":\"4\",\"grant\":\"3\"}"),
    ] {
        assert!(decode_query(&wq(kind, args)).is_err(), "{kind} {args}");
    }
}

/// I-86, Q1 A: each answer is one bit and names no account. An answer
/// with an account set is refused for either query.
#[test]
fn i_86_bank_and_hardship_answers_carry_no_account() {
    let qs = [
        wq(11, "{\"at\":1,\"grant\":\"3\",\"hold\":7}"),
        wq(12, "{\"evidence\":\"4\",\"grant\":\"3\"}"),
    ];
    let bit = |holds| WireAnswer {
        holds,
        accounts: None,
        epoch: 1,
    };
    assert!(check_answers(&qs, &[bit(true), bit(false)]).is_ok());
    for i in 0..2 {
        let mut answers = vec![bit(true), bit(true)];
        if let Some(a) = answers.get_mut(i) {
            a.accounts = Some(vec![WireAccount(1)]);
        }
        assert!(check_answers(&qs, &answers).is_err(), "answer {i}");
    }
}
