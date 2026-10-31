//! `fstp_vault_proto::decode_request` (design section 6.2, TH-26, H-05,
//! ADR-006, NOTE 3, NOTE 4).
//!
//! The encoding is the one `common::wire` writes: canonical JSON with a
//! `type` member, W1c's query arguments and fact bodies, ids as decimal
//! strings and amounts as ADR-006 strings. A decoder accepts exactly the
//! reference spelling of each request, so every accepted input has one
//! spelling and re-encodes byte for byte.
//!
//! Every refusal test first decodes a valid twin, so a decoder that
//! refuses everything (the W0 stub) fails each test.
//!
//! Gaps (lane report): `ProtoError` has only `NotImplemented`, so these
//! tests can tell a typed refusal from the stub but not one refusal from
//! another. The crate has no encoders yet. `fstp-cell` and `fstp-vault`
//! need `encode_request` and `encode_response`, and these tests then also
//! check them against `common::wire`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::wire::{self, RQuery, kind};
use common::{ask_with, gen_query, gen_request, is_stub, non_canonical, raw_query, shown};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_proto::{
    RelationshipKind, VaultRequest, WireAccount, WireProgramme, WireProposal, decode_request,
};

/// A link of 32 bytes `0x00, 0x01, ...`.
fn link() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    out
}

const LINK_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Decodes `bytes` and asserts the result.
#[track_caller]
fn decodes(bytes: &[u8], want: &VaultRequest) {
    assert_eq!(
        decode_request(bytes).as_ref(),
        Ok(want),
        "{}",
        String::from_utf8_lossy(bytes)
    );
}

/// Asserts that `bytes` is refused with a typed refusal, not the stub.
#[track_caller]
fn refused(what: &str, bytes: &[u8]) {
    match decode_request(bytes) {
        Err(e) if !is_stub(&e) => {}
        other => panic!(
            "{what}: {:?} must be refused, got {other:?}",
            String::from_utf8_lossy(bytes)
        ),
    }
}

/// The valid twin every refusal table starts from.
#[track_caller]
fn control() {
    decodes(
        format!("{{\"epoch\":1,\"ledger_seq\":2,\"link\":\"{LINK_HEX}\",\"type\":\"ack\"}}")
            .as_bytes(),
        &VaultRequest::Ack {
            epoch: 1,
            ledger_seq: 2,
            link: link(),
        },
    );
}

/// Design section 6.2: one golden vector per request variant.
#[test]
fn th_26_vault_request_golden_vectors_decode() {
    decodes(b"{\"type\":\"epoch\"}", &VaultRequest::Epoch);
    decodes(
        b"{\"at\":1700000000000000,\"queries\":[{\"args\":{\"account\":\"7\"},\"kind\":0},{\"args\":{\"epoch\":3},\"kind\":10}],\"reaction_for\":4,\"type\":\"ask\"}",
        &VaultRequest::Ask {
            at: 1_700_000_000_000_000,
            reaction_for: Some(4),
            queries: vec![
                raw_query(kind::IS_VERIFIED, "{\"account\":\"7\"}"),
                raw_query(kind::CHANGED_SINCE, "{\"epoch\":3}"),
            ],
        },
    );
    decodes(
        b"{\"at\":0,\"queries\":[],\"reaction_for\":null,\"type\":\"ask\"}",
        &VaultRequest::Ask {
            at: 0,
            reaction_for: None,
            queries: vec![],
        },
    );
    control();
    decodes(
        b"{\"accounts\":[\"1\",\"9\",\"10\"],\"ledger_seq\":12,\"proposal\":\"5\",\"type\":\"negotiation_opened\"}",
        &VaultRequest::NegotiationOpened {
            proposal: WireProposal(5),
            accounts: vec![WireAccount(1), WireAccount(9), WireAccount(10)],
            ledger_seq: 12,
        },
    );
    decodes(
        b"{\"ledger_seq\":13,\"proposal\":\"5\",\"type\":\"negotiation_closed\"}",
        &VaultRequest::NegotiationClosed {
            proposal: WireProposal(5),
            ledger_seq: 13,
        },
    );
    decodes(
        b"{\"a\":\"1\",\"b\":\"2\",\"kind\":\"conflict\",\"ledger_seq\":14,\"programme\":\"3\",\"type\":\"record_relationship\"}",
        &VaultRequest::RecordRelationship {
            a: WireAccount(1),
            b: WireAccount(2),
            kind: RelationshipKind::Conflict,
            programme: WireProgramme(3),
            ledger_seq: 14,
        },
    );
}

/// Design section 6.2, H-05: every request the reference encodes decodes
/// to itself, including ids at the `u128` bounds and amounts at the
/// ADR-006 bounds.
#[test]
fn th_26_vault_request_round_trips_through_the_reference_encoding() {
    fstp_prop::check(
        "th_26_vault_request_round_trips_through_the_reference_encoding",
        |g: &mut Gen| {
            let r = gen_request(g);
            let bytes = wire::request(&r);
            g.note("bytes", &String::from_utf8_lossy(&bytes));
            prop_assert_eq!(decode_request(&bytes), Ok(r));
            Ok(())
        },
    );
}

/// TH-26, H-05: one spelling. White space, a trailing byte, an escape, an
/// unknown member and a repeated member are each refused, while the
/// canonical twin decodes.
#[test]
fn th_26_vault_request_refuses_non_canonical_spellings() {
    fstp_prop::check(
        "th_26_vault_request_refuses_non_canonical_spellings",
        |g: &mut Gen| {
            let r = gen_request(g);
            let bytes = wire::request(&r);
            prop_assert_eq!(decode_request(&bytes), Ok(r), "the canonical twin");
            for (what, b) in non_canonical(&bytes) {
                let got = decode_request(&b);
                prop_assert!(
                    matches!(&got, Err(e) if !is_stub(e)),
                    "{what}: {:?} decoded as {}",
                    String::from_utf8_lossy(&b),
                    shown(&got)
                );
            }
            Ok(())
        },
    );
}

/// TH-26: malformed requests are refused with a typed error and never
/// panic. Each line breaks one rule of the encoding.
#[test]
fn th_26_vault_request_refuses_malformed_input() {
    control();
    let ack = |epoch: &str, seq: &str, link: &str| {
        format!("{{\"epoch\":{epoch},\"ledger_seq\":{seq},\"link\":\"{link}\",\"type\":\"ack\"}}")
    };
    let opened = |accounts: &str| {
        format!(
            "{{\"accounts\":{accounts},\"ledger_seq\":1,\"proposal\":\"5\",\"type\":\"negotiation_opened\"}}"
        )
    };
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("null", "null".to_owned()),
        ("array", "[]".to_owned()),
        ("no type", "{}".to_owned()),
        ("type case", "{\"type\":\"Epoch\"}".to_owned()),
        ("unknown type", "{\"type\":\"seal\"}".to_owned()),
        ("type not a string", "{\"type\":1}".to_owned()),
        ("short link", ack("1", "2", &LINK_HEX[1..])),
        ("long link", ack("1", "2", &format!("{LINK_HEX}0"))),
        ("upper hex link", ack("1", "2", &LINK_HEX.to_uppercase())),
        ("non-hex link", ack("1", "2", &LINK_HEX.replacen('0', "g", 1))),
        ("leading zero", ack("01", "2", LINK_HEX)),
        ("negative epoch", ack("-1", "2", LINK_HEX)),
        ("fraction", ack("1.0", "2", LINK_HEX)),
        ("exponent", ack("1e0", "2", LINK_HEX)),
        ("beyond 2^53 - 1", ack("9007199254740992", "2", LINK_HEX)),
        ("u64 overflow", ack("18446744073709551616", "2", LINK_HEX)),
        ("epoch as string", ack("\"1\"", "2", LINK_HEX)),
        (
            "missing member",
            format!("{{\"epoch\":1,\"link\":\"{LINK_HEX}\",\"type\":\"ack\"}}"),
        ),
        (
            "members out of order",
            format!("{{\"ledger_seq\":2,\"epoch\":1,\"link\":\"{LINK_HEX}\",\"type\":\"ack\"}}"),
        ),
        ("unsorted set", opened("[\"2\",\"1\"]")),
        ("repeated set member", opened("[\"1\",\"1\"]")),
        ("id leading zero", opened("[\"01\"]")),
        ("id as number", opened("[1]")),
        ("id with plus", opened("[\"+1\"]")),
        ("id with minus", opened("[\"-1\"]")),
        ("empty id", opened("[\"\"]")),
        (
            "u128 overflow",
            opened("[\"340282366920938463463374607431768211456\"]"),
        ),
        (
            "reaction_for as string",
            "{\"at\":1,\"queries\":[],\"reaction_for\":\"1\",\"type\":\"ask\"}".to_owned(),
        ),
        (
            "queries not an array",
            "{\"at\":1,\"queries\":{},\"reaction_for\":null,\"type\":\"ask\"}".to_owned(),
        ),
        (
            "query without args",
            "{\"at\":1,\"queries\":[{\"kind\":0}],\"reaction_for\":null,\"type\":\"ask\"}"
                .to_owned(),
        ),
        (
            "args not an object",
            "{\"at\":1,\"queries\":[{\"args\":\"7\",\"kind\":0}],\"reaction_for\":null,\"type\":\"ask\"}"
                .to_owned(),
        ),
        ("deep nesting", "[".repeat(100_000)),
    ];
    for (what, text) in &cases {
        refused(what, text.as_bytes());
    }
    refused("not UTF-8", b"{\"type\":\"epoch\xff\"}");
}

/// Design section 6.2: a query kind outside `QueryKind::ALL` is refused,
/// with valid `IsVerified` arguments.
#[test]
fn th_26_vault_request_refuses_an_unknown_query_kind() {
    let args = "{\"account\":\"7\"}";
    decodes(
        &ask_with(kind::IS_VERIFIED, args),
        &VaultRequest::Ask {
            at: 1,
            reaction_for: None,
            queries: vec![raw_query(kind::IS_VERIFIED, args)],
        },
    );
    for k in [kind::COUNT, 255, u16::MAX] {
        refused(&format!("kind {k}"), &ask_with(k, args));
    }
    refused(
        "kind beyond u16",
        b"{\"at\":1,\"queries\":[{\"args\":{\"account\":\"7\"},\"kind\":65536}],\"reaction_for\":null,\"type\":\"ask\"}",
    );
}

/// Design section 6.2: the arguments must be those of the query's own
/// kind. No two kinds share a member set, so arguments under another
/// kind's code are always refused.
#[test]
fn th_26_vault_request_query_args_must_match_their_kind() {
    fstp_prop::check(
        "th_26_vault_request_query_args_must_match_their_kind",
        |g: &mut Gen| {
            let q = gen_query(g);
            let other = g.u16_in(0..=(kind::COUNT - 1));
            g.assume(other != q.kind());
            let good = ask_with(q.kind(), &q.args());
            prop_assert!(decode_request(&good).is_ok(), "the twin {q:?}");
            let got = decode_request(&ask_with(other, &q.args()));
            prop_assert!(
                matches!(&got, Err(e) if !is_stub(e)),
                "args of {q:?} under kind {other}: {}",
                shown(&got)
            );
            Ok(())
        },
    );
}

/// ADR-006, design section 6.2: amounts cross as exact ADR-006 strings
/// with their currency. Every other spelling is refused, never normalised.
#[test]
fn adr006_vault_request_amounts_are_exact_strings() {
    let cap = |amount: &str| {
        format!(
            "{{\"cap\":{amount},\"committed\":{{\"1\":{{\"amount\":\"1.00\",\"currency\":\"EUR\"}}}}}}"
        )
    };
    let eur = |text: &str| format!("{{\"amount\":\"{text}\",\"currency\":\"EUR\"}}");
    for good in ["0.00", "0.01", "1234.50", "9999999999999999.99"] {
        let args = cap(&eur(good));
        decodes(
            &ask_with(kind::ALL_RECIPIENTS_WITHIN_CAP, &args),
            &VaultRequest::Ask {
                at: 1,
                reaction_for: None,
                queries: vec![raw_query(kind::ALL_RECIPIENTS_WITHIN_CAP, &args)],
            },
        );
    }
    let bad: Vec<(&str, String)> = vec![
        ("one fraction digit", eur("1234.5")),
        ("three fraction digits", eur("1234.500")),
        ("no fraction", eur("1234")),
        ("leading zero", eur("01.00")),
        ("minus", eur("-1.00")),
        ("plus", eur("+1.00")),
        ("exponent", eur("1e3")),
        ("comma", eur("1,00")),
        ("space", eur(" 1.00")),
        ("beyond the ADR-006 maximum", eur("10000000000000000.00")),
        (
            "number",
            "{\"amount\":1234.50,\"currency\":\"EUR\"}".to_owned(),
        ),
        (
            "lower case currency",
            "{\"amount\":\"1.00\",\"currency\":\"eur\"}".to_owned(),
        ),
        (
            "unknown currency",
            "{\"amount\":\"1.00\",\"currency\":\"USD\"}".to_owned(),
        ),
        ("no currency", "{\"amount\":\"1.00\"}".to_owned()),
        ("bare string", "\"1.00\"".to_owned()),
    ];
    for (what, amount) in &bad {
        refused(
            what,
            &ask_with(kind::ALL_RECIPIENTS_WITHIN_CAP, &cap(amount)),
        );
    }
}

/// ADR-006, RFC 8785: the members of a `committed` map follow the byte
/// order of their keys, so `"10"` precedes `"9"`. The account order is
/// another spelling and is refused.
///
/// Reading, in the lane report: W1c's `reference::vault::wire::query`
/// writes account order, which differs here.
#[test]
fn adr006_committed_members_follow_rfc_8785_key_order() {
    let q = RQuery::AllRecipientsWithinCap {
        committed: [(9, 100), (10, 200)].into_iter().collect(),
        cap: 500,
    };
    let args = q.args();
    assert!(
        args.contains("{\"10\":"),
        "the reference writes key order: {args}"
    );
    decodes(
        &ask_with(q.kind(), &args),
        &VaultRequest::Ask {
            at: 1,
            reaction_for: None,
            queries: vec![q.wire()],
        },
    );
    let account_order = "{\"cap\":{\"amount\":\"5.00\",\"currency\":\"EUR\"},\"committed\":{\"9\":{\"amount\":\"1.00\",\"currency\":\"EUR\"},\"10\":{\"amount\":\"2.00\",\"currency\":\"EUR\"}}}";
    refused(
        "account order",
        &ask_with(kind::ALL_RECIPIENTS_WITHIN_CAP, account_order),
    );
}
