//! `fstp_vault_proto::decode_response` (design section 6.2, NOTE 3,
//! NOTE 5, TH-26, H-05).
//!
//! Every answer is one bit, except `ChangedSince`, which lists account
//! ids and nothing else (`overview.md`). The decoder cannot see which
//! query an answer belongs to, so it enforces what the bytes show: an
//! account set is in ascending order, and the bit says whether it is
//! non-empty, as for `ChangedSince`. The cell pairs answers with queries
//! and refuses a set on any other kind.
//!
//! Every refusal test first decodes a valid twin, so a decoder that
//! refuses everything (the W0 stub) fails each test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::wire::{self, answer_is_lawful};
use common::{gen_response, gen_u64, is_stub, non_canonical, shown};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};
use fstp_vault_proto::{VaultRefusal, VaultResponse, WireAccount, WireAnswer, decode_response};

#[track_caller]
fn decodes(bytes: &[u8], want: &VaultResponse) {
    assert_eq!(
        decode_response(bytes).as_ref(),
        Ok(want),
        "{}",
        String::from_utf8_lossy(bytes)
    );
}

#[track_caller]
fn refused(what: &str, bytes: &[u8]) {
    match decode_response(bytes) {
        Err(e) if !is_stub(&e) => {}
        other => panic!(
            "{what}: {:?} must be refused, got {other:?}",
            String::from_utf8_lossy(bytes)
        ),
    }
}

fn answers(inner: &str) -> String {
    format!("{{\"answers\":[{inner}],\"type\":\"answers\"}}")
}

/// Design section 6.2: one golden vector per response and refusal variant.
#[test]
fn th_26_vault_response_golden_vectors_decode() {
    decodes(
        b"{\"epoch\":7,\"type\":\"epoch\"}",
        &VaultResponse::Epoch(7),
    );
    decodes(b"{\"type\":\"acked\"}", &VaultResponse::Acked);
    decodes(
        answers("{\"accounts\":null,\"epoch\":3,\"holds\":true},{\"accounts\":[\"1\",\"10\"],\"epoch\":3,\"holds\":true},{\"accounts\":[],\"epoch\":3,\"holds\":false}").as_bytes(),
        &VaultResponse::Answers(vec![
            WireAnswer {
                holds: true,
                accounts: None,
                epoch: 3,
            },
            WireAnswer {
                holds: true,
                accounts: Some(vec![WireAccount(1), WireAccount(10)]),
                epoch: 3,
            },
            WireAnswer {
                holds: false,
                accounts: Some(vec![]),
                epoch: 3,
            },
        ]),
    );
    let refusals = [
        (
            "{\"epoch\":4,\"type\":\"pending\"}",
            VaultRefusal::Pending { epoch: 4 },
        ),
        (
            "{\"current\":5,\"type\":\"stale_epoch\"}",
            VaultRefusal::StaleEpoch { current: 5 },
        ),
        ("{\"type\":\"not_this_cell\"}", VaultRefusal::NotThisCell),
        ("{\"type\":\"malformed\"}", VaultRefusal::Malformed),
        ("{\"type\":\"unavailable\"}", VaultRefusal::Unavailable),
    ];
    for (text, want) in refusals {
        decodes(
            format!("{{\"refusal\":{text},\"type\":\"refused\"}}").as_bytes(),
            &VaultResponse::Refused(want),
        );
    }
}

/// Design section 6.2, H-05: every response the reference encodes decodes
/// to itself.
#[test]
fn th_26_vault_response_round_trips_through_the_reference_encoding() {
    fstp_prop::check(
        "th_26_vault_response_round_trips_through_the_reference_encoding",
        |g: &mut Gen| {
            let r = gen_response(g);
            let bytes = wire::response(&r);
            g.note("bytes", &String::from_utf8_lossy(&bytes));
            prop_assert_eq!(decode_response(&bytes), Ok(r));
            Ok(())
        },
    );
}

/// TH-26, H-05: one spelling for every response.
#[test]
fn th_26_vault_response_refuses_non_canonical_spellings() {
    fstp_prop::check(
        "th_26_vault_response_refuses_non_canonical_spellings",
        |g: &mut Gen| {
            let r = gen_response(g);
            let bytes = wire::response(&r);
            prop_assert_eq!(decode_response(&bytes), Ok(r), "the canonical twin");
            for (what, b) in non_canonical(&bytes) {
                let got = decode_response(&b);
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

/// NOTE 5, design section 6.2: an answer that carries an account set
/// says by its bit whether the set is non-empty, and lists the set in
/// ascending order. A set that disagrees with its bit is refused.
#[test]
fn note5_one_bit_answers_carry_no_account_set() {
    let lawful = "{\"accounts\":[\"2\"],\"epoch\":1,\"holds\":true}";
    assert!(decode_response(answers(lawful).as_bytes()).is_ok());
    let cases = [
        (
            "a set under a no",
            "{\"accounts\":[\"2\"],\"epoch\":1,\"holds\":false}",
        ),
        (
            "an empty set under a yes",
            "{\"accounts\":[],\"epoch\":1,\"holds\":true}",
        ),
        (
            "an unsorted set",
            "{\"accounts\":[\"3\",\"2\"],\"epoch\":1,\"holds\":true}",
        ),
        (
            "a repeated member",
            "{\"accounts\":[\"2\",\"2\"],\"epoch\":1,\"holds\":true}",
        ),
    ];
    for (what, a) in cases {
        refused(what, answers(a).as_bytes());
    }
}

/// NOTE 5: whatever the decoder accepts keeps the one-bit rule, over
/// random answers with random bits and sets.
#[test]
fn note5_decoded_answers_keep_the_one_bit_rule() {
    fstp_prop::check(
        "note5_decoded_answers_keep_the_one_bit_rule",
        |g: &mut Gen| {
            let set: Vec<WireAccount> = g
                .vec(0..=3, |g| WireAccount(u128::from(g.u8_in(0..=4))))
                .into_iter()
                .collect();
            let a = WireAnswer {
                holds: g.bool(),
                accounts: g.option(|_| set.clone()),
                epoch: gen_u64(g),
            };
            let bytes = answers(&wire::answer(&a));
            let lawful = answer_is_lawful(&a);
            let got = decode_response(bytes.as_bytes());
            if lawful {
                prop_assert_eq!(got, Ok(VaultResponse::Answers(vec![a])));
            } else {
                prop_assert!(
                    matches!(&got, Err(e) if !is_stub(e)),
                    "an unlawful answer {a:?} decoded as {}",
                    shown(&got)
                );
            }
            Ok(())
        },
    );
}

/// TH-26: malformed responses are refused with a typed error.
#[test]
fn th_26_vault_response_refuses_malformed_input() {
    decodes(
        b"{\"epoch\":7,\"type\":\"epoch\"}",
        &VaultResponse::Epoch(7),
    );
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("unknown type", "{\"type\":\"ok\"}".to_owned()),
        (
            "negative epoch",
            "{\"epoch\":-7,\"type\":\"epoch\"}".to_owned(),
        ),
        (
            "epoch as string",
            "{\"epoch\":\"7\",\"type\":\"epoch\"}".to_owned(),
        ),
        (
            "unknown refusal",
            "{\"refusal\":{\"type\":\"busy\"},\"type\":\"refused\"}".to_owned(),
        ),
        (
            "refusal without its member",
            "{\"refusal\":{\"type\":\"pending\"},\"type\":\"refused\"}".to_owned(),
        ),
        (
            "bit as string",
            answers("{\"accounts\":null,\"epoch\":1,\"holds\":\"true\"}"),
        ),
        (
            "bit as number",
            answers("{\"accounts\":null,\"epoch\":1,\"holds\":1}"),
        ),
        (
            "answer without bit",
            answers("{\"accounts\":null,\"epoch\":1}"),
        ),
        (
            "answer without epoch",
            answers("{\"accounts\":null,\"holds\":true}"),
        ),
        (
            "an attribute beside the bit",
            answers("{\"accounts\":null,\"country\":\"FR\",\"epoch\":1,\"holds\":true}"),
        ),
        ("deep nesting", "{\"answers\":".repeat(50_000)),
    ];
    for (what, text) in &cases {
        refused(what, text.as_bytes());
    }
}

/// NOTE 5, design section 6.2: `answers_for` pairs answers with their
/// queries. It refuses a count mismatch, an account set on a one-bit
/// answer, a `ChangedSince` answer with no set, and a response that holds
/// no answers.
#[test]
fn note5_answers_for_pairs_answers_with_their_queries() {
    use fstp_vault_proto::answers_for;
    let one_bit = wire::RQuery::IsVerified { account: 7 }.wire();
    let changed = wire::RQuery::ChangedSince { epoch: 0 }.wire();
    let bit = WireAnswer {
        holds: true,
        accounts: None,
        epoch: 3,
    };
    let set = WireAnswer {
        holds: true,
        accounts: Some(vec![WireAccount(7)]),
        epoch: 3,
    };
    let queries = [one_bit.clone(), changed.clone()];
    let good = VaultResponse::Answers(vec![bit.clone(), set.clone()]);
    assert_eq!(
        answers_for(&queries, &good).map(<[WireAnswer]>::to_vec),
        Ok(vec![bit.clone(), set.clone()])
    );
    for bad in [
        VaultResponse::Answers(vec![bit.clone()]),
        VaultResponse::Answers(vec![set.clone(), set.clone()]),
        VaultResponse::Answers(vec![bit.clone(), bit.clone()]),
        VaultResponse::Acked,
        VaultResponse::Refused(VaultRefusal::Malformed),
    ] {
        assert!(answers_for(&queries, &bad).is_err(), "{bad:?} was paired");
    }
}

/// NOTE 2, NOTE 5: every response `encode_response` writes, the cell's
/// `decode_response` reads, up to the bound of account ids. Past the
/// bound the encoder refuses, so the vault never emits a reply its peer
/// cannot read.
#[test]
fn note5_encode_response_stays_within_what_decode_response_reads() {
    use fstp_vault_proto::{MAX_ANSWER_ACCOUNTS, encode_response};
    let answer = |n: usize| WireAnswer {
        holds: n > 0,
        accounts: Some(
            (0..n)
                .map(|i| WireAccount(u128::MAX - u128::try_from(i).unwrap()))
                .rev()
                .collect(),
        ),
        epoch: 9,
    };
    let full = VaultResponse::Answers(vec![answer(MAX_ANSWER_ACCOUNTS)]);
    let bytes = encode_response(&full).unwrap();
    assert_eq!(decode_response(&bytes), Ok(full));
    let over = VaultResponse::Answers(vec![answer(MAX_ANSWER_ACCOUNTS / 2 + 1); 2]);
    assert!(
        encode_response(&over).is_err(),
        "over the bound was encoded"
    );
}
