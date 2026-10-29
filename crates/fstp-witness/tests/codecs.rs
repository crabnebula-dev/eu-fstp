//! TH-26: the `fstp-witness` decoders of design section 15,
//! `witness_message_decode` (prepare, abort, in-doubt) and
//! `file_store_decode`.
//!
//! The design fixes neither layout, so the properties hold for any
//! one-spelling layout: round trip, one spelling, truncation refused,
//! trailing bytes refused, empty input refused. The file store is
//! append-only: a cut inside a record is detected, and a cut at a record
//! boundary keeps exactly the records before it (a crash between two
//! appends). Records keep strictly rising witness sequences.
//!
//! Red until lane W2g lands the encoders and the decoders.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::api::{self, Chain, FileRec, Hash, Msg, Prepare};
use common::codec::Codec;
use common::{answered, real_refusal};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The composite signature length of draft 19.
const SIG_LEN: usize = 3373;

const MESSAGE: Codec<Msg> = Codec {
    what: "witness message",
    encode: api::encode_message,
    decode: api::decode_message,
};

const FILE: Codec<Vec<FileRec>> = Codec {
    what: "file store",
    encode: enc_file,
    decode: api::decode_file_store,
};

#[allow(clippy::ptr_arg, reason = "the codec encodes a `Vec<FileRec>`")]
fn enc_file(rs: &Vec<FileRec>) -> Result<Vec<u8>, fstp_witness::WitnessError> {
    api::encode_file_store(rs)
}

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

fn gen_cell(g: &mut Gen) -> [u8; 16] {
    let mut c = [0u8; 16];
    for b in &mut c {
        *b = g.u8();
    }
    c
}

fn gen_msg(g: &mut Gen) -> Msg {
    let cell = gen_cell(g);
    let chain = *g.pick(&Chain::ALL);
    match g.u8_in(0..=2) {
        0 => {
            let prev_n = g.u64_in(0..=1_000);
            let stored_hashes = g.vec(1..=4, gen_hash);
            let n = prev_n + u64::try_from(stored_hashes.len()).unwrap();
            let mut signature = vec![0u8; SIG_LEN];
            signature[g.usize_in(0..=SIG_LEN - 1)] = g.u8();
            Msg::Prepare(Prepare {
                cell,
                chain,
                prev: (prev_n, gen_hash(g)),
                stored_hashes,
                n,
                link: gen_hash(g),
                at: g.i64(),
                signature,
            })
        }
        1 => Msg::Abort {
            cell,
            chain,
            n: g.u64_in(1..=u64::MAX),
            link: gen_hash(g),
        },
        _ => Msg::InDoubtAbsent {
            cell,
            chain,
            n: g.u64_in(1..=u64::MAX),
            link: gen_hash(g),
        },
    }
}

/// Up to six records with witness sequences rising from a random start.
fn gen_records(g: &mut Gen) -> Vec<FileRec> {
    let mut seq = g.u64_in(1..=1_000);
    g.vec(0..=6, |g| {
        let r = FileRec {
            witness_seq: seq,
            bytes: g.bytes(0..=48),
        };
        seq += g.u64_in(1..=3);
        r
    })
}

// ---------------------------------------------------------------------------
// Witness messages (`witness_message_decode`).

/// TH-26, I-24: a prepare, an abort and an in-doubt record round-trip.
#[test]
fn th_26_witness_message_round_trips() {
    check("th_26_witness_message_round_trips", |g| {
        MESSAGE.round_trip(&gen_msg(g))
    });
}

/// TH-26: one spelling per message. A changed byte never decodes to the
/// same message.
#[test]
fn th_26_witness_message_has_one_spelling() {
    check("th_26_witness_message_has_one_spelling", |g| {
        let m = gen_msg(g);
        MESSAGE.one_spelling_under_change(&m, g)
    });
}

/// TH-26: arbitrary bytes are refused for real or re-encode byte for
/// byte.
#[test]
fn th_26_witness_message_decode_of_arbitrary_bytes_has_one_spelling() {
    check(
        "th_26_witness_message_decode_of_arbitrary_bytes_has_one_spelling",
        |g| MESSAGE.one_spelling_on(&g.bytes(0..=160)),
    );
}

/// TH-26: every proper prefix of an encoded message is refused.
#[test]
fn th_26_witness_message_decode_refuses_every_truncation() {
    check(
        "th_26_witness_message_decode_refuses_every_truncation",
        |g| MESSAGE.refuses_prefixes(&gen_msg(g)),
    );
}

/// TH-26: an encoded message with trailing bytes is refused.
#[test]
fn th_26_witness_message_decode_refuses_trailing_bytes() {
    check("th_26_witness_message_decode_refuses_trailing_bytes", |g| {
        let m = gen_msg(g);
        let extra = g.bytes(1..=8);
        MESSAGE.refuses_trailing(&m, &extra)
    });
}

/// TH-26, I-24: a prepare with no rows, or whose `n` is not its previous
/// head plus its row count, is refused by the encoder or the decoder.
#[test]
fn th_26_witness_message_refuses_a_prepare_of_inconsistent_length() {
    check(
        "th_26_witness_message_refuses_a_prepare_of_inconsistent_length",
        |g| {
            let Msg::Prepare(mut p) = gen_msg(g) else {
                g.reject();
            };
            if g.bool() {
                p.stored_hashes.clear();
            } else {
                p.n += g.u64_in(1..=3);
            }
            let r = api::encode_message(&Msg::Prepare(p)).and_then(|b| api::decode_message(&b));
            real_refusal("inconsistent prepare", &r)
        },
    );
}

// ---------------------------------------------------------------------------
// The append-only file store (`file_store_decode`).

/// TH-26, I-24: a file store of records round-trips.
#[test]
fn th_26_file_store_round_trips() {
    check("th_26_file_store_round_trips", |g| {
        FILE.round_trip(&gen_records(g))
    });
}

/// TH-26: one spelling per file store.
#[test]
fn th_26_file_store_has_one_spelling() {
    check("th_26_file_store_has_one_spelling", |g| {
        let rs = gen_records(g);
        g.assume(!rs.is_empty());
        FILE.one_spelling_under_change(&rs, g)
    });
}

/// TH-26: arbitrary bytes are refused for real or re-encode byte for
/// byte.
#[test]
fn th_26_file_store_decode_of_arbitrary_bytes_has_one_spelling() {
    check(
        "th_26_file_store_decode_of_arbitrary_bytes_has_one_spelling",
        |g| FILE.one_spelling_on(&g.bytes(0..=160)),
    );
}

/// The offsets at which each record of `rs` ends, from the encoder.
fn boundaries(rs: &[FileRec]) -> Result<Vec<usize>, String> {
    (0..=rs.len())
        .map(|i| answered("encode", api::encode_file_store(&rs[..i])).map(|b| b.len()))
        .collect()
}

/// TH-26, design section 15 "truncated files detected": a file cut
/// inside a record is refused.
#[test]
fn th_26_file_store_detects_a_cut_inside_a_record() {
    check("th_26_file_store_detects_a_cut_inside_a_record", |g| {
        let rs = gen_records(g);
        let bytes = answered("encode", api::encode_file_store(&rs))?;
        let ends = boundaries(&rs)?;
        for cut in 0..bytes.len() {
            if ends.contains(&cut) {
                continue;
            }
            real_refusal(
                &format!("cut at {cut}"),
                &api::decode_file_store(&bytes[..cut]),
            )?;
        }
        Ok(())
    });
}

/// I-24: the store is append-only. A file cut at a record boundary holds
/// exactly the records before the cut, and each encoding of a prefix is
/// a prefix of the full encoding.
#[test]
fn i24_file_store_cut_at_a_record_boundary_keeps_the_records_before_it() {
    check(
        "i24_file_store_cut_at_a_record_boundary_keeps_the_records_before_it",
        |g| {
            let rs = gen_records(g);
            let bytes = answered("encode", api::encode_file_store(&rs))?;
            for (i, end) in boundaries(&rs)?.into_iter().enumerate() {
                prop_assert!(end <= bytes.len(), "prefix {} is longer than the file", i);
                let got = answered("decode", api::decode_file_store(&bytes[..end]))?;
                prop_assert_eq!(got, rs[..i].to_vec());
            }
            Ok(())
        },
    );
}

/// I-24: witness sequences in the store strictly rise. A record whose
/// sequence repeats or falls is refused by the encoder or the decoder.
#[test]
fn i24_file_store_refuses_a_sequence_that_does_not_rise() {
    check(
        "i24_file_store_refuses_a_sequence_that_does_not_rise",
        |g| {
            let mut rs = gen_records(g);
            g.assume(!rs.is_empty());
            let last = rs[rs.len() - 1].witness_seq;
            let seq = last - g.u64_in(0..=last.min(2));
            rs.push(FileRec {
                witness_seq: seq,
                bytes: g.bytes(0..=8),
            });
            let r = api::encode_file_store(&rs).and_then(|b| api::decode_file_store(&b));
            real_refusal(&format!("sequence {seq} after {last}"), &r)
        },
    );
}

/// TH-26: empty input is refused as a message, and the file decoder
/// gives a real answer for it, never a stub refusal.
#[test]
fn th_26_witness_decoders_on_empty_input() {
    let msg = real_refusal("empty message", &api::decode_message(&[]));
    let file = match api::decode_file_store(&[]) {
        Ok(rs) if rs.is_empty() => Ok(()),
        other => real_refusal("empty file store", &other),
    };
    assert_eq!((msg, file), (Ok(()), Ok(())));
}
