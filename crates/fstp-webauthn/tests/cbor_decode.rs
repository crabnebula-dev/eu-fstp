//! The strict CBOR subset of `fstp_webauthn::cbor::decode` (ADR-008
//! "WebAuthn subset", design section 8.1, TH-26).
//!
//! ADR-008 admits definite lengths, shortest form, no tags, no floats, no
//! duplicate map keys, depth at most 4 and input at most 64 KiB. ADR-008
//! implements only what the platform uses, and `Item` has no variant for
//! simple values, so `false`, `true`, `null` and `undefined` are refused
//! as well.
//!
//! Depth reading used here: a scalar has depth 0, and an array or map has
//! one more than its deepest member. So four nested arrays are depth 4.
//!
//! Every refusal must be a real refusal. A `NotImplemented` from the W0
//! stub fails the test (`common::refused`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::cbor::{self, depth, encode, encode_widened, head_count, nested_arrays, nested_maps};
use common::{assert_refused, refused};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_webauthn::WebAuthnError;
use fstp_webauthn::cbor::{Item, decode};

/// ADR-008: the input limit, 64 KiB.
const MAX_INPUT: usize = 64 * 1024;

/// ADR-008: the depth limit.
const MAX_DEPTH: usize = 4;

/// A scalar map key.
fn gen_key(g: &mut Gen) -> Item {
    match g.u8_in(0..=2) {
        0 => Item::Unsigned(g.u64()),
        1 => Item::Negative(g.u64()),
        _ => Item::Text(g.string(0..=8)),
    }
}

/// An item of depth at most `room`, with distinct keys in every map.
fn gen_item(g: &mut Gen, room: usize) -> Item {
    let kinds = if room == 0 { 3 } else { 5 };
    match g.u8_in(0..=kinds) {
        0 => Item::Unsigned(g.u64()),
        1 => Item::Negative(g.u64()),
        2 => Item::Bytes(g.bytes(0..=40)),
        3 => Item::Text(g.string(0..=12)),
        4 => Item::Array(g.vec(0..=3, |g| gen_item(g, room - 1))),
        _ => {
            let pairs = g.vec(0..=3, |g| (gen_key(g), gen_item(g, room - 1)));
            Item::Map(distinct(pairs))
        }
    }
}

/// `pairs` with every repeated key after the first dropped, sorted in the
/// CTAP2 canonical key order (shorter encoded key first, then bytewise).
/// ADR-008 neither requires nor forbids that order, so the generated
/// inputs keep to it and the tests hold under either reading.
fn distinct(pairs: Vec<(Item, Item)>) -> Vec<(Item, Item)> {
    let mut out: Vec<(Item, Item)> = Vec::new();
    for (k, v) in pairs {
        if !out.iter().any(|(seen, _)| *seen == k) {
            out.push((k, v));
        }
    }
    out.sort_by_key(|(k, _)| {
        let e = encode(k);
        (e.len(), e)
    });
    out
}

/// Whether any map in `item` repeats a key.
fn has_duplicate_key(item: &Item) -> bool {
    match item {
        Item::Array(items) => items.iter().any(has_duplicate_key),
        Item::Map(pairs) => {
            pairs
                .iter()
                .enumerate()
                .any(|(i, (k, _))| pairs[..i].iter().any(|(seen, _)| seen == k))
                || pairs
                    .iter()
                    .any(|(k, v)| has_duplicate_key(k) || has_duplicate_key(v))
        }
        _ => false,
    }
}

/// The ADR-008 predicate on an accepted input: it is at most 64 KiB, the
/// item is at most depth 4, no map repeats a key, and the shortest
/// definite encoding of the item is the input byte for byte.
fn canonical(input: &[u8], item: &Item) -> Result<(), String> {
    prop_assert!(input.len() <= MAX_INPUT, "accepted {} bytes", input.len());
    prop_assert!(depth(item) <= MAX_DEPTH, "accepted depth {}", depth(item));
    prop_assert!(!has_duplicate_key(item), "accepted a duplicate key");
    prop_assert_eq!(encode(item), input.to_vec());
    Ok(())
}

/// ADR-008: each major type of the subset decodes to its item, at every
/// head width, including the bounds of each width.
#[test]
fn adr008_cbor_decodes_each_major_type_of_the_subset() {
    let cases: Vec<(Vec<u8>, Item)> = vec![
        (vec![0x00], Item::Unsigned(0)),
        (vec![0x17], Item::Unsigned(23)),
        (vec![0x18, 0x18], Item::Unsigned(24)),
        (vec![0x18, 0xff], Item::Unsigned(255)),
        (vec![0x19, 0x01, 0x00], Item::Unsigned(256)),
        (vec![0x19, 0xff, 0xff], Item::Unsigned(65_535)),
        (vec![0x1a, 0x00, 0x01, 0x00, 0x00], Item::Unsigned(65_536)),
        (
            vec![0x1a, 0xff, 0xff, 0xff, 0xff],
            Item::Unsigned(u64::from(u32::MAX)),
        ),
        (
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            Item::Unsigned(1 << 32),
        ),
        (
            vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            Item::Unsigned(u64::MAX),
        ),
        (vec![0x20], Item::Negative(0)),
        (vec![0x37], Item::Negative(23)),
        (vec![0x38, 0x63], Item::Negative(99)),
        (vec![0x39, 0x01, 0x00], Item::Negative(256)),
        (
            vec![0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            Item::Negative(u64::MAX),
        ),
        (vec![0x40], Item::Bytes(vec![])),
        (vec![0x43, 0x01, 0x02, 0x03], Item::Bytes(vec![1, 2, 3])),
        (vec![0x60], Item::Text(String::new())),
        (vec![0x63, b'f', b'm', b't'], Item::Text("fmt".to_owned())),
        (vec![0x62, 0xc3, 0xa9], Item::Text("\u{e9}".to_owned())),
        (vec![0x80], Item::Array(vec![])),
        (
            vec![0x82, 0x01, 0x20],
            Item::Array(vec![Item::Unsigned(1), Item::Negative(0)]),
        ),
        (vec![0xa0], Item::Map(vec![])),
        (
            vec![0xa2, 0x01, 0x02, 0x20, 0x41, 0x07],
            Item::Map(vec![
                (Item::Unsigned(1), Item::Unsigned(2)),
                (Item::Negative(0), Item::Bytes(vec![7])),
            ]),
        ),
    ];
    for (input, want) in cases {
        assert_eq!(decode(&input), Ok(want), "input {input:02x?}");
    }
}

/// ADR-008: every generated item of the subset decodes from its shortest
/// definite encoding to itself.
#[test]
fn adr008_cbor_round_trips_generated_items() {
    check("adr008_cbor_round_trips_generated_items", |g| {
        let item = gen_item(g, MAX_DEPTH);
        let input = encode(&item);
        g.note("input", &input);
        prop_assert_eq!(decode(&input), Ok(item));
        Ok(())
    });
}

/// ADR-008 "shortest form": a head written wider than it needs is
/// refused, for each major type and each width.
#[test]
fn adr008_cbor_refuses_non_shortest_heads() {
    let cases: [&[u8]; 14] = [
        &[0x18, 0x17],
        &[0x18, 0x00],
        &[0x19, 0x00, 0xff],
        &[0x1a, 0x00, 0x00, 0xff, 0xff],
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        &[0x38, 0x00],
        &[0x39, 0x00, 0x10],
        &[0x58, 0x00],
        &[0x59, 0x00, 0x01, 0xaa],
        &[0x78, 0x01, b'a'],
        &[0x98, 0x00],
        &[0xb8, 0x00],
        &[0x9a, 0x00, 0x00, 0x00, 0x01, 0x00],
        &[0xb9, 0x00, 0x01, 0x00, 0x00],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// ADR-008 "shortest form": widening any one head of a generated item is
/// refused.
#[test]
fn adr008_cbor_refuses_every_widened_head_of_generated_items() {
    check(
        "adr008_cbor_refuses_every_widened_head_of_generated_items",
        |g| {
            let item = gen_item(g, MAX_DEPTH);
            let k = g.usize_in(0..=head_count(&item) - 1);
            let widened = encode_widened(&item, k);
            g.assume(widened.is_some());
            let input = widened.unwrap_or_default();
            g.note("input", &input);
            refused("widened head", &decode(&input))
        },
    );
}

/// ADR-008 "definite lengths": indefinite-length strings, arrays and
/// maps, and a lone break, are refused.
#[test]
fn adr008_cbor_refuses_indefinite_lengths() {
    let cases: [&[u8]; 6] = [
        &[0x5f, 0x41, 0x00, 0xff],
        &[0x7f, 0x61, b'a', 0xff],
        &[0x9f, 0xff],
        &[0x9f, 0x01, 0xff],
        &[0xbf, 0x01, 0x02, 0xff],
        &[0xff],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// ADR-008 "definite lengths": a lone break, at the top or inside a
/// definite container, is refused as `Indefinite`, as `CborError`
/// documents. It is not reported as a float or simple value.
#[test]
fn adr008_cbor_reports_a_lone_break_as_indefinite() {
    use fstp_webauthn::CborError;
    let cases: [&[u8]; 3] = [&[0xff], &[0x81, 0xff], &[0xa1, 0x01, 0xff]];
    for input in cases {
        assert_eq!(
            decode(input),
            Err(WebAuthnError::Cbor(CborError::Indefinite)),
            "{input:02x?}"
        );
    }
}

/// ADR-008 "no tags": a tagged item is refused, whatever the tag.
#[test]
fn adr008_cbor_refuses_tags() {
    let cases: [&[u8]; 5] = [
        &[0xc0, 0x60],
        &[0xc2, 0x41, 0x01],
        &[0xd8, 0x18, 0x40],
        &[0xd9, 0xd9, 0xf7, 0x80],
        &[0x81, 0xc1, 0x00],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// ADR-008 "no floats": half, single and double precision are refused.
#[test]
fn adr008_cbor_refuses_floats() {
    let cases: [&[u8]; 4] = [
        &[0xf9, 0x00, 0x00],
        &[0xfa, 0x00, 0x00, 0x00, 0x00],
        &[0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0xa1, 0x01, 0xf9, 0x3c, 0x00],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// ADR-008 "only what the platform uses": `false`, `true`, `null`,
/// `undefined` and the other simple values are refused. No field the
/// crate reads takes one, and the platform requests no authenticator
/// extension whose output would (stricter reading, lane report).
#[test]
fn adr008_cbor_refuses_simple_values() {
    let cases: [&[u8]; 7] = [
        &[0xf4],
        &[0xf5],
        &[0xf6],
        &[0xf7],
        &[0xe0],
        &[0xf8, 0x20],
        &[0xa1, 0x01, 0xf5],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// TH-26: the reserved additional information values 28 to 30, and 31
/// on the integer types, are refused for every major type.
#[test]
fn th_26_cbor_refuses_reserved_additional_information() {
    for major in 0u8..8 {
        for ai in [28u8, 29, 30] {
            let input = [major << 5 | ai, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_refused(&format!("major {major} ai {ai}"), &decode(&input));
        }
    }
    for input in [[0x1f_u8], [0x3f]] {
        assert_refused(&format!("{input:02x?}"), &decode(&input));
    }
}

/// ADR-008 "no duplicate map keys": a repeated key is refused, with the
/// same or another value, for integer and text keys, at any depth.
#[test]
fn adr008_cbor_refuses_duplicate_map_keys() {
    let fmt = cbor::text("fmt");
    let cases: Vec<Vec<u8>> = vec![
        vec![0xa2, 0x01, 0x00, 0x01, 0x00],
        vec![0xa2, 0x01, 0x00, 0x01, 0x01],
        vec![0xa2, 0x20, 0x00, 0x20, 0x01],
        cbor::map(&[(fmt.clone(), cbor::int(0)), (fmt.clone(), cbor::int(1))]),
        cbor::map(&[
            (fmt.clone(), cbor::int(0)),
            (cbor::int(1), cbor::int(1)),
            (fmt, cbor::int(0)),
        ]),
        vec![0xa1, 0x00, 0xa2, 0x01, 0x00, 0x01, 0x00],
        vec![0x81, 0xa2, 0x05, 0x00, 0x05, 0x00],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(&input));
    }
}

/// ADR-008 "no duplicate map keys": repeating any key of a generated map
/// is refused.
#[test]
fn adr008_cbor_refuses_duplicate_keys_in_generated_maps() {
    check(
        "adr008_cbor_refuses_duplicate_keys_in_generated_maps",
        |g| {
            let mut pairs = distinct(g.vec(1..=3, |g| (gen_key(g), gen_item(g, MAX_DEPTH - 1))));
            let i = g.usize_in(0..=pairs.len() - 1);
            let repeat = (pairs[i].0.clone(), gen_item(g, MAX_DEPTH - 1));
            // Right after the original, so the keys stay in canonical order
            // and only the repetition is wrong.
            pairs.insert(i + 1, repeat);
            let input = encode(&Item::Map(pairs));
            g.note("input", &input);
            refused("duplicate key", &decode(&input))
        },
    );
}

/// ADR-008 "depth at most 4": four nested arrays or maps are accepted.
#[test]
fn adr008_cbor_accepts_depth_four() {
    let arrays = decode(&nested_arrays(MAX_DEPTH)).expect("four nested arrays");
    assert_eq!(depth(&arrays), MAX_DEPTH);
    let maps = decode(&nested_maps(MAX_DEPTH)).expect("four nested maps");
    assert_eq!(depth(&maps), MAX_DEPTH);
}

/// ADR-008 "depth at most 4": five nested containers are refused, as
/// arrays, maps, or both mixed, and with a scalar inside.
#[test]
fn adr008_cbor_refuses_depth_five() {
    let cases: Vec<Vec<u8>> = vec![
        nested_arrays(5),
        nested_maps(5),
        vec![0x81, 0xa1, 0x00, 0x81, 0xa1, 0x00, 0x80],
        vec![0x81, 0x81, 0x81, 0x81, 0x81, 0x00],
        vec![0x82, 0x00, 0x81, 0x81, 0x81, 0x81, 0x00],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(&input));
    }
}

/// TH-26: deep nesting within the size limit is refused without
/// exhausting the stack.
#[test]
fn th_26_cbor_deep_nesting_is_refused_without_overflow() {
    let mut arrays = vec![0x81; MAX_INPUT - 1];
    arrays.push(0x80);
    assert_refused("65 536 nested arrays", &decode(&arrays));
    let mut maps = [0xa1, 0x00].repeat(MAX_INPUT / 2 - 1);
    maps.push(0xa0);
    assert_refused("32 767 nested maps", &decode(&maps));
}

/// ADR-008 "at most 64 KiB": an item of exactly 65 536 bytes is accepted.
#[test]
fn adr008_cbor_accepts_input_of_exactly_64_kib() {
    // A byte string of 65 533 bytes has a 3-byte head.
    let input = cbor::bytes(&vec![0xab; MAX_INPUT - 3]);
    assert_eq!(input.len(), MAX_INPUT);
    assert_eq!(decode(&input), Ok(Item::Bytes(vec![0xab; MAX_INPUT - 3])));
}

/// ADR-008 "at most 64 KiB": one byte more is refused, whatever the item.
#[test]
fn adr008_cbor_refuses_input_over_64_kib() {
    let bytes = cbor::bytes(&vec![0xab; MAX_INPUT - 2]);
    assert_eq!(bytes.len(), MAX_INPUT + 1);
    assert_refused("a 65 537-byte byte string", &decode(&bytes));
    let text = cbor::text(&"a".repeat(MAX_INPUT - 2));
    assert_eq!(text.len(), MAX_INPUT + 1);
    assert_refused("a 65 537-byte text string", &decode(&text));
    let mut array = Vec::new();
    cbor::head(&mut array, cbor::ARRAY, (MAX_INPUT - 2) as u64);
    array.resize(MAX_INPUT + 1, 0x00);
    assert_refused("a 65 537-byte array", &decode(&array));
}

/// TH-26: a length or count beyond the input is refused at once, never
/// trusted for an allocation, and a truncated head is refused.
#[test]
fn th_26_cbor_refuses_lengths_beyond_the_input() {
    let cases: [&[u8]; 12] = [
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, b'a'],
        &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
        &[
            0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        ],
        &[0x5a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03],
        &[0x43, 0x01, 0x02],
        &[0x82, 0x01],
        &[0xa1, 0x01],
        &[0x18],
        &[0x19, 0x01],
        &[0x1a, 0x00, 0x01, 0x00],
        &[0x1b, 0x00, 0x00, 0x00, 0x01],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// ADR-008: `decode` reads exactly one item, so trailing bytes and empty
/// input are refused.
#[test]
fn adr008_cbor_refuses_trailing_bytes_and_empty_input() {
    let cases: [&[u8]; 4] = [&[], &[0x00, 0x00], &[0x80, 0x00], &[0xa0, 0xa0]];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// TH-26: text strings must be well-formed UTF-8. Invalid bytes, overlong
/// forms, surrogates and truncated sequences are refused.
#[test]
fn th_26_cbor_refuses_invalid_utf8_text() {
    let cases: [&[u8]; 5] = [
        &[0x62, 0xc3, 0x28],
        &[0x61, 0xff],
        &[0x62, 0xc0, 0x80],
        &[0x63, 0xed, 0xa0, 0x80],
        &[0x61, 0xc3],
    ];
    for input in cases {
        assert_refused(&format!("{input:02x?}"), &decode(input));
    }
}

/// TH-26 and ADR-008: one changed, dropped or added byte of a valid
/// encoding is either refused for a real reason, or decodes to an item
/// that meets the ADR-008 predicate (`canonical`).
#[test]
fn th_26_cbor_mutated_encodings_are_canonical_or_refused() {
    check(
        "th_26_cbor_mutated_encodings_are_canonical_or_refused",
        |g| {
            let mut input = encode(&gen_item(g, MAX_DEPTH));
            match g.u8_in(0..=2) {
                0 => {
                    let at = g.usize_in(0..=input.len() - 1);
                    input[at] ^= g.u8_in(1..=255);
                }
                1 => {
                    let at = g.usize_in(0..=input.len() - 1);
                    input.remove(at);
                }
                _ => {
                    let at = g.usize_in(0..=input.len());
                    input.insert(at, g.u8());
                }
            }
            g.note("input", &input);
            match decode(&input) {
                Ok(item) => canonical(&input, &item),
                Err(WebAuthnError::NotImplemented(op)) => {
                    Err(format!("{op} is the W0 stub; no input is decided"))
                }
                #[allow(
                    unreachable_patterns,
                    reason = "the W0 stub has only NotImplemented; W2a adds the refusal reasons"
                )]
                Err(_) => Ok(()),
            }
        },
    );
}
