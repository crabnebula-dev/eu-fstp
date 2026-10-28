//! Composed decodings, case folding and identifier extraction of the
//! canary scanner (M3 design sections 14.1, 14.3 and 14.4, lane W1a).
//! Written by the W1a implementer in fix round 1, after review.
//!
//! The encoders here are written independently of `fstp_celltest::scan`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{CellDump, PublicConstants, StoreSet, scan, shared_identifiers};
use fstp_prop::{Gen, check};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    bytes
        .iter()
        .flat_map(|b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
        .collect()
}

fn gen_canary(g: &mut Gen) -> Canary {
    let kinds = CanaryKind::ALL;
    let kind = *g.pick(&kinds);
    let mut nonce = [0u8; 16];
    for b in &mut nonce {
        *b = g.u8();
    }
    Canary {
        cell: g.u8(),
        kind,
        nonce,
    }
}

/// A line break in one of the spellings a store can carry it in, with the
/// prefix and suffix that put the body in that context.
#[derive(Clone, Copy, Debug)]
enum Break {
    Lf,
    CrLf,
    JsonLf,
    JsonCrLf,
    PercentLf,
    PercentCrLf,
}

const BREAKS: [Break; 6] = [
    Break::Lf,
    Break::CrLf,
    Break::JsonLf,
    Break::JsonCrLf,
    Break::PercentLf,
    Break::PercentCrLf,
];

impl Break {
    fn spelling(self) -> &'static [u8] {
        match self {
            Break::Lf => b"\n",
            Break::CrLf => b"\r\n",
            Break::JsonLf => b"\\n",
            Break::JsonCrLf => b"\\r\\n",
            Break::PercentLf => b"%0A",
            Break::PercentCrLf => b"%0D%0A",
        }
    }

    fn frame(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Break::Lf | Break::CrLf => (b"-----BEGIN DATA-----\n", b"\n-----END DATA-----\n"),
            Break::JsonLf | Break::JsonCrLf => (b"{\"body\":\"", b"\"}"),
            Break::PercentLf | Break::PercentCrLf => (b"body=", b"&end=1"),
        }
    }
}

/// Design section 14.1: a canary in base64 or hex, wrapped at a random
/// width with any line-break spelling (real CR LF, JSON `\n`, `%0A`), is
/// found. The context before the canary moves it across the line breaks.
fn finds_wrapped_bodies(g: &mut Gen) -> Result<(), String> {
    let canary = gen_canary(g);
    let mut doc = g.ascii_string(0..=40).into_bytes();
    doc.retain(u8::is_ascii_alphanumeric);
    doc.extend_from_slice(canary.text().as_bytes());
    doc.extend_from_slice(b"-trailer");
    let body = match g.u8_in(0..=2) {
        0 => base64(&doc),
        1 => hex(&doc, false),
        _ => hex(&doc, true),
    };
    let width = g.usize_in(4..=80);
    let brk = *g.pick(&BREAKS);
    let (head, tail) = brk.frame();
    let mut store = head.to_vec();
    for (i, line) in body.chunks(width).enumerate() {
        if i > 0 {
            store.extend_from_slice(brk.spelling());
        }
        store.extend_from_slice(line);
    }
    store.extend_from_slice(tail);
    let mut set = StoreSet::default();
    set.push("wrapped", store);
    let report = scan(&set, std::slice::from_ref(&canary)).map_err(|e| format!("{e:?}"))?;
    if report.is_clean() {
        Err(format!("missed a body wrapped at {width} with {brk:?}"))
    } else {
        Ok(())
    }
}

/// I-17, I-19, I-38 instrument, design section 14.1: line-wrapped base64
/// and hex are found inside JSON strings and percent-encoded bodies too.
#[test]
fn harness_scan_finds_wrapped_bodies_with_every_line_break_spelling() {
    check(
        "harness_scan_finds_wrapped_bodies_with_every_line_break_spelling",
        finds_wrapped_bodies,
    );
}

/// Design sections 4.2 and 14.1: a component that lowercases a login
/// address writes the canary in lowercase. The scan still finds it.
#[test]
fn harness_scan_finds_a_lowercased_email_canary() {
    let canary = Canary::generate(3, CanaryKind::Email).unwrap();
    let mut set = StoreSet::default();
    set.push(
        "log",
        format!("login {}", canary.email_address().to_ascii_lowercase()).into_bytes(),
    );
    let report = scan(&set, std::slice::from_ref(&canary)).unwrap();
    assert_eq!(report.hits, vec![("log".to_owned(), canary.text())]);
}

/// Design section 14.1: an uppercased canary, base64-encoded, is found.
#[test]
fn harness_scan_finds_an_uppercased_canary_in_base64() {
    let canary = Canary::generate(3, CanaryKind::Name).unwrap();
    let mut set = StoreSet::default();
    set.push(
        "blob",
        base64(canary.text().to_ascii_uppercase().as_bytes()),
    );
    let report = scan(&set, std::slice::from_ref(&canary)).unwrap();
    assert_eq!(report.hits, vec![("blob".to_owned(), canary.text())]);
}

/// A 32-byte lookup key with every byte distinct.
fn lookup_key(seed: u8) -> Vec<u8> {
    (0u8..32)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// I-20 teeth, design section 14.4 (`i20_teeth_shared_lookup_key_is_caught`
/// shape): one lookup key stored as hex in cell A's store and as base64 in
/// cell B's store is a shared identifier of the two dumps.
#[test]
fn harness_scan_i20_teeth_shared_lookup_key_is_caught() {
    let key = lookup_key(1);
    let mut a = StoreSet::default();
    a.push("a/dump/c_a", [b"key\t".to_vec(), hex(&key, false)].concat());
    let mut b = StoreSet::default();
    b.push(
        "b/dump/c_b",
        [b"{\"k\":\"".to_vec(), base64(&key), b"\"}".to_vec()].concat(),
    );
    let shared = shared_identifiers(
        &CellDump::from_stores(&a),
        &CellDump::from_stores(&b),
        &PublicConstants::default(),
    )
    .unwrap();
    assert!(shared.contains(&key), "{shared:?}");
}

/// I-20 control: two cells with different lookup keys and the same
/// surrounding text share no identifier.
#[test]
fn harness_scan_i20_control_distinct_keys_are_not_shared() {
    let mut a = StoreSet::default();
    a.push(
        "a",
        [b"key\t".to_vec(), hex(&lookup_key(1), false)].concat(),
    );
    let mut b = StoreSet::default();
    b.push(
        "b",
        [b"key\t".to_vec(), hex(&lookup_key(2), false)].concat(),
    );
    let shared = shared_identifiers(
        &CellDump::from_stores(&a),
        &CellDump::from_stores(&b),
        &PublicConstants::default(),
    )
    .unwrap();
    assert!(shared.is_empty(), "{shared:?}");
}

/// I-20, design section 14.4: a UUID-shaped account id in two cells is a
/// shared identifier, and the public-constant allow list removes it.
#[test]
fn harness_scan_i20_uuid_identifiers_are_extracted_and_allowed() {
    let uuid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    let mut a = StoreSet::default();
    a.push("a", format!("id={uuid};").into_bytes());
    let b = a.clone();
    let bytes: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&uuid.replace('-', "")[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let (da, db) = (CellDump::from_stores(&a), CellDump::from_stores(&b));
    let none = shared_identifiers(&da, &db, &PublicConstants::default()).unwrap();
    let allow = PublicConstants {
        values: none.clone(),
    };
    let after = shared_identifiers(&da, &db, &allow).unwrap();
    assert_eq!((none.contains(&bytes), after.is_empty()), (true, true));
}
