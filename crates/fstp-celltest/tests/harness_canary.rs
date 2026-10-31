//! The canary generator of the isolation harness (M3 design section 14.1,
//! lane W1a). Every synthetic personal value is a canary
//! `CNRY-<cell>-<kind>-<32 hex>`. The canaries are the seeds of the I-17,
//! I-19, I-38 and I-80 scans. Written test first: rendering and generation
//! refuse until lane W1a lands them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::canary::{Canary, CanaryKind, generate_set};
use fstp_prop::{Gen, check};

/// Every kind of design section 14.1. The match is exhaustive, so a new
/// kind fails to compile here until the list names it.
const KINDS: [CanaryKind; 10] = [
    CanaryKind::Name,
    CanaryKind::Email,
    CanaryKind::Phone,
    CanaryKind::Country,
    CanaryKind::Document,
    CanaryKind::IpAddress,
    CanaryKind::ProposalText,
    CanaryKind::RootKey,
    CanaryKind::TextSalt,
    CanaryKind::AccountId,
];

const fn listed(kind: CanaryKind) -> usize {
    match kind {
        CanaryKind::Name => 0,
        CanaryKind::Email => 1,
        CanaryKind::Phone => 2,
        CanaryKind::Country => 3,
        CanaryKind::Document => 4,
        CanaryKind::IpAddress => 5,
        CanaryKind::ProposalText => 6,
        CanaryKind::RootKey => 7,
        CanaryKind::TextSalt => 8,
        CanaryKind::AccountId => 9,
    }
}

fn gen_canary(g: &mut Gen) -> Canary {
    let cell = g.u8();
    let kind = *g.pick(&KINDS);
    let mut nonce = [0u8; 16];
    for b in &mut nonce {
        *b = g.u8();
    }
    Canary { cell, kind, nonce }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Design section 14.1: `CanaryKind::ALL` lists every kind once, in the
/// order of the section.
#[test]
fn harness_canary_kind_list_is_complete() {
    assert_eq!(CanaryKind::ALL, KINDS);
    for (i, k) in KINDS.iter().enumerate() {
        assert_eq!(listed(*k), i);
    }
}

/// Design section 14.1: a canary renders as `CNRY-<cell>-<kind>-<32 hex>`.
/// The cell and kind parts are non-empty lowercase ASCII without a dash,
/// and the hex part is the nonce in lowercase hex.
#[test]
fn harness_canary_renders_cnry_cell_kind_hex() {
    check("harness_canary_renders_cnry_cell_kind_hex", |g| {
        let c = gen_canary(g);
        let text = c.render().map_err(|e| format!("render refused: {e:?}"))?;
        let parts: Vec<&str> = text.split('-').collect();
        let plain = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        };
        if parts.len() == 4
            && parts[0] == "CNRY"
            && plain(parts[1])
            && plain(parts[2])
            && parts[3] == lower_hex(&c.nonce)
        {
            Ok(())
        } else {
            Err(format!("{c:?} rendered as {text:?}"))
        }
    });
}

/// Design section 14.1: the text determines the canary. Two canaries that
/// differ in cell, kind or nonce render differently, so a hit names one
/// cell and one kind.
#[test]
fn harness_canary_text_determines_cell_kind_and_nonce() {
    check("harness_canary_text_determines_cell_kind_and_nonce", |g| {
        let a = gen_canary(g);
        let mut b = a.clone();
        match g.u8_in(0..=2) {
            0 => b.cell = g.u8(),
            1 => b.kind = *g.pick(&KINDS),
            _ => {
                let i = g.usize_in(0..=15);
                b.nonce[i] = g.u8();
            }
        }
        let ta = a.render().map_err(|e| format!("render refused: {e:?}"))?;
        let tb = b.render().map_err(|e| format!("render refused: {e:?}"))?;
        if (a == b) == (ta == tb) {
            Ok(())
        } else {
            Err(format!("{a:?} as {ta:?} and {b:?} as {tb:?}"))
        }
    });
}

/// Design section 14.1: the generator keeps the cell and kind it is given
/// and draws a fresh random nonce each time.
#[test]
fn harness_canary_generate_draws_fresh_nonces() {
    for kind in KINDS {
        let a = Canary::generate(7, kind).unwrap();
        let b = Canary::generate(7, kind).unwrap();
        assert_eq!((a.cell, a.kind), (7, kind));
        assert_eq!((b.cell, b.kind), (7, kind));
        assert_ne!(a.nonce, b.nonce, "{kind:?}");
        assert_ne!(a.nonce, [0; 16], "{kind:?}");
    }
}

/// Design section 14.1: a cell's canary set holds one canary of every
/// kind, in the listed order, each with its own nonce.
#[test]
fn harness_canary_generate_set_covers_every_kind_once() {
    let set = generate_set(3).unwrap();
    let kinds: Vec<CanaryKind> = set.iter().map(|c| c.kind).collect();
    assert_eq!(kinds, KINDS);
    assert!(set.iter().all(|c| c.cell == 3));
    let nonces: BTreeSet<[u8; 16]> = set.iter().map(|c| c.nonce).collect();
    assert_eq!(nonces.len(), KINDS.len());
}
