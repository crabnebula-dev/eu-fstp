//! Sealing and opening in `fstp_keys::envelope` (design section 3.2,
//! ADR-004 part 1, R-CR-01, R-NF-08, I-75).
//!
//! The W0 stub has no `seal_key`, `open_key`, `seal_blob`, `open_blob` or
//! `DataKey`. These tests call them through the test-side seams of
//! `common`, which have the designed shapes. They are red with
//! `ENVELOPE_SEAM` or `SEAL_COUNT_SEAM` until lane W2f adds the calls and
//! edits those helpers. The cross-checks against the independent
//! reference live in `fstp-celltest` (`r_cr_01_*`, `i75_*`). These are
//! the crate's own unit and property tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code indexes fixed layouts"
)]

mod common;

use common::{
    E_AT, Fail, NONCE_AT, SEALED_KEY_LEN, arr32, chain_code, classify, expect_refused, gen_ctx,
    moved_ctx, open_blob, open_key, purpose_codes, seal_blob, seal_blob_at_count, seal_key,
};
use fstp_crypto::hybrid_kem::{self, HybridSecretKey};
use fstp_keys::envelope::{
    decode_sealed_blob, decode_sealed_key, encode_sealed_blob, encode_sealed_key,
};
use fstp_prop::{Gen, prop_assert, prop_assert_eq, prop_assert_ne};

fn key_pair() -> HybridSecretKey {
    hybrid_kem::generate().expect("hybrid key generation")
}

/// R-CR-01, ADR-004 part 1: a data key sealed to a group key opens under
/// the same context with the group's secret key, and gives the same 32
/// bytes back.
#[test]
fn r_cr_01_sealed_key_round_trips_under_its_context() {
    let sk = key_pair();
    fstp_prop::check(
        "r_cr_01_sealed_key_round_trips_under_its_context",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let sealed = seal_key(sk.public(), &dek, &ctx)?;
            prop_assert_eq!(open_key(&sk, &sealed, &ctx)?, dek);
            Ok(())
        },
    );
}

/// ADR-004 part 1: a sealed key is 1210 bytes in the FSK1 form. Its
/// header names version 1, `kem` 1, `aead` 1, and the chain code, group
/// and generation of its context, big-endian.
#[test]
fn adr004_sealed_key_is_1210_bytes_with_its_context_in_the_header() {
    let sk = key_pair();
    fstp_prop::check(
        "adr004_sealed_key_is_1210_bytes_with_its_context_in_the_header",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let sealed = seal_key(sk.public(), &arr32(g), &ctx)?;
            let bytes = encode_sealed_key(&sealed).map_err(classify)?;
            prop_assert_eq!(bytes.len(), SEALED_KEY_LEN);
            prop_assert_eq!(&bytes[0..4], b"FSK1");
            prop_assert_eq!(bytes[4], 1, "version");
            prop_assert_eq!(&bytes[5..7], &1u16.to_be_bytes(), "kem code");
            prop_assert_eq!(&bytes[7..9], &1u16.to_be_bytes(), "aead code");
            prop_assert_eq!(bytes[9], chain_code(ctx.chain), "chain code");
            prop_assert_eq!(&bytes[10..26], &ctx.group.0, "group");
            prop_assert_eq!(&bytes[26..30], &ctx.generation.to_be_bytes(), "generation");
            Ok(())
        },
    );
}

/// ADR-004 part 1 and test vector plan item 7: a sealed key moved to
/// another cell, chain, purpose, group, generation or object fails to
/// open.
#[test]
fn adr004_sealed_key_moved_to_another_context_never_opens() {
    let sk = key_pair();
    fstp_prop::check(
        "adr004_sealed_key_moved_to_another_context_never_opens",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let sealed = seal_key(sk.public(), &arr32(g), &ctx)?;
            // The key must open under its own context, so a stub that
            // refuses every open fails here.
            let _ = open_key(&sk, &sealed, &ctx)?;
            let field = g.usize_in(0..=5);
            g.note("changed field", &field);
            expect_refused(
                open_key(&sk, &sealed, &moved_ctx(g, &ctx, field)),
                "a sealed key under a moved context",
            )
        },
    );
}

/// ADR-004 part 1, design section 15 (`sealed_key_decode`): a sealed key
/// with any one byte changed either fails to decode or fails to open.
#[test]
fn adr004_sealed_key_with_a_mutated_byte_never_opens() {
    let sk = key_pair();
    fstp_prop::check(
        "adr004_sealed_key_with_a_mutated_byte_never_opens",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let sealed = seal_key(sk.public(), &arr32(g), &ctx)?;
            let _ = open_key(&sk, &sealed, &ctx)?;
            let mut bytes = encode_sealed_key(&sealed).map_err(classify)?;
            let at = g.usize_in(0..=SEALED_KEY_LEN - 1);
            bytes[at] ^= g.u8_in(1..=255);
            g.note("mutated byte", &at);
            let opened = decode_sealed_key(&bytes)
                .map_err(classify)
                .and_then(|m| open_key(&sk, &m, &ctx));
            expect_refused(opened, "a sealed key with a mutated byte")
        },
    );
}

/// R-NF-08, ADR-004 nonce rule: two seals of one data key under one
/// context draw a fresh ephemeral key and a fresh nonce each. No sealed
/// key repeats either.
#[test]
fn r_nf_08_two_seals_of_one_data_key_draw_fresh_nonces() {
    let sk = key_pair();
    fstp_prop::check(
        "r_nf_08_two_seals_of_one_data_key_draw_fresh_nonces",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let a = encode_sealed_key(&seal_key(sk.public(), &dek, &ctx)?).map_err(classify)?;
            let b = encode_sealed_key(&seal_key(sk.public(), &dek, &ctx)?).map_err(classify)?;
            prop_assert_ne!(
                &a[NONCE_AT..NONCE_AT + 12],
                &b[NONCE_AT..NONCE_AT + 12],
                "nonce"
            );
            prop_assert_ne!(&a[E_AT..E_AT + 32], &b[E_AT..E_AT + 32], "ephemeral key");
            Ok(())
        },
    );
}

/// A secret key with the X25519 half of `x` and the ML-KEM half of `m`.
fn mixed(x: &HybridSecretKey, m: &HybridSecretKey) -> HybridSecretKey {
    let (xb, mb) = (x.to_bytes(), m.to_bytes());
    let mut bytes = mb.to_vec();
    bytes[..32].copy_from_slice(&xb[..32]);
    HybridSecretKey::from_bytes(&bytes).expect("mixed secret key")
}

/// I-75, ADR-004 test vector plan item 6: `open_key` needs both secret
/// halves. A secret key with a wrong X25519 half, or a wrong ML-KEM
/// half, fails to open.
#[test]
fn i75_open_key_needs_both_secret_halves() {
    let sk = key_pair();
    let other = key_pair();
    let wrong_x = mixed(&other, &sk);
    let wrong_m = mixed(&sk, &other);
    fstp_prop::check("i75_open_key_needs_both_secret_halves", |g: &mut Gen| {
        let ctx = gen_ctx(g);
        let sealed = seal_key(sk.public(), &arr32(g), &ctx)?;
        let _ = open_key(&sk, &sealed, &ctx)?;
        let half = if g.bool() { &wrong_x } else { &wrong_m };
        expect_refused(
            open_key(half, &sealed, &ctx),
            "a secret key with one wrong half",
        )
    });
}

/// R-CR-01, design section 3.2: a blob sealed under a data key opens
/// under the same key and context. Its bytes decode and re-encode in one
/// spelling.
#[test]
fn r_cr_01_sealed_blob_round_trips_under_its_context() {
    fstp_prop::check(
        "r_cr_01_sealed_blob_round_trips_under_its_context",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let pt = g.bytes(0..=512);
            let blob = seal_blob(&dek, &ctx, &pt)?;
            let bytes = encode_sealed_blob(&blob).map_err(classify)?;
            let back = decode_sealed_blob(&bytes).map_err(classify)?;
            prop_assert_eq!(&back, &blob, "decode of the encoding");
            prop_assert_eq!(encode_sealed_blob(&back).map_err(classify)?, bytes);
            prop_assert_eq!(open_blob(&dek, &ctx, &back)?, pt);
            Ok(())
        },
    );
}

/// ADR-004 part 1 ("a blob moved to another cell, row or object fails to
/// open"): a blob opened under a context with one field changed fails.
#[test]
fn adr004_sealed_blob_moved_to_another_context_never_opens() {
    fstp_prop::check(
        "adr004_sealed_blob_moved_to_another_context_never_opens",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let blob = seal_blob(&dek, &ctx, &g.bytes(0..=64))?;
            let _ = open_blob(&dek, &ctx, &blob)?;
            let field = g.usize_in(0..=5);
            g.note("changed field", &field);
            expect_refused(
                open_blob(&dek, &moved_ctx(g, &ctx, field), &blob),
                "a blob under a moved context",
            )
        },
    );
}

/// Design section 3.2, section 15 (`sealed_blob_decode`): a sealed blob
/// with any one byte changed either fails to decode or fails to open.
#[test]
fn adr004_sealed_blob_with_a_mutated_byte_never_opens() {
    fstp_prop::check(
        "adr004_sealed_blob_with_a_mutated_byte_never_opens",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let blob = seal_blob(&dek, &ctx, &g.bytes(0..=64))?;
            let mut bytes = encode_sealed_blob(&blob).map_err(classify)?;
            let at = g.usize_in(0..=bytes.len() - 1);
            bytes[at] ^= g.u8_in(1..=255);
            g.note("mutated byte", &at);
            let opened = decode_sealed_blob(&bytes)
                .map_err(classify)
                .and_then(|b| open_blob(&dek, &ctx, &b));
            expect_refused(opened, "a blob with a mutated byte")
        },
    );
}

/// A data key opens no blob sealed under another data key.
#[test]
fn adr004_sealed_blob_never_opens_under_another_data_key() {
    fstp_prop::check(
        "adr004_sealed_blob_never_opens_under_another_data_key",
        |g: &mut Gen| {
            let ctx = gen_ctx(g);
            let dek = arr32(g);
            let mut other = dek;
            other[g.usize_in(0..=31)] ^= g.u8_in(1..=255);
            let blob = seal_blob(&dek, &ctx, &g.bytes(0..=64))?;
            let _ = open_blob(&dek, &ctx, &blob)?;
            expect_refused(open_blob(&other, &ctx, &blob), "a blob under another key")
        },
    );
}

/// R-NF-08, ADR-004 nonce rule: two seals of one plaintext under one data
/// key and context differ, since each draws its own nonce.
#[test]
fn r_nf_08_two_seals_of_one_blob_differ() {
    fstp_prop::check("r_nf_08_two_seals_of_one_blob_differ", |g: &mut Gen| {
        let ctx = gen_ctx(g);
        let dek = arr32(g);
        let pt = g.bytes(0..=64);
        let a = encode_sealed_blob(&seal_blob(&dek, &ctx, &pt)?).map_err(classify)?;
        let b = encode_sealed_blob(&seal_blob(&dek, &ctx, &pt)?).map_err(classify)?;
        prop_assert_ne!(a, b, "two seals gave equal bytes");
        Ok(())
    });
}

/// The hard seal limit of ADR-004 part 1 for every data key.
const SEAL_LIMIT: u64 = 1 << 24;

/// R-NF-08, ADR-004 part 1 Seal-count limit: "fstp-keys counts every seal
/// call per key in memory ... At the hard limit it refuses to seal." A
/// data key that has made 2^24 - 1 seals makes one more, and one that
/// has made 2^24 refuses.
#[test]
fn r_nf_08_data_key_refuses_to_seal_past_two_to_the_24() {
    let ctx = fstp_keys::envelope::SealContext {
        cell: fstp_keys::CellId([1; 16]),
        chain: fstp_keys::Chain::App,
        purpose: fstp_keys::Purpose::Ledger,
        group: fstp_keys::GroupId([2; 16]),
        generation: 1,
        object: fstp_keys::ObjectId([3; 16]),
    };
    let dek = [7u8; 32];
    let last = seal_blob_at_count(&dek, SEAL_LIMIT - 1, &ctx, b"last allowed seal");
    assert!(last.is_ok(), "the 2^24th seal was refused: {last:?}");
    let past = seal_blob_at_count(&dek, SEAL_LIMIT, &ctx, b"one seal too many");
    assert!(
        matches!(past, Err(Fail::Refused(_))),
        "a seal past 2^24 was not refused: {past:?}"
    );
}

/// The purposes ADR-004 part 2 names in its chain table.
const ADR004_PURPOSES: [&str; 10] = [
    "Text",
    "Ledger",
    "Lookup",
    "CredLookup",
    "Ticket",
    "Anchor",
    "Attribute",
    "Document",
    "Fact",
    "Match",
];

/// ADR-004 parts 1 and 2: the purpose code table names every purpose of
/// the chain table, and no two purposes share a code. The `ctx` of a
/// sealed key binds the code, so a shared code would let a key move
/// between purposes.
#[test]
fn adr004_purpose_codes_cover_every_chain_purpose_and_are_distinct() {
    let table = purpose_codes().unwrap_or_else(|e| panic!("{e}"));
    let missing: Vec<&str> = ADR004_PURPOSES
        .into_iter()
        .filter(|p| !table.iter().any(|(name, _)| name == p))
        .collect();
    assert!(missing.is_empty(), "purposes with no code: {missing:?}");
    let mut codes: Vec<u8> = table.iter().map(|(_, c)| *c).collect();
    codes.sort_unstable();
    let before = codes.len();
    codes.dedup();
    assert_eq!(codes.len(), before, "two purposes share a code: {table:?}");
    assert!(!codes.contains(&0), "a purpose has code 0: {table:?}");
}

/// The seal helpers and the decoders agree: what `seal_key` returns is a
/// key the decoder accepts back as equal, so the key a caller stores is
/// the key it later opens.
#[test]
fn adr004_sealed_key_decodes_back_to_itself() {
    let sk = key_pair();
    fstp_prop::check("adr004_sealed_key_decodes_back_to_itself", |g: &mut Gen| {
        let ctx = gen_ctx(g);
        let sealed = seal_key(sk.public(), &arr32(g), &ctx)?;
        let bytes = encode_sealed_key(&sealed).map_err(classify)?;
        let back = decode_sealed_key(&bytes).map_err(classify)?;
        prop_assert!(back == sealed, "decode of the encoding differs");
        Ok(())
    });
}
