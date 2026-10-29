//! Tests of `fstp_release::metadata` (TH-32, T-UPDATE, I-90, design
//! sections 10.3 and 15, `self-hosted-services.md`).
//!
//! M3 installs nothing and announces no update. Metadata cannot be
//! verified until the release root certification of I-91 lands in M9, so
//! `decode_release_metadata` refuses every input with a typed error. The
//! acceptance rules still hold over metadata that a test signing key
//! verifies: rollback, expiry and a second body under a seen version are
//! refused, and unverified metadata never moves the floor.
//!
//! The metadata signature is the composite Ed25519 plus ML-DSA-65 of
//! ADR-010, over the body with the context the oracle proposes. The W0
//! stub has no verifier under a given key and no store
//! ([`seams::METADATA_SEAM`]).
//!
//! The tests are red until lane W2j lands the metadata module.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use std::sync::OnceLock;

use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_release::metadata::{ReleaseMetadata, decode_release_metadata, may_apply};

use oracle::{
    DAY_S, METADATA_BODY_LEN, METADATA_LEN, MetaRefusal, MetaStore, T0, gen_metadata,
    metadata_with_sig, sign_metadata,
};
use seams::{ProdMetaStore, is_stub, oracle_verified, stub_msg, verify_metadata};

/// Two composite release signing keys for tests, made once.
fn keys() -> &'static (CompositeSigningKey, CompositeSigningKey) {
    static KEYS: OnceLock<(CompositeSigningKey, CompositeSigningKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        (
            composite::generate().unwrap(),
            composite::generate().unwrap(),
        )
    })
}

fn pk(k: &CompositeSigningKey) -> Vec<u8> {
    k.public_key().to_bytes().to_vec()
}

fn gen_any(g: &mut Gen) -> oracle::Metadata {
    let seq = g.u64();
    let expires_at = T0 + g.i64_in(-30 * DAY_S..=30 * DAY_S);
    gen_metadata(g, seq, expires_at)
}

// ---------------------------------------------------------------------------
// The M3 surface: nothing decodes, nothing applies.

/// TH-32, design sections 10.3 and 15: in M3 no release key is certified
/// by the release root, so `decode_release_metadata` refuses every
/// metadata with a typed error. That includes metadata validly signed by
/// a composite key that no root certifies, and any signature bytes.
#[test]
fn th_32_decode_release_metadata_refuses_all_metadata_in_m3() {
    let (a, _) = keys();
    check(
        "th_32_decode_release_metadata_refuses_all_metadata_in_m3",
        |g| {
            let m = gen_any(g);
            let bytes = if g.bool() {
                sign_metadata(&m, a)
            } else {
                metadata_with_sig(&m, &g.bytes(0..=composite::SIGNATURE_LEN + 8))
            };
            match decode_release_metadata(&bytes) {
                Ok(got) => Err(format!("TH-32: unverifiable {m:?} decoded as {got:?}")),
                Err(e) => stub_msg(&e).map_or(Ok(()), Err),
            }
        },
    );
}

/// TH-32, design section 10.3: M3 installs nothing. `may_apply` is false
/// for every metadata value, newer or older than the running version.
#[test]
fn th_32_may_apply_is_false_in_m3() {
    check("th_32_may_apply_is_false_in_m3", |g| {
        let mut sha = [0u8; 32];
        for b in &mut sha {
            *b = g.u8();
        }
        let meta = ReleaseMetadata {
            version: (g.u16(), g.u16(), g.u16()),
            artifact_sha256: sha,
        };
        match may_apply(&meta) {
            Ok(applies) => {
                prop_assert!(!applies, "TH-32: M3 would install {meta:?}");
                Ok(())
            }
            Err(e) if is_stub(&e) => Err(stub_msg(&e).unwrap_or_default()),
            Err(e) => Err(format!("may_apply refused {meta:?}: {e:?}")),
        }
    });
}

// ---------------------------------------------------------------------------
// Verification under a test release key.

/// TH-32, design section 15 ("signature checked before use"): metadata
/// signed by the test key verifies to exactly its fields.
#[test]
fn th_32_verify_metadata_reads_back_signed_fields() {
    let (a, _) = keys();
    check("th_32_verify_metadata_reads_back_signed_fields", |g| {
        let m = gen_any(g);
        prop_assert_eq!(verify_metadata(&sign_metadata(&m, a), &pk(a))?, Some(m));
        Ok(())
    });
}

/// TH-32, design section 15: metadata signed by another key, with any one
/// bit flipped, or of another length, is refused.
#[test]
fn th_32_verify_metadata_refuses_forged_or_mutated_metadata() {
    let (a, b) = keys();
    check(
        "th_32_verify_metadata_refuses_forged_or_mutated_metadata",
        |g| {
            let m = gen_any(g);
            let bytes = match g.u8_in(0..=2) {
                0 => sign_metadata(&m, b),
                1 => {
                    let mut x = sign_metadata(&m, a);
                    let i = g.usize_in(0..=METADATA_LEN - 1);
                    x[i] ^= 1u8 << g.u8_in(0..=7);
                    x
                }
                _ => {
                    let mut x = sign_metadata(&m, a);
                    x.truncate(g.usize_in(0..=METADATA_LEN - 1));
                    x
                }
            };
            prop_assert_eq!(verify_metadata(&bytes, &pk(a))?, None);
            Ok(())
        },
    );
}

/// I-90, TH-67 (design section 12): a composite signature verifies only
/// when both halves do. A valid Ed25519 half with the ML-DSA-65 half of
/// another key's signature over the same body is refused, and so is the
/// reverse.
#[test]
fn i90_verify_metadata_needs_both_signature_halves() {
    let (a, b) = keys();
    check("i90_verify_metadata_needs_both_signature_halves", |g| {
        let m = gen_any(g);
        let good = sign_metadata(&m, a);
        let other = sign_metadata(&m, b);
        let split = METADATA_BODY_LEN + fstp_crypto::composite::MLDSA_SIGNATURE_LEN;
        let mixed = if g.bool() {
            [
                &good[..METADATA_BODY_LEN],
                &other[METADATA_BODY_LEN..split],
                &good[split..],
            ]
            .concat()
        } else {
            [&good[..split], &other[split..]].concat()
        };
        prop_assert!(!oracle_verified(&mixed, &pk(a)), "oracle check");
        prop_assert_eq!(verify_metadata(&mixed, &pk(a))?, None);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The store: rollback, expiry and conflict.

/// One step: metadata, whether it is signed by the trusted key, and the
/// instant.
fn gen_steps(g: &mut Gen) -> Vec<(oracle::Metadata, bool, i64)> {
    let mut seen: Vec<oracle::Metadata> = Vec::new();
    let mut now = T0;
    let mut steps = Vec::new();
    for _ in 0..g.usize_in(1..=8) {
        now += g.i64_in(0..=DAY_S);
        let m = match (seen.last().copied(), g.u8_in(0..=4)) {
            (Some(prev), 0) => prev,
            (Some(prev), 1) => {
                let mut c = gen_metadata(g, prev.seq, prev.expires_at);
                c.artifact_sha256[0] ^= 1;
                c
            }
            (Some(prev), 2) => {
                let seq = prev.seq.saturating_sub(g.u64_in(1..=3));
                gen_metadata(g, seq, now + DAY_S)
            }
            (_, 3) => {
                let (seq, ago) = (g.u64_in(0..=20), g.i64_in(0..=DAY_S));
                gen_metadata(g, seq, now - ago)
            }
            _ => {
                let (seq, ahead) = (g.u64_in(0..=20), g.i64_in(1..=30 * DAY_S));
                gen_metadata(g, seq, now + ahead)
            }
        };
        seen.push(m);
        steps.push((m, g.u8_in(0..=4) != 0, now));
    }
    steps
}

/// TH-32, T-UPDATE (design section 10.3): over sequences of verified and
/// unverified metadata, with refetches, rollbacks, expiries and a second
/// body under a seen version, production's verdict on every step equals
/// the oracle store's.
#[test]
fn th_32_metadata_store_matches_the_oracle_over_sequences() {
    let (a, b) = keys();
    check(
        "th_32_metadata_store_matches_the_oracle_over_sequences",
        |g| {
            let mut prod = ProdMetaStore::new()?;
            let mut want = MetaStore::default();
            for (m, trusted, now) in gen_steps(g) {
                let bytes = sign_metadata(&m, if trusted { a } else { b });
                let verdict = want.accept(&m, trusted, now);
                let got = prod.accept(&bytes, &pk(a), now)?;
                prop_assert_eq!(
                    got,
                    verdict.map(|_| ()),
                    "{m:?} at {now}, trusted {trusted}"
                );
                if let Ok(next) = verdict {
                    want = next;
                }
            }
            Ok(())
        },
    );
}

/// TH-32, design section 15: unverified metadata is refused before any
/// field is read, so even a very high metadata version signed by another
/// key never moves the floor. Fresh metadata from the trusted key is
/// accepted afterwards.
#[test]
fn th_32_unverified_metadata_never_moves_the_floor() {
    let (a, b) = keys();
    check("th_32_unverified_metadata_never_moves_the_floor", |g| {
        let mut prod = ProdMetaStore::new()?;
        let high = u64::MAX - g.u64_in(0..=3);
        let forged = gen_metadata(g, high, T0 + 30 * DAY_S);
        prop_assert_eq!(
            prod.accept(&sign_metadata(&forged, b), &pk(a), T0)?,
            Err(MetaRefusal::Unverifiable)
        );
        let seq = g.u64_in(0..=10);
        let fresh = gen_metadata(g, seq, T0 + DAY_S);
        prop_assert_eq!(prod.accept(&sign_metadata(&fresh, a), &pk(a), T0)?, Ok(()));
        Ok(())
    });
}

/// TH-32: the oracle's metadata signature verifies under the signing key
/// only, so the comparisons above are not vacuous. Green on the oracle.
#[test]
fn th_32_oracle_metadata_signature_verifies_under_its_key_only() {
    let (a, b) = keys();
    check(
        "th_32_oracle_metadata_signature_verifies_under_its_key_only",
        |g| {
            let bytes = sign_metadata(&gen_any(g), a);
            prop_assert_eq!(bytes.len(), METADATA_LEN);
            prop_assert!(oracle_verified(&bytes, &pk(a)), "own key");
            prop_assert!(!oracle_verified(&bytes, &pk(b)), "other key");
            Ok(())
        },
    );
}
