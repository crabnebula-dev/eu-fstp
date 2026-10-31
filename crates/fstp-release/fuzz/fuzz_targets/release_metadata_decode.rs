//! Fuzz target `release_metadata_decode` of `fstp-release` (TH-26, H-05,
//! M3 design sections 10.3 and 15, TH-32).
//!
//! Design checks: no panic; signature checked before use.
//!
//! The first byte picks a mode:
//!
//! - 0: the rest goes to `decode_release_metadata`. In M3 no release
//!   signing key is certified by the release root (I-91 lands in M9), so
//!   every input is refused.
//! - 1: as 0, with the rest signed as a metadata body by a composite key
//!   that no root certifies. Even validly signed metadata is refused.
//! - 2: the rest goes to `verify_metadata` and
//!   `MetadataStore::accept_signed` under a trusted test key.
//! - 3: as 2, with the rest signed under `METADATA_CONTEXT` by that key.
//!   Bit 2 then flips one bit of the signed bytes, at a place the first
//!   byte of the rest picks.
//!
//! Accepted metadata has `METADATA_LEN` bytes and the magic, both halves
//! of the composite signature verify, and its fields read back from the
//! signed body. Mutated input never yields fields. The store accepts
//! exactly the verified metadata that has not expired, and the same
//! bytes again change nothing.

#![no_main]

use std::sync::OnceLock;

use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_release::metadata::{
    METADATA_BODY_LEN, METADATA_CONTEXT, METADATA_LEN, METADATA_MAGIC, MetadataStore,
    ReleaseSigningKey, decode_release_metadata, verify_metadata,
};
use libfuzzer_sys::fuzz_target;

const NOW: i64 = 1_800_000_000;

/// An unrooted key, for modes 0 and 1.
fn unrooted() -> Option<&'static CompositeSigningKey> {
    static KEY: OnceLock<Option<CompositeSigningKey>> = OnceLock::new();
    KEY.get_or_init(|| composite::generate().ok()).as_ref()
}

/// The trusted test key and its public form, for modes 2 and 3.
fn trusted() -> Option<&'static (CompositeSigningKey, ReleaseSigningKey, Vec<u8>)> {
    static KEY: OnceLock<Option<(CompositeSigningKey, ReleaseSigningKey, Vec<u8>)>> =
        OnceLock::new();
    KEY.get_or_init(|| {
        let k = composite::generate().ok()?;
        let public = k.public_key().to_bytes().to_vec();
        let release = ReleaseSigningKey::from_bytes(&public).ok()?;
        Some((k, release, public))
    })
    .as_ref()
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be64(b: &[u8], at: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[at..at + 8]);
    out
}

fn unrooted_mode(mode: u8, rest: &[u8]) {
    let bytes = if mode == 0 {
        rest.to_vec()
    } else {
        let Some(sig) = unrooted().and_then(|k| k.sign_with_context(rest, METADATA_CONTEXT).ok())
        else {
            return;
        };
        [rest, sig.to_bytes().as_slice()].concat()
    };
    let result = decode_release_metadata(&bytes);
    assert!(!format!("{result:?}").is_empty());
    assert!(
        result.is_err(),
        "M3 decoded unverifiable metadata: {result:?}"
    );
}

fn trusted_mode(mode: u8, rest: &[u8]) {
    let Some((signing, key, public)) = trusted() else {
        return;
    };
    let (bytes, mutated) = if mode & 3 == 2 {
        (rest.to_vec(), false)
    } else {
        let Ok(sig) = signing.sign_with_context(rest, METADATA_CONTEXT) else {
            return;
        };
        let mut bytes = [rest, sig.to_bytes().as_slice()].concat();
        let flip = mode & 4 == 4 && !bytes.is_empty();
        if flip {
            let at = usize::from(rest.first().copied().unwrap_or(0)) * 31 % bytes.len();
            bytes[at] ^= 1 << (mode >> 5);
        }
        (bytes, flip)
    };
    let result = verify_metadata(&bytes, key);
    assert!(!format!("{result:?}").is_empty());
    let mut store = MetadataStore::new();
    let accepted = store.accept_signed(&bytes, key, NOW);
    match result {
        Ok(m) => {
            assert!(!mutated, "mutated metadata verified");
            assert_eq!(bytes.len(), METADATA_LEN, "accepted another length");
            let (body, sig) = bytes.split_at(METADATA_BODY_LEN);
            assert_eq!(&body[..8], &METADATA_MAGIC, "accepted another magic");
            assert!(
                composite::verify_with_context(public, body, METADATA_CONTEXT, sig).is_ok(),
                "accepted metadata the key did not sign"
            );
            assert_eq!(m.channel().code(), body[8]);
            assert_eq!(m.seq(), u64::from_be_bytes(be64(body, 9)));
            let v = m.version();
            assert_eq!(
                (v.0, v.1, v.2),
                (be16(body, 17), be16(body, 19), be16(body, 21))
            );
            assert_eq!(m.expires_at(), i64::from_be_bytes(be64(body, 23)));
            assert_eq!(&m.artifact_sha256()[..], &body[31..63]);
            if m.expires_at() > NOW {
                assert_eq!(accepted, Ok(()), "refused fresh verified metadata");
                assert_eq!(store.highest(), Some(&m));
                let again = store.accept_signed(&bytes, key, NOW);
                assert_eq!(again, Ok(()), "refused the same metadata again");
                assert_eq!(store.highest(), Some(&m));
            } else {
                assert!(accepted.is_err(), "accepted expired metadata");
                assert_eq!(store.highest(), None);
            }
        }
        Err(e) => {
            assert_eq!(accepted, Err(e), "the store and the verifier disagree");
            assert_eq!(store.highest(), None, "a refusal moved the store");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    match mode & 3 {
        m @ (0 | 1) => unrooted_mode(m, rest),
        _ => trusted_mode(*mode, rest),
    }
});
