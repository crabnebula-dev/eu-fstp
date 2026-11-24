//! The outer seal of a key copy to the guard (ADR-004 record of lane
//! `m10/guard-key`, row "Outer seal of a copy"). Integers are big-endian.
//!
//! ```text
//! header = "FGC1" | version u8 = 1 | kem u16 = 1 | entry u8 | generation u32
//!          | copy id 16 | created u64                                  36 bytes
//! file   = header | hybrid ciphertext 1120 | nonce 12
//!          | AES-256-GCM(kek, aad = header, inner copy) | tag 16
//! kek    = HKDF-SHA-256(salt = "fstp-guard-copy-v1", ikm = ss, info = header)
//! ```
//!
//! `ss` comes from [`fstp_crypto::hybrid_kem::encapsulate`] to the guard's
//! public half: ML-KEM-768 from moduletto with X25519 from aws-lc-rs,
//! never one half alone (I-75). The inner copy is the passphrase-sealed
//! `"FKX1"` copy of [`crate::export`], unchanged. Only the custodian can
//! derive `kek`, and only while the generation lives. The header decoder
//! is fuzzed (`guard_link_decode`).

use zeroize::Zeroizing;

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, CIPHERTEXT_LEN, HybridCiphertext, HybridPublicKey};

use super::GuardEntry;
use crate::KeydError;
use crate::export::{ExportId, MAX_EXPORT_LEN};

/// The magic of a guarded copy.
pub const COPY_MAGIC: [u8; 4] = *b"FGC1";
/// Its version.
pub const COPY_VERSION: u8 = 1;
/// The KEM code: the hybrid combiner of ADR-004 part 1.
pub const COPY_KEM: u16 = 1;
/// The length of the clear header.
pub const HEADER_LEN: usize = 36;
/// The offset of the copy id in the header, for `fstp-admin`.
pub const ID_AT: usize = 12;
/// The salt of the key derivation.
pub const KEK_SALT: &[u8; 18] = b"fstp-guard-copy-v1";
/// The longest guarded copy.
pub const MAX_GUARDED_LEN: usize =
    HEADER_LEN + CIPHERTEXT_LEN + aead::NONCE_LEN + MAX_EXPORT_LEN + aead::TAG_LEN;

/// The clear header of a guarded copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardedHeader {
    /// The pilot entry the copy is of.
    pub entry: GuardEntry,
    /// The guard generation it is sealed to.
    pub generation: u32,
    /// The copy's id, the same as the inner copy's.
    pub id: ExportId,
    /// When it was made, in Unix seconds.
    pub created: u64,
}

impl GuardedHeader {
    /// The header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let parts: [&[u8]; 7] = [
            &COPY_MAGIC,
            &[COPY_VERSION],
            &COPY_KEM.to_be_bytes(),
            &[self.entry.code()],
            &self.generation.to_be_bytes(),
            &self.id.0,
            &self.created.to_be_bytes(),
        ];
        let mut at = 0usize;
        for p in parts {
            let end = at.saturating_add(p.len());
            if let Some(dst) = out.get_mut(at..end) {
                dst.copy_from_slice(p);
            }
            at = end;
        }
        out
    }
}

fn bad(rule: &'static str) -> KeydError {
    KeydError::Malformed(rule)
}

/// Decodes the clear header of a guarded copy and returns it with the
/// hybrid ciphertext and the sealed rest. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for a copy above [`MAX_GUARDED_LEN`], another
/// magic, version, KEM or entry, generation 0, and a sealed part shorter
/// than a nonce and a tag.
pub fn decode_guarded(
    bytes: &[u8],
) -> Result<(GuardedHeader, [u8; CIPHERTEXT_LEN], &[u8]), KeydError> {
    if bytes.len() > MAX_GUARDED_LEN {
        return Err(bad("a guarded copy is too long"));
    }
    let (head, rest) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(bad("a guarded copy is cut short"))?;
    let (ct, sealed) = rest
        .split_first_chunk::<CIPHERTEXT_LEN>()
        .ok_or(bad("a guarded copy is cut short"))?;
    if sealed.len() < aead::NONCE_LEN.saturating_add(aead::TAG_LEN) {
        return Err(bad("a guarded copy is cut short"));
    }
    Ok((decode_header(head)?, *ct, sealed))
}

/// Decodes the 36 header bytes alone. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// As [`decode_guarded`].
pub fn decode_header(head: &[u8; HEADER_LEN]) -> Result<GuardedHeader, KeydError> {
    let (magic, h) = head.split_at(4);
    if magic != COPY_MAGIC {
        return Err(bad("a guarded copy has the wrong magic"));
    }
    let take = |at: usize, n: usize| h.get(at..at.saturating_add(n)).unwrap_or_default();
    if take(0, 1) != [COPY_VERSION] || take(1, 2) != COPY_KEM.to_be_bytes() {
        return Err(bad("a guarded copy has an unknown version or KEM"));
    }
    let entry = take(3, 1)
        .first()
        .and_then(|c| GuardEntry::from_code(*c))
        .ok_or(bad("a guarded copy names an unknown entry"))?;
    let generation = u32::from_be_bytes(take(4, 4).try_into().map_err(|_| bad("cut short"))?);
    if generation == 0 {
        return Err(bad("a guarded copy names generation 0"));
    }
    let id = ExportId(take(8, 16).try_into().map_err(|_| bad("cut short"))?);
    let created = u64::from_be_bytes(take(24, 8).try_into().map_err(|_| bad("cut short"))?);
    Ok(GuardedHeader {
        entry,
        generation,
        id,
        created,
    })
}

/// Whether `bytes` start as a guarded copy.
#[must_use]
pub fn is_guarded(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&COPY_MAGIC[..])
}

/// The key of the outer seal, from the shared secret and the header.
///
/// # Errors
///
/// [`KeydError::Crypto`] when aws-lc-rs refuses.
pub fn kek(
    ss: &[u8; hybrid_kem::SHARED_SECRET_LEN],
    header: &[u8; HEADER_LEN],
) -> Result<Zeroizing<[u8; 32]>, KeydError> {
    let mut out = Zeroizing::new([0u8; 32]);
    fstp_crypto::kdf::hkdf_sha256(KEK_SALT, ss, header, &mut out[..]).map_err(KeydError::Crypto)?;
    Ok(out)
}

/// Seals the inner copy `inner` to the guard `public` of `header`.
///
/// # Errors
///
/// [`KeydError::Crypto`] when the generator or aws-lc-rs fails, and
/// [`KeydError::Malformed`] for an inner copy above [`MAX_EXPORT_LEN`].
pub fn seal(
    header: &GuardedHeader,
    public: &HybridPublicKey,
    inner: &[u8],
) -> Result<Vec<u8>, KeydError> {
    if inner.len() > MAX_EXPORT_LEN {
        return Err(bad("a copy is too long"));
    }
    let hb = header.encode();
    let (ct, ss) = hybrid_kem::encapsulate(public).map_err(KeydError::Crypto)?;
    let k = kek(ss.expose(), &hb)?;
    let key = aead::Key::from_bytes(&k).map_err(KeydError::Crypto)?;
    let sealed = aead::seal(&key, &hb, inner).map_err(KeydError::Crypto)?;
    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(CIPHERTEXT_LEN)
            .saturating_add(aead::NONCE_LEN)
            .saturating_add(sealed.body.len()),
    );
    out.extend_from_slice(&hb);
    out.extend_from_slice(&ct.to_bytes());
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

/// Opens the sealed rest of a guarded copy under `kek`.
///
/// # Errors
///
/// [`KeydError::WrongPassphrase`] when the seal does not open, which a
/// changed byte or a wrong key gives.
pub fn open(
    header: &GuardedHeader,
    kek: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeydError> {
    let (nonce, body) = sealed
        .split_first_chunk::<{ aead::NONCE_LEN }>()
        .ok_or(bad("a guarded copy is cut short"))?;
    let key = aead::Key::from_bytes(kek).map_err(KeydError::Crypto)?;
    let plain =
        aead::open(&key, nonce, &header.encode(), body).map_err(|_| KeydError::WrongPassphrase)?;
    Ok(Zeroizing::new(plain.to_vec()))
}

/// Derives `kek` on the custodian side, from the guard secret, the header
/// and the ciphertext.
pub(crate) fn derive_on_custodian(
    secret: &hybrid_kem::HybridSecretKey,
    header: &[u8; HEADER_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
) -> Result<Zeroizing<[u8; 32]>, KeydError> {
    let ct = HybridCiphertext::from_bytes(ciphertext).map_err(KeydError::Crypto)?;
    let ss = hybrid_kem::decapsulate(secret, &ct).map_err(KeydError::Crypto)?;
    kek(ss.expose(), header)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    /// ADR-004 record of lane `m10/guard-key`, I-75: a copy sealed to a
    /// guard opens with the key both halves of the guard give, and not
    /// with the key of another guard. A changed header byte fails too.
    #[test]
    fn i75_guarded_copy_opens_only_under_its_guard() {
        let guard = hybrid_kem::generate().unwrap();
        let other = hybrid_kem::generate().unwrap();
        let header = GuardedHeader {
            entry: GuardEntry::Cell,
            generation: 3,
            id: ExportId([7; 16]),
            created: 99,
        };
        let sealed = seal(&header, guard.public(), b"inner copy").unwrap();
        let (h, ct, rest) = decode_guarded(&sealed).unwrap();
        assert_eq!(h, header);
        assert_eq!(&sealed[ID_AT..ID_AT + 16], &[7; 16]);
        let k = derive_on_custodian(&guard, &h.encode(), &ct).unwrap();
        assert_eq!(&open(&h, &k, rest).unwrap()[..], b"inner copy");
        let wrong = derive_on_custodian(&other, &h.encode(), &ct).unwrap();
        assert!(open(&h, &wrong, rest).is_err());
        let mut moved = h;
        moved.generation = 4;
        assert!(open(&moved, &k, rest).is_err());
    }
}
