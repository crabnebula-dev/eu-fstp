//! The writer key of a cluster's backup agent (ADR-012 record of lane
//! m10/backup-format, F-043, F-044, TH-51).
//!
//! The group key of `cluster-backup.key` is a KEM key. Anyone who holds
//! its public half can seal a container to it, so a sealed container
//! alone does not say who wrote it. The agent therefore also holds a
//! composite signing key (ML-DSA-65 with Ed25519, draft 19, through
//! `fstp_crypto::composite`), and signs:
//!
//! - every cluster backup container, under [`CONTAINER_CONTEXT`];
//! - the bytes of its key file that name the group public key and the
//!   writer public key, under [`BINDING_CONTEXT`].
//!
//! ```text
//! cluster-backup-writer.key = "FBW1" | version u8 = 1 | cluster 16 | composite private key 64
//! ```
//!
//! The file is not a root key, so I-80 does not cover it. It is readable
//! by the `postgres` user, which runs `archive_command`, and by no one
//! else. The decoder admits exactly this form and is fuzzed
//! (`backup_key_file_decode`). Every composite verification of this crate
//! goes through [`verifies`], the one call site of the I-90 sweep.

use fstp_crypto::composite::{self, CompositeSigningKey};
use zeroize::Zeroizing;

use crate::BackupError;

/// The writer key file's name in the credentials directory.
pub const WRITER_FILE: &str = "cluster-backup-writer.key";
/// The magic of the writer key file.
pub const WRITER_MAGIC: [u8; 4] = *b"FBW1";
/// The version of the writer key file.
pub const WRITER_VERSION: u8 = 1;
/// The length of the writer key file.
pub const WRITER_FILE_LEN: usize = 4 + 1 + 16 + composite::PRIVATE_KEY_LEN;
/// The length of a writer public key.
pub const WRITER_PUBLIC_LEN: usize = composite::PUBLIC_KEY_LEN;
/// The length of a writer signature.
pub const SIGNATURE_LEN: usize = composite::SIGNATURE_LEN;
/// The context of the key file binding signature (F-044).
pub const BINDING_CONTEXT: &[u8] = b"fstp-backup-key-binding-v1";
/// The context of a container signature (F-043).
pub const CONTAINER_CONTEXT: &[u8] = b"fstp-backup-container-v1";

fn bad(rule: &'static str) -> BackupError {
    BackupError::KeyFile(rule)
}

/// The writer key of one cluster. Wiped on drop. It has no `Clone`, and
/// its `Debug` shows no key byte.
pub struct WriterKey {
    cluster: [u8; 16],
    key: CompositeSigningKey,
}

impl std::fmt::Debug for WriterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterKey").finish_non_exhaustive()
    }
}

impl WriterKey {
    /// Draws a new writer key for `cluster`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Seal`] when the generator fails.
    pub fn generate(cluster: [u8; 16]) -> Result<WriterKey, BackupError> {
        let key = composite::generate().map_err(|_| BackupError::Seal("writer key"))?;
        Ok(WriterKey { cluster, key })
    }

    /// The cluster.
    #[must_use]
    pub fn cluster(&self) -> [u8; 16] {
        self.cluster
    }

    /// The composite public key.
    #[must_use]
    pub fn public(&self) -> [u8; WRITER_PUBLIC_LEN] {
        self.key.public_key().to_bytes()
    }

    /// The signing key itself, for the I-90 sweep's sign side.
    #[must_use]
    pub fn signing_key(&self) -> &CompositeSigningKey {
        &self.key
    }

    /// Encodes the writer key file. Wiped on drop.
    ///
    /// # Errors
    ///
    /// [`BackupError::Seal`] when the key does not export.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let private = self
            .key
            .to_bytes()
            .map_err(|_| BackupError::Seal("writer key"))?;
        let mut out = Zeroizing::new(Vec::with_capacity(WRITER_FILE_LEN));
        out.extend_from_slice(&WRITER_MAGIC);
        out.push(WRITER_VERSION);
        out.extend_from_slice(&self.cluster);
        out.extend_from_slice(&private[..]);
        Ok(out)
    }

    /// Decodes a writer key file. Fuzzed (`backup_key_file_decode`).
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] for another length, magic or version, or
    /// a key that does not load.
    pub fn decode(bytes: &[u8]) -> Result<WriterKey, BackupError> {
        if bytes.len() != WRITER_FILE_LEN {
            return Err(bad("writer key length"));
        }
        let (magic, rest) = bytes.split_at(4);
        if magic != WRITER_MAGIC {
            return Err(bad("writer key magic"));
        }
        let (version, rest) = rest.split_at(1);
        if version != [WRITER_VERSION] {
            return Err(bad("writer key version"));
        }
        let (cluster, private) = rest.split_at(16);
        let cluster: [u8; 16] = cluster.try_into().map_err(|_| bad("writer key length"))?;
        let key = CompositeSigningKey::from_bytes(private).map_err(|_| bad("writer key"))?;
        Ok(WriterKey { cluster, key })
    }

    /// Signs the key file bytes `message` under [`BINDING_CONTEXT`].
    ///
    /// # Errors
    ///
    /// [`BackupError::Seal`] when a half fails.
    pub fn sign_binding(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], BackupError> {
        sign_binding(&self.key, message)
    }

    /// Signs the container bytes `body` under [`CONTAINER_CONTEXT`].
    ///
    /// # Errors
    ///
    /// [`BackupError::Seal`] when a half fails.
    pub fn sign_container(&self, body: &[u8]) -> Result<[u8; SIGNATURE_LEN], BackupError> {
        sign_container(&self.key, body)
    }
}

fn sign(
    key: &CompositeSigningKey,
    ctx: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], BackupError> {
    key.sign_with_context(message, ctx)
        .map(|s| s.to_bytes())
        .map_err(|_| BackupError::Seal("writer signature"))
}

/// The binding signature of `key` over the key file bytes `message`.
///
/// # Errors
///
/// [`BackupError::Seal`] when a half fails.
pub fn sign_binding(
    key: &CompositeSigningKey,
    message: &[u8],
) -> Result<[u8; SIGNATURE_LEN], BackupError> {
    sign(key, BINDING_CONTEXT, message)
}

/// The container signature of `key` over the container bytes `body`.
///
/// # Errors
///
/// [`BackupError::Seal`] when a half fails.
pub fn sign_container(
    key: &CompositeSigningKey,
    body: &[u8],
) -> Result<[u8; SIGNATURE_LEN], BackupError> {
    sign(key, CONTAINER_CONTEXT, body)
}

/// The one composite verification of this crate: both halves under
/// `public`, with `ctx` (I-90).
fn verifies(public: &[u8], ctx: &[u8], message: &[u8], signature: &[u8]) -> bool {
    composite::verify_with_context(public, message, ctx, signature).is_ok()
}

/// Whether `signature` is the binding signature of the writer key
/// `public` over the key file bytes `message` (F-044).
#[must_use]
pub fn binding_verifies(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verifies(public, BINDING_CONTEXT, message, signature)
}

/// Whether `signature` is the container signature of the writer key
/// `public` over the container bytes `body` (F-043).
#[must_use]
pub fn container_signature_verifies(public: &[u8], body: &[u8], signature: &[u8]) -> bool {
    verifies(public, CONTAINER_CONTEXT, body, signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// F-043, ADR-012 record of lane m10/backup-format: the writer key
    /// file decodes in one spelling, a signature verifies only under its
    /// own context, and the file's `Debug` shows no key byte.
    #[test]
    fn f043_writer_key_file_round_trips_in_one_spelling() {
        let w = WriterKey::generate([7; 16]).unwrap();
        let bytes = w.encode().unwrap();
        assert_eq!(bytes.len(), WRITER_FILE_LEN);
        let back = WriterKey::decode(&bytes).unwrap();
        assert_eq!((back.cluster(), back.public()), (w.cluster(), w.public()));
        for cut in [0, 4, 5, WRITER_FILE_LEN - 1] {
            assert!(WriterKey::decode(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(WriterKey::decode(&long).is_err());
        let mut magic = bytes.to_vec();
        magic[3] ^= 1;
        assert!(WriterKey::decode(&magic).is_err());
        let mut version = bytes.to_vec();
        version[4] = 2;
        assert!(WriterKey::decode(&version).is_err());
        let s = w.sign_container(b"body").unwrap();
        assert!(container_signature_verifies(&w.public(), b"body", &s));
        assert!(!binding_verifies(&w.public(), b"body", &s));
        assert!(!container_signature_verifies(&w.public(), b"bodY", &s));
        let other = WriterKey::generate([7; 16]).unwrap();
        assert!(!container_signature_verifies(&other.public(), b"body", &s));
        assert!(!format!("{w:?}").contains(&format!("{:?}", &bytes[21..30])));
    }
}
