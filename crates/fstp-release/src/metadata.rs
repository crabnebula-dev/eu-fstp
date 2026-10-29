//! Release metadata, its store and `may_apply` (design section 10.3,
//! TH-32).
//!
//! Signed metadata is `"FSTPRM01" || channel || seq || major || minor ||
//! patch || expires_at || artifact_sha256 || signature` (W1g proposal).
//! The signature is the composite Ed25519 plus ML-DSA-65 of ADR-010 over
//! the body, with the context [`METADATA_CONTEXT`] (lane W2j proposal).
//!
//! In M3 no release signing key is certified by the release root, since
//! I-91 lands in M9. So [`decode_release_metadata`] refuses every input,
//! the cell announces no update, and nothing is installed. The store and
//! its rollback, expiry and conflict rules still run over metadata that
//! a key the caller trusts verifies, so they are tested now.

use fstp_crypto::composite;

use crate::ReleaseError;
use crate::egress::{Channel, ProductVersion};
use crate::wire;

/// Signed metadata of one release, as `may_apply` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseMetadata {
    /// The version, `major.minor.patch`.
    pub version: (u16, u16, u16),
    /// SHA-256 of the artifact.
    pub artifact_sha256: [u8; 32],
}

/// The first bytes of every metadata document.
pub const METADATA_MAGIC: [u8; 8] = *b"FSTPRM01";

/// The composite signature context of release metadata.
///
/// Reading: the W1g reference leaves the signature to the caller. Lane
/// W2j proposes this context with the ADR-010 composite encoding, for
/// Daniel to confirm.
pub const METADATA_CONTEXT: &[u8] = b"fstp-release-metadata-v1";

/// The metadata body length: magic, channel, metadata version, product
/// version, expiry and artifact digest.
pub const METADATA_BODY_LEN: usize = 8 + 1 + 8 + 6 + 8 + 32;

/// The signed metadata length.
pub const METADATA_LEN: usize = METADATA_BODY_LEN + composite::SIGNATURE_LEN;

/// A composite release signing key the caller trusts.
///
/// In M3 no release root certifies one (I-91), so only tests and the
/// update service's own checks build one.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleaseSigningKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for ReleaseSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReleaseSigningKey(..)")
    }
}

impl ReleaseSigningKey {
    /// A key from its composite public key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::Length`] unless `bytes` is a composite
    /// public key that `fstp-crypto` accepts, with neither half
    /// degenerate.
    pub fn from_bytes(bytes: &[u8]) -> Result<ReleaseSigningKey, ReleaseError> {
        composite::CompositePublicKey::from_bytes(bytes).map_err(|_| ReleaseError::Length)?;
        Ok(ReleaseSigningKey {
            bytes: bytes.to_vec(),
        })
    }
}

/// The fields of release metadata whose signature verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifiedMetadata {
    channel: Channel,
    seq: u64,
    version: ProductVersion,
    expires_at: i64,
    artifact_sha256: [u8; 32],
}

impl VerifiedMetadata {
    /// The channel.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// The metadata version. A higher one supersedes a lower one.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The product version.
    #[must_use]
    pub const fn version(&self) -> ProductVersion {
        self.version
    }

    /// UTC seconds. Expired from this instant on.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// SHA-256 of the artifact.
    #[must_use]
    pub const fn artifact_sha256(&self) -> [u8; 32] {
        self.artifact_sha256
    }

    /// The release this metadata describes.
    #[must_use]
    pub const fn release(&self) -> ReleaseMetadata {
        ReleaseMetadata {
            version: (self.version.0, self.version.1, self.version.2),
            artifact_sha256: self.artifact_sha256,
        }
    }
}

/// Verifies signed metadata under `key`: length and magic, then both
/// halves of the composite signature (I-90), then the fields.
///
/// # Errors
///
/// [`ReleaseError::Length`], [`ReleaseError::Magic`],
/// [`ReleaseError::Signature`] or [`ReleaseError::Channel`], in that
/// order of checks.
pub fn verify_metadata(
    bytes: &[u8],
    key: &ReleaseSigningKey,
) -> Result<VerifiedMetadata, ReleaseError> {
    if bytes.len() != METADATA_LEN {
        return Err(ReleaseError::Length);
    }
    let (body, signature) = bytes
        .split_at_checked(METADATA_BODY_LEN)
        .ok_or(ReleaseError::Length)?;
    if body.get(..8) != Some(METADATA_MAGIC.as_slice()) {
        return Err(ReleaseError::Magic);
    }
    composite::verify_with_context(&key.bytes, body, METADATA_CONTEXT, signature)
        .map_err(|_| ReleaseError::Signature)?;
    let channel = body
        .get(8)
        .copied()
        .and_then(Channel::from_code)
        .ok_or(ReleaseError::Channel)?;
    let field = |at: usize| wire::be_u16(body, at).ok_or(ReleaseError::Length);
    Ok(VerifiedMetadata {
        channel,
        seq: wire::be_u64(body, 9).ok_or(ReleaseError::Length)?,
        version: ProductVersion(field(17)?, field(19)?, field(21)?),
        expires_at: wire::be_i64(body, 23).ok_or(ReleaseError::Length)?,
        artifact_sha256: wire::array::<32>(body, 31).ok_or(ReleaseError::Length)?,
    })
}

/// Decodes release metadata, signature first, under the release keys the
/// release root certifies. Fuzzed (`release_metadata_decode`).
///
/// In M3 the root certifies no key (I-91 lands in M9). So nothing
/// verifies, no field is read, and every input is refused.
///
/// # Errors
///
/// Returns [`ReleaseError::NotYetVerifiable`] for every input in M3.
pub fn decode_release_metadata(bytes: &[u8]) -> Result<ReleaseMetadata, ReleaseError> {
    let _ = bytes;
    Err(ReleaseError::NotYetVerifiable)
}

/// Whether the release may be applied. Update installation is out of M3,
/// so this is false for every release (design section 10.3).
///
/// From M9 it also needs a target newer than the running version, no
/// call with a proposal in STAGE1, STAGE2, RANKED or IRC_REVIEW, and no
/// payment release in flight (`self-hosted-services.md`).
///
/// # Errors
///
/// None. The `Result` stays so that callers keep one error path for
/// every operation of this crate.
pub fn may_apply(meta: &ReleaseMetadata) -> Result<bool, ReleaseError> {
    let _ = meta;
    Ok(false)
}

/// Whether the cell may tell a tenant admin that an update is available.
/// Only verified metadata may, and in M3 nothing verifies (TH-32), so
/// this is false.
#[must_use]
pub const fn announces_update() -> bool {
    false
}

/// What a cell remembers of release metadata: the verified metadata with
/// the highest metadata version it has accepted (one channel in M3).
///
/// Reading (W1g): design section 10.3 says the cell "stores the highest
/// metadata version it has seen". The store keeps the highest version it
/// has accepted after verification, so unverified metadata never moves
/// the rollback floor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetadataStore {
    highest: Option<VerifiedMetadata>,
}

impl MetadataStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> MetadataStore {
        MetadataStore { highest: None }
    }

    /// A store restored from the cell's sealed store.
    #[must_use]
    pub const fn restored(highest: Option<VerifiedMetadata>) -> MetadataStore {
        MetadataStore { highest }
    }

    /// The accepted metadata with the highest metadata version, if any.
    #[must_use]
    pub const fn highest(&self) -> Option<&VerifiedMetadata> {
        self.highest.as_ref()
    }

    /// Accepts verified metadata at `now`, or names the refusal. A refusal
    /// leaves the store unchanged.
    ///
    /// The order: expiry, then rollback, then conflict. The same metadata
    /// fetched again is accepted and changes nothing.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::Expired`] when `expires_at <= now`,
    /// [`ReleaseError::Rollback`] below the highest accepted metadata
    /// version, and [`ReleaseError::Conflict`] for another body under it.
    pub fn accept(&mut self, m: &VerifiedMetadata, now: i64) -> Result<(), ReleaseError> {
        if m.expires_at <= now {
            return Err(ReleaseError::Expired);
        }
        match self.highest {
            Some(h) if m.seq < h.seq => Err(ReleaseError::Rollback),
            Some(h) if m.seq == h.seq && *m != h => Err(ReleaseError::Conflict),
            Some(h) if m.seq == h.seq => Ok(()),
            _ => {
                self.highest = Some(*m);
                Ok(())
            }
        }
    }

    /// Verifies `bytes` under `key`, then accepts it at `now`. Metadata
    /// that does not verify is refused before any field is read.
    ///
    /// # Errors
    ///
    /// Any refusal of [`verify_metadata`], then of
    /// [`MetadataStore::accept`].
    pub fn accept_signed(
        &mut self,
        bytes: &[u8],
        key: &ReleaseSigningKey,
        now: i64,
    ) -> Result<(), ReleaseError> {
        let m = verify_metadata(bytes, key)?;
        self.accept(&m, now)
    }
}
