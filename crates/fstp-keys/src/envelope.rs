//! Sealed key and sealed blob formats (M3 design section 3.2, ADR-004).
//!
//! `seal_key`, `open_key`, `seal_blob` and `open_blob` take the hybrid key
//! types of `fstp_crypto::hybrid_kem`, which do not exist yet. They arrive
//! with lane W2f once lane W1h lands that module. The decoders exist now so
//! that the fuzz targets run from the first commit (TH-26).

use crate::hierarchy::{CellId, Chain, GroupId, ObjectId, Purpose};

/// Length of the X25519 half of a hybrid ciphertext.
pub const X25519_CT_LEN: usize = 32;
/// Length of the ML-KEM-768 half of a hybrid ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;

/// Everything a seal binds as associated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealContext {
    /// The cell.
    pub cell: CellId,
    /// The key chain.
    pub chain: Chain,
    /// What the sealed object is for.
    pub purpose: Purpose,
    /// The key group.
    pub group: GroupId,
    /// The group generation.
    pub generation: u32,
    /// The object.
    pub object: ObjectId,
}

/// The header of a sealed key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHeader {
    /// The format version.
    pub version: u8,
}

/// A data key wrapped under a hybrid public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKey {
    header: KeyHeader,
    ct_x25519: [u8; X25519_CT_LEN],
    ct_mlkem: Vec<u8>,
    nonce: [u8; 12],
    wrapped: [u8; 48],
}

impl SealedKey {
    /// The header.
    pub fn header(&self) -> KeyHeader {
        self.header
    }
}

/// The header of a sealed blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobHeader {
    /// The format version.
    pub version: u8,
}

/// A body sealed under a data key: ciphertext followed by the tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    header: BlobHeader,
    nonce: [u8; 12],
    body: Vec<u8>,
}

impl SealedBlob {
    /// The header.
    pub fn header(&self) -> BlobHeader {
        self.header
    }
}

/// Why a sealed format did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoder is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Why sealing or opening failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The operation is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// Decodes a sealed key. Fuzzed (`sealed_key_decode`).
pub fn decode_sealed_key(bytes: &[u8]) -> Result<SealedKey, DecodeError> {
    let _ = bytes;
    Err(DecodeError::NotImplemented(
        "fstp_keys::envelope::decode_sealed_key",
    ))
}

/// Decodes a sealed blob. Fuzzed (`sealed_blob_decode`).
pub fn decode_sealed_blob(bytes: &[u8]) -> Result<SealedBlob, DecodeError> {
    let _ = bytes;
    Err(DecodeError::NotImplemented(
        "fstp_keys::envelope::decode_sealed_blob",
    ))
}

/// Encodes a sealed key in its one spelling.
pub fn encode_sealed_key(key: &SealedKey) -> Result<Vec<u8>, DecodeError> {
    let _ = (
        &key.header,
        &key.ct_x25519,
        &key.ct_mlkem,
        &key.nonce,
        &key.wrapped,
    );
    Err(DecodeError::NotImplemented(
        "fstp_keys::envelope::encode_sealed_key",
    ))
}

/// Encodes a sealed blob in its one spelling.
pub fn encode_sealed_blob(blob: &SealedBlob) -> Result<Vec<u8>, DecodeError> {
    let _ = (&blob.header, &blob.nonce, &blob.body);
    Err(DecodeError::NotImplemented(
        "fstp_keys::envelope::encode_sealed_blob",
    ))
}
