//! Sealed key and sealed blob formats (M3 design section 3.2, ADR-004
//! part 1, R-CR-01, R-NF-08, I-75).
//!
//! # Sealed key
//!
//! A level 3 data key sealed to a level 2 group key through the hybrid
//! KEM of `fstp_crypto::hybrid_kem`. The bytes are those of ADR-004 part 1:
//!
//! ```text
//! header  = "FSK1" | version u8 = 1 | kem u16 = 1 | aead u16 = 1
//!           | chain u8 | group 16 | generation u32                    30 bytes
//! ctx     = "FSC1" | owner 16 | chain u8 | purpose u8 | group 16
//!           | generation u32 | object 16                              58 bytes
//! kek     = HKDF-SHA-256(salt = empty, ikm = ss,
//!                        info = "fstp-seal-v1" || header, L = 32)
//! wrapped = AES-256-GCM(kek, nonce, aad = header || ctx, data key)    48 bytes
//! sealed  = header | E 32 | ct_M 1088 | nonce 12 | wrapped 48         1210 bytes
//! ```
//!
//! # Sealed blob
//!
//! No ADR fixed the blob header bytes before this lane. Lane W2f writes
//! this layout at first use. Its record in ADR-004 is with the lead:
//!
//! ```text
//! header  = "FSB1" | version u8 = 1 | aead u16 = 1                      7 bytes
//! blob    = header | nonce 12 | ciphertext | tag 16
//! aad     = header || ctx                                              65 bytes
//! ```
//!
//! The AAD binds the blob to its owner, chain, purpose, group, generation
//! and object, so a blob moved to another cell, row or object fails to
//! open. ADR-007 and ADR-012 may name a finer position for their tables
//! through the `object` field.
//!
//! Every AES-256-GCM seal goes through `fstp_crypto::aead::seal`, which
//! draws a fresh random nonce (ADR-004 "Nonce rule"). No function here
//! takes a nonce from its caller.

use fstp_crypto::CryptoError;
use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridCiphertext, HybridPublicKey, HybridSecretKey};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::hierarchy::{CellId, Chain, GroupId, ObjectId, Purpose};

/// Length of the X25519 half of a hybrid ciphertext.
pub const X25519_CT_LEN: usize = 32;
/// Length of the ML-KEM-768 half of a hybrid ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;
/// The magic of a sealed key.
pub const KEY_MAGIC: [u8; 4] = *b"FSK1";
/// The magic of a seal context.
pub const CTX_MAGIC: [u8; 4] = *b"FSC1";
/// The magic of a sealed blob.
pub const BLOB_MAGIC: [u8; 4] = *b"FSB1";
/// The format version of every sealed form here.
pub const FORMAT_VERSION: u8 = 1;
/// The `kem` code of the ADR-004 combiner.
pub const KEM_HYBRID: u16 = 1;
/// The `aead` code of AES-256-GCM.
pub const AEAD_AES_256_GCM: u16 = 1;
/// The KDF label of the key-encryption key.
pub const SEAL_INFO: &[u8; 12] = b"fstp-seal-v1";
/// Length of a sealed key header.
pub const KEY_HEADER_LEN: usize = 30;
/// Length of a seal context.
pub const CTX_LEN: usize = 58;
/// Length of a nonce.
pub const NONCE_LEN: usize = aead::NONCE_LEN;
/// Length of an AES-256-GCM tag.
pub const TAG_LEN: usize = aead::TAG_LEN;
/// Length of a data key.
pub const DATA_KEY_LEN: usize = aead::KEY_LEN;
/// Length of the wrapped data key: the key and its tag.
pub const WRAPPED_LEN: usize = DATA_KEY_LEN + TAG_LEN;
/// Length of a sealed key.
pub const SEALED_KEY_LEN: usize =
    KEY_HEADER_LEN + X25519_CT_LEN + MLKEM768_CT_LEN + NONCE_LEN + WRAPPED_LEN;
/// Length of a sealed blob header.
pub const BLOB_HEADER_LEN: usize = 7;
/// The shortest sealed blob: header, nonce and the tag of an empty body.
pub const MIN_BLOB_LEN: usize = BLOB_HEADER_LEN + NONCE_LEN + TAG_LEN;
/// The hard limit of seals per data key (ADR-004 part 1 "Seal-count
/// limit"): 2^24.
pub const SEAL_LIMIT: u64 = aead::SEAL_LIMIT;

/// Everything a seal binds as associated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealContext {
    /// The owner: the cell, or the cluster or environment id for the
    /// ClusterBackup and ControlPlane chains (ADR-004 part 1).
    pub cell: CellId,
    /// The key chain.
    pub chain: Chain,
    /// What the sealed object is for.
    pub purpose: Purpose,
    /// The key group.
    pub group: GroupId,
    /// The group generation.
    pub generation: u32,
    /// The object: the data key id for a sealed key.
    pub object: ObjectId,
}

impl SealContext {
    /// The 58 context bytes of ADR-004 part 1. They are bound as AAD and
    /// never stored.
    #[must_use]
    pub fn encode(&self) -> [u8; CTX_LEN] {
        let mut w = Writer::<CTX_LEN>::new();
        w.put(&CTX_MAGIC);
        w.put(&self.cell.0);
        w.put(&[self.chain.code(), self.purpose.code()]);
        w.put(&self.group.0);
        w.put(&self.generation.to_be_bytes());
        w.put(&self.object.0);
        w.finish()
    }
}

/// A data key (level 3, AES-256-GCM). It counts its own seals and refuses
/// at [`SEAL_LIMIT`]. It implements no `Clone`, `Copy` or `Debug`, and
/// wipes its bytes on drop.
pub struct DataKey {
    bytes: Zeroizing<[u8; DATA_KEY_LEN]>,
    key: aead::Key,
}

impl ZeroizeOnDrop for DataKey {}

impl DataKey {
    /// A fresh data key from the system generator.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Crypto`] when the generator fails.
    pub fn generate() -> Result<DataKey, SealError> {
        let mut bytes = Zeroizing::new([0u8; DATA_KEY_LEN]);
        fstp_crypto::random_bytes(&mut bytes[..]).map_err(SealError::Crypto)?;
        DataKey::from_bytes(&bytes)
    }

    /// Imports key bytes, with a seal count of zero.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Crypto`] when the AEAD refuses the key.
    pub fn from_bytes(bytes: &[u8; DATA_KEY_LEN]) -> Result<DataKey, SealError> {
        DataKey::from_bytes_with_count(bytes, 0)
    }

    /// Imports key bytes that have already sealed `seals_so_far` times,
    /// so the limit holds across a re-import (ADR-004 part 1). At or
    /// above [`SEAL_LIMIT`] the key opens but refuses every seal.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Crypto`] when the AEAD refuses the key.
    pub fn from_bytes_with_count(
        bytes: &[u8; DATA_KEY_LEN],
        seals_so_far: u64,
    ) -> Result<DataKey, SealError> {
        let key =
            aead::Key::from_bytes_with_count(bytes, seals_so_far).map_err(SealError::Crypto)?;
        Ok(DataKey {
            bytes: Zeroizing::new(*bytes),
            key,
        })
    }

    /// The seals counted for this key, refused seals excluded.
    #[must_use]
    pub fn seal_count(&self) -> u64 {
        self.key.seal_count()
    }

    /// The key bytes, for a caller that seals them to a group key or
    /// hands them to a backup writer.
    #[must_use]
    pub fn expose(&self) -> &[u8; DATA_KEY_LEN] {
        &self.bytes
    }
}

/// The header of a sealed key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHeader {
    /// The format version.
    pub version: u8,
    /// The KEM code.
    pub kem: u16,
    /// The AEAD code.
    pub aead: u16,
    /// The chain of the group key.
    pub chain: Chain,
    /// The group.
    pub group: GroupId,
    /// The group generation.
    pub generation: u32,
}

impl KeyHeader {
    /// The header ADR-004 writes for `ctx`.
    #[must_use]
    pub fn for_context(ctx: &SealContext) -> KeyHeader {
        KeyHeader {
            version: FORMAT_VERSION,
            kem: KEM_HYBRID,
            aead: AEAD_AES_256_GCM,
            chain: ctx.chain,
            group: ctx.group,
            generation: ctx.generation,
        }
    }

    /// The 30 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; KEY_HEADER_LEN] {
        let mut w = Writer::<KEY_HEADER_LEN>::new();
        w.put(&KEY_MAGIC);
        w.put(&[self.version]);
        w.put(&self.kem.to_be_bytes());
        w.put(&self.aead.to_be_bytes());
        w.put(&[self.chain.code()]);
        w.put(&self.group.0);
        w.put(&self.generation.to_be_bytes());
        w.finish()
    }
}

/// A data key wrapped under a hybrid public key, in the FSK1 form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKey {
    header: KeyHeader,
    ct_x25519: [u8; X25519_CT_LEN],
    ct_mlkem: Box<[u8; MLKEM768_CT_LEN]>,
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl SealedKey {
    /// The header.
    #[must_use]
    pub fn header(&self) -> KeyHeader {
        self.header
    }
}

/// The header of a sealed blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobHeader {
    /// The format version.
    pub version: u8,
    /// The AEAD code.
    pub aead: u16,
}

impl BlobHeader {
    /// The header this crate writes.
    #[must_use]
    pub const fn current() -> BlobHeader {
        BlobHeader {
            version: FORMAT_VERSION,
            aead: AEAD_AES_256_GCM,
        }
    }

    /// The 7 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; BLOB_HEADER_LEN] {
        let mut w = Writer::<BLOB_HEADER_LEN>::new();
        w.put(&BLOB_MAGIC);
        w.put(&[self.version]);
        w.put(&self.aead.to_be_bytes());
        w.finish()
    }
}

/// A body sealed under a data key: ciphertext followed by the tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    header: BlobHeader,
    nonce: [u8; NONCE_LEN],
    body: Vec<u8>,
}

impl SealedBlob {
    /// The header.
    #[must_use]
    pub fn header(&self) -> BlobHeader {
        self.header
    }

    /// The length of the plaintext the blob holds.
    #[must_use]
    pub fn plaintext_len(&self) -> usize {
        self.body.len().saturating_sub(TAG_LEN)
    }
}

/// Why a sealed format did not decode. The display never holds input
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Kept for the W0 callers that match on it. No decoder here returns
    /// it.
    NotImplemented(&'static str),
    /// The input has a length the format does not allow.
    WrongLength,
    /// The magic is not the format's.
    BadMagic,
    /// The version is not 1.
    UnknownVersion,
    /// The KEM code is unknown.
    UnknownKem,
    /// The AEAD code is unknown.
    UnknownAead,
    /// The chain code is unknown.
    UnknownChain,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DecodeError::NotImplemented(op) => op,
            DecodeError::WrongLength => "sealed form has the wrong length",
            DecodeError::BadMagic => "sealed form has the wrong magic",
            DecodeError::UnknownVersion => "sealed form has an unknown version",
            DecodeError::UnknownKem => "sealed key has an unknown kem code",
            DecodeError::UnknownAead => "sealed form has an unknown aead code",
            DecodeError::UnknownChain => "sealed key has an unknown chain code",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DecodeError {}

/// Why sealing or opening failed. The display never holds key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// Kept for the W0 callers that match on it. No call here returns it.
    NotImplemented(&'static str),
    /// The sealed key's header names another chain, group or generation
    /// than the context. Checked before any decapsulation (ADR-004).
    ContextMismatch,
    /// The data key has sealed [`SEAL_LIMIT`] times.
    SealLimitReached,
    /// The sealed form did not open under this key and context.
    OpenFailed,
    /// The crypto layer refused.
    Crypto(CryptoError),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::NotImplemented(op) => f.write_str(op),
            SealError::ContextMismatch => f.write_str("sealed key does not match its context"),
            SealError::SealLimitReached => f.write_str("data key reached its seal-count limit"),
            SealError::OpenFailed => f.write_str("sealed form did not open"),
            SealError::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for SealError {}

fn crypto(e: CryptoError) -> SealError {
    match e {
        CryptoError::SealLimitReached => SealError::SealLimitReached,
        CryptoError::OpenFailed => SealError::OpenFailed,
        other => SealError::Crypto(other),
    }
}

/// The key-encryption key of a sealed key.
fn kek(ss: &[u8; 32], header: &[u8; KEY_HEADER_LEN]) -> Result<aead::Key, SealError> {
    let mut info = [0u8; SEAL_INFO.len() + KEY_HEADER_LEN];
    {
        let (a, b) = info.split_at_mut(SEAL_INFO.len());
        a.copy_from_slice(SEAL_INFO);
        b.copy_from_slice(header);
    }
    let mut out = Zeroizing::new([0u8; DATA_KEY_LEN]);
    fstp_crypto::kdf::hkdf_sha256(&[], ss, &info, &mut out[..]).map_err(crypto)?;
    aead::Key::from_bytes(&out).map_err(crypto)
}

/// The AAD of a sealed key or blob: its header, then the context.
fn aad_of(header: &[u8], ctx: &SealContext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len().saturating_add(CTX_LEN));
    aad.extend_from_slice(header);
    aad.extend_from_slice(&ctx.encode());
    aad
}

/// Seals the data key `dek` to the group key `pk` under `ctx`.
///
/// # Errors
///
/// Returns [`SealError::Crypto`] when the KEM or the AEAD fails.
pub fn seal_key(
    pk: &HybridPublicKey,
    dek: &DataKey,
    ctx: &SealContext,
) -> Result<SealedKey, SealError> {
    let header = KeyHeader::for_context(ctx);
    let hb = header.encode();
    let (ct, ss) = hybrid_kem::encapsulate(pk).map_err(crypto)?;
    let key = kek(ss.expose(), &hb)?;
    let sealed = aead::seal(&key, &aad_of(&hb, ctx), dek.expose()).map_err(crypto)?;
    let wrapped: [u8; WRAPPED_LEN] = sealed
        .body
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Crypto(CryptoError::InvalidLength))?;
    let ct = ct.to_bytes();
    let (e, m) = ct.split_at(X25519_CT_LEN);
    Ok(SealedKey {
        header,
        ct_x25519: e
            .try_into()
            .map_err(|_| SealError::Crypto(CryptoError::InvalidLength))?,
        ct_mlkem: Box::new(
            m.try_into()
                .map_err(|_| SealError::Crypto(CryptoError::InvalidLength))?,
        ),
        nonce: sealed.nonce,
        wrapped,
    })
}

/// Opens a sealed key with the group's secret key under `ctx`. The
/// header's chain, group and generation are compared with `ctx` before
/// any decapsulation. Both secret halves always run (I-75).
///
/// # Errors
///
/// Returns [`SealError::ContextMismatch`] for another chain, group or
/// generation, and [`SealError::OpenFailed`] when the key does not open.
pub fn open_key(
    sk: &HybridSecretKey,
    s: &SealedKey,
    ctx: &SealContext,
) -> Result<DataKey, SealError> {
    if s.header.chain != ctx.chain
        || s.header.group != ctx.group
        || s.header.generation != ctx.generation
    {
        return Err(SealError::ContextMismatch);
    }
    let mut ct = [0u8; hybrid_kem::CIPHERTEXT_LEN];
    {
        let (e, m) = ct.split_at_mut(X25519_CT_LEN);
        e.copy_from_slice(&s.ct_x25519);
        m.copy_from_slice(&s.ct_mlkem[..]);
    }
    let ct = HybridCiphertext::from_bytes(&ct).map_err(crypto)?;
    let hb = s.header.encode();
    let ss = hybrid_kem::decapsulate(sk, &ct).map_err(|_| SealError::OpenFailed)?;
    let key = kek(ss.expose(), &hb)?;
    let opened = aead::open(&key, &s.nonce, &aad_of(&hb, ctx), &s.wrapped)
        .map_err(|_| SealError::OpenFailed)?;
    let bytes: Zeroizing<[u8; DATA_KEY_LEN]> = Zeroizing::new(
        opened
            .as_slice()
            .try_into()
            .map_err(|_| SealError::OpenFailed)?,
    );
    DataKey::from_bytes(&bytes)
}

/// Seals `pt` under the data key `dek`, bound to `ctx`. The seal counts
/// against the key's limit, even if the caller's transaction later
/// aborts.
///
/// # Errors
///
/// Returns [`SealError::SealLimitReached`] once the key has sealed
/// [`SEAL_LIMIT`] times, and [`SealError::Crypto`] when the AEAD fails.
pub fn seal_blob(dek: &DataKey, ctx: &SealContext, pt: &[u8]) -> Result<SealedBlob, SealError> {
    let header = BlobHeader::current();
    let sealed = aead::seal(&dek.key, &aad_of(&header.encode(), ctx), pt).map_err(crypto)?;
    Ok(SealedBlob {
        header,
        nonce: sealed.nonce,
        body: sealed.body,
    })
}

/// Opens a sealed blob under the data key `dek` and `ctx`.
///
/// # Errors
///
/// Returns [`SealError::OpenFailed`] when the blob does not open.
pub fn open_blob(
    dek: &DataKey,
    ctx: &SealContext,
    b: &SealedBlob,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    aead::open(
        &dek.key,
        &b.nonce,
        &aad_of(&b.header.encode(), ctx),
        &b.body,
    )
    .map_err(|_| SealError::OpenFailed)
}

/// Decodes a sealed key: exactly 1210 bytes, the magic, version 1 and
/// known codes. Any other input is refused. Fuzzed (`sealed_key_decode`).
///
/// # Errors
///
/// Returns the first rule the input breaks.
pub fn decode_sealed_key(bytes: &[u8]) -> Result<SealedKey, DecodeError> {
    if bytes.len() != SEALED_KEY_LEN {
        return Err(DecodeError::WrongLength);
    }
    let mut r = Reader::new(bytes);
    if r.array::<4>()? != KEY_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = r.u8()?;
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnknownVersion);
    }
    let kem = r.u16()?;
    if kem != KEM_HYBRID {
        return Err(DecodeError::UnknownKem);
    }
    let aead = r.u16()?;
    if aead != AEAD_AES_256_GCM {
        return Err(DecodeError::UnknownAead);
    }
    let chain = Chain::from_code(r.u8()?).ok_or(DecodeError::UnknownChain)?;
    let group = GroupId(r.array()?);
    let generation = u32::from_be_bytes(r.array()?);
    let ct_x25519 = r.array()?;
    let ct_mlkem = Box::new(r.array::<MLKEM768_CT_LEN>()?);
    let nonce = r.array()?;
    let wrapped = r.array()?;
    r.end()?;
    Ok(SealedKey {
        header: KeyHeader {
            version,
            kem,
            aead,
            chain,
            group,
            generation,
        },
        ct_x25519,
        ct_mlkem,
        nonce,
        wrapped,
    })
}

/// Decodes a sealed blob: the magic, version 1, a known AEAD code, a
/// nonce and at least a tag. Fuzzed (`sealed_blob_decode`).
///
/// # Errors
///
/// Returns the first rule the input breaks.
pub fn decode_sealed_blob(bytes: &[u8]) -> Result<SealedBlob, DecodeError> {
    if bytes.len() < MIN_BLOB_LEN {
        return Err(DecodeError::WrongLength);
    }
    let mut r = Reader::new(bytes);
    if r.array::<4>()? != BLOB_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = r.u8()?;
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnknownVersion);
    }
    let aead = r.u16()?;
    if aead != AEAD_AES_256_GCM {
        return Err(DecodeError::UnknownAead);
    }
    let nonce = r.array()?;
    let body = r.rest().to_vec();
    if body.len() < TAG_LEN {
        return Err(DecodeError::WrongLength);
    }
    Ok(SealedBlob {
        header: BlobHeader { version, aead },
        nonce,
        body,
    })
}

/// Encodes a sealed key in its one spelling.
///
/// # Errors
///
/// Infallible for every key this crate builds or decodes. The `Result`
/// keeps the W0 signature.
pub fn encode_sealed_key(key: &SealedKey) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(SEALED_KEY_LEN);
    out.extend_from_slice(&key.header.encode());
    out.extend_from_slice(&key.ct_x25519);
    out.extend_from_slice(&key.ct_mlkem[..]);
    out.extend_from_slice(&key.nonce);
    out.extend_from_slice(&key.wrapped);
    Ok(out)
}

/// Encodes a sealed blob in its one spelling.
///
/// # Errors
///
/// Infallible for every blob this crate builds or decodes. The `Result`
/// keeps the W0 signature.
pub fn encode_sealed_blob(blob: &SealedBlob) -> Result<Vec<u8>, DecodeError> {
    let len = BLOB_HEADER_LEN
        .saturating_add(NONCE_LEN)
        .saturating_add(blob.body.len());
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&blob.header.encode());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.body);
    Ok(out)
}

/// A fixed-size writer. Writes past the end are dropped, which the
/// callers never do: every caller writes exactly `N` bytes.
struct Writer<const N: usize> {
    out: [u8; N],
    at: usize,
}

impl<const N: usize> Writer<N> {
    fn new() -> Self {
        Writer {
            out: [0u8; N],
            at: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = self.at.saturating_add(bytes.len()).min(N);
        if let Some(dst) = self.out.get_mut(self.at..end) {
            let n = dst.len();
            if let Some(src) = bytes.get(..n) {
                dst.copy_from_slice(src);
            }
        }
        self.at = end;
    }

    fn finish(self) -> [u8; N] {
        self.out
    }
}

/// A cursor over input bytes that never reads past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(DecodeError::WrongLength)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DecodeError::WrongLength)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }

    fn end(&self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::WrongLength)
        }
    }
}
