//! The backup container writer and opener (ADR-012 "Container format",
//! R-CR-01, I-81). Lane F-ERASE.
//!
//! The writer holds the group's public key only, so it cannot open what
//! it wrote (ADR-012 "Writer"). Each container draws a fresh data key,
//! which is sealed to the group key through the hybrid KEM of ADR-004 in
//! the `FSK1` form. Each chunk is sealed with AES-256-GCM through
//! `fstp_crypto::aead::seal`, which draws a random nonce. The AAD of chunk
//! `i` is the header bytes, `i` as a u64 and the final flag, as ADR-012
//! writes it.
//!
//! The data key's seal context, interim pending Daniel (ADR-012 leaves
//! it to ADR-004): the owner is the context's owner field, the purpose is
//! `Backup`, the group and generation are the group key's, and the
//! object is the container id.

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{HybridPublicKey, HybridSecretKey};
use fstp_keys::envelope::{
    self, AEAD_AES_256_GCM, DataKey, FORMAT_VERSION, SealContext, decode_sealed_key,
};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};

use crate::BackupError;
use crate::container::{CHUNK_SIZE, CONTAINER_MAGIC, HEADER_LEN, decode_header};

/// What a container holds (ADR-012 `kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerKind {
    /// A base backup file of a cluster.
    BaseBackup,
    /// A WAL segment of a cluster.
    WalSegment,
    /// A keystore snapshot of a cell.
    KeystoreSnapshot,
}

impl ContainerKind {
    /// The ADR-012 code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ContainerKind::BaseBackup => 1,
            ContainerKind::WalSegment => 2,
            ContainerKind::KeystoreSnapshot => 3,
        }
    }

    /// The chain whose group key seals a container of this kind: the
    /// ClusterBackup chain for base backups and WAL segments, the
    /// CellBackup chain for keystore snapshots (ADR-012 "What is backed
    /// up").
    #[must_use]
    pub const fn chain(self) -> Chain {
        match self {
            ContainerKind::BaseBackup | ContainerKind::WalSegment => Chain::ClusterBackup,
            ContainerKind::KeystoreSnapshot => Chain::CellBackup,
        }
    }

    fn from_code(code: u8) -> Option<ContainerKind> {
        match code {
            1 => Some(ContainerKind::BaseBackup),
            2 => Some(ContainerKind::WalSegment),
            3 => Some(ContainerKind::KeystoreSnapshot),
            _ => None,
        }
    }
}

/// The group key a container is sealed to: its owner, group and
/// generation on the kind's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRef {
    /// The owner: the cluster id for ClusterBackup, the cell id for
    /// CellBackup.
    pub owner: [u8; 16],
    /// The group.
    pub group: GroupId,
    /// The group generation.
    pub generation: u32,
}

/// What [`open_container`] gives back.
#[derive(Debug)]
pub struct Opened {
    /// The kind.
    pub kind: ContainerKind,
    /// The owner.
    pub owner: [u8; 16],
    /// The container id, which is also the data key id.
    pub container: [u8; 16],
    /// The part number.
    pub part: u32,
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

fn context(kind: ContainerKind, group: &GroupRef, container: [u8; 16]) -> SealContext {
    SealContext {
        cell: CellId(group.owner),
        chain: kind.chain(),
        purpose: Purpose::Backup,
        group: group.group,
        generation: group.generation,
        object: ObjectId(container),
    }
}

/// The AAD of chunk `index` (ADR-012): header, index, final flag.
fn chunk_aad(header: &[u8], index: u64, last: bool) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

/// Seals `plaintext` into one container of `kind`, part `part`, under a
/// fresh data key sealed to `public` through the hybrid KEM. An empty
/// plaintext gives one empty final chunk.
///
/// # Errors
///
/// [`BackupError::Malformed`] when the plaintext needs more chunks than
/// the ADR-004 seal limit allows (the caller splits it into parts), and
/// [`BackupError::Seal`] when the KEM or the AEAD fails.
pub fn seal_container(
    public: &HybridPublicKey,
    kind: ContainerKind,
    group: &GroupRef,
    part: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let size = CHUNK_SIZE as usize;
    let chunks = plaintext.len().div_ceil(size).max(1);
    if u64::try_from(chunks).map_or(true, |n| n >= aead::SEAL_LIMIT) {
        return Err(BackupError::Malformed("seal limit"));
    }
    let container =
        fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("container id"))?;
    let ctx = context(kind, group, container);
    let dek = DataKey::generate().map_err(|_| BackupError::Seal("data key"))?;
    let sealed = envelope::seal_key(public, &dek, &ctx).map_err(|_| BackupError::Seal("key"))?;
    let sealed = envelope::encode_sealed_key(&sealed).map_err(|_| BackupError::Seal("key"))?;
    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(plaintext.len())
            .saturating_add(chunks.saturating_mul(33)),
    );
    out.extend_from_slice(&CONTAINER_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());
    out.push(kind.code());
    out.push(kind.chain().code());
    out.extend_from_slice(&group.owner);
    out.extend_from_slice(&container);
    out.extend_from_slice(&part.to_be_bytes());
    out.extend_from_slice(&CHUNK_SIZE.to_be_bytes());
    out.extend_from_slice(&sealed);
    let header = out.clone();
    let key = aead::Key::from_bytes(dek.expose()).map_err(|_| BackupError::Seal("data key"))?;
    let mut parts: Vec<&[u8]> = plaintext.chunks(size).collect();
    if parts.is_empty() {
        parts.push(&[]);
    }
    let count = parts.len();
    for (i, body) in parts.into_iter().enumerate() {
        let last = i.saturating_add(1) == count;
        let index = u64::try_from(i).map_err(|_| BackupError::Malformed("chunk index"))?;
        let s = aead::seal(&key, &chunk_aad(&header, index, last), body)
            .map_err(|_| BackupError::Seal("chunk"))?;
        let len = u32::try_from(body.len()).map_err(|_| BackupError::Malformed("chunk length"))?;
        out.push(u8::from(last));
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&s.nonce);
        out.extend_from_slice(&s.body);
    }
    Ok(out)
}

/// Opens a container with the secret of the group key it is sealed to.
/// The container is decoded first ([`crate::decode_container`]), so
/// every ADR-012 rule holds before any key is used. The group and
/// generation come from the sealed key's header.
///
/// # Errors
///
/// The decoder's refusal, and [`BackupError::OpenFailed`] when the data
/// key or a chunk does not open under `secret`.
pub fn open_container(secret: &HybridSecretKey, bytes: &[u8]) -> Result<Opened, BackupError> {
    let chunks = crate::container::decode(bytes)?;
    let h = decode_header(bytes)?;
    let kind = ContainerKind::from_code(h.kind).ok_or(BackupError::Malformed("kind"))?;
    let header = bytes.get(..HEADER_LEN).ok_or(BackupError::Truncated)?;
    let sealed = decode_sealed_key(h.sealed_key).map_err(|_| BackupError::KeyNotHybrid)?;
    let kh = sealed.header();
    let group = GroupRef {
        owner: h.owner,
        group: kh.group,
        generation: kh.generation,
    };
    let ctx = context(kind, &group, h.container);
    let dek = envelope::open_key(secret, &sealed, &ctx).map_err(|_| BackupError::OpenFailed)?;
    let key = aead::Key::from_bytes(dek.expose()).map_err(|_| BackupError::OpenFailed)?;
    let mut plaintext = Vec::new();
    for c in &chunks {
        let (nonce, body) = c
            .sealed
            .split_at_checked(aead::NONCE_LEN)
            .ok_or(BackupError::Truncated)?;
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| BackupError::Truncated)?;
        let pt = aead::open(&key, &nonce, &chunk_aad(header, c.index, c.last), body)
            .map_err(|_| BackupError::OpenFailed)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(Opened {
        kind,
        owner: h.owner,
        container: h.container,
        part: h.part,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use fstp_crypto::hybrid_kem;

    fn group() -> GroupRef {
        GroupRef {
            owner: [7; 16],
            group: GroupId([8; 16]),
            generation: 3,
        }
    }

    /// R-CR-01, ADR-012: a sealed container decodes, its data key is a
    /// hybrid FSK1 key of the kind's chain, and it opens under the group
    /// secret to its plaintext, for an empty, a short and a two-chunk
    /// plaintext.
    #[test]
    fn r_cr_01_container_round_trips_under_the_hybrid_kem() {
        let sk = hybrid_kem::generate().unwrap();
        let big: Vec<u8> = (0..CHUNK_SIZE as usize + 9).map(|i| i as u8).collect();
        for (kind, pt) in [
            (ContainerKind::KeystoreSnapshot, Vec::new()),
            (ContainerKind::WalSegment, b"wal".to_vec()),
            (ContainerKind::BaseBackup, big),
        ] {
            let c = seal_container(sk.public(), kind, &group(), 0, &pt).unwrap();
            assert_eq!(c[8], kind.chain().code());
            assert!(crate::decode_container(&c).is_ok());
            let o = open_container(&sk, &c).unwrap();
            assert_eq!((o.kind, o.owner, o.part), (kind, [7; 16], 0));
            assert_eq!(o.plaintext, pt);
        }
    }

    /// I-81, ADR-012 "Writer": a container does not open under another
    /// group secret, and a chunk moved to another container fails.
    #[test]
    fn i81_container_opens_only_under_its_group_secret() {
        let sk = hybrid_kem::generate().unwrap();
        let other = hybrid_kem::generate().unwrap();
        let a = seal_container(sk.public(), ContainerKind::WalSegment, &group(), 0, b"a").unwrap();
        assert_eq!(
            open_container(&other, &a).unwrap_err(),
            BackupError::OpenFailed
        );
        let b = seal_container(sk.public(), ContainerKind::WalSegment, &group(), 0, b"b").unwrap();
        let mut moved = b[..HEADER_LEN].to_vec();
        moved.extend_from_slice(&a[HEADER_LEN..]);
        assert_eq!(
            open_container(&sk, &moved).unwrap_err(),
            BackupError::OpenFailed
        );
    }

    /// ADR-012 "Data key: fresh for every backup attempt": two seals of
    /// the same plaintext share no container id and no sealed key.
    #[test]
    fn r_cr_01_each_container_draws_its_own_data_key() {
        let sk = hybrid_kem::generate().unwrap();
        let a = seal_container(sk.public(), ContainerKind::BaseBackup, &group(), 0, b"x").unwrap();
        let b = seal_container(sk.public(), ContainerKind::BaseBackup, &group(), 0, b"x").unwrap();
        assert_ne!(a[25..41], b[25..41]);
        assert_ne!(a[49..HEADER_LEN], b[49..HEADER_LEN]);
    }
}
