//! Version 2 backup containers, `FBC2`, for the cluster backup objects
//! (ADR-012 record of lane m10/backup-format, F-043, TH-51, R-CR-01).
//!
//! ```text
//! header  = "FBC2" | version u8 = 1 | aead u16 = 1 | kind u8 | chain u8 | owner 16
//!           | container 16 | chunk_size u32 | ident_len u8 | ident | sealed_key 1210
//! ident   = backup id 16 | be32(part) | last u8      (kind 1, base backup part)
//!         | the archive file name in ASCII           (kind 2, WAL segment or history file)
//!         | be32(file) | be64(offset) | file name    (kind 6, witness store segment)
//! chunk   = final u8 | len u32 | nonce 12 | ciphertext len | tag 16
//! aad(i)  = header | i u64 | final u8
//! trailer = the writer's composite signature over every byte before it,
//!           context "fstp-backup-container-v1"
//! ```
//!
//! The header names the object the container is stored under, so every
//! chunk's AAD and the signature bind it. The writer's signature says
//! that the backup agent wrote the container, which a holder of the
//! group public key alone cannot say. [`open_object`] verifies the
//! signature under the key file's writer public key before any KEM or
//! AEAD call, and the agent then compares the identity with the object
//! it asked for.

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{HybridPublicKey, HybridSecretKey};
use fstp_keys::envelope::{self, AEAD_AES_256_GCM, DataKey, FORMAT_VERSION, decode_sealed_key};

use crate::container::{
    CHUNK_SIZE, CONTAINER_MAGIC_V2, MAX_IDENT_LEN, V2_FIXED_LEN, V2_SIGNATURE_LEN, decode_v2,
};
use crate::seal::{chunk_aad, context};
use crate::wal::{self, ArchiveName};
use crate::writer::{self, WriterKey};
use crate::{BackupError, ContainerKind, GroupRef};

/// The object a version 2 container is stored under, beside its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectIdent {
    /// Part `part` of base backup `backup`, and whether it is the last.
    Base {
        /// The backup id.
        backup: [u8; 16],
        /// The part number, from 0.
        part: u32,
        /// Whether no part follows.
        last: bool,
    },
    /// The archive file of this name: a WAL segment or a timeline
    /// history file.
    Wal(String),
    /// The segment at byte `offset` of the witness store file `name`, the
    /// store's file number `file` (ADR-012 record of lane m10/witness-copy).
    Witness {
        /// The file number, from 0.
        file: u32,
        /// The byte offset of the segment in its file.
        offset: u64,
        /// The file's name in the store ([`crate::witness::valid_name`]).
        name: String,
    },
}

impl ObjectIdent {
    /// The container kind of the object.
    #[must_use]
    pub fn kind(&self) -> ContainerKind {
        match self {
            ObjectIdent::Base { .. } => ContainerKind::BaseBackup,
            ObjectIdent::Wal(_) => ContainerKind::WalSegment,
            ObjectIdent::Witness { .. } => ContainerKind::WitnessCopy,
        }
    }

    /// The `ident` bytes.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] for a name that is not an archived
    /// segment or history file.
    pub fn encode(&self) -> Result<Vec<u8>, BackupError> {
        match self {
            ObjectIdent::Base { backup, part, last } => {
                let mut out = backup.to_vec();
                out.extend_from_slice(&part.to_be_bytes());
                out.push(u8::from(*last));
                Ok(out)
            }
            ObjectIdent::Wal(name) => {
                check_wal_name(name)?;
                Ok(name.as_bytes().to_vec())
            }
            ObjectIdent::Witness { file, offset, name } => {
                if !crate::witness::valid_name(name) {
                    return Err(BackupError::Malformed("ident"));
                }
                let mut out = file.to_be_bytes().to_vec();
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(name.as_bytes());
                Ok(out)
            }
        }
    }

    /// Decodes the `ident` of a container of `kind`, in one spelling.
    ///
    /// # Errors
    ///
    /// [`BackupError::Malformed`] naming the rule broken.
    pub fn decode(kind: ContainerKind, bytes: &[u8]) -> Result<ObjectIdent, BackupError> {
        let bad = BackupError::Malformed("ident");
        match kind {
            ContainerKind::BaseBackup => {
                let (backup, rest) = bytes.split_first_chunk::<16>().ok_or(bad)?;
                let (part, rest) = rest.split_first_chunk::<4>().ok_or(bad)?;
                let last = match rest {
                    [0] => false,
                    [1] => true,
                    _ => return Err(bad),
                };
                Ok(ObjectIdent::Base {
                    backup: *backup,
                    part: u32::from_be_bytes(*part),
                    last,
                })
            }
            ContainerKind::WalSegment => {
                let name = std::str::from_utf8(bytes).map_err(|_| bad)?;
                check_wal_name(name)?;
                Ok(ObjectIdent::Wal(name.to_owned()))
            }
            ContainerKind::WitnessCopy => {
                let (file, rest) = bytes.split_first_chunk::<4>().ok_or(bad)?;
                let (offset, name) = rest.split_first_chunk::<8>().ok_or(bad)?;
                let name = std::str::from_utf8(name).map_err(|_| bad)?;
                if !crate::witness::valid_name(name) {
                    return Err(bad);
                }
                Ok(ObjectIdent::Witness {
                    file: u32::from_be_bytes(*file),
                    offset: u64::from_be_bytes(*offset),
                    name: name.to_owned(),
                })
            }
            _ => Err(BackupError::Malformed("kind")),
        }
    }
}

/// A segment or history file name, never a skipped one.
fn check_wal_name(name: &str) -> Result<(), BackupError> {
    match wal::parse_archive(name)? {
        ArchiveName::Segment(_) | ArchiveName::History(_) => Ok(()),
        ArchiveName::Skipped => Err(BackupError::Malformed("ident")),
    }
}

/// What [`open_object`] gives back.
#[derive(Debug)]
pub struct OpenedObject {
    /// The owner, the cluster.
    pub owner: [u8; 16],
    /// The object the container names.
    pub ident: ObjectIdent,
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

/// Seals `plaintext` as the version 2 container of the object `ident` of
/// the cluster of `group`, under a fresh data key sealed to `public`
/// through the hybrid KEM, and signs it with `writer`.
///
/// # Errors
///
/// [`BackupError::Malformed`] for an `ident` that names no object or a
/// plaintext over the seal limit, and [`BackupError::Seal`] when the KEM,
/// the AEAD or the signature fails.
pub fn seal_object(
    public: &HybridPublicKey,
    writer: &WriterKey,
    group: &GroupRef,
    ident: &ObjectIdent,
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let kind = ident.kind();
    let id = ident.encode()?;
    let id_len = u8::try_from(id.len())
        .ok()
        .filter(|n| (1..=MAX_IDENT_LEN).contains(&usize::from(*n)))
        .ok_or(BackupError::Malformed("ident length"))?;
    let size = CHUNK_SIZE as usize;
    let count = plaintext.len().div_ceil(size).max(1);
    if u64::try_from(count).map_or(true, |n| n >= aead::SEAL_LIMIT) {
        return Err(BackupError::Malformed("seal limit"));
    }
    let container =
        fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("container id"))?;
    let ctx = context(kind, group, container);
    let dek = DataKey::generate().map_err(|_| BackupError::Seal("data key"))?;
    let sealed = envelope::seal_key(public, &dek, &ctx).map_err(|_| BackupError::Seal("key"))?;
    let sealed = envelope::encode_sealed_key(&sealed).map_err(|_| BackupError::Seal("key"))?;
    let mut out = Vec::with_capacity(
        V2_FIXED_LEN
            .saturating_add(id.len())
            .saturating_add(sealed.len())
            .saturating_add(plaintext.len())
            .saturating_add(count.saturating_mul(33))
            .saturating_add(V2_SIGNATURE_LEN),
    );
    out.extend_from_slice(&CONTAINER_MAGIC_V2);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());
    out.push(kind.code());
    out.push(kind.chain().code());
    out.extend_from_slice(&group.owner);
    out.extend_from_slice(&container);
    out.extend_from_slice(&CHUNK_SIZE.to_be_bytes());
    out.push(id_len);
    out.extend_from_slice(&id);
    out.extend_from_slice(&sealed);
    let header = out.clone();
    let key = aead::Key::from_bytes(dek.expose()).map_err(|_| BackupError::Seal("data key"))?;
    let mut parts: Vec<&[u8]> = plaintext.chunks(size).collect();
    if parts.is_empty() {
        parts.push(&[]);
    }
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
    let signature = writer.sign_container(&out)?;
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Opens a version 2 container. It is decoded first, so every ADR-012
/// rule holds before any key is used. Then the signature must verify
/// under `writer_public`, the key file's writer public key, before any
/// KEM or AEAD call. Only then are the data key and the chunks opened
/// under `secret`. The caller compares [`OpenedObject::ident`] and the
/// owner with the object it asked for.
///
/// # Errors
///
/// The decoder's refusal, [`BackupError::Malformed`] (`writer
/// signature`) when the signature does not verify, and
/// [`BackupError::OpenFailed`] when the data key or a chunk does not
/// open.
pub fn open_object(
    secret: &HybridSecretKey,
    writer_public: &[u8],
    bytes: &[u8],
) -> Result<OpenedObject, BackupError> {
    let d = decode_v2(bytes)?;
    if !writer::container_signature_verifies(writer_public, d.signed, d.signature) {
        return Err(BackupError::Malformed("writer signature"));
    }
    let sealed = decode_sealed_key(d.sealed_key).map_err(|_| BackupError::KeyNotHybrid)?;
    let kh = sealed.header();
    let group = GroupRef {
        owner: d.owner,
        group: kh.group,
        generation: kh.generation,
    };
    let ctx = context(d.kind, &group, d.container);
    let dek = envelope::open_key(secret, &sealed, &ctx).map_err(|_| BackupError::OpenFailed)?;
    let key = aead::Key::from_bytes(dek.expose()).map_err(|_| BackupError::OpenFailed)?;
    let mut plaintext = Vec::new();
    for c in &d.chunks {
        let (nonce, body) = c
            .sealed
            .split_at_checked(aead::NONCE_LEN)
            .ok_or(BackupError::Truncated)?;
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| BackupError::Truncated)?;
        let pt = aead::open(&key, &nonce, &chunk_aad(d.header, c.index, c.last), body)
            .map_err(|_| BackupError::OpenFailed)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(OpenedObject {
        owner: d.owner,
        ident: d.ident,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use fstp_crypto::hybrid_kem;
    use fstp_keys::GroupId;

    fn group() -> GroupRef {
        GroupRef {
            owner: [7; 16],
            group: GroupId([8; 16]),
            generation: 3,
        }
    }

    fn base(part: u32, last: bool) -> ObjectIdent {
        ObjectIdent::Base {
            backup: [9; 16],
            part,
            last,
        }
    }

    /// F-043, R-CR-01, ADR-012 record of lane m10/backup-format: an `FBC2`
    /// container round trips for an empty, a short and a two-chunk
    /// plaintext, names its object, and decodes through
    /// `decode_container`. Every cut, appended byte, changed header byte
    /// and changed signature byte is refused, and another writer key or
    /// group secret opens nothing.
    #[test]
    fn adr012_fbc2_round_trips_and_refuses_other_spellings() {
        let sk = hybrid_kem::generate().unwrap();
        let w = WriterKey::generate([7; 16]).unwrap();
        let big: Vec<u8> = (0..CHUNK_SIZE as usize + 9).map(|i| i as u8).collect();
        for (ident, pt) in [
            (base(0, true), Vec::new()),
            (
                ObjectIdent::Wal("000000010000000000000003".into()),
                b"wal".to_vec(),
            ),
            (ObjectIdent::Wal("00000002.history".into()), b"h".to_vec()),
            (base(4, false), big),
        ] {
            let c = seal_object(sk.public(), &w, &group(), &ident, &pt).unwrap();
            assert_eq!(&c[..4], b"FBC2");
            let chunks = crate::decode_container(&c).unwrap();
            assert_eq!(chunks.len(), pt.len().div_ceil(CHUNK_SIZE as usize).max(1));
            let o = open_object(&sk, &w.public(), &c).unwrap();
            assert_eq!((o.owner, &o.ident, &o.plaintext), ([7; 16], &ident, &pt));
            // The FBC1 opener does not read it.
            assert!(crate::open_container(&sk, &c).is_err());
        }
        let c = seal_object(sk.public(), &w, &group(), &base(1, true), b"x").unwrap();
        for cut in [0, 3, 4, 45, 46, 60, c.len() - V2_SIGNATURE_LEN, c.len() - 1] {
            assert!(open_object(&sk, &w.public(), &c[..cut]).is_err(), "{cut}");
        }
        let mut long = c.clone();
        long.push(0);
        assert_eq!(
            crate::decode_container(&long).unwrap_err(),
            BackupError::Malformed("bytes after the signature")
        );
        for i in [
            4,
            5,
            7,
            8,
            9,
            30,
            41,
            45,
            46,
            60,
            67,
            100,
            c.len() - 40,
            c.len() - 1,
        ] {
            let mut flipped = c.clone();
            flipped[i] ^= 1;
            assert!(open_object(&sk, &w.public(), &flipped).is_err(), "{i}");
        }
        let other = WriterKey::generate([7; 16]).unwrap();
        assert_eq!(
            open_object(&sk, &other.public(), &c).unwrap_err(),
            BackupError::Malformed("writer signature")
        );
        let sk2 = hybrid_kem::generate().unwrap();
        assert_eq!(
            open_object(&sk2, &w.public(), &c).unwrap_err(),
            BackupError::OpenFailed
        );
        // A skipped archive name and an over-long or foreign ident are
        // refused at the writer.
        for bad in ["000000010000000000000003.partial", "x", ""] {
            assert!(
                seal_object(
                    sk.public(),
                    &w,
                    &group(),
                    &ObjectIdent::Wal(bad.into()),
                    b""
                )
                .is_err()
            );
        }
        assert!(ObjectIdent::decode(ContainerKind::BaseBackup, &[0; 22]).is_err());
        assert!(
            ObjectIdent::decode(
                ContainerKind::BaseBackup,
                &[[0; 20].as_slice(), &[2]].concat()
            )
            .is_err()
        );
        assert!(ObjectIdent::decode(ContainerKind::KeystoreSnapshot, &[0; 21]).is_err());
    }

    /// F-043, R-CR-01, ADR-012 record of lane m10/witness-copy, row
    /// "Identity": a witness segment names its file number, its offset and
    /// its file name in one spelling, seals and opens as kind 6, and any
    /// other name is refused at the writer and the reader.
    #[test]
    fn adr012_wc_witness_ident_round_trips_in_one_spelling() {
        let sk = hybrid_kem::generate().unwrap();
        let w = WriterKey::generate([7; 16]).unwrap();
        let id = ObjectIdent::Witness {
            file: 3,
            offset: 0x0102_0304_0506,
            name: "chain-0102030405060708090a0b0c0d0e0f10-1".into(),
        };
        let bytes = id.encode().unwrap();
        assert_eq!(&bytes[..12], &[0, 0, 0, 3, 0, 0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(bytes.len(), 12 + 40);
        assert_eq!(
            ObjectIdent::decode(ContainerKind::WitnessCopy, &bytes).unwrap(),
            id
        );
        let c = seal_object(sk.public(), &w, &group(), &id, b"records").unwrap();
        assert_eq!(c[7], 6);
        let o = open_object(&sk, &w.public(), &c).unwrap();
        assert_eq!((o.ident, o.plaintext), (id, b"records".to_vec()));
        for bad in [
            "",
            "-x",
            "Registry",
            "a/b",
            "..",
            "chain.1",
            &"a".repeat(49),
        ] {
            let id = ObjectIdent::Witness {
                file: 0,
                offset: 0,
                name: bad.to_owned(),
            };
            assert!(id.encode().is_err(), "{bad:?}");
            let mut raw = vec![0u8; 12];
            raw.extend_from_slice(bad.as_bytes());
            assert!(
                ObjectIdent::decode(ContainerKind::WitnessCopy, &raw).is_err(),
                "{bad:?}"
            );
        }
        assert!(ObjectIdent::decode(ContainerKind::WitnessCopy, &[0; 11]).is_err());
        // The legacy `FBC1` writer cannot spell a witness copy.
        let c1 = crate::seal_container(sk.public(), ContainerKind::WitnessCopy, &group(), 0, b"x");
        assert!(c1.map_or(true, |c| crate::decode_container(&c).is_err()));
    }
}
