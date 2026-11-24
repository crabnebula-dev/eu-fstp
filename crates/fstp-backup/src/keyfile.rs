//! The ClusterBackup key file `cluster-backup.key` (ADR-012 record of
//! lane L10, ADR-004, R-CR-01, I-80), in its version 2 form since lane
//! m10/backup-format (F-044):
//!
//! ```text
//! file    = MAGIC (22) || cluster (16) || group (16) || be32(generation) || be64(epoch)
//!           || public key (1216) || writer public key (1984) || binding (3373)
//!           || be16(len) || custody handle || be16(len) || wrapped S
//!           || nonce (12) || sealed (2432 + 16)
//! aad     = every byte before the binding
//! binding = composite signature of the writer key over aad, context
//!           "fstp-backup-key-binding-v1" (crate::writer)
//! wrap    = custody wrap of S under the root {no cell, ClusterBackup, epoch}, AAD = aad
//! sealed  = AES-256-GCM under S of the hybrid secret key, AAD = aad
//! ```
//!
//! So custody binds both public keys at every open, and the agent checks
//! the binding with its own writer key before every seal
//! ([`KeyFile::check_writer`]). The version 1 form under [`MAGIC_V1`]
//! ([`FileKind::ClusterBackupV1`]) has no writer key and no binding, and
//! its AAD ends at the epoch. Only `upgrade-keys` reads it ([`upgrade`]).
//!
//! A second custodian's key file `custodian.key` has the version 1 layout
//! under [`CUSTODIAN_MAGIC`] (ADR-012 record of lane L16): its group
//! field is the custodian id, and its secret is the custodian key.
//!
//! The snapshot key files `cell-snapshot.key` and `vault-snapshot.key`
//! have the version 2 layout above under their own magics ([`FileKind`],
//! ADR-012 record of lane m10/backup-followups): their sealed part holds
//! the process's snapshot writer key after the group secret, so the
//! writer key opens only through custody ([`open_writer`]). Their owner
//! field holds the cell, and their root is `{cell, CellBackup or
//! VaultBackup, epoch 1}` in the process's own custody entry (ADR-004
//! record of lane L17). Their version 1 form is read only by
//! [`upgrade_snapshot`].
//!
//! The writer reads the public key only, so it cannot open what it wrote
//! (ADR-012 "Writer"). Opening the secret needs the custody root, which
//! the `fstp-keyd` console socket serves. The file never holds an open
//! key (I-80). The decoder admits exactly this form and is fuzzed
//! (`backup_key_file_decode`). An error names its rule and never quotes
//! the file (R-NF-02).

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_custody::{
    Aad, BackendId, CellId, Chain, Custody, CustodyHandle, Epoch, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_keys::GroupId;
use zeroize::Zeroizing;

use crate::writer::{self, SIGNATURE_LEN, WRITER_PRIVATE_LEN, WRITER_PUBLIC_LEN, WriterKey};
use crate::{BackupError, GroupRef};

/// The magic of the version 2 group key file (record of lane
/// m10/backup-format).
pub const MAGIC: &[u8; 22] = b"fstp-cluster-backup-v2";
/// The magic of the version 1 group key file (record of lane L10). Only
/// [`upgrade`] reads it.
pub const MAGIC_V1: &[u8; 22] = b"fstp-cluster-backup-v1";
/// The magic of a second custodian's key file (ADR-012 record of lane
/// L16). Its own magic keeps it from being read as a group key file.
pub const CUSTODIAN_MAGIC: &[u8; 22] = b"fstp-backup-custodian1";
/// The file's name in the credentials directory.
pub const KEY_FILE: &str = "cluster-backup.key";

/// The label before the digest in [`KeyFile::custody_aad`] of a bound key
/// file (ADR-012 record of lane m10/backup-format, row "Custody AAD").
pub const CUSTODY_AAD_LABEL: &[u8] = b"fstp-backup-key-custody-aad-v2";
/// The magic of the App chain's snapshot key file `cell-snapshot.key`,
/// version 2, bound to the cell's snapshot writer key (ADR-012 record of
/// lane m10/backup-followups).
pub const CELL_SNAPSHOT_MAGIC: &[u8; 22] = b"fstp-cell-snapshots-v2";
/// The magic of the vault's snapshot key file `vault-snapshot.key`,
/// version 2 (ADR-012 record of lane m10/backup-followups).
pub const VAULT_SNAPSHOT_MAGIC: &[u8; 22] = b"fstp-vault-snapshot-v2";
/// The magic of `cell-snapshot.key`, version 1 (ADR-004 record of lane
/// L17). Only the upgrade reads it.
pub const CELL_SNAPSHOT_MAGIC_V1: &[u8; 22] = b"fstp-cell-snapshots-v1";
/// The magic of `vault-snapshot.key`, version 1 (ADR-004 record of lane
/// L17). Only the upgrade reads it.
pub const VAULT_SNAPSHOT_MAGIC_V1: &[u8; 22] = b"fstp-vault-snapshot-v1";
/// The App chain's snapshot key file name in the cell's credentials
/// directory.
pub const CELL_SNAPSHOT_KEY_FILE: &str = "cell-snapshot.key";
/// The vault's snapshot key file name in the vault's credentials
/// directory.
pub const VAULT_SNAPSHOT_KEY_FILE: &str = "vault-snapshot.key";

/// What a key file is for. Each kind has its own magic, so no file decodes
/// as another kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// `cluster-backup.key`, version 2: the ClusterBackup group of a
    /// cluster, bound to the agent's writer key (F-044).
    ClusterBackup,
    /// `cluster-backup.key`, version 1, before lane m10/backup-format.
    /// Read only by [`upgrade`].
    ClusterBackupV1,
    /// `custodian.key`: a second custodian's key (record of lane L16).
    Custodian,
    /// `cell-snapshot.key`, version 2: the CellBackup group of a cell's App
    /// chain keystore snapshots (record of lane L17), bound to the cell's
    /// snapshot writer key, whose private half it seals beside the group
    /// secret (record of lane m10/backup-followups).
    CellSnapshot,
    /// `vault-snapshot.key`, version 2: the VaultBackup group of a vault's
    /// keystore snapshots (record of lane L17), bound and sealed as
    /// [`FileKind::CellSnapshot`].
    VaultSnapshot,
    /// `cell-snapshot.key`, version 1. Read only by [`upgrade_snapshot`].
    CellSnapshotV1,
    /// `vault-snapshot.key`, version 1. Read only by [`upgrade_snapshot`].
    VaultSnapshotV1,
}

impl FileKind {
    /// Every kind.
    pub const ALL: [FileKind; 7] = [
        FileKind::ClusterBackup,
        FileKind::ClusterBackupV1,
        FileKind::Custodian,
        FileKind::CellSnapshot,
        FileKind::VaultSnapshot,
        FileKind::CellSnapshotV1,
        FileKind::VaultSnapshotV1,
    ];

    /// The magic of the kind.
    #[must_use]
    pub const fn magic(self) -> &'static [u8; 22] {
        match self {
            FileKind::ClusterBackup => MAGIC,
            FileKind::ClusterBackupV1 => MAGIC_V1,
            FileKind::Custodian => CUSTODIAN_MAGIC,
            FileKind::CellSnapshot => CELL_SNAPSHOT_MAGIC,
            FileKind::VaultSnapshot => VAULT_SNAPSHOT_MAGIC,
            FileKind::CellSnapshotV1 => CELL_SNAPSHOT_MAGIC_V1,
            FileKind::VaultSnapshotV1 => VAULT_SNAPSHOT_MAGIC_V1,
        }
    }

    /// The chain of the kind's root and group.
    #[must_use]
    pub const fn chain(self) -> Chain {
        match self {
            FileKind::ClusterBackup | FileKind::ClusterBackupV1 | FileKind::Custodian => {
                Chain::ClusterBackup
            }
            FileKind::CellSnapshot | FileKind::CellSnapshotV1 => Chain::CellBackup,
            FileKind::VaultSnapshot | FileKind::VaultSnapshotV1 => Chain::VaultBackup,
        }
    }

    /// Whether the root names the owner as its cell: the snapshot keys do,
    /// the cluster keys name no cell.
    #[must_use]
    pub const fn per_cell(self) -> bool {
        matches!(
            self,
            FileKind::CellSnapshot
                | FileKind::VaultSnapshot
                | FileKind::CellSnapshotV1
                | FileKind::VaultSnapshotV1
        )
    }

    /// Whether the file holds a writer public key and its binding: the
    /// version 2 group key file and the version 2 snapshot key files.
    #[must_use]
    pub const fn bound(self) -> bool {
        matches!(
            self,
            FileKind::ClusterBackup | FileKind::CellSnapshot | FileKind::VaultSnapshot
        )
    }

    /// Whether the sealed part holds the writer's private key after the
    /// group secret: the version 2 snapshot key files (record of lane
    /// m10/backup-followups, row "Where the writer key lives").
    #[must_use]
    pub const fn seals_writer(self) -> bool {
        matches!(self, FileKind::CellSnapshot | FileKind::VaultSnapshot)
    }

    /// The length of the sealed part.
    #[must_use]
    pub const fn sealed_len(self) -> usize {
        if self.seals_writer() {
            SEALED_LEN + WRITER_PRIVATE_LEN
        } else {
            SEALED_LEN
        }
    }

    /// The version 1 kind a version 2 snapshot kind upgrades from, and the
    /// reverse.
    #[must_use]
    pub const fn snapshot_v1(self) -> Option<FileKind> {
        match self {
            FileKind::CellSnapshot => Some(FileKind::CellSnapshotV1),
            FileKind::VaultSnapshot => Some(FileKind::VaultSnapshotV1),
            _ => None,
        }
    }
}
/// The epoch of the root at genesis.
pub const ROOT_EPOCH: u64 = 1;
/// The group generation at genesis.
pub const GENERATION: u32 = 1;
/// The longest custody handle or wrapped key the file holds.
pub const MAX_FIELD_LEN: usize = 4096;

const SEALED_LEN: usize = hybrid_kem::SECRET_KEY_LEN + aead::TAG_LEN;

fn bad(rule: &'static str) -> BackupError {
    BackupError::KeyFile(rule)
}

/// The writer public key of a version 2 key file and its binding
/// signature (F-044).
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    /// The writer's composite public key.
    pub writer: Box<[u8; WRITER_PUBLIC_LEN]>,
    /// The writer's composite signature over [`KeyFile::aad`].
    pub signature: Box<[u8; SIGNATURE_LEN]>,
}

/// A decoded key file: the public key, references and sealed bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyFile {
    /// The owner of the group: the cluster, or the cell of a snapshot key.
    pub cluster: [u8; 16],
    /// The group.
    pub group: [u8; 16],
    /// The group generation.
    pub generation: u32,
    /// The root epoch.
    pub epoch: u64,
    /// The group public key.
    pub public: [u8; hybrid_kem::PUBLIC_KEY_LEN],
    /// The writer key and its binding, for a version 2 group key file.
    pub binding: Option<Binding>,
    /// The custody handle of the root.
    pub handle: Vec<u8>,
    /// `S`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The nonce of the sealed secret.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The sealed group secret.
    pub sealed: Vec<u8>,
    /// What the file is for, which fixes its magic and its chain.
    pub kind: FileKind,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("generation", &self.generation)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl KeyFile {
    /// The magic of this file's kind.
    #[must_use]
    pub fn magic(&self) -> &'static [u8; 22] {
        self.kind.magic()
    }

    /// The AAD of the wrap and the seal. For a version 2 group key file it
    /// also covers the group public key and the writer public key, and it
    /// is the message of the binding signature.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut out = [
            &self.magic()[..],
            &self.cluster[..],
            &self.group[..],
            &self.generation.to_be_bytes(),
            &self.epoch.to_be_bytes(),
        ]
        .concat();
        if let Some(b) = &self.binding {
            out.extend_from_slice(&self.public);
            out.extend_from_slice(&b.writer[..]);
        }
        out
    }

    /// The AAD custody sees for the wrap of the seal key. `fstp-keyd`
    /// takes at most 1,024 bytes of AAD, and a version 2 group key file
    /// carries both public keys in [`KeyFile::aad`]. So a bound file gives
    /// custody `CUSTODY_AAD_LABEL || SHA-256(aad)`, which still binds the
    /// wrap to every byte of it. A file without a binding gives its
    /// [`KeyFile::aad`] as before, so existing wraps still open.
    #[must_use]
    pub fn custody_aad(&self) -> Vec<u8> {
        let aad = self.aad();
        if self.binding.is_none() {
            return aad;
        }
        [CUSTODY_AAD_LABEL, &fstp_crypto::sha256(&aad)[..]].concat()
    }

    /// The group key the writer seals to.
    #[must_use]
    pub fn group_ref(&self) -> GroupRef {
        GroupRef {
            owner: self.cluster,
            group: GroupId(self.group),
            generation: self.generation,
        }
    }

    /// The group public key.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] when it does not decode.
    pub fn public_key(&self) -> Result<HybridPublicKey, BackupError> {
        HybridPublicKey::from_bytes(&self.public).map_err(|_| bad("public key"))
    }

    /// The writer public key of a version 2 group key file.
    #[must_use]
    pub fn writer_public(&self) -> Option<&[u8; WRITER_PUBLIC_LEN]> {
        self.binding.as_ref().map(|b| &*b.writer)
    }

    /// The check before every seal (F-044): this is a version 2 group key
    /// file of the writer's cluster, its writer public key is the public
    /// half of `writer`, and its binding signature verifies under it. So
    /// a replaced group public key or writer key stops the backup.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] naming the check that failed.
    pub fn check_writer(&self, writer: &WriterKey) -> Result<(), BackupError> {
        let b = self.check_binding()?;
        if writer.cluster() != self.cluster {
            return Err(bad("writer key of another cluster"));
        }
        if writer.public() != *b.writer {
            return Err(bad("writer key of another key file"));
        }
        Ok(())
    }

    /// That this is a version 2 group key file whose binding signature
    /// verifies under its own writer public key. A host that only
    /// restores holds no writer key, so it checks this much, and custody
    /// binds both public keys when it opens the secret.
    ///
    /// # Errors
    ///
    /// [`BackupError::KeyFile`] naming the check that failed.
    pub fn check_binding(&self) -> Result<&Binding, BackupError> {
        if !self.kind.bound() {
            return Err(bad("version 1 key file, run upgrade-keys"));
        }
        let b = self.binding.as_ref().ok_or(bad("binding"))?;
        if !writer::binding_verifies(&b.writer[..], &self.aad(), &b.signature[..]) {
            return Err(bad("binding"));
        }
        Ok(b)
    }

    /// The custody root.
    #[must_use]
    pub fn root(&self) -> RootRef {
        RootRef {
            backend: BackendId::Keyd,
            cell: self.kind.per_cell().then_some(CellId(self.cluster)),
            chain: self.kind.chain(),
            epoch: Epoch(self.epoch),
            handle: CustodyHandle(self.handle.clone()),
        }
    }
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BackupError> {
    if field.is_empty() || field.len() > MAX_FIELD_LEN {
        return Err(bad("field length"));
    }
    let len = u16::try_from(field.len()).map_err(|_| bad("field length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Encodes a key file.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for an empty or overlong field, a sealed
/// secret of another length, or a binding on a kind without one.
pub fn encode(f: &KeyFile) -> Result<Vec<u8>, BackupError> {
    if f.sealed.len() != f.kind.sealed_len() {
        return Err(bad("sealed length"));
    }
    if f.kind.bound() != f.binding.is_some() {
        return Err(bad("binding"));
    }
    let mut out = [
        &f.magic()[..],
        &f.cluster[..],
        &f.group[..],
        &f.generation.to_be_bytes(),
        &f.epoch.to_be_bytes(),
    ]
    .concat();
    out.extend_from_slice(&f.public);
    if let Some(b) = &f.binding {
        out.extend_from_slice(&b.writer[..]);
        out.extend_from_slice(&b.signature[..]);
    }
    put16(&mut out, &f.handle)?;
    put16(&mut out, &f.wrapped)?;
    out.extend_from_slice(&f.nonce);
    out.extend_from_slice(&f.sealed);
    Ok(out)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BackupError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(bad("truncated"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn field(&mut self) -> Result<Vec<u8>, BackupError> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        if len == 0 || len > MAX_FIELD_LEN {
            return Err(bad("field length"));
        }
        Ok(self.take(len)?.to_vec())
    }
}

/// Decodes a version 2 group key file. Fuzzed (`backup_key_file_decode`).
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a wrong magic, a cut or overlong field,
/// a generation or epoch of 0, or trailing bytes. A version 1 file is
/// refused with the rule `magic`.
pub fn decode(bytes: &[u8]) -> Result<KeyFile, BackupError> {
    decode_kind(bytes, FileKind::ClusterBackup)
}

/// Decodes a second custodian's key file: the version 1 layout under
/// [`CUSTODIAN_MAGIC`] (ADR-012 record of lane L16). Fuzzed
/// (`backup_key_file_decode`).
///
/// # Errors
///
/// As [`decode`].
pub fn decode_custodian(bytes: &[u8]) -> Result<KeyFile, BackupError> {
    decode_kind(bytes, FileKind::Custodian)
}

/// Decodes a key file of `kind`: the layout of the kind under its magic.
/// Fuzzed (`backup_key_file_decode`).
///
/// # Errors
///
/// As [`decode`].
pub fn decode_kind(bytes: &[u8], kind: FileKind) -> Result<KeyFile, BackupError> {
    let magic = kind.magic();
    let mut r = Reader { rest: bytes };
    if r.take(magic.len())? != magic {
        return Err(bad("magic"));
    }
    let cluster = r.array::<16>()?;
    let group = r.array::<16>()?;
    let generation = u32::from_be_bytes(r.array()?);
    let epoch = u64::from_be_bytes(r.array()?);
    if generation == 0 || epoch == 0 {
        return Err(bad("generation or epoch"));
    }
    let public = r.array::<{ hybrid_kem::PUBLIC_KEY_LEN }>()?;
    let binding = if kind.bound() {
        Some(Binding {
            writer: Box::new(r.array::<WRITER_PUBLIC_LEN>()?),
            signature: Box::new(r.array::<SIGNATURE_LEN>()?),
        })
    } else {
        None
    };
    let handle = r.field()?;
    let wrapped = r.field()?;
    let nonce = r.array::<{ aead::NONCE_LEN }>()?;
    let sealed = r.take(kind.sealed_len())?.to_vec();
    if !r.rest.is_empty() {
        return Err(bad("trailing bytes"));
    }
    Ok(KeyFile {
        cluster,
        group,
        generation,
        epoch,
        public,
        binding,
        handle,
        wrapped,
        nonce,
        sealed,
        kind,
    })
}

/// A new version 2 group key file and the writer key it is bound to.
pub struct Created {
    /// The bytes of `cluster-backup.key`.
    pub key_file: Vec<u8>,
    /// The bytes of `cluster-backup-writer.key`. Wiped on drop.
    pub writer_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Created").finish_non_exhaustive()
    }
}

/// Genesis (`fstp-backup init-keys`): draws the group key pair, a group
/// id and the writer key, creates the root through `custody`, wraps a
/// fresh `S` under it, seals the group secret under `S`, and binds the
/// writer key (F-044).
///
/// # Errors
///
/// [`BackupError::Custody`] when custody refuses, and
/// [`BackupError::Seal`] when a draw, a signature or the seal fails.
pub async fn create<C: Custody>(custody: &C, cluster: [u8; 16]) -> Result<Created, BackupError> {
    let secret = hybrid_kem::generate().map_err(|_| BackupError::Seal("group key"))?;
    let group = fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("group id"))?;
    let root = new_root(custody, cluster, FileKind::ClusterBackup).await?;
    let writer = WriterKey::generate(cluster)?;
    let file = KeyFile {
        cluster,
        group,
        generation: GENERATION,
        epoch: ROOT_EPOCH,
        public: secret.public().to_bytes(),
        binding: None,
        handle: root.handle.0.clone(),
        wrapped: Vec::new(),
        nonce: [0; aead::NONCE_LEN],
        sealed: Vec::new(),
        kind: FileKind::ClusterBackup,
    };
    let key_file = seal_file(custody, &root, file, &secret, Some(&writer)).await?;
    Ok(Created {
        key_file,
        writer_key: writer.encode()?,
    })
}

/// `fstp-backup upgrade-keys` (record of lane m10/backup-format): opens
/// the group secret of the version 1 file `v1` through `custody`, and
/// writes a version 2 file for the same group key, root, group and
/// generation, bound to `writer` or to a fresh writer key. A fresh `S`
/// is wrapped under the same root with the version 2 AAD.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a file that is not version 1 or a writer
/// key of another cluster, and the errors of [`open`] and the seal.
pub async fn upgrade<C: Custody>(
    custody: &C,
    v1: &[u8],
    writer: Option<WriterKey>,
) -> Result<Created, BackupError> {
    let old = decode_kind(v1, FileKind::ClusterBackupV1)?;
    let secret = open(custody, &old).await?;
    let writer = match writer {
        Some(w) if w.cluster() == old.cluster => w,
        Some(_) => return Err(bad("writer key of another cluster")),
        None => WriterKey::generate(old.cluster)?,
    };
    let root = old.root();
    let file = KeyFile {
        kind: FileKind::ClusterBackup,
        binding: None,
        wrapped: Vec::new(),
        sealed: Vec::new(),
        ..old
    };
    let key_file = seal_file(custody, &root, file, &secret, Some(&writer)).await?;
    Ok(Created {
        key_file,
        writer_key: writer.encode()?,
    })
}

/// As [`create`], for a second custodian's key file when `custodian`
/// (ADR-012 record of lane L16). It creates the root `{cell: none,
/// chain: ClusterBackup, epoch: 1}` in `custody`, and no other. A group
/// key file comes from [`create`], so this refuses `custodian = false`.
///
/// # Errors
///
/// As [`create`], and [`BackupError::KeyFile`] for a group key file.
pub async fn create_as<C: Custody>(
    custody: &C,
    cluster: [u8; 16],
    custodian: bool,
) -> Result<Vec<u8>, BackupError> {
    if !custodian {
        return Err(bad("a group key file comes from create"));
    }
    create_kind(custody, cluster, FileKind::Custodian).await
}

async fn new_root<C: Custody>(
    custody: &C,
    owner: [u8; 16],
    kind: FileKind,
) -> Result<RootRef, BackupError> {
    custody
        .create_root(RootLabel {
            cell: kind.per_cell().then_some(CellId(owner)),
            chain: kind.chain(),
            epoch: Epoch(ROOT_EPOCH),
        })
        .await
        .map_err(|_| BackupError::Custody("create root"))
}

/// Binds `writer` into `file` when given, wraps a fresh `S` under `root`
/// with the file's AAD, seals `secret` under `S`, and encodes the file.
async fn seal_file<C: Custody>(
    custody: &C,
    root: &RootRef,
    mut file: KeyFile,
    secret: &HybridSecretKey,
    writer: Option<&WriterKey>,
) -> Result<Vec<u8>, BackupError> {
    if let Some(w) = writer {
        file.binding = Some(Binding {
            writer: Box::new(w.public()),
            signature: Box::new([0; SIGNATURE_LEN]),
        });
        let signature = w.sign_binding(&file.aad())?;
        if let Some(b) = file.binding.as_mut() {
            *b.signature = signature;
        }
    }
    let seal = SealKey::generate().map_err(|_| BackupError::Seal("seal key"))?;
    let aad = file.aad();
    let wrapped = custody
        .wrap(root, &seal, &Aad(file.custody_aad()))
        .await
        .map_err(|_| BackupError::Custody("wrap"))?;
    file.wrapped = wrapped.0;
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| BackupError::Seal("seal key"))?;
    let mut plain = Zeroizing::new(secret.to_bytes().to_vec());
    if file.kind.seals_writer() {
        let w = writer.ok_or(bad("writer key"))?;
        plain.extend_from_slice(&w.private_bytes()?[..]);
    }
    let sealed = aead::seal(&key, &aad, &plain[..]).map_err(|_| BackupError::Seal("group key"))?;
    file.nonce = sealed.nonce;
    file.sealed = sealed.body;
    encode(&file)
}

/// As [`create`], for a key file of `kind` owned by `owner`: a cluster, or
/// the cell of a snapshot key (ADR-004 record of lane L17). It creates the
/// root of the kind's chain at epoch 1, labelled with the cell for a
/// snapshot key, and no other. A version 2 snapshot key file draws its
/// writer key and seals it beside the group secret (ADR-012 record of
/// lane m10/backup-followups). A version 2 group key file keeps its
/// writer key in a file of its own, so it comes from [`create`] only.
///
/// # Errors
///
/// As [`create`], and [`BackupError::KeyFile`] for
/// [`FileKind::ClusterBackup`].
pub async fn create_kind<C: Custody>(
    custody: &C,
    owner: [u8; 16],
    kind: FileKind,
) -> Result<Vec<u8>, BackupError> {
    if kind == FileKind::ClusterBackup {
        return Err(bad("a group key file comes from create"));
    }
    let secret = hybrid_kem::generate().map_err(|_| BackupError::Seal("group key"))?;
    let group = fstp_crypto::random_array::<16>().map_err(|_| BackupError::Seal("group id"))?;
    let writer = if kind.seals_writer() {
        Some(WriterKey::generate(owner)?)
    } else {
        None
    };
    let root = new_root(custody, owner, kind).await?;
    let file = KeyFile {
        cluster: owner,
        group,
        generation: GENERATION,
        epoch: ROOT_EPOCH,
        public: secret.public().to_bytes(),
        binding: None,
        handle: root.handle.0.clone(),
        wrapped: Vec::new(),
        nonce: [0; aead::NONCE_LEN],
        sealed: Vec::new(),
        kind,
    };
    seal_file(custody, &root, file, &secret, writer.as_ref()).await
}

/// Opens the sealed part of `f` through `custody`: the group secret, and
/// for a version 2 snapshot key file the writer key. The secret's public
/// half must be the file's public key, and the writer key's public half
/// the file's writer public key.
async fn open_parts<C: Custody>(
    custody: &C,
    f: &KeyFile,
) -> Result<(HybridSecretKey, Option<WriterKey>), BackupError> {
    let aad = f.aad();
    let seal = custody
        .unwrap(
            &f.root(),
            &WrappedSealKey(f.wrapped.clone()),
            &Aad(f.custody_aad()),
        )
        .await
        .map_err(|_| BackupError::Custody("unwrap"))?;
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("seal key"))?;
    let plain = aead::open(&key, &f.nonce, &aad, &f.sealed).map_err(|_| bad("open"))?;
    let (secret, private) = plain
        .split_at_checked(hybrid_kem::SECRET_KEY_LEN)
        .ok_or(bad("secret key"))?;
    let secret = HybridSecretKey::from_bytes(secret).map_err(|_| bad("secret key"))?;
    if secret.public().to_bytes() != f.public {
        return Err(bad("public key mismatch"));
    }
    let writer = if f.kind.seals_writer() {
        let w = WriterKey::from_private(f.cluster, private)?;
        if Some(&w.public()) != f.writer_public() {
            return Err(bad("writer key mismatch"));
        }
        Some(w)
    } else if private.is_empty() {
        None
    } else {
        return Err(bad("secret key"));
    };
    Ok((secret, writer))
}

/// Opens the group secret of `f` through `custody`. The secret's public
/// half must be the file's public key.
///
/// # Errors
///
/// [`BackupError::Custody`] when custody refuses the unwrap, and
/// [`BackupError::KeyFile`] when the secret does not open or does not
/// match.
pub async fn open<C: Custody>(custody: &C, f: &KeyFile) -> Result<HybridSecretKey, BackupError> {
    open_parts(custody, f).await.map(|(s, _)| s)
}

/// Opens the writer key sealed in a version 2 snapshot key file through
/// `custody` (ADR-012 record of lane m10/backup-followups, row "Where the
/// writer key lives"). Its public half must be the file's writer public
/// key.
///
/// # Errors
///
/// As [`open`], and [`BackupError::KeyFile`] for a kind that seals no
/// writer key.
pub async fn open_writer<C: Custody>(custody: &C, f: &KeyFile) -> Result<WriterKey, BackupError> {
    open_parts(custody, f)
        .await?
        .1
        .ok_or(bad("no sealed writer key"))
}

/// The upgrade of a version 1 snapshot key file to version 2 of `kind`
/// (ADR-012 record of lane m10/backup-followups, row "Upgrade"): opens the
/// group secret of `v1` through `custody`, draws a writer key, and seals
/// both under a fresh `S` wrapped under the same root, with the same
/// owner, group, generation and group key.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a `kind` that is not a version 2
/// snapshot kind or a file that is not its version 1, and the errors of
/// [`open`] and the seal.
pub async fn upgrade_snapshot<C: Custody>(
    custody: &C,
    v1: &[u8],
    kind: FileKind,
) -> Result<Vec<u8>, BackupError> {
    let old_kind = kind.snapshot_v1().ok_or(bad("not a snapshot key file"))?;
    let old = decode_kind(v1, old_kind)?;
    let secret = open(custody, &old).await?;
    let writer = WriterKey::generate(old.cluster)?;
    let root = old.root();
    let file = KeyFile {
        kind,
        binding: None,
        wrapped: Vec::new(),
        sealed: Vec::new(),
        ..old
    };
    seal_file(custody, &root, file, &secret, Some(&writer)).await
}
