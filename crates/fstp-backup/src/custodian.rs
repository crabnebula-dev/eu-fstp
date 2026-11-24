//! The second custodian of the ClusterBackup chain (ADR-012 record of
//! lane L16, I-80, I-81, R-CR-01).
//!
//! Decided by Daniel on 2026-11-21: a second `fstp-keyd` on another
//! machine holds its own custody of the ClusterBackup chain, so a restore
//! works after the first host is gone.
//!
//! No root moves between custodies. The second host creates its own
//! ClusterBackup root and a hybrid KEM key pair, the custodian key, sealed
//! under that root in `custodian.key` ([`init`]). It hands out the public
//! half in a request:
//!
//! ```text
//! request = "FCP1" | version u8 = 1 | cluster 16 | custodian id 16 | public key 1216
//! ```
//!
//! The first host opens the group secret through its own custody and
//! seals it to that public key in one ADR-012 container of kind 4, the
//! escrow ([`escrow`]):
//!
//! ```text
//! plaintext = group 16 | be32(generation) | group public key 1216 | group secret key 2432
//! ```
//!
//! The second host opens the escrow through its own custody ([`open`]).
//! Since lane m10/backup-followups the escrow is an `FBC2` container that
//! names the custodian id and carries the cluster writer key's signature,
//! so the second host verifies it under the version 2 key file.
//!
//! That key file reaches the second host through the object stores with
//! no operator step ([`publish`], [`adopt_published`]):
//!
//! ```text
//! published = "FBK1" | version u8 = 1 | len u16 | key file | tag 32
//! tag       = HMAC-SHA256(HKDF-SHA256(group secret, salt = cluster,
//!             info = "fstp-backup-key-file-tag-v1"), key file)
//! ```
//!
//! Only a holder of the group secret makes or checks the tag: the first
//! host through its root, the second through its escrow. Every plain copy of a secret here sits in `Zeroizing` storage (ADR-001
//! record of 2026-11-21).

use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_custody::Custody;
use fstp_keys::GroupId;
use zeroize::Zeroizing;

use crate::keyfile::{self, KeyFile};
use crate::object::{ObjectIdent, open_object, seal_object};
use crate::snapshot::{ObjectStore, first_good};
use crate::writer::WriterKey;
use crate::{BackupError, ContainerKind, GroupRef, open_container};

/// The custodian key file in the second host's credentials directory.
pub const CUSTODIAN_KEY_FILE: &str = "custodian.key";
/// The request file the second host hands to the first.
pub const REQUEST_FILE: &str = "custodian.pub";
/// The escrow file in the second host's credentials directory.
pub const ESCROW_FILE: &str = "cluster-backup.escrow";
/// The magic of a request.
pub const REQUEST_MAGIC: [u8; 4] = *b"FCP1";
/// The version of a request.
pub const REQUEST_VERSION: u8 = 1;
/// The length of a request.
pub const REQUEST_LEN: usize = 4 + 1 + 16 + 16 + hybrid_kem::PUBLIC_KEY_LEN;
/// The length of an escrow plaintext.
pub const ESCROW_PLAIN_LEN: usize =
    16 + 4 + hybrid_kem::PUBLIC_KEY_LEN + hybrid_kem::SECRET_KEY_LEN;
/// The longest escrow file read.
pub const MAX_ESCROW_LEN: usize = 16 * 1024;

fn bad(rule: &'static str) -> BackupError {
    BackupError::KeyFile(rule)
}

/// A second custodian's request: the cluster, its custodian id and the
/// public half of its custodian key. It holds no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The cluster whose group secret the custodian will hold.
    pub cluster: [u8; 16],
    /// The custodian id, the group field of its key file.
    pub custodian: [u8; 16],
    /// The custodian public key.
    pub public: [u8; hybrid_kem::PUBLIC_KEY_LEN],
}

/// Encodes a request.
#[must_use]
pub fn encode_request(r: &Request) -> Vec<u8> {
    let mut out = Vec::with_capacity(REQUEST_LEN);
    out.extend_from_slice(&REQUEST_MAGIC);
    out.push(REQUEST_VERSION);
    out.extend_from_slice(&r.cluster);
    out.extend_from_slice(&r.custodian);
    out.extend_from_slice(&r.public);
    out
}

/// Decodes a request. Fuzzed (`backup_custodian_decode`).
///
/// # Errors
///
/// [`BackupError::KeyFile`] for any length but [`REQUEST_LEN`], a wrong
/// magic or version, and a public key that does not decode.
pub fn decode_request(bytes: &[u8]) -> Result<Request, BackupError> {
    if bytes.len() != REQUEST_LEN {
        return Err(bad("request length"));
    }
    let (magic, rest) = bytes.split_at_checked(4).ok_or(bad("request length"))?;
    if magic != REQUEST_MAGIC {
        return Err(bad("request magic"));
    }
    let (version, rest) = rest.split_first().ok_or(bad("request length"))?;
    if *version != REQUEST_VERSION {
        return Err(bad("request version"));
    }
    let (cluster, rest) = rest.split_at_checked(16).ok_or(bad("request length"))?;
    let (custodian, public) = rest.split_at_checked(16).ok_or(bad("request length"))?;
    HybridPublicKey::from_bytes(public).map_err(|_| bad("request public key"))?;
    Ok(Request {
        cluster: cluster.try_into().map_err(|_| bad("request length"))?,
        custodian: custodian.try_into().map_err(|_| bad("request length"))?,
        public: public.try_into().map_err(|_| bad("request length"))?,
    })
}

/// The opened plaintext of an escrow.
pub struct EscrowPlain {
    /// The group.
    pub group: [u8; 16],
    /// The group generation.
    pub generation: u32,
    /// The group public key.
    pub public: [u8; hybrid_kem::PUBLIC_KEY_LEN],
    /// The group secret.
    pub secret: HybridSecretKey,
}

/// Decodes the plaintext of an escrow. The secret's public half must be
/// the public key it names. Fuzzed (`backup_custodian_decode`).
///
/// # Errors
///
/// [`BackupError::KeyFile`] for any length but [`ESCROW_PLAIN_LEN`], a
/// generation of 0, a secret that does not decode, or one of another
/// public key.
pub fn decode_escrow_plain(bytes: &[u8]) -> Result<EscrowPlain, BackupError> {
    if bytes.len() != ESCROW_PLAIN_LEN {
        return Err(bad("escrow length"));
    }
    let (group, rest) = bytes.split_at_checked(16).ok_or(bad("escrow length"))?;
    let (generation, rest) = rest.split_at_checked(4).ok_or(bad("escrow length"))?;
    let (public, secret) = rest
        .split_at_checked(hybrid_kem::PUBLIC_KEY_LEN)
        .ok_or(bad("escrow length"))?;
    let generation = u32::from_be_bytes(generation.try_into().map_err(|_| bad("escrow length"))?);
    if generation == 0 {
        return Err(bad("escrow generation"));
    }
    let public: [u8; hybrid_kem::PUBLIC_KEY_LEN] =
        public.try_into().map_err(|_| bad("escrow length"))?;
    let secret = HybridSecretKey::from_bytes(secret).map_err(|_| bad("escrow secret key"))?;
    if secret.public().to_bytes() != public {
        return Err(bad("escrow public key mismatch"));
    }
    Ok(EscrowPlain {
        group: group.try_into().map_err(|_| bad("escrow length"))?,
        generation,
        public,
        secret,
    })
}

/// `fstp-backup custodian-init`, on the second host: creates its own
/// ClusterBackup root through `custody` and a custodian key sealed under
/// it. Returns the custodian key file and the request.
///
/// # Errors
///
/// As [`keyfile::create`].
pub async fn init<C: Custody>(
    custody: &C,
    cluster: [u8; 16],
) -> Result<(Vec<u8>, Vec<u8>), BackupError> {
    let bytes = keyfile::create_as(custody, cluster, true).await?;
    let f = keyfile::decode_custodian(&bytes)?;
    let request = encode_request(&Request {
        cluster,
        custodian: f.group,
        public: f.public,
    });
    Ok((bytes, request))
}

/// `fstp-backup custodian-escrow`, on the first host: opens the group
/// secret of `key` through `custody` and seals it to the custodian key of
/// `request`, as an `FBC2` container of kind 4 that names the custodian id
/// and carries the signature of the cluster's writer key `writer`
/// (ADR-012 record of lane m10/backup-followups, row "Escrow, version 2").
/// Returns the escrow container.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a request of another cluster or one that
/// does not decode, a writer key that is not the key file's, and the
/// errors of [`keyfile::open`] and the seal.
pub async fn escrow<C: Custody>(
    custody: &C,
    key: &KeyFile,
    writer: &WriterKey,
    request: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let req = decode_request(request)?;
    if req.cluster != key.cluster || key.kind != keyfile::FileKind::ClusterBackup {
        return Err(bad("another cluster"));
    }
    key.check_writer(writer)?;
    let to = HybridPublicKey::from_bytes(&req.public).map_err(|_| bad("request public key"))?;
    let secret = keyfile::open(custody, key).await?;
    let mut plain = Zeroizing::new(Vec::with_capacity(ESCROW_PLAIN_LEN));
    plain.extend_from_slice(&key.group);
    plain.extend_from_slice(&key.generation.to_be_bytes());
    plain.extend_from_slice(&key.public);
    plain.extend_from_slice(&secret.to_bytes()[..]);
    let group = GroupRef {
        owner: key.cluster,
        group: GroupId(req.custodian),
        generation: keyfile::GENERATION,
    };
    seal_object(
        &to,
        writer,
        &group,
        &ObjectIdent::Escrow(req.custodian),
        &plain,
    )
}

/// Opens the group secret of `key` on the second host: the custodian key
/// through `custody`, then the escrow under it. The escrow must name the
/// group, generation and public key of `key`.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a custodian key file of another cluster,
/// an escrow of another kind, cluster or group key, and the errors of
/// [`keyfile::open`] and of the container's opener.
pub async fn open<C: Custody>(
    custody: &C,
    custodian_key: &[u8],
    escrow: &[u8],
    key: &KeyFile,
) -> Result<HybridSecretKey, BackupError> {
    let ck = keyfile::decode_custodian(custodian_key)?;
    if ck.cluster != key.cluster || key.kind != keyfile::FileKind::ClusterBackup {
        return Err(bad("another cluster"));
    }
    let custodian_secret = keyfile::open(custody, &ck).await?;
    open_with(&custodian_secret, ck.group, escrow, key)
}

/// Opens `escrow` under the opened custodian key of custodian `id`. An
/// `FBC2` escrow (record of lane m10/backup-followups) must verify under
/// the writer public key of `key` before anything opens, and name `id`.
/// An `FBC1` escrow, made before that lane and carried by hand, opens as
/// the record of lane L16 says. Either must name the group, generation
/// and public key of `key`.
fn open_with(
    custodian_secret: &HybridSecretKey,
    id: [u8; 16],
    escrow: &[u8],
    key: &KeyFile,
) -> Result<HybridSecretKey, BackupError> {
    if escrow.len() > MAX_ESCROW_LEN {
        return Err(bad("escrow length"));
    }
    let plain = if escrow.get(..4) == Some(&b"FBC2"[..]) {
        let writer = key.check_binding()?;
        let o = open_object(custodian_secret, &writer.writer[..], escrow)?;
        let plain = Zeroizing::new(o.plaintext);
        if o.owner != key.cluster || o.ident != ObjectIdent::Escrow(id) {
            return Err(bad("escrow container"));
        }
        plain
    } else {
        let opened = open_container(custodian_secret, escrow)?;
        let plain = Zeroizing::new(opened.plaintext);
        if opened.kind != ContainerKind::CustodianEscrow
            || opened.owner != key.cluster
            || opened.part != 0
        {
            return Err(bad("escrow container"));
        }
        plain
    };
    let p = decode_escrow_plain(&plain)?;
    if p.group != key.group || p.generation != key.generation || p.public != key.public {
        return Err(bad("escrow names another group key"));
    }
    Ok(p.secret)
}

/// The object name of the published key file of `cluster` (ADR-012 record
/// of lane m10/backup-followups, row "Published key file").
#[must_use]
pub fn published_name(cluster: [u8; 16]) -> String {
    format!("{}/keys/{}", crate::sigv4::hex(&cluster), keyfile::KEY_FILE)
}

/// The tag of the version 2 key file `key_file` of `cluster` under the
/// group secret `secret`: HMAC-SHA256 over the key file under
/// HKDF-SHA256(input: the secret key bytes, salt: the cluster id, info:
/// [`TAG_INFO`]). Only a holder of the group secret makes or checks it.
///
/// # Errors
///
/// [`BackupError::Seal`] when the key derivation fails.
pub fn key_file_tag(
    secret: &HybridSecretKey,
    cluster: [u8; 16],
    key_file: &[u8],
) -> Result<[u8; 32], BackupError> {
    let mut k = Zeroizing::new([0u8; 32]);
    let ikm = secret.to_bytes();
    fstp_crypto::kdf::hkdf_sha256(&cluster, &ikm[..], TAG_INFO, &mut k[..])
        .map_err(|_| BackupError::Seal("key file tag"))?;
    Ok(fstp_crypto::hmac_sha256(&k[..], key_file))
}

/// Encodes the published key file: `"FBK1" | version u8 = 1 | len u16 |
/// key file | tag 32`.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a key file longer than a `u16` counts.
pub fn encode_published(key_file: &[u8], tag: &[u8; 32]) -> Result<Vec<u8>, BackupError> {
    let len = u16::try_from(key_file.len()).map_err(|_| bad("published length"))?;
    let mut out = Vec::with_capacity(key_file.len().saturating_add(39));
    out.extend_from_slice(&PUBLISHED_MAGIC);
    out.push(PUBLISHED_VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(key_file);
    out.extend_from_slice(tag);
    Ok(out)
}

/// Decodes a published key file into the key file bytes and the tag, in
/// one spelling. Nothing here checks the tag or decodes the key file.
/// Fuzzed (`backup_custodian_decode`).
///
/// # Errors
///
/// [`BackupError::KeyFile`] for another magic or version, a length that
/// does not match, or a body above [`MAX_PUBLISHED_LEN`].
pub fn decode_published(bytes: &[u8]) -> Result<(&[u8], [u8; 32]), BackupError> {
    let e = bad("published key file");
    if bytes.len() > MAX_PUBLISHED_LEN {
        return Err(e);
    }
    let (magic, rest) = bytes.split_first_chunk::<4>().ok_or(e)?;
    let (&[version], rest) = rest.split_first_chunk::<1>().ok_or(e)?;
    let (len, rest) = rest.split_first_chunk::<2>().ok_or(e)?;
    if *magic != PUBLISHED_MAGIC || version != PUBLISHED_VERSION {
        return Err(e);
    }
    let (key_file, tag) = rest
        .split_at_checked(usize::from(u16::from_be_bytes(*len)))
        .ok_or(e)?;
    let tag: [u8; 32] = tag.try_into().map_err(|_| e)?;
    Ok((key_file, tag))
}

/// The magic of a published key file.
pub const PUBLISHED_MAGIC: [u8; 4] = *b"FBK1";
/// The version of a published key file.
pub const PUBLISHED_VERSION: u8 = 1;
/// The longest published key file read.
pub const MAX_PUBLISHED_LEN: usize = 64 * 1024;
/// The HKDF info of the key file tag.
pub const TAG_INFO: &[u8] = b"fstp-backup-key-file-tag-v1";

/// The published key file of `key_file` for its cluster, tagged under the
/// group secret that `custody` opens (`fstp-backup publish-key`, ADR-012
/// record of lane m10/backup-followups, row "Publishing"). The key file
/// must be version 2 with a binding that verifies.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a key file that is not version 2 or whose
/// binding fails, and the errors of [`keyfile::open`] and the tag.
pub async fn publish<C: Custody>(custody: &C, key_file: &[u8]) -> Result<Vec<u8>, BackupError> {
    let key = keyfile::decode(key_file)?;
    key.check_binding()?;
    let secret = keyfile::open(custody, &key).await?;
    encode_published(key_file, &key_file_tag(&secret, key.cluster, key_file)?)
}

/// On the second host, the version 2 key file of `cluster` from the first
/// of `stores` whose published copy is good (ADR-012 record of lane
/// m10/backup-followups, row "On the second host"): its binding verifies,
/// `escrow` opens under the custodian key that `custody` opens, the
/// escrow names its group, generation and group public key, the local
/// version 1 file `local`, if any, names the same, and the tag verifies
/// under the escrow's secret. Returns the key file bytes.
///
/// # Errors
///
/// [`BackupError::NotFound`] when no store holds a copy, otherwise the
/// first refusal, and the errors of [`keyfile::open`] for the custodian
/// key.
pub async fn adopt_published<C: Custody>(
    custody: &C,
    stores: &[&dyn ObjectStore],
    cluster: [u8; 16],
    local: Option<&[u8]>,
    custodian_key: &[u8],
    escrow: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let ck = keyfile::decode_custodian(custodian_key)?;
    if ck.cluster != cluster {
        return Err(bad("another cluster"));
    }
    let pin = match local {
        None => None,
        Some(b) => Some(
            keyfile::decode_kind(b, keyfile::FileKind::ClusterBackupV1)
                .or_else(|_| keyfile::decode(b))?,
        ),
    };
    let custodian_secret = keyfile::open(custody, &ck).await?;
    let got = first_good(stores, &published_name(cluster), |bytes| {
        let (file, tag) = decode_published(&bytes)?;
        let key = keyfile::decode(file)?;
        if key.cluster != cluster {
            return Err(bad("another cluster"));
        }
        key.check_binding()?;
        if let Some(p) = &pin
            && (p.cluster, p.group, p.generation, p.public)
                != (key.cluster, key.group, key.generation, key.public)
        {
            return Err(bad("published key file names another group key"));
        }
        let secret = open_with(&custodian_secret, ck.group, escrow, &key)?;
        let want = key_file_tag(&secret, cluster, file)?;
        if !fstp_crypto::constant_time_eq(&want, &tag) {
            return Err(bad("published key file tag"));
        }
        Ok(file.to_vec())
    })
    .await?;
    got.ok_or(BackupError::NotFound)
}
