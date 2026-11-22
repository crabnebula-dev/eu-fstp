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
//! Every plain copy of a secret here sits in `Zeroizing` storage (ADR-001
//! record of 2026-11-21).

use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_custody::Custody;
use fstp_keys::GroupId;
use zeroize::Zeroizing;

use crate::keyfile::{self, KeyFile};
use crate::{BackupError, ContainerKind, GroupRef, open_container, seal_container};

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
/// `request`. Returns the escrow container.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a request of another cluster or one that
/// does not decode, and the errors of [`keyfile::open`] and the seal.
pub async fn escrow<C: Custody>(
    custody: &C,
    key: &KeyFile,
    request: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let req = decode_request(request)?;
    if req.cluster != key.cluster || key.custodian {
        return Err(bad("another cluster"));
    }
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
    seal_container(&to, ContainerKind::CustodianEscrow, &group, 0, &plain)
}

/// Opens the group secret of `key` on the second host: the custodian key
/// through `custody`, then the escrow under it. The escrow must name the
/// group, generation and public key of `key`.
///
/// # Errors
///
/// [`BackupError::KeyFile`] for a custodian key file of another cluster,
/// an escrow of another kind, cluster or group key, and the errors of
/// [`keyfile::open`] and [`open_container`].
pub async fn open<C: Custody>(
    custody: &C,
    custodian_key: &[u8],
    escrow: &[u8],
    key: &KeyFile,
) -> Result<HybridSecretKey, BackupError> {
    let ck = keyfile::decode_custodian(custodian_key)?;
    if ck.cluster != key.cluster || key.custodian {
        return Err(bad("another cluster"));
    }
    if escrow.len() > MAX_ESCROW_LEN {
        return Err(bad("escrow length"));
    }
    let custodian_secret = keyfile::open(custody, &ck).await?;
    let opened = open_container(&custodian_secret, escrow)?;
    let plain = Zeroizing::new(opened.plaintext);
    if opened.kind != ContainerKind::CustodianEscrow
        || opened.owner != key.cluster
        || opened.part != 0
    {
        return Err(bad("escrow container"));
    }
    let p = decode_escrow_plain(&plain)?;
    if p.group != key.group || p.generation != key.generation || p.public != key.public {
        return Err(bad("escrow names another group key"));
    }
    Ok(p.secret)
}
