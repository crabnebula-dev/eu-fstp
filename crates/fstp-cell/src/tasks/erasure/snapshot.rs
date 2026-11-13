//! The keystore image of the App chain: what a keystore snapshot and a
//! backup of the keystore tables hold (ADR-012 "Keystore snapshots",
//! design sections 3.5 and 3.8, I-80, I-81). Lane F-ERASE.
//!
//! An image holds the wrapped and sealed rows of a [`Keystore`] only: each
//! root's custody reference and wrapped seal key, each group secret sealed
//! under a seal key, each data key sealed to its group key through the
//! hybrid KEM, and each text's sealed blob. It holds no root material
//! (I-80), no open seal key and no open group secret. So an image opens
//! only through custody, and only while a root of its rows lives (I-81).
//!
//! Interim, pending Daniel:
//!
//! - The keystore is still held in memory by its owner (W2e has not
//!   moved it into the `keystore` tables), so the image stands for those
//!   tables. The texts are in it too, as `blob.text` would hold them.
//! - The level 2 signing key rows and the chain state are not in it yet.
//!   They open nothing that the tests here read.
//! - The bytes below are this lane's own:
//!
//! ```text
//! image = "FKI1" | version u8 = 1 | cell 16
//!         | n u32 | root*  | n u32 | group* | n u32 | key* | n u32 | text*
//!         | n u32 | digest*
//! root  = epoch u64 | backend u8 | handle_len u8 | handle | wrapped_len u16
//!         | wrapped | destroyed u8 | receipt digest 32, when destroyed = 1
//! group = group 16 | generation u32 | epoch u64 | nonce 12 | len u32 | body
//! key   = dek 16 | group 16 | generation u32 | sealed key 1210 (FSK1)
//! text  = id 16 | dek 16 | generation u32 | len u32 | sealed blob (FSB1)
//! digest = keyed digest 32 | account 16
//! ```
//!
//! Integers are big-endian. Rows are in strictly increasing order of
//! their key (epoch, then group and generation, then data key, then text
//! id, then keyed digest), so the decoder admits one spelling only. A data
//! key's group and generation must be those of its sealed key's header.
//! Bytes after the last digest are refused. Fuzzed
//! (`keystore_image_decode`).
//!
//! The digest rows are the keyed login email index (design sections 3.5
//! and 4.2, decision 27): each `HMAC-SHA-256(Lookup, normalised address)`
//! and its account, as an index table row would hold them. Lane
//! m3/erase-steps added them, interim pending Daniel, with the image still
//! at version 1, since no image has left a test world.

use std::collections::BTreeMap;

use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::{Aad, BackendId, CustodyHandle, RootRef, SealKey, WrappedSealKey};
use fstp_keys::envelope::{
    self, SEALED_KEY_LEN, decode_sealed_blob, decode_sealed_key, encode_sealed_blob,
    encode_sealed_key,
};
use fstp_keys::{CellId, Chain, Epoch, GroupId, Purpose};

use super::{
    GroupRow, Keystore, ctx_for, digest_key, keyed_digest, normalise_email, open_group, seal_aad,
};

/// The magic of a keystore image.
pub const IMAGE_MAGIC: [u8; 4] = *b"FKI1";
/// The only image version.
pub const IMAGE_VERSION: u8 = 1;
/// The longest custody handle an image holds.
pub const MAX_HANDLE: usize = 255;
/// The longest wrapped seal key an image holds.
pub const MAX_WRAPPED: usize = 1024;
/// The longest sealed group secret an image holds.
pub const MAX_GROUP_BODY: usize = 8192;
/// The longest sealed text an image holds: 16 MiB.
pub const MAX_BLOB: usize = 16 * 1024 * 1024;

/// Why an image did not decode. It names the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// The image ends early.
    Truncated,
    /// The image breaks the named rule.
    Malformed(&'static str),
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::Truncated => f.write_str("the keystore image is truncated"),
            ImageError::Malformed(rule) => write!(f, "the keystore image breaks the {rule} rule"),
        }
    }
}

impl std::error::Error for ImageError {}

/// One root row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRoot {
    /// The epoch.
    pub epoch: u64,
    /// The custody backend.
    pub backend: BackendId,
    /// The custody handle.
    pub handle: Vec<u8>,
    /// The seal key `S(epoch)`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The digest of the destroy receipt, once the root is destroyed.
    pub receipt: Option<[u8; 32]>,
}

/// One group secret row, sealed under the seal key of `epoch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageGroup {
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The epoch of the seal key.
    pub epoch: u64,
    /// The AES-256-GCM nonce.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The ciphertext and its tag.
    pub body: Vec<u8>,
}

/// One data key row: the key sealed to its group key, in the FSK1 form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageKey {
    /// The data key id.
    pub dek: [u8; 16],
    /// The group.
    pub group: [u8; 16],
    /// The generation.
    pub generation: u32,
    /// The sealed key bytes.
    pub sealed: Vec<u8>,
}

/// One text row: its data key id, the generation its blob was sealed
/// under, and its sealed blob, in the FSB1 form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageText {
    /// The text id.
    pub id: [u8; 16],
    /// The data key id.
    pub dek: [u8; 16],
    /// The group generation of the blob's seal context.
    pub generation: u32,
    /// The sealed blob bytes.
    pub blob: Vec<u8>,
}

/// One row of the keyed login email index (module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageDigest {
    /// The keyed digest of a normalised login email.
    pub digest: [u8; 32],
    /// The account it names.
    pub account: [u8; 16],
}

/// The wrapped and sealed rows of one keystore (module documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeystoreImage {
    /// The cell.
    pub cell: [u8; 16],
    /// The roots, by epoch.
    pub roots: Vec<ImageRoot>,
    /// The sealed group secrets, by group and generation.
    pub groups: Vec<ImageGroup>,
    /// The sealed data keys, by id.
    pub keys: Vec<ImageKey>,
    /// The sealed texts, by id.
    pub texts: Vec<ImageText>,
    /// The keyed login email index, by digest.
    pub digests: Vec<ImageDigest>,
}

const fn backend_code(b: BackendId) -> u8 {
    match b {
        BackendId::Okms => 1,
        BackendId::Keyd => 2,
        BackendId::Simulator => 3,
    }
}

fn backend_of(code: u8) -> Option<BackendId> {
    match code {
        1 => Some(BackendId::Okms),
        2 => Some(BackendId::Keyd),
        3 => Some(BackendId::Simulator),
        _ => None,
    }
}

impl Keystore {
    /// The image of this keystore (module documentation).
    ///
    /// # Errors
    ///
    /// [`ImageError::Malformed`] when a row does not encode.
    pub fn image(&self) -> Result<KeystoreImage, ImageError> {
        let roots = self
            .roots
            .iter()
            .map(|(epoch, row)| ImageRoot {
                epoch: *epoch,
                backend: row.root.backend,
                handle: row.root.handle.0.clone(),
                wrapped: row.wrapped.0.clone(),
                receipt: self.receipts.get(epoch).copied(),
            })
            .collect();
        let groups = self
            .groups
            .iter()
            .map(|((g, generation), row)| ImageGroup {
                group: g.0,
                generation: *generation,
                epoch: row.epoch,
                nonce: row.nonce,
                body: row.body.clone(),
            })
            .collect();
        let mut keys = Vec::with_capacity(self.keys.len());
        for (dek, (g, generation, sealed)) in &self.keys {
            keys.push(ImageKey {
                dek: dek.0,
                group: g.0,
                generation: *generation,
                sealed: encode_sealed_key(sealed).map_err(|_| ImageError::Malformed("key"))?,
            });
        }
        let mut texts = Vec::with_capacity(self.texts.len());
        for (id, row) in &self.texts {
            texts.push(ImageText {
                id: *id,
                dek: row.dek.0,
                generation: row.generation,
                blob: encode_sealed_blob(&row.blob).map_err(|_| ImageError::Malformed("text"))?,
            });
        }
        let digests = self
            .logins
            .digests
            .iter()
            .map(|(digest, account)| ImageDigest {
                digest: *digest,
                account: account.to_be_bytes(),
            })
            .collect();
        Ok(KeystoreImage {
            cell: self.cell.0,
            roots,
            groups,
            keys,
            texts,
            digests,
        })
    }
}

fn len_u8(n: usize) -> Result<u8, ImageError> {
    u8::try_from(n).map_err(|_| ImageError::Malformed("length"))
}

fn len_u16(n: usize) -> Result<u16, ImageError> {
    u16::try_from(n).map_err(|_| ImageError::Malformed("length"))
}

fn len_u32(n: usize) -> Result<u32, ImageError> {
    u32::try_from(n).map_err(|_| ImageError::Malformed("length"))
}

/// Encodes `image` in the one spelling [`decode_image`] admits.
///
/// # Errors
///
/// [`ImageError::Malformed`] for a row out of order, a length above its
/// bound, or a sealed key or blob that does not decode.
pub fn encode_image(image: &KeystoreImage) -> Result<Vec<u8>, ImageError> {
    let mut out = IMAGE_MAGIC.to_vec();
    out.push(IMAGE_VERSION);
    out.extend_from_slice(&image.cell);
    out.extend_from_slice(&len_u32(image.roots.len())?.to_be_bytes());
    for r in &image.roots {
        if r.handle.len() > MAX_HANDLE || r.wrapped.len() > MAX_WRAPPED {
            return Err(ImageError::Malformed("root length"));
        }
        out.extend_from_slice(&r.epoch.to_be_bytes());
        out.push(backend_code(r.backend));
        out.push(len_u8(r.handle.len())?);
        out.extend_from_slice(&r.handle);
        out.extend_from_slice(&len_u16(r.wrapped.len())?.to_be_bytes());
        out.extend_from_slice(&r.wrapped);
        match r.receipt {
            Some(d) => {
                out.push(1);
                out.extend_from_slice(&d);
            }
            None => out.push(0),
        }
    }
    out.extend_from_slice(&len_u32(image.groups.len())?.to_be_bytes());
    for g in &image.groups {
        if g.body.len() > MAX_GROUP_BODY {
            return Err(ImageError::Malformed("group length"));
        }
        out.extend_from_slice(&g.group);
        out.extend_from_slice(&g.generation.to_be_bytes());
        out.extend_from_slice(&g.epoch.to_be_bytes());
        out.extend_from_slice(&g.nonce);
        out.extend_from_slice(&len_u32(g.body.len())?.to_be_bytes());
        out.extend_from_slice(&g.body);
    }
    out.extend_from_slice(&len_u32(image.keys.len())?.to_be_bytes());
    for k in &image.keys {
        if k.sealed.len() != SEALED_KEY_LEN {
            return Err(ImageError::Malformed("key length"));
        }
        out.extend_from_slice(&k.dek);
        out.extend_from_slice(&k.group);
        out.extend_from_slice(&k.generation.to_be_bytes());
        out.extend_from_slice(&k.sealed);
    }
    out.extend_from_slice(&len_u32(image.texts.len())?.to_be_bytes());
    for t in &image.texts {
        if t.blob.len() > MAX_BLOB {
            return Err(ImageError::Malformed("text length"));
        }
        out.extend_from_slice(&t.id);
        out.extend_from_slice(&t.dek);
        out.extend_from_slice(&t.generation.to_be_bytes());
        out.extend_from_slice(&len_u32(t.blob.len())?.to_be_bytes());
        out.extend_from_slice(&t.blob);
    }
    out.extend_from_slice(&len_u32(image.digests.len())?.to_be_bytes());
    for d in &image.digests {
        out.extend_from_slice(&d.digest);
        out.extend_from_slice(&d.account);
    }
    // The encoder admits only what the decoder admits.
    match decode_image(&out) {
        Ok(back) if back == *image => Ok(out),
        Ok(_) => Err(ImageError::Malformed("canonical form")),
        Err(e) => Err(e),
    }
}

/// A cursor that never reads past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ImageError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(ImageError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ImageError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ImageError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, ImageError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ImageError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ImageError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A count of rows, each at least `min` bytes long, checked against
    /// what is left so a count never asks for more than the input holds.
    fn count(&mut self, min: usize) -> Result<usize, ImageError> {
        let n = usize::try_from(self.u32()?).map_err(|_| ImageError::Malformed("count"))?;
        if n.checked_mul(min).is_none_or(|need| need > self.rest.len()) {
            return Err(ImageError::Truncated);
        }
        Ok(n)
    }

    fn len(&mut self, n: usize, max: usize) -> Result<&'a [u8], ImageError> {
        if n > max {
            return Err(ImageError::Malformed("length"));
        }
        self.take(n)
    }
}

/// Fails unless `next` is strictly above the previous key.
fn ascending<K: Ord + Copy>(prev: &mut Option<K>, next: K) -> Result<(), ImageError> {
    if prev.is_some_and(|p| p >= next) {
        return Err(ImageError::Malformed("row order"));
    }
    *prev = Some(next);
    Ok(())
}

/// Decodes a keystore image (module documentation). Fuzzed
/// (`keystore_image_decode`).
///
/// # Errors
///
/// [`ImageError::Truncated`] when the input ends early, and
/// [`ImageError::Malformed`] with the first other rule it breaks.
pub fn decode_image(bytes: &[u8]) -> Result<KeystoreImage, ImageError> {
    let mut r = Reader { rest: bytes };
    if r.array::<4>()? != IMAGE_MAGIC {
        return Err(ImageError::Malformed("magic"));
    }
    if r.u8()? != IMAGE_VERSION {
        return Err(ImageError::Malformed("version"));
    }
    let cell = r.array::<16>()?;
    let mut image = KeystoreImage {
        cell,
        ..KeystoreImage::default()
    };
    let mut prev = None;
    for _ in 0..r.count(13)? {
        let epoch = r.u64()?;
        ascending(&mut prev, epoch)?;
        let backend = backend_of(r.u8()?).ok_or(ImageError::Malformed("backend"))?;
        let n = usize::from(r.u8()?);
        let handle = r.len(n, MAX_HANDLE)?.to_vec();
        let n = usize::from(r.u16()?);
        let wrapped = r.len(n, MAX_WRAPPED)?.to_vec();
        let receipt = match r.u8()? {
            0 => None,
            1 => Some(r.array::<32>()?),
            _ => return Err(ImageError::Malformed("destroyed flag")),
        };
        image.roots.push(ImageRoot {
            epoch,
            backend,
            handle,
            wrapped,
            receipt,
        });
    }
    let mut prev = None;
    for _ in 0..r.count(44)? {
        let group = r.array::<16>()?;
        let generation = r.u32()?;
        ascending(&mut prev, (group, generation))?;
        let epoch = r.u64()?;
        let nonce = r.array()?;
        let n = usize::try_from(r.u32()?).map_err(|_| ImageError::Malformed("length"))?;
        let body = r.len(n, MAX_GROUP_BODY)?.to_vec();
        image.groups.push(ImageGroup {
            group,
            generation,
            epoch,
            nonce,
            body,
        });
    }
    let mut prev = None;
    for _ in 0..r.count(36 + SEALED_KEY_LEN)? {
        let dek = r.array::<16>()?;
        ascending(&mut prev, dek)?;
        let group = r.array::<16>()?;
        let generation = r.u32()?;
        let sealed = r.take(SEALED_KEY_LEN)?.to_vec();
        let h = decode_sealed_key(&sealed)
            .map_err(|_| ImageError::Malformed("sealed key"))?
            .header();
        if h.group.0 != group || h.generation != generation || h.chain != Chain::App {
            return Err(ImageError::Malformed("key group"));
        }
        image.keys.push(ImageKey {
            dek,
            group,
            generation,
            sealed,
        });
    }
    let mut prev = None;
    for _ in 0..r.count(40)? {
        let id = r.array::<16>()?;
        ascending(&mut prev, id)?;
        let dek = r.array::<16>()?;
        let generation = r.u32()?;
        let n = usize::try_from(r.u32()?).map_err(|_| ImageError::Malformed("length"))?;
        let blob = r.len(n, MAX_BLOB)?.to_vec();
        decode_sealed_blob(&blob).map_err(|_| ImageError::Malformed("sealed blob"))?;
        image.texts.push(ImageText {
            id,
            dek,
            generation,
            blob,
        });
    }
    let mut prev = None;
    for _ in 0..r.count(48)? {
        let digest = r.array::<32>()?;
        ascending(&mut prev, digest)?;
        let account = r.array::<16>()?;
        image.digests.push(ImageDigest { digest, account });
    }
    if !r.rest.is_empty() {
        return Err(ImageError::Malformed("bytes after the last digest"));
    }
    Ok(image)
}

/// The AAD under which custody wraps `S(epoch)` of `cell`'s App chain. A
/// caller that holds custody unwraps an image root's wrapped key with it.
#[must_use]
pub fn seal_key_aad(cell: [u8; 16], epoch: u64) -> Aad {
    seal_aad(CellId(cell), epoch)
}

/// The reference of an image root, as custody takes it.
#[must_use]
pub fn root_ref(cell: [u8; 16], root: &ImageRoot) -> RootRef {
    RootRef {
        backend: root.backend,
        cell: Some(CellId(cell)),
        chain: Chain::App,
        epoch: Epoch(root.epoch),
        handle: CustodyHandle(root.handle.clone()),
    }
}

/// The wrapped seal key of an image root, as custody takes it.
#[must_use]
pub fn wrapped_of(root: &ImageRoot) -> WrappedSealKey {
    WrappedSealKey(root.wrapped.clone())
}

/// Tries to open text `text` of `cell` with every row of `rows` and every
/// seal key of `seal_keys`. Every group secret row is tried under every
/// seal key, every data key row of the text's key under every group
/// secret that opened, and the blob under every data key that opened.
/// The plaintext of the first path that opens, or `None` (I-81).
///
/// The caller unwraps `seal_keys` through custody, so a destroyed root
/// gives none.
#[must_use]
pub fn open_text(
    cell: [u8; 16],
    rows: &[&KeystoreImage],
    seal_keys: &[SealKey],
    text: &ImageText,
) -> Option<Vec<u8>> {
    let blob = decode_sealed_blob(&text.blob).ok()?;
    let cell = CellId(cell);
    let mut secrets: BTreeMap<(GroupId, u32), Vec<HybridSecretKey>> = BTreeMap::new();
    for img in rows {
        for g in &img.groups {
            let id = GroupId(g.group);
            let row = GroupRow {
                epoch: g.epoch,
                nonce: g.nonce,
                body: g.body.clone(),
            };
            for s in seal_keys {
                if let Ok(sk) = open_group(s, cell, id, g.generation, &row) {
                    secrets.entry((id, g.generation)).or_default().push(sk);
                }
            }
        }
    }
    for img in rows {
        for k in img.keys.iter().filter(|k| k.dek == text.dek) {
            let Ok(sealed) = decode_sealed_key(&k.sealed) else {
                continue;
            };
            let ctx = ctx_for(cell, GroupId(k.group), k.generation, text.id);
            let body = ctx_for(cell, GroupId(k.group), text.generation, text.id);
            for sk in secrets
                .get(&(GroupId(k.group), k.generation))
                .into_iter()
                .flatten()
            {
                if let Ok(dk) = envelope::open_key(sk, &sealed, &ctx)
                    && let Ok(pt) = envelope::open_blob(&dk, &body, &blob)
                {
                    return Some(pt.to_vec());
                }
            }
        }
    }
    None
}

/// Every HMAC key of the login email index that `rows` give under
/// `seal_keys` (design section 3.5, G24, I-81). Every group secret row is
/// tried under every seal key, and each secret that opens gives the
/// `Lookup` key it would derive, whatever its group. So the list holds
/// at least every `Lookup` key a caller can reach.
///
/// The caller unwraps `seal_keys` through custody, so a destroyed root
/// gives none.
#[must_use]
pub fn login_digest_keys(
    cell: [u8; 16],
    rows: &[&KeystoreImage],
    seal_keys: &[SealKey],
) -> Vec<SealKey> {
    let cell = CellId(cell);
    let mut out = Vec::new();
    for img in rows {
        for g in &img.groups {
            let row = GroupRow {
                epoch: g.epoch,
                nonce: g.nonce,
                body: g.body.clone(),
            };
            for s in seal_keys {
                if let Ok(sk) = open_group(s, cell, GroupId(g.group), g.generation, &row)
                    && let Ok(key) = digest_key(&sk, Purpose::Lookup)
                {
                    out.push(key);
                }
            }
        }
    }
    out
}

/// The keyed digest of the login email `email` under the index key `key`:
/// `HMAC-SHA-256(key, normalised address)`, as the index row holds it.
#[must_use]
pub fn login_digest(key: &SealKey, email: &str) -> [u8; 32] {
    keyed_digest(key, normalise_email(email).as_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use fstp_keys::ObjectId;
    use fstp_keys::envelope::{DataKey, SealContext};

    fn image() -> KeystoreImage {
        let sk = fstp_crypto::hybrid_kem::generate().unwrap();
        let ctx = SealContext {
            cell: CellId([1; 16]),
            chain: Chain::App,
            purpose: Purpose::Text,
            group: GroupId([2; 16]),
            generation: 1,
            object: ObjectId([3; 16]),
        };
        let dek = DataKey::generate().unwrap();
        let sealed = envelope::seal_key(sk.public(), &dek, &ctx).unwrap();
        let blob = envelope::seal_blob(&dek, &ctx, b"synthetic").unwrap();
        KeystoreImage {
            cell: [1; 16],
            roots: vec![
                ImageRoot {
                    epoch: 0,
                    backend: BackendId::Simulator,
                    handle: vec![9; 16],
                    wrapped: vec![8; 60],
                    receipt: Some([7; 32]),
                },
                ImageRoot {
                    epoch: 1,
                    backend: BackendId::Keyd,
                    handle: vec![6; 16],
                    wrapped: vec![5; 60],
                    receipt: None,
                },
            ],
            groups: vec![ImageGroup {
                group: [2; 16],
                generation: 1,
                epoch: 1,
                nonce: [4; 12],
                body: vec![3; 40],
            }],
            keys: vec![ImageKey {
                dek: [3; 16],
                group: [2; 16],
                generation: 1,
                sealed: encode_sealed_key(&sealed).unwrap(),
            }],
            texts: vec![ImageText {
                id: [3; 16],
                dek: [3; 16],
                generation: 1,
                blob: encode_sealed_blob(&blob).unwrap(),
            }],
            digests: vec![
                ImageDigest {
                    digest: [1; 32],
                    account: [2; 16],
                },
                ImageDigest {
                    digest: [3; 32],
                    account: [4; 16],
                },
            ],
        }
    }

    /// I-81, ADR-012 "Keystore snapshots": an image round trips, and every
    /// strict prefix of it is refused.
    #[test]
    fn i81_keystore_image_round_trips_and_refuses_prefixes() {
        let img = image();
        let bytes = encode_image(&img).unwrap();
        assert_eq!(decode_image(&bytes).unwrap(), img);
        for cut in 0..bytes.len() {
            assert!(decode_image(&bytes[..cut]).is_err(), "{cut}");
        }
        let mut more = bytes.clone();
        more.push(0);
        assert!(decode_image(&more).is_err());
    }

    /// One spelling only: rows out of order, a key whose group differs
    /// from its sealed header, and an unknown backend are refused.
    #[test]
    fn i81_keystore_image_refuses_other_spellings() {
        let mut img = image();
        img.roots.swap(0, 1);
        assert!(encode_image(&img).is_err());
        let mut img = image();
        img.digests.swap(0, 1);
        assert!(encode_image(&img).is_err());
        let mut img = image();
        img.keys[0].group = [5; 16];
        assert!(encode_image(&img).is_err());
        let mut bytes = encode_image(&image()).unwrap();
        bytes[33] = 9;
        assert_eq!(decode_image(&bytes), Err(ImageError::Malformed("backend")));
    }
}
