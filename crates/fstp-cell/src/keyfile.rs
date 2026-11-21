//! The sealed cell key file `cell-keys.sealed` (ADR-004 record of lane L4,
//! decided by Daniel on 2026-11-20, gap G8).
//!
//! It holds the keys that the keystore groups do not give yet: the App
//! chain's composite `Anchor` key, the CredLookup key, the vault `Ticket`
//! key and every ledger key generation. It is sealed under an epoch seal
//! key `S(e)`, which a dedicated custody cell root wraps. That root lives
//! in its own `fstp-keyd` entry, is created at genesis, and no erasure
//! ever destroys it.
//!
//! ```text
//! file    = MAGIC (17) || cell (16) || be64(epoch)
//!           || be16(len) || custody handle || be16(len) || wrapped S(e)
//!           || nonce (12) || be32(len) || sealed
//! wrap    = custody wrap of S(e), AAD = MAGIC || cell || "cellbackup" || be64(epoch)
//! sealed  = AES-256-GCM under S(e) of body, with the same AAD
//! body    = anchor composite secret (64) || CredLookup (32) || ticket seed (32)
//!           || be16(n) || n x (be32(key_ix) || data key id (16) || key (32))
//! ```
//!
//! Both decoders accept exactly this form and are fuzzed
//! (`cell_key_file_decode`). The file never holds an open key (I-80). An
//! error names its rule and never quotes the file (R-NF-02).
//!
//! Each start draws a new ledger key generation and rewrites the file
//! before its first seal ([`KeyBody::next_generation`],
//! [`write_atomic`]). A generation is never reused across starts.

use std::path::Path;
use std::sync::Arc;

use fstp_audit::codec::Reader;
use fstp_crypto::aead;
use fstp_custody::{
    Aad, BackendId, CellId, Chain, Custody, CustodyHandle, Epoch, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use zeroize::Zeroizing;

use crate::process::CellKeys;

/// The magic that opens a key file and labels both AADs.
pub const MAGIC: &[u8; 17] = b"fstp-cell-keys-v1";

/// The key file's name in the credentials directory.
pub const KEY_FILE: &str = "cell-keys.sealed";

/// The chain the dedicated root is labelled with (ADR-004 record of L4).
pub const ROOT_CHAIN: Chain = Chain::CellBackup;

/// The epoch of the dedicated root.
pub const ROOT_EPOCH: u64 = 1;

/// The longest custody handle or wrapped seal key a file holds.
pub const MAX_FIELD_LEN: usize = 4096;

/// The most ledger key generations a file holds.
pub const MAX_GENERATIONS: usize = 4096;

/// The length of one generation in the body.
const GENERATION_LEN: usize = 4 + 16 + aead::KEY_LEN;

/// The length of the body before the generations.
const FIXED_LEN: usize = fstp_crypto::composite::PRIVATE_KEY_LEN + 32 + 32 + 2;

/// The longest sealed body.
pub const MAX_SEALED_LEN: usize = FIXED_LEN + MAX_GENERATIONS * GENERATION_LEN + aead::TAG_LEN;

/// The shortest sealed body: one generation.
const MIN_SEALED_LEN: usize = FIXED_LEN + GENERATION_LEN + aead::TAG_LEN;

/// Why a key file was refused. It names a rule and never quotes the file
/// (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyFileError(pub &'static str);

impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cell key file refused: {}", self.0)
    }
}

impl std::error::Error for KeyFileError {}

/// A decoded key file: references and sealed bytes only (I-80).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyFile {
    /// The cell.
    pub cell: [u8; 16],
    /// The epoch of the dedicated root.
    pub epoch: u64,
    /// The custody handle of the root.
    pub handle: Vec<u8>,
    /// `S(e)`, wrapped under the root.
    pub wrapped: Vec<u8>,
    /// The AES-256-GCM nonce of the body.
    pub nonce: [u8; aead::NONCE_LEN],
    /// The sealed body.
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// One ledger key generation, wiped on drop.
pub struct Generation {
    /// The generation index (`key_ix`).
    pub key_ix: u32,
    /// The data key id.
    pub dek: [u8; 16],
    /// The key.
    pub key: Zeroizing<[u8; aead::KEY_LEN]>,
}

/// The plain body of a key file. Every secret is wiped on drop. It
/// implements no `Clone` and its debug form shows no key.
pub struct KeyBody {
    /// The composite `Anchor` secret.
    pub anchor: Zeroizing<[u8; fstp_crypto::composite::PRIVATE_KEY_LEN]>,
    /// The CredLookup key.
    pub cred_lookup: Zeroizing<[u8; 32]>,
    /// The Ed25519 seed of the ticket key.
    pub ticket: Zeroizing<[u8; 32]>,
    /// The ledger key generations, oldest first. The last is current.
    pub generations: Vec<Generation>,
}

impl std::fmt::Debug for KeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyBody")
            .field("generations", &self.generations.len())
            .finish_non_exhaustive()
    }
}

fn bad(rule: &'static str) -> KeyFileError {
    KeyFileError(rule)
}

/// The AAD of the custody wrap and of the body seal.
#[must_use]
pub fn aad(cell: &[u8; 16], epoch: u64) -> Vec<u8> {
    [
        &MAGIC[..],
        &cell[..],
        ROOT_CHAIN.name().as_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

fn put16(out: &mut Vec<u8>, field: &[u8]) -> Result<(), KeyFileError> {
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
/// [`KeyFileError`] for an empty or overlong field, or a sealed body
/// outside its bounds.
pub fn encode_key_file(f: &KeyFile) -> Result<Vec<u8>, KeyFileError> {
    if !(MIN_SEALED_LEN..=MAX_SEALED_LEN).contains(&f.sealed.len()) {
        return Err(bad("sealed length"));
    }
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&f.cell);
    out.extend_from_slice(&f.epoch.to_be_bytes());
    put16(&mut out, &f.handle)?;
    put16(&mut out, &f.wrapped)?;
    out.extend_from_slice(&f.nonce);
    let len = u32::try_from(f.sealed.len()).map_err(|_| bad("sealed length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&f.sealed);
    Ok(out)
}

/// Decodes a key file. Fuzzed (`cell_key_file_decode`).
///
/// # Errors
///
/// [`KeyFileError`] for a wrong magic, a cut or overlong field, a sealed
/// body outside its bounds, or trailing bytes.
pub fn decode_key_file(bytes: &[u8]) -> Result<KeyFile, KeyFileError> {
    let mut r = Reader::new(bytes);
    let e = |_| bad("form");
    if r.take(MAGIC.len()).map_err(e)? != MAGIC {
        return Err(bad("magic"));
    }
    let cell = r.array::<16>().map_err(e)?;
    let epoch = r.be64().map_err(e)?;
    let field = |r: &mut Reader<'_>| -> Result<Vec<u8>, KeyFileError> {
        let len = usize::from(r.be16().map_err(e)?);
        if len == 0 || len > MAX_FIELD_LEN {
            return Err(bad("field length"));
        }
        Ok(r.take(len).map_err(e)?.to_vec())
    };
    let handle = field(&mut r)?;
    let wrapped = field(&mut r)?;
    let nonce = r.array::<{ aead::NONCE_LEN }>().map_err(e)?;
    let len = usize::try_from(r.be32().map_err(e)?).map_err(|_| bad("sealed length"))?;
    if !(MIN_SEALED_LEN..=MAX_SEALED_LEN).contains(&len) {
        return Err(bad("sealed length"));
    }
    let sealed = r.take(len).map_err(e)?.to_vec();
    r.finish().map_err(e)?;
    Ok(KeyFile {
        cell,
        epoch,
        handle,
        wrapped,
        nonce,
        sealed,
    })
}

/// Encodes a body. The result is wiped on drop.
///
/// # Errors
///
/// [`KeyFileError`] for no generation, too many, or generations whose
/// indexes do not increase or whose data key ids repeat.
pub fn encode_body(b: &KeyBody) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    check_generations(&b.generations)?;
    let n = u16::try_from(b.generations.len()).map_err(|_| bad("generations"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(
        FIXED_LEN.saturating_add(b.generations.len().saturating_mul(GENERATION_LEN)),
    ));
    out.extend_from_slice(&b.anchor[..]);
    out.extend_from_slice(&b.cred_lookup[..]);
    out.extend_from_slice(&b.ticket[..]);
    out.extend_from_slice(&n.to_be_bytes());
    for g in &b.generations {
        out.extend_from_slice(&g.key_ix.to_be_bytes());
        out.extend_from_slice(&g.dek);
        out.extend_from_slice(&g.key[..]);
    }
    Ok(out)
}

fn check_generations(gs: &[Generation]) -> Result<(), KeyFileError> {
    if gs.is_empty() || gs.len() > MAX_GENERATIONS {
        return Err(bad("generations"));
    }
    for (i, g) in gs.iter().enumerate() {
        if let Some(prev) = i.checked_sub(1).and_then(|p| gs.get(p))
            && prev.key_ix >= g.key_ix
        {
            return Err(bad("generation order"));
        }
        if gs.iter().skip(i.saturating_add(1)).any(|o| o.dek == g.dek) {
            return Err(bad("generation data key id"));
        }
    }
    Ok(())
}

/// Decodes a body. Fuzzed (`cell_key_file_decode`).
///
/// # Errors
///
/// [`KeyFileError`] for a cut body, trailing bytes, or generations that
/// [`encode_body`] would refuse.
pub fn decode_body(bytes: &[u8]) -> Result<KeyBody, KeyFileError> {
    let mut r = Reader::new(bytes);
    let e = |_| bad("body form");
    let mut anchor = Zeroizing::new([0u8; fstp_crypto::composite::PRIVATE_KEY_LEN]);
    anchor.copy_from_slice(r.take(fstp_crypto::composite::PRIVATE_KEY_LEN).map_err(e)?);
    let mut cred_lookup = Zeroizing::new([0u8; 32]);
    cred_lookup.copy_from_slice(r.take(32).map_err(e)?);
    let mut ticket = Zeroizing::new([0u8; 32]);
    ticket.copy_from_slice(r.take(32).map_err(e)?);
    let n = usize::from(r.be16().map_err(e)?);
    if n == 0 || n > MAX_GENERATIONS {
        return Err(bad("generations"));
    }
    let mut generations = Vec::with_capacity(n);
    for _ in 0..n {
        let key_ix = r.be32().map_err(e)?;
        let dek = r.array::<16>().map_err(e)?;
        let mut key = Zeroizing::new([0u8; aead::KEY_LEN]);
        key.copy_from_slice(r.take(aead::KEY_LEN).map_err(e)?);
        generations.push(Generation { key_ix, dek, key });
    }
    r.finish().map_err(e)?;
    check_generations(&generations)?;
    Ok(KeyBody {
        anchor,
        cred_lookup,
        ticket,
        generations,
    })
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, KeyFileError> {
    let mut out = Zeroizing::new([0u8; N]);
    fstp_crypto::random_bytes(&mut out[..]).map_err(|_| bad("random"))?;
    Ok(out)
}

impl KeyBody {
    /// A body of the given keys with one fresh ledger generation, index 1.
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] when a key does not export or no random value is
    /// available.
    pub fn from_keys(
        anchor: &fstp_crypto::composite::CompositeSigningKey,
        cred_lookup: &[u8; 32],
        ticket: &fstp_crypto::sig::Ed25519SigningKey,
    ) -> Result<KeyBody, KeyFileError> {
        let anchor = anchor.to_bytes().map_err(|_| bad("anchor export"))?;
        let ticket = ticket.seed().map_err(|_| bad("ticket export"))?;
        let mut body = KeyBody {
            anchor: Zeroizing::new(*anchor),
            cred_lookup: Zeroizing::new(*cred_lookup),
            ticket: Zeroizing::new(*ticket),
            generations: Vec::new(),
        };
        body.next_generation()?;
        Ok(body)
    }

    /// A body of fresh keys (`fstp-cell init-keys`).
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] when a key cannot be made.
    pub fn generate() -> Result<KeyBody, KeyFileError> {
        let anchor = fstp_crypto::composite::generate().map_err(|_| bad("anchor"))?;
        let ticket = fstp_crypto::sig::Ed25519SigningKey::generate().map_err(|_| bad("ticket"))?;
        let cred = random::<32>()?;
        KeyBody::from_keys(&anchor, &cred, &ticket)
    }

    /// Draws a new current ledger generation: the next index and a fresh
    /// data key id and key. The older ones stay, for opening (ADR-004
    /// record of L4: a generation is never reused across starts).
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] at [`MAX_GENERATIONS`], at the last index, or when
    /// no random value is available.
    pub fn next_generation(&mut self) -> Result<(), KeyFileError> {
        if self.generations.len() >= MAX_GENERATIONS {
            return Err(bad("generations"));
        }
        let key_ix = match self.generations.last() {
            None => 1,
            Some(g) => g.key_ix.checked_add(1).ok_or(bad("generation index"))?,
        };
        let mut dek = [0u8; 16];
        loop {
            fstp_crypto::random_bytes(&mut dek).map_err(|_| bad("random"))?;
            if !self.generations.iter().any(|g| g.dek == dek) {
                break;
            }
        }
        self.generations.push(Generation {
            key_ix,
            dek,
            key: random::<{ aead::KEY_LEN }>()?,
        });
        Ok(())
    }

    /// The anchor public key, which the witness pins.
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] when the secret does not read.
    pub fn anchor_public(&self) -> Result<Vec<u8>, KeyFileError> {
        let k = fstp_crypto::composite::CompositeSigningKey::from_bytes(&self.anchor[..])
            .map_err(|_| bad("anchor"))?;
        Ok(k.public_key().to_bytes().to_vec())
    }

    /// The ticket public key, which the vault pins.
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] when the seed does not read.
    pub fn ticket_public(&self) -> Result<[u8; 32], KeyFileError> {
        let k = fstp_crypto::sig::Ed25519SigningKey::from_seed(&self.ticket)
            .map_err(|_| bad("ticket"))?;
        Ok(k.public_key())
    }

    /// The keys a cell starts with ([`crate::process::CellKeys`]): the
    /// last generation seals, the older ones open.
    ///
    /// # Errors
    ///
    /// [`KeyFileError`] when a key does not read.
    pub fn cell_keys(&self) -> Result<CellKeys, KeyFileError> {
        let ledger_key = |g: &Generation| -> Result<fstp_pgstore::LedgerKey, KeyFileError> {
            let key = aead::Key::from_bytes(&g.key).map_err(|_| bad("ledger key"))?;
            Ok(fstp_pgstore::LedgerKey::new(
                g.key_ix,
                fstp_keys::DekId(g.dek),
                key,
            ))
        };
        let (current, older) = self.generations.split_last().ok_or(bad("generations"))?;
        let mut ledger = fstp_pgstore::LedgerKeys::new(ledger_key(current)?);
        for g in older {
            ledger = ledger
                .with_older(ledger_key(g)?)
                .map_err(|_| bad("generations"))?;
        }
        Ok(CellKeys {
            anchor: fstp_crypto::composite::CompositeSigningKey::from_bytes(&self.anchor[..])
                .map_err(|_| bad("anchor"))?,
            ledger: Arc::new(ledger),
            cred_lookup: *self.cred_lookup,
            ticket: Some(Arc::new(
                fstp_crypto::sig::Ed25519SigningKey::from_seed(&self.ticket)
                    .map_err(|_| bad("ticket"))?,
            )),
        })
    }
}

/// The custody root of `f`: the dedicated cell root on its own
/// `fstp-keyd` entry.
#[must_use]
pub fn root_of(f: &KeyFile) -> RootRef {
    RootRef {
        backend: BackendId::Keyd,
        cell: Some(CellId(f.cell)),
        chain: ROOT_CHAIN,
        epoch: Epoch(f.epoch),
        handle: CustodyHandle(f.handle.clone()),
    }
}

/// Seals `body` under `seal` into a key file with the root reference of
/// `template` (its cell, epoch, handle and wrapped key).
///
/// # Errors
///
/// [`KeyFileError`] when the body does not encode or the seal fails.
pub fn seal_body(
    template: &KeyFile,
    body: &KeyBody,
    seal: &SealKey,
) -> Result<KeyFile, KeyFileError> {
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("seal key"))?;
    let plain = encode_body(body)?;
    let sealed = aead::seal(&key, &aad(&template.cell, template.epoch), &plain[..])
        .map_err(|_| bad("seal"))?;
    Ok(KeyFile {
        nonce: sealed.nonce,
        sealed: sealed.body,
        ..template.clone()
    })
}

/// Opens the body of `f` under `seal`.
///
/// # Errors
///
/// [`KeyFileError`] when the body does not open or does not decode.
pub fn open_body(f: &KeyFile, seal: &SealKey) -> Result<KeyBody, KeyFileError> {
    let key = aead::Key::from_bytes(seal.expose()).map_err(|_| bad("seal key"))?;
    let plain =
        aead::open(&key, &f.nonce, &aad(&f.cell, f.epoch), &f.sealed).map_err(|_| bad("open"))?;
    decode_body(&plain)
}

/// Genesis of the key file of `cell` (ADR-004 record of L4): creates the
/// dedicated root through `custody`, draws `S(e)`, wraps it, and seals
/// `body`. The caller writes the bytes ([`write_atomic`]).
///
/// # Errors
///
/// [`KeyFileError`] when custody refuses or the seal fails.
pub async fn create<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    body: &KeyBody,
) -> Result<Vec<u8>, KeyFileError> {
    let root = custody
        .create_root(RootLabel {
            cell: Some(CellId(cell)),
            chain: ROOT_CHAIN,
            epoch: Epoch(ROOT_EPOCH),
        })
        .await
        .map_err(|_| bad("custody create"))?;
    let seal = SealKey::generate().map_err(|_| bad("seal key"))?;
    let wrapped = custody
        .wrap(&root, &seal, &Aad(aad(&cell, ROOT_EPOCH)))
        .await
        .map_err(|_| bad("custody wrap"))?;
    let template = KeyFile {
        cell,
        epoch: ROOT_EPOCH,
        handle: root.handle.0,
        wrapped: wrapped.0,
        nonce: [0; aead::NONCE_LEN],
        sealed: Vec::new(),
    };
    encode_key_file(&seal_body(&template, body, &seal)?)
}

/// Opens the key file `bytes` of `cell` through `custody`, draws a new
/// ledger generation, and gives the body with the resealed file. The
/// caller writes the file before the first seal under the new generation.
///
/// # Errors
///
/// [`KeyFileError`] for a file of another cell, a refused unwrap, or a
/// body that does not open.
pub async fn open_and_advance<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    bytes: &[u8],
) -> Result<(KeyBody, Vec<u8>), KeyFileError> {
    let f = decode_key_file(bytes)?;
    if f.cell != cell {
        return Err(bad("another cell"));
    }
    let seal = custody
        .unwrap(
            &root_of(&f),
            &WrappedSealKey(f.wrapped.clone()),
            &Aad(aad(&f.cell, f.epoch)),
        )
        .await
        .map_err(|_| bad("custody unwrap"))?;
    let mut body = open_body(&f, &seal)?;
    body.next_generation()?;
    let file = encode_key_file(&seal_body(&f, &body, &seal)?)?;
    Ok((body, file))
}

/// Writes `bytes` to `path` so a crash leaves the old file or the new
/// one: a new temporary file beside it with mode 0600, synced, then
/// renamed over `path`, and the directory synced.
///
/// # Errors
///
/// [`KeyFileError`] when a step fails. It names the step only.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), KeyFileError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path.parent().ok_or(bad("directory"))?;
    let name = path.file_name().ok_or(bad("file name"))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".new");
    let tmp = dir.join(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| bad("temporary file"))?;
    f.write_all(bytes).map_err(|_| bad("write"))?;
    f.sync_all().map_err(|_| bad("sync"))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|_| bad("rename"))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| bad("directory sync"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn body() -> KeyBody {
        let mut b = KeyBody {
            anchor: Zeroizing::new([0xA1; fstp_crypto::composite::PRIVATE_KEY_LEN]),
            cred_lookup: Zeroizing::new([0xC2; 32]),
            ticket: Zeroizing::new([0x73; 32]),
            generations: Vec::new(),
        };
        b.next_generation().unwrap();
        b.next_generation().unwrap();
        b
    }

    fn template() -> KeyFile {
        KeyFile {
            cell: [7; 16],
            epoch: ROOT_EPOCH,
            handle: b"handle".to_vec(),
            wrapped: vec![0x5a; 60],
            nonce: [0; aead::NONCE_LEN],
            sealed: Vec::new(),
        }
    }

    /// ADR-004 record of L4: a body sealed under `S(e)` opens under the
    /// same `S(e)` only, and the file round-trips byte for byte. A cut
    /// file, trailing bytes, a wrong magic or a moved file are refused.
    #[test]
    fn adr004_cell_key_file_round_trips() {
        let seal = SealKey::generate().unwrap();
        let f = seal_body(&template(), &body(), &seal).unwrap();
        let bytes = encode_key_file(&f).unwrap();
        let back = decode_key_file(&bytes).unwrap();
        assert_eq!(back, f);
        assert_eq!(encode_key_file(&back).unwrap(), bytes);
        let opened = open_body(&back, &seal).unwrap();
        assert_eq!(opened.generations.len(), 2);
        assert_eq!(opened.generations[1].key_ix, 2);
        assert!(open_body(&back, &SealKey::generate().unwrap()).is_err());
        let mut moved = back.clone();
        moved.cell = [8; 16];
        assert!(open_body(&moved, &seal).is_err(), "a moved file opened");
        assert!(decode_key_file(&bytes[..bytes.len() - 1]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_key_file(&long).is_err());
        let mut magic = bytes;
        magic[0] ^= 1;
        assert_eq!(decode_key_file(&magic), Err(KeyFileError("magic")));
    }

    /// ADR-004 record of L4 (L3's open question 3): each start draws a
    /// generation with a new index and data key id, and keeps the older
    /// ones. The keys a cell starts with seal under the newest.
    #[test]
    fn adr004_each_start_draws_a_new_ledger_generation() {
        let mut b = body();
        let before: Vec<(u32, [u8; 16])> =
            b.generations.iter().map(|g| (g.key_ix, g.dek)).collect();
        b.next_generation().unwrap();
        assert_eq!(b.generations.len(), before.len() + 1);
        let last = b.generations.last().unwrap();
        assert!(
            before
                .iter()
                .all(|(ix, dek)| *ix < last.key_ix && *dek != last.dek)
        );
        let bytes = encode_body(&b).unwrap();
        let back = decode_body(&bytes).unwrap();
        assert_eq!(back.generations.len(), 3);
        // Generations out of order or with a repeated data key id are
        // refused.
        let mut swapped = decode_body(&bytes).unwrap();
        swapped.generations.swap(0, 1);
        assert!(encode_body(&swapped).is_err());
        let mut repeated = decode_body(&bytes).unwrap();
        repeated.generations[1].dek = repeated.generations[0].dek;
        assert!(encode_body(&repeated).is_err());
    }

    /// I-80: the file holds no open key. No secret of the body, and no
    /// seal key, appears in the file bytes.
    #[test]
    fn i80_cell_key_file_holds_no_open_key() {
        let seal = SealKey::generate().unwrap();
        let b = body();
        let bytes = encode_key_file(&seal_body(&template(), &b, &seal).unwrap()).unwrap();
        let mut secrets: Vec<Vec<u8>> = vec![
            b.anchor[..16].to_vec(),
            b.cred_lookup[..16].to_vec(),
            b.ticket[..16].to_vec(),
            seal.expose()[..16].to_vec(),
        ];
        secrets.extend(b.generations.iter().map(|g| g.key[..16].to_vec()));
        for s in secrets {
            assert!(
                !bytes.windows(s.len()).any(|w| w == s.as_slice()),
                "I-80: an open key is in the file"
            );
        }
        // The debug forms show no key.
        assert!(!format!("{b:?}").contains("a1a1"));
        assert_eq!(
            format!("{:?}", decode_key_file(&bytes).unwrap()),
            "KeyFile { epoch: 1, .. }"
        );
    }

    /// R-NF-02: a refused configuration or key file never quotes its
    /// bytes. Each error names a fixed rule only.
    #[test]
    fn r_nf_02_config_and_key_errors_never_quote_bytes() {
        let marker = "s3cr3tm4rk3r";
        let configs = [
            format!("{{\"cell\":\"{marker}\"}}"),
            format!("{{\"{marker}\":1}}"),
            crate::config::tests_file(&format!(",\"assets_dir\":\"{marker}\"")),
            crate::config::tests_file(&format!(
                ",\"mail\":{{\"relay\":\"{marker}.\",\"sender\":\"{marker}\",\"username\":\"u\"}}"
            )),
            crate::config::tests_file("").replace("db.internal", &format!("{marker} x")),
            marker.to_owned(),
        ];
        for c in &configs {
            let e = crate::config::decode_file(c.as_bytes()).unwrap_err();
            let shown = format!("{e:?} {}", crate::CellError::Config(e));
            assert!(!shown.contains(marker), "R-NF-02: {shown}");
        }
        let e = crate::config::decode_receipt_keys(marker.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}").contains(marker));
        let mut file = MAGIC.to_vec();
        file.extend_from_slice(marker.as_bytes());
        for bytes in [file.clone(), marker.as_bytes().to_vec(), file.repeat(3)] {
            let e = decode_key_file(&bytes).unwrap_err();
            let shown = format!("{e:?} {e} {}", crate::CellError::Keys(e.0));
            assert!(!shown.contains(marker), "R-NF-02: {shown}");
        }
        let e = decode_body(marker.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}").contains(marker));
    }

    /// The rewrite of a key file replaces it whole, with mode 0600.
    #[test]
    fn adr004_key_file_rewrite_is_atomic_and_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "fstp-keyfile-{}-{}",
            std::process::id(),
            fstp_crypto::random_array::<4>()
                .map(u32::from_be_bytes)
                .unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(KEY_FILE);
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.join("cell-keys.sealed.new").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
