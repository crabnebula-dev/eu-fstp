//! The copy register of a sealed key file (ADR-004 record of lane L16,
//! Q-L16-3, decided by Daniel on 2026-11-21, I-81).
//!
//! The cell key file `cell-keys.sealed` and the witness receipt key file
//! sit in credentials directories, outside the key volumes. An operator
//! copies each off the host with its owner's `copy-key-file` command,
//! which records the copy here: a random id, the time, and a digest of
//! each key the copy holds. While a copy that is not retired holds a key
//! the owner no longer holds, the owner reports reduced I-81 assurance at
//! start. The owner's `retire-key-file-copy` command records that every
//! copy of an id is destroyed.
//!
//! ```text
//! record = tag u8 | copy id 16
//!          tag 1 (taken):   created u64 | count u16 | count times digest 32
//!          tag 2 (retired): nothing more
//! digest = SHA-256("fstp-copy-register-v1" | label_len u8 | label | key)
//! ```
//!
//! A digest names a high-entropy key without revealing it. The register
//! holds no key bytes. Its decoder is fuzzed (`copy_register_decode`).

use std::io::Write as _;
use std::path::Path;

/// The longest register read.
pub const MAX_REGISTER_LEN: usize = 1 << 20;
/// The label of every key digest.
pub const DIGEST_LABEL: &[u8; 21] = b"fstp-copy-register-v1";

const TAG_TAKEN: u8 = 1;
const TAG_RETIRED: u8 = 2;

/// Why a register step failed. It names the rule or step only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyError(pub &'static str);

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the copy register refused: {}", self.0)
    }
}

impl std::error::Error for CopyError {}

/// The random id of a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CopyId(pub [u8; 16]);

impl CopyId {
    /// The id as 32 lowercase hex digits.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The id of 32 hex digits, or `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<CopyId> {
        if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 16];
        for (o, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *o = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(CopyId(out))
    }
}

/// One record of the register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyRecord {
    /// A copy was taken at `created`, holding the keys of `keys`.
    Taken {
        /// The copy.
        id: CopyId,
        /// When, in Unix seconds.
        created: u64,
        /// The digest of each key it holds.
        keys: Vec<[u8; 32]>,
    },
    /// The operator stated that every copy of `id` is destroyed.
    Retired {
        /// The copy.
        id: CopyId,
    },
}

/// The digest of `key` under `label`, such as `"cred_lookup"`.
#[must_use]
pub fn key_digest(label: &str, key: &[u8]) -> [u8; 32] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(DIGEST_LABEL);
    h.update(&[u8::try_from(label.len()).unwrap_or(u8::MAX)]);
    h.update(label.as_bytes());
    h.update(key);
    h.finish()
}

/// Encodes one record.
///
/// # Errors
///
/// Refuses more than `u16::MAX` keys.
pub fn encode_record(r: &CopyRecord) -> Result<Vec<u8>, CopyError> {
    match r {
        CopyRecord::Taken { id, created, keys } => {
            let count = u16::try_from(keys.len()).map_err(|_| CopyError("too many keys"))?;
            let mut out = vec![TAG_TAKEN];
            out.extend_from_slice(&id.0);
            out.extend_from_slice(&created.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            for k in keys {
                out.extend_from_slice(k);
            }
            Ok(out)
        }
        CopyRecord::Retired { id } => {
            let mut out = vec![TAG_RETIRED];
            out.extend_from_slice(&id.0);
            Ok(out)
        }
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], CopyError> {
    let (head, tail) = rest.split_at_checked(n).ok_or(CopyError("cut record"))?;
    *rest = tail;
    Ok(head)
}

fn array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], CopyError> {
    take(rest, N)?
        .try_into()
        .map_err(|_| CopyError("cut record"))
}

/// Decodes a register. Fuzzed (`copy_register_decode`).
///
/// # Errors
///
/// [`CopyError`] for a register above [`MAX_REGISTER_LEN`], an unknown
/// tag and a cut record.
pub fn decode_register(bytes: &[u8]) -> Result<Vec<CopyRecord>, CopyError> {
    if bytes.len() > MAX_REGISTER_LEN {
        return Err(CopyError("register too long"));
    }
    let mut rest = bytes;
    let mut out = Vec::new();
    while let Some((&tag, tail)) = rest.split_first() {
        rest = tail;
        let id = CopyId(array(&mut rest)?);
        match tag {
            TAG_TAKEN => {
                let created = u64::from_be_bytes(array(&mut rest)?);
                let count = u16::from_be_bytes(array(&mut rest)?);
                let mut keys = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    keys.push(array(&mut rest)?);
                }
                out.push(CopyRecord::Taken { id, created, keys });
            }
            TAG_RETIRED => out.push(CopyRecord::Retired { id }),
            _ => return Err(CopyError("unknown tag")),
        }
    }
    Ok(out)
}

fn read(path: &Path) -> Result<Vec<CopyRecord>, CopyError> {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > MAX_REGISTER_LEN as u64 => return Err(CopyError("register too long")),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(CopyError("read the register")),
    }
    decode_register(&std::fs::read(path).map_err(|_| CopyError("read the register"))?)
}

fn append(path: &Path, r: &CopyRecord) -> Result<(), CopyError> {
    let bytes = encode_record(r)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|_| CopyError("open the register"))?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| CopyError("write the register"))
}

/// Records a new copy that holds the keys of `keys` and returns its id.
///
/// # Errors
///
/// [`CopyError`] when the register does not decode or the write fails.
pub fn record_copy(path: &Path, keys: Vec<[u8; 32]>) -> Result<CopyId, CopyError> {
    read(path)?;
    let id = CopyId(fstp_crypto::random_array().map_err(|_| CopyError("random"))?);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    append(path, &CopyRecord::Taken { id, created, keys })?;
    Ok(id)
}

/// Records that every copy of `id` is destroyed.
///
/// # Errors
///
/// [`CopyError`] for an id the register holds no live copy of.
pub fn retire_copy(path: &Path, id: CopyId) -> Result<(), CopyError> {
    let records = read(path)?;
    let taken = records
        .iter()
        .any(|r| matches!(r, CopyRecord::Taken { id: t, .. } if *t == id));
    let retired = records
        .iter()
        .any(|r| matches!(r, CopyRecord::Retired { id: t } if *t == id));
    if !taken || retired {
        return Err(CopyError("no live copy of this id"));
    }
    append(path, &CopyRecord::Retired { id })
}

/// Whether a copy that is not retired holds a key whose digest is not
/// among `current`, the digests of the keys the owner holds now. A
/// missing register holds no copy. A register that does not decode
/// counts as holding such a copy.
#[must_use]
pub fn holds_replaced(path: &Path, current: &[[u8; 32]]) -> bool {
    let Ok(records) = read(path) else {
        return true;
    };
    let retired: Vec<CopyId> = records
        .iter()
        .filter_map(|r| match r {
            CopyRecord::Retired { id } => Some(*id),
            CopyRecord::Taken { .. } => None,
        })
        .collect();
    records.iter().any(|r| match r {
        CopyRecord::Taken { id, keys, .. } => {
            !retired.contains(id) && keys.iter().any(|k| !current.contains(k))
        }
        CopyRecord::Retired { .. } => false,
    })
}

/// The file beside a copy that names its id: the copy's path with `.id`
/// appended.
#[must_use]
pub fn id_file(copy: &Path) -> std::path::PathBuf {
    let mut name = copy.as_os_str().to_owned();
    name.push(".id");
    std::path::PathBuf::from(name)
}

/// Writes the id of a copy, as 32 hex digits and a line end, to the new
/// file [`id_file`] beside it, so the operator can retire it later
/// without a line on standard output (R-NF-02).
///
/// # Errors
///
/// [`CopyError`] for an existing file or a failed write.
pub fn write_id_file(copy: &Path, id: CopyId) -> Result<(), CopyError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(id_file(copy))
        .map_err(|_| CopyError("create the id file"))?;
    f.write_all(format!("{}\n", id.hex()).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| CopyError("write the id file"))
}
