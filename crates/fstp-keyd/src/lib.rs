//! File custody server for self-hosted cells (I-80, I-81, Q32 A, ADR-004
//! part 2 "File custody").
//!
//! `fstp-keyd` is the only shipped crate that names [`RootMaterial`]
//! (layering rule 7). It serves create, wrap, unwrap, destroy and usage
//! requests on one Unix socket per client OS user. Each socket serves a
//! fixed set of chains ([`access`]), so the `fstp-cell` socket never
//! reaches the Vault chain (R-NF-08). The custody boundary is this
//! process: root bytes and the per-epoch keys `K(e)` never leave it.
//!
//! # The key volume
//!
//! Every file lives on a dedicated key volume, which must be ext4 or XFS
//! ([`key_volume_accepted`]) and is never backed up or snapshotted.
//!
//! - `epoch-<chain>-<e>.key`: the 32 root bytes of one epoch, sealed with
//!   AES-256-GCM under a per-epoch random key `K(e)` ([`epoch`]).
//! - `keytable`: every `K(e)`, one sealed slot each, under a key derived
//!   from the passphrase with PBKDF2-HMAC-SHA-256, at least 600 000
//!   iterations, with a random salt in its header ([`table`]). A torn
//!   write damages one slot at most.
//! - `usage.log`: the append-only usage log of request ids, operations,
//!   chains, epochs, times, outcomes and client roles. It holds no key
//!   bytes.
//!
//! Destroy overwrites `K(e)` in its slot of the key table in place,
//! fsyncs, unlinks the epoch file, fsyncs the directory and reads back.
//! The receipt records each step ([`receipt`]). The I-81 claim for file
//! custody is scoped to "the key volume is excluded from host backups and
//! snapshots" (ADR-004 part 2).
//!
//! # The passphrase
//!
//! There is no default passphrase (R-NF-05). [`serve`] reads it from the
//! systemd credential [`PASSPHRASE_CREDENTIAL`] in `$CREDENTIALS_DIRECTORY`
//! (`LoadCredentialEncrypted=`), which systemd can bind to the host's
//! TPM 2.0. Without that credential `serve` refuses to start. The
//! `fstp-keyd` binary asks the operator through `systemd-ask-password`
//! instead, on a host without a TPM ([`PassphraseSource::CredentialOrAsk`]),
//! and waits for the answer.

use zeroize::{ZeroizeOnDrop, Zeroizing};

pub mod access;
pub mod epoch;
pub mod receipt;
pub mod request;
pub mod table;
pub mod volume;

mod server;
mod usage;

#[cfg(test)]
mod review_tests;

pub use access::{ClientRole, ClientSocket, SignKeyClass};
pub use fstp_custody::keyd::Request as KeydRequest;
pub use receipt::{DestroyStep, Receipt, decode_receipt};
pub use request::{decode_request, encode_response};
pub use server::{PassphraseSource, serve, serve_sockets, stop};
pub use table::{
    EpochKey, KeyTable, KeyTableEntry, MIN_ITERATIONS, decode_key_table_body, encode_key_table,
    open_key_table,
};
pub use volume::{
    ACCEPTED_VOLUMES, EXT4_SUPER_MAGIC, MountEntry, XFS_SUPER_MAGIC, check_key_volume,
    decode_mountinfo, key_volume_accepted, type_magic,
};

/// The systemd credential that holds the passphrase.
pub const PASSPHRASE_CREDENTIAL: &str = "fstp-keyd-passphrase";

/// The program that asks the operator for the passphrase on a host
/// without a TPM (ADR-004 part 2 "Unattended boot").
pub const ASK_PASSWORD_PROGRAM: &str = "/usr/bin/systemd-ask-password";

/// The longest passphrase `fstp-keyd` reads.
pub const MAX_PASSPHRASE_LEN: usize = 4096;

/// The root bytes of one file custody epoch. No `Clone`, no `Debug`, no
/// public field and no method that hands out the bytes outside this
/// crate (I-80). It wipes them on drop.
pub struct RootMaterial {
    bytes: Zeroizing<[u8; 32]>,
}

impl ZeroizeOnDrop for RootMaterial {}

impl RootMaterial {
    /// The number of root bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the material is empty. It never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Fresh root bytes from the system generator.
    pub(crate) fn generate() -> Result<RootMaterial, KeydError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fstp_crypto::random_bytes(&mut bytes[..]).map_err(KeydError::Crypto)?;
        Ok(RootMaterial { bytes })
    }

    /// Root bytes opened from an epoch file.
    pub(crate) fn from_opened(bytes: Zeroizing<[u8; 32]>) -> RootMaterial {
        RootMaterial { bytes }
    }

    /// The bytes, for sealing into the epoch file and for the wrap key.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// A decoded key table file, still sealed under the passphrase. No
/// `Clone` and no `Debug`. Once opened it tells which epochs are live.
/// The `K(e)` it holds never leave this crate.
pub struct CustodyFile {
    sealed: table::SealedTable,
}

impl CustodyFile {
    /// The number of slots in use, read without opening the table.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.sealed.entry_count()
    }

    /// The PBKDF2 iteration count in the header.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.sealed.iterations()
    }

    /// Opens the table under `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`KeydError::WrongPassphrase`] when the table does not
    /// open, and [`KeydError::Malformed`] when its plaintext breaks the
    /// format.
    pub fn open(&self, passphrase: &Passphrase) -> Result<KeyTable, KeydError> {
        self.sealed.open(passphrase)
    }
}

/// The passphrase of the key table. No `Clone`, no `Debug`, wiped on
/// drop.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl ZeroizeOnDrop for Passphrase {}

impl Passphrase {
    /// A passphrase from its bytes.
    ///
    /// # Errors
    ///
    /// Refuses an empty passphrase and one above [`MAX_PASSPHRASE_LEN`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Passphrase, KeydError> {
        if bytes.is_empty() || bytes.len() > MAX_PASSPHRASE_LEN {
            return Err(KeydError::NoPassphrase);
        }
        Ok(Passphrase(Zeroizing::new(bytes.to_vec())))
    }

    /// The passphrase of the systemd credential [`PASSPHRASE_CREDENTIAL`]
    /// in `$CREDENTIALS_DIRECTORY`. One trailing newline is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`KeydError::NoPassphrase`] when the variable or the
    /// credential is missing, empty or too long.
    pub fn from_credentials() -> Result<Passphrase, KeydError> {
        let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(KeydError::NoPassphrase)?;
        let path = std::path::Path::new(&dir).join(PASSPHRASE_CREDENTIAL);
        let meta = std::fs::metadata(&path).map_err(|_| KeydError::NoPassphrase)?;
        let limit = u64::try_from(MAX_PASSPHRASE_LEN.saturating_add(1)).unwrap_or(u64::MAX);
        if meta.len() > limit {
            return Err(KeydError::NoPassphrase);
        }
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| KeydError::NoPassphrase)?);
        let trimmed = bytes.strip_suffix(b"\n").unwrap_or(&bytes[..]);
        Passphrase::from_bytes(trimmed)
    }

    /// The passphrase of the systemd credential, or else the one the
    /// operator enters through [`ASK_PASSWORD_PROGRAM`] (ADR-004 part 2
    /// "Unattended boot": without a TPM, `fstp-keyd` waits for the
    /// operator). The program asks through the systemd password agents,
    /// with no timeout, so the start waits until the operator answers.
    ///
    /// The flags `--id`, `--timeout=0` and `--no-tty` were written from
    /// the systemd manual as remembered. The check against the systemd of
    /// the supported hosts, and the minimum version in ADR-004, are with
    /// the lead.
    ///
    /// # Errors
    ///
    /// Returns [`KeydError::NoPassphrase`] when neither gives a
    /// passphrase.
    pub fn from_credentials_or_ask() -> Result<Passphrase, KeydError> {
        match Passphrase::from_credentials() {
            Ok(p) => Ok(p),
            Err(_) => Passphrase::ask(),
        }
    }

    fn ask() -> Result<Passphrase, KeydError> {
        use std::io::Read as _;
        use std::process::{Command, Stdio};

        let mut child = Command::new(ASK_PASSWORD_PROGRAM)
            .args([
                "--id=fstp-keyd:passphrase",
                "--timeout=0",
                "--no-tty",
                "fstp-keyd key table passphrase:",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| KeydError::NoPassphrase)?;
        let mut out = Zeroizing::new(Vec::new());
        let limit = u64::try_from(MAX_PASSPHRASE_LEN.saturating_add(2)).unwrap_or(u64::MAX);
        let read = child
            .stdout
            .take()
            .ok_or(KeydError::NoPassphrase)
            .and_then(|s| {
                s.take(limit)
                    .read_to_end(&mut out)
                    .map_err(|_| KeydError::NoPassphrase)
            });
        let status = child.wait().map_err(|_| KeydError::NoPassphrase)?;
        read?;
        if !status.success() {
            return Err(KeydError::NoPassphrase);
        }
        let trimmed = out.strip_suffix(b"\n").unwrap_or(&out[..]);
        Passphrase::from_bytes(trimmed)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a keyd operation failed. Its display never holds key bytes or
/// input bytes: every variant carries static text or a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeydError {
    /// Kept for W0 callers that match on it. No call here returns it.
    NotImplemented(&'static str),
    /// The input breaks the format. It names the rule.
    Malformed(&'static str),
    /// The key table did not open under the passphrase.
    WrongPassphrase,
    /// The key table names fewer than [`MIN_ITERATIONS`] PBKDF2
    /// iterations, or more than the decoder accepts.
    WeakKdf,
    /// No passphrase credential is available, or it is empty.
    NoPassphrase,
    /// The key volume is refused. It names the rule.
    Volume(&'static str),
    /// A file or socket operation failed. It names the stage.
    Io(&'static str),
    /// Another server already serves this socket.
    AlreadyRunning,
    /// No server of this process serves this socket.
    NotRunning,
    /// The crypto layer refused.
    Crypto(fstp_crypto::CryptoError),
}

impl std::fmt::Display for KeydError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeydError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            KeydError::Malformed(s) => write!(f, "malformed input: {s}"),
            KeydError::WrongPassphrase => f.write_str("the key table did not open"),
            KeydError::WeakKdf => f.write_str("the key table KDF iteration count is refused"),
            KeydError::NoPassphrase => f.write_str("no passphrase credential is available"),
            KeydError::Volume(s) => write!(f, "key volume refused: {s}"),
            KeydError::Io(s) => write!(f, "keyd I/O failed: {s}"),
            KeydError::AlreadyRunning => f.write_str("another fstp-keyd serves this socket"),
            KeydError::NotRunning => f.write_str("no fstp-keyd of this process serves this socket"),
            KeydError::Crypto(e) => write!(f, "keyd crypto: {e}"),
        }
    }
}

impl std::error::Error for KeydError {}

/// Decodes a key table file without opening it. Fuzzed
/// (`custody_file_decode`).
///
/// # Errors
///
/// Refuses a wrong magic, version or KDF code, an iteration count
/// outside the accepted range, and a length that holds no whole number
/// of entries.
pub fn decode_custody_file(bytes: &[u8]) -> Result<CustodyFile, KeydError> {
    table::SealedTable::decode(bytes).map(|sealed| CustodyFile { sealed })
}
