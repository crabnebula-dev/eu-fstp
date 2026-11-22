//! Off-host copies of the cell key file (ADR-004 record of lane L16,
//! Q-L16-3, decided by Daniel on 2026-11-21, I-81).
//!
//! `fstp-cell copy-key-file <out>` opens `cell-keys.sealed` through the
//! key file's own `fstp-keyd` entry, writes its sealed bytes to `<out>`
//! and records the copy in `cell-keys.copies` beside it, with a digest of
//! each key the copy holds ([`fstp_custody::copies`]). The file is copied
//! as sealed: the copy never holds an open key (I-80).
//!
//! At each start, the cell compares the register with the keys of the
//! live file. While a copy that is not retired holds a key the live file
//! no longer holds, such as a replaced `CredLookup` key, it logs reduced
//! I-81 assurance ([`report`]). `fstp-cell retire-key-file-copy <id>`
//! records that every copy of an id is destroyed.

use std::path::Path;

use fstp_custody::copies::{self, CopyId};
use fstp_custody::{Aad, Custody, WrappedSealKey};
use fstp_obs::LogEvent;
use fstp_obs::assurance::{Assurance, ReducedReason};

use crate::keyfile::{self, KeyBody, KeyFileError};

/// The copy register in the credentials directory.
pub const COPY_REGISTER: &str = "cell-keys.copies";

/// The digest of every key of `body`: the anchor, the `CredLookup` key,
/// the ticket key and each ledger generation.
#[must_use]
pub fn key_digests(body: &KeyBody) -> Vec<[u8; 32]> {
    let mut out = vec![
        copies::key_digest("anchor", &body.anchor[..]),
        copies::key_digest("cred_lookup", &body.cred_lookup[..]),
        copies::key_digest("ticket", &body.ticket[..]),
    ];
    out.extend(
        body.generations
            .iter()
            .map(|g| copies::key_digest("ledger", &g.key[..])),
    );
    out
}

/// The I-81 assurance the copy register of `creds` gives against the
/// live keys `body`: reduced while a copy that is not retired holds a key
/// `body` no longer holds, and `None` otherwise.
#[must_use]
pub fn assurance(creds: &Path, body: &KeyBody) -> Option<Assurance> {
    copies::holds_replaced(&creds.join(COPY_REGISTER), &key_digests(body))
        .then_some(Assurance::Reduced(ReducedReason::CopyHoldsReplacedKey))
}

/// Logs the reduced assurance of [`assurance`], if any, as a typed event.
pub fn report(creds: &Path, body: &KeyBody) {
    if let Some(assurance) = assurance(creds, body) {
        let _ = fstp_obs::log_to_stderr(&LogEvent::KeyFileAssurance {
            file: keyfile::KEY_FILE,
            assurance,
        });
    }
}

/// Copies the key file of `cell` in `creds` to the new file `out`, as
/// sealed, and records the copy with the digests of the keys it holds.
/// The key file is opened through `custody` only to learn those keys.
///
/// # Errors
///
/// [`KeyFileError`] for a key file that does not open, an existing
/// `out`, and a register that refuses.
pub async fn copy_key_file<C: Custody>(
    custody: &C,
    cell: [u8; 16],
    creds: &Path,
    out: &Path,
) -> Result<CopyId, KeyFileError> {
    let bytes = std::fs::read(creds.join(keyfile::KEY_FILE))
        .map_err(|_| KeyFileError("read the key file"))?;
    let f = keyfile::decode_key_file(&bytes)?;
    if f.cell != cell {
        return Err(KeyFileError("another cell"));
    }
    let seal = custody
        .unwrap(
            &keyfile::root_of(&f),
            &WrappedSealKey(f.wrapped.clone()),
            &Aad(keyfile::aad(&f.cell, f.epoch)),
        )
        .await
        .map_err(|_| KeyFileError("custody unwrap"))?;
    let body = keyfile::open_body(&f, &seal)?;
    write_new(out, &bytes)?;
    let id = copies::record_copy(&creds.join(COPY_REGISTER), key_digests(&body))
        .map_err(|e| KeyFileError(e.0))?;
    copies::write_id_file(out, id).map_err(|e| KeyFileError(e.0))?;
    Ok(id)
}

/// Records that every copy of `id` is destroyed.
///
/// # Errors
///
/// [`KeyFileError`] for an id the register holds no live copy of.
pub fn retire(creds: &Path, id: CopyId) -> Result<(), KeyFileError> {
    copies::retire_copy(&creds.join(COPY_REGISTER), id).map_err(|e| KeyFileError(e.0))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), KeyFileError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| KeyFileError("create the copy"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| KeyFileError("write the copy"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fstp-cell-l16-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// I-81, ADR-004 record of lane L16 (Q-L16-3): a copy of the cell key
    /// file lowers the assurance once the live file replaces a key the
    /// copy holds, and until the copy is retired. A new ledger generation
    /// alone adds a key and replaces none.
    #[test]
    fn i81_cell_key_file_copy_reports_reduced_after_a_key_is_replaced() {
        let creds = scratch("replace");
        let mut body = KeyBody::generate().unwrap();
        assert_eq!(assurance(&creds, &body), None);
        let id = copies::record_copy(&creds.join(COPY_REGISTER), key_digests(&body)).unwrap();
        body.next_generation().unwrap();
        assert_eq!(assurance(&creds, &body), None, "a new generation");
        *body.cred_lookup = [0x42; 32];
        assert_eq!(
            assurance(&creds, &body),
            Some(Assurance::Reduced(ReducedReason::CopyHoldsReplacedKey))
        );
        retire(&creds, id).unwrap();
        assert_eq!(assurance(&creds, &body), None);
        let _ = std::fs::remove_dir_all(&creds);
    }

    /// ADR-004 record of lane L16: the binary takes `copy-key-file <out>`
    /// and `retire-key-file-copy <id>`, with an id of 32 hex digits.
    #[test]
    fn adr004_cell_binary_takes_the_key_file_copy_commands() {
        use crate::run::{Command, parse_args};
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&s(&["copy-key-file", "/c"])).unwrap(),
            Command::CopyKeyFile("/c".into())
        );
        assert_eq!(
            parse_args(&s(&["retire-key-file-copy", &"0f".repeat(16)])).unwrap(),
            Command::RetireKeyFileCopy(CopyId([0x0f; 16]))
        );
        assert!(parse_args(&s(&["retire-key-file-copy", "zz"])).is_err());
        assert!(parse_args(&s(&["copy-key-file"])).is_err());
    }

    /// I-80, ADR-004 record of lane L16: the register names each key by
    /// a digest only. No key of the file is in it.
    #[test]
    fn i80_cell_key_file_copy_register_holds_no_key() {
        let creds = scratch("bytes");
        let body = KeyBody::generate().unwrap();
        copies::record_copy(&creds.join(COPY_REGISTER), key_digests(&body)).unwrap();
        let reg = std::fs::read(creds.join(COPY_REGISTER)).unwrap();
        for key in [&body.cred_lookup[..], &body.ticket[..]] {
            assert!(!reg.windows(key.len()).any(|w| w == key));
        }
        let _ = std::fs::remove_dir_all(&creds);
    }
}
