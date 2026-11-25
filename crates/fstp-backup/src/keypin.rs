//! The digest pin of the backup key file (ADR-012 record of lane
//! m10/key-pin-reason, F-044, TH-51).
//!
//! The file [`PIN_FILE`] in the agent's state directory holds the
//! SHA-256 of `cluster-backup.key` in 64 lowercase hex digits and a line
//! feed. The state directory is root's, apart from the credentials
//! directory. `fstp-backup` writes the pin in the same step as the key
//! file (`init-keys`, `upgrade-keys`, the adoption on a second custodian,
//! and `pin-key` once on a host set up before the pin). The agent refuses
//! every seal while the pin does not name the key file it read. The
//! decoder admits one spelling and is fuzzed (`backup_key_pin_decode`).

use std::path::Path;

use crate::BackupError;

/// The pin file in the agent's state directory.
pub const PIN_FILE: &str = "key-pin";

/// The length of a pin file: 64 hex digits and a line feed.
pub const PIN_LEN: usize = 65;

/// The pin text of the key file `key_file`.
#[must_use]
pub fn encode(key_file: &[u8]) -> String {
    format!("{}\n", crate::sigv4::hex(&fstp_crypto::sha256(key_file)))
}

/// Decodes a pin file: exactly 64 lowercase hex digits and a line feed.
///
/// # Errors
///
/// [`BackupError::Malformed`] (`key pin`) for any other spelling.
pub fn decode(bytes: &[u8]) -> Result<[u8; 32], BackupError> {
    let bad = BackupError::Malformed("key pin");
    if bytes.len() != PIN_LEN || bytes.last() != Some(&b'\n') {
        return Err(bad);
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let (Some(&hi), Some(&lo)) = (pair.first(), pair.get(1)) else {
            return Err(bad);
        };
        *slot = (digit(hi).ok_or(bad)? << 4) | digit(lo).ok_or(bad)?;
    }
    Ok(out)
}

/// What the agent knows of the pin when it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pin {
    /// The pin names this digest.
    Names([u8; 32]),
    /// No pin file.
    Missing,
    /// A pin file that does not decode, or does not read.
    Unreadable,
}

/// Reads the pin of the state directory `state_dir`.
#[must_use]
pub fn read(state_dir: &Path) -> Pin {
    match std::fs::read(state_dir.join(PIN_FILE)) {
        Ok(b) => decode(&b).map_or(Pin::Unreadable, Pin::Names),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Pin::Missing,
        Err(_) => Pin::Unreadable,
    }
}

/// Whether `pin` names the key file `key_file`.
///
/// # Errors
///
/// [`BackupError::KeyPinMissing`] without a pin, and
/// [`BackupError::KeyPinDiffers`] for a pin of another file or one that
/// does not decode.
pub fn matches(pin: Pin, key_file: &[u8]) -> Result<(), BackupError> {
    matches_digest(pin, &fstp_crypto::sha256(key_file))
}

/// Whether `pin` names the key file of SHA-256 `digest`.
///
/// # Errors
///
/// As [`matches`].
pub fn matches_digest(pin: Pin, digest: &[u8; 32]) -> Result<(), BackupError> {
    match pin {
        Pin::Names(d) if d == *digest => Ok(()),
        Pin::Names(_) | Pin::Unreadable => Err(BackupError::KeyPinDiffers),
        Pin::Missing => Err(BackupError::KeyPinMissing),
    }
}

/// Whether the pin of `state_dir` names the key file `key_file`.
///
/// # Errors
///
/// As [`matches`].
pub fn check(state_dir: &Path, key_file: &[u8]) -> Result<(), BackupError> {
    matches(read(state_dir), key_file)
}

/// Writes the pin of `key_file` into `state_dir`, through a temporary
/// file and a rename, with mode 0644: `archive_command` reads it as
/// `postgres`. The state directory is created when it is missing.
///
/// # Errors
///
/// [`BackupError::Io`] (`key pin`) when a file step fails.
pub fn write(state_dir: &Path, key_file: &[u8]) -> Result<(), BackupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |_| BackupError::Io("key pin");
    std::fs::create_dir_all(state_dir).map_err(io)?;
    let tmp = state_dir.join(format!("{PIN_FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(encode(key_file).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(io)?;
    std::fs::rename(&tmp, state_dir.join(PIN_FILE)).map_err(io)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// F-044, ADR-012 record of lane m10/key-pin-reason, row "Decoder":
    /// the pin round-trips in one spelling, and every other spelling is
    /// refused: upper case, no line feed, a carriage return, a short or a
    /// long digest, a space.
    #[test]
    fn f044_key_pin_decodes_one_spelling() {
        let key = b"synthetic key file";
        let text = encode(key);
        assert_eq!(text.len(), PIN_LEN);
        assert_eq!(decode(text.as_bytes()).unwrap(), fstp_crypto::sha256(key));
        let digits = text.trim_end();
        for bad in [
            digits.to_owned(),
            digits.to_uppercase() + "\n",
            format!("{digits}\r\n"),
            format!("{}\n", &digits[..62]),
            format!("{digits}00\n"),
            format!(" {}\n", &digits[1..]),
            format!("{}g\n", &digits[..63]),
            String::new(),
        ] {
            assert_eq!(
                decode(bad.as_bytes()),
                Err(BackupError::Malformed("key pin")),
                "{bad:?}"
            );
        }
        assert_eq!(matches(Pin::Names(fstp_crypto::sha256(key)), key), Ok(()));
        assert_eq!(
            matches(Pin::Names([0; 32]), key),
            Err(BackupError::KeyPinDiffers)
        );
        assert_eq!(
            matches(Pin::Unreadable, key),
            Err(BackupError::KeyPinDiffers)
        );
        assert_eq!(matches(Pin::Missing, key), Err(BackupError::KeyPinMissing));
    }
}
