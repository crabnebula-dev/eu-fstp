//! The guard state of a pilot key volume (ADR-004 record of lane
//! `m10/guard-key`, row "Pilot guard state").
//!
//! ```text
//! guard.state = "FGS1" | version u8 = 1 | generation u32 | rotated u64
//!               | owed u8 | event 16                              34 bytes
//! ```
//!
//! `generation` is the guard generation the custodian last named, 0 before
//! the first answer. `rotated` is the time of the last rotation in Unix
//! seconds, 0 before the first. `owed` is 1 while a rotation is owed for
//! `event`, the request id of the destroy that caused it, and 0 with 16
//! zero bytes otherwise. It holds no key bytes. The file is written to a
//! temporary file, synced and renamed, so a crash leaves the old state or
//! the new one. The decoder is fuzzed (`guard_link_decode`).

use std::io::Write as _;
use std::path::Path;

use crate::KeydError;

/// The file name on the key volume.
pub const STATE_FILE: &str = "guard.state";
/// The magic.
pub const STATE_MAGIC: [u8; 4] = *b"FGS1";
/// The version.
pub const STATE_VERSION: u8 = 1;
/// The length of the file.
pub const STATE_LEN: usize = 34;

/// The guard state of a pilot entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardState {
    /// The generation the custodian last named, 0 before any answer.
    pub generation: u32,
    /// When the guard was last replaced, Unix seconds, 0 before.
    pub rotated: u64,
    /// The owed event, while a rotation is owed.
    pub owed: Option<[u8; 16]>,
}

impl GuardState {
    /// The file bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; STATE_LEN] {
        let mut out = [0u8; STATE_LEN];
        let parts: [&[u8]; 6] = [
            &STATE_MAGIC,
            &[STATE_VERSION],
            &self.generation.to_be_bytes(),
            &self.rotated.to_be_bytes(),
            &[u8::from(self.owed.is_some())],
            &self.owed.unwrap_or([0u8; 16]),
        ];
        let mut at = 0usize;
        for p in parts {
            let end = at.saturating_add(p.len());
            if let Some(dst) = out.get_mut(at..end) {
                dst.copy_from_slice(p);
            }
            at = end;
        }
        out
    }
}

fn bad(rule: &'static str) -> KeydError {
    KeydError::Malformed(rule)
}

/// Decodes a guard state file. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for another length, magic, version or owed
/// flag, and for an event beside a flag of 0.
pub fn decode_state(bytes: &[u8]) -> Result<GuardState, KeydError> {
    let b: &[u8; STATE_LEN] = bytes
        .try_into()
        .map_err(|_| bad("a guard state has the wrong length"))?;
    let (magic, rest) = b.split_at(4);
    if magic != STATE_MAGIC {
        return Err(bad("a guard state has the wrong magic"));
    }
    let (version, rest) = rest.split_at(1);
    if version != [STATE_VERSION] {
        return Err(bad("a guard state has an unknown version"));
    }
    let (generation, rest) = rest.split_at(4);
    let (rotated, rest) = rest.split_at(8);
    let (flag, event) = rest.split_at(1);
    let event: [u8; 16] = event.try_into().map_err(|_| bad("cut short"))?;
    let owed = match flag {
        [0] if event == [0u8; 16] => None,
        [1] => Some(event),
        _ => return Err(bad("a guard state has a bad owed flag")),
    };
    Ok(GuardState {
        generation: u32::from_be_bytes(generation.try_into().map_err(|_| bad("cut short"))?),
        rotated: u64::from_be_bytes(rotated.try_into().map_err(|_| bad("cut short"))?),
        owed,
    })
}

/// Reads the guard state of `volume`. A missing file is the default
/// state.
///
/// # Errors
///
/// [`KeydError::Io`] for a file that does not read, and the decoder's
/// refusal.
pub fn read_state(volume: &Path) -> Result<GuardState, KeydError> {
    match std::fs::read(volume.join(STATE_FILE)) {
        Ok(b) => decode_state(&b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GuardState::default()),
        Err(_) => Err(KeydError::Io("read the guard state")),
    }
}

/// Writes the guard state of `volume` so a crash leaves the old one or the
/// new one.
///
/// # Errors
///
/// [`KeydError::Io`] when a step fails.
pub fn write_state(volume: &Path, state: &GuardState) -> Result<(), KeydError> {
    let tmp = volume.join(format!("{STATE_FILE}.new"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = crate::volume::private(std::fs::OpenOptions::new().write(true).create_new(true))
        .open(&tmp)
        .map_err(|_| KeydError::Io("create the guard state"))?;
    f.write_all(&state.encode())
        .and_then(|()| f.sync_all())
        .map_err(|_| KeydError::Io("write the guard state"))?;
    drop(f);
    std::fs::rename(&tmp, volume.join(STATE_FILE))
        .map_err(|_| KeydError::Io("move the guard state"))?;
    crate::epoch::sync_dir(volume)
}

/// The current Unix time in seconds.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    /// ADR-004 record of lane `m10/guard-key`: the guard state reads back
    /// in one spelling, owed or not.
    #[test]
    fn adr004_guard_state_round_trips_in_one_spelling() {
        for s in [
            GuardState::default(),
            GuardState {
                generation: 4,
                rotated: 77,
                owed: Some([9; 16]),
            },
        ] {
            assert_eq!(decode_state(&s.encode()).unwrap(), s);
        }
        let mut b = GuardState::default().encode();
        b[20] = 1;
        assert!(decode_state(&b).is_err(), "an event beside flag 0");
        b[17] = 2;
        assert!(decode_state(&b).is_err(), "flag 2");
    }
}
