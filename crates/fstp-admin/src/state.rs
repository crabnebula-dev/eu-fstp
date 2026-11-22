//! The admin's own record of a host (ADR-028 "Setup is resumable").
//!
//! One text file, `<state>/admin/state`, with one `key value` pair per
//! line. It holds the cell id, the done steps and the applied migration
//! versions. It never holds a secret. Each write replaces the file
//! atomically.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The admin state of a host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    path: PathBuf,
    pairs: BTreeMap<String, String>,
}

/// The longest state file read.
const MAX_STATE_LEN: u64 = 1 << 20;

fn valid(word: &str) -> bool {
    !word.is_empty() && word.len() <= 256 && word.bytes().all(|b| b.is_ascii_graphic())
}

impl State {
    /// Loads the state at `path`, or an empty state when the file does
    /// not exist yet. Malformed lines are dropped.
    ///
    /// # Errors
    ///
    /// The I/O error of a file that exists and does not read.
    pub fn load(path: &Path) -> std::io::Result<State> {
        let mut pairs = BTreeMap::new();
        match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
            Ok(m) if m.len() > MAX_STATE_LEN => {
                return Err(std::io::Error::other("the state file is too long"));
            }
            Ok(_) => {
                let text = std::fs::read_to_string(path)?;
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(' ')
                        && valid(k)
                        && valid(v)
                    {
                        pairs.insert(k.to_owned(), v.to_owned());
                    }
                }
            }
        }
        Ok(State {
            path: path.to_owned(),
            pairs,
        })
    }

    /// The value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs.get(key).map(String::as_str)
    }

    /// Sets `key` and writes the file.
    ///
    /// # Errors
    ///
    /// An invalid key or value, or the I/O error of the write.
    pub fn set(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        if !valid(key) || !valid(value) {
            return Err(std::io::Error::other("a state word is not printable ASCII"));
        }
        self.pairs.insert(key.to_owned(), value.to_owned());
        self.save()
    }

    /// Removes `key` and writes the file.
    ///
    /// # Errors
    ///
    /// The I/O error of the write.
    pub fn remove(&mut self, key: &str) -> std::io::Result<()> {
        if self.pairs.remove(key).is_some() {
            self.save()?;
        }
        Ok(())
    }

    /// Whether the step `name` is recorded as done.
    #[must_use]
    pub fn done(&self, name: &str) -> bool {
        self.get(&format!("step.{name}")).is_some()
    }

    /// Records the step `name` as done now.
    ///
    /// # Errors
    ///
    /// The I/O error of the write.
    pub fn mark(&mut self, name: &str) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.set(&format!("step.{name}"), &now.to_string())
    }

    fn save(&self) -> std::io::Result<()> {
        let mut text = String::new();
        for (k, v) in &self.pairs {
            text.push_str(k);
            text.push(' ');
            text.push_str(v);
            text.push('\n');
        }
        write_atomic(&self.path, text.as_bytes(), 0o600)
    }
}

/// Writes `bytes` to `path` through a temporary file and a rename, with
/// `mode`, creating the parent directory.
///
/// # Errors
///
/// The I/O error of any step.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-028 "Setup is resumable": a done step survives a reload.
    #[test]
    fn adr028_done_steps_survive_a_reload() {
        let dir = std::env::temp_dir().join(format!("fstp-admin-state-{}", std::process::id()));
        let path = dir.join("state");
        let mut s = State::load(&path).unwrap();
        assert!(!s.done("pki"));
        s.mark("pki").unwrap();
        s.set("cell", "00112233445566778899aabbccddeeff").unwrap();
        assert!(s.set("bad key", "x").is_err());
        let back = State::load(&path).unwrap();
        assert!(back.done("pki"));
        assert_eq!(back.get("cell"), Some("00112233445566778899aabbccddeeff"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
