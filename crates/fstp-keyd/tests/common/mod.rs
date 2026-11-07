//! Helpers shared by the `fstp-keyd` crate tests (lane W2f, test author).
//!
//! - [`Fail`] separates a refusal the crate means from a W0 stub that
//!   refuses everything with `NotImplemented`. A refusal test passes only
//!   on [`Fail::Refused`].
//! - [`impls!`] reads `true` exactly when a bound holds, at compile time.
//! - [`start`] runs `fstp-keyd` on a fresh socket and key volume. The key
//!   volume lives under `FSTP_KEY_VOLUME_DIR`, or else in the temporary
//!   directory at reduced assurance (I-81 NOTE, Q-F interim).

#![allow(
    dead_code,
    unreachable_pub,
    unused_macros,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; each test binary uses a subset"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fstp_custody::KeydCustody;
use fstp_obs::assurance::Assurance;

/// Why a call did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// A W0 stub refused with `NotImplemented`, or a test-side seam stands
    /// in for a call the stub lacks. Never a pass for a refusal test.
    Seam(String),
    /// The crate refused. The error's `Debug` and `Display` forms.
    Refused {
        /// The `Debug` form.
        debug: String,
        /// The `Display` form.
        display: String,
    },
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Seam(s) => write!(f, "seam: {s}"),
            Fail::Refused { debug, .. } => write!(f, "refused: {debug}"),
        }
    }
}

impl From<Fail> for String {
    fn from(f: Fail) -> String {
        f.to_string()
    }
}

/// Sorts an error of the crate. Every W0 stub error is a `NotImplemented`
/// variant, so its `Debug` form names it. Any other error is a refusal.
pub fn classify<E: std::fmt::Debug + std::fmt::Display>(e: E) -> Fail {
    let debug = format!("{e:?}");
    if debug.starts_with("NotImplemented(") {
        Fail::Seam(debug)
    } else {
        Fail::Refused {
            debug,
            display: e.to_string(),
        }
    }
}

/// Passes only when `r` is a real refusal, and returns its two forms.
pub fn expect_refused<T>(r: Result<T, Fail>, what: &str) -> Result<(String, String), String> {
    match r {
        Err(Fail::Refused { debug, display }) => Ok((debug, display)),
        Err(Fail::Seam(s)) => Err(format!("{what}: seam: {s}")),
        Ok(_) => Err(format!("{what}: accepted")),
    }
}

/// Reads `true` exactly when `$t` implements every bound, at compile
/// time, and compiles either way.
macro_rules! impls {
    ($t:ty: $($tr:tt)+) => {{
        #[allow(dead_code)]
        trait DoesNotImpl {
            const IMPLS: bool = false;
        }
        #[allow(dead_code)]
        impl<T: ?Sized> DoesNotImpl for T {}
        struct Wrapper<T: ?Sized>(::core::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $($tr)+> Wrapper<T> {
            const IMPLS: bool = true;
        }
        <Wrapper<$t>>::IMPLS
    }};
}
#[allow(unused_imports)]
pub(crate) use impls;

/// Whether `haystack` holds `needle` anywhere.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The key volume and the server.

/// The variable that names a directory on an ext4 or XFS mount.
pub const KEY_VOLUME_ENV: &str = "FSTP_KEY_VOLUME_DIR";

/// The directory under which the server tests make key volumes: the one
/// `FSTP_KEY_VOLUME_DIR` names, or else the system temporary directory.
/// Q-F, interim pending Daniel (m3-finish section 5 step 4): without the
/// variable every test still runs, on a volume of reduced assurance. The
/// Linux CI test job sets it to an ext4 mount, and the guard
/// `i81_note_linux_ci_key_volume_reports_full` fails there without it.
pub fn key_volume_root() -> PathBuf {
    match std::env::var_os(KEY_VOLUME_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir(),
    }
}

/// Whether `FSTP_KEY_VOLUME_DIR` names a directory.
pub fn key_volume_named() -> bool {
    std::env::var_os(KEY_VOLUME_ENV).is_some_and(|d| !d.is_empty())
}

/// Checks the I-81 assurance of `volume` (I-81 NOTE of 2026-11-01, Q-F).
/// A volume under `FSTP_KEY_VOLUME_DIR` on Linux must report `Full`.
/// Off Linux every volume reports `Reduced` with a reason. Elsewhere the
/// test asserts `Full` only where the volume reports it.
pub fn check_volume_assurance(volume: &Path) -> Result<Assurance, String> {
    let a = fstp_keyd::check_key_volume(volume);
    let linux = cfg!(target_os = "linux");
    match a {
        Assurance::Full if !linux => Err(format!(
            "{} reports full assurance off Linux",
            volume.display()
        )),
        Assurance::Reduced(r) if linux && key_volume_named() => Err(format!(
            "FSTP_KEY_VOLUME_DIR names a volume of reduced assurance: {}",
            r.as_str()
        )),
        _ => Ok(a),
    }
}

/// A fresh socket directory and key volume, removed when dropped.
pub struct Scratch {
    pub socket_dir: PathBuf,
    pub socket: PathBuf,
    pub volume: PathBuf,
}

impl Scratch {
    /// A scratch set for the test `name`.
    pub fn new(name: &str) -> Result<Scratch, String> {
        let leaf = format!("fstp-keyd-crate-{name}-{}", std::process::id());
        let root = key_volume_root();
        let socket_dir = std::env::temp_dir().join(&leaf);
        let volume = root.join(&leaf);
        for dir in [&socket_dir, &volume] {
            let _ = fs::remove_dir_all(dir);
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        check_volume_assurance(&volume)?;
        Ok(Scratch {
            socket: socket_dir.join("keyd.sock"),
            socket_dir,
            volume,
        })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.socket_dir);
        let _ = fs::remove_dir_all(&self.volume);
    }
}

/// Starts `fstp-keyd` on `socket` and `volume` in a thread, and returns a
/// client once the socket is bound. A server that exits first is
/// reported with its error. The thread is not joined, so the server ends
/// with the test process. A test that restarts it calls `fstp_keyd::stop`
/// first.
pub fn start(socket: &Path, volume: &Path) -> Result<KeydCustody, String> {
    let (done, exited) = std::sync::mpsc::channel();
    {
        let (socket, volume) = (socket.to_path_buf(), volume.to_path_buf());
        std::thread::spawn(move || {
            let _ = done.send(fstp_keyd::serve(&socket, &volume).map_err(classify));
        });
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        match exited.try_recv() {
            Ok(Err(e)) => return Err(format!("fstp_keyd::serve: {e}")),
            Ok(Ok(())) => return Err("fstp_keyd::serve returned before binding".to_owned()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("fstp_keyd::serve panicked".to_owned());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() > deadline {
            return Err(format!("fstp-keyd bound no socket at {}", socket.display()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    KeydCustody::new(socket).map_err(|e| format!("KeydCustody::new: {e}"))
}

/// Starts `fstp-keyd` on `volume` with the `fstp-cell` socket at
/// `cell` and the `fstp-vault` socket at `vault` (ADR-004 part 2 "Access
/// to `fstp-keyd`"), and returns one client for each once both sockets
/// are bound.
pub fn start_cell_and_vault(
    cell: &Path,
    vault: &Path,
    volume: &Path,
) -> Result<(KeydCustody, KeydCustody), String> {
    use fstp_keyd::{ClientRole, ClientSocket, PassphraseSource};
    let (done, exited) = std::sync::mpsc::channel();
    {
        let sockets = vec![
            ClientSocket::owner_only(cell, ClientRole::Cell),
            ClientSocket::owner_only(vault, ClientRole::Vault),
        ];
        let volume = volume.to_path_buf();
        std::thread::spawn(move || {
            let r = fstp_keyd::serve_sockets(&sockets, &volume, PassphraseSource::Credential);
            let _ = done.send(r.map_err(classify));
        });
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(cell.exists() && vault.exists()) {
        match exited.try_recv() {
            Ok(Err(e)) => return Err(format!("fstp_keyd::serve_sockets: {e}")),
            Ok(Ok(())) => return Err("fstp_keyd::serve_sockets returned early".to_owned()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("fstp_keyd::serve_sockets panicked".to_owned());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() > deadline {
            return Err("fstp-keyd bound no cell and vault sockets".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let c = KeydCustody::new(cell).map_err(|e| format!("KeydCustody::new: {e}"))?;
    let v = KeydCustody::new(vault).map_err(|e| format!("KeydCustody::new: {e}"))?;
    Ok((c, v))
}

/// A scratch set and a client of a server running on it. Panics with the
/// reason when either cannot be made.
pub fn running(name: &str) -> (Scratch, KeydCustody) {
    let scratch = Scratch::new(name).unwrap_or_else(|e| panic!("{e}"));
    let client = start(&scratch.socket, &scratch.volume).unwrap_or_else(|e| panic!("{e}"));
    (scratch, client)
}

/// Every regular file under `dir`, recursively, with its bytes.
pub fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            out.extend(files_under(&path));
        } else if meta.is_file()
            && let Ok(bytes) = fs::read(&path)
        {
            out.push((path, bytes));
        }
    }
    out
}
