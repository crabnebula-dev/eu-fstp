//! The self-hosted witness of a host (ADR-028 "One-host witness",
//! "Witness key commands" and "Witness custody").
//!
//! The key work runs in the witness's own binary: `fstp-witness
//! init-keys` creates the receipt key file through its own custody entry,
//! and `fstp-witness register` writes the cell's CA and anchor keys into
//! the file store while the witness is stopped. `fstp-admin` holds no
//! witness key.

use std::path::Path;

use crate::layout::Layout;
use crate::stack;
use crate::svc::{Manager, run_logged};

/// Why a witness step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessFail {
    /// `fstp-witness init-keys` failed: custody refused or did not answer.
    Keys(Option<i32>),
    /// `fstp-witness register` failed: the store refused the cell.
    Register(Option<i32>),
    /// `fstp-witness declare-restore` failed: the store refused the
    /// declaration, for example a head the witness never receipted (ADR-012
    /// record of lane m10/declared-restore).
    Declare(Option<i32>),
    /// A file did not read or write, or a public key file is malformed.
    Io,
}

/// The bytes of lowercase hex text.
#[must_use]
pub fn unhex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    t.as_bytes()
        .chunks_exact(2)
        .map(|p| Some((digit(*p.first()?)? << 4) | digit(*p.get(1)?)?))
        .collect()
}

fn run(layout: &Layout, args: &[&std::ffi::OsStr]) -> Result<Option<i32>, WitnessFail> {
    let mut c = stack::as_user(layout, stack::WITNESS_USER, &layout.bin("fstp-witness"));
    c.env("FSTP_WITNESS_CONFIG", layout.config_file("witness"))
        .args(args);
    run_logged(&mut c, &Manager::new(layout).log()).map_err(|_| WitnessFail::Io)
}

/// Creates the receipt key file once and copies `receipt.pub` into
/// `public`. Returns whether it created one.
///
/// # Errors
///
/// [`WitnessFail`] for the part that failed.
pub fn init_keys(layout: &Layout, public: &Path) -> Result<bool, WitnessFail> {
    let key = layout.creds("witness").join("receipt.key");
    let out = public.join("receipt.pub");
    if key.is_file() && out.is_file() {
        return Ok(false);
    }
    let tmp = layout.admin_dir().join("witness-public");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|_| WitnessFail::Io)?;
    crate::setup::own_path(layout, &tmp, stack::WITNESS_USER).map_err(|_| WitnessFail::Io)?;
    match run(layout, &["init-keys".as_ref(), tmp.as_os_str()])? {
        Some(0) => {}
        code => return Err(WitnessFail::Keys(code)),
    }
    let bytes = std::fs::read(tmp.join("receipt.pub")).map_err(|_| WitnessFail::Io)?;
    crate::state::write_atomic(&out, &bytes, 0o644).map_err(|_| WitnessFail::Io)?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(true)
}

/// Registers the cell with its CA and its App and Vault anchor keys. The
/// witness must be stopped. A repeat changes nothing.
///
/// # Errors
///
/// [`WitnessFail::Register`] when the store refuses.
pub fn register(layout: &Layout, cell: &str, public: &Path) -> Result<(), WitnessFail> {
    std::fs::create_dir_all(layout.witness_store()).map_err(|_| WitnessFail::Io)?;
    crate::setup::own_path(layout, &layout.witness_store(), stack::WITNESS_USER)
        .map_err(|_| WitnessFail::Io)?;
    let ca = layout.creds("witness").join("cell-ca.pem");
    match run(
        layout,
        &[
            "register".as_ref(),
            cell.as_ref(),
            ca.as_os_str(),
            public.join("anchor.pub").as_os_str(),
            public.join("vault-anchor.pub").as_os_str(),
        ],
    )? {
        Some(0) => Ok(()),
        code => Err(WitnessFail::Register(code)),
    }
}

/// Records a declared restore of one chain at the stopped witness:
/// `fstp-witness declare-restore <args>` as the witness's OS user (ADR-012
/// record of lane m10/declared-restore, `crate::declare`).
///
/// # Errors
///
/// [`WitnessFail::Declare`] when the witness refuses.
pub fn declare_restore(layout: &Layout, args: &[String]) -> Result<(), WitnessFail> {
    let mut all: Vec<&std::ffi::OsStr> = vec!["declare-restore".as_ref()];
    all.extend(args.iter().map(|a| std::ffi::OsStr::new(a.as_str())));
    match run(layout, &all)? {
        Some(0) => Ok(()),
        code => Err(WitnessFail::Declare(code)),
    }
}
