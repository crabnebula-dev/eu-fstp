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
    /// `fstp-backup witness-archive` failed with this status (ADR-028
    /// record of lane `m10/witness-copy`).
    Copy(Option<i32>),
    /// `fstp-backup witness-restore` or `witness-fetch` failed with this
    /// status.
    Rebuild(Option<i32>),
    /// `fstp-witness check-store` refused the store with this status.
    Check(Option<i32>),
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

/// Runs `fstp-backup <args>` with the application cluster's backup
/// configuration, as root (ADR-012 record of lane m10/witness-copy, row
/// "Mechanism"). The exit status.
fn backup_tool(layout: &Layout, args: &[&std::ffi::OsStr]) -> Result<Option<i32>, WitnessFail> {
    let mut c = std::process::Command::new(layout.bin("fstp-backup"));
    let (k, v) = crate::ops::backup_env(layout, crate::layout::Cluster::App);
    c.env(k, v).args(args);
    run_logged(&mut c, &Manager::new(layout).log()).map_err(|_| WitnessFail::Io)
}

/// `fstp-witness check-store <dir>` as the witness user: the store in
/// `dir` loads and every witness link recomputes (ADR-028 record of lane
/// `m10/witness-copy`).
///
/// # Errors
///
/// [`WitnessFail::Check`] when the store does not load.
pub fn check_store(layout: &Layout, dir: &Path) -> Result<(), WitnessFail> {
    match run(layout, &["check-store".as_ref(), dir.as_os_str()])? {
        Some(0) => Ok(()),
        code => Err(WitnessFail::Check(code)),
    }
}

/// `fstp-backup witness-fetch <dir>`: every witness copy into the new
/// directory `dir`, owned by the witness user afterwards (the drill,
/// ADR-012 record of lane m10/witness-copy).
///
/// # Errors
///
/// [`WitnessFail::Rebuild`] when the copies do not fetch or open.
pub fn fetch(layout: &Layout, dir: &Path) -> Result<(), WitnessFail> {
    fetch_for(layout, dir, stack::WITNESS_USER)
}

/// `fstp-backup witness-fetch <dir>`, as [`fetch`], with `dir` owned by
/// `user` afterwards: the drill's chain check reads it as the cell or
/// the vault user (ADR-012 record of lane m10/drill-chain).
///
/// # Errors
///
/// [`WitnessFail::Rebuild`] when the copies do not fetch or open.
pub fn fetch_for(layout: &Layout, dir: &Path, user: &str) -> Result<(), WitnessFail> {
    match backup_tool(layout, &["witness-fetch".as_ref(), dir.as_os_str()])? {
        Some(0) => crate::setup::own_path(layout, dir, user).map_err(|_| WitnessFail::Io),
        code => Err(WitnessFail::Rebuild(code)),
    }
}

/// The exit status of `fstp-backup witness-restore` for a store that
/// differs from its copies.
pub const DIVERGED: i32 = 5;

/// Rebuilds the witness store from its copies where it is missing or
/// behind, then checks that it loads (ADR-012 record of lane
/// m10/witness-copy, row "Rebuild in `restore`"). After `restore-keys`, a store
/// that differs from its copies moves aside as
/// `<store>.before-restore-<time>` and is rebuilt (lead answer 1).
/// Without that marker it stops the restore. The witness must be
/// stopped. A store with no copies stays as it is.
///
/// # Errors
///
/// [`crate::fail::Fail::Refused`] for a store that differs from its
/// copies, after a line that says what to do, and
/// [`crate::fail::Fail::Step`] when the fetch or the check fails.
pub fn rebuild(layout: &Layout) -> Result<(), crate::fail::Fail> {
    use crate::fail::{Cause, Fail};
    use crate::say::{Part, out};
    let step = |e: WitnessFail| Fail::Step("restore", Cause::Witness(e));
    let store = layout.witness_store();
    let restore = || backup_tool(layout, &["witness-restore".as_ref(), store.as_os_str()]);
    let mut code = restore().map_err(step)?;
    // Lead answer 1 of 2026-11-24 (ADR-012 record of lane m10/witness-copy):
    // after restore-keys, a diverged store is the new host's own, so it
    // moves aside, kept, and the store comes back from the copies.
    if code == Some(DIVERGED) && crate::custodian::host_loss_pending(layout) {
        let aside = store.with_file_name(format!(
            "{}.before-restore-{}",
            store
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("witness"),
            crate::pki::now()
        ));
        std::fs::rename(&store, &aside).map_err(|_| step(WitnessFail::Io))?;
        out(&[
            Part::T("  done     moved the witness store that differs from its copies aside to "),
            Part::P(&aside),
        ]);
        code = restore().map_err(step)?;
    }
    match code {
        Some(0) => {}
        Some(DIVERGED) => {
            out(&[
                Part::T("The witness store "),
                Part::P(&store),
                Part::T(
                    " differs from its copies in the object store, so the restore stopped before any change. It may be evidence of tampering. If this host replaces a lost one, run fstp-admin restore-keys first: the restore after it keeps this store aside and rebuilds it.",
                ),
            ]);
            return Err(Fail::Refused("fstp-backup witness-restore", Some(DIVERGED)));
        }
        code => return Err(step(WitnessFail::Rebuild(code))),
    }
    if !store.is_dir() {
        out(&[Part::T(
            "  done     no witness copies and no witness store yet: the witness starts empty",
        )]);
        return Ok(());
    }
    crate::setup::own_path(layout, &store, stack::WITNESS_USER)
        .map_err(|_| step(WitnessFail::Io))?;
    out(&[Part::T(
        "  done     the witness store holds every record of its copies",
    )]);
    check_store(layout, &store).map_err(step)?;
    out(&[Part::T(
        "  done     checked the witness store: every record loads and every link recomputes",
    )]);
    crate::custodian::clear_host_loss(layout);
    Ok(())
}

/// The exit status of `fstp-backup witness-archive` when the object store
/// holds witness copies this host did not write.
pub const FOREIGN: i32 = 4;

/// `fstp-admin witness-copy` (ADR-028 record of lane `m10/witness-copy`):
/// one run of `fstp-backup witness-archive` over the witness store,
/// recorded in the witness copy status file for `status`. The timer
/// `fstp-admin-witness-copy` runs it every minute.
///
/// # Errors
///
/// [`crate::fail::Fail::Waits`] without backups, and
/// [`crate::fail::Fail::Refused`] when the run failed, after a line that
/// says what to do.
pub fn copy(layout: &Layout) -> Result<(), crate::fail::Fail> {
    use crate::fail::Fail;
    use crate::say::{Part, out};
    use fstp_obs::witness_copy;
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "the witness copy needs \"backup\" in the configuration file, then fstp-admin setup",
        ));
    }
    let store = layout.witness_store();
    let code = backup_tool(layout, &["witness-archive".as_ref(), store.as_os_str()]);
    let now = u64::try_from(crate::pki::now()).unwrap_or(0);
    let dir = layout.admin_dir();
    let before = witness_copy::read(&dir);
    let ok = matches!(code, Ok(Some(0)));
    let after = if ok {
        before.after_success(now)
    } else {
        before.after_failure(now)
    };
    if witness_copy::write(&dir, &after).is_err() {
        out(&[Part::T(
            "  The witness copy status file did not write, so status cannot show this run.",
        )]);
    }
    match code {
        Ok(Some(0)) => {
            out(&[Part::T(
                "  done     every whole witness record is in each object store",
            )]);
            Ok(())
        }
        Ok(Some(FOREIGN)) => {
            out(&[Part::T(
                "The object store holds witness copies that this host did not write, so nothing was copied. If this host replaces a lost one, run fstp-admin restore: it rebuilds the witness store from those copies first.",
            )]);
            Err(Fail::Refused("fstp-backup witness-archive", Some(FOREIGN)))
        }
        Ok(c) => {
            out(&[Part::T(
                "The witness records did not reach every object store. The cause is in admin/logs/fstp-admin.log, often the object store or its key files. The next run tries again within a minute.",
            )]);
            Err(Fail::Refused("fstp-backup witness-archive", c))
        }
        Err(_) => Err(Fail::Refused("fstp-backup witness-archive", None)),
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
