//! Host commands of the cell and the vault that `fstp-admin` wraps
//! (ADR-028 "First admin", "Erase an identity", "Verify the first
//! admins").
//!
//! Seams: `first-admin --email` is lane L12's form, and
//! `verify-first-admin` is lane L13b's. Where the installed binary
//! refuses the newer form as usage (status 2), the wrapper says so.

use std::path::Path;

use crate::fail::{Cause, Fail};
use crate::layout::Layout;
use crate::say::{Part, out};
use crate::stack;
use crate::svc::{Manager, RunFail, run_logged};

/// Runs `fstp-cell first-admin --email <email> <out>`. A cell without
/// lane L12 refuses `--email` with status 2; the plain form then runs,
/// and the admin hears that recovery by email waits for a second admin.
///
/// # Errors
///
/// [`Fail::Step`] when the command fails.
pub fn first_admin(layout: &Layout, email: &str, out_file: &Path) -> Result<(), Fail> {
    let log = Manager::new(layout).log();
    let run = |with_email: bool| -> Result<Option<i32>, Fail> {
        let mut c = stack::as_user(layout, stack::CELL_USER, &layout.bin("fstp-cell"));
        c.env("FSTP_CELL_CONFIG", layout.config_file("cell"))
            .arg("first-admin");
        if with_email {
            c.arg("--email").arg(email);
        }
        c.arg(out_file);
        run_logged(&mut c, &log).map_err(|e| Fail::Step("first admin", e.into()))
    };
    match run(true)? {
        Some(0) => Ok(()),
        Some(2) if !out_file.exists() => match run(false)? {
            Some(0) => {
                out(&[Part::T(
                    "  note     this cell has no first-admin --email yet: the first admin's recovery needs a second admin",
                )]);
                Ok(())
            }
            code => Err(Fail::Step(
                "first admin",
                Cause::Run(RunFail::Exit(layout.bin("fstp-cell"), code)),
            )),
        },
        code => Err(Fail::Step(
            "first admin",
            Cause::Run(RunFail::Exit(layout.bin("fstp-cell"), code)),
        )),
    }
}

/// Whether `account` reads as an account id: 32 lowercase hex digits, or
/// the UUID form.
#[must_use]
pub fn is_account(account: &str) -> bool {
    let plain: String = account.chars().filter(|c| *c != '-').collect();
    let dashes_ok = account.len() == 32
        || (account.len() == 36
            && account
                .char_indices()
                .all(|(i, c)| (c == '-') == matches!(i, 8 | 13 | 18 | 23)));
    dashes_ok
        && plain.len() == 32
        && plain
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stops the vault, runs `fstp-vault <args>`, and starts the vault
/// again, also when the command failed.
fn with_vault_stopped(
    layout: &Layout,
    step: &'static str,
    args: &[&std::ffi::OsStr],
) -> Result<(), Fail> {
    let m = Manager::new(layout);
    let vault = stack::vault(layout);
    m.stop(&vault).map_err(|e| Fail::Step(step, e.into()))?;
    let mut c = stack::as_user(layout, stack::VAULT_USER, &layout.bin("fstp-vault"));
    c.env("FSTP_VAULT_CONFIG", layout.config_file("vault"))
        .args(args);
    let code = run_logged(&mut c, &m.log());
    let restarted = m.ensure(&vault);
    let code = code.map_err(|e| Fail::Step(step, e.into()))?;
    restarted.map_err(|e| Fail::Step(step, e.into()))?;
    match code {
        Some(0) => Ok(()),
        code => Err(Fail::Refused(step, code)),
    }
}

/// `fstp-vault erase-identity <account>`, with the vault stopped.
///
/// # Errors
///
/// [`Fail::Usage`] for a malformed account, [`Fail::Refused`] when the
/// vault refuses.
pub fn erase_identity(layout: &Layout, account: &str) -> Result<(), Fail> {
    if !is_account(account) {
        return Err(Fail::Usage);
    }
    with_vault_stopped(
        layout,
        "fstp-vault erase-identity",
        &["erase-identity".as_ref(), account.as_ref()],
    )
}

/// The identity a technical admin checked in person: family names, given
/// names, date of birth and issuing state. Never printed or logged.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckedIdentity {
    /// Family names, as on the document.
    pub family_names: String,
    /// Given names, as on the document.
    pub given_names: String,
    /// Date of birth, `YYYY-MM-DD`.
    pub date_of_birth: String,
    /// The issuing state, two upper-case letters.
    pub issuing_state: String,
}

impl std::fmt::Debug for CheckedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckedIdentity(<redacted>)")
    }
}

impl CheckedIdentity {
    /// Whether every field has a plausible form.
    #[must_use]
    pub fn valid(&self) -> bool {
        let name = |s: &str| {
            !s.trim().is_empty() && s.chars().count() <= 200 && !s.chars().any(char::is_control)
        };
        let d = self.date_of_birth.as_bytes();
        name(&self.family_names)
            && name(&self.given_names)
            && d.len() == 10
            && d.iter().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    *b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
            && self.issuing_state.len() == 2
            && self.issuing_state.bytes().all(|b| b.is_ascii_uppercase())
    }

    /// The JSON the vault command reads.
    #[must_use]
    pub fn json(&self) -> String {
        use crate::config::quote;
        format!(
            "{{\"date_of_birth\":{},\"family_names\":{},\"given_names\":{},\"issuing_state\":{}}}\n",
            quote(&self.date_of_birth),
            quote(&self.family_names),
            quote(&self.given_names),
            quote(&self.issuing_state)
        )
    }
}

/// Reads a checked identity from a JSON file with the four members.
///
/// # Errors
///
/// [`Fail::Usage`] when a member is missing or malformed.
pub fn read_identity(path: &Path) -> Result<CheckedIdentity, Fail> {
    let bytes =
        std::fs::read(path).map_err(|_| Fail::Missing(path.to_owned(), "the identity file"))?;
    let v = fstp_json::parse(&bytes).map_err(|_| Fail::Usage)?;
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .ok_or(Fail::Usage)
    };
    let id = CheckedIdentity {
        family_names: s("family_names")?,
        given_names: s("given_names")?,
        date_of_birth: s("date_of_birth")?,
        issuing_state: s("issuing_state")?,
    };
    if id.valid() { Ok(id) } else { Err(Fail::Usage) }
}

/// Records that the technical admin verified the first admin `account`
/// in person (lane L13b, `fstp-vault verify-first-admin <account>
/// <identity file>`), with the vault stopped. The identity goes to the
/// vault through a root-only file that is deleted afterwards.
///
/// # Errors
///
/// [`Fail::Usage`] for a malformed account or identity, [`Fail::Waits`]
/// when the vault has no such command yet, [`Fail::Refused`] when it
/// refuses.
pub fn verify_first_admin(
    layout: &Layout,
    account: &str,
    id: &CheckedIdentity,
) -> Result<(), Fail> {
    if !is_account(account) || !id.valid() {
        return Err(Fail::Usage);
    }
    let dir = layout.admin_dir().join("verify");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("verify", Cause::Io))?;
    let file = dir.join("identity.json");
    crate::state::write_atomic(&file, id.json().as_bytes(), 0o600)
        .map_err(|_| Fail::Step("verify", Cause::Io))?;
    if layout.cfg.services == crate::config::Services::Systemd {
        let mut c = std::process::Command::new("chown");
        c.arg("-R")
            .arg(format!("{0}:{0}", stack::VAULT_USER))
            .arg(&dir);
        let _ = run_logged(&mut c, &Manager::new(layout).log());
    }
    let r = with_vault_stopped(
        layout,
        "fstp-vault verify-first-admin",
        &[
            "verify-first-admin".as_ref(),
            account.as_ref(),
            file.as_os_str(),
        ],
    );
    let _ = std::fs::remove_dir_all(&dir);
    match r {
        Err(Fail::Refused(_, Some(2))) => Err(Fail::Waits(
            "the installed fstp-vault has no verify-first-admin command (lane L13b), or it refused the input",
        )),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-004 record of lane L13: an account is 32 hex digits or a UUID.
    #[test]
    fn adr004_account_forms() {
        assert!(is_account("0123456789abcdef0123456789abcdef"));
        assert!(is_account("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(!is_account("01234567-89ab-cdef-0123-456789abcdeg"));
        assert!(!is_account("0123456789abcdef0123456789abcde-f"));
        assert!(!is_account("x"));
    }

    /// R-NF-02: a checked identity never shows in a debug print.
    #[test]
    fn r_nf_02_checked_identity_debug_is_redacted() {
        let id = CheckedIdentity {
            family_names: "Synthetic".into(),
            given_names: "Ada".into(),
            date_of_birth: "1990-01-31".into(),
            issuing_state: "DE".into(),
        };
        assert!(id.valid());
        assert!(!format!("{id:?}").contains("Synthetic"));
        assert!(fstp_json::parse(id.json().as_bytes()).is_ok());
    }
}
