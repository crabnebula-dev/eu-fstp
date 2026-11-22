//! Host commands of the cell and the vault that `fstp-admin` wraps
//! (ADR-028 "First admin", "Erase an identity", "Verify the first
//! admins").
//!
//! The cell commands are `first-admin --email` (lane L12) and `admins`
//! (lane L19); the vault commands are `verify-first-admin` (lane L13b)
//! and `erase-identity` (lane L13).

use std::path::Path;

use crate::fail::{Cause, Fail};
use crate::layout::Layout;
use crate::say::{self, Part, out};
use crate::stack;
use crate::state::State;
use crate::svc::{Manager, RunFail, run_logged};

/// Runs `fstp-cell first-admin --email <email> <out>` (ADR-026 "First
/// admin email").
///
/// # Errors
///
/// [`Fail::Step`] when the command fails.
pub fn first_admin(layout: &Layout, email: &str, out_file: &Path) -> Result<(), Fail> {
    let mut c = stack::as_user(layout, stack::CELL_USER, &layout.bin("fstp-cell"));
    c.env("FSTP_CELL_CONFIG", layout.config_file("cell"))
        .arg("first-admin")
        .arg("--email")
        .arg(email)
        .arg(out_file);
    match run_logged(&mut c, &Manager::new(layout).log())
        .map_err(|e| Fail::Step("first admin", e.into()))?
    {
        Some(0) => Ok(()),
        code => Err(Fail::Step(
            "first admin",
            Cause::Run(RunFail::Exit(layout.bin("fstp-cell"), code)),
        )),
    }
}

/// The tenant admins' accounts `fstp-admin` last read, in the form
/// `fstp-vault verify-first-admin` takes, the first admin first.
#[must_use]
pub fn cached_admins(state: &State) -> Vec<String> {
    state
        .get("admins")
        .map(|a| {
            a.split(',')
                .filter(|x| is_account(x))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Reads the tenant admins with `fstp-cell admins` and keeps them in the
/// admin state. The cell is stopped for it, since only one process may
/// open the ledger, and started again when `restart` is true.
///
/// # Errors
///
/// [`Fail::Step`] when the command fails or its file is malformed.
pub fn refresh_admins(
    layout: &Layout,
    state: &mut State,
    restart: bool,
) -> Result<Vec<String>, Fail> {
    let step = "list the admins";
    let m = Manager::new(layout);
    let cell = stack::cell(layout);
    m.stop(&cell).map_err(|e| Fail::Step(step, e.into()))?;
    let tmp = layout.admin_dir().join("admins");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|_| Fail::Step(step, Cause::Io))?;
    crate::setup::own_path(layout, &tmp, stack::CELL_USER).map_err(|c| Fail::Step(step, c))?;
    let file = tmp.join("admins");
    let mut c = stack::as_user(layout, stack::CELL_USER, &layout.bin("fstp-cell"));
    c.env("FSTP_CELL_CONFIG", layout.config_file("cell"))
        .arg("admins")
        .arg(&file);
    let code = run_logged(&mut c, &m.log());
    let text = std::fs::read_to_string(&file);
    let _ = std::fs::remove_dir_all(&tmp);
    if restart {
        m.ensure(&cell).map_err(|e| Fail::Step(step, e.into()))?;
    }
    match code.map_err(|e| Fail::Step(step, e.into()))? {
        Some(0) => {}
        Some(2) => return Err(Fail::Waits("the installed fstp-cell has no admins command")),
        code => {
            return Err(Fail::Step(
                step,
                Cause::Run(RunFail::Exit(layout.bin("fstp-cell"), code)),
            ));
        }
    }
    let text = text.map_err(|_| Fail::Step(step, Cause::Io))?;
    let list: Vec<String> = text
        .lines()
        .filter(|l| is_account(l))
        .map(str::to_owned)
        .collect();
    if !list.is_empty() {
        state
            .set("admins", &list.join(","))
            .map_err(|_| Fail::Step(step, Cause::Io))?;
    }
    Ok(list)
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
    )?;
    // ADR-028 record of lane L20: a key copy older than this erasure
    // holds the erased key, so `status` and the System page ask for a new
    // copy.
    let mut st = crate::state::State::load(&layout.admin_dir().join("state"))
        .map_err(|_| Fail::Step("erase identity", crate::fail::Cause::Io))?;
    st.set(
        crate::status::VAULT_ERASED_AT,
        &crate::pki::now().to_string(),
    )
    .map_err(|_| Fail::Step("erase identity", crate::fail::Cause::Io))
}

/// The kinds of identity document `fstp-vault verify-first-admin` takes.
pub const DOCUMENT_TYPES: [&str; 3] = ["passport", "identity_card", "residence_permit"];

/// The checks a technical admin confirms for an in-person verification.
pub const CHECKS: [&str; 3] = ["document_authentic", "document_valid", "photo_match"];

/// What the technical admin checked in person, in the file form of
/// `fstp-vault verify-first-admin` (ADR-008, lane L13b). Never printed or
/// logged, and the document number is never asked for.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckedIdentity {
    /// `passport`, `identity_card` or `residence_permit`.
    pub document_type: String,
    /// Family names, as on the document.
    pub family_names: String,
    /// Given names, as on the document.
    pub given_names: String,
    /// Date of birth, `YYYY-MM-DD`.
    pub birth_date: String,
    /// The issuing state, three upper-case letters.
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
        let d = self.birth_date.as_bytes();
        DOCUMENT_TYPES.contains(&self.document_type.as_str())
            && name(&self.family_names)
            && name(&self.given_names)
            && d.len() == 10
            && d.iter().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    *b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
            && self.issuing_state.len() == 3
            && self.issuing_state.bytes().all(|b| b.is_ascii_uppercase())
    }

    /// The file the vault command reads, with the three checks the admin
    /// confirmed.
    #[must_use]
    pub fn json(&self) -> String {
        use crate::config::quote;
        format!(
            "{{\"checks\":[\"{}\",\"{}\",\"{}\"],\"document_type\":{},\"identity\":{{\"birth_date\":{},\"family_names\":{},\"given_names\":{},\"issuing_state\":{}}},\"method\":\"manual\"}}\n",
            CHECKS[0],
            CHECKS[1],
            CHECKS[2],
            quote(&self.document_type),
            quote(&self.birth_date),
            quote(&self.family_names),
            quote(&self.given_names),
            quote(&self.issuing_state)
        )
    }
}

/// Records that the technical admin verified `account` in person, with
/// `fstp-vault verify-first-admin <account> <file>` (lane L13b), the vault
/// stopped. `file` is the vault's own file form; the identity reaches the
/// vault through a root-only copy that is deleted afterwards.
///
/// # Errors
///
/// [`Fail::Usage`] for a malformed account, [`Fail::Refused`] when the
/// vault refuses the file or the account.
pub fn verify_first_admin_file(layout: &Layout, account: &str, json: &[u8]) -> Result<(), Fail> {
    if !is_account(account) {
        return Err(Fail::Usage);
    }
    let dir = layout.admin_dir().join("verify");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("verify", Cause::Io))?;
    let file = dir.join("identity.json");
    crate::state::write_atomic(&file, json, 0o600).map_err(|_| Fail::Step("verify", Cause::Io))?;
    crate::setup::own_path(layout, &dir, stack::VAULT_USER).map_err(|c| Fail::Step("verify", c))?;
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
    r
}

/// Asks for one admin's checked identity.
///
/// # Errors
///
/// [`Fail::Usage`] when standard input closes or an answer is malformed.
pub fn ask_identity() -> Result<CheckedIdentity, Fail> {
    let q = |text: &'static str| say::ask(text).ok_or(Fail::Usage);
    out(&[Part::T(
        "Type the details exactly as on the ID document you checked in person. Never the document number.",
    )]);
    let document_type =
        match q("Document: 1 passport, 2 identity card, 3 residence permit: ")?.as_str() {
            "1" => "passport",
            "2" => "identity_card",
            "3" => "residence_permit",
            _ => return Err(Fail::Usage),
        };
    let id = CheckedIdentity {
        document_type: document_type.to_owned(),
        family_names: q("Family names: ")?,
        given_names: q("Given names: ")?,
        birth_date: q("Date of birth (YYYY-MM-DD): ")?,
        issuing_state: q("Issuing state, three letters (for example DEU): ")?.to_ascii_uppercase(),
    };
    let yes = q(
        "Did you check that the document is authentic, still valid, and that the photo matches the person? (yes/no): ",
    )?;
    if yes != "yes" || !id.valid() {
        return Err(Fail::Usage);
    }
    Ok(id)
}

/// `fstp-admin verify [<account> [<file>]]` (ADR-028 "Verify the first
/// admins"). With no account, it reads the current admins first and asks
/// for each one not verified yet. With a file, it passes the vault's own
/// file form through. Each success is kept in the admin state, so
/// `status` knows who is left.
///
/// # Errors
///
/// The first [`Fail`].
pub fn verify(
    layout: &Layout,
    state: &mut State,
    account: Option<&str>,
    file: Option<&Path>,
) -> Result<(), Fail> {
    let accounts = match account {
        Some(a) if is_account(a) => vec![a.to_owned()],
        Some(_) => return Err(Fail::Usage),
        None => refresh_admins(layout, state, true)?,
    };
    for a in accounts {
        if account.is_none() && state.done(&format!("verified.{a}")) {
            out(&[
                Part::T("  skipped  "),
                Part::Name(&a),
                Part::T(" (verified)"),
            ]);
            continue;
        }
        out(&[Part::T("Admin account "), Part::Name(&a)]);
        let json = match file {
            Some(f) => {
                std::fs::read(f).map_err(|_| Fail::Missing(f.to_owned(), "the identity file"))?
            }
            None => ask_identity()?.json().into_bytes(),
        };
        verify_first_admin_file(layout, &a, &json)?;
        state
            .mark(&format!("verified.{a}"))
            .map_err(|_| Fail::Step("verify", Cause::Io))?;
        out(&[Part::T("  done     verified "), Part::Name(&a)]);
    }
    Ok(())
}

/// How many of the cached admins are verified.
#[must_use]
pub fn verified_count(state: &State) -> usize {
    cached_admins(state)
        .iter()
        .filter(|a| state.done(&format!("verified.{a}")))
        .count()
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

    /// R-NF-02, ADR-008: a checked identity never shows in a debug print,
    /// and its file is the vault command's form, with no document number.
    #[test]
    fn r_nf_02_checked_identity_is_redacted_and_in_the_vault_form() {
        let id = CheckedIdentity {
            document_type: "passport".into(),
            family_names: "Synthetic".into(),
            given_names: "Ada".into(),
            birth_date: "1990-01-31".into(),
            issuing_state: "DEU".into(),
        };
        assert!(id.valid());
        assert!(!format!("{id:?}").contains("Synthetic"));
        let v = fstp_json::parse(id.json().as_bytes()).unwrap();
        assert_eq!(v.get("method").and_then(|m| m.as_str()), Some("manual"));
        assert_eq!(
            v.get("identity")
                .and_then(|i| i.get("issuing_state"))
                .and_then(|s| s.as_str()),
            Some("DEU")
        );
        let mut bad = id.clone();
        bad.issuing_state = "DE".into();
        assert!(!bad.valid());
    }
}
