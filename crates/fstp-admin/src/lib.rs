//! `fstp-admin`: the one operator command of a host (ADR-028).
//!
//! One configuration file, `/etc/fstp/fstp.json`, and one command:
//!
//! ```text
//! fstp-admin setup                      set up or resume; safe to run again
//! fstp-admin status                     what runs, and the next thing to do
//! fstp-admin start | stop               every service, in order
//! fstp-admin renew                      certificates near their end, and the route pins
//! fstp-admin backup | restore           base backups of both databases
//! fstp-admin backup-keys <dir>          the off-host copy of the custody entries
//! fstp-admin verify [<account> [<file>]] record the admins' checked IDs
//! fstp-admin admins                   list the tenant admins' accounts
//! fstp-admin erase-identity <account>   erase an identity in the vault
//! fstp-admin route add <file> | remove <cell> | list
//! ```
//!
//! `--config <path>` or `FSTP_ADMIN_CONFIG` names another configuration
//! file. Exit codes: [`fail`].

pub mod cellcmd;
pub mod config;
pub mod fail;
pub mod layout;
pub mod ops;
pub mod pg;
pub mod pki;
pub mod render;
pub mod route;
pub mod say;
pub mod setup;
pub mod stack;
pub mod state;
pub mod status;
pub mod svc;
pub mod witness;

use std::path::{Path, PathBuf};

use crate::fail::{Fail, OK};
use crate::layout::Layout;
use crate::say::{Part, out};

/// The default configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/fstp/fstp.json";

/// Prints the command summary.
pub fn usage() {
    for line in [
        "Usage: fstp-admin [--config <file>] <command>",
        "",
        "  setup                      set up this host, or continue; safe to run again",
        "  status                     what runs, and the one next thing to do",
        "  start | stop               start or stop every service",
        "  renew                      renew certificates near their end and update the route",
        "  backup                     back up both databases now",
        "  restore                    restore both databases from their newest backups",
        "  backup-keys <dir>          copy the sealed keys off the host, for example to a USB stick",
        "  verify [<account> [<file>]] record that you checked an admin's ID in person",
        "  admins                     list the tenant admins' account ids (stops the cell briefly)",
        "  erase-identity <account>   erase one person's identity in the vault",
        "  route add <file> | route remove <cell id> | route list",
        "",
        "The configuration file is /etc/fstp/fstp.json unless --config or FSTP_ADMIN_CONFIG names another.",
    ] {
        say::err(&[Part::T(line)]);
    }
}

fn load(path: &Path) -> Result<Layout, Fail> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Err(Fail::NoConfig(path.to_owned())),
    };
    config::decode(&bytes)
        .map(Layout::new)
        .map_err(|e| Fail::Config(path.to_owned(), e))
}

/// Asks the four questions of a new host and writes the starter file.
fn ask_config(path: &Path) -> Result<(), Fail> {
    out(&[Part::T(
        "No configuration yet. Four questions, then setup starts.",
    )]);
    let domain = say::ask("1. The platform's domain, for example grants.example.eu: ")
        .ok_or_else(|| Fail::NoConfig(path.to_owned()))?;
    let email = say::ask("2. The first admin's email address: ")
        .ok_or_else(|| Fail::NoConfig(path.to_owned()))?;
    let relay = say::ask("3. The mail relay's host name, for example smtp.example.eu: ")
        .ok_or_else(|| Fail::NoConfig(path.to_owned()))?;
    let user = say::ask("4. The mail relay's user name: ")
        .ok_or_else(|| Fail::NoConfig(path.to_owned()))?;
    let text = config::starter(&domain, &email, &relay, &user);
    config::decode(text.as_bytes()).map_err(|e| Fail::Config(path.to_owned(), e))?;
    state::write_atomic(path, text.as_bytes(), 0o600)
        .map_err(|_| Fail::Missing(path.to_owned(), "a writable configuration directory"))?;
    out(&[
        Part::T("Wrote "),
        Part::P(path),
        Part::T(". Put the relay password in /etc/fstp/mail.password."),
    ]);
    Ok(())
}

fn verify(layout: &Layout, account: Option<&str>, file: Option<&str>) -> Result<(), Fail> {
    let mut st = state::State::load(&layout.admin_dir().join("state"))
        .map_err(|_| Fail::Step("verify", fail::Cause::Io))?;
    cellcmd::verify(layout, &mut st, account, file.map(Path::new))?;
    if cellcmd::verified_count(&st) >= 2 {
        st.mark("first-admin-verified")
            .map_err(|_| Fail::Step("verify", fail::Cause::Io))?;
        out(&[Part::T(
            "Both admins are verified. Next, on the web: the admins finish the checklist on Onboarding summary.",
        )]);
    }
    Ok(())
}

fn dispatch(config_path: &Path, args: &[String]) -> Result<u8, Fail> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if words.first() == Some(&"setup") && !config_path.exists() {
        ask_config(config_path)?;
    }
    let need = || load(config_path);
    match words.as_slice() {
        ["setup"] => setup::run(&need()?).map(|()| OK),
        ["status"] => Ok(status::run(&need()?)),
        ["start"] => ops::start(&need()?).map(|()| OK),
        ["stop"] => ops::stop(&need()?).map(|()| OK),
        ["renew"] => ops::renew(&need()?).map(|()| OK),
        ["backup"] => ops::backup(&need()?).map(|()| OK),
        ["restore"] => ops::restore(&need()?).map(|()| OK),
        ["backup-keys", dest] => {
            let l = need()?;
            let mut st = state::State::load(&l.admin_dir().join("state"))
                .map_err(|_| Fail::Step("key copy", fail::Cause::Io))?;
            ops::backup_keys(&l, &mut st, &PathBuf::from(dest)).map(|()| OK)
        }
        ["verify"] => verify(&need()?, None, None).map(|()| OK),
        ["verify", account] => verify(&need()?, Some(account), None).map(|()| OK),
        ["verify", account, file] => verify(&need()?, Some(account), Some(file)).map(|()| OK),
        ["admins"] => {
            let l = need()?;
            let mut st = state::State::load(&l.admin_dir().join("state"))
                .map_err(|_| Fail::Step("admins", fail::Cause::Io))?;
            for a in cellcmd::refresh_admins(&l, &mut st, true)? {
                out(&[Part::Name(&a)]);
            }
            Ok(OK)
        }
        ["erase-identity", account] => cellcmd::erase_identity(&need()?, account).map(|()| OK),
        ["route", "list"] => {
            let l = need()?;
            for r in route::list(&l)? {
                out(&[
                    Part::Name(&r.host),
                    Part::T("  cell "),
                    Part::Name(&r.cell),
                    Part::T("  app "),
                    Part::Name(&r.app),
                    Part::T("  vault "),
                    Part::Name(&r.vault),
                ]);
            }
            Ok(OK)
        }
        ["route", "add", file] => {
            let l = need()?;
            let m = svc::Manager::new(&l);
            for r in route::read_file(Path::new(file))? {
                route::add(&l, &m, &r)?;
                out(&[Part::T("  done     route of "), Part::Name(&r.host)]);
            }
            Ok(OK)
        }
        ["route", "remove", cell] => {
            let l = need()?;
            if cell.len() != 32 || !cell.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Fail::Usage);
            }
            let removed = route::remove(&l, &svc::Manager::new(&l), cell)?;
            out(&[Part::T(if removed {
                "  done     route removed"
            } else {
                "  skipped  no route of that cell"
            })]);
            Ok(OK)
        }
        _ => Err(Fail::Usage),
    }
}

/// Runs the command line `args` (without the program name) and returns
/// the exit code.
#[must_use]
pub fn main_with(args: &[String]) -> u8 {
    let (config_path, rest) = match args {
        [flag, path, rest @ ..] if flag == "--config" => (PathBuf::from(path), rest.to_vec()),
        rest => (
            std::env::var_os("FSTP_ADMIN_CONFIG")
                .map_or_else(|| PathBuf::from(DEFAULT_CONFIG), PathBuf::from),
            rest.to_vec(),
        ),
    };
    match dispatch(&config_path, &rest) {
        Ok(code) => code,
        Err(f) => {
            fail::report(&f);
            f.code()
        }
    }
}
