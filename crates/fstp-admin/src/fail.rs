//! Why a command failed, what the admin should do about it, and the exit
//! code for scripts (ADR-028 "Exit codes").

use std::path::PathBuf;

use crate::config::{ConfigError, Problem};
use crate::pg::PgFail;
use crate::pki::PkiFail;
use crate::say::{Part, err};
use crate::svc::RunFail;
use crate::witness::WitnessFail;

/// Exit status: success.
pub const OK: u8 = 0;
/// Exit status: something failed that the admin can fix and retry.
pub const FAILED: u8 = 1;
/// Exit status: a refused configuration or argument.
pub const USAGE: u8 = 2;
/// Exit status: `status` found a problem.
pub const UNHEALTHY: u8 = 3;
/// Exit status: the step waits on a part that is not built yet.
pub const WAITS: u8 = 4;

/// Why a command failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The configuration file is wrong.
    Config(PathBuf, ConfigError),
    /// The configuration file does not exist and no answers were given.
    NoConfig(PathBuf),
    /// The command line is wrong.
    Usage,
    /// A file the admin supplies is missing: the path and what it is.
    Missing(PathBuf, &'static str),
    /// Systemd mode needs root.
    NotRoot,
    /// Direct mode needs `FSTP_DEPLOYMENT_MODE=development`.
    NotDevelopment,
    /// Direct mode needs the custody simulator.
    NoSimulator,
    /// A setup step failed: the step and the cause.
    Step(&'static str, Cause),
    /// A part that is not built yet: what it waits for.
    Waits(&'static str),
    /// A host command of a service refused: the command and its exit code.
    Refused(&'static str, Option<i32>),
}

/// The cause of a failed step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A command or service.
    Run(RunFail),
    /// The databases.
    Pg(PgFail),
    /// A certificate.
    Pki(PkiFail),
    /// The witness keys or registry.
    Witness(WitnessFail),
    /// A file.
    Io,
}

impl From<RunFail> for Cause {
    fn from(e: RunFail) -> Cause {
        Cause::Run(e)
    }
}
impl From<PgFail> for Cause {
    fn from(e: PgFail) -> Cause {
        Cause::Pg(e)
    }
}
impl From<PkiFail> for Cause {
    fn from(e: PkiFail) -> Cause {
        Cause::Pki(e)
    }
}
impl From<WitnessFail> for Cause {
    fn from(e: WitnessFail) -> Cause {
        Cause::Witness(e)
    }
}
impl From<std::io::Error> for Cause {
    fn from(_: std::io::Error) -> Cause {
        Cause::Io
    }
}

impl Fail {
    /// The exit code.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            Fail::Config(..) | Fail::NoConfig(_) | Fail::Usage => USAGE,
            Fail::Waits(_) => WAITS,
            _ => FAILED,
        }
    }
}

fn problem_text(p: Problem) -> (&'static str, &'static str) {
    match p {
        Problem::NotJson => (
            "is not a JSON object",
            "check the braces, quotes and commas; each member is \"name\": value",
        ),
        Problem::TooLong => ("is longer than 16 KiB", "remove what is not needed"),
        Problem::Missing => (
            "is missing",
            "add it; docs/guide/claude-connector-production.md shows an example",
        ),
        Problem::Unknown => (
            "is not a member fstp-admin knows",
            "check its spelling, or remove it",
        ),
        Problem::NotText => (
            "is not valid text",
            "write it as a quoted string of plain characters",
        ),
        Problem::NotNumber => (
            "is not a whole number in range",
            "write a number from 1 to 65535, without quotes",
        ),
        Problem::NotBool => (
            "is not true or false",
            "write true or false, without quotes",
        ),
        Problem::NotObject => (
            "is not an object",
            "write it as { ... } with its own members",
        ),
        Problem::BadHost => (
            "is not a lowercase host name",
            "write it like grants.example.eu",
        ),
        Problem::BadEmail => ("is not an email address", "write it like admin@example.eu"),
        Problem::NotAbsolute => (
            "is not an absolute path",
            "write a full path that starts with /",
        ),
        Problem::BadPort => (
            "is 0 or collides with the ports fstp-admin uses",
            "pick another port; ports.base takes the next 10 ports",
        ),
        Problem::BadAddress => ("is not an address and port", "write it like 192.0.2.7:465"),
        Problem::BadServices => (
            "is not systemd or direct",
            "write \"systemd\", or leave it out",
        ),
        Problem::SimulatorNeedsDirect => (
            "is only for a development machine",
            "remove it, or set \"services\": \"direct\" on a development machine",
        ),
        Problem::BadVersion => (
            "is not a version like 0.3.0",
            "write three numbers with dots",
        ),
        Problem::TlsNeedsBoth => (
            "needs both cert and key",
            "name the certificate chain and its key, or remove tls",
        ),
    }
}

fn cause_line(cause: &Cause) {
    match cause {
        Cause::Run(RunFail::Spawn(p)) => err(&[
            Part::T("  Could not start "),
            Part::P(p),
            Part::T(". Check that it is installed."),
        ]),
        Cause::Run(RunFail::Exit(p, code)) => err(&[
            Part::T("  "),
            Part::P(p),
            Part::T(" exited with status "),
            Part::N(code.map_or(0, |c| u64::from(c.unsigned_abs()))),
            Part::T(". Its messages are in the admin log, under the state directory: admin/logs."),
        ]),
        Cause::Run(RunFail::NotReady(name)) => err(&[
            Part::T("  The service "),
            Part::Name(name),
            Part::T(" did not get ready. See its log: journalctl -u "),
            Part::Name(name),
            Part::T(" (or admin/logs in direct mode)."),
        ]),
        Cause::Run(RunFail::Io) | Cause::Io => {
            err(&[Part::T(
                "  A file could not be read or written. Check the disk and the permissions.",
            )]);
        }
        Cause::Pg(PgFail::Sql(what)) => err(&[
            Part::T("  The database refused "),
            Part::T(what),
            Part::T(". Details are in admin/logs/fstp-admin.log."),
        ]),
        Cause::Pg(PgFail::Migration(c, v)) => err(&[
            Part::T("  Migration "),
            Part::N(u64::from(*v)),
            Part::T(" of the "),
            Part::T(c),
            Part::T(" database failed. Details are in admin/logs/fstp-admin.log."),
        ]),
        Cause::Pg(PgFail::Migrations(p)) => err(&[
            Part::T("  The migration files in "),
            Part::P(p),
            Part::T(" are missing or misnamed. Install them with the binaries."),
        ]),
        Cause::Pg(PgFail::Run(r)) => cause_line(&Cause::Run(r.clone())),
        Cause::Pg(PgFail::Job(word)) => err(&[
            Part::T("  fstp-pgagent run-job "),
            Part::T(word),
            Part::T(" failed. Details are in admin/logs/fstp-admin.log."),
        ]),
        Cause::Pg(PgFail::Pki(_)) | Cause::Pki(_) => {
            err(&[Part::T(
                "  A certificate could not be made. Check the CA files under the configuration directory: ca/.",
            )]);
        }
        Cause::Pg(PgFail::Io) => err(&[Part::T("  A database file could not be read or written.")]),
        Cause::Witness(WitnessFail::Keys(_)) => err(&[Part::T(
            "  fstp-witness init-keys failed. Is the witness's fstp-keyd entry running? See admin/logs/fstp-admin.log.",
        )]),
        Cause::Witness(WitnessFail::Register(_)) => err(&[Part::T(
            "  fstp-witness register failed. Is the witness stopped, and was the cell registered with other keys before?",
        )]),
        Cause::Witness(WitnessFail::Io) => err(&[Part::T(
            "  A witness or public key file could not be read or written.",
        )]),
    }
}

/// Tells the admin what failed and what to do.
pub fn report(f: &Fail) {
    match f {
        Fail::Config(path, e) => {
            let (what, fix) = problem_text(e.problem);
            err(&[
                Part::P(path),
                Part::T(": "),
                Part::Name(&e.field),
                Part::T(" "),
                Part::T(what),
                Part::T("."),
            ]);
            err(&[Part::T("Fix: "), Part::T(fix), Part::T(".")]);
        }
        Fail::NoConfig(path) => {
            err(&[
                Part::T("No configuration file at "),
                Part::P(path),
                Part::T("."),
            ]);
            err(&[Part::T(
                "Fix: run fstp-admin setup in a terminal and answer its questions, or write the file (see docs/guide/claude-connector-production.md).",
            )]);
        }
        Fail::Usage => crate::usage(),
        Fail::Missing(path, what) => {
            err(&[
                Part::T("Missing "),
                Part::T(what),
                Part::T(": "),
                Part::P(path),
            ]);
            err(&[Part::T(
                "Fix: put it there, then run the same command again.",
            )]);
        }
        Fail::NotRoot => err(&[Part::T("Run this as root, for example with sudo.")]),
        Fail::NotDevelopment => err(&[Part::T(
            "\"services\": \"direct\" is for a development machine only. Set FSTP_DEPLOYMENT_MODE=development, or use systemd.",
        )]),
        Fail::NoSimulator => err(&[Part::T(
            "Direct mode needs \"custody_simulator\": fstp-keyd serves fixed paths that need root and systemd.",
        )]),
        Fail::Step(step, cause) => {
            err(&[
                Part::T("Step \""),
                Part::T(step),
                Part::T(
                    "\" failed. Fix the cause below, then run fstp-admin setup again; it continues here.",
                ),
            ]);
            cause_line(cause);
        }
        Fail::Waits(what) => {
            err(&[Part::T("Not possible yet: "), Part::T(what), Part::T(".")]);
        }
        Fail::Refused(cmd, code) => {
            err(&[
                Part::T(cmd),
                Part::T(" refused with status "),
                Part::N(code.map_or(0, |c| u64::from(c.unsigned_abs()))),
                Part::T(
                    ". Status 2 means the argument was wrong. Details are in admin/logs/fstp-admin.log.",
                ),
            ]);
        }
    }
}
