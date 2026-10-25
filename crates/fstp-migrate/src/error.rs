//! The runner's error type.

use std::fmt;

use crate::ledger::LedgerInconsistency;

/// An error from [`MigrationSet::verify`](crate::MigrationSet::verify),
/// [`MigrationSet::plan`](crate::MigrationSet::plan) or
/// [`MigrationSet::apply`](crate::MigrationSet::apply).
///
/// Display and Debug output name versions, migration names, statement
/// numbers and lines. A server error shows as `fstp-pgwire` shows it: its
/// severity and SQLSTATE, plus table, column and constraint names when the
/// server supplies them. The server's message, detail, hint and context
/// can quote row values or SQL text, so they never appear there (R-NF-02).
/// [`Error::server_message`] and [`Error::pg_error`] reach them.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The connection is inside a transaction block. The runner controls
    /// transactions itself, so it needs an idle connection.
    TransactionOpen,
    /// A statement of the runner itself failed, or the connection broke.
    Database {
        /// What the runner was doing.
        context: &'static str,
        /// The client's error.
        source: fstp_pgwire::Error,
    },
    /// A runner query that always returns one row returned none. Only a
    /// misbehaving server or proxy gets here.
    NoRow {
        /// What the runner was doing.
        context: &'static str,
    },
    /// The ledger contradicts the embedded migrations. Nothing was applied
    /// in the transaction that found it.
    Inconsistent(LedgerInconsistency),
    /// The server's `standard_conforming_strings` setting is not `on`, or
    /// the connection does not report it. The statement splitter relies on
    /// it, so nothing was applied.
    StandardConformingStringsOff,
    /// A migration statement failed. The migration was rolled back and its
    /// version stays unapplied.
    Statement {
        /// The migration version.
        version: u32,
        /// The migration name.
        name: &'static str,
        /// The 1-based statement number within the migration.
        statement: usize,
        /// The 1-based line of the migration file where the statement starts.
        line: usize,
        /// The client's error, usually a server error with its SQLSTATE.
        source: fstp_pgwire::Error,
    },
    /// A migration statement cannot run inside a transaction block
    /// (SQLSTATE `25001`). Such statements are unsupported in M1. The
    /// migration was rolled back.
    NotTransactional {
        /// The migration version.
        version: u32,
        /// The migration name.
        name: &'static str,
        /// The 1-based statement number within the migration.
        statement: usize,
        /// The 1-based line of the migration file where the statement starts.
        line: usize,
        /// The server's error.
        source: fstp_pgwire::Error,
    },
    /// The commit of a migration failed, for example on a deferred
    /// constraint. The server rolled the migration back.
    Commit {
        /// The migration version.
        version: u32,
        /// The migration name.
        name: &'static str,
        /// The client's error.
        source: fstp_pgwire::Error,
    },
    /// A migration changed a session setting that the splitter or later
    /// migrations depend on, such as `search_path`. The migration was
    /// rolled back. Use `SET LOCAL` only for settings outside that list,
    /// or qualify names with their schema.
    SessionChanged {
        /// The migration version.
        version: u32,
        /// The migration name.
        name: &'static str,
        /// The setting that changed.
        setting: &'static str,
    },
}

impl Error {
    pub(crate) fn db(context: &'static str, source: fstp_pgwire::Error) -> Self {
        Self::Database { context, source }
    }

    /// The client error behind this error, if any.
    ///
    /// Its Display and Debug output follow R-NF-02 as this error's do.
    /// The accessors of its [`fstp_pgwire::DbError`] can return data
    /// values and SQL text.
    #[must_use]
    pub fn pg_error(&self) -> Option<&fstp_pgwire::Error> {
        match self {
            Self::Database { source, .. }
            | Self::Statement { source, .. }
            | Self::NotTransactional { source, .. }
            | Self::Commit { source, .. } => Some(source),
            Self::TransactionOpen
            | Self::NoRow { .. }
            | Self::Inconsistent(_)
            | Self::StandardConformingStringsOff
            | Self::SessionChanged { .. } => None,
        }
    }

    /// The SQLSTATE of the server error behind this error, if any.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.pg_error().and_then(fstp_pgwire::Error::code)
    }

    /// The primary message of the server error behind this error, if any.
    ///
    /// It can contain data values, such as the input that failed a cast,
    /// and SQL text near a syntax error. Display and Debug leave it out for
    /// that reason (R-NF-02). Do not write it to logs.
    #[must_use]
    pub fn server_message(&self) -> Option<&str> {
        self.pg_error()
            .and_then(fstp_pgwire::Error::as_db_error)
            .map(fstp_pgwire::DbError::message)
    }

    /// The ledger problems, when the ledger is inconsistent.
    #[must_use]
    pub fn inconsistency(&self) -> Option<&LedgerInconsistency> {
        match self {
            Self::Inconsistent(i) => Some(i),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionOpen => f.write_str(
                "the connection is inside a transaction; the migration runner needs an idle \
                 connection",
            ),
            Self::Database { context, source } => write!(f, "{context}: {source}"),
            Self::NoRow { context } => write!(f, "{context}: the server returned no row"),
            Self::Inconsistent(i) => write!(f, "{i}"),
            Self::StandardConformingStringsOff => f.write_str(
                "standard_conforming_strings is not reported as on; the statement splitter requires it",
            ),
            Self::Statement {
                version,
                name,
                statement,
                line,
                source,
            } => write!(
                f,
                "migration {version} ({name}), statement {statement} at line {line} failed \
                 and the migration was rolled back: {source}"
            ),
            Self::NotTransactional {
                version,
                name,
                statement,
                line,
                source,
            } => write!(
                f,
                "migration {version} ({name}), statement {statement} at line {line} cannot run \
                 inside a transaction block, which is not supported; the migration was rolled \
                 back: {source}"
            ),
            Self::Commit {
                version,
                name,
                source,
            } => write!(
                f,
                "migration {version} ({name}) failed at commit and was rolled back: {source}"
            ),
            Self::SessionChanged {
                version,
                name,
                setting,
            } => write!(
                f,
                "migration {version} ({name}) changed {setting}, which the runner and later \
                 migrations depend on; the migration was rolled back"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inconsistent(i) => Some(i),
            other => other
                .pg_error()
                .map(|e| e as &(dyn std::error::Error + 'static)),
        }
    }
}
