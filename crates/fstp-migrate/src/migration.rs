//! Embedded migrations and their validation.

use std::collections::HashMap;
use std::fmt;

use crate::lex::{Lexer, TokenKind, is_keyword};
use crate::split::{SplitError, SplitLimits, SqlStatement, split_statements};

/// One migration embedded in the binary: a version, a name and the SQL
/// text, usually from `include_str!`.
///
/// The SQL stays `&'static str` so that every statement split from it can
/// go to `fstp-pgwire`, which accepts only static SQL text.
///
/// ```
/// use fstp_migrate::Migration;
///
/// const MIGRATIONS: &[Migration] = &[
///     Migration::new(1, "create_notes", "CREATE TABLE notes (id bigint PRIMARY KEY);"),
///     // In a real crate: include_str!("../migrations/0002_add_body.sql")
///     Migration::new(2, "add_body", "ALTER TABLE notes ADD COLUMN body text;"),
/// ];
/// # assert!(fstp_migrate::MigrationSet::new(MIGRATIONS).is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Migration {
    /// The version. The list holds versions 1, 2, 3 and so on, in order.
    pub version: u32,
    /// The name: one or more of `a` to `z`, `0` to `9` and `_`.
    pub name: &'static str,
    /// The SQL text of the migration file.
    pub sql: &'static str,
}

impl Migration {
    /// A migration entry, usable in a `const` list.
    #[must_use]
    pub const fn new(version: u32, name: &'static str, sql: &'static str) -> Self {
        Self { version, name, sql }
    }
}

/// Limits for validating a migration list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MigrationLimits {
    /// Most migrations in one list. Default 10 000.
    pub max_migrations: usize,
    /// Longest migration name in bytes. Default 128.
    pub max_name_len: usize,
    /// Limits for splitting each migration file.
    pub split: SplitLimits,
}

impl Default for MigrationLimits {
    fn default() -> Self {
        Self {
            max_migrations: 10_000,
            max_name_len: 128,
            split: SplitLimits::default(),
        }
    }
}

/// A validated migration: its entry, the SHA-256 checksum of its SQL text
/// and its statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedMigration<'a> {
    version: u32,
    name: &'a str,
    sql: &'a str,
    checksum: [u8; 32],
    statements: Vec<SqlStatement<'a>>,
}

impl<'a> CheckedMigration<'a> {
    /// The version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The name.
    #[must_use]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The full SQL text.
    #[must_use]
    pub fn sql(&self) -> &'a str {
        self.sql
    }

    /// SHA-256 of the SQL text's bytes, which are the file's bytes when
    /// the text comes from `include_str!`. Line endings count, so the
    /// repository's `.gitattributes` keeps SQL files byte-exact
    /// (`*.sql -text`) in every checkout.
    #[must_use]
    pub fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }

    /// The statements, in file order. Never empty.
    #[must_use]
    pub fn statements(&self) -> &[SqlStatement<'a>] {
        &self.statements
    }
}

/// Why a statement is not allowed in a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementRule {
    /// Transaction control such as `COMMIT`, `ROLLBACK` or `SAVEPOINT`.
    /// The runner owns the transaction: a `COMMIT` inside a migration
    /// would commit part of it without its ledger row.
    TransactionControl,
    /// A statement PostgreSQL refuses to run inside a transaction block,
    /// such as `VACUUM` or `CREATE INDEX CONCURRENTLY`. Unsupported in M1.
    NotTransactional,
    /// The statement contains a NUL character, which the wire protocol
    /// cannot carry.
    NulCharacter,
    /// `COPY ... FROM STDIN` or `COPY ... TO STDOUT`, which need the COPY
    /// sub-protocol. `fstp-pgwire` does not support it and would break the
    /// connection.
    CopyProtocol,
    /// `DEALLOCATE` or `DISCARD`. They drop the prepared statements that
    /// the runner's connection caches, or other session state, and a
    /// rollback does not bring prepared statements back.
    SessionState,
}

impl fmt::Display for StatementRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TransactionControl => "transaction control is not allowed in a migration",
            Self::NotTransactional => {
                "statements that cannot run inside a transaction block are not supported"
            }
            Self::NulCharacter => "a NUL character cannot be sent to the server",
            Self::CopyProtocol => "COPY FROM STDIN and COPY TO STDOUT are not supported",
            Self::SessionState => {
                "DEALLOCATE and DISCARD would drop the runner's prepared statements"
            }
        })
    }
}

/// Why a migration list failed validation. Messages name versions,
/// migration names and positions, never SQL text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The list holds more than [`MigrationLimits::max_migrations`]
    /// entries.
    TooManyMigrations {
        /// The number of entries.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// A version appears twice.
    DuplicateVersion {
        /// The 0-based position of the second entry.
        position: usize,
        /// The repeated version.
        version: u32,
    },
    /// The versions are not 1, 2, 3 and so on in list order.
    VersionOutOfSequence {
        /// The 0-based position of the entry.
        position: usize,
        /// The version expected at that position.
        expected: u32,
        /// The version found.
        found: u32,
    },
    /// A name is empty, too long, or has a character outside `[a-z0-9_]`.
    InvalidName {
        /// The version of the entry.
        version: u32,
    },
    /// Two entries share a name.
    DuplicateName {
        /// The version of the second entry.
        version: u32,
        /// The version of the first entry with that name.
        first: u32,
    },
    /// The SQL text cannot be split into statements.
    Split {
        /// The version of the entry.
        version: u32,
        /// The splitter's error.
        error: SplitError,
    },
    /// The SQL text holds no statement, only whitespace and comments.
    Empty {
        /// The version of the entry.
        version: u32,
    },
    /// A statement breaks a [`StatementRule`].
    Statement {
        /// The version of the entry.
        version: u32,
        /// The 1-based statement number within the migration.
        statement: usize,
        /// The 1-based line where the statement starts.
        line: usize,
        /// The rule it breaks.
        rule: StatementRule,
    },
}

impl ValidationError {
    /// The version of the entry the error is about, or `None` when the
    /// error is about the list as a whole or its sequence of versions.
    #[must_use]
    pub fn version(&self) -> Option<u32> {
        match self {
            Self::TooManyMigrations { .. }
            | Self::DuplicateVersion { .. }
            | Self::VersionOutOfSequence { .. } => None,
            Self::InvalidName { version }
            | Self::DuplicateName { version, .. }
            | Self::Split { version, .. }
            | Self::Empty { version }
            | Self::Statement { version, .. } => Some(*version),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyMigrations { count, limit } => {
                write!(f, "{count} migrations exceed the limit of {limit}")
            }
            Self::DuplicateVersion { position, version } => {
                write!(f, "version {version} appears again at position {position}")
            }
            Self::VersionOutOfSequence {
                position,
                expected,
                found,
            } => write!(
                f,
                "position {position} holds version {found}, but versions must run 1, 2, 3 \
                 in order, so {expected} was expected"
            ),
            Self::InvalidName { version } => write!(
                f,
                "migration {version} has an invalid name; use one or more of a-z, 0-9 and _"
            ),
            Self::DuplicateName { version, first } => {
                write!(
                    f,
                    "migration {version} repeats the name of migration {first}"
                )
            }
            Self::Split { version, error } => write!(f, "migration {version}: {error}"),
            Self::Empty { version } => write!(f, "migration {version} holds no statement"),
            Self::Statement {
                version,
                statement,
                line,
                rule,
            } => write!(
                f,
                "migration {version}, statement {statement} at line {line}: {rule}"
            ),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Split { error, .. } => Some(error),
            _ => None,
        }
    }
}

fn valid_name(name: &str, max_len: usize) -> bool {
    !name.is_empty()
        && name.len() <= max_len
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Checks one statement against the [`StatementRule`]s.
///
/// The leading keywords decide transaction control and most statements
/// that cannot run in a transaction block. The keyword `CONCURRENTLY`
/// anywhere outside strings, quoted identifiers and comments marks the
/// rest, except in `REFRESH MATERIALIZED VIEW CONCURRENTLY`, which does
/// run in a transaction. The server remains the final check: it rejects
/// any other such statement with SQLSTATE `25001`, and the runner then
/// rolls the migration back. A `COPY` statement that names `STDIN` or
/// `STDOUT` needs the COPY sub-protocol. `DEALLOCATE` and `DISCARD` in
/// any form break the session state of the runner's connection.
pub(crate) fn statement_rule(stmt: &str, max_comment_depth: usize) -> Option<StatementRule> {
    if stmt.contains('\0') {
        return Some(StatementRule::NulCharacter);
    }
    let src = stmt.as_bytes();
    let mut lexer = Lexer::new(src, max_comment_depth);
    let mut lead: [Option<&[u8]>; 2] = [None, None];
    let mut seen = 0usize;
    let mut concurrently = false;
    let mut stream = false;
    // The statement came out of the splitter, so it scans cleanly; an
    // error would only end the scan early.
    while let Ok(Some(token)) = lexer.next_token() {
        let word = (token.kind == TokenKind::Word)
            .then(|| src.get(token.start..token.end))
            .flatten();
        if let Some(slot) = lead.get_mut(seen) {
            *slot = word;
        }
        seen = seen.saturating_add(1);
        if let Some(w) = word {
            concurrently |= is_keyword(w, "CONCURRENTLY");
            stream |= is_keyword(w, "STDIN") || is_keyword(w, "STDOUT");
        }
    }
    let [w0, w1] = lead;
    let first = |k: &str| w0.is_some_and(|w| is_keyword(w, k));
    let second = |k: &str| w1.is_some_and(|w| is_keyword(w, k));
    let transaction_control = [
        "BEGIN",
        "START",
        "COMMIT",
        "END",
        "ROLLBACK",
        "ABORT",
        "SAVEPOINT",
        "RELEASE",
    ]
    .iter()
    .any(|k| first(k))
        || (first("PREPARE") && second("TRANSACTION"));
    if transaction_control {
        return Some(StatementRule::TransactionControl);
    }
    if first("COPY") && stream {
        return Some(StatementRule::CopyProtocol);
    }
    if first("DEALLOCATE") || first("DISCARD") {
        return Some(StatementRule::SessionState);
    }
    let not_transactional = first("VACUUM")
        || ((first("CREATE") || first("DROP")) && (second("DATABASE") || second("TABLESPACE")))
        || (first("ALTER") && second("SYSTEM"))
        || (concurrently && !first("REFRESH"));
    not_transactional.then_some(StatementRule::NotTransactional)
}

/// Validates a migration list and splits each migration into statements.
///
/// Checks, in list order:
///
/// - at most [`MigrationLimits::max_migrations`] entries;
/// - versions run 1, 2, 3 and so on in list order, so they are
///   contiguous from 1 and unique;
/// - names are 1 to [`MigrationLimits::max_name_len`] bytes of `a` to
///   `z`, `0` to `9` and `_`, and unique;
/// - each SQL text splits into at least one statement, and no statement
///   breaks a [`StatementRule`].
///
/// [`MigrationSet::new`](crate::MigrationSet::new) calls this for the
/// embedded list. It is public so that tests and fuzz targets can feed it
/// borrowed data.
///
/// # Errors
///
/// Returns the first problem found as a [`ValidationError`].
pub fn validate_entries<'a, I>(
    entries: I,
    limits: &MigrationLimits,
) -> Result<Vec<CheckedMigration<'a>>, ValidationError>
where
    I: IntoIterator<Item = (u32, &'a str, &'a str)>,
    I::IntoIter: ExactSizeIterator,
{
    let entries = entries.into_iter();
    let count = entries.len();
    if count > limits.max_migrations {
        return Err(ValidationError::TooManyMigrations {
            count,
            limit: limits.max_migrations,
        });
    }
    let mut out: Vec<CheckedMigration<'a>> = Vec::with_capacity(count);
    let mut names: HashMap<&'a str, u32> = HashMap::with_capacity(count);
    for (position, (version, name, sql)) in entries.enumerate() {
        let expected = u32::try_from(position)
            .ok()
            .and_then(|p| p.checked_add(1))
            .ok_or(ValidationError::TooManyMigrations {
                count,
                limit: limits.max_migrations,
            })?;
        if version != expected {
            if version != 0 && version < expected {
                return Err(ValidationError::DuplicateVersion { position, version });
            }
            return Err(ValidationError::VersionOutOfSequence {
                position,
                expected,
                found: version,
            });
        }
        if !valid_name(name, limits.max_name_len) {
            return Err(ValidationError::InvalidName { version });
        }
        if let Some(&first) = names.get(name) {
            return Err(ValidationError::DuplicateName { version, first });
        }
        names.insert(name, version);
        let statements = split_statements(sql, &limits.split)
            .map_err(|error| ValidationError::Split { version, error })?;
        if statements.is_empty() {
            return Err(ValidationError::Empty { version });
        }
        for (i, stmt) in statements.iter().enumerate() {
            if let Some(rule) = statement_rule(stmt.text(), limits.split.max_comment_depth) {
                return Err(ValidationError::Statement {
                    version,
                    statement: i.saturating_add(1),
                    line: stmt.line(),
                    rule,
                });
            }
        }
        out.push(CheckedMigration {
            version,
            name,
            sql,
            checksum: fstp_crypto::sha256(sql.as_bytes()),
            statements,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(list: &[(u32, &'static str, &'static str)]) -> Result<usize, ValidationError> {
        validate_entries(list.iter().copied(), &MigrationLimits::default()).map(|v| v.len())
    }

    #[test]
    fn a_valid_list_is_split_and_checksummed() {
        let list = [
            (1, "create_t", "CREATE TABLE t (id int); -- note\n"),
            (
                2,
                "fill_t_2",
                "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2);",
            ),
        ];
        let checked = validate_entries(list.iter().copied(), &MigrationLimits::default()).unwrap();
        assert_eq!(checked.len(), 2);
        assert_eq!(checked[0].statements().len(), 1);
        assert_eq!(checked[1].statements().len(), 2);
        assert_eq!(
            checked[0].checksum(),
            &fstp_crypto::sha256(b"CREATE TABLE t (id int); -- note\n")
        );
        assert_eq!(checked[1].name(), "fill_t_2");
        assert_eq!(validate(&[]), Ok(0));
    }

    #[test]
    fn versions_must_run_from_one_without_gaps_or_duplicates() {
        assert_eq!(
            validate(&[(2, "a", "SELECT 1")]),
            Err(ValidationError::VersionOutOfSequence {
                position: 0,
                expected: 1,
                found: 2
            })
        );
        assert_eq!(
            validate(&[(0, "a", "SELECT 1")]),
            Err(ValidationError::VersionOutOfSequence {
                position: 0,
                expected: 1,
                found: 0
            })
        );
        assert_eq!(
            validate(&[(1, "a", "SELECT 1"), (1, "b", "SELECT 1")]),
            Err(ValidationError::DuplicateVersion {
                position: 1,
                version: 1
            })
        );
        assert_eq!(
            validate(&[(1, "a", "SELECT 1"), (3, "b", "SELECT 1")]),
            Err(ValidationError::VersionOutOfSequence {
                position: 1,
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn names_must_be_lowercase_snake_case_and_unique() {
        for bad in ["", "Upper", "with-dash", "space here", "ünï", "dot.sql"] {
            assert_eq!(
                validate(&[(1, bad, "SELECT 1")]),
                Err(ValidationError::InvalidName { version: 1 }),
                "{bad:?}"
            );
        }
        let long: &'static str = Box::leak("a".repeat(129).into_boxed_str());
        assert_eq!(
            validate(&[(1, long, "SELECT 1")]),
            Err(ValidationError::InvalidName { version: 1 })
        );
        assert_eq!(
            validate(&[(1, "same", "SELECT 1"), (2, "same", "SELECT 2")]),
            Err(ValidationError::DuplicateName {
                version: 2,
                first: 1
            })
        );
    }

    #[test]
    fn empty_and_unsplittable_migrations_are_rejected() {
        assert_eq!(
            validate(&[(1, "a", "-- nothing here\n;")]),
            Err(ValidationError::Empty { version: 1 })
        );
        assert!(matches!(
            validate(&[(1, "a", "SELECT 'oops")]),
            Err(ValidationError::Split { version: 1, .. })
        ));
    }

    #[test]
    fn transaction_control_is_rejected() {
        for sql in [
            "BEGIN",
            "begin transaction",
            "START TRANSACTION",
            "COMMIT",
            "end",
            "ROLLBACK",
            "rollback to savepoint s",
            "ABORT",
            "SAVEPOINT s",
            "RELEASE SAVEPOINT s",
            "PREPARE TRANSACTION 'x'",
            "COMMIT PREPARED 'x'",
            "/* c */ commit",
        ] {
            let text: &'static str = Box::leak(format!("SELECT 1;\n{sql};").into_boxed_str());
            let list = [(1, "a", "SELECT 1;"), (2, "b", text)];
            assert_eq!(
                validate(&list),
                Err(ValidationError::Statement {
                    version: 2,
                    statement: 2,
                    line: 2,
                    rule: StatementRule::TransactionControl
                }),
                "{sql}"
            );
        }
    }

    #[test]
    fn statements_that_cannot_run_in_a_transaction_are_rejected() {
        for sql in [
            "VACUUM t",
            "CREATE INDEX CONCURRENTLY i ON t (a)",
            "create unique index concurrently i on t (a)",
            "DROP INDEX CONCURRENTLY i",
            "REINDEX (CONCURRENTLY) TABLE t",
            "ALTER TABLE t DETACH PARTITION p CONCURRENTLY",
            "CREATE DATABASE d",
            "DROP DATABASE d",
            "CREATE TABLESPACE s LOCATION '/x'",
            "DROP TABLESPACE s",
            "ALTER SYSTEM SET work_mem = '1MB'",
        ] {
            let text: &'static str = Box::leak(sql.to_owned().into_boxed_str());
            assert!(
                matches!(
                    validate(&[(1, "a", text)]),
                    Err(ValidationError::Statement {
                        rule: StatementRule::NotTransactional,
                        ..
                    })
                ),
                "{sql}"
            );
        }
    }

    #[test]
    fn look_alikes_are_allowed() {
        for sql in [
            "REFRESH MATERIALIZED VIEW CONCURRENTLY v",
            "SELECT 'COMMIT; VACUUM'",
            "CREATE TABLE \"commit\" (\"concurrently\" int)",
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN COMMIT; END $$",
            "CREATE FUNCTION g() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END",
            "SELECT 'DISCARD ALL', \"deallocate\" FROM t",
            "ALTER DATABASE d SET work_mem = '1MB'",
            "PREPARE q AS SELECT 1",
            "CREATE INDEX i ON t (a)",
        ] {
            let text: &'static str = Box::leak(sql.to_owned().into_boxed_str());
            assert_eq!(validate(&[(1, "a", text)]), Ok(1), "{sql}");
        }
    }

    #[test]
    fn copy_streams_are_rejected_and_server_side_copy_is_allowed() {
        for (sql, rejected) in [
            ("COPY t FROM STDIN", true),
            ("copy (SELECT 1) TO stdout WITH (FORMAT csv)", true),
            ("COPY t FROM '/srv/data.csv'", false),
            ("SELECT 'COPY t FROM STDIN'", false),
        ] {
            let text: &'static str = Box::leak(sql.to_owned().into_boxed_str());
            let got = validate(&[(1, "a", text)]);
            if rejected {
                assert!(
                    matches!(
                        got,
                        Err(ValidationError::Statement {
                            rule: StatementRule::CopyProtocol,
                            ..
                        })
                    ),
                    "{sql}"
                );
            } else {
                assert_eq!(got, Ok(1), "{sql}");
            }
        }
    }

    /// `DEALLOCATE ALL` in a migration drops the prepared statements
    /// that `fstp-pgwire` caches for the runner, and `ROLLBACK` does not
    /// restore them. `DISCARD` drops them or other session state.
    #[test]
    fn deallocate_and_discard_are_rejected() {
        for sql in [
            "DEALLOCATE ALL",
            "deallocate prepare all",
            "DEALLOCATE fstp_1",
            "DISCARD ALL",
            "discard plans",
            "DISCARD SEQUENCES",
            "DISCARD TEMP",
            "DISCARD TEMPORARY",
            "/* c */ Deallocate q",
        ] {
            let text: &'static str = Box::leak(format!("SELECT 1;\n{sql};").into_boxed_str());
            assert_eq!(
                validate(&[(1, "a", text)]),
                Err(ValidationError::Statement {
                    version: 1,
                    statement: 2,
                    line: 2,
                    rule: StatementRule::SessionState
                }),
                "{sql}"
            );
        }
    }

    /// Review finding `checksum-line-endings`. The checksum covers the raw
    /// file bytes, so a checkout that turned LF into CRLF would compute
    /// other checksums and refuse every migrated database. The repository's
    /// `.gitattributes` keeps SQL files byte-exact, and the fixtures hold
    /// no carriage return.
    #[test]
    fn review_checksum_line_endings() {
        let checksum = |sql: &'static str| {
            let checked = validate_entries([(1, "a", sql)], &MigrationLimits::default()).unwrap();
            *checked[0].checksum()
        };
        assert_ne!(checksum("SELECT 1;\n"), checksum("SELECT 1;\r\n"));

        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let attributes = std::fs::read_to_string(format!("{root}/.gitattributes")).unwrap();
        assert!(
            attributes.lines().any(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("*.sql") && words.any(|w| w == "-text")
            }),
            "{attributes}"
        );
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/migrations");
        for dir in std::fs::read_dir(fixtures).unwrap() {
            for file in std::fs::read_dir(dir.unwrap().path()).unwrap() {
                let path = file.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                assert!(!bytes.contains(&b'\r'), "{}", path.display());
            }
        }
    }

    #[test]
    fn nul_characters_are_rejected() {
        assert!(matches!(
            validate(&[(1, "a", "SELECT '\0'")]),
            Err(ValidationError::Statement {
                rule: StatementRule::NulCharacter,
                ..
            })
        ));
    }

    #[test]
    fn the_list_size_is_limited() {
        let limits = MigrationLimits {
            max_migrations: 1,
            ..MigrationLimits::default()
        };
        let list = [(1, "a", "SELECT 1"), (2, "b", "SELECT 2")];
        assert_eq!(
            validate_entries(list.iter().copied(), &limits),
            Err(ValidationError::TooManyMigrations { count: 2, limit: 1 })
        );
    }
}
