//! The migration ledger and the forward-only consistency rules.
//!
//! The ledger is the table [`LEDGER_TABLE_NAME`] in a schema of its own,
//! [`DEFAULT_LEDGER_SCHEMA`](crate::DEFAULT_LEDGER_SCHEMA) unless the caller
//! configures another. The runner creates the schema and the table if they
//! are missing. The table holds one row per applied migration, written
//! in the same transaction as the migration.
//! [`check_ledger`] compares its rows with the embedded migrations. It is
//! a pure function, so the rules are testable without a server.

use std::fmt;

use fstp_pgwire::Timestamptz;

use crate::migration::CheckedMigration;

/// The ledger table's name within the ledger schema. Every runner
/// statement qualifies it with the schema, as
/// [`LedgerSchema`](crate::LedgerSchema) describes. A qualified name never
/// resolves through `search_path` and never to a temporary table, so
/// neither can redirect the ledger.
pub const LEDGER_TABLE_NAME: &str = "schema_migrations";

/// Most problems reported in one [`LedgerInconsistency`].
pub const MAX_REPORTED_PROBLEMS: usize = 32;

/// One row of the ledger, as read from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    /// The migration version.
    pub version: i64,
    /// The migration name.
    pub name: String,
    /// SHA-256 of the migration's SQL text when it was applied.
    pub checksum: Vec<u8>,
    /// The number of statements the migration had when it was applied.
    /// Informational only: it is not compared.
    pub statement_count: i32,
    /// When the applying transaction started.
    pub applied_at: Timestamptz,
}

/// One way in which the ledger contradicts the embedded migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerProblem {
    /// The database holds a version this binary does not know: the
    /// database is ahead of the binary.
    UnknownVersion {
        /// The unknown version.
        version: i64,
    },
    /// A version is missing while a later one is applied, so the applied
    /// versions are not a prefix of the embedded list.
    Missing {
        /// The missing version.
        version: u32,
    },
    /// A version below 1.
    InvalidVersion {
        /// The stored version.
        version: i64,
    },
    /// A version appears more than once.
    Duplicate {
        /// The repeated version.
        version: i64,
    },
    /// An applied migration has a different name in this binary.
    NameMismatch {
        /// The version.
        version: u32,
        /// The name in this binary.
        expected: String,
        /// The name in the ledger.
        found: String,
    },
    /// An applied migration's SQL text has changed since it was applied.
    ChecksumMismatch {
        /// The version.
        version: u32,
        /// The migration's name.
        name: String,
    },
}

impl fmt::Display for LedgerProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion { version } => write!(
                f,
                "version {version} is applied but unknown to this binary, so the database is \
                 ahead of it"
            ),
            Self::Missing { version } => write!(
                f,
                "version {version} is not applied although a later version is"
            ),
            Self::InvalidVersion { version } => write!(f, "invalid version {version}"),
            Self::Duplicate { version } => write!(f, "version {version} is recorded twice"),
            Self::NameMismatch {
                version,
                expected,
                found,
            } => write!(
                f,
                "version {version} was applied as {found:?} but is named {expected:?} here"
            ),
            Self::ChecksumMismatch { version, name } => write!(
                f,
                "version {version} ({name}) has changed since it was applied; migrations are \
                 forward-only, so add a new migration instead"
            ),
        }
    }
}

/// The problems [`check_ledger`] found. At most
/// [`MAX_REPORTED_PROBLEMS`] are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInconsistency {
    problems: Vec<LedgerProblem>,
    truncated: bool,
}

impl LedgerInconsistency {
    /// The problems, in version order.
    #[must_use]
    pub fn problems(&self) -> &[LedgerProblem] {
        &self.problems
    }

    /// True when more problems existed than were kept.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    fn push(&mut self, problem: LedgerProblem) {
        if self.problems.len() < MAX_REPORTED_PROBLEMS {
            self.problems.push(problem);
        } else {
            self.truncated = true;
        }
    }
}

impl fmt::Display for LedgerInconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the migration ledger does not match this binary")?;
        for (i, p) in self.problems.iter().enumerate() {
            f.write_str(if i == 0 { ": " } else { "; " })?;
            write!(f, "{p}")?;
        }
        if self.truncated {
            f.write_str("; and more")?;
        }
        Ok(())
    }
}

impl std::error::Error for LedgerInconsistency {}

/// Checks the ledger against the embedded migrations and returns the
/// number of applied migrations.
///
/// The ledger is consistent when its versions are exactly 1 to n for some
/// n no larger than the embedded list, and each row's name and checksum
/// equal those of the embedded migration with its version. The rows may
/// come in any order.
///
/// # Errors
///
/// Returns every problem found, up to [`MAX_REPORTED_PROBLEMS`]: unknown
/// versions (the database is ahead), versions missing before an applied
/// one (not a prefix), invalid or repeated versions, and changed names or
/// checksums.
pub fn check_ledger(
    migrations: &[CheckedMigration<'_>],
    rows: &[LedgerRow],
) -> Result<usize, LedgerInconsistency> {
    let mut sorted: Vec<&LedgerRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.version);
    let mut report = LedgerInconsistency {
        problems: Vec::new(),
        truncated: false,
    };
    let mut next: u32 = 1;
    let mut last: Option<i64> = None;
    for row in sorted {
        if last == Some(row.version) {
            report.push(LedgerProblem::Duplicate {
                version: row.version,
            });
            continue;
        }
        last = Some(row.version);
        if row.version < 1 {
            report.push(LedgerProblem::InvalidVersion {
                version: row.version,
            });
            continue;
        }
        let known = u32::try_from(row.version)
            .ok()
            .and_then(|v| Some((v, migrations.get(usize::try_from(v).ok()?.checked_sub(1)?)?)));
        let Some((version, migration)) = known else {
            report.push(LedgerProblem::UnknownVersion {
                version: row.version,
            });
            continue;
        };
        if version > next {
            report.push(LedgerProblem::Missing { version: next });
        }
        next = version.saturating_add(1);
        if row.name != migration.name() {
            report.push(LedgerProblem::NameMismatch {
                version,
                expected: migration.name().to_owned(),
                found: row.name.clone(),
            });
        }
        if row.checksum.as_slice() != migration.checksum().as_slice() {
            report.push(LedgerProblem::ChecksumMismatch {
                version,
                name: migration.name().to_owned(),
            });
        }
    }
    if report.problems.is_empty() && !report.truncated {
        Ok(rows.len())
    } else {
        Err(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{MigrationLimits, validate_entries};

    const LIST: [(u32, &str, &str); 3] = [
        (1, "one", "SELECT 1"),
        (2, "two", "SELECT 2"),
        (3, "three", "SELECT 3"),
    ];

    fn checked() -> Vec<CheckedMigration<'static>> {
        validate_entries(LIST, &MigrationLimits::default()).unwrap()
    }

    fn row(m: &CheckedMigration<'_>) -> LedgerRow {
        LedgerRow {
            version: i64::from(m.version()),
            name: m.name().to_owned(),
            checksum: m.checksum().to_vec(),
            statement_count: 1,
            applied_at: Timestamptz::from_unix_micros(0).unwrap(),
        }
    }

    fn problems(rows: &[LedgerRow]) -> Vec<LedgerProblem> {
        check_ledger(&checked(), rows)
            .unwrap_err()
            .problems()
            .to_vec()
    }

    #[test]
    fn prefixes_are_consistent() {
        let m = checked();
        assert_eq!(check_ledger(&m, &[]), Ok(0));
        assert_eq!(check_ledger(&m, &[row(&m[0])]), Ok(1));
        assert_eq!(check_ledger(&m, &[row(&m[1]), row(&m[0])]), Ok(2));
        assert_eq!(
            check_ledger(&m, &[row(&m[0]), row(&m[1]), row(&m[2])]),
            Ok(3)
        );
    }

    /// Forward-only (test plan, Database layer): a changed migration is refused.
    #[test]
    fn changed_checksum_is_refused() {
        let m = checked();
        let mut r = row(&m[0]);
        r.checksum[0] ^= 1;
        assert_eq!(
            problems(&[r, row(&m[1])]),
            vec![LedgerProblem::ChecksumMismatch {
                version: 1,
                name: "one".into()
            }]
        );
        let mut short = row(&m[0]);
        short.checksum.truncate(31);
        assert_eq!(problems(&[short]).len(), 1);
    }

    /// Forward-only (test plan, Database layer): a database ahead of the
    /// binary is refused.
    #[test]
    fn unknown_versions_are_refused() {
        let m = checked();
        let mut ahead = row(&m[2]);
        ahead.version = 4;
        assert_eq!(
            problems(&[row(&m[0]), row(&m[1]), row(&m[2]), ahead]),
            vec![LedgerProblem::UnknownVersion { version: 4 }]
        );
        let mut huge = row(&m[0]);
        huge.version = i64::MAX;
        assert_eq!(
            problems(&[huge]),
            vec![LedgerProblem::UnknownVersion { version: i64::MAX }]
        );
    }

    /// Forward-only (test plan, Database layer): applied versions must be a
    /// prefix of the embedded list.
    #[test]
    fn gaps_are_refused() {
        let m = checked();
        assert_eq!(
            problems(&[row(&m[0]), row(&m[2])]),
            vec![LedgerProblem::Missing { version: 2 }]
        );
        assert_eq!(
            problems(&[row(&m[1])]),
            vec![LedgerProblem::Missing { version: 1 }]
        );
    }

    #[test]
    fn invalid_duplicate_and_renamed_rows_are_refused() {
        let m = checked();
        let mut zero = row(&m[0]);
        zero.version = 0;
        let mut renamed = row(&m[0]);
        renamed.name = "uno".into();
        assert_eq!(
            problems(&[zero, row(&m[0]), row(&m[0]), renamed]),
            vec![
                LedgerProblem::InvalidVersion { version: 0 },
                LedgerProblem::Duplicate { version: 1 },
                LedgerProblem::Duplicate { version: 1 },
            ]
        );
        let mut renamed = row(&m[0]);
        renamed.name = "uno".into();
        assert_eq!(
            problems(&[renamed]),
            vec![LedgerProblem::NameMismatch {
                version: 1,
                expected: "one".into(),
                found: "uno".into()
            }]
        );
    }

    #[test]
    fn reports_are_capped() {
        let m = checked();
        let rows: Vec<LedgerRow> = (0..100)
            .map(|i| {
                let mut r = row(&m[0]);
                r.version = -i;
                r
            })
            .collect();
        let err = check_ledger(&m, &rows).unwrap_err();
        assert_eq!(err.problems().len(), MAX_REPORTED_PROBLEMS);
        assert!(err.truncated());
        assert!(err.to_string().ends_with("and more"));
    }
}
