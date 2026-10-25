//! Forward-only, checksummed PostgreSQL migration runner.
//!
//! This is the migration component of the build approach in
//! `SPEC/03-architecture/overview.md`. It serves the "Database" layer of
//! `SPEC/07-test-plan/test-plan.md` (migrations forward-only) and R-NF-06:
//! security updates apply without data migration loss, because every
//! migration either applies completely or not at all.
//!
//! # Embedding migrations
//!
//! Migrations are SQL files compiled into the binary with `include_str!`,
//! listed in a `const` slice of [`Migration`] entries. The SQL stays
//! `&'static str`, which `fstp-pgwire` requires of all SQL text.
//!
//! ```
//! use fstp_migrate::{Migration, MigrationSet};
//!
//! // Real code writes include_str!("../migrations/0001_create_tenants.sql")
//! // in place of each literal.
//! const MIGRATIONS: &[Migration] = &[
//!     Migration::new(1, "create_tenants", "CREATE TABLE tenants (id bigint PRIMARY KEY);"),
//!     Migration::new(2, "add_tenant_locale", "ALTER TABLE tenants ADD COLUMN locale text;"),
//! ];
//!
//! let set = MigrationSet::new(MIGRATIONS).expect("the list is valid");
//! # let _ = set;
//! ```
//!
//! [`MigrationSet::new`] validates the list at startup: versions run 1, 2,
//! 3 and so on in order, names match `[a-z0-9_]+` and are unique, every
//! file splits into at least one statement, and no statement breaks a
//! [`StatementRule`]. Each migration's checksum is the SHA-256 of its file
//! bytes, computed with `fstp-crypto`. The bytes include line endings, so
//! the repository's `.gitattributes` stops Git from converting them in SQL
//! files.
//!
//! # Running
//!
//! - [`MigrationSet::verify`] checks the ledger without changing anything.
//! - [`MigrationSet::plan`] lists the migrations that would run.
//! - [`MigrationSet::apply`] runs them.
//!
//! The ledger lives in the schema `fstp_migrate` unless the caller names
//! another:
//!
//! ```
//! use fstp_migrate::{LedgerSchema, Migration, MigrationSet};
//!
//! const MIGRATIONS: &[Migration] = &[Migration::new(1, "create_t", "CREATE TABLE t (id int);")];
//!
//! let ledger = LedgerSchema::new("app_ledger").expect("a plain lowercase identifier");
//! let set = MigrationSet::new(MIGRATIONS)
//!     .expect("the list is valid")
//!     .with_ledger_schema(ledger);
//! assert_eq!(set.ledger_schema().as_str(), "app_ledger");
//! assert!(LedgerSchema::new("app\"; DROP SCHEMA public; --").is_err());
//! ```
//!
//! The runner works over the [`Database`] trait. [`fstp_pgwire::Client`]
//! and [`fstp_pgwire::Session`] both implement it.
//!
//! Each migration runs in one transaction together with its row in the
//! ledger table. A transaction-scoped advisory lock
//! ([`ADVISORY_LOCK_KEY`]) and a reread of the ledger under that lock make
//! concurrent runners apply each migration exactly once.
//!
//! # Forward-only rules
//!
//! There is no down-migration API. The runner refuses to apply anything,
//! and [`MigrationSet::verify`] fails, when the ledger shows that:
//!
//! - an applied migration's checksum or name differs from the binary's;
//! - the database holds a version the binary does not know, so the
//!   database is ahead of the binary;
//! - the applied versions are not a prefix of the embedded list.
//!
//! A changed migration therefore needs a new migration that corrects it.
//!
//! # The ledger
//!
//! | Column | Type | Content |
//! | --- | --- | --- |
//! | `version` | `bigint` primary key | The migration version |
//! | `name` | `text` | The migration name |
//! | `checksum` | `bytea` | SHA-256 of the file bytes, 32 bytes |
//! | `applied_at` | `timestamptz` | Start of the applying transaction |
//! | `statement_count` | `integer` | Statements in the file, informational |
//!
//! The table is [`LEDGER_TABLE_NAME`] in the ledger schema, which is
//! [`DEFAULT_LEDGER_SCHEMA`] unless [`MigrationSet::with_ledger_schema`]
//! names another [`LedgerSchema`]. The name is a plain lowercase
//! identifier that [`LedgerSchema::new`] validates.
//!
//! [`MigrationSet::apply`] creates the schema if it is missing, owned by
//! the migrating role (`current_user`), and then the table. Every runner
//! method refuses an existing schema of that name that another role
//! owns, with [`Error::LedgerSchemaOwner`], because that role could change
//! the ledger.
//!
//! Every runner statement names the table qualified with the ledger
//! schema. Neither a different `search_path` nor a temporary table with
//! the same name can therefore redirect it. The runner's statements also
//! qualify types, functions and operators with `pg_catalog`.
//!
//! SQL text stays `&'static str`, so the schema name never enters it on
//! the client. The runner sends the name as a bind parameter. Where a
//! statement needs it as an identifier, a `DO` block quotes it on the
//! server with `format('%I', ...)`, after checking it against the same
//! rules as [`LedgerSchema::new`].
//!
//! # Session settings
//!
//! The runner refuses a migration that changes `search_path`,
//! `standard_conforming_strings`, `current_user` or `session_user`, even
//! with `SET LOCAL`, and rolls it back. A plain `SET` would carry over
//! into the later migrations of the same run, which a fresh session would
//! not see.
//!
//! The splitter reads every statement with `standard_conforming_strings`
//! on. The runner therefore checks the value that the server reports
//! after every statement, and stops before the next statement runs.
//!
//! # Unsupported in M1
//!
//! - Statements that cannot run inside a transaction block, such as
//!   `VACUUM`, `CREATE INDEX CONCURRENTLY`, `CREATE DATABASE` or
//!   `ALTER SYSTEM`. Validation rejects the common ones by their keywords.
//!   The server rejects the rest with SQLSTATE `25001`, which the runner
//!   reports as [`Error::NotTransactional`] after rolling back.
//! - Transaction control inside a migration (`BEGIN`, `COMMIT`,
//!   `ROLLBACK`, `SAVEPOINT` and the like). Validation rejects it, since
//!   the runner owns the transaction.
//! - `COPY ... FROM STDIN` and `COPY ... TO STDOUT`, whose sub-protocol
//!   `fstp-pgwire` does not support. Validation rejects them.
//! - `DEALLOCATE` and `DISCARD`, which drop the prepared statements and
//!   other session state of the runner's connection. Validation rejects
//!   them.
//! - Servers with `standard_conforming_strings = off`.
//!
//! # Statement splitting
//!
//! [`split_statements`] cuts a file into statements with the lexical rules
//! of the server's scanner. See the [`split`] module for the details. For
//! valid SQL it agrees with the server. For invalid SQL, the statement
//! that holds the first invalid token fails at the server, so the whole
//! migration rolls back.
//!
//! # Fuzzing
//!
//! The fuzz project in `fuzz/` covers the splitter (`sql_split`) and list
//! validation (`migration_list_validate`) (TH-26, H-05).
//!
//! # Logging
//!
//! The crate logs nothing. The Display and Debug output of its errors
//! shows versions, migration names, statement numbers, lines, and the
//! server's severity and SQLSTATE. It adds table, column and constraint
//! names when the server supplies them. It never shows SQL text or the
//! server's message, detail, hint or context, which can quote row values
//! (R-NF-02). [`Error::server_message`] returns the message to code that
//! needs it.

mod error;
mod ledger;
mod lex;
mod migration;
mod runner;
mod schema;
pub mod split;

pub use crate::error::Error;
pub use crate::ledger::{
    LEDGER_TABLE_NAME, LedgerInconsistency, LedgerProblem, LedgerRow, MAX_REPORTED_PROBLEMS,
    check_ledger,
};
pub use crate::migration::{
    CheckedMigration, Migration, MigrationLimits, StatementRule, ValidationError, validate_entries,
};
pub use crate::runner::{
    ADVISORY_LOCK_KEY, ApplyReport, Database, MigrationInfo, MigrationSet, Status,
};
pub use crate::schema::{
    DEFAULT_LEDGER_SCHEMA, LedgerSchema, LedgerSchemaError, MAX_LEDGER_SCHEMA_LEN,
};
pub use crate::split::{SplitError, SplitErrorKind, SplitLimits, SqlStatement, split_statements};
