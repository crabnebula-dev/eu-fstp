//! The migration runner: `verify`, `plan` and `apply`.

use std::future::Future;

use fstp_pgwire::{Client, Row, Session, Timestamptz, ToSql, TransactionStatus};
use fstp_rt::Runtime;

use crate::error::Error;
use crate::ledger::{LedgerRow, check_ledger};
use crate::migration::{CheckedMigration, Migration, MigrationLimits, validate_entries};
use crate::schema::LedgerSchema;
use crate::split::SqlStatement;

/// The key of the transaction-scoped advisory lock that serialises
/// runners: the ASCII bytes of `FSTPMIGR` as a big-endian `i64`.
/// Applications must not use this key for their own advisory locks.
pub const ADVISORY_LOCK_KEY: i64 = 0x4653_5450_4D49_4752;

// SQL text stays &'static str, which fstp-pgwire requires, so the ledger
// schema name never enters it on the client (P4). It travels as a bind
// parameter. The catalog probe compares it as a value. Statements that
// need it as an identifier run in DO blocks, which read it from a
// transaction-local custom setting and quote it with format('%I'). A DO
// block takes no bind parameters, so the runner sets those settings in the
// statement just before each block, and no other statement runs between
// the two.
//
// Every ledger reference is qualified with the ledger schema, and types,
// functions and operators with pg_catalog. A qualified name never
// resolves through search_path or to a temporary relation. The session's
// temporary schema comes first in type lookup, and a search_path can list
// another schema before pg_catalog.
const BEGIN_APPLY_SQL: &str = "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE";
const BEGIN_VERIFY_SQL: &str = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY";
const COMMIT_SQL: &str = "COMMIT";
const ROLLBACK_SQL: &str = "ROLLBACK";
const LOCK_SQL: &str = "SELECT pg_catalog.pg_advisory_xact_lock($1::pg_catalog.int8)";

/// The ledger schema's owner, the migrating role, and whether the ledger
/// table exists. No row means that the schema does not exist.
const PROBE_SQL: &str = "SELECT pg_catalog.pg_get_userbyid(n.nspowner)::pg_catalog.text, \
    CURRENT_USER::pg_catalog.text, \
    EXISTS (SELECT FROM pg_catalog.pg_class c \
    WHERE c.relnamespace OPERATOR(pg_catalog.=) n.oid \
    AND c.relname OPERATOR(pg_catalog.=) 'schema_migrations') \
    FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) $1::pg_catalog.name";

/// Sets the ledger schema for the DO block that follows.
const PARAM_SCHEMA_SQL: &str =
    "SELECT pg_catalog.set_config('fstp_ledger.schema', $1::pg_catalog.text, true)";
/// Sets the ledger schema and the read limit for [`OPEN_LEDGER_SQL`].
const PARAM_READ_SQL: &str = "SELECT \
    pg_catalog.set_config('fstp_ledger.schema', $1::pg_catalog.text, true), \
    pg_catalog.set_config('fstp_ledger.read_limit', $2::pg_catalog.int8::pg_catalog.text, true)";
/// Sets the ledger schema and the new row's values for [`INSERT_SQL`].
const PARAM_INSERT_SQL: &str = "SELECT \
    pg_catalog.set_config('fstp_ledger.schema', $1::pg_catalog.text, true), \
    pg_catalog.set_config('fstp_ledger.version', $2::pg_catalog.int8::pg_catalog.text, true), \
    pg_catalog.set_config('fstp_ledger.name', $3::pg_catalog.text, true), \
    pg_catalog.set_config('fstp_ledger.checksum', \
    pg_catalog.encode($4::pg_catalog.bytea, 'hex'), true), \
    pg_catalog.set_config('fstp_ledger.statement_count', \
    $5::pg_catalog.int4::pg_catalog.text, true)";

/// A DO block that reads the ledger schema into `s`, refuses it unless it
/// follows the [`LedgerSchema`] rules, declares `$decl` and runs `$body`.
/// The check repeats the client's validation on the server, so a name
/// that somehow bypassed it still never reaches `format`.
macro_rules! ledger_do {
    ($decl:literal, $body:literal) => {
        concat!(
            "DO $fstp$ DECLARE \
            s pg_catalog.text := pg_catalog.current_setting('fstp_ledger.schema', true); ",
            $decl,
            " BEGIN IF s IS NULL \
            OR pg_catalog.octet_length(s) OPERATOR(pg_catalog.>) 63 \
            OR s OPERATOR(pg_catalog.!~) '^[a-z_][a-z0-9_]*$' \
            OR pg_catalog.starts_with(s, 'pg_') \
            OR s OPERATOR(pg_catalog.=) 'information_schema' \
            THEN RAISE EXCEPTION USING ERRCODE = 'invalid_schema_name', \
            MESSAGE = 'invalid ledger schema name'; END IF; ",
            $body,
            " END $fstp$"
        )
    };
}

/// Creates the ledger schema, owned by the migrating role.
const CREATE_SCHEMA_SQL: &str = ledger_do!(
    "",
    "EXECUTE pg_catalog.format('CREATE SCHEMA %I AUTHORIZATION CURRENT_USER', s);"
);
/// Creates the ledger table in the ledger schema.
const CREATE_TABLE_SQL: &str = ledger_do!(
    "",
    "EXECUTE pg_catalog.format('CREATE TABLE %I.schema_migrations (\
    version pg_catalog.int8 PRIMARY KEY CHECK (version OPERATOR(pg_catalog.>) 0), \
    name pg_catalog.text NOT NULL CHECK (name OPERATOR(pg_catalog.~) ''^[a-z0-9_]+$''), \
    checksum pg_catalog.bytea NOT NULL \
    CHECK (pg_catalog.octet_length(checksum) OPERATOR(pg_catalog.=) 32), \
    applied_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.now(), \
    statement_count pg_catalog.int4 NOT NULL \
    CHECK (statement_count OPERATOR(pg_catalog.>=) 0))', s);"
);
/// Opens the cursor `fstp_ledger_rows` over the ledger rows, at most the
/// read limit of them, in version order. The cursor lives until
/// [`CLOSE_LEDGER_SQL`] or the end of the transaction.
const OPEN_LEDGER_SQL: &str = ledger_do!(
    "c pg_catalog.refcursor := 'fstp_ledger_rows'; \
    lim pg_catalog.int8 := pg_catalog.current_setting('fstp_ledger.read_limit')::pg_catalog.int8;",
    "OPEN c FOR EXECUTE pg_catalog.format('SELECT version, name, checksum, statement_count, \
    applied_at FROM %I.schema_migrations ORDER BY version LIMIT $1', s) USING lim;"
);
const FETCH_LEDGER_SQL: &str = "FETCH ALL FROM fstp_ledger_rows";
const CLOSE_LEDGER_SQL: &str = "CLOSE fstp_ledger_rows";
/// Inserts the ledger row whose values [`PARAM_INSERT_SQL`] set.
const INSERT_SQL: &str = ledger_do!(
    "",
    "EXECUTE pg_catalog.format('INSERT INTO %I.schema_migrations \
    (version, name, checksum, statement_count) VALUES ($1, $2, $3, $4)', s) USING \
    pg_catalog.current_setting('fstp_ledger.version')::pg_catalog.int8, \
    pg_catalog.current_setting('fstp_ledger.name'), \
    pg_catalog.decode(pg_catalog.current_setting('fstp_ledger.checksum'), 'hex'), \
    pg_catalog.current_setting('fstp_ledger.statement_count')::pg_catalog.int4;"
);
const SCS: &str = "standard_conforming_strings";
const SESSION_SQL: &str = "SELECT pg_catalog.current_setting('search_path'), \
    pg_catalog.current_setting('standard_conforming_strings'), \
    current_user::pg_catalog.text, session_user::pg_catalog.text";

/// The database operations the runner needs, over one connection.
///
/// [`Client`] and [`Session`] implement it.
///
/// The runner sends `BEGIN`, `COMMIT` and `ROLLBACK` itself, so the
/// connection must be idle when a runner method starts.
pub trait Database {
    /// Runs `sql` and returns the number of rows affected. Rows it
    /// returns are discarded.
    fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, fstp_pgwire::Error>> + Send;

    /// Runs `sql` and collects its rows.
    fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, fstp_pgwire::Error>> + Send;

    /// The transaction status from the last ReadyForQuery.
    fn transaction_status(&self) -> TransactionStatus;

    /// A run-time parameter as the server last reported it with a
    /// ParameterStatus message. The runner reads
    /// `standard_conforming_strings` after every migration statement.
    fn parameter(&self, name: &str) -> Option<&str>;
}

impl<R: Runtime> Database for Client<R> {
    fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, fstp_pgwire::Error>> + Send {
        Client::execute(self, sql, params)
    }

    fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, fstp_pgwire::Error>> + Send {
        Client::query(self, sql, params)
    }

    fn transaction_status(&self) -> TransactionStatus {
        Client::transaction_status(self)
    }

    fn parameter(&self, name: &str) -> Option<&str> {
        Client::parameter(self, name)
    }
}

impl Database for Session {
    fn execute(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<u64, fstp_pgwire::Error>> + Send {
        Session::execute(self, sql, params)
    }

    fn query(
        &mut self,
        sql: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> impl Future<Output = Result<Vec<Row>, fstp_pgwire::Error>> + Send {
        Session::query(self, sql, params)
    }

    fn transaction_status(&self) -> TransactionStatus {
        Session::transaction_status(self)
    }

    fn parameter(&self, name: &str) -> Option<&str> {
        Session::parameter(self, name)
    }
}

/// A short description of one embedded migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MigrationInfo {
    /// The version.
    pub version: u32,
    /// The name.
    pub name: &'static str,
    /// SHA-256 of the SQL text.
    pub checksum: [u8; 32],
    /// The number of statements.
    pub statements: usize,
}

impl MigrationInfo {
    fn of(m: &CheckedMigration<'static>) -> Self {
        Self {
            version: m.version(),
            name: m.name(),
            checksum: *m.checksum(),
            statements: m.statements().len(),
        }
    }
}

/// The result of [`MigrationSet::verify`]: a consistent ledger and what
/// remains to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// True when the ledger table exists.
    pub ledger_exists: bool,
    /// The ledger rows, in version order.
    pub applied: Vec<LedgerRow>,
    /// The migrations not yet applied, in version order.
    pub pending: Vec<MigrationInfo>,
}

/// The result of [`MigrationSet::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// The migrations this call applied, in order. Migrations that another
    /// runner applied concurrently are not listed.
    pub applied: Vec<MigrationInfo>,
    /// The number of applied migrations when the call finished, which is
    /// also the highest applied version.
    pub version: u32,
}

/// The session settings compared before and after each migration.
#[derive(Debug, PartialEq, Eq)]
struct SessionState {
    search_path: String,
    standard_conforming_strings: String,
    current_user: String,
    session_user: String,
}

impl SessionState {
    /// The first setting that differs, by name.
    fn changed(&self, after: &SessionState) -> Option<&'static str> {
        if self.search_path != after.search_path {
            Some("search_path")
        } else if self.standard_conforming_strings != after.standard_conforming_strings {
            Some("standard_conforming_strings")
        } else if self.current_user != after.current_user {
            Some("current_user")
        } else if self.session_user != after.session_user {
            Some("session_user")
        } else {
            None
        }
    }
}

/// What one apply transaction did.
enum Step<'m> {
    /// Nothing was pending; the value is the number of applied migrations.
    Done(usize),
    /// This migration was applied and awaits commit.
    Applied(&'m CheckedMigration<'static>),
}

/// A validated list of embedded migrations, and the runner for it.
///
/// Build one at startup with [`MigrationSet::new`], which refuses an
/// invalid list. Then [`verify`](MigrationSet::verify) the database,
/// [`plan`](MigrationSet::plan) what would run, or
/// [`apply`](MigrationSet::apply) what is pending. There is no way to undo
/// a migration: the runner is forward-only.
///
/// The ledger lives in the schema
/// [`DEFAULT_LEDGER_SCHEMA`](crate::DEFAULT_LEDGER_SCHEMA) unless
/// [`with_ledger_schema`](MigrationSet::with_ledger_schema) names another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSet {
    migrations: Vec<CheckedMigration<'static>>,
    ledger_schema: LedgerSchema,
}

impl MigrationSet {
    /// Validates `list` with the default [`MigrationLimits`].
    ///
    /// # Errors
    ///
    /// Returns the first problem, as described for
    /// [`validate_entries`](crate::validate_entries).
    pub fn new(list: &[Migration]) -> Result<Self, crate::ValidationError> {
        Self::with_limits(list, &MigrationLimits::default())
    }

    /// Validates `list` with explicit limits.
    ///
    /// # Errors
    ///
    /// As for [`MigrationSet::new`].
    pub fn with_limits(
        list: &[Migration],
        limits: &MigrationLimits,
    ) -> Result<Self, crate::ValidationError> {
        let migrations = validate_entries(list.iter().map(|m| (m.version, m.name, m.sql)), limits)?;
        Ok(Self {
            migrations,
            ledger_schema: LedgerSchema::default(),
        })
    }

    /// Keeps the ledger in `schema` instead of
    /// [`DEFAULT_LEDGER_SCHEMA`](crate::DEFAULT_LEDGER_SCHEMA).
    ///
    /// [`apply`](MigrationSet::apply) creates the schema if it is missing,
    /// owned by the migrating role (`current_user`). Every runner method
    /// refuses a schema of that name that another role owns.
    #[must_use]
    pub fn with_ledger_schema(mut self, schema: LedgerSchema) -> Self {
        self.ledger_schema = schema;
        self
    }

    /// The schema that holds the ledger.
    #[must_use]
    pub fn ledger_schema(&self) -> &LedgerSchema {
        &self.ledger_schema
    }

    /// The validated migrations, in version order.
    #[must_use]
    pub fn migrations(&self) -> &[CheckedMigration<'static>] {
        &self.migrations
    }

    /// The highest embedded version, or 0 for an empty list.
    #[must_use]
    pub fn latest_version(&self) -> u32 {
        self.migrations.last().map_or(0, CheckedMigration::version)
    }

    /// The most ledger rows read: one more than the embedded list, so that
    /// a database ahead of the binary always shows an unknown version.
    fn read_limit(&self) -> i64 {
        i64::try_from(self.migrations.len())
            .unwrap_or(i64::MAX)
            .saturating_add(1)
    }

    fn pending_from(&self, applied: usize) -> Vec<MigrationInfo> {
        self.migrations
            .get(applied..)
            .unwrap_or_default()
            .iter()
            .map(MigrationInfo::of)
            .collect()
    }

    /// Checks the ledger against the embedded list without changing
    /// anything, and reports what is applied and what is pending.
    ///
    /// It reads in one `REPEATABLE READ READ ONLY` transaction and takes
    /// no lock. A database without the ledger schema or table counts as
    /// empty.
    ///
    /// # Errors
    ///
    /// - [`Error::Inconsistent`] when an applied migration's checksum or
    ///   name differs, the database holds a version this binary does not
    ///   know, or the applied versions are not a prefix of the list.
    /// - [`Error::LedgerSchemaOwner`] when the ledger schema exists but
    ///   another role than `current_user` owns it.
    /// - [`Error::TransactionOpen`] when the connection is not idle.
    /// - [`Error::Database`] for a server or connection error.
    pub async fn verify<D: Database>(&self, db: &mut D) -> Result<Status, Error> {
        ensure_idle(db)?;
        db.execute(BEGIN_VERIFY_SQL, &[])
            .await
            .map_err(|e| Error::db("cannot start a read-only transaction", e))?;
        let state = self.read_state(db).await;
        let ended = match state {
            Ok(_) => db
                .execute(COMMIT_SQL, &[])
                .await
                .map_err(|e| Error::db("cannot end the read-only transaction", e)),
            Err(_) => {
                abort(db).await;
                Ok(0)
            }
        };
        let (ledger_exists, rows) = state?;
        ended?;
        let applied = check_ledger(&self.migrations, &rows).map_err(Error::Inconsistent)?;
        Ok(Status {
            ledger_exists,
            applied: rows,
            pending: self.pending_from(applied),
        })
    }

    /// The migrations that [`apply`](MigrationSet::apply) would run now, in
    /// order, after the same checks as [`verify`](MigrationSet::verify).
    ///
    /// # Errors
    ///
    /// As for [`MigrationSet::verify`].
    pub async fn plan<D: Database>(&self, db: &mut D) -> Result<Vec<MigrationInfo>, Error> {
        self.verify(db).await.map(|s| s.pending)
    }

    /// Applies every pending migration, in order.
    ///
    /// Each migration runs in its own `READ COMMITTED` transaction together
    /// with its ledger row:
    ///
    /// 1. take the transaction-scoped advisory lock [`ADVISORY_LOCK_KEY`],
    ///    which waits for any other runner's transaction to end;
    /// 2. look up the ledger schema, refuse it when another role than
    ///    `current_user` owns it, and create the schema or the table where
    ///    either is missing;
    /// 3. read the ledger again under the lock and check it as
    ///    [`verify`](MigrationSet::verify) does;
    /// 4. run the first pending migration's statements one by one through
    ///    the extended query protocol, and stop as soon as the server
    ///    reports that `standard_conforming_strings` is no longer on;
    /// 5. check that the migration left `search_path`,
    ///    `standard_conforming_strings`, `current_user` and `session_user`
    ///    as they were;
    /// 6. insert the ledger row and commit.
    ///
    /// Because every runner rereads the ledger under the lock, concurrent
    /// runners apply each migration exactly once. The ledger's primary key
    /// on `version` backs this up. A failing statement rolls back the whole
    /// migration, so its version stays unapplied and earlier migrations
    /// stay applied.
    ///
    /// `READ COMMITTED` is explicit so that the reread in step 3 sees rows
    /// committed while the runner waited for the lock, whatever the
    /// server's default isolation level.
    ///
    /// The lock key does not depend on the ledger schema. Runners with
    /// different ledger schemas in one database therefore also wait for
    /// each other.
    ///
    /// Steps 2, 3 and 6 run `DO` blocks, so the database needs the
    /// `plpgsql` language, which PostgreSQL installs by default, and the
    /// migrating role needs `USAGE` on it. Creating the schema needs the
    /// `CREATE` privilege on the database.
    ///
    /// The client's statement timeout, if any, applies to every statement,
    /// including the wait for the lock. So do the server's
    /// `statement_timeout` and `lock_timeout`. Dropping the returned future
    /// part-way leaves a transaction open on the connection: close the
    /// connection then.
    ///
    /// # Errors
    ///
    /// - [`Error::Inconsistent`], [`Error::LedgerSchemaOwner`],
    ///   [`Error::TransactionOpen`] and [`Error::Database`] as for
    ///   [`MigrationSet::verify`].
    /// - [`Error::StandardConformingStringsOff`] when the server setting
    ///   is off, or the connection does not report it.
    /// - [`Error::Statement`] or [`Error::NotTransactional`] when a
    ///   migration statement fails, and [`Error::Commit`] when its commit
    ///   fails.
    /// - [`Error::SessionChanged`] when a migration changes one of the
    ///   settings listed in step 5, or `standard_conforming_strings` in
    ///   step 4.
    ///
    /// Migrations applied before the error stay applied and are not
    /// listed, since the error replaces the report.
    pub async fn apply<D: Database>(&self, db: &mut D) -> Result<ApplyReport, Error> {
        ensure_idle(db)?;
        let mut applied = Vec::new();
        loop {
            db.execute(BEGIN_APPLY_SQL, &[])
                .await
                .map_err(|e| Error::db("cannot start a migration transaction", e))?;
            match self.step(db).await {
                Ok(Step::Done(count)) => {
                    if let Err(e) = db.execute(COMMIT_SQL, &[]).await {
                        abort(db).await;
                        return Err(Error::db("cannot commit the ledger check", e));
                    }
                    return Ok(ApplyReport {
                        applied,
                        version: u32::try_from(count).unwrap_or(u32::MAX),
                    });
                }
                Ok(Step::Applied(m)) => {
                    if let Err(source) = db.execute(COMMIT_SQL, &[]).await {
                        abort(db).await;
                        return Err(Error::Commit {
                            version: m.version(),
                            name: m.name(),
                            source,
                        });
                    }
                    applied.push(MigrationInfo::of(m));
                }
                Err(e) => {
                    abort(db).await;
                    return Err(e);
                }
            }
        }
    }

    /// The body of one apply transaction, after `BEGIN`.
    async fn step<D: Database>(&self, db: &mut D) -> Result<Step<'_>, Error> {
        db.execute(LOCK_SQL, &[&ADVISORY_LOCK_KEY])
            .await
            .map_err(|e| Error::db("cannot take the migration lock", e))?;
        match self.probe(db).await? {
            Ledger::Exists => {}
            Ledger::NoTable => self.create_table(db).await?,
            Ledger::NoSchema => {
                self.run_do(db, CREATE_SCHEMA_SQL, "cannot create the ledger schema")
                    .await?;
                self.create_table(db).await?;
            }
        }
        let rows = self.read_ledger(db).await?;
        let count = check_ledger(&self.migrations, &rows).map_err(Error::Inconsistent)?;
        let Some(next) = self.migrations.get(count) else {
            return Ok(Step::Done(count));
        };
        let before = session_state(db).await?;
        if before.standard_conforming_strings != "on" || db.parameter(SCS) != Some("on") {
            return Err(Error::StandardConformingStringsOff);
        }
        for (i, stmt) in next.statements().iter().enumerate() {
            if let Err(e) = db.execute(stmt.text(), &[]).await {
                return Err(statement_error(next, i, stmt, e));
            }
            // The splitter read the remaining statements with the setting
            // on. The server reports every change of it before
            // ReadyForQuery, including SET LOCAL and set_config.
            if db.parameter(SCS) != Some("on") {
                return Err(Error::SessionChanged {
                    version: next.version(),
                    name: next.name(),
                    setting: SCS,
                });
            }
        }
        let after = session_state(db).await?;
        if let Some(setting) = before.changed(&after) {
            return Err(Error::SessionChanged {
                version: next.version(),
                name: next.name(),
                setting,
            });
        }
        let context = "cannot record the migration in the ledger";
        let schema = self.ledger_schema.as_str();
        let version = i64::from(next.version());
        let name = next.name();
        let checksum: &[u8] = next.checksum();
        let statements = i32::try_from(next.statements().len()).unwrap_or(i32::MAX);
        // The settings go right before the block that reads them, so a
        // value that the migration set for them is overwritten.
        db.execute(
            PARAM_INSERT_SQL,
            &[&schema, &version, &name, &checksum, &statements],
        )
        .await
        .map_err(|e| Error::db(context, e))?;
        db.execute(INSERT_SQL, &[])
            .await
            .map_err(|e| Error::db(context, e))?;
        Ok(Step::Applied(next))
    }

    /// Looks up the ledger schema and table by name in the catalog, and
    /// refuses a schema that another role than `current_user` owns.
    async fn probe<D: Database>(&self, db: &mut D) -> Result<Ledger, Error> {
        let context = "cannot look up the ledger schema";
        let schema = self.ledger_schema.as_str();
        let rows = db
            .query(PROBE_SQL, &[&schema])
            .await
            .map_err(|e| Error::db(context, e))?;
        let Some(row) = rows.first() else {
            return Ok(Ledger::NoSchema);
        };
        let owner: String = row.get(0).map_err(|e| Error::db(context, e))?;
        let current_user: String = row.get(1).map_err(|e| Error::db(context, e))?;
        let table: bool = row.get(2).map_err(|e| Error::db(context, e))?;
        if owner != current_user {
            return Err(Error::LedgerSchemaOwner {
                schema: self.ledger_schema.clone(),
                owner,
                current_user,
            });
        }
        Ok(if table {
            Ledger::Exists
        } else {
            Ledger::NoTable
        })
    }

    async fn create_table<D: Database>(&self, db: &mut D) -> Result<(), Error> {
        self.run_do(db, CREATE_TABLE_SQL, "cannot create the ledger table")
            .await
    }

    /// Sets the ledger schema for `block`, then runs it.
    async fn run_do<D: Database>(
        &self,
        db: &mut D,
        block: &'static str,
        context: &'static str,
    ) -> Result<(), Error> {
        let schema = self.ledger_schema.as_str();
        db.execute(PARAM_SCHEMA_SQL, &[&schema])
            .await
            .map_err(|e| Error::db(context, e))?;
        db.execute(block, &[])
            .await
            .map_err(|e| Error::db(context, e))?;
        Ok(())
    }

    /// Reads at most [`MigrationSet::read_limit`] ledger rows, in version
    /// order, through the cursor that [`OPEN_LEDGER_SQL`] opens.
    async fn read_ledger<D: Database>(&self, db: &mut D) -> Result<Vec<LedgerRow>, Error> {
        let context = "cannot read the ledger";
        let schema = self.ledger_schema.as_str();
        let limit = self.read_limit();
        db.execute(PARAM_READ_SQL, &[&schema, &limit])
            .await
            .map_err(|e| Error::db(context, e))?;
        db.execute(OPEN_LEDGER_SQL, &[])
            .await
            .map_err(|e| Error::db(context, e))?;
        let rows = db
            .query(FETCH_LEDGER_SQL, &[])
            .await
            .map_err(|e| Error::db(context, e))?;
        db.execute(CLOSE_LEDGER_SQL, &[])
            .await
            .map_err(|e| Error::db(context, e))?;
        rows.iter()
            .map(|r| {
                Ok(LedgerRow {
                    version: r.get(0)?,
                    name: r.get(1)?,
                    checksum: r.get(2)?,
                    statement_count: r.get(3)?,
                    applied_at: r.get::<Timestamptz>(4)?,
                })
            })
            .collect::<Result<Vec<_>, fstp_pgwire::Error>>()
            .map_err(|e| Error::db("cannot decode the ledger", e))
    }

    /// Whether the ledger exists, and its rows if it does.
    async fn read_state<D: Database>(&self, db: &mut D) -> Result<(bool, Vec<LedgerRow>), Error> {
        match self.probe(db).await? {
            Ledger::Exists => Ok((true, self.read_ledger(db).await?)),
            Ledger::NoTable | Ledger::NoSchema => Ok((false, Vec::new())),
        }
    }
}

/// What [`MigrationSet::probe`] found.
enum Ledger {
    /// The schema, owned by `current_user`, holds the ledger table.
    Exists,
    /// The schema exists and `current_user` owns it, but it holds no
    /// ledger table.
    NoTable,
    /// The schema does not exist.
    NoSchema,
}

fn statement_error(
    m: &CheckedMigration<'static>,
    index: usize,
    stmt: &SqlStatement<'static>,
    source: fstp_pgwire::Error,
) -> Error {
    let (version, name, statement, line) =
        (m.version(), m.name(), index.saturating_add(1), stmt.line());
    if source.code() == Some("25001") {
        Error::NotTransactional {
            version,
            name,
            statement,
            line,
            source,
        }
    } else {
        Error::Statement {
            version,
            name,
            statement,
            line,
            source,
        }
    }
}

fn ensure_idle<D: Database>(db: &D) -> Result<(), Error> {
    if db.transaction_status() == TransactionStatus::Idle {
        Ok(())
    } else {
        Err(Error::TransactionOpen)
    }
}

/// Ends an open transaction after a failure. The original error matters
/// more than a failed rollback, so a rollback error is dropped; a broken
/// connection ends the transaction anyway.
async fn abort<D: Database>(db: &mut D) {
    if db.transaction_status() != TransactionStatus::Idle {
        let _ = db.execute(ROLLBACK_SQL, &[]).await;
    }
}

async fn session_state<D: Database>(db: &mut D) -> Result<SessionState, Error> {
    let context = "cannot read the session settings";
    let rows = db
        .query(SESSION_SQL, &[])
        .await
        .map_err(|e| Error::db(context, e))?;
    let row = rows.first().ok_or(Error::NoRow { context })?;
    let get = |i: usize| row.get::<String>(i).map_err(|e| Error::db(context, e));
    Ok(SessionState {
        search_path: get(0)?,
        standard_conforming_strings: get(1)?,
        current_user: get(2)?,
        session_user: get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LEDGER_TABLE_NAME;
    use crate::schema::DEFAULT_LEDGER_SCHEMA;

    const ALL: [&str; 16] = [
        BEGIN_APPLY_SQL,
        BEGIN_VERIFY_SQL,
        COMMIT_SQL,
        ROLLBACK_SQL,
        LOCK_SQL,
        PROBE_SQL,
        PARAM_SCHEMA_SQL,
        PARAM_READ_SQL,
        PARAM_INSERT_SQL,
        CREATE_SCHEMA_SQL,
        CREATE_TABLE_SQL,
        OPEN_LEDGER_SQL,
        FETCH_LEDGER_SQL,
        CLOSE_LEDGER_SQL,
        INSERT_SQL,
        SESSION_SQL,
    ];

    /// The DO blocks that take the ledger schema as an identifier.
    const BLOCKS: [&str; 4] = [
        CREATE_SCHEMA_SQL,
        CREATE_TABLE_SQL,
        OPEN_LEDGER_SQL,
        INSERT_SQL,
    ];

    /// P4 (revised), and review findings `ledger-located-via-search-path`
    /// and `temp-table-shadows-ledger`. No runner statement holds a schema
    /// name. Each statement that uses the ledger table names it as
    /// `%I.schema_migrations`, which the server qualifies with the quoted
    /// ledger schema. The catalog probe matches the table by name within
    /// the schema's namespace, and takes the schema as a bind parameter.
    #[test]
    fn p4_ledger_statements_qualify_the_table_with_the_configured_schema() {
        let qualified = format!("%I.{LEDGER_TABLE_NAME}");
        let literal = format!("'{LEDGER_TABLE_NAME}'");
        for sql in ALL {
            assert!(!sql.contains(DEFAULT_LEDGER_SCHEMA), "{sql}");
            assert_eq!(
                sql.matches(LEDGER_TABLE_NAME).count(),
                sql.matches(&qualified).count() + sql.matches(&literal).count(),
                "{sql}"
            );
        }
        for sql in [CREATE_TABLE_SQL, OPEN_LEDGER_SQL, INSERT_SQL] {
            assert_eq!(sql.matches(&qualified).count(), 1, "{sql}");
        }
        assert!(CREATE_SCHEMA_SQL.contains("CREATE SCHEMA %I AUTHORIZATION CURRENT_USER"));
        assert_eq!(PROBE_SQL.matches(&literal).count(), 1);
        assert!(PROBE_SQL.contains("n.nspname OPERATOR(pg_catalog.=) $1::pg_catalog.name"));
        for sql in BLOCKS {
            assert!(sql.starts_with("DO $fstp$ "), "{sql}");
            // The only format directive is %I, which quotes an identifier.
            assert_eq!(sql.matches('%').count(), sql.matches("%I").count(), "{sql}");
            assert!(sql.contains("'invalid ledger schema name'"), "{sql}");
        }
        for sql in [OPEN_LEDGER_SQL, FETCH_LEDGER_SQL, CLOSE_LEDGER_SQL] {
            assert!(sql.contains("fstp_ledger_rows"), "{sql}");
        }
    }

    /// P4 (revised), defence in depth. Every DO block refuses a schema
    /// name that did not pass [`LedgerSchema::new`], before `format`
    /// quotes it, so no hostile name reaches an identifier position even
    /// if the client check were bypassed. The names here cannot be built
    /// through the public API.
    #[test]
    fn p4_do_blocks_refuse_unvalidated_schema_names() {
        let server = fstp_pgtest::PgServer::shared().unwrap_or_else(|e| panic!("{e}"));
        let db = server.fresh_database().unwrap_or_else(|e| panic!("{e}"));
        let long = "a".repeat(64);
        let hostile = [
            "x\"; DROP SCHEMA public CASCADE; --",
            "x; DROP SCHEMA public CASCADE",
            "Upper",
            "a.b",
            "pg_temp",
            "pg_catalog",
            "information_schema",
            "",
            long.as_str(),
        ];
        let set_up = "SELECT pg_catalog.set_config('fstp_ledger.read_limit', '1', true);\n\
                      SELECT pg_catalog.set_config('fstp_ledger.version', '1', true);\n\
                      SELECT pg_catalog.set_config('fstp_ledger.name', 'm', true);\n\
                      SELECT pg_catalog.set_config('fstp_ledger.checksum', '00', true);\n\
                      SELECT pg_catalog.set_config('fstp_ledger.statement_count', '1', true);\n";
        for name in hostile {
            for block in BLOCKS {
                let sql = format!(
                    "BEGIN;\nSELECT pg_catalog.set_config('fstp_ledger.schema', $h${name}$h$, true);\n\
                     {set_up}{block};\nCOMMIT;\n"
                );
                let err = server.psql(&db.dbname, &sql).map(|_| ()).expect_err(name);
                assert!(
                    err.to_string().contains("invalid ledger schema name"),
                    "{name:?}: {err}"
                );
            }
        }
        // An unset schema is refused too.
        let err = server
            .psql(&db.dbname, &format!("{CREATE_SCHEMA_SQL};\n"))
            .map(|_| ())
            .expect_err("unset");
        assert!(
            err.to_string().contains("invalid ledger schema name"),
            "{err}"
        );
        let schemas = server
            .psql(
                &db.dbname,
                "SELECT string_agg(nspname, ',' ORDER BY nspname) FROM pg_namespace \
                 WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'",
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(schemas, "public");
    }

    #[test]
    fn the_lock_key_spells_fstpmigr() {
        assert_eq!(&ADVISORY_LOCK_KEY.to_be_bytes(), b"FSTPMIGR");
    }

    #[test]
    fn runner_statements_are_single_statements() {
        let limits = crate::SplitLimits::default();
        for sql in ALL {
            let split = crate::split_statements(sql, &limits).unwrap();
            assert_eq!(split.len(), 1, "{sql}");
            assert_eq!(split[0].text(), sql);
        }
    }

    #[test]
    fn session_changes_are_named() {
        let state = |path: &str, scs: &str, user: &str, session: &str| SessionState {
            search_path: path.into(),
            standard_conforming_strings: scs.into(),
            current_user: user.into(),
            session_user: session.into(),
        };
        let base = state("public", "on", "app", "app");
        assert_eq!(base.changed(&state("public", "on", "app", "app")), None);
        assert_eq!(
            base.changed(&state("other", "on", "app", "app")),
            Some("search_path")
        );
        assert_eq!(
            base.changed(&state("public", "off", "app", "app")),
            Some("standard_conforming_strings")
        );
        assert_eq!(
            base.changed(&state("public", "on", "admin", "app")),
            Some("current_user")
        );
        assert_eq!(
            base.changed(&state("public", "on", "app", "admin")),
            Some("session_user")
        );
    }
}
