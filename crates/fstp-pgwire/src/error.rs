//! Error types.
//!
//! [`Error`] is the one error type of the client API. A server error is a
//! [`DbError`] with its SQLSTATE. Display and Debug output never carry data
//! values or SQL text (R-NF-02). A `DbError` shows its severity, SQLSTATE
//! and the SQLSTATE's standard condition name, plus the table, column and
//! constraint names when the server supplies them. The primary message,
//! detail, hint and context can quote data, so they stay behind accessors.

use std::fmt;
use std::io;

/// Broad classes of failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The configuration is invalid, for example a password outside
    /// printable ASCII.
    Config,
    /// The transport failed.
    Io,
    /// The TLS handshake failed, for example because the server certificate
    /// does not chain to a trusted root. [`Error::tls_error`] has details.
    Tls,
    /// The server refused TLS. This client never continues without it.
    TlsRequired,
    /// A connect or statement deadline passed.
    Timeout,
    /// The server broke the protocol or sent a message this client does not
    /// support, such as COPY. The connection is broken afterwards.
    Protocol,
    /// Client-side authentication failure: the server asked for a method
    /// that `require_auth` does not allow, its SCRAM signature was wrong, or
    /// channel binding was not possible.
    Auth,
    /// The server reported an error. [`Error::as_db_error`] has the details.
    Db,
    /// A parameter value could not be encoded.
    Encode,
    /// A column value could not be decoded.
    Decode,
    /// A parameter or column type does not match the Rust type.
    TypeMismatch,
    /// The number of parameters does not match the statement.
    ParameterCount,
    /// `query_one` or `query_opt` saw a different number of rows.
    RowCount,
    /// No column has the requested name or index.
    ColumnNotFound,
    /// A collected result exceeded [`Limits::max_result_bytes`](crate::Limits).
    ResultTooLarge,
    /// `COMMIT` rolled the transaction back, because an earlier statement in
    /// it failed.
    RolledBack,
    /// The connection is closed or broken and cannot be used.
    Closed,
}

/// An error from the PostgreSQL client.
pub struct Error {
    inner: Box<Inner>,
}

struct Inner {
    kind: ErrorKind,
    message: String,
    db: Option<DbError>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(Inner {
                kind,
                message: message.into(),
                db: None,
                source: None,
            }),
        }
    }

    pub(crate) fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        let mut e = Self::new(kind, message);
        e.inner.source = Some(Box::new(source));
        e
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }

    pub(crate) fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Auth, message)
    }

    pub(crate) fn closed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Closed, message)
    }

    pub(crate) fn timeout(what: &str) -> Self {
        Self::new(ErrorKind::Timeout, format!("{what} timed out"))
    }

    pub(crate) fn db(err: DbError) -> Self {
        let mut e = Self::new(ErrorKind::Db, String::new());
        e.inner.db = Some(err);
        e
    }

    /// Classifies a transport error. A TLS error that fstp-tls wrapped in
    /// the `io::Error` becomes [`ErrorKind::Tls`].
    pub(crate) fn io(context: &str, e: io::Error) -> Self {
        if fstp_tls::TlsError::from_io(&e).is_some() {
            return Self::with_source(ErrorKind::Tls, context.to_owned(), e);
        }
        if e.kind() == io::ErrorKind::TimedOut {
            return Self::with_source(ErrorKind::Timeout, context.to_owned(), e);
        }
        Self::with_source(ErrorKind::Io, context.to_owned(), e)
    }

    /// The class of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// The server error, when this is one.
    #[must_use]
    pub fn as_db_error(&self) -> Option<&DbError> {
        self.inner.db.as_ref()
    }

    /// The SQLSTATE code of a server error.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.inner.db.as_ref().map(DbError::code)
    }

    /// The fstp-tls error behind a TLS failure.
    #[must_use]
    pub fn tls_error(&self) -> Option<&fstp_tls::TlsError> {
        let source = self.inner.source.as_ref()?;
        if let Some(io) = source.downcast_ref::<io::Error>() {
            return fstp_tls::TlsError::from_io(io);
        }
        source.downcast_ref::<fstp_tls::TlsError>()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(db) = &self.inner.db {
            return fmt::Display::fmt(db, f);
        }
        let kind = match self.inner.kind {
            ErrorKind::Config => "invalid configuration",
            ErrorKind::Io => "I/O error",
            ErrorKind::Tls => "TLS error",
            ErrorKind::TlsRequired => "TLS required",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Protocol => "protocol error",
            ErrorKind::Auth => "authentication error",
            ErrorKind::Db => "database error",
            ErrorKind::Encode => "cannot encode parameter",
            ErrorKind::Decode => "cannot decode column",
            ErrorKind::TypeMismatch => "type mismatch",
            ErrorKind::ParameterCount => "wrong number of parameters",
            ErrorKind::RowCount => "unexpected number of rows",
            ErrorKind::ColumnNotFound => "column not found",
            ErrorKind::ResultTooLarge => "result too large",
            ErrorKind::RolledBack => "transaction rolled back",
            ErrorKind::Closed => "connection closed",
        };
        if self.inner.message.is_empty() {
            f.write_str(kind)?;
        } else {
            write!(f, "{kind}: {}", self.inner.message)?;
        }
        if let Some(source) = &self.inner.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.inner.kind);
        if !self.inner.message.is_empty() {
            d.field("message", &self.inner.message);
        }
        if let Some(db) = &self.inner.db {
            d.field("db", db);
        }
        if let Some(source) = &self.inner.source {
            d.field("source", &format_args!("{source}"));
        }
        d.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// An error or notice reported by the server, with its SQLSTATE.
///
/// [`fmt::Display`] and [`fmt::Debug`] show the severity, the SQLSTATE and
/// its standard condition name from [`crate::sqlstate`]. For a code without
/// a name they show the name of its class, marked `class`, or nothing when
/// the class has none either. They add the table, column and constraint
/// names when the server supplies them, since these are schema names and
/// not data. Examples are
/// `ERROR 23505 unique_violation (table "people", constraint "people_pkey")`
/// and `ERROR 23P99 class integrity_constraint_violation`.
///
/// Every other field is reachable only through its accessor (R-NF-02). The
/// primary message can quote the offending value, as in `invalid input
/// syntax for type integer: "..."` (SQLSTATE `22P02`) or a `RAISE` with a
/// formatted value. The detail, hint, context and internal query can carry
/// data values too, such as the duplicate key of a unique violation. Do not
/// write them to logs.
#[derive(Clone, PartialEq, Eq)]
pub struct DbError {
    severity: String,
    code: String,
    message: String,
    detail: Option<String>,
    hint: Option<String>,
    position: Option<u32>,
    internal_position: Option<u32>,
    internal_query: Option<String>,
    where_: Option<String>,
    schema: Option<String>,
    table: Option<String>,
    column: Option<String>,
    datatype: Option<String>,
    constraint: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    routine: Option<String>,
}

impl DbError {
    /// Builds a `DbError` from the fields of an ErrorResponse or
    /// NoticeResponse.
    ///
    /// The severity, SQLSTATE and message fields are required. Unknown field
    /// types are ignored, as the protocol specifies. Field values that are
    /// not valid UTF-8 are converted lossily: error text can arrive before
    /// the client encoding is in effect.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Protocol`] error when a required field is
    /// missing or the SQLSTATE is not five ASCII letters or digits.
    pub fn from_fields(fields: &[(u8, Vec<u8>)]) -> Result<DbError, Error> {
        let mut severity_local = None;
        let mut severity = None;
        let mut code = None;
        let mut message = None;
        let mut e = DbError {
            severity: String::new(),
            code: String::new(),
            message: String::new(),
            detail: None,
            hint: None,
            position: None,
            internal_position: None,
            internal_query: None,
            where_: None,
            schema: None,
            table: None,
            column: None,
            datatype: None,
            constraint: None,
            file: None,
            line: None,
            routine: None,
        };
        for (ty, raw) in fields {
            let value = String::from_utf8_lossy(raw).into_owned();
            match ty {
                b'S' => severity_local = Some(value),
                b'V' => severity = Some(value),
                b'C' => code = Some(value),
                b'M' => message = Some(value),
                b'D' => e.detail = Some(value),
                b'H' => e.hint = Some(value),
                b'P' => e.position = value.parse().ok(),
                b'p' => e.internal_position = value.parse().ok(),
                b'q' => e.internal_query = Some(value),
                b'W' => e.where_ = Some(value),
                b's' => e.schema = Some(value),
                b't' => e.table = Some(value),
                b'c' => e.column = Some(value),
                b'd' => e.datatype = Some(value),
                b'n' => e.constraint = Some(value),
                b'F' => e.file = Some(value),
                b'L' => e.line = value.parse().ok(),
                b'R' => e.routine = Some(value),
                _ => {}
            }
        }
        let Some(severity) = severity.or(severity_local) else {
            return Err(Error::protocol("error response without a severity"));
        };
        let Some(code) = code else {
            return Err(Error::protocol("error response without a SQLSTATE"));
        };
        if code.len() != 5 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::protocol("error response with a malformed SQLSTATE"));
        }
        let Some(message) = message else {
            return Err(Error::protocol("error response without a message"));
        };
        e.severity = severity;
        e.code = code;
        e.message = message;
        Ok(e)
    }

    /// The severity: `ERROR`, `FATAL` or `PANIC` for errors, or `WARNING`,
    /// `NOTICE`, `DEBUG`, `INFO` or `LOG` for notices. The non-localized
    /// form is used when the server sends it.
    #[must_use]
    pub fn severity(&self) -> &str {
        &self.severity
    }

    /// The SQLSTATE code, for example `23505` for a unique violation.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The primary message. It can contain data values, for example the
    /// input that failed a type cast (R-NF-02). [`fmt::Display`] leaves it
    /// out for that reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The detail message. It can contain data values (R-NF-02).
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The hint. It can contain data values (R-NF-02).
    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// The 1-based character position of the error in the statement.
    #[must_use]
    pub fn position(&self) -> Option<u32> {
        self.position
    }

    /// The position in an internally generated statement.
    #[must_use]
    pub fn internal_position(&self) -> Option<u32> {
        self.internal_position
    }

    /// An internally generated statement. It can contain data values.
    #[must_use]
    pub fn internal_query(&self) -> Option<&str> {
        self.internal_query.as_deref()
    }

    /// The context ("where") of the error. It can contain data values.
    #[must_use]
    pub fn where_(&self) -> Option<&str> {
        self.where_.as_deref()
    }

    /// The schema of the object involved.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The table involved.
    #[must_use]
    pub fn table(&self) -> Option<&str> {
        self.table.as_deref()
    }

    /// The column involved.
    #[must_use]
    pub fn column(&self) -> Option<&str> {
        self.column.as_deref()
    }

    /// The data type involved.
    #[must_use]
    pub fn datatype(&self) -> Option<&str> {
        self.datatype.as_deref()
    }

    /// The constraint involved.
    #[must_use]
    pub fn constraint(&self) -> Option<&str> {
        self.constraint.as_deref()
    }

    /// The server source file that reported the error.
    #[must_use]
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    /// The line in [`DbError::file`].
    #[must_use]
    pub fn line(&self) -> Option<u32> {
        self.line
    }

    /// The server routine that reported the error.
    #[must_use]
    pub fn routine(&self) -> Option<&str> {
        self.routine.as_deref()
    }

    /// The standard condition name of the SQLSTATE, for example
    /// `unique_violation` for `23505`. `None` when the code has none.
    #[must_use]
    pub fn condition_name(&self) -> Option<&'static str> {
        crate::sqlstate::condition_name(&self.code)
    }

    /// The condition name of the SQLSTATE's class, for example
    /// `integrity_constraint_violation` for any `23` code. `None` when the
    /// class has none.
    #[must_use]
    pub fn class_name(&self) -> Option<&'static str> {
        crate::sqlstate::class_name(&self.code)
    }

    /// True for `FATAL` and `PANIC`, after which the server closes the
    /// connection.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self.severity.as_str(), "FATAL" | "PANIC")
    }
}

impl DbError {
    /// The schema names that Display may show: table, column and constraint.
    fn schema_names(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("table", self.table.as_deref()),
            ("column", self.column.as_deref()),
            ("constraint", self.constraint.as_deref()),
        ]
        .into_iter()
        .filter_map(|(what, name)| name.map(|n| (what, n)))
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The primary message, detail, hint and context can quote data, so
        // only the severity, the SQLSTATE, its condition name and schema
        // names appear (R-NF-02). Schema names use Debug quoting, which
        // escapes control characters. Condition names come from the
        // generated table, never from the server.
        write!(f, "{} {}", self.severity, self.code)?;
        if let Some(name) = self.condition_name() {
            write!(f, " {name}")?;
        } else if let Some(class) = self.class_name() {
            write!(f, " class {class}")?;
        }
        let mut sep = " (";
        for (what, name) in self.schema_names() {
            write!(f, "{sep}{what} {name:?}")?;
            sep = ", ";
        }
        if sep == ", " {
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the fields that Display shows; the rest can carry data.
        let mut d = f.debug_struct("DbError");
        d.field("severity", &self.severity)
            .field("code", &self.code)
            .field("condition", &self.condition_name());
        if self.condition_name().is_none() {
            d.field("class", &self.class_name());
        }
        d.field("table", &self.table)
            .field("column", &self.column)
            .field("constraint", &self.constraint)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for DbError {}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn fields(list: &[(u8, &str)]) -> Vec<(u8, Vec<u8>)> {
        list.iter()
            .map(|(t, v)| (*t, v.as_bytes().to_vec()))
            .collect()
    }

    /// R-NF-02: Display and Debug never show the primary message, detail,
    /// hint or where.
    #[test]
    fn r_nf_02_display_hides_detail_hint_and_where() {
        let e = DbError::from_fields(&fields(&[
            (b'S', "FEHLER"),
            (b'V', "ERROR"),
            (b'C', "23505"),
            (
                b'M',
                "duplicate key value violates unique constraint \"t_pkey\" message canary",
            ),
            (b'D', "Key (email)=(canary@example.org) already exists."),
            (b'H', "hint canary"),
            (b'W', "where canary"),
            (b'q', "internal query canary"),
            (b'n', "t_pkey"),
            (b't', "t"),
        ]))
        .unwrap();
        let shown = format!(
            "{e} {e:?} {:?} {}",
            Error::db(e.clone()),
            Error::db(e.clone())
        );
        assert!(!shown.contains("canary"), "{shown}");
        assert_eq!(
            e.to_string(),
            "ERROR 23505 unique_violation (table \"t\", constraint \"t_pkey\")"
        );
        assert!(e.message().contains("message canary"));
        assert_eq!(
            e.detail(),
            Some("Key (email)=(canary@example.org) already exists.")
        );
        assert_eq!(e.severity(), "ERROR");
        assert_eq!(e.constraint(), Some("t_pkey"));
    }

    /// R-NF-02: the primary message of a failed cast quotes the input. It
    /// stays behind `message()`, and Display shows the SQLSTATE only.
    #[test]
    fn review_pg_dberror_display_leaks_values() {
        let e = DbError::from_fields(&fields(&[
            (b'S', "ERROR"),
            (b'C', "22P02"),
            (
                b'M',
                "invalid input syntax for type integer: \"canary@example.org\"",
            ),
        ]))
        .unwrap();
        let shown = format!("{e} {e:?} {}", Error::db(e.clone()));
        assert!(!shown.contains("canary"), "{shown}");
        assert_eq!(e.to_string(), "ERROR 22P02 invalid_text_representation");
        assert!(e.message().contains("canary@example.org"));
        // A schema name with a control character cannot forge a log line.
        let e = DbError::from_fields(&fields(&[
            (b'S', "ERROR"),
            (b'C', "23514"),
            (b'M', "m"),
            (b'c', "col\nfake"),
        ]))
        .unwrap();
        assert_eq!(
            e.to_string(),
            "ERROR 23514 check_violation (column \"col\\nfake\")"
        );
    }

    /// P1, R-NF-02: Display and Debug name the SQLSTATE's standard
    /// condition. A unique violation reads like
    /// `ERROR 23505 unique_violation (table ..., constraint ...)` and shows
    /// no row values.
    #[test]
    fn p1_display_names_the_condition_without_values() {
        let e = DbError::from_fields(&fields(&[
            (b'S', "ERROR"),
            (b'C', "23505"),
            (b'M', "duplicate key value canary"),
            (b'D', "Key (email)=(canary@example.org) already exists."),
            (b's', "public"),
            (b't', "people"),
            (b'n', "people_email_key"),
        ]))
        .unwrap();
        let expected =
            "ERROR 23505 unique_violation (table \"people\", constraint \"people_email_key\")";
        assert_eq!(e.to_string(), expected);
        assert_eq!(Error::db(e.clone()).to_string(), expected);
        let debug = format!("{e:?} {:?}", Error::db(e.clone()));
        assert!(debug.contains("code: \"23505\""), "{debug}");
        assert!(
            debug.contains("condition: Some(\"unique_violation\")"),
            "{debug}"
        );
        assert!(debug.contains("table: Some(\"people\")"), "{debug}");
        assert!(
            debug.contains("constraint: Some(\"people_email_key\")"),
            "{debug}"
        );
        assert!(!debug.contains("canary"), "{debug}");
    }

    /// P1: a SQLSTATE without a condition name shows its class name,
    /// marked `class`, and a code whose class has no name shows only the
    /// code.
    #[test]
    fn p1_unknown_code_shows_its_class_or_only_the_code() {
        let with_class = DbError::from_fields(&fields(&[
            (b'S', "ERROR"),
            (b'C', "23P99"),
            (b'M', "m"),
            (b't', "t"),
        ]))
        .unwrap();
        assert_eq!(
            with_class.to_string(),
            "ERROR 23P99 class integrity_constraint_violation (table \"t\")"
        );
        let debug = format!("{with_class:?}");
        assert!(debug.contains("condition: None"), "{debug}");
        assert!(
            debug.contains("class: Some(\"integrity_constraint_violation\")"),
            "{debug}"
        );
        let unknown =
            DbError::from_fields(&fields(&[(b'S', "ERROR"), (b'C', "ZZ999"), (b'M', "m")]))
                .unwrap();
        assert_eq!(unknown.to_string(), "ERROR ZZ999");
        assert_eq!(
            format!("{unknown:?}"),
            "DbError { severity: \"ERROR\", code: \"ZZ999\", condition: None, class: None, \
             table: None, column: None, constraint: None, .. }"
        );
    }

    #[test]
    fn required_fields_are_checked() {
        assert!(DbError::from_fields(&fields(&[(b'C', "42601"), (b'M', "m")])).is_err());
        assert!(DbError::from_fields(&fields(&[(b'S', "ERROR"), (b'M', "m")])).is_err());
        assert!(DbError::from_fields(&fields(&[(b'S', "ERROR"), (b'C', "42601")])).is_err());
        assert!(
            DbError::from_fields(&fields(&[(b'S', "ERROR"), (b'C', "4260"), (b'M', "m")])).is_err()
        );
        let ok = DbError::from_fields(&fields(&[
            (b'S', "ERROR"),
            (b'C', "42601"),
            (b'M', "m"),
            (b'P', "7"),
            (b'Z', "unknown field type is ignored"),
        ]))
        .unwrap();
        assert_eq!(ok.position(), Some(7));
        assert!(!ok.is_fatal());
    }
}
