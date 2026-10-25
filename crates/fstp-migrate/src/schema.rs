//! The name of the schema that holds the migration ledger.
//!
//! The schema is configurable (P4). The name stays a plain lowercase
//! identifier, so it needs no case folding and cannot carry SQL syntax.
//! It never enters SQL text on the client: the runner sends it as a bind
//! parameter, and the server quotes it with `format('%I', ...)` where a
//! statement needs it as an identifier.

use std::fmt;

/// The ledger schema that [`LedgerSchema::default`] names.
pub const DEFAULT_LEDGER_SCHEMA: &str = "fstp_migrate";

/// The most bytes a ledger schema name may have. PostgreSQL truncates
/// longer identifiers to this length (`NAMEDATALEN` minus one in a
/// default build).
pub const MAX_LEDGER_SCHEMA_LEN: usize = 63;

/// A validated name for the schema that holds the migration ledger.
///
/// A valid name matches `[a-z_][a-z0-9_]*`, has at most
/// [`MAX_LEDGER_SCHEMA_LEN`] bytes, does not start with `pg_` and is not
/// `information_schema`. PostgreSQL reserves both for system schemas,
/// and `pg_temp` would name the session's temporary schema. An SQL
/// keyword such as `order` is valid: the server quotes the name whenever
/// it uses it as an identifier.
///
/// The default is [`DEFAULT_LEDGER_SCHEMA`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerSchema {
    name: String,
}

impl LedgerSchema {
    /// Validates `name` as a ledger schema name.
    ///
    /// # Errors
    ///
    /// Returns the first rule that `name` breaks. The error never quotes
    /// the name.
    pub fn new(name: &str) -> Result<LedgerSchema, LedgerSchemaError> {
        validate(name)?;
        Ok(LedgerSchema {
            name: name.to_owned(),
        })
    }

    /// The schema name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl Default for LedgerSchema {
    fn default() -> Self {
        LedgerSchema {
            name: DEFAULT_LEDGER_SCHEMA.to_owned(),
        }
    }
}

impl fmt::Display for LedgerSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Why [`LedgerSchema::new`] refused a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LedgerSchemaError {
    /// The name is empty.
    Empty,
    /// The name has more than [`MAX_LEDGER_SCHEMA_LEN`] bytes.
    TooLong {
        /// The name's length in bytes.
        len: usize,
    },
    /// The byte at `offset` is not allowed there. The first byte must be
    /// `a` to `z` or `_`, and later bytes may also be `0` to `9`.
    InvalidByte {
        /// The 0-based byte offset.
        offset: usize,
    },
    /// The name starts with `pg_` or is `information_schema`, which
    /// PostgreSQL reserves for system schemas.
    Reserved,
}

impl fmt::Display for LedgerSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the ledger schema name is empty"),
            Self::TooLong { len } => write!(
                f,
                "the ledger schema name has {len} bytes, more than the {MAX_LEDGER_SCHEMA_LEN} \
                 allowed"
            ),
            Self::InvalidByte { offset } => write!(
                f,
                "the ledger schema name has a byte at offset {offset} outside [a-z_][a-z0-9_]*"
            ),
            Self::Reserved => f.write_str(
                "the ledger schema name starts with pg_ or is information_schema, which \
                 PostgreSQL reserves for system schemas",
            ),
        }
    }
}

impl std::error::Error for LedgerSchemaError {}

fn validate(name: &str) -> Result<(), LedgerSchemaError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(LedgerSchemaError::Empty);
    }
    if bytes.len() > MAX_LEDGER_SCHEMA_LEN {
        return Err(LedgerSchemaError::TooLong { len: bytes.len() });
    }
    for (offset, &b) in bytes.iter().enumerate() {
        let allowed = b.is_ascii_lowercase() || b == b'_' || (offset > 0 && b.is_ascii_digit());
        if !allowed {
            return Err(LedgerSchemaError::InvalidByte { offset });
        }
    }
    if name.starts_with("pg_") || name == "information_schema" {
        return Err(LedgerSchemaError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_fstp_migrate_and_valid() {
        assert_eq!(LedgerSchema::default().as_str(), DEFAULT_LEDGER_SCHEMA);
        assert_eq!(
            LedgerSchema::new(DEFAULT_LEDGER_SCHEMA),
            Ok(LedgerSchema::default())
        );
    }

    #[test]
    fn plain_lowercase_identifiers_are_accepted() {
        for name in [
            "a",
            "_",
            "app_ledger",
            "order",
            "x1",
            "pg",
            "pgx_a",
            "_pg_x",
        ] {
            assert_eq!(
                LedgerSchema::new(name).map(|s| s.to_string()),
                Ok(name.into())
            );
        }
        let longest = "a".repeat(MAX_LEDGER_SCHEMA_LEN);
        assert!(LedgerSchema::new(&longest).is_ok());
    }

    #[test]
    fn other_names_are_refused() {
        use LedgerSchemaError::{Empty, InvalidByte, Reserved, TooLong};
        let cases: &[(&str, LedgerSchemaError)] = &[
            ("", Empty),
            ("1a", InvalidByte { offset: 0 }),
            ("App", InvalidByte { offset: 0 }),
            ("a-b", InvalidByte { offset: 1 }),
            ("a.b", InvalidByte { offset: 1 }),
            ("a b", InvalidByte { offset: 1 }),
            ("ab\"", InvalidByte { offset: 2 }),
            ("a;", InvalidByte { offset: 1 }),
            ("a'", InvalidByte { offset: 1 }),
            ("a\0", InvalidByte { offset: 1 }),
            ("\u{e9}", InvalidByte { offset: 0 }),
            ("pg_", Reserved),
            ("pg_catalog", Reserved),
            ("pg_temp", Reserved),
            ("information_schema", Reserved),
        ];
        for (name, want) in cases {
            assert_eq!(LedgerSchema::new(name), Err(*want), "{name:?}");
        }
        let long = "a".repeat(MAX_LEDGER_SCHEMA_LEN + 1);
        assert_eq!(LedgerSchema::new(&long), Err(TooLong { len: 64 }));
    }
}
