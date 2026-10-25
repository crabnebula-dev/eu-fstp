//! In-house JSON and NDJSON parser and serializer.
//!
//! This crate is the JSON component of the build approach in
//! `03-architecture/overview.md`. The API, tenant export files
//! (`schemas/README.md`), adapters and the PostgreSQL `jsonb` codec share it.
//!
//! # Parsing
//!
//! [`parse`] and [`parse_with`] accept exactly RFC 8259 JSON texts with the
//! I-JSON restrictions of RFC 7493:
//!
//! - the input must be valid UTF-8, and a byte order mark is rejected;
//! - object member names must be unique;
//! - `\u` escapes of lone surrogates are rejected;
//! - trailing commas, comments, `NaN`, `Infinity`, leading zeros and
//!   whitespace other than space, tab, line feed and carriage return are
//!   rejected;
//! - any value may be the top-level value.
//!
//! Every resource is bounded by [`ParseLimits`], including the estimated
//! memory of the parsed value. The parser never recurses, so input cannot
//! overflow the stack, and it runs in expected linear time.
//! A [`ParseError`] carries the byte offset, line and column, and never any
//! input content (R-NF-02). Fuzz targets under `fuzz/` cover the parser,
//! the NDJSON reader, typed mapping and canonical output (TH-26, H-05).
//!
//! # Values
//!
//! A [`Value`] is a tree of [`Array`], [`Object`], [`Number`], strings,
//! booleans and null. A [`Number`] keeps its exact lexeme, offers checked
//! integer accessors, an explicitly lossy float accessor and an exact
//! [`Decimal`] for money. An [`Object`] keeps member order and supports
//! lookup by name. Drop, clone, equality and serialization never recurse, so
//! a value of any depth is safe.
//!
//! # Serializing
//!
//! - [`to_compact`]: no whitespace, members in stored order, number lexemes
//!   unchanged. Byte-stable.
//! - [`to_pretty`]: indented, members in stored order.
//! - [`to_canonical`]: RFC 8785 (JCS). Members sorted by UTF-16 code units,
//!   JCS string escaping, ECMAScript number formatting. This is the form for
//!   content hashes and signatures. By default it rejects numbers whose
//!   canonical form would denote a different value (see [`CanonicalOptions`]).
//!
//! No serializer emits a raw control character. [`WriteOptions::escape_html`]
//! also escapes `<`, `>`, `&`, U+2028 and U+2029 for embedding in HTML.
//!
//! # NDJSON
//!
//! [`NdjsonReader`] streams values from a [`std::io::BufRead`] with a line
//! length limit and line-numbered errors. It accepts LF and CRLF and rejects
//! blank lines. [`NdjsonWriter`] writes one compact value per line.
//!
//! # Typed mapping
//!
//! [`ToJson`] and [`FromJson`] map Rust types without serde. [`json!`]
//! builds values. [`json_struct!`] maps structs with named fields, with
//! required and optional fields, and rejects unknown members by default.
//! A [`FromJsonError`] reports a path such as `$.calls[2].deadline`.
//!
//! ```
//! use fstp_json::{FromJson, ToJson, json, json_struct, parse, to_canonical};
//!
//! #[derive(Debug, PartialEq)]
//! struct Payment { id: String, amount: fstp_json::Decimal, note: Option<String> }
//! json_struct!(Payment { required id, required amount, optional note });
//!
//! let v = parse(br#"{"id": "p-1", "amount": 1250.00}"#).unwrap();
//! let p = Payment::from_json(&v).unwrap();
//! assert_eq!(p.amount.to_scaled_i128(2), Ok(125000));
//! assert_eq!(to_canonical(&p.to_json()).unwrap(), r#"{"amount":1250,"id":"p-1"}"#);
//! assert_eq!(json!({"id": "p-1"}).get("id").and_then(|v| v.as_str()), Some("p-1"));
//! ```

mod macros;
mod ndjson;
mod number;
mod object;
mod parse;
mod path;
mod ser;
pub mod typed;
mod value;

pub use ndjson::{NdjsonError, NdjsonErrorKind, NdjsonOptions, NdjsonReader, NdjsonWriter};
pub use number::{Decimal, DecimalError, Number, NumberError};
pub use object::{DuplicateKey, Iter as ObjectIter, Object};
pub use parse::{Limit, ParseError, ParseErrorKind, ParseLimits, parse, parse_str, parse_with};
pub use path::{Path, Segment};
pub use ser::{
    CanonicalError, CanonicalErrorKind, CanonicalOptions, WriteOptions, cmp_utf16, to_canonical,
    to_canonical_with, to_compact, to_pretty, to_string_with, write_value,
};
pub use typed::{FromJson, FromJsonError, FromJsonErrorKind, ToJson};
pub use value::{Array, Value};
