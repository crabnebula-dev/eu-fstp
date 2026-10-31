//! Query strings of the public routes.

use crate::PublicError;

/// A parsed public query.
///
/// W0 placeholder with no fields. Lane W2c writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicQuery {
    _w0: (),
}

/// Parses the query string of a public route. Fuzzed (`public_query_parse`).
pub fn parse_public_query(bytes: &[u8]) -> Result<PublicQuery, PublicError> {
    let _ = bytes;
    Err(PublicError::NotImplemented(
        "fstp_public::query::parse_public_query",
    ))
}
