//! Request methods (RFC 9110 section 9).

use std::fmt;
use std::str::FromStr;

use crate::chars::is_token;
use crate::error::InvalidInput;

/// A request method. Methods are case-sensitive tokens.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Method(Inner);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Inner {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Extension(Box<str>),
}

impl Method {
    /// GET.
    pub const GET: Method = Method(Inner::Get);
    /// HEAD.
    pub const HEAD: Method = Method(Inner::Head);
    /// POST.
    pub const POST: Method = Method(Inner::Post);
    /// PUT.
    pub const PUT: Method = Method(Inner::Put);
    /// DELETE.
    pub const DELETE: Method = Method(Inner::Delete);
    /// CONNECT. The parser rejects it with 501, since tunnels are out of
    /// scope.
    pub const CONNECT: Method = Method(Inner::Connect);
    /// OPTIONS.
    pub const OPTIONS: Method = Method(Inner::Options);
    /// TRACE.
    pub const TRACE: Method = Method(Inner::Trace);
    /// PATCH (RFC 5789).
    pub const PATCH: Method = Method(Inner::Patch);

    /// Parses a method token.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidInput`] when `b` is empty or not a token.
    pub fn from_bytes(b: &[u8]) -> Result<Method, InvalidInput> {
        Ok(Method(match b {
            b"GET" => Inner::Get,
            b"HEAD" => Inner::Head,
            b"POST" => Inner::Post,
            b"PUT" => Inner::Put,
            b"DELETE" => Inner::Delete,
            b"CONNECT" => Inner::Connect,
            b"OPTIONS" => Inner::Options,
            b"TRACE" => Inner::Trace,
            b"PATCH" => Inner::Patch,
            _ => {
                if !is_token(b) {
                    return Err(InvalidInput::new("method is not a token"));
                }
                // A token is ASCII, so this conversion cannot fail.
                let s = std::str::from_utf8(b)
                    .map_err(|_| InvalidInput::new("method is not a token"))?;
                Inner::Extension(s.into())
            }
        }))
    }

    /// The method as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Inner::Get => "GET",
            Inner::Head => "HEAD",
            Inner::Post => "POST",
            Inner::Put => "PUT",
            Inner::Delete => "DELETE",
            Inner::Connect => "CONNECT",
            Inner::Options => "OPTIONS",
            Inner::Trace => "TRACE",
            Inner::Patch => "PATCH",
            Inner::Extension(s) => s,
        }
    }

    /// True for methods whose repetition has the same effect as one
    /// request (RFC 9110 section 9.2.2). The client retries only these.
    #[must_use]
    pub fn is_idempotent(&self) -> bool {
        matches!(
            self.0,
            Inner::Get | Inner::Head | Inner::Put | Inner::Delete | Inner::Options | Inner::Trace
        )
    }
}

impl FromStr for Method {
    type Err = InvalidInput;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Method::from_bytes(s.as_bytes())
    }
}

impl fmt::Debug for Method {
    /// A standard method prints its name, such as `Method(GET)`. An
    /// extension method prints `Method(<extension>)`, since a client
    /// chooses its name freely and it could carry content (R-NF-02).
    /// [`fmt::Display`] prints every name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Inner::Extension(_) => f.write_str("Method(<extension>)"),
            _ => write!(f, "Method({})", self.as_str()),
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_and_extension() {
        assert_eq!(Method::from_bytes(b"GET").unwrap(), Method::GET);
        assert_eq!(
            Method::from_bytes(b"PROPFIND").unwrap().as_str(),
            "PROPFIND"
        );
        assert_ne!(Method::from_bytes(b"get").unwrap(), Method::GET);
        assert!(Method::from_bytes(b"").is_err());
        assert!(Method::from_bytes(b"G T").is_err());
        assert!(Method::from_bytes(b"GET\r\n").is_err());
        assert!(Method::PUT.is_idempotent());
        assert!(!Method::POST.is_idempotent());
    }

    /// R-NF-02, review finding debug-prints-client-chosen-names.
    #[test]
    fn review_debug_prints_client_chosen_names_method() {
        let m = Method::from_bytes(b"CANARYSECRET").unwrap();
        assert_eq!(format!("{m:?}"), "Method(<extension>)");
        assert_eq!(m.to_string(), "CANARYSECRET");
        assert_eq!(format!("{:?}", Method::PATCH), "Method(PATCH)");
        assert_eq!(format!("{:?}", Method::CONNECT), "Method(CONNECT)");
    }
}
