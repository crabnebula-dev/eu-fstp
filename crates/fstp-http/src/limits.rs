//! Explicit parser limits.

/// Size and count limits that every decoder enforces.
///
/// A violation maps to a status code through
/// [`ParseErrorKind::status`](crate::ParseErrorKind::status): 414 for the
/// request line, 431 for header and trailer sections, 413 for bodies and
/// chunks, and 400 for chunk-size lines and extensions.
///
/// Zero values are allowed and simply reject the corresponding element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest request line or status line, in bytes, without CRLF.
    pub max_start_line: usize,
    /// Most empty lines accepted before a request line (RFC 9112 section
    /// 2.2 asks servers to ignore at least one).
    pub max_leading_empty_lines: usize,
    /// Most header fields.
    pub max_headers: usize,
    /// Largest header section, in bytes, counting every field line with its
    /// CRLF and excluding the start line and the final empty line.
    pub max_header_bytes: usize,
    /// Largest body, in bytes, after chunked decoding.
    pub max_body_bytes: u64,
    /// Largest single chunk, in bytes.
    pub max_chunk_size: u64,
    /// Longest chunk-size line, in bytes, without CRLF. It bounds the
    /// extensions of one chunk. The size itself has at most 16 hex digits,
    /// leading zeros included, whatever this limit says.
    pub max_chunk_line: usize,
    /// Largest total of chunk extension bytes over one message.
    pub max_chunk_ext_bytes: usize,
    /// Most trailer fields.
    pub max_trailers: usize,
    /// Largest trailer section, in bytes, counted like `max_header_bytes`.
    pub max_trailer_bytes: usize,
}

impl Default for Limits {
    /// Conservative defaults for an API server:
    ///
    /// - a request line of at most 8 KiB;
    /// - at most 100 header fields in at most 16 KiB;
    /// - a body of at most 1 MiB;
    /// - chunk-size lines of at most 1 KiB, with at most 4 KiB of
    ///   extensions per message;
    /// - at most 32 trailer fields in at most 8 KiB.
    fn default() -> Self {
        Self {
            max_start_line: 8 * 1024,
            max_leading_empty_lines: 1,
            max_headers: 100,
            max_header_bytes: 16 * 1024,
            max_body_bytes: 1024 * 1024,
            max_chunk_size: 1024 * 1024,
            max_chunk_line: 1024,
            max_chunk_ext_bytes: 4 * 1024,
            max_trailers: 32,
            max_trailer_bytes: 8 * 1024,
        }
    }
}
