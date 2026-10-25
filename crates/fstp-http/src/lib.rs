//! In-house HTTP/1.1 server and client with a sans-IO, fuzzed message parser.
//!
//! # Scope
//!
//! This crate implements HTTP/1.1 (RFC 9110 and RFC 9112) only. HTTP/2 and
//! HTTP/3 are out of scope for M1, and so are CONNECT tunnels, protocol
//! upgrades and transfer codings other than chunked.
//!
//! # Layers
//!
//! - A sans-IO core that never touches a socket: the incremental decoders
//!   [`RequestDecoder`], [`ResponseDecoder`] and [`ChunkedDecoder`], the
//!   whole-buffer helpers [`parse_request`] and [`parse_response`], and the
//!   encoders [`encode_request`] and [`encode_response`].
//! - A [`Server`] driver over any [`fstp_rt::Runtime`], with optional TLS
//!   and mutual TLS through `fstp-tls`, a [`Handler`] trait and a small
//!   [`Router`].
//! - A [`Client`] driver with connection reuse per authority.
//!
//! Bodies are fully buffered up to a configured limit in M1.
//!
//! # Decoders
//!
//! A decoder owns a byte buffer. The caller appends input with `feed`,
//! signals the end of the stream with `feed_eof`, and pulls events with
//! `next_event`:
//!
//! - `Ok(Some(event))`: a head, a piece of body data, or the end of a
//!   message with its trailers.
//! - `Ok(None)`: more input is needed, or the stream ended cleanly between
//!   messages.
//! - `Err(e)`: the input violates the grammar, a framing rule or a limit.
//!   The error is sticky: every later call returns it again.
//!
//! The result does not depend on how the input is split across `feed`
//! calls. The same bytes give the same heads, the same concatenated body,
//! the same trailers and the same error, for any split. Body data may
//! arrive in differently sized pieces, and a failing message may yield a
//! different amount of body data before its error.
//!
//! Callers bound memory by feeding more input only after `next_event`
//! returned `Ok(None)`. A line that cannot fit its limit is rejected as soon
//! as enough bytes arrived to prove it. After a message ends, the decoder
//! parses the next one from the bytes that follow (keep-alive and
//! pipelining).
//!
//! # Strict parsing (TH-26, H-05)
//!
//! The decoders follow the grammar strictly. Anything another parser could
//! read differently is rejected, which defends against request smuggling.
//!
//! | Input | Error kind | Status |
//! | --- | --- | --- |
//! | LF without CR, or CR inside a line | `BareLf`, `BareCr` | 400 |
//! | More than one space between request-line parts | `InvalidRequestLine` | 400 |
//! | Whitespace between field name and colon | `WhitespaceBeforeColon` | 400 |
//! | Field line starting with whitespace (obs-fold) | `ObsoleteLineFolding` | 400 |
//! | NUL, control bytes or DEL in a field value | `InvalidHeaderValue` | 400 |
//! | HTTP/1.1 request without exactly one valid Host | `MissingHost`, `MultipleHost`, `InvalidHost` | 400 |
//! | Content-Length together with Transfer-Encoding | `ContentLengthWithTransferEncoding` | 400 |
//! | More than one Content-Length field line | `MultipleContentLength` | 400 |
//! | Content-Length that is not plain digits | `InvalidContentLength` | 400 |
//! | Final transfer coding other than chunked | `TransferEncodingNotChunked` | 400 |
//! | Chunked applied twice, or a malformed coding list | `ChunkedAppliedTwice`, `InvalidTransferEncoding` | 400 |
//! | Another coding before chunked | `UnsupportedTransferCoding` | 501 |
//! | Transfer-Encoding in HTTP/1.0 | `TransferEncodingInHttp10` | 400 |
//! | Expectation other than `100-continue` | `UnsupportedExpectation` | 417 |
//! | CONNECT | `UnsupportedMethod` | 501 |
//! | HTTP major version other than 1 | `UnsupportedVersion` | 505 |
//! | Request line over [`Limits::max_start_line`] | `RequestLineTooLong` | 414 |
//! | Header count or size over the limits | `TooManyHeaders`, `HeaderSectionTooLarge` | 431 |
//! | Trailer count or size over the limits | `TooManyTrailers`, `TrailerSectionTooLarge` | 431 |
//! | Body or chunk over the limits | `BodyTooLarge`, `ChunkTooLarge` | 413 |
//! | Chunk-size line or extensions over the limits | `ChunkLineTooLong`, `ChunkExtensionsTooLarge` | 400 |
//! | Chunk size over 16 hex digits, leading zeros included | `InvalidChunkSize` | 400 |
//! | Chunk size above `u64::MAX`, whatever the limits | `ChunkTooLarge` | 413 |
//!
//! Every limit is explicit and configurable through [`Limits`]. The decoders
//! give the same result for any split of the input into pieces.
//!
//! The encoders check every header name and value again before writing, so
//! CR or LF injection (response splitting) is impossible through the API.
//!
//! # Privacy (R-NF-02)
//!
//! The crate never logs. Errors name the rule that failed and never quote
//! message bytes. `Debug` output of messages and header lists redacts
//! values, bodies and targets. It also hides extension method names and
//! field names outside a fixed list of registered names. The server
//! reports content-free [`ServerEvent`]s to an optional hook.
//!
//! # Fuzzing
//!
//! The cargo-fuzz project in `fuzz/` has five targets:
//!
//! - `http_request_parse`, with a differential check over input splits;
//! - `http_response_parse`;
//! - `http_chunked_decode`, against a reference decoder;
//! - `http_header_value`: the encoder never emits CR or LF inside a field;
//! - `http_router_path`: the [`Router`] path decoder and dispatch against
//!   a reference decoder and matcher.

mod chars;
mod client;
mod decode;
mod encode;
mod error;
mod handler;
mod header;
mod io;
mod limits;
mod message;
mod method;
mod router;
mod server;
mod status;
mod target;
mod version;

pub use crate::client::{Client, ClientConfig, ClientError, ClientPhase};
pub use crate::decode::{
    ChunkedDecoder, ChunkedEvent, Parsed, RequestDecoder, RequestEvent, ResponseDecoder,
    ResponseEvent, parse_request, parse_response,
};
pub use crate::encode::{
    CONTINUE_RESPONSE, Framing, SerializeError, encode_request, encode_response,
};
pub use crate::error::{InvalidInput, ParseError, ParseErrorKind};
pub use crate::handler::{Handler, HandlerFn, handler_fn};
pub use crate::header::{HeaderName, HeaderValue, Headers};
pub use crate::limits::Limits;
pub use crate::message::{BodyKind, Request, RequestHead, Response, ResponseHead};
pub use crate::method::Method;
pub use crate::router::{RouteError, Router};
pub use crate::server::{EventHook, Server, ServerConfig, ServerEvent, ServerHandle, TimeoutPhase};
pub use crate::status::StatusCode;
pub use crate::target::{Authority, RequestTarget, Scheme, TargetForm};
pub use crate::version::Version;
