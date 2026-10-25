//! Sans-IO codec for PostgreSQL protocol 3.0.
//!
//! - [`frontend`] encodes every message this client sends.
//! - [`backend`] frames and decodes every message the server may send, with
//!   strict length checks and a maximum message size. It also encodes them,
//!   for test servers and round-trip checks.
//!
//! Nothing here performs IO. The connection code in this crate moves bytes
//! between these functions and a transport.

pub mod backend;
mod cursor;
pub mod frontend;

/// Protocol version 3.0, as sent in the StartupMessage.
pub const PROTOCOL_VERSION: i32 = 196_608;

/// The request code of an SSLRequest.
pub const SSL_REQUEST_CODE: i32 = 80_877_103;

/// The request code of a CancelRequest.
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;

/// The request code of a GSSENCRequest. This client never sends it; the
/// constant documents the value it must not confuse with others.
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;
