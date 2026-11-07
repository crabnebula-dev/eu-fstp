//! The M6 dispatcher (M6 design section 5.1, I-25, I-26).
//!
//! - [`store`]: the in-memory model of the delivery log `ops.delivery`
//!   that the crash tests run against (lane L6-REC).
//! - [`worker`]: the dispatch worker. Claims under a lease, staging
//!   without the final dot, the COMMITTING row before the dot, IN_DOUBT on
//!   an unknown outcome, the attempt number as fencing token, and
//!   recovery (lane L6-DISP).
//! - [`prepare`]: S2, the envelope, event and template version of a
//!   stored message.
//! - [`smtp`]: the worker's transport over `fstp-smtp`.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod prepare;
pub mod smtp;
pub mod store;
pub mod worker;

pub use prepare::{Envelope, PrepareError, Prepared, prepare};
pub use smtp::SmtpTransport;
pub use worker::{
    DigestKey, EndOfData, LoadError, Outcome, Refused, Source, Step, Store, Transport, Worker,
    body_digest,
};
