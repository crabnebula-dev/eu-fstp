//! In-house SMTP submission client (M6 design section 5.2).
//!
//! - Implicit TLS on port 465 only (RFC 8314), through `fstp-tls`. There is
//!   no STARTTLS, so there is no downgrade path.
//! - [`reply`]: a strict parser for multi-line replies, with bounded line
//!   length and line count.
//! - [`client`]: EHLO, AUTH PLAIN, MAIL, RCPT and DATA. [`client::SmtpClient::stage`]
//!   streams the body without the final dot, so the dispatcher can record
//!   its commit point first. [`client::Staged::commit`] then sends the dot
//!   (I-26).
//! - [`data`]: dot-stuffing and CRLF normalisation of the body, and the
//!   strict decoder the test sink uses.
//! - [`command`] and [`auth`]: the command lines the client writes. The test
//!   sink in `fstp-api-testkit` parses them with the same code.
//!
//! The fuzz project in `fuzz/` holds the targets `smtp_reply` and
//! `smtp_sink_command` (TH-26, H-05).

mod base64;

pub mod auth;
pub mod client;
pub mod command;
pub mod data;
pub mod lines;
pub mod reply;
