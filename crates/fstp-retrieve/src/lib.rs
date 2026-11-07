//! GET-only retrieval proxy for claim verification (M7 design section 3.2,
//! lane L-RETR, TH-12).
//!
//! # Parts
//!
//! - [`SourceUrl`]: a strict absolute URL parser with one canonical form.
//! - [`DestinationPolicy`]: the hosts the proxy may reach. IP literals,
//!   local names, unlisted hosts and non-default ports are refused. M7
//!   reaches the fixture server only ([`DestinationPolicy::fixture`]).
//! - [`Retriever`]: GET only, no name resolution, a pinned upstream,
//!   redirects checked again, and size and time limits.
//! - [`decode_body`] and [`html_to_text`]: media type and charset checks
//!   and an in-house HTML-to-text converter that drops scripts, styles,
//!   comments and attributes.
//! - [`ApplicantSources`] and [`th12_rule`]: source classing and the rule
//!   that refuses `verified` on applicant-controlled sources alone.
//! - [`Outcome`] and [`router`]: the wire form and the proxy endpoint.
//!
//! # Untrusted data (TH-01, TH-12)
//!
//! Retrieved text is held as [`fstp_findings::UntrustedText`]. It goes to
//! a model only through the data channel of `fstp-infer`, never into an
//! instruction.
//!
//! # Fuzzing
//!
//! The cargo-fuzz project in `fuzz/` has three targets: `retrieve_html_text`,
//! `retrieve_http_body` and `retrieve_url`.

mod body;
mod classing;
mod fetch;
mod html;
mod policy;
mod refusal;
mod url;
mod wire;

pub use crate::body::decode_body;
pub use crate::classing::{ApplicantSources, Basis, ClaimVerdict, Ruling, SourceClass, th12_rule};
pub use crate::fetch::{RetrieveConfig, Retrieved, Retriever};
pub use crate::html::{PlainText, html_to_text};
pub use crate::policy::DestinationPolicy;
pub use crate::refusal::Refusal;
pub use crate::url::{MAX_URL_BYTES, SourceUrl, UrlScheme};
pub use crate::wire::{Outcome, RETRIEVE_PATH, query_for, router, url_param};
