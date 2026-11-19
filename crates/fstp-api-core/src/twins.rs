//! I-86 `i86_identity_types_are_not_mcp_safe`: compile-fail twins for the
//! types that hold identity data or vault facts (M4 design section 8.4).
//!
//! This module holds doc comments only. It is compiled under
//! `cfg(doctest)` alone, so it adds nothing to the library. It follows
//! the twin pattern of `fstp-creator/src/twins.rs`.
//!
//! `fstp_mcp::McpResponse::new` takes only a `T: McpSafe` (design section
//! 3.8). Each test below asks for the same bound, so a type that fails it
//! can never become an MCP response. The pinned stable rustdoc ignores
//! `compile_fail` error codes. So each forbidden line gets a
//! `compile_fail` doctest and a `no_run` twin. The twin names the same
//! type, differs only in that one line, and must compile. A typo in the
//! shared text then breaks the twin, so no pair passes vacuously. The
//! first pair shows that the bound admits an `McpSafe` read model.
//!
//! The design names `VaultBound<T>`, `IdentityAttribute`, `BankDetails`,
//! `VaultOutcomeRow` and `AccountContact`. Of these, only `VaultBound<T>`
//! and `VaultOutcomeRow` exist. The others are covered as follows, a
//! reading for Daniel to confirm:
//!
//! - `IdentityAttribute`: the identity attributes this crate holds are the
//!   stated country (`port::CountryCode`) and the declared affiliations
//!   (`port::Affiliations`), both for the vault only (R-NG-01).
//! - `AccountContact`: the account contact this crate holds is the
//!   invitation email of an unmask log row (`unmask::UnmaskRow::contact`).
//! - `BankDetails`: this crate holds no bank detail type. Bank details
//!   exist only as a vault fact in `fstp-vault-core`, which neither this
//!   crate nor `fstp-mcp` may name (layering rule A5). No twin is
//!   possible here.
//!
//! The blanket `impl McpSafe for ReadModel` still covers the audit and
//! unmask variants of `ReadModel`. Those reads have no tool, and the
//! dispatch guard refuses them through MCP (`ReadModel::carries_email`
//! and the registry tests).
//!
//! # The bound admits an `McpSafe` read model and refuses a port type
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::Receipt) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::views::ProposalRow) {
//!     need(v)
//! }
//! ```
//!
//! # `VaultBound<T>` is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::VaultBound<u8>) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::VaultBound<u8>) {
//!     let _ = v;
//! }
//! ```
//!
//! # `VaultBound<T>` of a safe model is not `McpSafe` either
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::VaultBound<fstp_api_core::views::ProposalRow>) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::VaultBound<fstp_api_core::views::ProposalRow>) {
//!     let _ = v;
//! }
//! ```
//!
//! # The stated country is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::CountryCode) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::CountryCode) {
//!     let _ = v;
//! }
//! ```
//!
//! # The declared affiliations are not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::Affiliations) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::port::Affiliations) {
//!     let _ = v;
//! }
//! ```
//!
//! # `VaultOutcomeRow` is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::VaultOutcomeRow) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::VaultOutcomeRow) {
//!     let _ = v;
//! }
//! ```
//!
//! # The vault outcomes of a programme are not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::VaultOutcomes) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::VaultOutcomes) {
//!     let _ = v;
//! }
//! ```
//!
//! # The audit model is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::AuditModel) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::audit::AuditModel) {
//!     let _ = v;
//! }
//! ```
//!
//! # An unmask row, with its account contact, is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::unmask::UnmaskRow) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::unmask::UnmaskRow) {
//!     let _ = v;
//! }
//! ```
//!
//! # The unmask model is not `McpSafe`
//!
//! ```compile_fail
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::unmask::UnmaskModel) {
//!     need(v)
//! }
//! ```
//!
//! ```no_run
//! fn need<T: fstp_api_core::McpSafe>(_: &T) {}
//! fn leak(v: &fstp_api_core::unmask::UnmaskModel) {
//!     let _ = v;
//! }
//! ```
