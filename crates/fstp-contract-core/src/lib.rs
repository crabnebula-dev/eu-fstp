//! The pure core of contracts (M5 design sections 3 and 4.1, lane L-CON;
//! `SPEC/02-domain/contracts.md`).
//!
//! - [`model`]: parties, routes and the folded contract store;
//! - [`record`]: the records of the `Contract` ledger envelope and their
//!   stored JSON form;
//! - [`decide`](mod@decide): the contract commands and their rules, with
//!   I-30 at the centre: a signed version is immutable, and any change is
//!   a new version signed by all parties;
//! - [`digest`]: the SHA-256 digest value and its stored spelling.
//!
//! `fstp-engine` reaches contracts through this crate only, so it stays
//! free of I/O and of third-party crates (M2 layering rule 1). The crate
//! computes no digest and does no cryptography. Every digest the fold
//! records arrives as a value that the shell side computed. PDF rendering,
//! blob storage, the `SignaturePort` and signing stay in `fstp-contract`.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod decide;
pub mod digest;
pub mod model;
pub mod record;

pub use decide::{ContractCommand, ContractFoldError, ContractRefusal, apply, decide};
pub use digest::Digest;
pub use model::{
    ChangeStatus, Contract, ContractStatus, ContractStore, Party, PartyRole, Route, Side, Version,
    VersionState,
};
pub use record::ContractRecord;
