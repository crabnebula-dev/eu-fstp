//! Contracts: records, versions, PDFs and signatures (M5 design sections
//! 3 and 4.1, lane L-CON; `SPEC/02-domain/contracts.md`).
//!
//! - [`model`]: parties, routes and the folded contract store;
//! - [`record`]: the records of the `Contract` ledger envelope and their
//!   stored JSON form;
//! - [`decide`](mod@decide): the contract commands and their rules, with
//!   I-30 at the centre: a signed version is immutable, and any change is
//!   a new version signed by all parties;
//! - [`render`](mod@render): the deterministic contract PDF through
//!   `fstp-pdf` (R-CT-01);
//! - [`blob`]: write-once storage of PDF revisions by SHA-256;
//! - [`port`] and [`fake`]: the `SignaturePort`, its production adapter
//!   that refuses with a typed error (M5 design 12.1, Q2), and the fake
//!   wallet, QTSP and trusted list for tests and the demo;
//! - [`signing`]: one signature over a verified increment, validated by
//!   `fstp-sigval` from the stored bytes.
//!
//! The crate never creates a party's signature in production. The fake
//! adapter signs only with its own test CA (`contracts.md` Signature).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

pub mod blob;
pub mod decide;
pub mod digest;
pub mod fake;
pub mod model;
pub mod port;
pub mod record;
pub mod render;
pub mod signing;

pub use blob::{BlobError, BlobKind, BlobStore, MemBlobStore};
pub use decide::{ContractCommand, ContractFoldError, ContractRefusal, apply, decide};
pub use digest::Digest;
pub use model::{
    ChangeStatus, Contract, ContractStatus, ContractStore, Party, PartyRole, Route, Side, Version,
    VersionState,
};
pub use port::{ProductionSignaturePort, SignatureError, SignaturePort, SignerRef};
pub use record::ContractRecord;
pub use render::{ContractTerms, RenderError, TermsBlock, render};
pub use signing::{Signed, SigningError, sign_increment, verify_revision_chain};
