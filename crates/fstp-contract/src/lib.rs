//! Contracts: records, versions, PDFs and signatures (M5 design sections
//! 3 and 4.1, lane L-CON; `SPEC/02-domain/contracts.md`).
//!
//! - [`model`], [`record`] and [`decide`](mod@decide): the pure core,
//!   re-exported from `fstp-contract-core`. It holds the parties, the
//!   `Contract` envelope records, the commands under I-30 and the fold.
//!   `fstp-engine` depends on the core only (M2 layering rule 1);
//! - [`digest`]: SHA-256 through `fstp-crypto`, for the digests the fold
//!   records;
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
pub mod digest;
pub mod fake;
pub mod port;
pub mod render;
pub mod signing;

pub use fstp_contract_core::{decide, model, record};

pub use blob::{BlobError, BlobKind, BlobStore, MemBlobStore};
// `decide` above names both the module and the function of the core.
pub use decide::{ContractCommand, ContractFoldError, ContractRefusal, apply};
pub use digest::Digest;
pub use model::{
    ChangeStatus, Contract, ContractStatus, ContractStore, Party, PartyRole, Route, Side, Version,
    VersionState,
};
pub use port::{ProductionSignaturePort, SignatureError, SignaturePort, SignerRef};
pub use record::ContractRecord;
pub use render::{ContractTerms, RenderError, TermsBlock, render};
pub use signing::{Signed, SigningError, required_level, sign_increment, verify_revision_chain};
