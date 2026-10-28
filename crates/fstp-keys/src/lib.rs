//! Key hierarchy model, envelope formats, group and epoch state, and the
//! erasure planner (M3 design section 3, ADR-004).
//!
//! The crate is pure. It does no I/O and holds no custody client.
//!
//! Status: W0 stub. Lane W2f fills it. The sealing functions of design
//! section 3.2 wait for `fstp_crypto::hybrid_kem`, which lane W1h builds
//! with moduletto (seam recorded in `docs/handoff/m3-base.md`). Until then
//! only the decoders and the erasure state types exist, and each operation
//! refuses with a typed `NotImplemented` error.

pub mod envelope;
pub mod erasure;
pub mod hierarchy;

pub use hierarchy::{CellId, Chain, DekId, Epoch, GroupId, ObjectId, Purpose};
