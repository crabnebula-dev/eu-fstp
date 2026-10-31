//! Key hierarchy model, envelope formats, group and epoch state, and the
//! erasure planner (M3 design section 3, ADR-004).
//!
//! The crate is pure. It does no I/O and holds no custody client
//! (design section 2.4 rule 1). Every cryptographic operation goes
//! through `fstp-crypto`.
//!
//! - [`hierarchy`]: chains, purposes and their frozen codes, and ids.
//! - [`envelope`]: the FSK1 sealed key of ADR-004 part 1 and the sealed
//!   blob, with [`envelope::DataKey`] and its seal count.
//! - [`erasure`]: the chain state and the planner of the seven erasure
//!   steps of ADR-004 part 2 (I-81).

pub mod envelope;
pub mod erasure;
pub mod hierarchy;

pub use hierarchy::{CellId, Chain, DekId, Epoch, GroupId, ObjectId, Purpose};
