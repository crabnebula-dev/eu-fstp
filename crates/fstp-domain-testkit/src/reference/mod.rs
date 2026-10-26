//! Independent references, written from the spec text (design section 6.1).
//!
//! They share only id and record types with production code. Module list
//! from milestone M2 step W0. Each lane owns its own file.

pub mod findings;
pub mod lifecycle;
pub mod money;
pub mod payment;
pub mod policy;
pub mod review;
pub mod scoring;
pub mod sod;
