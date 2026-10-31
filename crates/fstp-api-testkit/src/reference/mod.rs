//! Independent references, written from the spec text (M4 design section
//! 8). They share only id and record types with production code. Module
//! list from M4 step W0. Each lane owns its own file.

pub mod authz;
pub mod creator;
pub mod public;
