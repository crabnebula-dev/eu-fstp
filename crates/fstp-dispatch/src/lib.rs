//! The M6 dispatcher (M6 design section 5.1, I-25, I-26).
//!
//! Lane L6-REC lands [`store`], the in-memory model of the delivery log
//! that the crash tests run against. Lane L6-DISP lands the worker, its
//! leases, recovery and alerts.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

pub mod store;
