//! Adapters from the domain to fstp-prop and fstp-mc, and teeth helpers (design section 6.1).
//!
//! - `prop`: two-way postconditions and the I-23 ledger checks.
//! - `mc`: tripwires, exhaustive checks and the symmetry self-test.
//! - `teeth`: record injection through the public `apply`, fault and
//!   over-denial mutants, and the assertions that a fault was caught.
//!
//! Lane W2 owns this directory.

pub mod mc;
pub mod prop;
pub mod teeth;
