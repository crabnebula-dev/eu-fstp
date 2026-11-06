//! The M4 test kit (M4 design sections 1.1 and 13). Test only: never
//! published and never a normal dependency of another crate (layering rule
//! A9).
//!
//! It holds the fake M3 ports, the authorisation matrix and its
//! independent reference, the three-channel harness, the canary vault, the
//! M4 models, the scenario bridge to `fstp-domain-testkit`, the synthetic
//! legal-wording profile source and the `fstp-e2e-cell` test binary.
//!
//! Status: W0 stub. The lead holds this file after W0. Each lane owns the
//! module files that design section 13 gives it. Every operation refuses
//! with [`NotImplemented`]. Nothing here answers a check with an empty
//! result, so no test passes on a stub.

pub mod canary;
pub mod fake;
pub mod harness;
pub mod matrix;
pub mod mc;
pub mod profiles;
pub mod reference;
pub mod scenario;
pub mod smtp_sink;

/// The refusal of a W0 stub. It names the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotImplemented {
    /// The operation that refused.
    pub operation: &'static str,
}

impl NotImplemented {
    /// The refusal of `operation`.
    pub const fn new(operation: &'static str) -> NotImplemented {
        NotImplemented { operation }
    }
}

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not implemented yet", self.operation)
    }
}

impl std::error::Error for NotImplemented {}
